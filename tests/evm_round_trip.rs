//! Whole-contract EVM source round-trip property, for both the lifted
//! form and the instruction listing:
//!
//! ```text
//! lower_to_evm(parse(decompile_evm_to_text(code))) == code
//! lower_to_evm(parse(decompile_evm_listing_to_text(code))) == code
//! ```
//!
//! plus checks that the lifted form recovers the contracts' structure.
//!
//! Fixtures are mainnet runtime bytecode (`eth_getCode`), saved as
//! raw bytes under `testdata/*.evm`:
//!
//! * `weth9-mainnet.evm` — WETH9, solc 0.4.x, `bzzr0` metadata.
//! * `uniswap-v2-router02-mainnet.evm` — solc 0.6.6, IPFS metadata.
//! * `uniswap-v4-poolmanager-mainnet.evm` — solc 0.8.26 via-IR,
//!   transient storage (`TLOAD`/`TSTORE`), version-only metadata.

use std::path::{Path, PathBuf};

use univdreams::format::evm::{looks_like_evm, metadata_trailer};
use univdreams::translate::compile::{lower_to_evm, parse};
use univdreams::translate::decompile::decompile_evm_to_text;
use univdreams::translate::decompile::evm::{decompile_evm_listing_to_text, dispatch_table};

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

fn fixtures() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(testdata())
        .expect("testdata dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "evm"))
        .collect();
    out.sort();
    out
}

fn read(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    // An un-fetched LFS pointer is ASCII text, not bytecode.
    assert!(
        !bytes.starts_with(b"version https://git-lfs"),
        "{} is an LFS pointer; run `git lfs pull`",
        path.display()
    );
    bytes
}

#[test]
fn evm_fixtures_round_trip_through_source() {
    let paths = fixtures();
    assert!(paths.len() >= 3, "expected the committed .evm fixtures");
    for path in paths {
        let code = read(&path);
        assert!(looks_like_evm(&code), "{} not detected", path.display());
        for (form, text) in [
            ("lifted", decompile_evm_to_text(&code)),
            ("listing", decompile_evm_listing_to_text(&code)),
        ] {
            let ast =
                parse(&text).unwrap_or_else(|e| panic!("parse {} ({form}): {e}", path.display()));
            let rebuilt = lower_to_evm(&ast)
                .unwrap_or_else(|e| panic!("lower {} ({form}): {e}", path.display()));
            assert!(
                rebuilt == code,
                "{} ({form}) differs after round-trip",
                path.display()
            );
        }
    }
}

#[test]
fn weth9_dispatcher_is_recovered() {
    let code = read(&testdata().join("weth9-mainnet.evm"));
    let table = dispatch_table(&code);
    // name, approve, totalSupply, transferFrom, withdraw, decimals,
    // balanceOf, symbol, transfer, deposit, allowance.
    for sel in [
        0x06fd_de03u32,
        0x095e_a7b3,
        0x1816_0ddd,
        0x23b8_72dd,
        0x2e1a_7d4d,
        0x313c_e567,
        0x70a0_8231,
        0x95d8_9b41,
        0xa905_9cbb,
        0xd0e3_0db0,
        0xdd62_ed3e,
    ] {
        assert!(table.contains_key(&sel), "missing selector 0x{sel:08x}");
    }
    let text = decompile_evm_to_text(&code);
    assert!(text.contains("fn withdraw"));
    assert!(text.contains("fn deposit"));
    assert!(text.contains("event Transfer(address,address,uint256)"));
    assert!(text.contains("compiler metadata (CBOR), bzzr0: 0x"));
}

/// The lifted WETH9 reads like its source: `withdraw` is
/// `require(balanceOf[msg.sender] >= wad); balanceOf[msg.sender] -= wad;
/// msg.sender.transfer(wad); Withdrawal(msg.sender, wad)`.
#[test]
fn weth9_lifts_to_statements() {
    let code = read(&testdata().join("weth9-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    // Nonpayable guard, then the call into the internal body with the
    // ABI parameter named after the signature.
    assert!(text.contains("// selector 0x2e1a7d4d: withdraw(uint256 param0)"));
    assert!(text.contains("require(!msg.value)"), "{text}");
    assert!(text.contains("sub_09d9(param0)"));
    assert!(text.contains("// internal function: 1 argument(s), 0 return value(s)"));
    // balanceOf[msg.sender]: Solidity's mapping slot, read in place.
    assert!(text.contains("v3 = sload(mapping(0x3, address(msg.sender)))"));
    assert!(text.contains("require((v3 >= arg0))"));
    assert!(text.contains("call(v3, address(msg.sender), arg0"));
    // Events and return values with their ABI encoding folded.
    assert!(text.contains("emit(Withdrawal(address(msg.sender), arg0))"));
    assert!(text.contains("emit(Deposit(address(msg.sender), msg.value))"));
    assert!(text.contains("return abi.encode(bool(v1));"));
    // `name()`'s copy loop is structured.
    assert!(text.contains("whileblock ("));
    assert!(text.matches("@asm(").count() <= 4);
}

#[test]
fn poolmanager_uses_transient_storage_and_carries_solc_version() {
    let code = read(&testdata().join("uniswap-v4-poolmanager-mainnet.evm"));
    let md = metadata_trailer(&code).expect("metadata trailer");
    assert_eq!(md.compiler(), Some(("solc", "0.8.26".to_string())));
    let listing = decompile_evm_listing_to_text(&code);
    assert!(listing.contains("@asm(\"TLOAD\")"));
    assert!(listing.contains("@asm(\"TSTORE\")"));
    let text = decompile_evm_to_text(&code);
    assert!(text.contains("compiler: \"solc 0.8.26\""));
    assert!(text.contains("fn unlock"));
    // All 33 entry points are named from the signature table, and the
    // fee-flag compare against 0x800000 is not mistaken for one.
    let table = dispatch_table(&code);
    assert_eq!(table.len(), 33);
    assert!(!table.contains_key(&0x0080_0000));
    assert!(!text.contains("fn fn_"), "unnamed selector left");
    // `if (Lock.isUnlocked()) AlreadyUnlocked.selector.revertWith();`
    assert!(text.contains("require(!v3, AlreadyUnlocked())"));
    assert!(text.contains("mstore(v5, unlockCallback.selector)"));
    assert!(text.contains("emit(OperatorSet(msg.sender, address(v2), v1))"));
    assert!(text.contains("return abi.encode(address(v3));"));
    assert!(!text.contains("unknown return value"));
    assert!(text.matches("@asm(").count() <= 8);
}

#[test]
fn router_selectors_resolve_to_names() {
    let code = read(&testdata().join("uniswap-v2-router02-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    for name in [
        "swapExactTokensForTokens",
        "addLiquidityETH",
        "getAmountsOut",
        "WETH",
        "factory",
    ] {
        assert!(text.contains(&format!("fn {name}")), "missing fn {name}");
    }
    // solc 0.6 `require(cond, "reason")` and `&&`, from the library's
    // `getAmountIn`.
    assert!(
        text.contains("require((arg0 > 0x0), \"UniswapV2Library: INSUFFICIENT_OUTPUT_AMOUNT\")")
    );
    assert!(text.contains("v5 = (arg1 > 0x0) && (arg2 > 0x0)"));
    // Calls through masked library targets and shared tails resolve.
    assert!(!text.contains("unknown return value"));
    assert!(text.matches("@asm(").count() <= 8);
}
