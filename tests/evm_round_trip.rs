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
//! * `usdc-proxy-mainnet.evm` — USDC's ZeppelinOS
//!   `AdminUpgradeabilityProxy`, solc 0.4.24.
//! * `curve-3pool-mainnet.evm` — Curve's 3pool, vyper 0.2 (no
//!   metadata; selector kept in memory, private functions with
//!   memory-held return addresses).
//! * `crvusd-mainnet.evm` — the crvUSD stablecoin, vyper 0.3.7
//!   (metadata trailer followed by appended immutables).
//! * `eip1167-clone-mainnet.evm` — an EIP-1167 minimal proxy.
//!
//! and creation code (the `input` of the deploying transaction,
//! `ud evm <tx-hash>`):
//!
//! * `initcode-immutable-mainnet.evm` — tx `0xaa4c0a4f…7b41cf3`,
//!   solc 0.8.35; the constructor patches an immutable into the
//!   runtime before returning it.
//! * `initcode-ctor-args-mainnet.evm` — tx `0x4c94aedd…31cbee89`,
//!   solc 0.8.24; one constructor argument after the runtime.

use std::path::{Path, PathBuf};

use univdreams::ast::Item;
use univdreams::format::evm::{find_metadata, looks_like_evm, metadata_trailer, minimal_proxy};
use univdreams::translate::compile::{lower_to_evm, parse};
use univdreams::translate::decompile::decompile_evm_to_text;
use univdreams::translate::decompile::evm::{
    decompile_evm, decompile_evm_listing, decompile_evm_listing_to_text, dispatch_table,
};

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
    assert!(paths.len() >= 9, "expected the committed .evm fixtures");
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
    // balanceOf[msg.sender]: Solidity's mapping slot, read in place
    // and named after the `balanceOf(address)` getter that reads it.
    assert!(
        text.contains("v3 = balanceOf[address(msg.sender)]"),
        "{text}"
    );
    assert!(text.contains("v3 = &balanceOf[address(msg.sender)]"));
    assert!(text.contains("require((v3 >= arg0))"));
    // `msg.sender.transfer(wad)`: a stipend-only send, then `require`.
    assert!(text.contains("v6 = msg.sender.send(arg0)"), "{text}");
    assert!(text.contains("require(bool(v6))"));
    // Events and return values with their ABI encoding folded.
    assert!(text.contains("emit(Withdrawal(address(msg.sender), arg0))"));
    assert!(text.contains("emit(Deposit(address(msg.sender), msg.value))"));
    assert!(text.contains("return abi.encode(bool(v1));"));
    // The getters' own internal accessors, and `decimals` (slot 2).
    assert!(text.contains("arg0 = balanceOf[arg0]"));
    assert!(text.contains("arg0 = allowance[arg0][arg1]"));
    assert!(text.contains("allowance[address(msg.sender)][address(arg0)] = arg1"));
    assert!(text.contains("v6 = allowance[address(arg0)][address(msg.sender)]"));
    assert!(text.contains("v2 = decimals"));
    assert!(!text.contains("mapping(0x"));
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
    assert!(text.contains("emit(OperatorSet(msg.sender, address(param0), v1))"));
    assert!(text.contains("return abi.encode(address(v3));"));
    // Storage named from the public getters: `owner` (slot 0),
    // `protocolFeeController` (2), `isOperator` (3), `allowance` (5).
    assert!(text.contains("v3 = protocolFeeController"));
    assert!(text.contains("v4 = &isOperator[msg.sender]"));
    // via-IR decodes calldata in shared helpers; their results are the
    // parameters, which also key the named storage.
    assert!(text.contains("param0 = sub_2d3f()"), "{text}");
    assert!(text.contains("v3 = isOperator[address(param0)][address(param1)]"));
    assert!(text.contains("return abi.encode(balanceOf[address(param0)][param1]);"));
    assert!(text.contains("v2 = allowance[address(param0)][address(param1)][param2]"));
    assert!(text.contains(
        "owner = (v2 & 0xffffffffffffffffffffffff0000000000000000000000000000000000000000) | address(param0)"
    ));
    // Static tuples take one head word per member.
    assert!(text.contains(
        "swap((address,address,uint24,int24,address) param0, (bool,int256,uint160) param1, bytes param2)"
    ));
    assert!(text.contains("require(!(param1.f0 - bool(param1.f0)))"));
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
    // solc 0.6 decodes inline from a `headStart` of 0x4 kept in a
    // stack slot; dynamic parameters are their offset words, and
    // unknown signatures get `param0…`.
    assert!(text.contains(
        "v1, v2 = sub_0de4(address(param0), param1, param2, param3, address(param4), param5)"
    ));
    assert!(text.contains(
        "swapExactTokensForTokens(uint256 param0, uint256 param1, address[] param2, address param3, uint256 param4)"
    ));
    assert!(text.contains("v7 = 0x4 + param2"));
    assert!(text.contains("= address(param0), address(param1), param2, param3"));
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

#[test]
fn usdc_proxy_reads_like_its_source() {
    let code = read(&testdata().join("usdc-proxy-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    for name in ["upgradeTo", "upgradeToAndCall", "implementation", "admin"] {
        assert!(text.contains(&format!("fn {name}()")), "missing fn {name}");
    }
    // `_fallback()` ends in `_delegate()`'s assembly return / revert.
    assert!(text.contains("never returns"), "{text}");
    assert!(text.contains("// does not return"));
    assert!(!text.contains("return-value count unknown"));
    // solc 0.4 stores long revert reasons word by word.
    assert!(text.contains(
        "require((address(arg0) != address(0x0)), \"Cannot change the admin of a proxy to the zero address\")"
    ));
    assert!(text.contains("delegatecall(gasleft(), arg0, 0x0, msg.data.length, 0x0, 0x0)"));
    let listing = decompile_evm_listing_to_text(&code);
    assert!(listing.contains("ZeppelinOS implementation slot"));
    assert!(text.matches("@asm(").count() <= 12);
}

#[test]
fn vyper02_curve_3pool() {
    let code = read(&testdata().join("curve-3pool-mainnet.evm"));
    assert!(find_metadata(&code).is_none(), "vyper 0.2 has no trailer");
    let table = dispatch_table(&code);
    // A(), get_virtual_price(), exchange(int128,int128,uint256,uint256),
    // remove_liquidity_one_coin(uint256,int128,uint256).
    for sel in [0xf446_c1d0u32, 0xbb7b_8b80, 0x3df0_2124, 0x1a4d_01d2] {
        assert!(table.contains_key(&sel), "missing selector 0x{sel:08x}");
    }
    assert!(table.len() >= 35, "{}", table.len());
    let text = decompile_evm_to_text(&code);
    assert!(!text.contains("fn fn_"), "unnamed selector left");
    // Each case starts with its own selector test, read from memory 0.
    assert!(text.contains("if (msg.sig != 0xf446c1d0)"), "{text}");
    // Private functions keep their return address in memory.
    assert!(text.matches("// internal function:").count() >= 8);
    assert!(text.contains("v0 = sub_00a9()"));
    assert!(text.matches("@asm(").count() <= 110);
}

#[test]
fn vyper03_crvusd() {
    let code = read(&testdata().join("crvusd-mainnet.evm"));
    // The trailer is followed by the immutables vyper appends.
    let md = find_metadata(&code).expect("vyper trailer");
    assert!(md.end < code.len());
    assert_eq!(md.compiler(), Some(("vyper", "0.3.7".to_string())));
    assert!(metadata_trailer(&code).is_none());
    let text = decompile_evm_to_text(&code);
    assert!(text.contains("compiler: \"vyper 0.3.7\""));
    assert!(text.contains("appended after the metadata"));
    assert!(text.contains("fn transferFrom()"));
    assert!(text.contains("fn set_minter()"));
    assert!(text.contains("if (v0 != 0x23b872dd)"), "{text}");
    // `self.allowance[_from][msg.sender]`: vyper hashes slot ‖ key.
    assert!(text.contains("sload(mapping(mapping(0x0, mload(0xc0)), msg.sender))"));
    assert!(!text.contains("fn fn_"));
    assert!(text.matches("@asm(").count() <= 4);
}

#[test]
fn eip1167_clone_is_a_proxy() {
    let code = read(&testdata().join("eip1167-clone-mainnet.evm"));
    let proxy = minimal_proxy(&code).expect("EIP-1167");
    assert_eq!(proxy.code_len, code.len());
    let text = decompile_evm_to_text(&code);
    assert!(text.contains("EIP-1167 minimal proxy"));
    assert!(
        text.contains("return delegatecall(0x7F9F70Da4af54671a6abAc58e705b5634cac8819, msg.data);"),
        "{text}"
    );
    assert!(!text.contains("@asm("));
}

/// The `@section` holding the runtime that initcode deploys.
fn runtime_section(items: &[Item]) -> (u64, &[Item]) {
    items
        .iter()
        .find_map(|i| match i {
            Item::Section { name, addr, items } if name == "runtime" => {
                Some((*addr, items.as_slice()))
            }
            _ => None,
        })
        .expect("runtime section")
}

#[test]
fn initcode_nests_the_runtime_it_deploys() {
    for (fixture, start, end) in [
        ("initcode-immutable-mainnet.evm", 0x31, 0x439),
        ("initcode-ctor-args-mainnet.evm", 0xbe, 0x1b80),
    ] {
        let code = read(&testdata().join(fixture));
        let forms: [fn(&[u8]) -> univdreams::ast::UdFile; 2] =
            [decompile_evm, decompile_evm_listing];
        for form in forms {
            let ast = form(&code);
            let (addr, items) = runtime_section(&ast.items);
            assert_eq!(addr, start, "{fixture}");
            // The section is the runtime decompiled on its own, from
            // offset 0 — what `eth_getCode` would return, immutables
            // aside.
            let alone = form(&code[usize::try_from(start).unwrap()..end]);
            assert_eq!(items, alone.items.as_slice(), "{fixture}");
        }
        let text = decompile_evm_to_text(&code);
        assert!(text.contains("runtime code the constructor deploys"));
        assert!(text.contains("fn transfer()") || text.contains("fn owner()"));
    }
    let code = read(&testdata().join("initcode-ctor-args-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    assert!(
        text.contains("data 0x1b80..0x1ba0: constructor arguments"),
        "{text}"
    );
    assert!(text.contains("codecopy(v0, 0x1b80, v1)"));
    // Immutables are written into the memory copy before RETURN.
    assert!(text.contains("return memory(0x0, 0x1ac2);"));
}
