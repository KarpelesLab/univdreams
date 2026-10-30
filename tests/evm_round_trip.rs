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
//! * `curve-stableswap-ng-math-mainnet.evm` — the Curve
//!   StableSwap-NG math library (`0xc9CBC565…bB3E5E`), vyper 0.3.10
//!   runtime with no trailer: a sparse selector table.
//! * `uniswap-v2-factory-mainnet.evm` — the Uniswap V2 factory
//!   (`0x5C69bEe7…9cc5aA6f`), solc 0.5.16; embeds the `UniswapV2Pair`
//!   initcode it `CREATE2`s, which embeds the pair's runtime.
//!
//! an ERC-5202 blueprint, the code a factory deploys contracts from
//! with `create_from_blueprint`:
//!
//! * `curve-stableswap-ng-blueprint-mainnet.evm` — the StableSwap-NG
//!   plain-pool blueprint (`0xDCc91f93…2958b202`): `0xFE7100`, then the
//!   pools' initcode (vyper 0.3.10 trailer), which deploys a runtime
//!   with a dense selector table.
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
use univdreams::format::evm::{
    blueprint, find_metadata, looks_like_evm, metadata_trailer, minimal_proxy,
};
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
    assert!(paths.len() >= 12, "expected the committed .evm fixtures");
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
    // Well-known structs name their members (`SwapParams`).
    assert!(text.contains("require(!(param1.zeroForOne - bool(param1.zeroForOne)))"));
    // via-IR decodes the `PoolKey` into memory in a helper; its fields
    // read back by name, and `key.toId()` hashes the whole struct.
    assert!(text.contains("v13 = param0.hooks"), "{text}");
    assert!(text.contains("v6 = keccak256(abi.encode(param0))"));
    assert!(text.contains("mstore((v13 + 0x60), signextend(0x2, param0.tickSpacing))"));
    // `SwapParams` copied into memory field by field, then read back.
    assert!(text.contains("v6 = param1.amountSpecified"));
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

/// External calls read as the Solidity that made them: the selector
/// and argument stores, solc's `extcodesize` check (a block of its
/// own) and the re-raise of a failed call's revert data fold into
/// `Iface(target).name(args)`.
#[test]
fn router_external_calls_fold() {
    let code = read(&testdata().join("uniswap-v2-router02-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    for call in [
        "v13 = IWETH(0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2).withdraw(v8)",
        "= IWETH(0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2).deposit.value(msg.value)()",
        "= IUniswapV2Factory(0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f).getPair(address(arg0), address(arg1))",
        "= IERC20(v12).transferFrom(msg.sender, address(v12), arg2)",
        "= IUniswapV2Pair(v8).getReserves()",
        // `IERC20(path[i]).balanceOf(…)`, the target read from calldata.
        "v13 = IERC20(calldataload((0x20 * v12) + v10)).balanceOf(address(v6))",
        "= IERC20(v15).permit(msg.sender, address(this), v17, v8, (v10 & 0xff), v11, v12)",
    ] {
        assert!(text.contains(call), "missing `{call}`");
    }
    assert!(text.contains("= IUniswapV2Pair(v11).burn(address(arg5))"));
    // Left: calls with dynamic arguments, and checks in shared tails.
    assert!(text.matches("extcodesize(").count() <= 9);
}

/// Dynamic parameters (`bytes`, `T[]`) name their length word and data
/// offset, `paramK.length` / `paramK.offset`, whichever compiler
/// decodes them; a revert whose data nests another error's selector
/// isn't mistaken for that error.
#[test]
fn dynamic_parameters_are_named() {
    let code = read(&testdata().join("uniswap-v2-router02-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    assert!(text.contains(
        "v1 = sub_0f4c(param0, param1, param2.offset, param2.length, address(param3), param4)"
    ));
    assert!(
        text.contains("calldatacopy(t1, param1.offset, v12)"),
        "{text}"
    );
    let code = read(&testdata().join("uniswap-v4-poolmanager-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    // via-IR's decoder helper returns both.
    assert!(
        text.contains("param2.offset, param2.length = sub_2f4d(msg.data.length, (0x4 + param2))")
    );
    assert!(text.contains("mstore((t13 + 0xc4), NativeTransferFailed.selector)"));
    assert!(!text.contains("revert(NativeTransferFailed())"));
}

/// Calls whose failure the code handles itself keep the success flag:
/// `t.staticcall(IERC20.balanceOf(a))`. Vyper's selector sits in the
/// low bytes of the word before the call data.
#[test]
fn low_level_external_calls_fold() {
    let code = read(&testdata().join("uniswap-v4-poolmanager-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    assert!(text.contains("v2 = arg0.staticcall(IERC20.balanceOf(address(this)))"));
    assert!(text.contains("= s0.call(IERC20.transfer(address(s3), s2))"));
    assert!(text.contains("mstore((v11 + 0x20), beforeInitialize.selector)"));
    let code = read(&testdata().join("curve-3pool-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    // Vyper reverts when a call fails: `ERC20(coin).balanceOf(self)`.
    assert!(text.contains("v0 = IERC20(sload(0x5)).totalSupply()"));
    assert!(text.contains("v2 = IERC20(mload(0x500)).balanceOf(address(this))"));
    assert!(text.contains("v0 = IERC20(sload(0x5)).burnFrom(msg.sender, param0)"));
    let code = read(&testdata().join("initcode-immutable-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    assert!(text.contains("v4 = v2.call(IERC20.transfer(v3, v5))"));
    // solc ≥0.8's computed address mask reads as `address(x)`.
    let code = read(&testdata().join("initcode-ctor-args-mainnet.evm"));
    let text = decompile_evm_to_text(&code);
    assert!(
        text.contains("= IERC20(v17).approve(address(v13), arg4)"),
        "{text}"
    );
    assert!(text.contains("if (msg.sender != address(v2))"));
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
    // Memory frames saved to the stack around private calls, and
    // arrays returned on it, are counted loops: the blocks after them
    // keep frame-relative names, and `_xp_mem()` returns three values.
    assert!(
        text.contains("v38, v39, v40 = sub_03a1(v38, v39, v40)"),
        "{text}"
    );
    assert!(text.contains("mstore(0x3c0, v40)"));
    let entry_relative = text
        .lines()
        .filter(|l| {
            l.split(|c: char| !c.is_alphanumeric() && c != '-')
                .any(|w| {
                    w.strip_prefix('s').is_some_and(|n| {
                        !n.is_empty()
                            && n.trim_start_matches('-')
                                .bytes()
                                .all(|b| b.is_ascii_digit())
                    })
                })
        })
        .count();
    // What's left are the loop bodies themselves.
    assert!(entry_relative <= 45, "{entry_relative}");
    // Returns load the spilled return address as part of the `return`.
    assert!(text.contains("return mload(0x0); [0x60, 0x00, 0x51, 0x61, 0x01, 0x40, 0x51, 0x56]"));
    assert!(text.matches("@asm(").count() <= 100);
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
    // The selector the dispatcher keeps in a stack slot is known in
    // every case.
    assert!(text.contains("if (msg.sig != 0x23b872dd)"), "{text}");
    assert!(text.contains("if (msg.sig != 0xa9059cbb)"));
    assert!(!text.contains("v0 != 0x"));
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

/// The `@section` named `name` among `items`.
fn section<'a>(items: &'a [Item], name: &str) -> (u64, &'a [Item]) {
    items
        .iter()
        .find_map(|i| match i {
            Item::Section {
                name: n,
                addr,
                items,
            } if n == name => Some((*addr, items.as_slice())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no section {name}"))
}

#[test]
fn vyper0310_blueprint_and_dense_selector_table() {
    let code = read(&testdata().join("curve-stableswap-ng-blueprint-mainnet.evm"));
    let bp = blueprint(&code).expect("ERC-5202 blueprint");
    assert_eq!((bp.preamble_len, bp.version, bp.initcode), (3, 0, 3));
    // Vyper ≥0.3.10 counts the length suffix in the trailer length,
    // and only initcode carries one.
    let md = metadata_trailer(&code).expect("vyper trailer");
    assert_eq!(md.compiler(), Some(("vyper", "0.3.10".to_string())));
    let text = decompile_evm_to_text(&code);
    assert!(text.contains("compiler: \"vyper 0.3.10\""));
    assert!(text.contains("ERC-5202 blueprint (version 0)"), "{text}");
    assert!(text.contains("@section(\"initcode\", 0x3)"));
    assert!(text.contains("@section(\"runtime\", 0x9c6)"));
    assert!(text.contains("selector table (dense: bucket headers and entries)"));
    let forms: [fn(&[u8]) -> univdreams::ast::UdFile; 2] = [decompile_evm, decompile_evm_listing];
    let rt_code = &code[3 + 0x9c6..3 + 0x5db9];
    for form in forms {
        let ast = form(&code);
        let (at, initcode) = section(&ast.items, "initcode");
        assert_eq!(at, 3);
        // The initcode and the runtime it deploys are each decompiled
        // on their own, from offset 0.
        assert_eq!(initcode, form(&code[3..]).items.as_slice());
        let (rt, runtime) = section(initcode, "runtime");
        assert_eq!(rt, 0x9c6);
        assert_eq!(runtime, form(rt_code).items.as_slice());
    }
    // Every entry of the hash table is a named function.
    let table = dispatch_table(rt_code);
    assert_eq!(table.len(), 61);
    // exchange(int128,int128,uint256,uint256), A(), get_virtual_price(),
    // and the receiver overload exchange(…, address).
    for sel in [0x3df0_2124u32, 0xf446_c1d0, 0xbb7b_8b80, 0xddc1_f59d] {
        assert!(table.contains_key(&sel), "missing selector 0x{sel:08x}");
    }
    assert!(!text.contains("fn fn_"), "unnamed selector left");
    assert!(text.contains("fn exchange_received()"));
    assert!(text.contains(
        "// selector 0xddc1f59d: exchange(int128 param0, int128 param1, uint256 param2, uint256 param3, address param4)"
    ));
    // The dispatcher's computed jump reaches every entry, and the
    // selector it keeps on the stack reads as `msg.sig`.
    assert!(text.contains("// one of: N_COINS, coins, fee,"));
    assert!(text.contains("codecopy(0x1b, (0x522a + ((msg.sig % 0x6) * 0x5)), 0x5)"));
    assert!(text.matches("@asm(").count() <= 40);
}

#[test]
fn vyper0310_sparse_selector_table() {
    let code = read(&testdata().join("curve-stableswap-ng-math-mainnet.evm"));
    assert!(
        find_metadata(&code).is_none(),
        "0.3.10 runtime has no trailer"
    );
    // get_y(…), get_D(uint256[],uint256,uint256), get_y_D(…), exp(int256):
    // three bucket heads, one of them chained to a second test.
    assert_eq!(dispatch_table(&code).len(), 4);
    let text = decompile_evm_to_text(&code);
    for name in ["get_y", "get_D", "get_y_D", "exp"] {
        assert!(text.contains(&format!("fn {name}()")), "missing fn {name}");
    }
    assert!(text.contains("selector table (sparse: one bucket head per entry)"));
    assert!(text.contains("// one of: get_y, get_D, get_y_D"), "{text}");
    assert!(text.contains("require((msg.sig == 0xaa3ded9b))"));
    assert!(text.matches("@asm(").count() <= 16);
}

#[test]
fn uniswap_v2_factory_embeds_pair_initcode() {
    let code = read(&testdata().join("uniswap-v2-factory-mainnet.evm"));
    let forms: [fn(&[u8]) -> univdreams::ast::UdFile; 2] = [decompile_evm, decompile_evm_listing];
    let rt_code = &code[0x87b + 0x105..0x87b + 0x2d22];
    for form in forms {
        let ast = form(&code);
        // The pair's initcode, which `createPair` copies out and
        // `CREATE2`s, then the runtime that initcode deploys.
        let (at, pair_init) = section(&ast.items, "contract");
        assert_eq!(at, 0x87b);
        assert_eq!(pair_init, form(&code[0x87b..0x35ef]).items.as_slice());
        let (rt, pair) = section(pair_init, "runtime");
        assert_eq!(rt, 0x105);
        assert_eq!(pair, form(rt_code).items.as_slice());
    }
    let text = decompile_evm_to_text(&code);
    assert!(
        text.contains("embedded contract code (11636 bytes)"),
        "{text}"
    );
    assert!(text.contains("codecopy(arg0, 0x87b, 0x2d74)"));
    assert!(text.contains("create2(0x0, v8 + 0x20, mload(v8), v9)"));
    for name in [
        "createPair",
        "allPairs",
        "feeTo",
        "setFeeToSetter",
        "swap",
        "mint",
        "burn",
        "skim",
        "getReserves",
        "initialize",
        "kLast",
    ] {
        assert!(text.contains(&format!("fn {name}()")), "missing fn {name}");
    }
    assert!(!text.contains("fn fn_"), "unnamed selector left");
    assert!(text.matches("@asm(").count() <= 16);
}
