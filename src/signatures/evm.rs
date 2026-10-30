//! Well-known EVM ABI names: function / error selectors, event topics
//! and standard storage slots.
//!
//! Entries are stored as canonical signature text and hashed with
//! keccak-256 at first use, so a typo can only cost a missed match —
//! it can never attach the wrong name to a selector.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::arch::evm::{keccak256, selector};

/// Functions and custom errors from the common standards (ERC-20 /
/// 721 / 1155 / 2612 / 4626, Ownable, Pausable, AccessControl,
/// proxies) plus the WETH9 and Uniswap V2 / V4 entry points that
/// show up across DeFi deployments.
const FUNCTIONS: &[&str] = &[
    // ERC-20
    "name()",
    "symbol()",
    "decimals()",
    "totalSupply()",
    "balanceOf(address)",
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
    "approve(address,uint256)",
    "allowance(address,address)",
    "increaseAllowance(address,uint256)",
    "decreaseAllowance(address,uint256)",
    "mint(address,uint256)",
    "burn(uint256)",
    "burnFrom(address,uint256)",
    // ERC-2612 / EIP-712
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "nonces(address)",
    "DOMAIN_SEPARATOR()",
    "eip712Domain()",
    // WETH9
    "deposit()",
    "withdraw(uint256)",
    // ERC-721
    "ownerOf(uint256)",
    "safeTransferFrom(address,address,uint256)",
    "safeTransferFrom(address,address,uint256,bytes)",
    "setApprovalForAll(address,bool)",
    "getApproved(uint256)",
    "isApprovedForAll(address,address)",
    "tokenURI(uint256)",
    "tokenByIndex(uint256)",
    "tokenOfOwnerByIndex(address,uint256)",
    "onERC721Received(address,address,uint256,bytes)",
    // ERC-1155
    "balanceOfBatch(address[],uint256[])",
    "safeTransferFrom(address,address,uint256,uint256,bytes)",
    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    "uri(uint256)",
    // ERC-6909 (multi-token; Uniswap v4 claims)
    "balanceOf(address,uint256)",
    "allowance(address,address,uint256)",
    "isOperator(address,address)",
    "setOperator(address,bool)",
    "approve(address,uint256,uint256)",
    "transfer(address,uint256,uint256)",
    "transferFrom(address,address,uint256,uint256)",
    // ERC-165
    "supportsInterface(bytes4)",
    // ERC-4626
    "asset()",
    "totalAssets()",
    "convertToShares(uint256)",
    "convertToAssets(uint256)",
    "deposit(uint256,address)",
    "mint(uint256,address)",
    "withdraw(uint256,address,address)",
    "redeem(uint256,address,address)",
    // Ownable / Ownable2Step
    "owner()",
    "transferOwnership(address)",
    "renounceOwnership()",
    "pendingOwner()",
    "acceptOwnership()",
    // Pausable
    "paused()",
    "pause()",
    "unpause()",
    // AccessControl
    "hasRole(bytes32,address)",
    "getRoleAdmin(bytes32)",
    "grantRole(bytes32,address)",
    "revokeRole(bytes32,address)",
    "renounceRole(bytes32,address)",
    "DEFAULT_ADMIN_ROLE()",
    // Proxies (transparent, UUPS, beacon)
    "implementation()",
    "admin()",
    "changeAdmin(address)",
    "upgradeTo(address)",
    "upgradeToAndCall(address,bytes)",
    "proxiableUUID()",
    "initialize()",
    // Misc
    "multicall(bytes[])",
    "version()",
    // Uniswap V2 router
    "factory()",
    "WETH()",
    "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
    "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
    "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
    "swapExactETHForTokens(uint256,address[],address,uint256)",
    "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
    "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    "swapETHForExactTokens(uint256,address[],address,uint256)",
    "quote(uint256,uint256,uint256)",
    "getAmountOut(uint256,uint256,uint256)",
    "getAmountIn(uint256,uint256,uint256)",
    "getAmountsOut(uint256,address[])",
    "getAmountsIn(uint256,address[])",
    // Uniswap V2 pair / factory
    "getReserves()",
    "token0()",
    "token1()",
    "swap(uint256,uint256,address,bytes)",
    "sync()",
    "skim(address)",
    "mint(address)",
    "burn(address)",
    "getPair(address,address)",
    "createPair(address,address)",
    "feeTo()",
    "feeToSetter()",
    "allPairs(uint256)",
    "allPairsLength()",
    "setFeeTo(address)",
    "setFeeToSetter(address)",
    "mint(address)",
    "burn(address)",
    "initialize(address,address)",
    "price0CumulativeLast()",
    "price1CumulativeLast()",
    "kLast()",
    "MINIMUM_LIQUIDITY()",
    "PERMIT_TYPEHASH()",
    // Uniswap V4 pool manager
    "unlock(bytes)",
    "settle()",
    "settleFor(address)",
    "take(address,address,uint256)",
    "sync(address)",
    "clear(address,uint256)",
    "extsload(bytes32)",
    "extsload(bytes32,uint256)",
    "extsload(bytes32[])",
    "exttload(bytes32)",
    "exttload(bytes32[])",
    "protocolFeesAccrued(address)",
    "initialize((address,address,uint24,int24,address),uint160)",
    "modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
    "swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)",
    "donate((address,address,uint24,int24,address),uint256,uint256,bytes)",
    "mint(address,uint256,uint256)",
    "burn(address,uint256,uint256)",
    "updateDynamicLPFee((address,address,uint24,int24,address),uint24)",
    "setProtocolFee((address,address,uint24,int24,address),uint24)",
    "collectProtocolFees(address,address,uint256)",
    // Uniswap v4 callbacks and hooks
    "unlockCallback(bytes)",
    "beforeInitialize(address,(address,address,uint24,int24,address),uint160)",
    "afterInitialize(address,(address,address,uint24,int24,address),uint160,int24)",
    "beforeAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
    "afterAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),int256,int256,bytes)",
    "beforeRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
    "afterRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),int256,int256,bytes)",
    "beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)",
    "afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),int256,bytes)",
    "beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
    "afterDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
    "protocolFeeController()",
    "setProtocolFeeController(address)",
    // Curve StableSwap (Vyper; the 3pool's ABI, shared by most
    // plain pools) and crvUSD
    "A()",
    "get_virtual_price()",
    "calc_token_amount(uint256[2],bool)",
    "calc_token_amount(uint256[3],bool)",
    "calc_token_amount(uint256[4],bool)",
    "add_liquidity(uint256[2],uint256)",
    "add_liquidity(uint256[3],uint256)",
    "add_liquidity(uint256[4],uint256)",
    "get_dy(int128,int128,uint256)",
    "get_dy_underlying(int128,int128,uint256)",
    "exchange(int128,int128,uint256,uint256)",
    "exchange_underlying(int128,int128,uint256,uint256)",
    "remove_liquidity(uint256,uint256[2])",
    "remove_liquidity(uint256,uint256[3])",
    "remove_liquidity(uint256,uint256[4])",
    "remove_liquidity_imbalance(uint256[2],uint256)",
    "remove_liquidity_imbalance(uint256[3],uint256)",
    "remove_liquidity_imbalance(uint256[4],uint256)",
    "calc_withdraw_one_coin(uint256,int128)",
    "remove_liquidity_one_coin(uint256,int128,uint256)",
    "ramp_A(uint256,uint256)",
    "stop_ramp_A()",
    "commit_new_fee(uint256,uint256)",
    "apply_new_fee()",
    "revert_new_parameters()",
    "commit_transfer_ownership(address)",
    "apply_transfer_ownership()",
    "revert_transfer_ownership()",
    "admin_balances(uint256)",
    "withdraw_admin_fees()",
    "donate_admin_fees()",
    "kill_me()",
    "unkill_me()",
    "coins(uint256)",
    "balances(uint256)",
    "fee()",
    "admin_fee()",
    "initial_A()",
    "future_A()",
    "initial_A_time()",
    "future_A_time()",
    "admin_actions_deadline()",
    "transfer_ownership_deadline()",
    "future_fee()",
    "future_admin_fee()",
    "future_owner()",
    "minter()",
    "set_minter(address)",
    "salt()",
    "burn(address,uint256)",
    // Built-in revert payloads
    "Error(string)",
    "Panic(uint256)",
    // OpenZeppelin v5 custom errors
    "OwnableUnauthorizedAccount(address)",
    "OwnableInvalidOwner(address)",
    "ERC20InsufficientBalance(address,uint256,uint256)",
    "ERC20InsufficientAllowance(address,uint256,uint256)",
    "ERC20InvalidSender(address)",
    "ERC20InvalidReceiver(address)",
    "ERC20InvalidApprover(address)",
    "ERC20InvalidSpender(address)",
    "ReentrancyGuardReentrantCall()",
    "EnforcedPause()",
    "ExpectedPause()",
    "AccessControlUnauthorizedAccount(address,bytes32)",
    "SafeERC20FailedOperation(address)",
    "AddressEmptyCode(address)",
    "FailedInnerCall()",
    "InvalidInitialization()",
    "NotInitializing()",
    // Uniswap v4 errors
    "AlreadyUnlocked()",
    "CurrencyNotSettled()",
    "ManagerLocked()",
    "DelegateCallNotAllowed()",
    "InvalidCaller()",
    "ProtocolFeeTooLarge(uint24)",
    "ProtocolFeeCurrencySynced()",
    "UnauthorizedDynamicLPFeeUpdate()",
    "SwapAmountCannotBeZero()",
    "NonzeroNativeValue()",
    "MustClearExactPositiveDelta()",
    "CurrenciesOutOfOrderOrEqual(address,address)",
    "TickSpacingTooLarge(int24)",
    "TickSpacingTooSmall(int24)",
    "PoolNotInitialized()",
    "PoolAlreadyInitialized()",
    "InvalidHookResponse()",
    "HookAddressNotValid(address)",
    "WrappedError(address,bytes4,bytes,bytes)",
    "HookCallFailed()",
    "NativeTransferFailed()",
    "ERC20TransferFailed()",
    "TicksMisordered(int24,int24)",
    "TickLowerOutOfBounds(int24)",
    "TickUpperOutOfBounds(int24)",
    "TickLiquidityOverflow(int24)",
    "CannotUpdateEmptyPosition()",
    "PriceLimitAlreadyExceeded(uint160,uint160)",
    "PriceLimitOutOfBounds(uint160)",
    "NoLiquidityToReceiveFees()",
    "InvalidFeeForExactOut()",
    "LPFeeTooLarge(uint24)",
    // Curve StableSwap-NG (Vyper 0.3.10): pools, their math
    // library and the factory
    "exchange(int128,int128,uint256,uint256,address)",
    "exchange_received(int128,int128,uint256,uint256)",
    "exchange_received(int128,int128,uint256,uint256,address)",
    "add_liquidity(uint256[],uint256)",
    "add_liquidity(uint256[],uint256,address)",
    "remove_liquidity_one_coin(uint256,int128,uint256,address)",
    "remove_liquidity_imbalance(uint256[],uint256)",
    "remove_liquidity_imbalance(uint256[],uint256,address)",
    "remove_liquidity(uint256,uint256[])",
    "remove_liquidity(uint256,uint256[],address)",
    "remove_liquidity(uint256,uint256[],address,bool)",
    "last_price(uint256)",
    "ema_price(uint256)",
    "get_p(uint256)",
    "price_oracle(uint256)",
    "D_oracle()",
    "get_dx(int128,int128,uint256)",
    "calc_token_amount(uint256[],bool)",
    "A_precise()",
    "get_balances()",
    "stored_rates()",
    "dynamic_fee(int128,int128)",
    "set_new_fee(uint256,uint256)",
    "set_ma_exp_time(uint256,uint256)",
    "N_COINS()",
    "offpeg_fee_multiplier()",
    "ma_exp_time()",
    "D_ma_time()",
    "ma_last_time()",
    "get_D(uint256[],uint256,uint256)",
    "get_y_D(uint256,int128,uint256[],uint256,uint256)",
    "exp(int256)",
    "get_y(int128,int128,uint256,uint256[],uint256,uint256,uint256)",
    "math_implementation()",
    "views_implementation()",
    "pool_implementations(uint256)",
    "deploy_plain_pool(string,string,address[],uint256,uint256,uint256,uint256,uint256,uint8[],bytes4[],address[])",
    "deploy_metapool(address,string,string,address,uint256,uint256,uint256,uint256,uint256,uint8,bytes4,address)",
    "pool_count()",
    "pool_list(uint256)",
    "get_coins(address)",
    "get_n_coins(address)",
    "get_balances(address)",
    "get_A(address)",
    "get_fees(address)",
    "get_decimals(address)",
    "get_gauge(address)",
    "find_pool_for_coins(address,address)",
    "find_pool_for_coins(address,address,uint256)",
    "fee_receiver()",
    "gauge_implementation()",
    "future_admin()",
    "accept_transfer_ownership()",
    "deploy_gauge(address)",
    "is_meta(address)",
    "get_meta_n_coins(address)",
    "get_underlying_coins(address)",
    "get_underlying_balances(address)",
    "get_underlying_decimals(address)",
    "get_coin_indices(address,address,address)",
    "get_admin_balances(address)",
    "get_implementation_address(address)",
    "base_pool_count()",
    "base_pool_list(uint256)",
    "base_pool_data(address)",
    "base_pool_assets(address)",
    "add_base_pool(address,address,uint8[],uint256)",
    "set_pool_implementations(uint256,address)",
    "set_metapool_implementations(uint256,address)",
    "set_math_implementation(address)",
    "set_views_implementation(address)",
    "set_gauge_implementation(address)",
    "metapool_implementations(uint256)",
    "asset_types(uint8)",
    "get_metapool_rates(address)",
];

const EVENTS: &[&str] = &[
    "Transfer(address,address,uint256)",
    "Approval(address,address,uint256)",
    "ApprovalForAll(address,address,bool)",
    "TransferSingle(address,address,address,uint256,uint256)",
    "TransferBatch(address,address,address,uint256[],uint256[])",
    "URI(string,uint256)",
    "OwnershipTransferred(address,address)",
    "OwnershipTransferStarted(address,address)",
    "Paused(address)",
    "Unpaused(address)",
    "RoleGranted(bytes32,address,address)",
    "RoleRevoked(bytes32,address,address)",
    "RoleAdminChanged(bytes32,bytes32,bytes32)",
    "Upgraded(address)",
    "AdminChanged(address,address)",
    "BeaconUpgraded(address)",
    "Initialized(uint8)",
    "Initialized(uint64)",
    "Deposit(address,uint256)",
    "Withdrawal(address,uint256)",
    "Deposit(address,address,uint256,uint256)",
    "Withdraw(address,address,address,uint256,uint256)",
    "Swap(address,uint256,uint256,uint256,uint256,address)",
    "Sync(uint112,uint112)",
    "Mint(address,uint256,uint256)",
    "Burn(address,uint256,uint256,address)",
    "PairCreated(address,address,address,uint256)",
    // ERC-6909
    "Transfer(address,address,address,uint256,uint256)",
    "Approval(address,address,uint256,uint256)",
    "OperatorSet(address,address,bool)",
    // Uniswap v4 pool manager
    "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)",
    "ModifyLiquidity(bytes32,address,int24,int24,int256,bytes32)",
    "Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)",
    "Donate(bytes32,address,uint256,uint256)",
    "ProtocolFeeControllerUpdated(address)",
    "ProtocolFeeUpdated(bytes32,uint24)",
];

/// The interfaces that declare known functions, for naming external
/// calls (`IERC20(token).transfer(to, amount)`). The first interface
/// listing a signature names it.
const INTERFACES: &[(&str, &[&str])] = &[
    (
        "IERC20",
        &[
            "name()",
            "symbol()",
            "decimals()",
            "totalSupply()",
            "balanceOf(address)",
            "transfer(address,uint256)",
            "transferFrom(address,address,uint256)",
            "approve(address,uint256)",
            "allowance(address,address)",
            "increaseAllowance(address,uint256)",
            "decreaseAllowance(address,uint256)",
            "mint(address,uint256)",
            "burn(uint256)",
            "burnFrom(address,uint256)",
            "burn(address,uint256)",
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            "nonces(address)",
            "DOMAIN_SEPARATOR()",
        ],
    ),
    ("IWETH", &["deposit()", "withdraw(uint256)"]),
    (
        "IERC721",
        &[
            "ownerOf(uint256)",
            "safeTransferFrom(address,address,uint256)",
            "safeTransferFrom(address,address,uint256,bytes)",
            "setApprovalForAll(address,bool)",
            "getApproved(uint256)",
            "isApprovedForAll(address,address)",
            "tokenURI(uint256)",
        ],
    ),
    (
        "IERC721Receiver",
        &["onERC721Received(address,address,uint256,bytes)"],
    ),
    (
        "IERC1155",
        &[
            "balanceOfBatch(address[],uint256[])",
            "safeTransferFrom(address,address,uint256,uint256,bytes)",
            "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
            "uri(uint256)",
        ],
    ),
    ("IERC165", &["supportsInterface(bytes4)"]),
    (
        "IERC4626",
        &[
            "asset()",
            "totalAssets()",
            "convertToShares(uint256)",
            "convertToAssets(uint256)",
            "deposit(uint256,address)",
            "mint(uint256,address)",
            "withdraw(uint256,address,address)",
            "redeem(uint256,address,address)",
        ],
    ),
    (
        "IUniswapV2Pair",
        &[
            "getReserves()",
            "token0()",
            "token1()",
            "swap(uint256,uint256,address,bytes)",
            "sync()",
            "skim(address)",
            "mint(address)",
            "burn(address)",
        ],
    ),
    (
        "IUniswapV2Factory",
        &["getPair(address,address)", "createPair(address,address)"],
    ),
    ("IUnlockCallback", &["unlockCallback(bytes)"]),
    (
        "IHooks",
        &[
            "beforeInitialize(address,(address,address,uint24,int24,address),uint160)",
            "afterInitialize(address,(address,address,uint24,int24,address),uint160,int24)",
            "beforeAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
            "afterAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),int256,int256,bytes)",
            "beforeRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
            "afterRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),int256,int256,bytes)",
            "beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)",
            "afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),int256,bytes)",
            "beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
            "afterDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
        ],
    ),
];

/// Well-known ABI tuples: canonical type, struct name, member names.
const STRUCTS: &[(&str, &str, &[&str])] = &[
    (
        "(address,address,uint24,int24,address)",
        "PoolKey",
        &["currency0", "currency1", "fee", "tickSpacing", "hooks"],
    ),
    (
        "(bool,int256,uint160)",
        "SwapParams",
        &["zeroForOne", "amountSpecified", "sqrtPriceLimitX96"],
    ),
    (
        "(int24,int24,int256,bytes32)",
        "ModifyLiquidityParams",
        &["tickLower", "tickUpper", "liquidityDelta", "salt"],
    ),
];

/// ERC-1967 slots, defined as `keccak256(label) - 1`.
const ERC1967_SLOTS: &[(&str, &str)] = &[
    (
        "eip1967.proxy.implementation",
        "ERC-1967 implementation slot",
    ),
    ("eip1967.proxy.admin", "ERC-1967 admin slot"),
    ("eip1967.proxy.beacon", "ERC-1967 beacon slot"),
];

/// Pre-ERC-1967 ZeppelinOS proxy slots (USDC's proxy and other
/// 2018-era upgradeable contracts), defined as plain `keccak256(label)`.
const ZEPPELINOS_SLOTS: &[(&str, &str)] = &[
    (
        "org.zeppelinos.proxy.implementation",
        "ZeppelinOS implementation slot",
    ),
    ("org.zeppelinos.proxy.admin", "ZeppelinOS admin slot"),
];

fn selector_map() -> &'static HashMap<u32, &'static str> {
    static MAP: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut map = HashMap::new();
        for sig in FUNCTIONS {
            map.entry(selector(sig)).or_insert(*sig);
        }
        map
    })
}

fn topic_map() -> &'static HashMap<[u8; 32], &'static str> {
    static MAP: OnceLock<HashMap<[u8; 32], &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        EVENTS
            .iter()
            .map(|sig| (keccak256(sig.as_bytes()), *sig))
            .collect()
    })
}

fn slot_map() -> &'static HashMap<[u8; 32], &'static str> {
    static MAP: OnceLock<HashMap<[u8; 32], &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        ERC1967_SLOTS
            .iter()
            .map(|(label, name)| (sub_one(keccak256(label.as_bytes())), *name))
            .chain(
                ZEPPELINOS_SLOTS
                    .iter()
                    .map(|(label, name)| (keccak256(label.as_bytes()), *name)),
            )
            .collect()
    })
}

fn sub_one(mut v: [u8; 32]) -> [u8; 32] {
    for b in v.iter_mut().rev() {
        let (r, borrow) = b.overflowing_sub(1);
        *b = r;
        if !borrow {
            break;
        }
    }
    v
}

/// Function or error signature for a 4-byte selector.
#[must_use]
pub fn function_by_selector(sel: u32) -> Option<&'static str> {
    selector_map().get(&sel).copied()
}

/// Selectors of the known functions / errors called `name`, one per
/// overload.
#[must_use]
pub fn selectors_named(name: &str) -> Vec<u32> {
    FUNCTIONS
        .iter()
        .filter(|sig| sig.split('(').next() == Some(name))
        .map(|sig| selector(sig))
        .collect()
}

/// The interface declaring the known function `sig` (`IERC20` for
/// `transfer(address,uint256)`).
#[must_use]
pub fn interface_of(sig: &str) -> Option<&'static str> {
    INTERFACES
        .iter()
        .find(|(_, sigs)| sigs.contains(&sig))
        .map(|(name, _)| *name)
}

/// Struct name and member names of a well-known ABI tuple type, given
/// in canonical form (`(address,address,uint24,int24,address)` is
/// Uniswap v4's `PoolKey`).
#[must_use]
pub fn struct_fields(tuple: &str) -> Option<(&'static str, &'static [&'static str])> {
    STRUCTS
        .iter()
        .find(|(t, _, _)| *t == tuple)
        .map(|&(_, name, fields)| (name, fields))
}

/// Event signature for a `LOGn` topic-0 value.
#[must_use]
pub fn event_by_topic(topic: &[u8; 32]) -> Option<&'static str> {
    topic_map().get(topic).copied()
}

/// Name of a standard storage slot constant.
#[must_use]
pub fn slot_name(slot: &[u8; 32]) -> Option<&'static str> {
    slot_map().get(slot).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_selectors() {
        assert_eq!(
            function_by_selector(0xa905_9cbb),
            Some("transfer(address,uint256)")
        );
        assert_eq!(function_by_selector(0x08c3_79a0), Some("Error(string)"));
        assert_eq!(function_by_selector(0x4e48_7b71), Some("Panic(uint256)"));
        assert_eq!(function_by_selector(0xd0e3_0db0), Some("deposit()"));
        assert_eq!(function_by_selector(0xdead_beef), None);
    }

    #[test]
    fn interfaces_and_structs() {
        assert_eq!(interface_of("transfer(address,uint256)"), Some("IERC20"));
        assert_eq!(interface_of("withdraw(uint256)"), Some("IWETH"));
        assert_eq!(interface_of("getReserves()"), Some("IUniswapV2Pair"));
        assert_eq!(interface_of("A()"), None);
        // Every interface member is a known function.
        for (_, sigs) in INTERFACES {
            for sig in *sigs {
                assert_eq!(function_by_selector(selector(sig)), Some(*sig), "{sig}");
            }
        }
        let (name, fields) = struct_fields("(address,address,uint24,int24,address)").unwrap();
        assert_eq!(name, "PoolKey");
        assert_eq!(fields[4], "hooks");
        for (t, _, fields) in STRUCTS {
            assert_eq!(t.matches(',').count() + 1, fields.len(), "{t}");
        }
        assert_eq!(struct_fields("(uint256)"), None);
    }

    #[test]
    fn erc1967_implementation_slot() {
        let mut want = [0u8; 32];
        let hex = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
        for (i, b) in want.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        assert_eq!(slot_name(&want), Some("ERC-1967 implementation slot"));
    }

    #[test]
    fn sub_one_borrows() {
        let mut v = [0u8; 32];
        v[31] = 0x00;
        v[30] = 0x01;
        let r = sub_one(v);
        assert_eq!((r[30], r[31]), (0x00, 0xff));
    }
}
