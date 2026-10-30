//! Fetch an EVM contract's runtime bytecode over JSON-RPC.
//!
//! Uses the standard `eth_getCode(address, "latest")` call, so any
//! EVM chain's endpoint works (Ethereum, L2s, sidechains, a local
//! node). Fetched code is cached under
//! `~/.cache/univdreams/evm/<chain-id>/<address>.evm`; the chain ID
//! comes from `eth_chainId`, so one address on two chains doesn't
//! collide. Contract code is immutable except for `SELFDESTRUCT` /
//! redeploy and EIP-7702 delegations — `--no-cache` covers those.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Default RPC endpoint when `--rpc` isn't given: a public, keyless
/// Ethereum mainnet endpoint.
pub const DEFAULT_RPC: &str = "https://ethereum-rpc.publicnode.com";

/// Fetch the runtime bytecode at `address` (`0x` + 40 hex digits).
/// With `use_cache = false` the cached copy is ignored and replaced.
pub fn fetch_code(address: &str, rpc_url: &str, use_cache: bool) -> Result<Vec<u8>> {
    let address = normalize_address(address)?;
    let chain_id = rpc_call::<String>(rpc_url, "eth_chainId", &serde_json::json!([]))
        .context("eth_chainId")
        .and_then(|hex| parse_quantity(&hex))?;

    let dir = cache_dir()?.join(chain_id.to_string());
    let cache_path = dir.join(format!("{address}.evm"));
    if use_cache && cache_path.is_file() {
        return fs::read(&cache_path)
            .with_context(|| format!("read cache {}", cache_path.display()));
    }

    let hex = rpc_call::<String>(
        rpc_url,
        "eth_getCode",
        &serde_json::json!([address, "latest"]),
    )
    .with_context(|| format!("eth_getCode {address}"))?;
    let code = crate::format::evm::decode_hex_text(hex.as_bytes()).unwrap_or_default();
    if code.is_empty() {
        bail!(
            "no code at {address} on chain {chain_id} (an externally-owned account, or a destroyed contract)"
        );
    }

    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("warning: couldn't create cache dir {}: {e}", dir.display());
    } else if let Err(e) = fs::write(&cache_path, &code) {
        eprintln!(
            "warning: couldn't write cache {}: {e}",
            cache_path.display()
        );
    }
    Ok(code)
}

/// Validate and lower-case a hex address. Checksum casing isn't
/// verified — the RPC accepts either form.
fn normalize_address(s: &str) -> Result<String> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| anyhow::anyhow!("address {s:?} must start with 0x"))?;
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid address {s:?}: expected 0x followed by 40 hex digits");
    }
    Ok(format!("0x{}", hex.to_ascii_lowercase()))
}

fn parse_quantity(hex: &str) -> Result<u64> {
    let digits = hex
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("quantity {hex:?} lacks 0x prefix"))?;
    u64::from_str_radix(digits, 16).with_context(|| format!("parse quantity {hex:?}"))
}

fn cache_dir() -> Result<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(xdg).join("univdreams").join("evm"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home)
            .join(".cache")
            .join("univdreams")
            .join("evm"));
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(local_app_data)
            .join("univdreams")
            .join("cache")
            .join("evm"));
    }
    bail!(
        "can't determine cache directory: neither $XDG_CACHE_HOME, $HOME, nor $LOCALAPPDATA is set"
    )
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

fn rpc_call<T: serde::de::DeserializeOwned>(
    rpc_url: &str,
    method: &str,
    params: &serde_json::Value,
) -> Result<T> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    let serialized = serde_json::to_string(&req).context("serialize RPC request")?;
    let body = agent
        .post(rpc_url)
        .set("Content-Type", "application/json")
        .send_string(&serialized)
        .with_context(|| format!("POST {rpc_url}"))?
        .into_string()
        .context("read RPC response body")?;
    let parsed: RpcResponse<T> =
        serde_json::from_str(&body).with_context(|| format!("parse RPC response: {body}"))?;
    if let Some(err) = parsed.error {
        bail!("RPC error {}: {}", err.code, err.message);
    }
    parsed
        .result
        .ok_or_else(|| anyhow::anyhow!("RPC response missing `result`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_validation() {
        assert_eq!(
            normalize_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        );
        assert!(normalize_address("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").is_err());
        assert!(normalize_address("0x1234").is_err());
        assert!(normalize_address("0xZZ2aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").is_err());
    }

    #[test]
    fn quantities() {
        assert_eq!(parse_quantity("0x1").unwrap(), 1);
        assert_eq!(parse_quantity("0x2105").unwrap(), 8453);
        assert!(parse_quantity("12").is_err());
    }
}
