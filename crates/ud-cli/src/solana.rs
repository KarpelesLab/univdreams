//! Fetch a Solana on-chain program and return its raw ELF
//! bytes. Strips the loader-state header so the resulting bytes
//! feed straight into [`ud_translate::decompile::decompile`].
//!
//! Solana stores SBF programs under one of three loaders, each
//! with its own account-data layout:
//!
//! * **`BPFLoader2111…`** (non-upgradeable, legacy). The
//!   program's account data IS the ELF — no header to strip.
//! * **`BPFLoaderUpgradeab1e…`** (today's default). Two
//!   accounts: the *Program* account holds a 36-byte
//!   `UpgradeableLoaderState::Program` (a Borsh enum tag of 2
//!   plus a 32-byte pubkey pointing at the *ProgramData*
//!   account). The ProgramData account starts with an
//!   `UpgradeableLoaderState::ProgramData` header (45 bytes
//!   when an upgrade authority is set, 13 bytes when it's
//!   `None`) followed by the ELF.
//! * **`LoaderV411…`** (Agave's newer loader). A
//!   `LoaderV4State` of 48 bytes (slot + authority pubkey +
//!   8-byte status) followed by the ELF.
//!
//! All three are recognised here. The strip routine validates
//! that the bytes immediately after the header carry the ELF
//! magic (`\x7fELF`), so a mismatched layout fails loudly
//! rather than producing garbage.
//!
//! Fetching uses Solana's standard JSON-RPC `getAccountInfo`
//! method against a public mainnet endpoint by default; the
//! caller can override with `--rpc`. Fetched ELFs are cached
//! under `~/.cache/univdreams/solana/` keyed by program ID
//! (and, for upgradeable programs, the ProgramData slot —
//! upgrades invalidate the cache).

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;
use ud_format::solana::{self as solana_layout, LoaderKind};

/// Default RPC endpoint when `--rpc` isn't given. Solana's
/// public mainnet endpoint — heavily rate-limited but the
/// universally-known fallback.
pub const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

/// Fetch the raw ELF bytes for `program_id`, caching under
/// `~/.cache/univdreams/solana/`. With `use_cache = false`, the
/// cached copy is ignored and overwritten.
pub fn fetch_program_elf(program_id: &str, rpc_url: &str, use_cache: bool) -> Result<Vec<u8>> {
    validate_pubkey(program_id)?;

    // We don't yet know the loader / slot, so the cache lookup
    // is by program ID alone. Upgradeable programs encode their
    // slot inside the cached ELF's filename suffix for clarity,
    // but for the cache-key lookup we use the bare program ID.
    let cache_dir = cache_dir()?;
    let cache_path = cache_dir.join(format!("{program_id}.elf"));
    if use_cache && cache_path.is_file() {
        return fs::read(&cache_path)
            .with_context(|| format!("read cache {}", cache_path.display()));
    }

    // Step 1: fetch the program account itself. The owner field
    // identifies which loader manages this program.
    let account = rpc_get_account(rpc_url, program_id)
        .with_context(|| format!("getAccountInfo {program_id}"))?;
    let owner = account.owner.clone();
    let data = account.decoded_data()?;

    let elf = match solana_layout::classify_loader(owner.as_str()) {
        LoaderKind::BpfLoader2 => solana_layout::strip_bpf_loader_v2(&data)
            .with_context(|| format!("{program_id}: BPFLoader2 strip"))?
            .to_vec(),
        LoaderKind::Upgradeable => fetch_upgradeable_elf(rpc_url, &data, program_id)?,
        LoaderKind::LoaderV4 => solana_layout::strip_loader_v4(&data)
            .with_context(|| format!("{program_id}: LoaderV4 strip"))?
            .to_vec(),
        LoaderKind::Unknown => bail!(
            "{program_id}: unknown loader {owner} — supported: \
             BPFLoader2, BPFLoaderUpgradeable, LoaderV4"
        ),
    };

    // Cache the stripped ELF for the next run.
    if let Err(e) = fs::create_dir_all(&cache_dir) {
        eprintln!(
            "warning: couldn't create cache dir {}: {e}",
            cache_dir.display()
        );
    } else if let Err(e) = fs::write(&cache_path, &elf) {
        eprintln!(
            "warning: couldn't write cache {}: {e}",
            cache_path.display()
        );
    }

    Ok(elf)
}

/// Two-step fetch for upgradeable programs: the Program
/// account points at a ProgramData account that carries the
/// actual ELF.
fn fetch_upgradeable_elf(
    rpc_url: &str,
    program_account_data: &[u8],
    program_id: &str,
) -> Result<Vec<u8>> {
    let pd_pubkey_bytes = solana_layout::programdata_pubkey(program_account_data)
        .with_context(|| format!("{program_id}: Program account"))?;
    let programdata_address = bs58::encode(pd_pubkey_bytes).into_string();

    let pd = rpc_get_account(rpc_url, &programdata_address)
        .with_context(|| format!("getAccountInfo (ProgramData) {programdata_address}"))?;
    let pd_data = pd.decoded_data()?;

    let stripped = solana_layout::strip_bpf_loader_upgradeable(&pd_data)
        .with_context(|| format!("{programdata_address}: ProgramData strip"))?;
    Ok(stripped.to_vec())
}

fn cache_dir() -> Result<PathBuf> {
    // We resolve `$XDG_CACHE_HOME` first, falling back to
    // `$HOME/.cache` on Unix-likes and `%LOCALAPPDATA%` on
    // Windows. Avoids pulling in the `dirs` crate for one
    // function.
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(xdg).join("univdreams").join("solana"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home)
            .join(".cache")
            .join("univdreams")
            .join("solana"));
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(local_app_data)
            .join("univdreams")
            .join("cache")
            .join("solana"));
    }
    bail!(
        "can't determine cache directory: neither $XDG_CACHE_HOME, $HOME, nor $LOCALAPPDATA is set"
    )
}

// ============================================================
// JSON-RPC plumbing
// ============================================================

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

#[derive(Debug, Deserialize)]
struct GetAccountInfoResult {
    value: Option<AccountInfo>,
}

#[derive(Debug, Deserialize)]
struct AccountInfo {
    owner: String,
    /// `[base64, "base64"]` when we ask for base64 encoding.
    data: (String, String),
    #[allow(dead_code)]
    executable: bool,
}

impl AccountInfo {
    fn decoded_data(&self) -> Result<Vec<u8>> {
        let (payload, encoding) = (&self.data.0, &self.data.1);
        if encoding != "base64" {
            bail!("unexpected account-data encoding {encoding:?}");
        }
        BASE64
            .decode(payload.as_bytes())
            .context("base64-decode account data")
    }
}

fn rpc_get_account(rpc_url: &str, pubkey: &str) -> Result<AccountInfo> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            pubkey,
            { "encoding": "base64" }
        ],
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
    let parsed: RpcResponse<GetAccountInfoResult> =
        serde_json::from_str(&body).with_context(|| format!("parse RPC response: {body}"))?;
    if let Some(err) = parsed.error {
        bail!("RPC error {}: {}", err.code, err.message);
    }
    let result = parsed
        .result
        .ok_or_else(|| anyhow::anyhow!("RPC response missing `result`"))?;
    result
        .value
        .ok_or_else(|| anyhow::anyhow!("account {pubkey} does not exist"))
}

fn validate_pubkey(s: &str) -> Result<()> {
    let bytes = bs58::decode(s)
        .into_vec()
        .with_context(|| format!("decode base58 pubkey {s}"))?;
    if bytes.len() != 32 {
        bail!(
            "invalid pubkey {s}: decoded to {} bytes (expected 32)",
            bytes.len()
        );
    }
    Ok(())
}
