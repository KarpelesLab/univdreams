//! Test-only fixture-fetch helper.
//!
//! Mirrors the `oxideav-vfw` approach: each codec corpus entry
//! has a stable URL, the resolver walks a tiered lookup
//! (user-staged dir → local cache → HTTPS), and on cache miss
//! the fetched bytes are written back unless `CI=true`.

#![allow(dead_code)]

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Resolve a codec DLL by `name` + the manifest's `base_url`.
///
/// Resolution order:
///
/// 1. `UD_FIXTURE_DIR` env var, if set — first hit anywhere
///    under that directory (case-insensitive on the basename).
/// 2. Local cache: `<CARGO_TARGET_DIR or target>/test-fixture-cache/<NAME>`.
///    Skipped (read + write) when `CI=true`.
/// 3. HTTPS fetch from `<base_url>/<name>`.
///
/// On HTTPS success, step 2's cache is populated (unless
/// `CI=true`).
pub fn fetch_or_load(base_url: &str, name: &str) -> Result<Vec<u8>, FetchError> {
    if let Some(dir) = env::var_os("UD_FIXTURE_DIR") {
        let dir = PathBuf::from(dir);
        if let Some(bytes) = read_case_insensitive(&dir, name)? {
            return Ok(bytes);
        }
    }

    let ci = env::var("CI").is_ok_and(|v| v == "true" || v == "1");

    let cache_path = cache_dir().join(name);
    if !ci && cache_path.is_file() {
        return fs::read(&cache_path).map_err(FetchError::Io);
    }

    let url = format!("{base_url}/{name}");
    let bytes = http_fetch(&url)?;

    if !ci {
        let _ = fs::create_dir_all(cache_dir());
        let _ = fs::write(&cache_path, &bytes);
    }
    Ok(bytes)
}

/// Errors surfaced by [`fetch_or_load`].
#[derive(Debug)]
pub enum FetchError {
    Io(std::io::Error),
    Http { url: String, message: String },
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Io(e) => write!(f, "io: {e}"),
            FetchError::Http { url, message } => write!(f, "HTTPS {url}: {message}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<std::io::Error> for FetchError {
    fn from(e: std::io::Error) -> Self {
        FetchError::Io(e)
    }
}

fn http_fetch(url: &str) -> Result<Vec<u8>, FetchError> {
    let resp = ureq::get(url).call().map_err(|e| FetchError::Http {
        url: url.to_string(),
        message: e.to_string(),
    })?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(FetchError::Io)?;
    Ok(buf)
}

fn read_case_insensitive(dir: &Path, name: &str) -> std::io::Result<Option<Vec<u8>>> {
    if !dir.is_dir() {
        return Ok(None);
    }
    let exact = dir.join(name);
    if exact.is_file() {
        return Ok(Some(fs::read(&exact)?));
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let n = entry.file_name();
        if n.to_string_lossy().eq_ignore_ascii_case(name) {
            return Ok(Some(fs::read(entry.path())?));
        }
        // Recurse one level for the user-staged dir case (the
        // corpus has codecs grouped by family, so a typical
        // staged layout mirrors the URL hierarchy).
        if entry.file_type()?.is_dir() {
            if let Some(bytes) = read_case_insensitive(&entry.path(), name)? {
                return Ok(Some(bytes));
            }
        }
    }
    Ok(None)
}

/// Resolve the cache root: `$CARGO_TARGET_DIR/test-fixture-cache`,
/// or `target/test-fixture-cache` relative to the workspace.
fn cache_dir() -> PathBuf {
    if let Some(target) = env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(target).join("test-fixture-cache");
    }
    let manifest =
        env::var_os("CARGO_MANIFEST_DIR").map_or_else(|| PathBuf::from("."), PathBuf::from);
    // Walk up to the workspace root so all crates share a cache.
    let mut p = manifest;
    while !p.join("Cargo.toml").is_file() || !p.join("crates").is_dir() {
        if !p.pop() {
            break;
        }
    }
    p.join("target").join("test-fixture-cache")
}
