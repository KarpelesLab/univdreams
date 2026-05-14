//! Auto-discovery — round 28.
//!
//! At [`crate::register`] time we walk a discovery path, probe
//! every loadable `*.dll` / `*.ax` for a VfW or DirectShow entry
//! point, and register one [`oxideav_core::CodecInfo`] per
//! recognised FourCC into [`oxideav_core::RuntimeContext::codecs`].
//!
//! ### Discovery path resolution
//!
//! - `OXIDEAV_VFW_CODEC_PATH=/p1:/p2` (colon-separated on UNIX,
//!   `;`-separated on Windows) **replaces** the default — empty
//!   strings between separators and unreadable directories are
//!   skipped silently.
//! - Default (env var unset):
//!     - UNIX: `$XDG_DATA_HOME/oxideav/codecs/` or
//!       `$HOME/.local/share/oxideav/codecs/`.
//!     - Windows: `%LOCALAPPDATA%\oxideav\codecs\`.
//!
//! Walks each path **non-recursively** for `*.dll` and `*.ax`.
//! Files that aren't valid PE32 (or that simply lack the codec
//! entry points we know how to drive) are skipped silently with a
//! `log::debug!` — discovery never panics at register time.
//!
//! ### Probe priority
//!
//! 1. **VfW** — call `Sandbox::load` then drive
//!    `DRV_LOAD → ICOpen('VIDC', candidate_fcc) → ICGetInfo`. Try
//!    a small fixed FourCC sweep (`MP43 / MP42 / MPG4 / DIV3 /
//!    IV31 / IV41 / IV50 / CVID / MJPG`). Each FourCC the codec
//!    accepts becomes one [`DiscoveryEntry`] tagged
//!    [`Kind::Vfw`].
//! 2. **DirectShow** — try `DllGetClassObject` with a short
//!    static CLSID candidate list (the wmpcdcs8-2001 known
//!    binaries — `MPG4DS32.AX`'s factory CLSID `{82CCD3E0-…}`).
//!    Candidates that succeed are recorded as
//!    [`Kind::DirectShow`]; their FourCCs are extracted from
//!    `IPin::EnumMediaTypes` (deferred — round 29 wires the full
//!    AMT walk; this round records the CLSID + leaves
//!    `fourccs` empty if the AMT walk fails).
//! 3. Anything that exports neither `DriverProc` nor a
//!    recognisable `DllGetClassObject` CLSID is recorded as
//!    [`Kind::Unsupported`] so we don't re-probe on the next
//!    `register()` call.
//!
//! ### Cache
//!
//! Discovery results are cached at
//! `$XDG_CACHE_HOME/oxideav/vfw-discovery.json`
//! (or `$HOME/.cache/oxideav/vfw-discovery.json`,
//! or `%LOCALAPPDATA%\oxideav\Cache\vfw-discovery.json`),
//! keyed by `(absolute_path, mtime, size_bytes)`. A stale entry
//! (mtime or size mismatch) is treated as a cache miss; on miss
//! we re-probe and overwrite the entry. The cache is written
//! atomically (tempfile + rename).
//!
//! See `docs/winmf/winmf-emulator.md` for the broader sandbox
//! design contract.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

mod cache;
mod codec;
mod paths;
mod probe;

pub use cache::{Cache, CacheEntry};
pub use codec::{
    codec_id_for, last_codec_allocator_negotiation, lookup_record, make_decoder,
    output_pixel_format, register_factory_for_id, CodecAllocatorNegotiation, DiscoveryRecord,
};
pub use paths::{cache_file_path, discovery_paths};
pub use probe::Kind;

/// Whether the `register()` cascade should silently skip a missing
/// discovery directory (the default — true) or surface it as a
/// `log::warn!` (false). Tests flip this off to assert "directory
/// missing" still produces zero codecs cleanly.
const ALLOW_MISSING_DIR: bool = true;

/// One probed DLL → its (possibly empty) list of recognised
/// FourCCs. The cache JSON stores a `Vec` of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryEntry {
    pub path: PathBuf,
    pub mtime_unix: i64,
    pub size_bytes: u64,
    pub kind: Kind,
    pub fourccs: Vec<String>,
    pub clsid: Option<String>,
}

impl DiscoveryEntry {
    /// True if `(absolute_path, mtime, size)` matches `path` —
    /// used by the cache layer to decide whether to honour or
    /// invalidate a stored entry.
    pub fn matches(&self, path: &Path, mtime: i64, size: u64) -> bool {
        self.path == path && self.mtime_unix == mtime && self.size_bytes == size
    }
}

/// Top-level discovery entry point. Walks `paths`, probes every
/// `*.dll` / `*.ax` in each, consults / updates the on-disk
/// cache, and returns the merged list.
///
/// Hard contract: never panics, never returns an error type. A
/// single bad DLL is silently skipped with `log::debug!`. The
/// outer caller (`crate::register`) is therefore safe to chain
/// multiple `register` calls without a panic-aborting path.
pub fn discover(paths: &[PathBuf]) -> Vec<DiscoveryEntry> {
    let cache_path = cache_file_path();
    let mut cache = Cache::load(&cache_path).unwrap_or_default();

    let mut out: Vec<DiscoveryEntry> = Vec::new();
    for dir in paths {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => {
                if !ALLOW_MISSING_DIR {
                    log::warn!("vfw discovery: cannot read {:?}", dir);
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_codec_candidate(&path) {
                continue;
            }
            let (mtime, size) = match file_meta(&path) {
                Some(m) => m,
                None => continue,
            };
            // Cache hit?
            if let Some(cached) = cache.lookup(&path, mtime, size) {
                out.push(cached.clone());
                continue;
            }
            // Cache miss — probe.
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    log::debug!("vfw discovery: read {:?} failed: {e}", path);
                    continue;
                }
            };
            let probed = probe::probe_bytes(&bytes);
            let entry = DiscoveryEntry {
                path: path.clone(),
                mtime_unix: mtime,
                size_bytes: size,
                kind: probed.kind,
                fourccs: probed.fourccs,
                clsid: probed.clsid,
            };
            cache.upsert(entry.clone());
            out.push(entry);
        }
    }
    // Best-effort write — never let a cache I/O failure poison
    // discovery itself.
    let _ = cache.save_atomic(&cache_path);
    out
}

/// Read the file's `(mtime_unix, size_bytes)` pair. Returns
/// `None` on stat failure — discovery treats those files as
/// unreadable and skips them silently.
fn file_meta(path: &Path) -> Option<(i64, u64)> {
    let md = fs::metadata(path).ok()?;
    let size = md.len();
    let mtime = md.modified().ok().and_then(systime_to_unix).unwrap_or(0);
    Some((mtime, size))
}

fn systime_to_unix(t: SystemTime) -> Option<i64> {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => Some(d.as_secs() as i64),
        Err(e) => Some(-(e.duration().as_secs() as i64)),
    }
}

/// True for `*.dll` / `*.ax`, case-insensitive.
fn is_codec_candidate(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => {
            let lower = ext.to_ascii_lowercase();
            lower == "dll" || lower == "ax"
        }
        None => false,
    }
}

/// Public entry — walks the configured discovery path, probes,
/// and registers each result into the codec registry.
///
/// Hard contract: never panics, never errors out. Always returns
/// the count of registered codecs (zero is fine — that's what
/// happens on a stock CI box that has no codecs to discover).
pub fn discover_and_register(ctx: &mut oxideav_core::RuntimeContext) -> usize {
    let paths = discovery_paths();
    let entries = discover(&paths);
    let mut registered = 0usize;
    let mut fourccs_seen: Vec<String> = Vec::new();
    for entry in entries {
        if matches!(entry.kind, Kind::Unsupported) {
            log::debug!("vfw discovery: {:?} is unsupported", entry.path);
            continue;
        }
        for fcc in &entry.fourccs {
            let codec_id_str = codec::codec_id_for(&entry.path, fcc);
            codec::register_factory_for_id(
                &codec_id_str,
                DiscoveryRecord {
                    dll_path: entry.path.clone(),
                    fourcc: fcc.clone(),
                    kind: entry.kind,
                    clsid: entry.clsid.clone(),
                },
            );
            codec::register_codec_info(ctx, &codec_id_str, fcc);
            fourccs_seen.push(fcc.clone());
            registered += 1;
        }
    }
    log::debug!(
        "vfw: discovered {} codecs from {:?}: {:?}",
        registered,
        paths,
        fourccs_seen
    );
    registered
}

#[cfg(test)]
pub(crate) mod test_tmpdir {
    //! Tiny zero-dep tempdir helper. We deliberately avoid
    //! taking a `tempfile` dev-dep just for these tests.
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct Tmp(pub PathBuf);

    impl Tmp {
        pub fn new(label: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path =
                std::env::temp_dir().join(format!("oxideav-vfw-disc-{label}-{pid}-{nanos}-{n}"));
            std::fs::create_dir_all(&path).unwrap();
            Tmp(path)
        }
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_tmpdir::Tmp;
    use super::*;
    use std::io::Write;

    #[test]
    fn discovery_on_nonexistent_path_returns_empty_cleanly() {
        let entries = discover(&[PathBuf::from("/this/does/not/exist/anywhere")]);
        assert!(entries.is_empty());
    }

    #[test]
    fn discovery_on_empty_dir_returns_empty() {
        let tmp = Tmp::new("empty");
        let entries = discover(&[tmp.path().to_path_buf()]);
        assert!(entries.is_empty());
    }

    #[test]
    fn discovery_skips_non_pe_files() {
        let tmp = Tmp::new("nonpe");
        let bogus = tmp.path().join("garbage.dll");
        let mut f = fs::File::create(&bogus).unwrap();
        f.write_all(b"this is not a PE32 file").unwrap();
        let entries = discover(&[tmp.path().to_path_buf()]);
        // Probe runs but yields Unsupported; entry IS recorded
        // (so we don't re-probe next time) but with empty FourCCs.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, Kind::Unsupported);
        assert!(entries[0].fourccs.is_empty());
    }

    #[test]
    fn is_codec_candidate_matches_dll_and_ax() {
        let tmp = Tmp::new("ext");
        let dll = tmp.path().join("foo.DLL");
        let ax = tmp.path().join("bar.Ax");
        let txt = tmp.path().join("baz.txt");
        for p in [&dll, &ax, &txt] {
            fs::File::create(p).unwrap();
        }
        assert!(is_codec_candidate(&dll));
        assert!(is_codec_candidate(&ax));
        assert!(!is_codec_candidate(&txt));
    }
}
