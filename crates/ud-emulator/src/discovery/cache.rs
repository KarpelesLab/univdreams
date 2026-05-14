//! On-disk JSON cache of discovery results.
//!
//! Schema: array of [`CacheEntry`]. Lookups are keyed by
//! `(absolute_path, mtime_unix, size_bytes)`. A mismatch on any
//! of those three is treated as a cache miss; on miss we re-probe
//! and overwrite the entry. Atomic writes via tempfile + rename.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::probe::Kind;
use super::DiscoveryEntry;

/// One cache row. Mirrors [`DiscoveryEntry`] verbatim — the
/// separate type exists so we can freely evolve the in-memory
/// representation without rewriting the on-disk schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub path: PathBuf,
    pub mtime_unix: i64,
    pub size_bytes: u64,
    pub kind: String,
    pub fourccs: Vec<String>,
    pub clsid: Option<String>,
    /// Reserved for round-29 — round-trip a captured handshake
    /// transcript so we can replay reverse-engineered protocols
    /// without re-driving the codec on every register call.
    pub handshake: Option<serde_json::Value>,
}

impl CacheEntry {
    fn from_entry(e: &DiscoveryEntry) -> Self {
        CacheEntry {
            path: e.path.clone(),
            mtime_unix: e.mtime_unix,
            size_bytes: e.size_bytes,
            kind: kind_to_str(e.kind).to_string(),
            fourccs: e.fourccs.clone(),
            clsid: e.clsid.clone(),
            handshake: None,
        }
    }

    fn to_entry(&self) -> DiscoveryEntry {
        DiscoveryEntry {
            path: self.path.clone(),
            mtime_unix: self.mtime_unix,
            size_bytes: self.size_bytes,
            kind: str_to_kind(&self.kind),
            fourccs: self.fourccs.clone(),
            clsid: self.clsid.clone(),
        }
    }
}

fn kind_to_str(k: Kind) -> &'static str {
    match k {
        Kind::Vfw => "vfw",
        Kind::DirectShow => "directshow",
        Kind::Unsupported => "unsupported",
    }
}

fn str_to_kind(s: &str) -> Kind {
    match s {
        "vfw" => Kind::Vfw,
        "directshow" => Kind::DirectShow,
        _ => Kind::Unsupported,
    }
}

/// In-memory cache. Loads / saves a flat JSON array.
#[derive(Debug, Default, Clone)]
pub struct Cache {
    entries: Vec<CacheEntry>,
}

impl Cache {
    /// Read `path`. Returns an empty cache on any I/O / parse
    /// failure (corrupted on-disk cache must never poison
    /// `register()`).
    pub fn load(path: &Path) -> Option<Self> {
        let data = fs::read(path).ok()?;
        let entries: Vec<CacheEntry> = serde_json::from_slice(&data).ok()?;
        Some(Cache { entries })
    }

    /// Look up by `(path, mtime, size)`. Stale entries (mtime or
    /// size mismatch) return `None`.
    pub fn lookup(&self, path: &Path, mtime: i64, size: u64) -> Option<DiscoveryEntry> {
        for e in &self.entries {
            if e.path == path && e.mtime_unix == mtime && e.size_bytes == size {
                return Some(e.to_entry());
            }
        }
        None
    }

    /// Insert or overwrite. If an entry for `entry.path` already
    /// exists (regardless of mtime/size), it is replaced.
    pub fn upsert(&mut self, entry: DiscoveryEntry) {
        let row = CacheEntry::from_entry(&entry);
        if let Some(pos) = self.entries.iter().position(|e| e.path == entry.path) {
            self.entries[pos] = row;
        } else {
            self.entries.push(row);
        }
    }

    /// Atomic write: serialise to a sibling tempfile, then
    /// rename. On any failure, leaves the original cache intact.
    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = tempfile_sibling(path);
        // Pretty-printed JSON — discovery output is human-grep-friendly.
        let json = serde_json::to_vec_pretty(&self.entries).map_err(io_err)?;
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    /// Total entry count — diagnostic only.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no entries are stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn io_err(e: serde_json::Error) -> std::io::Error {
    std::io::Error::other(e)
}

/// Build a tempfile path next to `target` for an atomic write.
fn tempfile_sibling(target: &Path) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut s = target.as_os_str().to_owned();
    s.push(format!(".tmp.{pid}.{nanos}"));
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::test_tmpdir::Tmp;

    fn sample_entry(path: &Path, kind: Kind) -> DiscoveryEntry {
        DiscoveryEntry {
            path: path.to_path_buf(),
            mtime_unix: 1_700_000_000,
            size_bytes: 524_288,
            kind,
            fourccs: vec!["MP43".into(), "MP42".into()],
            clsid: None,
        }
    }

    #[test]
    fn round_trip_preserves_entries() {
        let tmp = Tmp::new("cache");
        let cache_path = tmp.path().join("disc.json");
        let mut c = Cache::default();
        c.upsert(sample_entry(Path::new("/abs/a.dll"), Kind::Vfw));
        c.upsert(sample_entry(Path::new("/abs/b.ax"), Kind::DirectShow));
        c.save_atomic(&cache_path).unwrap();

        let loaded = Cache::load(&cache_path).unwrap();
        assert_eq!(loaded.len(), 2);
        let look = loaded
            .lookup(Path::new("/abs/a.dll"), 1_700_000_000, 524_288)
            .unwrap();
        assert_eq!(look.kind, Kind::Vfw);
        assert_eq!(look.fourccs, vec!["MP43".to_string(), "MP42".to_string()]);
    }

    #[test]
    fn lookup_misses_on_mtime_change() {
        let mut c = Cache::default();
        c.upsert(sample_entry(Path::new("/abs/a.dll"), Kind::Vfw));
        // size matches but mtime is different → miss.
        assert!(c
            .lookup(Path::new("/abs/a.dll"), 1_700_000_001, 524_288)
            .is_none());
    }

    #[test]
    fn lookup_misses_on_size_change() {
        let mut c = Cache::default();
        c.upsert(sample_entry(Path::new("/abs/a.dll"), Kind::Vfw));
        assert!(c
            .lookup(Path::new("/abs/a.dll"), 1_700_000_000, 999_999)
            .is_none());
    }

    #[test]
    fn upsert_overwrites_same_path() {
        let mut c = Cache::default();
        c.upsert(sample_entry(Path::new("/abs/a.dll"), Kind::Vfw));
        let mut second = sample_entry(Path::new("/abs/a.dll"), Kind::DirectShow);
        second.fourccs = vec!["WMV3".into()];
        c.upsert(second);
        assert_eq!(c.len(), 1);
        let look = c
            .lookup(Path::new("/abs/a.dll"), 1_700_000_000, 524_288)
            .unwrap();
        assert_eq!(look.kind, Kind::DirectShow);
        assert_eq!(look.fourccs, vec!["WMV3".to_string()]);
    }

    #[test]
    fn load_missing_file_returns_none() {
        let tmp = Tmp::new("missing");
        let path = tmp.path().join("absent.json");
        assert!(Cache::load(&path).is_none());
    }

    #[test]
    fn load_corrupted_file_returns_none() {
        let tmp = Tmp::new("corrupt");
        let path = tmp.path().join("bad.json");
        fs::write(&path, b"{not valid json").unwrap();
        assert!(Cache::load(&path).is_none());
    }
}
