//! Path resolution for the discovery directory + on-disk cache.
//!
//! Resolution order is documented on [`super`].
//!
//! No new dependencies — we read the relevant env vars directly
//! (`OXIDEAV_VFW_CODEC_PATH`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`,
//! `HOME`, `LOCALAPPDATA`) using `std::env::var_os` so non-UTF8
//! values still resolve.

use std::env;
use std::path::PathBuf;

/// On Windows, the platform separator for path lists is `;` — on
/// every other target we follow the conventional `:`.
#[cfg(windows)]
const PATH_SEP: char = ';';
#[cfg(not(windows))]
const PATH_SEP: char = ':';

/// Resolve the list of directories `discover()` should walk.
///
/// `OXIDEAV_VFW_CODEC_PATH=<list>` overrides the default and is
/// returned verbatim. Empty entries (e.g. `::` or a trailing
/// separator) are skipped silently. The default is a single-entry
/// list pointing at the platform-conventional codec directory.
///
/// Hard contract: never panics. Returns an empty `Vec` only when
/// no env var is set and the platform default cannot be resolved
/// (e.g. `HOME` and `LOCALAPPDATA` both unset — extremely
/// unusual).
pub fn discovery_paths() -> Vec<PathBuf> {
    if let Some(over) = env::var_os("OXIDEAV_VFW_CODEC_PATH") {
        return parse_path_list(&over);
    }
    default_discovery_paths()
}

/// Default discovery directory list (env var unset).
fn default_discovery_paths() -> Vec<PathBuf> {
    if let Some(d) = platform_default_codec_dir() {
        vec![d]
    } else {
        Vec::new()
    }
}

#[cfg(windows)]
fn platform_default_codec_dir() -> Option<PathBuf> {
    if let Some(local) = env::var_os("LOCALAPPDATA") {
        let p = PathBuf::from(local).join("oxideav").join("codecs");
        return Some(p);
    }
    None
}

#[cfg(not(windows))]
fn platform_default_codec_dir() -> Option<PathBuf> {
    if let Some(xdg) = env::var_os("XDG_DATA_HOME") {
        let p = PathBuf::from(xdg).join("oxideav").join("codecs");
        return Some(p);
    }
    if let Some(home) = env::var_os("HOME") {
        let p = PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("oxideav")
            .join("codecs");
        return Some(p);
    }
    None
}

/// Split a `PATH`-style list (`:`/`;`-separated, depending on
/// platform) into individual directory entries. Empty components
/// are filtered out.
fn parse_path_list(value: &std::ffi::OsStr) -> Vec<PathBuf> {
    // Convert via lossy string for splitting — paths that round-trip
    // through this lose sub-codepoint detail on weird inputs, but the
    // discovery path list is a user-facing config so UTF-8 is fine.
    let s = value.to_string_lossy();
    s.split(PATH_SEP)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Resolve the on-disk JSON cache file location.
pub fn cache_file_path() -> PathBuf {
    if let Some(p) = platform_cache_dir() {
        p.join("vfw-discovery.json")
    } else {
        // Pathological fallback — current working directory.
        PathBuf::from("vfw-discovery.json")
    }
}

#[cfg(windows)]
fn platform_cache_dir() -> Option<PathBuf> {
    if let Some(local) = env::var_os("LOCALAPPDATA") {
        let p = PathBuf::from(local).join("oxideav").join("Cache");
        return Some(p);
    }
    None
}

#[cfg(not(windows))]
fn platform_cache_dir() -> Option<PathBuf> {
    if let Some(xdg) = env::var_os("XDG_CACHE_HOME") {
        let p = PathBuf::from(xdg).join("oxideav");
        return Some(p);
    }
    if let Some(home) = env::var_os("HOME") {
        let p = PathBuf::from(home).join(".cache").join("oxideav");
        return Some(p);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn parse_empty_components_skipped() {
        let s = OsString::from(format!("{0}/a{0}{0}/b{0}", PATH_SEP));
        let v = parse_path_list(&s);
        assert_eq!(v, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    #[test]
    fn parse_single_component() {
        let s = OsString::from("/only/one");
        let v = parse_path_list(&s);
        assert_eq!(v, vec![PathBuf::from("/only/one")]);
    }

    #[test]
    fn discovery_paths_honours_override() {
        // Saved/restored manually so we don't poison sibling tests.
        let saved = env::var_os("OXIDEAV_VFW_CODEC_PATH");
        env::set_var(
            "OXIDEAV_VFW_CODEC_PATH",
            format!("/dev/null{0}/tmp/nonexistent", PATH_SEP),
        );
        let paths = discovery_paths();
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/dev/null"),
                PathBuf::from("/tmp/nonexistent"),
            ]
        );
        match saved {
            Some(v) => env::set_var("OXIDEAV_VFW_CODEC_PATH", v),
            None => env::remove_var("OXIDEAV_VFW_CODEC_PATH"),
        }
    }

    #[test]
    fn cache_file_path_basename() {
        let p = cache_file_path();
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("vfw-discovery.json")
        );
    }
}
