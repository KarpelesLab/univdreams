//! Byte-pattern signature database for recognizing well-known
//! functions in compiled binaries.
//!
//! v0 scope: CRT helpers that GCC's linker injects into ELF
//! executables on x86-64 (`deregister_tm_clones`, `register_tm_clones`,
//! `__do_global_dtors_aux`, `frame_dummy`). These don't appear in the
//! symbol table or `.eh_frame`, so without signatures they'd surface
//! as anonymous `@raw` blocks in `.text`.
//!
//! Each [`Signature`] is a sequence of [`PatternByte`]s where every
//! position is either an exact byte or a wildcard. Wildcards are how
//! we ignore relocation-dependent fields (RIP-relative displacements,
//! short-jump targets) without giving up matching power.
//!
//! Matching is byte-exact at the pattern positions, so the engine has
//! no architectural state. Per-arch signature DBs (this is the x86-64
//! one) live alongside.

#![allow(clippy::cast_possible_truncation)]

mod x86_64;

pub use x86_64::CRT_HELPERS_X86_64;

/// One byte position inside a [`Signature::pattern`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByte {
    /// Must equal this byte exactly.
    Exact(u8),
    /// Any byte matches. Use for relocation-dependent positions
    /// (displacements, immediates that vary across builds).
    Wild,
}

/// Construct a [`PatternByte`] array. `_` produces [`PatternByte::Wild`];
/// numeric literals produce [`PatternByte::Exact`].
///
/// ```
/// use ud_signatures::{pat, PatternByte};
/// let p = pat!(0x48, 0x8d, _, _, _, _, _);
/// assert_eq!(p[0], PatternByte::Exact(0x48));
/// assert_eq!(p[2], PatternByte::Wild);
/// ```
#[macro_export]
macro_rules! pat {
    ($($b:tt),* $(,)?) => {
        &[ $($crate::pat_byte!($b)),* ]
    };
}

/// Internal helper for [`pat!`]. Public so the macro can expand it.
#[doc(hidden)]
#[macro_export]
macro_rules! pat_byte {
    (_) => {
        $crate::PatternByte::Wild
    };
    ($b:literal) => {
        $crate::PatternByte::Exact($b)
    };
}

/// One named byte pattern.
#[derive(Debug)]
pub struct Signature {
    /// The function's canonical name.
    pub name: &'static str,

    /// Byte pattern matched at the function's start.
    pub pattern: &'static [PatternByte],
}

/// One match: a [`Signature`] hit at a specific virtual address.
#[derive(Debug, Clone)]
pub struct Match {
    pub addr: u64,
    pub name: &'static str,
}

/// Returns true if `bytes[..pattern.len()]` matches `pattern`. False
/// when bytes is too short.
#[must_use]
pub fn pattern_matches_at(bytes: &[u8], pattern: &[PatternByte]) -> bool {
    if bytes.len() < pattern.len() {
        return false;
    }
    for (i, p) in pattern.iter().enumerate() {
        if let PatternByte::Exact(b) = p {
            if bytes[i] != *b {
                return false;
            }
        }
    }
    true
}

/// Scan `bytes` (representing data at `base_addr` in some address
/// space) for any signature in `db`. Returns one [`Match`] per hit, in
/// ascending address order. Multiple signatures matching at the same
/// offset all produce hits — the caller decides how to disambiguate.
#[must_use]
pub fn scan(bytes: &[u8], base_addr: u64, db: &'static [Signature]) -> Vec<Match> {
    let mut matches = Vec::new();
    for sig in db {
        if sig.pattern.is_empty() || sig.pattern.len() > bytes.len() {
            continue;
        }
        let last = bytes.len() - sig.pattern.len();
        for offset in 0..=last {
            if pattern_matches_at(&bytes[offset..], sig.pattern) {
                matches.push(Match {
                    addr: base_addr + offset as u64,
                    name: sig.name,
                });
            }
        }
    }
    matches.sort_by_key(|m| m.addr);
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pat_macro_produces_pattern_bytes() {
        let p: &[PatternByte] = pat!(0x48, 0x8d, _, _, _, _, _);
        assert_eq!(p.len(), 7);
        assert_eq!(p[0], PatternByte::Exact(0x48));
        assert_eq!(p[1], PatternByte::Exact(0x8d));
        assert_eq!(p[2], PatternByte::Wild);
        assert_eq!(p[6], PatternByte::Wild);
    }

    #[test]
    fn pattern_matches_with_wildcards() {
        let p: &[PatternByte] = pat!(0x48, _, 0x05);
        assert!(pattern_matches_at(&[0x48, 0xff, 0x05, 0xab], p));
        assert!(pattern_matches_at(&[0x48, 0x00, 0x05, 0xab], p));
        assert!(!pattern_matches_at(&[0x48, 0xff, 0x06, 0xab], p));
        assert!(!pattern_matches_at(&[0x49, 0xff, 0x05, 0xab], p));
    }

    #[test]
    fn pattern_matches_too_short() {
        let p: &[PatternByte] = pat!(0x48, _);
        assert!(!pattern_matches_at(&[0x48], p));
        assert!(!pattern_matches_at(&[], p));
    }

    #[test]
    fn scan_returns_matches_in_address_order() {
        static DB: &[Signature] = &[
            Signature {
                name: "a",
                pattern: pat!(0xaa),
            },
            Signature {
                name: "b",
                pattern: pat!(0xbb),
            },
        ];
        let bytes = [0xbb, 0xff, 0xaa, 0xff, 0xbb];
        let m = scan(&bytes, 0x1000, DB);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].addr, 0x1000);
        assert_eq!(m[0].name, "b");
        assert_eq!(m[1].addr, 0x1002);
        assert_eq!(m[1].name, "a");
        assert_eq!(m[2].addr, 0x1004);
        assert_eq!(m[2].name, "b");
    }
}
