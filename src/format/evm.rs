//! EVM contract bytecode container.
//!
//! EVM code has no header: a contract is the flat byte string
//! `eth_getCode` returns (runtime code) or the `input` of a creation
//! transaction (initcode, which `CODECOPY`s the runtime out of its own
//! tail). What structure there is comes from compiler conventions:
//!
//! * **Metadata trailer.** solc (since 0.4.7) and vyper (since 0.3.10)
//!   append a CBOR item describing the build (compiler version, IPFS
//!   / Swarm hash of the metadata JSON) followed by its length as a
//!   big-endian `u16`. [`metadata_trailer`] recognises it by requiring
//!   that the claimed span parses as exactly one CBOR item.
//! * **EIP-7702 delegation.** An EOA that delegated to a contract has
//!   code `0xef0100 || address` (23 bytes); [`delegation_target`].
//!
//! Bytecode is often distributed as hex text (`solc --bin`, block
//! explorers, JSON-RPC); [`decode_hex_text`] accepts that form.

use std::fmt::Write as _;

/// Prefix of an EIP-7702 delegation designator.
pub const DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];

/// A recognised compiler metadata trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// Offset of the first CBOR byte. The trailer runs from here to
    /// the end of the code, including the 2-byte length suffix.
    pub offset: usize,
    /// Decoded top-level CBOR item.
    pub value: Cbor,
}

impl Metadata {
    /// Compiler name and version, e.g. `("solc", "0.8.26")`, when the
    /// trailer carries one.
    #[must_use]
    pub fn compiler(&self) -> Option<(&'static str, String)> {
        for (name, key) in [("solc", "solc"), ("vyper", "vyper")] {
            match self.value.find_key(key) {
                Some(Cbor::Bytes(v)) if v.len() == 3 => {
                    return Some((name, format!("{}.{}.{}", v[0], v[1], v[2])));
                }
                Some(Cbor::Text(s)) => return Some((name, s.clone())),
                Some(Cbor::Array(parts)) => {
                    let nums: Vec<String> = parts
                        .iter()
                        .filter_map(|p| match p {
                            Cbor::Uint(n) => Some(n.to_string()),
                            _ => None,
                        })
                        .collect();
                    if nums.len() == parts.len() && !nums.is_empty() {
                        return Some((name, nums.join(".")));
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// `key → rendered value` pairs for every text-keyed map entry,
    /// in trailer order. Byte strings render as `0x…` hex.
    #[must_use]
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        self.value.collect_entries(&mut out);
        out
    }
}

/// The subset of CBOR that compiler metadata uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cbor {
    Uint(u64),
    NegInt(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    /// Depth-first search for a text key in any nested map.
    #[must_use]
    pub fn find_key(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Cbor::Text(t) if t == key => Some(v),
                _ => v.find_key(key),
            }),
            Cbor::Array(items) => items.iter().find_map(|v| v.find_key(key)),
            _ => None,
        }
    }

    fn collect_entries(&self, out: &mut Vec<(String, String)>) {
        match self {
            Cbor::Map(entries) => {
                for (k, v) in entries {
                    if let Cbor::Text(t) = k {
                        if matches!(v, Cbor::Map(_)) {
                            v.collect_entries(out);
                        } else {
                            out.push((t.clone(), v.render()));
                        }
                    }
                }
            }
            Cbor::Array(items) => {
                for v in items {
                    v.collect_entries(out);
                }
            }
            _ => {}
        }
    }

    fn render(&self) -> String {
        match self {
            Cbor::Uint(n) => n.to_string(),
            Cbor::NegInt(n) => format!("-{}", u128::from(*n) + 1),
            Cbor::Bytes(b) => {
                let mut s = String::from("0x");
                for x in b {
                    let _ = write!(s, "{x:02x}");
                }
                s
            }
            Cbor::Text(t) => t.clone(),
            Cbor::Array(items) => {
                let parts: Vec<String> = items.iter().map(Cbor::render).collect();
                format!("[{}]", parts.join(", "))
            }
            Cbor::Map(_) => "{…}".into(),
            Cbor::Bool(b) => b.to_string(),
            Cbor::Null => "null".into(),
        }
    }
}

/// Parse one CBOR item at `bytes[*pos]`, advancing `pos`. Definite
/// lengths only; nesting is capped so hostile input can't recurse
/// deeply.
fn parse_cbor(bytes: &[u8], pos: &mut usize, depth: u32) -> Option<Cbor> {
    if depth > 8 {
        return None;
    }
    let initial = *bytes.get(*pos)?;
    *pos += 1;
    let major = initial >> 5;
    let info = initial & 0x1f;
    let arg = match info {
        0..=23 => u64::from(info),
        24..=27 => {
            let n = 1usize << (info - 24);
            let raw = bytes.get(*pos..*pos + n)?;
            *pos += n;
            raw.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
        }
        _ => return None,
    };
    let take = |pos: &mut usize, len: u64| -> Option<Vec<u8>> {
        let len = usize::try_from(len).ok()?;
        let raw = bytes.get(*pos..pos.checked_add(len)?)?.to_vec();
        *pos += len;
        Some(raw)
    };
    match major {
        0 => Some(Cbor::Uint(arg)),
        1 => Some(Cbor::NegInt(arg)),
        2 => Some(Cbor::Bytes(take(pos, arg)?)),
        3 => Some(Cbor::Text(String::from_utf8(take(pos, arg)?).ok()?)),
        4 => {
            let mut items = Vec::new();
            for _ in 0..arg.min(64) {
                items.push(parse_cbor(bytes, pos, depth + 1)?);
            }
            (arg <= 64).then_some(Cbor::Array(items))
        }
        5 => {
            let mut entries = Vec::new();
            for _ in 0..arg.min(64) {
                let k = parse_cbor(bytes, pos, depth + 1)?;
                let v = parse_cbor(bytes, pos, depth + 1)?;
                entries.push((k, v));
            }
            (arg <= 64).then_some(Cbor::Map(entries))
        }
        7 => match info {
            20 => Some(Cbor::Bool(false)),
            21 => Some(Cbor::Bool(true)),
            22 => Some(Cbor::Null),
            _ => None,
        },
        _ => None,
    }
}

/// Recognise a compiler metadata trailer at the end of `code`.
///
/// The last two bytes give the CBOR length `L`; the trailer is
/// accepted only when `code[len-2-L .. len-2]` is a single CBOR map
/// or array that consumes exactly `L` bytes and mentions a compiler
/// or content-hash key — loose enough for every solc / vyper version
/// that emits one, strict enough that random code tails don't match.
#[must_use]
pub fn metadata_trailer(code: &[u8]) -> Option<Metadata> {
    let n = code.len();
    if n < 2 {
        return None;
    }
    let cbor_len = usize::from(u16::from_be_bytes([code[n - 2], code[n - 1]]));
    if cbor_len == 0 || cbor_len + 2 > n {
        return None;
    }
    let offset = n - 2 - cbor_len;
    let body = &code[offset..n - 2];
    let mut pos = 0;
    let value = parse_cbor(body, &mut pos, 0)?;
    if pos != body.len() || !matches!(value, Cbor::Map(_) | Cbor::Array(_)) {
        return None;
    }
    let known = ["solc", "vyper", "ipfs", "bzzr0", "bzzr1", "experimental"];
    if !known.iter().any(|k| value.find_key(k).is_some()) {
        return None;
    }
    Some(Metadata { offset, value })
}

/// The delegate address of an EIP-7702 delegation designator.
#[must_use]
pub fn delegation_target(code: &[u8]) -> Option<[u8; 20]> {
    if code.len() == 23 && code.starts_with(&DELEGATION_PREFIX) {
        code[3..].try_into().ok()
    } else {
        None
    }
}

/// Heuristic "is this EVM bytecode" check for headerless input.
///
/// Accepts a recognised metadata trailer, an EIP-7702 designator, or
/// solc's free-memory-pointer prologue (`PUSH1 0x80 PUSH1 0x40
/// MSTORE`, or the `0x60`/`0xa0`/… and `DUP1` variants older and
/// via-IR builds emit).
#[must_use]
pub fn looks_like_evm(code: &[u8]) -> bool {
    if delegation_target(code).is_some() || metadata_trailer(code).is_some() {
        return true;
    }
    let prologue = |rest: &[u8]| rest.starts_with(&[0x60, 0x40, 0x52]);
    code.len() >= 5
        && code[0] == 0x60
        && (prologue(&code[2..]) || (code[2] == 0x80 && prologue(&code[3..])))
}

/// Decode bytecode written as hex text: optional `0x` prefix, ASCII
/// hex digits, surrounding whitespace ignored. Returns `None` unless
/// the whole input is hex.
#[must_use]
pub fn decode_hex_text(text: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(text).ok()?.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// solc 0.8.26 via-IR, no IPFS hash: `{"solc": 0x00081a}`.
    const SOLC_ONLY: [u8; 12] = [
        0xa1, 0x64, b's', b'o', b'l', b'c', 0x43, 0x00, 0x08, 0x1a, 0x00, 0x0a,
    ];

    #[test]
    fn solc_version_only_trailer() {
        let mut code = vec![0x60, 0x80, 0x60, 0x40, 0x52, 0xfe];
        code.extend_from_slice(&SOLC_ONLY);
        let md = metadata_trailer(&code).expect("trailer");
        assert_eq!(md.offset, 6);
        assert_eq!(md.compiler(), Some(("solc", "0.8.26".into())));
        assert_eq!(md.entries(), [("solc".to_string(), "0x00081a".to_string())]);
    }

    #[test]
    fn bzzr0_trailer() {
        // solc 0.4.x: {"bzzr0": <32 bytes>} + 0x0029.
        let mut code = vec![0x00, 0xa1, 0x65];
        code.extend_from_slice(b"bzzr0");
        code.extend_from_slice(&[0x58, 0x20]);
        code.extend_from_slice(&[0x11; 32]);
        code.extend_from_slice(&[0x00, 0x29]);
        let md = metadata_trailer(&code).expect("trailer");
        assert_eq!(md.offset, 1);
        assert_eq!(md.compiler(), None);
    }

    #[test]
    fn random_tail_is_not_a_trailer() {
        assert!(metadata_trailer(&[0x60, 0x80, 0x60, 0x40, 0x52, 0x00, 0x03]).is_none());
        // Claimed length runs past the start of the code.
        assert!(metadata_trailer(&[0xa1, 0xff, 0xff]).is_none());
        // Parses, but is a bare integer, not a map.
        assert!(metadata_trailer(&[0x01, 0x00, 0x01]).is_none());
    }

    #[test]
    fn delegation_designator() {
        let mut code = DELEGATION_PREFIX.to_vec();
        code.extend_from_slice(&[0xab; 20]);
        assert_eq!(delegation_target(&code), Some([0xab; 20]));
        assert!(looks_like_evm(&code));
        code.push(0);
        assert_eq!(delegation_target(&code), None);
    }

    #[test]
    fn prologue_detection() {
        assert!(looks_like_evm(&[0x60, 0x80, 0x60, 0x40, 0x52]));
        assert!(looks_like_evm(&[0x60, 0x60, 0x60, 0x40, 0x52]));
        assert!(looks_like_evm(&[0x60, 0xa0, 0x80, 0x60, 0x40, 0x52]));
        assert!(!looks_like_evm(b"\x7fELF\x02\x01"));
    }

    #[test]
    fn hex_text() {
        assert_eq!(decode_hex_text(b"0x6080\n"), Some(vec![0x60, 0x80]));
        assert_eq!(decode_hex_text(b"  60AB "), Some(vec![0x60, 0xab]));
        assert_eq!(decode_hex_text(b"0x608"), None);
        assert_eq!(decode_hex_text(b"0x"), None);
        assert_eq!(decode_hex_text(b"hello!"), None);
    }
}
