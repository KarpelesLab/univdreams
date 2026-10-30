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
//! * **EIP-1167 minimal proxy.** A 45-byte clone that `DELEGATECALL`s
//!   a fixed implementation with the caller's calldata and passes the
//!   result back; [`minimal_proxy`]. Clone factories that append
//!   immutable arguments keep the same code and add data after it.
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
    /// `end`, including the 2-byte length suffix.
    pub offset: usize,
    /// One past the length suffix: the end of the code, except when
    /// data was appended after the trailer (see [`find_metadata`]).
    pub end: usize,
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
#[non_exhaustive]
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
/// Vyper 0.3.10 and later count the two length bytes in `L` (and put
/// the trailer only on initcode, as `[runtime size, data sizes,
/// immutables size, {"vyper": [x, y, z]}]`).
#[must_use]
pub fn metadata_trailer(code: &[u8]) -> Option<Metadata> {
    let n = code.len();
    if n < 2 {
        return None;
    }
    let stated = usize::from(u16::from_be_bytes([code[n - 2], code[n - 1]]));
    let parse = |cbor_len: usize, keys: &[&str]| -> Option<Metadata> {
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
        keys.iter()
            .any(|k| value.find_key(k).is_some())
            .then_some(())?;
        Some(Metadata {
            offset,
            end: n,
            value,
        })
    };
    let known = ["solc", "vyper", "ipfs", "bzzr0", "bzzr1", "experimental"];
    parse(stated, &known).or_else(|| parse(stated.checked_sub(2)?, &["vyper"]))
}

/// The compiler metadata of `code`: the trailer at its end, or else a
/// Vyper trailer followed by data. Vyper appends a contract's
/// immutables to its runtime code at deployment, after the trailer,
/// and reads them back with `CODECOPY`.
#[must_use]
pub fn find_metadata(code: &[u8]) -> Option<Metadata> {
    const KEY: &[u8] = b"\x65vyper";
    if let Some(md) = metadata_trailer(code) {
        return Some(md);
    }
    let mut from = code.len();
    while let Some(pos) = code[..from].windows(KEY.len()).rposition(|w| w == KEY) {
        from = pos;
        // The map header (`0xa1`…) sits right before the first key.
        let Some(start) = pos.checked_sub(1) else {
            break;
        };
        let mut end = start;
        if parse_cbor(code, &mut end, 0).is_some()
            && let Some(md) = code.get(..end + 2).and_then(metadata_trailer)
            && md.offset == start
        {
            return Some(md);
        }
    }
    None
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

/// An EIP-1167 minimal proxy (clone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalProxy {
    /// The implementation every call is delegated to, left-padded to
    /// 20 bytes (vanity addresses with leading zero bytes are pushed
    /// with a shorter `PUSHn`).
    pub target: [u8; 20],
    /// Length of the proxy code; anything after it is appended data
    /// (immutable arguments) that the code itself never runs.
    pub code_len: usize,
}

/// Recognise EIP-1167 minimal-proxy code:
///
/// ```text
/// 363d3d373d3d3d363d 73<20-byte address> 5af43d82803e903d91 602b 57fd5bf3
/// ```
///
/// i.e. `calldatacopy(0, 0, calldatasize)`, `delegatecall(gas, impl,
/// 0, calldatasize, 0, 0)`, copy the return data out and `return` or
/// `revert` it. The address may be pushed with a shorter `PUSHn`, in
/// which case the `JUMPI` target moves with it; trailing bytes are
/// allowed (clones with immutable arguments).
#[must_use]
pub fn minimal_proxy(code: &[u8]) -> Option<MinimalProxy> {
    const HEAD: [u8; 9] = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d];
    const MID: [u8; 9] = [0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91];
    const TAIL: [u8; 4] = [0x57, 0xfd, 0x5b, 0xf3];
    let rest = code.strip_prefix(&HEAD)?;
    let push = *rest.first()?;
    if !(0x60..=0x73).contains(&push) {
        return None;
    }
    let n = usize::from(push - 0x5f);
    let addr = rest.get(1..=n)?;
    let rest = rest[n + 1..].strip_prefix(&MID)?;
    // PUSH1 <offset of the JUMPDEST>
    let dest = HEAD.len() + 1 + n + MID.len() + 2 + 2;
    if rest.first() != Some(&0x60) || rest.get(1).map(|&d| usize::from(d)) != Some(dest) {
        return None;
    }
    rest[2..].strip_prefix(&TAIL)?;
    let mut target = [0u8; 20];
    target[20 - n..].copy_from_slice(addr);
    Some(MinimalProxy {
        target,
        code_len: dest + 2,
    })
}

/// An ERC-5202 blueprint: code that isn't meant to run (it starts
/// with `INVALID`), holding initcode a factory deploys copies of with
/// `create_from_blueprint` (Vyper's `0xFE71` preamble).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blueprint {
    /// Preamble length: `0xFE 0x71`, the version byte, and the data
    /// length that follows when the version byte says so.
    pub preamble_len: usize,
    /// ERC-5202 version (the version byte's upper six bits).
    pub version: u8,
    /// Offset and length of the optional data section, between the
    /// preamble and the initcode.
    pub data: (usize, usize),
    /// Offset of the initcode, which runs to the end.
    pub initcode: usize,
}

/// Recognise an ERC-5202 blueprint: `0xFE 0x71`, a version byte whose
/// low two bits give the size `n` of a big-endian data length (`n ==
/// 3` is reserved), that length, the data, then initcode that must be
/// non-empty.
#[must_use]
pub fn blueprint(code: &[u8]) -> Option<Blueprint> {
    let [0xfe, 0x71, v, ..] = *code else {
        return None;
    };
    let n = usize::from(v & 3);
    if n == 3 {
        return None;
    }
    let len_bytes = code.get(3..3 + n)?;
    let data_len = len_bytes
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    let preamble_len = 3 + n;
    let initcode = preamble_len.checked_add(data_len)?;
    (initcode < code.len()).then_some(Blueprint {
        preamble_len,
        version: v >> 2,
        data: (preamble_len, data_len),
        initcode,
    })
}

/// An address in EIP-55 mixed-case checksum form (`0x` + 40 digits).
#[must_use]
pub fn checksum_address(addr: &[u8; 20]) -> String {
    let mut lower = String::with_capacity(40);
    for b in addr {
        let _ = write!(lower, "{b:02x}");
    }
    let hash = crate::arch::evm::keccak256(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
        out.push(if nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

/// Heuristic "is this EVM bytecode" check for headerless input.
///
/// Accepts a recognised metadata trailer, an EIP-7702 designator, an
/// EIP-1167 minimal proxy, solc's free-memory-pointer prologue
/// (`PUSH1 0x80 PUSH1 0x40 MSTORE`, or the `PUSH2`, `0x60`/`0xa0`/…
/// and `DUP1` variants older, immutable-heavy and via-IR builds
/// emit), or one of Vyper's entry sequences (which have no
/// free-memory pointer):
///
/// * `PUSH1 0 CALLDATALOAD PUSH1 0x1c MSTORE` — vyper 0.1;
/// * `PUSH1 4 CALLDATASIZE LT ISZERO PUSH2` — vyper 0.2;
/// * `PUSH1 3 CALLDATASIZE GT PUSH2` — vyper 0.3;
/// * `PUSH0 CALLDATALOAD PUSH1 0xe0 SHR PUSH1` (or `PUSH1 0` for
///   `PUSH0`) — vyper 0.3.10 and later, whose runtime code carries no
///   trailer and starts with its selector-table dispatcher.
///
/// An ERC-5202 blueprint counts when its initcode does.
#[must_use]
pub fn looks_like_evm(code: &[u8]) -> bool {
    const VYPER: [&[u8]; 5] = [
        &[0x60, 0x00, 0x35, 0x60, 0x1c, 0x52],
        &[0x60, 0x04, 0x36, 0x10, 0x15, 0x61],
        &[0x60, 0x03, 0x36, 0x11, 0x61],
        &[0x5f, 0x35, 0x60, 0xe0, 0x1c, 0x60],
        &[0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c, 0x60],
    ];
    if delegation_target(code).is_some()
        || minimal_proxy(code).is_some()
        || metadata_trailer(code).is_some()
        || blueprint(code).is_some_and(|b| looks_like_evm(&code[b.initcode..]))
    {
        return true;
    }
    let fmp = |rest: &[u8]| {
        let rest = rest.strip_prefix(&[0x80]).unwrap_or(rest);
        rest.starts_with(&[0x60, 0x40, 0x52])
    };
    let solc = match code.first() {
        Some(0x60) => code.get(2..).is_some_and(fmp),
        Some(0x61) => code.get(3..).is_some_and(fmp),
        _ => false,
    };
    solc || VYPER.iter().any(|p| code.starts_with(p))
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
    fn vyper_trailer_before_immutables() {
        // vyper 0.3.7: {"vyper": [0, 3, 7]} + 0x000b, then 64 bytes of
        // immutables appended at deployment.
        let mut code = vec![0x60, 0x00, 0x80, 0xfd];
        code.extend([0xa1, 0x65]);
        code.extend_from_slice(b"vyper");
        code.extend([0x83, 0x00, 0x03, 0x07, 0x00, 0x0b]);
        let end = code.len();
        code.extend([0u8; 63]);
        code.push(0x17);
        assert!(metadata_trailer(&code).is_none());
        let md = find_metadata(&code).expect("inner trailer");
        assert_eq!((md.offset, md.end), (4, end));
        assert_eq!(md.compiler(), Some(("vyper", "0.3.7".into())));
    }

    #[test]
    fn vyper_0310_trailer_counts_its_length() {
        // [runtime size, [data sizes], immutables size, {"vyper": [0, 3,
        // 10]}], with a length that includes its own two bytes.
        let mut code = vec![0x60, 0x00, 0x80, 0xfd];
        code.extend([0x84, 0x19, 0x12, 0x34, 0x81, 0x18, 0x40, 0x00, 0xa1, 0x65]);
        code.extend_from_slice(b"vyper");
        code.extend([0x83, 0x00, 0x03, 0x0a]);
        let cbor = code.len() - 4;
        code.extend(u16::try_from(cbor + 2).unwrap().to_be_bytes());
        let md = metadata_trailer(&code).expect("trailer");
        assert_eq!((md.offset, md.end), (4, code.len()));
        assert_eq!(md.compiler(), Some(("vyper", "0.3.10".into())));
        assert!(looks_like_evm(&code));
    }

    #[test]
    fn erc5202_blueprint() {
        let initcode = [0x60, 0x80, 0x60, 0x40, 0x52, 0x00];
        let mut code = vec![0xfe, 0x71, 0x00];
        code.extend(initcode);
        let bp = blueprint(&code).expect("blueprint");
        assert_eq!(
            (bp.preamble_len, bp.version, bp.data, bp.initcode),
            (3, 0, (3, 0), 3)
        );
        assert!(looks_like_evm(&code));
        // Version 1 with a one-byte data length (2), then the data.
        let mut code = vec![0xfe, 0x71, 0x05, 0x02, 0xaa, 0xbb];
        code.extend(initcode);
        let bp = blueprint(&code).expect("blueprint with data");
        assert_eq!(
            (bp.preamble_len, bp.version, bp.data, bp.initcode),
            (4, 1, (4, 2), 6)
        );
        // Reserved length size, or no initcode.
        assert_eq!(blueprint(&[0xfe, 0x71, 0x03, 0x60]), None);
        assert_eq!(blueprint(&[0xfe, 0x71, 0x00]), None);
        assert!(!looks_like_evm(&[0xfe, 0x71, 0x00, 0x42, 0x42]));
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
        assert!(looks_like_evm(&[0x61, 0x01, 0x00, 0x60, 0x40, 0x52]));
        // Vyper 0.2 / 0.3 entry checks.
        assert!(looks_like_evm(&[0x60, 0x04, 0x36, 0x10, 0x15, 0x61, 0x00]));
        assert!(looks_like_evm(&[0x60, 0x03, 0x36, 0x11, 0x61, 0x00]));
        assert!(!looks_like_evm(b"\x7fELF\x02\x01"));
        assert!(!looks_like_evm(&[0x60, 0x80]));
    }

    fn clone_code(addr: &[u8]) -> Vec<u8> {
        let mut c = vec![0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d];
        c.push(0x5f + u8::try_from(addr.len()).unwrap());
        c.extend_from_slice(addr);
        c.extend([0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91]);
        c.extend([0x60, u8::try_from(addr.len()).unwrap() + 23]);
        c.extend([0x57, 0xfd, 0x5b, 0xf3]);
        c
    }

    #[test]
    fn eip1167_minimal_proxy() {
        let addr = [0xbe; 20];
        let mut code = clone_code(&addr);
        assert_eq!(code.len(), 45);
        assert_eq!(code[40], 0x2b);
        let p = minimal_proxy(&code).expect("clone");
        assert_eq!(p.target, addr);
        assert_eq!(p.code_len, 45);
        assert!(looks_like_evm(&code));
        // Appended immutable arguments.
        code.extend([1, 2, 3]);
        assert_eq!(minimal_proxy(&code).map(|p| p.code_len), Some(45));
        // Vanity address pushed with PUSH18.
        let short = clone_code(&[0x11; 18]);
        let p = minimal_proxy(&short).expect("short clone");
        assert_eq!(p.code_len, 43);
        assert_eq!(&p.target[..2], &[0, 0]);
        // Wrong JUMPI target.
        let mut bad = clone_code(&addr);
        bad[40] = 0x2c;
        assert!(minimal_proxy(&bad).is_none());
    }

    #[test]
    fn eip55_checksum() {
        // From the EIP-55 test vectors.
        let mut a = [0u8; 20];
        let hex = "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        for (i, b) in a.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        assert_eq!(
            checksum_address(&a),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
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
