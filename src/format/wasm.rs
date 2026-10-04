//! WebAssembly binary container — parse + byte-identical write.
//!
//! WASM modules are a flat sequence of *sections*:
//!
//! ```text
//!   magic    : '\0' 'a' 's' 'm'         (4 bytes)
//!   version  : u32 little-endian        (4 bytes; 1 for current MVP)
//!   sections : (section_id:u8, size:LEB128, body:[u8; size])*
//! ```
//!
//! For round-trip byte identity we preserve every byte of the
//! header and every section. LEB128 size encodings vary in
//! width — LLVM pads them to 5 bytes so post-link patching
//! can adjust section sizes without shifting the rest of the
//! module — and `WasmFile` keeps the encoded form verbatim so
//! a parse → write_to_vec cycle reproduces the input exactly.
//!
//! Section interpretation (decoding function bodies, names,
//! types, …) lives in higher layers. The format crate only
//! offers: where each section starts, what its id is, and a
//! handle to its raw bytes.

use std::ops::Range;

/// 4-byte WASM magic.
pub const MAGIC: [u8; 4] = [0x00, b'a', b's', b'm'];

/// Errors raised by [`WasmFile::parse`].
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("buffer too short ({len} bytes); needs at least 8 for magic + version")]
    TooShort { len: usize },
    #[error("bad magic {magic:?}; expected {:?}", MAGIC)]
    BadMagic { magic: [u8; 4] },
    #[error("section header at offset {at:#x} truncated")]
    SectionTruncated { at: usize },
    #[error("section size LEB128 at offset {at:#x} doesn't terminate")]
    LebOverflow { at: usize },
    #[error("section size LEB128 at offset {at:#x} encodes value > usize::MAX")]
    LebTooLarge { at: usize },
    #[error("section at offset {at:#x} declares size {size} that runs past end of buffer")]
    SectionRunsPastEnd { at: usize, size: u64 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Standard section IDs. The custom id (0) groups everything
/// non-standard — debug info, name maps, producer metadata, …
pub const SECTION_CUSTOM: u8 = 0;
pub const SECTION_TYPE: u8 = 1;
pub const SECTION_IMPORT: u8 = 2;
pub const SECTION_FUNCTION: u8 = 3;
pub const SECTION_TABLE: u8 = 4;
pub const SECTION_MEMORY: u8 = 5;
pub const SECTION_GLOBAL: u8 = 6;
pub const SECTION_EXPORT: u8 = 7;
pub const SECTION_START: u8 = 8;
pub const SECTION_ELEMENT: u8 = 9;
pub const SECTION_CODE: u8 = 10;
pub const SECTION_DATA: u8 = 11;
pub const SECTION_DATA_COUNT: u8 = 12;

/// Metadata for one section, located by byte range into the
/// parent [`WasmFile`]'s `bytes`. The `header_range` covers
/// the section id byte plus the size-LEB; `body_range` covers
/// just the section's payload.
#[derive(Debug, Clone)]
pub struct Section {
    pub id: u8,
    pub header_range: Range<usize>,
    pub body_range: Range<usize>,
}

/// A parsed WASM module. `bytes` is the verbatim input; the
/// `sections` list records where each section starts and ends
/// so callers can read or rewrite them without re-parsing.
#[derive(Debug, Clone)]
pub struct WasmFile {
    pub bytes: Vec<u8>,
    pub version: u32,
    pub sections: Vec<Section>,
}

impl WasmFile {
    /// Parse `bytes` into a [`WasmFile`]. The bytes are
    /// retained verbatim so [`Self::write_to_vec`] can
    /// reproduce them.
    #[allow(clippy::missing_errors_doc)]
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::TooShort { len: bytes.len() });
        }
        let magic: [u8; 4] = bytes[0..4].try_into().expect("4-byte prefix");
        if magic != MAGIC {
            return Err(Error::BadMagic { magic });
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().expect("4-byte prefix"));

        let mut sections = Vec::new();
        let mut cursor = 8usize;
        while cursor < bytes.len() {
            if cursor + 1 > bytes.len() {
                return Err(Error::SectionTruncated { at: cursor });
            }
            let id = bytes[cursor];
            let header_start = cursor;
            cursor += 1;
            let (size, size_len) = read_leb128_u32(bytes, cursor)?;
            cursor += size_len;
            let body_start = cursor;
            let size_us = size as usize;
            let body_end = body_start
                .checked_add(size_us)
                .ok_or(Error::SectionRunsPastEnd {
                    at: header_start,
                    size: u64::from(size),
                })?;
            if body_end > bytes.len() {
                return Err(Error::SectionRunsPastEnd {
                    at: header_start,
                    size: u64::from(size),
                });
            }
            sections.push(Section {
                id,
                header_range: header_start..body_start,
                body_range: body_start..body_end,
            });
            cursor = body_end;
        }

        Ok(Self {
            bytes: bytes.to_vec(),
            version,
            sections,
        })
    }

    /// Reproduce the original bytes. Currently a clone — when
    /// section editing lands the layout-rebuild logic will
    /// live here.
    #[must_use]
    pub fn write_to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Body bytes of `section` (excluding the id + size header).
    #[must_use]
    pub fn section_body(&self, section: &Section) -> &[u8] {
        &self.bytes[section.body_range.clone()]
    }

    /// For a custom (id = 0) section, return its decoded name
    /// (UTF-8). The name is a LEB128-length-prefixed string at
    /// the start of the body. Returns `None` for non-custom
    /// sections or malformed names.
    #[must_use]
    pub fn custom_section_name(&self, section: &Section) -> Option<String> {
        if section.id != SECTION_CUSTOM {
            return None;
        }
        let body = self.section_body(section);
        let (len, len_len) = read_leb128_u32(body, 0).ok()?;
        let name_start = len_len;
        let name_end = name_start.checked_add(len as usize)?;
        if name_end > body.len() {
            return None;
        }
        std::str::from_utf8(&body[name_start..name_end])
            .ok()
            .map(str::to_string)
    }
}

/// Is `bytes` plausibly a WASM module? Just checks the first
/// 4 bytes against [`MAGIC`].
#[must_use]
pub fn is_wasm(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == MAGIC
}

/// Decode an unsigned LEB128 starting at `bytes[at]`. Returns
/// `(value, byte_count)`. Caps at 32-bit values per the WASM
/// section-size encoding rules (5-byte max LEB128).
fn read_leb128_u32(bytes: &[u8], at: usize) -> Result<(u32, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0usize;
    loop {
        let pos = at.checked_add(i).ok_or(Error::LebOverflow { at })?;
        let byte = *bytes.get(pos).ok_or(Error::LebOverflow { at })?;
        let chunk = u64::from(byte & 0x7f);
        result |= chunk << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if i > 5 {
            return Err(Error::LebOverflow { at });
        }
    }
    if result > u64::from(u32::MAX) {
        return Err(Error::LebTooLarge { at });
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok((result as u32, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_module_round_trips() {
        let bytes = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
        let m = WasmFile::parse(&bytes).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.sections.len(), 0);
        assert_eq!(m.write_to_vec(), bytes);
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes = [0x00, b'a', b's', b'n', 0x01, 0x00, 0x00, 0x00];
        assert!(matches!(
            WasmFile::parse(&bytes),
            Err(Error::BadMagic { .. })
        ));
    }

    #[test]
    fn leb128_handles_padded_encoding() {
        // 0x0b encoded as 5-byte padded LEB128: 8b 80 80 80 00.
        let bytes = [0x8b, 0x80, 0x80, 0x80, 0x00];
        assert_eq!(read_leb128_u32(&bytes, 0).unwrap(), (0x0b, 5));
        // Same value, minimal: just 0x0b.
        let minimal = [0x0b];
        assert_eq!(read_leb128_u32(&minimal, 0).unwrap(), (0x0b, 1));
    }
}
