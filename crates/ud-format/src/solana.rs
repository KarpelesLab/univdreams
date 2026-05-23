//! Solana on-chain program loader-state stripping.
//!
//! A Solana program's ELF bytes don't sit at the start of
//! its on-chain account — they're wrapped in a per-loader
//! header that the runtime parses before handing the ELF to
//! the verifier. Three loaders are in active use:
//!
//! * **`BPFLoader2111…`** (non-upgradeable, legacy). The
//!   program's account data IS the ELF; nothing to strip.
//! * **`BPFLoaderUpgradeab1e…`** (today's default). Two
//!   accounts: a *Program* account whose data is a 36-byte
//!   `UpgradeableLoaderState::Program` (a 4-byte Borsh enum
//!   tag of value 2, followed by the 32-byte ProgramData
//!   pubkey), and a *ProgramData* account whose data is an
//!   `UpgradeableLoaderState::ProgramData` header followed
//!   by the ELF. The ProgramData header is **45 bytes** when
//!   an upgrade authority is set or **13 bytes** when it's
//!   `None` (the difference is the 32-byte authority pubkey
//!   carried under a `Some` variant of `Option<Pubkey>`).
//! * **`LoaderV411…`** (Agave's newer loader). A
//!   `LoaderV4State` of 48 bytes (8 slot + 32 authority + 8
//!   status repr) followed by the ELF.
//!
//! Each stripping function verifies the ELF magic
//! (`\x7fELF`) immediately past the header so a mismatched
//! layout fails loudly rather than producing garbage. The
//! upgradeable case has a small subtlety: when one variant
//! (45-byte header) doesn't expose the magic, we try the
//! other (13-byte) before giving up, since the option-tag
//! byte at offset 12 can lie in unusual encoder paths.
//!
//! This module is the single source of truth for those
//! byte-level decisions. Two callers consume it:
//!
//! * [`ud_cli::solana`] — adds the network layer (JSON-RPC
//!   over `ureq` + base64 + on-disk cache) on top.
//! * [`ud_wasm`] — exposes the strippers as wasm-bindgen
//!   functions so the browser playground can do the network
//!   piece in JS and call into here for byte parsing.

use crate::elf::ELF_MAGIC;

/// Loader program ID (base58) — `BPFLoader2111…`,
/// non-upgradeable, legacy.
pub const BPF_LOADER_V2: &str = "BPFLoader2111111111111111111111111111111111";

/// Loader program ID (base58) — `BPFLoaderUpgradeab1e…`,
/// today's default.
pub const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

/// Loader program ID (base58) — `LoaderV411…`, Agave's
/// newer loader.
pub const LOADER_V4: &str = "LoaderV411111111111111111111111111111111111";

/// Borsh enum tag for `UpgradeableLoaderState::Program`.
const UPGRADEABLE_STATE_PROGRAM: u32 = 2;
/// Borsh enum tag for `UpgradeableLoaderState::ProgramData`.
const UPGRADEABLE_STATE_PROGRAM_DATA: u32 = 3;

/// `UpgradeableLoaderState::ProgramData` header size when
/// the `upgrade_authority_address: Option<Pubkey>` is
/// `Some`: 4 (enum tag) + 8 (slot) + 1 (option tag) + 32
/// (pubkey) = 45.
const PROGRAMDATA_HEADER_WITH_AUTH: usize = 45;

/// Same header when the authority is `None`:
/// 4 (enum tag) + 8 (slot) + 1 (option tag) = 13 bytes.
const PROGRAMDATA_HEADER_NO_AUTH: usize = 13;

/// `LoaderV4State` is 48 bytes: 8 (slot) + 32 (authority or
/// next-version pubkey) + 8 (`LoaderV4Status` repr).
const LOADER_V4_HEADER: usize = 48;

/// Which loader manages a given program account. The
/// classifier matches against the base58-encoded owner
/// pubkey as it comes out of the Solana JSON-RPC response;
/// callers don't need to decode to raw bytes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderKind {
    /// `BPFLoader2111…` — account data is the ELF directly.
    BpfLoader2,
    /// `BPFLoaderUpgradeab1e…` — Program + ProgramData split.
    Upgradeable,
    /// `LoaderV411…` — 48-byte header then ELF.
    LoaderV4,
    /// Owner doesn't match any known loader. Caller should
    /// surface the actual owner string to the user.
    Unknown,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("account data too short for {loader}: need ≥{need} bytes, got {got}")]
    TooShort {
        loader: &'static str,
        need: usize,
        got: usize,
    },
    #[error("ELF magic missing at expected offset {offset} for {loader}")]
    NotElf { loader: &'static str, offset: usize },
    #[error("expected {loader} Borsh enum tag {expected} at offset 0, got {got}")]
    BadEnumTag {
        loader: &'static str,
        expected: u32,
        got: u32,
    },
    #[error(
        "ProgramData has neither {with_auth}-byte nor {no_auth}-byte header that exposes ELF magic"
    )]
    AmbiguousProgramData { with_auth: usize, no_auth: usize },
}

/// Match a base58-encoded owner pubkey against the known
/// loader IDs.
#[must_use]
pub fn classify_loader(owner: &str) -> LoaderKind {
    match owner {
        BPF_LOADER_V2 => LoaderKind::BpfLoader2,
        BPF_LOADER_UPGRADEABLE => LoaderKind::Upgradeable,
        LOADER_V4 => LoaderKind::LoaderV4,
        _ => LoaderKind::Unknown,
    }
}

/// For a Program account whose owner is the upgradeable
/// loader, return the 32-byte ProgramData address embedded
/// in the account data. The caller fetches that account
/// next.
///
/// Layout: `UpgradeableLoaderState::Program` = 4 bytes
/// Borsh enum tag (value 2) + 32 bytes pubkey = 36 bytes
/// total.
pub fn programdata_pubkey(program_data: &[u8]) -> Result<[u8; 32], Error> {
    const NEEDED: usize = 36;
    if program_data.len() < NEEDED {
        return Err(Error::TooShort {
            loader: "BPFLoaderUpgradeable Program",
            need: NEEDED,
            got: program_data.len(),
        });
    }
    let tag = u32::from_le_bytes([
        program_data[0],
        program_data[1],
        program_data[2],
        program_data[3],
    ]);
    if tag != UPGRADEABLE_STATE_PROGRAM {
        return Err(Error::BadEnumTag {
            loader: "BPFLoaderUpgradeable Program",
            expected: UPGRADEABLE_STATE_PROGRAM,
            got: tag,
        });
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&program_data[4..36]);
    Ok(pubkey)
}

/// Strip the loader-state from a `BPFLoader2` account.
/// There's no header — the bytes are the ELF directly.
/// Verifies the ELF magic so a malformed account fails
/// loudly.
pub fn strip_bpf_loader_v2(data: &[u8]) -> Result<&[u8], Error> {
    verify_elf(data, "BPFLoader2", 0)?;
    Ok(data)
}

/// Strip the `UpgradeableLoaderState::ProgramData` header
/// off the ProgramData account's data. Returns a slice into
/// the input (no copy).
///
/// Tries the 45-byte (with-authority) variant first; if
/// that doesn't expose ELF magic, falls back to the 13-byte
/// (no-authority) variant before giving up.
pub fn strip_bpf_loader_upgradeable(programdata: &[u8]) -> Result<&[u8], Error> {
    if programdata.len() < PROGRAMDATA_HEADER_NO_AUTH {
        return Err(Error::TooShort {
            loader: "BPFLoaderUpgradeable ProgramData",
            need: PROGRAMDATA_HEADER_NO_AUTH,
            got: programdata.len(),
        });
    }
    let tag = u32::from_le_bytes([
        programdata[0],
        programdata[1],
        programdata[2],
        programdata[3],
    ]);
    if tag != UPGRADEABLE_STATE_PROGRAM_DATA {
        return Err(Error::BadEnumTag {
            loader: "BPFLoaderUpgradeable ProgramData",
            expected: UPGRADEABLE_STATE_PROGRAM_DATA,
            got: tag,
        });
    }
    // Option<Pubkey> byte at offset 12: 1 = Some, 0 = None.
    let auth_present = programdata.get(12).copied().unwrap_or(0) != 0;
    let primary = if auth_present {
        PROGRAMDATA_HEADER_WITH_AUTH
    } else {
        PROGRAMDATA_HEADER_NO_AUTH
    };
    if has_elf_at(programdata, primary) {
        return Ok(&programdata[primary..]);
    }
    let alt = if auth_present {
        PROGRAMDATA_HEADER_NO_AUTH
    } else {
        PROGRAMDATA_HEADER_WITH_AUTH
    };
    if has_elf_at(programdata, alt) {
        return Ok(&programdata[alt..]);
    }
    Err(Error::AmbiguousProgramData {
        with_auth: PROGRAMDATA_HEADER_WITH_AUTH,
        no_auth: PROGRAMDATA_HEADER_NO_AUTH,
    })
}

/// Strip the 48-byte `LoaderV4State` header. Returns a
/// slice into the input.
pub fn strip_loader_v4(data: &[u8]) -> Result<&[u8], Error> {
    if data.len() < LOADER_V4_HEADER + ELF_MAGIC.len() {
        return Err(Error::TooShort {
            loader: "LoaderV4",
            need: LOADER_V4_HEADER + ELF_MAGIC.len(),
            got: data.len(),
        });
    }
    verify_elf(&data[LOADER_V4_HEADER..], "LoaderV4", LOADER_V4_HEADER)?;
    Ok(&data[LOADER_V4_HEADER..])
}

fn has_elf_at(data: &[u8], offset: usize) -> bool {
    data.len() >= offset + ELF_MAGIC.len() && data[offset..offset + ELF_MAGIC.len()] == ELF_MAGIC
}

fn verify_elf(bytes: &[u8], loader: &'static str, offset: usize) -> Result<(), Error> {
    if bytes.len() < ELF_MAGIC.len() || bytes[..ELF_MAGIC.len()] != ELF_MAGIC {
        return Err(Error::NotElf { loader, offset });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_bytes(extra: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(ELF_MAGIC.len() + extra);
        v.extend_from_slice(&ELF_MAGIC);
        v.resize(ELF_MAGIC.len() + extra, 0);
        v
    }

    #[test]
    fn classify_recognises_the_three_loaders() {
        assert_eq!(classify_loader(BPF_LOADER_V2), LoaderKind::BpfLoader2);
        assert_eq!(
            classify_loader(BPF_LOADER_UPGRADEABLE),
            LoaderKind::Upgradeable
        );
        assert_eq!(classify_loader(LOADER_V4), LoaderKind::LoaderV4);
        assert_eq!(
            classify_loader("11111111111111111111111111111111"),
            LoaderKind::Unknown
        );
    }

    #[test]
    fn strip_bpf_loader_v2_is_identity_with_elf_check() {
        let bytes = elf_bytes(64);
        assert_eq!(strip_bpf_loader_v2(&bytes).unwrap(), &bytes[..]);
    }

    #[test]
    fn strip_bpf_loader_v2_rejects_non_elf() {
        let mut bytes = elf_bytes(64);
        bytes[0] = 0; // corrupt magic
        assert!(matches!(
            strip_bpf_loader_v2(&bytes),
            Err(Error::NotElf { offset: 0, .. })
        ));
    }

    #[test]
    fn programdata_pubkey_extracts_the_32_byte_address() {
        let mut buf = [0u8; 36];
        buf[0..4].copy_from_slice(&UPGRADEABLE_STATE_PROGRAM.to_le_bytes());
        for (i, b) in (0u8..32u8).enumerate() {
            buf[4 + i] = b;
        }
        let pk = programdata_pubkey(&buf).unwrap();
        let expected: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());
        assert_eq!(pk, expected);
    }

    #[test]
    fn programdata_pubkey_rejects_short_data() {
        assert!(matches!(
            programdata_pubkey(&[0u8; 20]),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn programdata_pubkey_rejects_wrong_tag() {
        let buf = [0u8; 36]; // tag = 0, not 2
        assert!(matches!(
            programdata_pubkey(&buf),
            Err(Error::BadEnumTag { .. })
        ));
    }

    #[test]
    fn strip_upgradeable_with_authority_header() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&UPGRADEABLE_STATE_PROGRAM_DATA.to_le_bytes()); // 4
        buf.extend_from_slice(&[0u8; 8]); // slot (12 bytes total so far)
        buf.push(1); // option tag = Some (13 bytes total)
        buf.extend_from_slice(&[0u8; 32]); // pubkey (45 bytes total)
        let payload = elf_bytes(32);
        buf.extend_from_slice(&payload);
        let stripped = strip_bpf_loader_upgradeable(&buf).unwrap();
        assert_eq!(stripped, &payload[..]);
    }

    #[test]
    fn strip_upgradeable_without_authority_header() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&UPGRADEABLE_STATE_PROGRAM_DATA.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        buf.push(0); // None → 13-byte header
        let payload = elf_bytes(32);
        buf.extend_from_slice(&payload);
        let stripped = strip_bpf_loader_upgradeable(&buf).unwrap();
        assert_eq!(stripped, &payload[..]);
    }

    #[test]
    fn strip_upgradeable_fallback_when_option_tag_lies() {
        // Option tag says "Some" but the actual bytes have
        // an ELF at offset 13 — meaning the encoder
        // actually wrote the no-authority shape. The
        // fallback path should still succeed.
        let mut buf = Vec::new();
        buf.extend_from_slice(&UPGRADEABLE_STATE_PROGRAM_DATA.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        buf.push(1); // option tag = Some, but...
        let payload = elf_bytes(32);
        buf.extend_from_slice(&payload); // ...ELF starts at offset 13
        let stripped = strip_bpf_loader_upgradeable(&buf).unwrap();
        assert_eq!(stripped, &payload[..]);
    }

    #[test]
    fn strip_loader_v4_removes_48_byte_header() {
        let mut buf = vec![0u8; LOADER_V4_HEADER];
        let payload = elf_bytes(32);
        buf.extend_from_slice(&payload);
        let stripped = strip_loader_v4(&buf).unwrap();
        assert_eq!(stripped, &payload[..]);
    }

    #[test]
    fn strip_loader_v4_rejects_short_account() {
        assert!(matches!(
            strip_loader_v4(&[0u8; 20]),
            Err(Error::TooShort { .. })
        ));
    }
}
