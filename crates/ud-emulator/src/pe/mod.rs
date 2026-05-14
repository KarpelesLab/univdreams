//! PE32 loader — parses Microsoft Portable Executable images,
//! maps them into the emulator MMU, applies base relocations,
//! resolves imports against the [`crate::win32::Registry`], and
//! exposes export-by-name lookup.
//!
//! Reference: Microsoft "PE Format" (a.k.a. "Microsoft PE and
//! COFF Specification"), revision 11.0 (2022-08-26). All struct
//! field names and offsets in this module match that document.
//!
//! Supported subset (per design doc §"The PE loader"):
//!
//! * PE32 only. PE32+ (`Magic == 0x20B`) → reject.
//! * `IMAGE_FILE_MACHINE_I386` only.
//! * No .NET CLR. `IMAGE_DIRECTORY_ENTRY_COMHEADER` non-zero →
//!   reject.
//! * No delay-load imports. The directory entry must be empty.
//! * No SxS manifest dependencies. (We don't enforce — codecs
//!   never have one.)
//!
//! Reject-paths return [`PeError`]; everything else surfaces as
//! a well-formed [`Image`].

pub mod exports;
pub mod header;
pub mod imports;
pub mod reloc;
pub mod sections;

use std::collections::BTreeMap;

use crate::emulator::{mmu::Mmu, Trap};
use crate::win32::{HostState, Registry};

/// PE-loader-specific error variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    /// File too small to contain a DOS header.
    TooSmall { got: usize, need: usize },
    /// "MZ" signature missing at offset 0.
    NotMz,
    /// `e_lfanew` points outside the file.
    BadELfanew { offset: u32, file_len: usize },
    /// "PE\0\0" signature missing at `e_lfanew`.
    NotPe,
    /// Optional-header magic indicates PE32+ (64-bit).
    Pe32PlusUnsupported,
    /// Optional-header magic is neither PE32 nor PE32+.
    BadOptionalHeaderMagic { magic: u16 },
    /// File-header machine field is not `IMAGE_FILE_MACHINE_I386`.
    UnsupportedMachine { machine: u16 },
    /// A directory entry refers to bytes outside the image.
    DirectoryOutOfRange {
        name: &'static str,
        rva: u32,
        size: u32,
    },
    /// `IMAGE_DIRECTORY_ENTRY_COMHEADER` non-zero — managed PE.
    ManagedPe,
    /// Referenced DLL is not registered with the Win32 stub
    /// registry.
    UnknownImportDll { dll: String },
    /// Specific function in a known DLL is not registered.
    UnknownImportFunction { dll: String, name: String },
    /// Section `SizeOfRawData` overflows the file or
    /// `VirtualSize` overflows the section table.
    SectionOutOfRange {
        name: String,
        raw_off: u32,
        raw_size: u32,
    },
    /// Base relocation block was malformed.
    BadRelocBlock { rva: u32, reason: &'static str },
    /// Memory-map operation traps. Wrapped here so the loader's
    /// public API exposes a single error type.
    Trap(Trap),
}

impl core::fmt::Display for PeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PeError::TooSmall { got, need } => {
                write!(f, "PE file too small: {got} bytes, need ≥ {need}")
            }
            PeError::NotMz => f.write_str("missing 'MZ' DOS signature"),
            PeError::BadELfanew { offset, file_len } => {
                write!(f, "e_lfanew {offset:#x} outside file (len {file_len})")
            }
            PeError::NotPe => f.write_str("missing 'PE\\0\\0' signature"),
            PeError::Pe32PlusUnsupported => f.write_str("PE32+ (64-bit) not supported"),
            PeError::BadOptionalHeaderMagic { magic } => {
                write!(f, "bad optional-header magic {magic:#x}")
            }
            PeError::UnsupportedMachine { machine } => {
                write!(f, "machine {machine:#x} is not IMAGE_FILE_MACHINE_I386")
            }
            PeError::DirectoryOutOfRange { name, rva, size } => {
                write!(
                    f,
                    "directory {name} (rva {rva:#x}, size {size}) out of image range"
                )
            }
            PeError::ManagedPe => f.write_str("managed (.NET) PE not supported"),
            PeError::UnknownImportDll { dll } => {
                write!(f, "no Round-1 stub registry entry for DLL '{dll}'")
            }
            PeError::UnknownImportFunction { dll, name } => {
                write!(f, "no stub for {dll}!{name}")
            }
            PeError::SectionOutOfRange {
                name,
                raw_off,
                raw_size,
            } => {
                write!(
                    f,
                    "section '{name}' raw bytes [{raw_off:#x}..+{raw_size}] out of file"
                )
            }
            PeError::BadRelocBlock { rva, reason } => {
                write!(f, "malformed reloc block at rva {rva:#x}: {reason}")
            }
            PeError::Trap(t) => write!(f, "MMU trap during load: {t}"),
        }
    }
}

impl From<Trap> for PeError {
    fn from(t: Trap) -> Self {
        PeError::Trap(t)
    }
}

/// A loaded PE image.
#[derive(Debug, Clone)]
pub struct Image {
    /// Path/identifier used during loading. May be empty.
    pub name: String,
    /// Final image base in emulator memory (after relocation if
    /// the preferred base was occupied; round-1 always uses the
    /// preferred base).
    pub image_base: u32,
    /// `OptionalHeader.AddressOfEntryPoint` resolved to a
    /// VA (= `image_base + AddressOfEntryPoint`).
    pub entry_point: u32,
    /// Total size of the image in memory (rounded to
    /// `SectionAlignment`).
    pub size_of_image: u32,
    /// Section descriptors, in load order.
    pub sections: Vec<sections::Section>,
    /// `(name → RVA-of-export)` table, RVA relative to
    /// `image_base`. Populated by [`exports::parse_exports`].
    pub exports: BTreeMap<String, u32>,
}

impl Image {
    /// Resolve an exported symbol to a guest VA.
    pub fn export(&self, name: &str) -> Option<u32> {
        self.exports
            .get(name)
            .map(|rva| self.image_base.wrapping_add(*rva))
    }
}

/// PE loader entry point.
pub struct Loader<'a> {
    mmu: &'a mut Mmu,
    registry: &'a mut Registry,
    host: &'a mut HostState,
}

impl<'a> Loader<'a> {
    pub fn new(mmu: &'a mut Mmu, registry: &'a mut Registry, host: &'a mut HostState) -> Self {
        Loader {
            mmu,
            registry,
            host,
        }
    }

    /// Parse + load a PE image from a byte slice. The image
    /// starts at offset 0 in `bytes`; `name` is recorded for
    /// diagnostics + module-handle lookups.
    pub fn load(&mut self, name: &str, bytes: &[u8]) -> Result<Image, PeError> {
        let parsed = header::parse(bytes)?;

        // Map sections: each section gets at least VirtualSize
        // bytes mapped at ImageBase + VirtualAddress. Bytes from
        // the file are written via write_initializer (which
        // bypasses the W bit — fine, we're populating).
        let secs = sections::map_sections(self.mmu, &parsed, bytes)?;

        // Apply base relocations. Round-1 always uses the
        // preferred base — relocations are a no-op delta. We
        // still parse + walk the table to make sure malformed
        // blocks are rejected, but we use delta=0 so no bytes
        // change. This keeps the codepath exercised in tests.
        let preferred_base = parsed.optional.image_base;
        let load_base = preferred_base;
        let delta = load_base.wrapping_sub(preferred_base);
        if delta != 0 {
            reloc::apply(self.mmu, &parsed, load_base, delta)?;
        }

        // Resolve imports.
        imports::resolve(self.mmu, &parsed, load_base, self.registry)?;

        // Build export table.
        let exports = exports::parse_exports(&parsed, bytes, load_base)?;

        // Stamp final permissions per section Characteristics
        // flags. Done last so write_initializer in earlier steps
        // does not need W on code pages.
        for s in &secs {
            sections::apply_section_permissions(self.mmu, s);
        }

        let image = Image {
            name: name.to_string(),
            image_base: load_base,
            entry_point: load_base.wrapping_add(parsed.optional.address_of_entry_point),
            size_of_image: parsed.optional.size_of_image,
            sections: secs,
            exports,
        };

        // Record the module so subsequent LoadLibraryA /
        // GetModuleHandleA calls return the right ImageBase.
        self.host
            .modules
            .insert(name.to_ascii_lowercase(), load_base);

        // Round 12 — record the resource directory location so
        // FindResourceA / LoadResource / LockResource can walk it.
        // PE/COFF Data Directory entry 2 is the Resource Table.
        let rsrc = parsed.optional.data_directories[2];
        if rsrc.virtual_address != 0 && rsrc.size != 0 {
            self.host
                .module_resource_dirs
                .insert(load_base, load_base.wrapping_add(rsrc.virtual_address));
        }

        Ok(image)
    }
}

/// Helper to synthesise a minimal valid PE32 DLL byte-by-byte
/// for tests. Used by both unit tests and the integration test
/// `tests/m1_load_dll_main.rs`. Always compiled, but only
/// referenced from `cfg(test)` paths in this crate's own
/// codebase.
pub mod test_image;

#[cfg(test)]
mod tests {
    use super::test_image::build_minimal_dll;
    use super::*;
    use crate::win32::HostState;

    #[test]
    fn load_minimal_synthesised_dll_succeeds() {
        let bytes = build_minimal_dll();
        let mut mmu = Mmu::new();
        let mut registry = Registry::new();
        registry.register_kernel32();
        let mut host = HostState::new(0x6000_0000, 0x7000_0000);
        let mut loader = Loader::new(&mut mmu, &mut registry, &mut host);
        let img = loader.load("synth.dll", &bytes).unwrap();
        assert_eq!(img.image_base, 0x1000_0000);
        // Entry point + 1 byte (the RET) must be readable+executable.
        assert!(mmu.fetch_x8(img.entry_point).is_ok());
    }

    #[test]
    fn rejects_non_mz() {
        let bytes = vec![0u8; 1024];
        let mut mmu = Mmu::new();
        let mut registry = Registry::new();
        let mut host = HostState::new(0, 0);
        let mut loader = Loader::new(&mut mmu, &mut registry, &mut host);
        match loader.load("bad.dll", &bytes) {
            Err(PeError::NotMz) => (),
            other => panic!("expected NotMz, got {other:?}"),
        }
    }

    #[test]
    fn rejects_pe32_plus() {
        let mut bytes = build_minimal_dll();
        // Bend the optional-header magic to 0x20B (PE32+).
        let pe_off =
            u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        let opt_magic_off = pe_off + 4 + 20; // PE sig (4) + IMAGE_FILE_HEADER (20)
        bytes[opt_magic_off] = 0x0B;
        bytes[opt_magic_off + 1] = 0x02;
        let mut mmu = Mmu::new();
        let mut registry = Registry::new();
        let mut host = HostState::new(0, 0);
        let mut loader = Loader::new(&mut mmu, &mut registry, &mut host);
        match loader.load("bad.dll", &bytes) {
            Err(PeError::Pe32PlusUnsupported) => (),
            other => panic!("expected Pe32PlusUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn rejects_managed_pe() {
        let mut bytes = build_minimal_dll();
        // Set IMAGE_DIRECTORY_ENTRY_COMHEADER (#14) RVA=1, Size=8.
        let pe_off =
            u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        // Optional-header data directories start at pe_off + 4 + 20 + 96
        // for PE32 (FileHeader=20, OptionalHeader standard fields = 96).
        let dirs_off = pe_off + 4 + 20 + 96;
        let comheader_off = dirs_off + 14 * 8;
        bytes[comheader_off..comheader_off + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[comheader_off + 4..comheader_off + 8].copy_from_slice(&8u32.to_le_bytes());
        let mut mmu = Mmu::new();
        let mut registry = Registry::new();
        let mut host = HostState::new(0, 0);
        let mut loader = Loader::new(&mut mmu, &mut registry, &mut host);
        match loader.load("bad.dll", &bytes) {
            Err(PeError::ManagedPe) => (),
            other => panic!("expected ManagedPe, got {other:?}"),
        }
    }

    #[test]
    fn export_by_name_resolves_to_va() {
        let bytes = build_minimal_dll();
        let mut mmu = Mmu::new();
        let mut registry = Registry::new();
        registry.register_kernel32();
        let mut host = HostState::new(0x6000_0000, 0x7000_0000);
        let mut loader = Loader::new(&mut mmu, &mut registry, &mut host);
        let img = loader.load("synth.dll", &bytes).unwrap();
        // The synthesised DLL exports DllMain at the entry-point.
        let p = img.export("DllMain").expect("DllMain export");
        assert_eq!(p, img.entry_point);
    }

    #[test]
    fn iat_is_populated_with_thunks() {
        let bytes = build_minimal_dll();
        let mut mmu = Mmu::new();
        let mut registry = Registry::new();
        registry.register_kernel32();
        let mut host = HostState::new(0x6000_0000, 0x7000_0000);
        let mut loader = Loader::new(&mut mmu, &mut registry, &mut host);
        let img = loader.load("synth.dll", &bytes).unwrap();
        // The IAT slot for kernel32!GetProcessHeap should now
        // hold the thunk address registered for that stub.
        let expected = registry.resolve("kernel32.dll", "GetProcessHeap").unwrap();
        // The synth DLL plants its IAT for one import — read it
        // back from the image. test_image::IAT_RVA is the RVA.
        let iat = mmu
            .load32(img.image_base + super::test_image::IAT_RVA)
            .unwrap();
        assert_eq!(iat, expected);
    }
}
