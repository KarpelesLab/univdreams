//! Build a minimal valid PE32 DLL byte-by-byte for in-tree
//! tests. No filesystem fixtures, no `pelite` / `goblin` — every
//! offset is explicit.
//!
//! Layout (all sizes in bytes; all multi-byte values
//! little-endian):
//!
//! ```text
//! 0x0000  DOS stub: "MZ", 58 bytes of padding, e_lfanew @ 0x3C
//! 0x0040  PE\0\0
//! 0x0044  IMAGE_FILE_HEADER (20)
//! 0x0058  IMAGE_OPTIONAL_HEADER32 (224 = 28 + 68 + 16*8 = 224)
//! 0x0138  Section table — 3 sections × 40 bytes = 120
//! 0x01B0  ... padding to FileAlignment 0x200 ...
//! 0x0200  .text section  raw bytes (single 0xC3 = ret)
//! 0x0400  .rdata section raw bytes (export table + import table)
//! 0x0600  .reloc section raw bytes (empty block)
//! 0x0800  end of file
//! ```
//!
//! At runtime the image is mapped at `ImageBase = 0x10000000`,
//! so:
//!
//! * `.text`  RVA = 0x1000 → VA = 0x10001000.
//! * `.rdata` RVA = 0x2000 → VA = 0x10002000.
//! * `.reloc` RVA = 0x3000 → VA = 0x10003000.
//!
//! The DLL exports one function (`DllMain`) at the entry point
//! and imports `kernel32!GetProcessHeap`. The entry-point code
//! is just `ret 12` (0xC2 0x0C 0x00) — i.e. it accepts the
//! standard 3 stdcall args (hInstance, fdwReason, lpvReserved)
//! and returns immediately. `eax` is whatever the caller had
//! pre-set. Tests pre-set `eax = 1` so the post-condition
//! "DllMain returned TRUE" is testable.

use crate::pe::header::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DOS_SIGNATURE, IMAGE_FILE_MACHINE_I386, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    IMAGE_NT_SIGNATURE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};

const FILE_ALIGN: usize = 0x200;
const SECTION_ALIGN: u32 = 0x1000;

/// Image base where the test DLL gets mapped.
pub const IMAGE_BASE: u32 = 0x1000_0000;

/// RVA of the IAT slot for kernel32!GetProcessHeap (the only
/// import). The PE loader patches it to the registry's thunk
/// address; tests check that.
pub const IAT_RVA: u32 = 0x2200;

/// Synthesise a minimal valid PE32 DLL.
pub fn build_minimal_dll() -> Vec<u8> {
    let mut bytes = vec![0u8; FILE_ALIGN]; // headers fit in <= 0x200

    // ---- DOS stub (offset 0..0x40) ------------------------------
    bytes[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
    let pe_off: u32 = 0x40;
    bytes[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());

    // ---- PE signature -------------------------------------------
    let pe = pe_off as usize;
    bytes[pe..pe + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

    // ---- IMAGE_FILE_HEADER (20 bytes) ---------------------------
    let fh = pe + 4;
    bytes[fh..fh + 2].copy_from_slice(&IMAGE_FILE_MACHINE_I386.to_le_bytes());
    bytes[fh + 2..fh + 4].copy_from_slice(&3u16.to_le_bytes()); // NumberOfSections
    bytes[fh + 4..fh + 8].copy_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    bytes[fh + 8..fh + 12].copy_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
    bytes[fh + 12..fh + 16].copy_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
    bytes[fh + 16..fh + 18].copy_from_slice(&224u16.to_le_bytes()); // SizeOfOptionalHeader
    bytes[fh + 18..fh + 20].copy_from_slice(&0x2000u16.to_le_bytes()); // Characteristics: IMAGE_FILE_DLL

    // ---- IMAGE_OPTIONAL_HEADER32 (224 bytes) --------------------
    let oh = fh + 20;
    bytes[oh..oh + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
    bytes[oh + 2] = 6; // MajorLinkerVersion
    bytes[oh + 3] = 0; // MinorLinkerVersion
    bytes[oh + 4..oh + 8].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes()); // SizeOfCode
    bytes[oh + 8..oh + 12].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes()); // SizeOfInitData
    bytes[oh + 12..oh + 16].copy_from_slice(&0u32.to_le_bytes()); // SizeOfUninitData
    bytes[oh + 16..oh + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint (RVA inside .text)
    bytes[oh + 20..oh + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode (RVA)
    bytes[oh + 24..oh + 28].copy_from_slice(&0x2000u32.to_le_bytes()); // BaseOfData (RVA)

    // Windows-specific fields (68 bytes) start at oh + 28.
    bytes[oh + 28..oh + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    bytes[oh + 32..oh + 36].copy_from_slice(&SECTION_ALIGN.to_le_bytes());
    bytes[oh + 36..oh + 40].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes());
    bytes[oh + 40..oh + 42].copy_from_slice(&4u16.to_le_bytes()); // MajOSVersion
    bytes[oh + 42..oh + 44].copy_from_slice(&0u16.to_le_bytes());
    bytes[oh + 44..oh + 46].copy_from_slice(&0u16.to_le_bytes()); // MajImageVersion
    bytes[oh + 46..oh + 48].copy_from_slice(&0u16.to_le_bytes());
    bytes[oh + 48..oh + 50].copy_from_slice(&4u16.to_le_bytes()); // MajSubsystemVersion
    bytes[oh + 50..oh + 52].copy_from_slice(&0u16.to_le_bytes());
    bytes[oh + 52..oh + 56].copy_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
    bytes[oh + 56..oh + 60].copy_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
    bytes[oh + 60..oh + 64].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes()); // SizeOfHeaders
    bytes[oh + 64..oh + 68].copy_from_slice(&0u32.to_le_bytes()); // CheckSum
    bytes[oh + 68..oh + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem: WINDOWS_CUI (any non-zero is fine)
    bytes[oh + 70..oh + 72].copy_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
    bytes[oh + 72..oh + 76].copy_from_slice(&0x10_0000u32.to_le_bytes()); // SizeOfStackReserve
    bytes[oh + 76..oh + 80].copy_from_slice(&0x1000u32.to_le_bytes()); // SizeOfStackCommit
    bytes[oh + 80..oh + 84].copy_from_slice(&0x10_0000u32.to_le_bytes()); // SizeOfHeapReserve
    bytes[oh + 84..oh + 88].copy_from_slice(&0x1000u32.to_le_bytes()); // SizeOfHeapCommit
    bytes[oh + 88..oh + 92].copy_from_slice(&0u32.to_le_bytes()); // LoaderFlags
    bytes[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // Data directories — 16 entries × 8 bytes = 128 bytes at oh + 96.
    let dirs = oh + 96;
    // Export at RVA 0x2000 + size set after we lay out the table.
    // Import directory at RVA 0x2100, size 40 (2 descriptors × 20).
    // Base reloc at RVA 0x3000, size 12 (one empty block).
    let export_rva = 0x2000u32;
    let export_size = EXPORT_TABLE_SIZE as u32;
    let import_rva = 0x2100u32;
    let import_size = 40u32;
    let reloc_rva = 0x4000u32;
    let reloc_size = 12u32;
    write_dir(
        &mut bytes,
        dirs,
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        export_rva,
        export_size,
    );
    write_dir(
        &mut bytes,
        dirs,
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        import_rva,
        import_size,
    );
    write_dir(
        &mut bytes,
        dirs,
        IMAGE_DIRECTORY_ENTRY_BASERELOC,
        reloc_rva,
        reloc_size,
    );

    // ---- Section table (3 entries × 40 = 120 bytes) -------------
    let st = dirs + 16 * 8;
    write_section(
        &mut bytes,
        st,
        b".text",
        /*virtual_size=*/ 0x10,
        /*virtual_address=*/ 0x1000,
        /*size_of_raw_data=*/ FILE_ALIGN as u32,
        /*pointer_to_raw_data=*/ FILE_ALIGN as u32,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
    );
    // .rdata occupies three FILE_ALIGN slots so we can place
    // import descriptors / IAT / strings at well-spaced RVAs
    // without overlapping. Raw bytes 0x400..0xA00 (3 × 0x200).
    write_section(
        &mut bytes,
        st + 40,
        b".rdata",
        /*virtual_size=*/ 0x600,
        /*virtual_address=*/ 0x2000,
        /*size_of_raw_data=*/ (FILE_ALIGN * 3) as u32,
        /*pointer_to_raw_data=*/ (FILE_ALIGN * 2) as u32,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, // we need W on .rdata so the loader can patch the IAT
    );
    write_section(
        &mut bytes,
        st + 80,
        b".reloc",
        /*virtual_size=*/ 0x10,
        /*virtual_address=*/ 0x4000,
        /*size_of_raw_data=*/ FILE_ALIGN as u32,
        /*pointer_to_raw_data=*/ (FILE_ALIGN * 5) as u32,
        IMAGE_SCN_MEM_READ,
    );

    // ---- .text section (offset 0x200) ---------------------------
    // Total file size = headers (1) + .text (1) + .rdata (3) + .reloc (1) = 6 × FILE_ALIGN.
    bytes.resize(FILE_ALIGN * 6, 0);

    // Entry point: ret 12 (0xC2 0x0C 0x00) — DllMain stdcall pops
    // its 3 dword args and returns whatever was in eax.
    bytes[FILE_ALIGN] = 0xC2;
    bytes[FILE_ALIGN + 1] = 0x0C;
    bytes[FILE_ALIGN + 2] = 0x00;

    // ---- .rdata section (offset 0x400) --------------------------
    // The .rdata section holds:
    //   * Export directory (0x2000 RVA — file off 0x400)
    //   * AddressOfFunctions  table @ 0x2080  (4 bytes)
    //   * AddressOfNames      table @ 0x2084  (4 bytes)
    //   * AddressOfNameOrds   table @ 0x2088  (2 bytes)
    //   * "DllMain\0"         @ 0x208C
    //   * "synth.dll\0"       @ 0x2094
    //   * Import descriptors  @ 0x2100  (2 × 20 = 40 bytes)
    //   * ILT (single entry + sentinel) @ 0x2150
    //   * IAT (single entry + sentinel) @ 0x2200
    //   * IMAGE_IMPORT_BY_NAME for GetProcessHeap @ 0x2300
    //   * "kernel32.dll\0"    @ 0x2400
    //
    // .rdata starts at file off 0x400 = RVA 0x2000.

    let rdata = FILE_ALIGN * 2;
    let off = |rva: u32| rdata + (rva - 0x2000) as usize;

    // -- Export directory at RVA 0x2000 (file off 0x400) ----------
    let edir = off(0x2000);
    // Characteristics
    bytes[edir..edir + 4].copy_from_slice(&0u32.to_le_bytes());
    // TimeDateStamp / Major / Minor / Name (RVA to "synth.dll")
    bytes[edir + 12..edir + 16].copy_from_slice(&0x2094u32.to_le_bytes());
    // Base
    bytes[edir + 16..edir + 20].copy_from_slice(&1u32.to_le_bytes());
    // NumberOfFunctions / NumberOfNames
    bytes[edir + 20..edir + 24].copy_from_slice(&1u32.to_le_bytes());
    bytes[edir + 24..edir + 28].copy_from_slice(&1u32.to_le_bytes());
    // AddressOfFunctions / Names / NameOrdinals
    bytes[edir + 28..edir + 32].copy_from_slice(&0x2080u32.to_le_bytes());
    bytes[edir + 32..edir + 36].copy_from_slice(&0x2084u32.to_le_bytes());
    bytes[edir + 36..edir + 40].copy_from_slice(&0x2088u32.to_le_bytes());

    // AddressOfFunctions[0] = 0x1000 (RVA of DllMain)
    let aof = off(0x2080);
    bytes[aof..aof + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    // AddressOfNames[0]     = 0x208C (RVA of "DllMain")
    let aon = off(0x2084);
    bytes[aon..aon + 4].copy_from_slice(&0x208Cu32.to_le_bytes());
    // AddressOfNameOrdinals[0] = 0
    let aoo = off(0x2088);
    bytes[aoo..aoo + 2].copy_from_slice(&0u16.to_le_bytes());
    // "DllMain\0" at 0x208C
    let dllmain = off(0x208C);
    let s = b"DllMain\0";
    bytes[dllmain..dllmain + s.len()].copy_from_slice(s);
    // "synth.dll\0" at 0x2094
    let synth = off(0x2094);
    let s = b"synth.dll\0";
    bytes[synth..synth + s.len()].copy_from_slice(s);

    // -- Import directory at RVA 0x2100 (file off 0x500) ----------
    let imp0 = off(0x2100);
    // Descriptor 0: kernel32
    bytes[imp0..imp0 + 4].copy_from_slice(&0x2150u32.to_le_bytes()); // OriginalFirstThunk (ILT)
    bytes[imp0 + 4..imp0 + 8].copy_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    bytes[imp0 + 8..imp0 + 12].copy_from_slice(&0u32.to_le_bytes()); // ForwarderChain
    bytes[imp0 + 12..imp0 + 16].copy_from_slice(&0x2400u32.to_le_bytes()); // Name (kernel32.dll)
    bytes[imp0 + 16..imp0 + 20].copy_from_slice(&IAT_RVA.to_le_bytes()); // FirstThunk (IAT)
                                                                         // Descriptor 1: sentinel (all zeros). bytes already zero.

    // -- ILT at RVA 0x2150 -----------------------------------------
    let ilt = off(0x2150);
    bytes[ilt..ilt + 4].copy_from_slice(&0x2300u32.to_le_bytes()); // → IMAGE_IMPORT_BY_NAME
    bytes[ilt + 4..ilt + 8].copy_from_slice(&0u32.to_le_bytes()); // sentinel

    // -- IAT at RVA 0x2200 (parallel; same RVAs as ILT initially) -
    let iat = off(IAT_RVA);
    bytes[iat..iat + 4].copy_from_slice(&0x2300u32.to_le_bytes());
    bytes[iat + 4..iat + 8].copy_from_slice(&0u32.to_le_bytes());

    // -- IMAGE_IMPORT_BY_NAME at RVA 0x2300 -----------------------
    let ibn = off(0x2300);
    bytes[ibn..ibn + 2].copy_from_slice(&0u16.to_le_bytes()); // hint
    let s = b"GetProcessHeap\0";
    bytes[ibn + 2..ibn + 2 + s.len()].copy_from_slice(s);

    // -- DLL name "kernel32.dll\0" at RVA 0x2400 -------------------
    let kn = off(0x2400);
    let s = b"kernel32.dll\0";
    bytes[kn..kn + s.len()].copy_from_slice(s);

    // ---- .reloc section (offset 0xA00) --------------------------
    // Single empty block: page_rva=0, block_size=8 (no entries),
    // followed by zero pad. The PE/COFF spec requires reloc
    // blocks be at least 8 bytes; an 8-byte block with zero
    // entries is well-formed.
    let reloc = FILE_ALIGN * 5;
    bytes[reloc..reloc + 4].copy_from_slice(&0u32.to_le_bytes()); // page_rva
    bytes[reloc + 4..reloc + 8].copy_from_slice(&8u32.to_le_bytes()); // block_size

    bytes
}

// Total bytes the export directory occupies in .rdata, end of
// strings inclusive (used to populate the data-directory size).
const EXPORT_TABLE_SIZE: usize = 0x100;

fn write_dir(bytes: &mut [u8], base: usize, idx: usize, rva: u32, size: u32) {
    let off = base + idx * 8;
    bytes[off..off + 4].copy_from_slice(&rva.to_le_bytes());
    bytes[off + 4..off + 8].copy_from_slice(&size.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_section(
    bytes: &mut [u8],
    off: usize,
    name: &[u8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
) {
    // 8-byte name field — pad with zeros if shorter.
    for (i, b) in name.iter().take(8).enumerate() {
        bytes[off + i] = *b;
    }
    bytes[off + 8..off + 12].copy_from_slice(&virtual_size.to_le_bytes());
    bytes[off + 12..off + 16].copy_from_slice(&virtual_address.to_le_bytes());
    bytes[off + 16..off + 20].copy_from_slice(&size_of_raw_data.to_le_bytes());
    bytes[off + 20..off + 24].copy_from_slice(&pointer_to_raw_data.to_le_bytes());
    // Skip PointerToRelocations (4) + PointerToLinenumbers (4) +
    // NumberOfRelocations (2) + NumberOfLinenumbers (2) — left at
    // zero since the file initialised to zero.
    bytes[off + 36..off + 40].copy_from_slice(&characteristics.to_le_bytes());
}
