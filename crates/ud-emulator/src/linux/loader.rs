//! Static ELF loader for the Linux personality.
//!
//! Maps an executable's `PT_LOAD` segments into the [`Mmu`] and builds the
//! initial process stack (argc / argv / envp / auxv) per the System V
//! i386 ABI, then reports the entry point and stack pointer the run loop
//! jumps to. Dynamic executables (`PT_INTERP`) are rejected — that needs
//! the runtime linker, which is a separate phase.

use ud_format::elf::{Elf64File, EM_386};

use crate::emulator::{Mmu, Perm};

/// `p_type` of a loadable segment.
const PT_LOAD: u32 = 1;
/// `p_type` of the interpreter path (present iff dynamically linked).
const PT_INTERP: u32 = 3;
/// `e_type` for an executable / a position-independent executable.
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

/// ELF segment permission flags (`p_flags`).
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Page size we report to the guest (`AT_PAGESZ`) and align maps to.
const PAGE: u32 = 0x1000;

/// Top of the user stack. The 32-bit interpreter has a 4 GiB space; we
/// keep the classic i386 Linux user/kernel split feel by placing the
/// stack just under 0xC000_0000.
const STACK_TOP: u32 = 0xC000_0000;
/// How much stack to map below [`STACK_TOP`].
const STACK_SIZE: u32 = 0x0080_0000; // 8 MiB

/// Auxiliary-vector tags we populate.
const AT_NULL: u32 = 0;
const AT_PHDR: u32 = 3;
const AT_PHENT: u32 = 4;
const AT_PHNUM: u32 = 5;
const AT_PAGESZ: u32 = 6;
const AT_ENTRY: u32 = 9;
const AT_RANDOM: u32 = 25;

/// The result of loading a static ELF: where to start executing, the
/// initial stack pointer, and the program break.
#[derive(Debug, Clone)]
pub struct ElfImage {
    pub entry: u32,
    pub stack_ptr: u32,
    pub brk: u32,
    /// `e_machine` of the loaded image (e.g. [`EM_386`]).
    pub machine: u16,
}

/// Errors the loader can surface.
#[derive(Debug, Clone)]
pub enum LoadError {
    Parse(String),
    Dynamic,
    NoLoadable,
    SegmentOutOfRange { offset: u64, len: u64 },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Parse(e) => write!(f, "ELF parse: {e}"),
            LoadError::Dynamic => write!(
                f,
                "dynamically-linked ELF (PT_INTERP) — only static binaries are supported"
            ),
            LoadError::NoLoadable => write!(f, "ELF has no PT_LOAD segments"),
            LoadError::SegmentOutOfRange { offset, len } => {
                write!(
                    f,
                    "PT_LOAD data [{offset:#x}..+{len:#x}] runs past the file"
                )
            }
        }
    }
}

/// Map `bytes` (a static ELF executable) into `mmu` and set up the
/// initial stack from `argv` / `envp`. Returns the [`ElfImage`].
///
/// # Errors
/// [`LoadError`] if the file is unparsable, dynamically linked, has no
/// loadable segments, or a segment's file range is out of bounds.
pub fn load_static(
    mmu: &mut Mmu,
    bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<ElfImage, LoadError> {
    let elf = Elf64File::parse(bytes).map_err(|e| LoadError::Parse(e.to_string()))?;

    if elf.phdrs.iter().any(|p| p.p_type == PT_INTERP) {
        return Err(LoadError::Dynamic);
    }

    // 1) Map every PT_LOAD: file bytes then zero-fill to memsz.
    let mut brk = 0u32;
    let mut mapped_any = false;
    for ph in elf.phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        mapped_any = true;
        let vaddr = ph.p_vaddr as u32;
        let memsz = ph.p_memsz as u32;
        let filesz = ph.p_filesz as u32;
        let offset = ph.p_offset as usize;

        // Page-align the mapping window [start, end).
        let start = vaddr & !(PAGE - 1);
        let end = (vaddr.wrapping_add(memsz).wrapping_add(PAGE - 1)) & !(PAGE - 1);
        let perm = seg_perm(ph.p_flags);
        // Map writable first so the initializer can populate it; the
        // guest then observes `perm`. (Our MMU stores perms per page; we
        // set the final perm via a second map — map() overwrites perms.)
        mmu.map(start, end.wrapping_sub(start), Perm::R | Perm::W | perm);

        let len = filesz as usize;
        let data = bytes
            .get(offset..offset + len)
            .ok_or(LoadError::SegmentOutOfRange {
                offset: ph.p_offset,
                len: ph.p_filesz,
            })?;
        mmu.write_initializer(vaddr, data)
            .map_err(|_| LoadError::SegmentOutOfRange {
                offset: ph.p_offset,
                len: ph.p_filesz,
            })?;
        // Re-apply the segment's real perms (e.g. drop W for a RX text
        // segment) now that it's populated.
        mmu.map(start, end.wrapping_sub(start), perm);

        brk = brk.max(end);
    }
    if !mapped_any {
        return Err(LoadError::NoLoadable);
    }

    // 2) Map the stack and build argc/argv/envp/auxv at the top.
    mmu.map(STACK_TOP - STACK_SIZE, STACK_SIZE, Perm::R | Perm::W);
    let stack_ptr = build_stack(mmu, &elf, argv, envp)?;

    Ok(ElfImage {
        entry: elf.ehdr.e_entry as u32,
        stack_ptr,
        brk,
        machine: elf.ehdr.e_machine,
    })
}

/// True iff `bytes` is an ELF this loader recognises as a Linux i386
/// executable (the only arch the interpreter can currently run).
#[must_use]
pub fn is_runnable_i386(bytes: &[u8]) -> bool {
    Elf64File::parse(bytes)
        .is_ok_and(|e| e.ehdr.e_machine == EM_386 && matches!(e.ehdr.e_type, ET_EXEC | ET_DYN))
}

fn seg_perm(p_flags: u32) -> Perm {
    let mut perm = Perm::default();
    if p_flags & PF_R != 0 {
        perm = perm | Perm::R;
    }
    if p_flags & PF_W != 0 {
        perm = perm | Perm::W;
    }
    if p_flags & PF_X != 0 {
        perm = perm | Perm::X;
    }
    perm
}

/// Write the initial stack and return the final `esp` (points at `argc`).
fn build_stack(
    mmu: &mut Mmu,
    elf: &Elf64File,
    argv: &[&str],
    envp: &[&str],
) -> Result<u32, LoadError> {
    let mut sp = STACK_TOP;
    let mut push_bytes = |mmu: &mut Mmu, data: &[u8]| -> u32 {
        sp -= data.len() as u32;
        let _ = mmu.write_initializer(sp, data);
        sp
    };

    // Argument + environment strings (NUL-terminated), recording pointers.
    let mut argv_ptrs = Vec::with_capacity(argv.len());
    for s in argv {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        argv_ptrs.push(push_bytes(mmu, &b));
    }
    let mut envp_ptrs = Vec::with_capacity(envp.len());
    for s in envp {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        envp_ptrs.push(push_bytes(mmu, &b));
    }
    // 16 bytes for AT_RANDOM (glibc/musl stack-canary + TLS seed).
    let at_random = push_bytes(mmu, &[0x42u8; 16]);

    // AT_PHDR: virtual address of the program-header table. For the
    // typical EXEC, the first PT_LOAD covers file offset 0, so the
    // headers sit at that segment's vaddr + e_phoff.
    let e_phoff = elf.ehdr.e_phoff;
    let phdr_vaddr = elf
        .phdrs
        .iter()
        .find(|p| p.p_type == PT_LOAD && e_phoff >= p.p_offset && e_phoff < p.p_offset + p.p_filesz)
        .map_or(0, |p| (p.p_vaddr + (e_phoff - p.p_offset)) as u32);

    let auxv: [(u32, u32); 7] = [
        (AT_PHDR, phdr_vaddr),
        (AT_PHENT, u32::from(elf.ehdr.e_phentsize)),
        (AT_PHNUM, u32::from(elf.ehdr.e_phnum)),
        (AT_PAGESZ, PAGE),
        (AT_ENTRY, elf.ehdr.e_entry as u32),
        (AT_RANDOM, at_random),
        (AT_NULL, 0),
    ];

    // Size of the main vector (words): argc + argv + NULL + envp + NULL
    // + auxv pairs.
    let words = 1 + (argv_ptrs.len() + 1) + (envp_ptrs.len() + 1) + auxv.len() * 2;
    let total = (words * 4) as u32;
    // 16-byte align the base so esp at entry is aligned.
    let mut esp = (sp - total) & !0xF;
    let base = esp;
    let mut put = |mmu: &mut Mmu, v: u32| {
        let _ = mmu.write_initializer(esp, &v.to_le_bytes());
        esp += 4;
    };
    put(mmu, argv_ptrs.len() as u32); // argc
    for p in &argv_ptrs {
        put(mmu, *p);
    }
    put(mmu, 0); // argv NULL
    for p in &envp_ptrs {
        put(mmu, *p);
    }
    put(mmu, 0); // envp NULL
    for (tag, val) in auxv {
        put(mmu, tag);
        put(mmu, val);
    }
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::Mmu;

    /// Minimal one-segment ELF32 EXEC (EM_386) with `code` at the entry.
    fn tiny_elf(code: &[u8]) -> Vec<u8> {
        const LOAD: u32 = 0x0804_8000;
        let (ehdr, phdr) = (52u32, 32u32);
        let code_off = ehdr + phdr;
        let filesz = code_off + code.len() as u32;
        let entry = LOAD + code_off;
        let mut e = Vec::new();
        e.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]);
        e.extend_from_slice(&[0u8; 8]);
        e.extend_from_slice(&2u16.to_le_bytes());
        e.extend_from_slice(&3u16.to_le_bytes());
        e.extend_from_slice(&1u32.to_le_bytes());
        e.extend_from_slice(&entry.to_le_bytes());
        e.extend_from_slice(&ehdr.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&(ehdr as u16).to_le_bytes());
        e.extend_from_slice(&(phdr as u16).to_le_bytes());
        e.extend_from_slice(&1u16.to_le_bytes());
        e.extend_from_slice(&[0u8; 6]);
        e.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        e.extend_from_slice(&0u32.to_le_bytes()); // p_offset
        e.extend_from_slice(&LOAD.to_le_bytes());
        e.extend_from_slice(&LOAD.to_le_bytes());
        e.extend_from_slice(&filesz.to_le_bytes());
        e.extend_from_slice(&filesz.to_le_bytes());
        e.extend_from_slice(&5u32.to_le_bytes()); // R|X
        e.extend_from_slice(&0x1000u32.to_le_bytes());
        e.extend_from_slice(code);
        e
    }

    #[test]
    fn maps_segment_and_lays_out_stack() {
        let mut mmu = Mmu::new();
        let elf = tiny_elf(&[0x90, 0x90, 0xc3]); // nop;nop;ret
        let img = load_static(&mut mmu, &elf, &["prog", "arg1"], &["X=1"]).expect("load");

        assert_eq!(img.entry, 0x0804_8000 + 52 + 32);
        assert_eq!(img.machine, EM_386);
        assert_eq!(mmu.load8(img.entry).unwrap(), 0x90);

        assert_eq!(mmu.load32(img.stack_ptr).unwrap(), 2, "argc");
        let argv0 = mmu.load32(img.stack_ptr + 4).unwrap();
        let argv1 = mmu.load32(img.stack_ptr + 8).unwrap();
        assert_eq!(mmu.load32(img.stack_ptr + 12).unwrap(), 0, "argv NULL");
        let read = |a: u32| {
            (0..)
                .map(|i| mmu.load8(a + i).unwrap())
                .take_while(|&b| b != 0)
                .collect::<Vec<_>>()
        };
        assert_eq!(read(argv0), b"prog");
        assert_eq!(read(argv1), b"arg1");
        assert_ne!(mmu.load32(img.stack_ptr + 16).unwrap(), 0, "envp[0]");
        assert_eq!(mmu.load32(img.stack_ptr + 20).unwrap(), 0, "envp NULL");
        assert_eq!(img.stack_ptr & 0xF, 0, "esp 16-byte aligned");
    }

    #[test]
    fn rejects_dynamic() {
        let mut e = tiny_elf(&[0xc3]);
        e[52] = 3; // p_type PT_LOAD -> PT_INTERP
        assert!(matches!(
            load_static(&mut Mmu::new(), &e, &["x"], &[]),
            Err(LoadError::Dynamic)
        ));
    }
}
