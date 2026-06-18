//! ELF loader for the Linux personality.
//!
//! Maps an executable's `PT_LOAD` segments into the MMU and builds the initial
//! process stack (argc / argv / envp / auxv) per the System V ABI, then reports
//! the entry point and stack pointer the run loop jumps to.
//!
//! Both **static** and **dynamically linked** (`PT_INTERP`) executables load:
//! for a dynamic binary the interpreter (`ld-musl`, …) is read from the guest
//! rootfs (the [`MountTable`](crate::fsmount::MountTable)), mapped at a fixed
//! base, and execution starts in it with a full auxv (`AT_BASE`, `AT_PHDR`,
//! `AT_ENTRY`, `AT_RANDOM`, …) so it can relocate and run the main object.

use ud_format::elf::{Elf64File, EM_386, EM_AARCH64, EM_X86_64};

use super::mem::GuestMem;
use crate::emulator::Perm;

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
const AT_BASE: u32 = 7;
const AT_ENTRY: u32 = 9;
const AT_UID: u32 = 11;
const AT_EUID: u32 = 12;
const AT_GID: u32 = 13;
const AT_EGID: u32 = 14;
const AT_CLKTCK: u32 = 17;
const AT_SECURE: u32 = 23;
const AT_RANDOM: u32 = 25;
const AT_EXECFN: u32 = 31;

/// Load bias for a position-independent (`ET_DYN`) **main** executable, and the
/// fixed base for the **interpreter** (`ld-musl`). Chosen low so everything
/// fits the 4 GiB MMU, and spaced apart from the mmap arena (`0x4000_0000`) and
/// stack (`0xC000_0000`). The main exe + its `brk` heap live below the interp.
const MAIN_DYN_BASE: u32 = 0x0100_0000;
const INTERP_BASE: u32 = 0x3000_0000;

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
    /// A dynamic ELF named an interpreter we couldn't read from the rootfs.
    InterpNotFound(String),
    NoLoadable,
    SegmentOutOfRange {
        offset: u64,
        len: u64,
    },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Parse(e) => write!(f, "ELF parse: {e}"),
            LoadError::Dynamic => write!(
                f,
                "dynamically-linked ELF (PT_INTERP) needs a root filesystem (--rootfs) to load its interpreter"
            ),
            LoadError::InterpNotFound(p) => {
                write!(f, "interpreter {p:?} not found in the root filesystem")
            }
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

/// Map `bytes` (a static ELF executable) into `mmu` and set up the initial
/// stack. Convenience wrapper over [`load_elf`] with no filesystem — a
/// dynamically linked ELF is rejected with [`LoadError::Dynamic`].
///
/// # Errors
/// [`LoadError`] if the file is unparsable, dynamically linked, has no
/// loadable segments, or a segment's file range is out of bounds.
pub fn load_static(
    mmu: &mut dyn GuestMem,
    bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<ElfImage, LoadError> {
    load_elf(mmu, None, bytes, argv, envp)
}

/// Map `bytes` into `mmu` and set up the initial process stack. Handles both
/// **static** executables and **dynamically linked** ones (`PT_INTERP`): the
/// interpreter (`ld-musl`, …) is read from `mounts` (the guest rootfs), mapped
/// at [`INTERP_BASE`], and execution starts in it with a full auxv so it can
/// relocate the main object and run it.
///
/// `mounts` is required for dynamic binaries; a dynamic ELF with `mounts =
/// None` is rejected with [`LoadError::Dynamic`].
///
/// # Errors
/// [`LoadError`] for parse failures, a dynamic binary with no rootfs, a
/// missing/unreadable interpreter, no loadable segments, or an out-of-range
/// segment.
pub fn load_elf(
    mmu: &mut dyn GuestMem,
    mounts: Option<&mut crate::fsmount::MountTable>,
    bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<ElfImage, LoadError> {
    let elf = Elf64File::parse(bytes).map_err(|e| LoadError::Parse(e.to_string()))?;
    let ptr64 = matches!(elf.ehdr.e_machine, EM_X86_64 | EM_AARCH64);

    let interp_path = interp_of(&elf, bytes);
    if interp_path.is_some() && mounts.is_none() {
        return Err(LoadError::Dynamic);
    }

    // The main object: PIE (`ET_DYN`) gets a load bias; a fixed-address
    // executable maps at its own vaddrs.
    let main_bias = if elf.ehdr.e_type == ET_DYN && interp_path.is_some() {
        MAIN_DYN_BASE
    } else {
        0
    };
    let brk = map_segments(mmu, bytes, &elf, main_bias)?;

    // Stack region.
    mmu.map(STACK_TOP - STACK_SIZE, STACK_SIZE, Perm::R | Perm::W);

    // AT_PHDR: where the program headers ended up in memory.
    let e_phoff = elf.ehdr.e_phoff;
    let phdr_vaddr = elf
        .phdrs
        .iter()
        .find(|p| p.p_type == PT_LOAD && e_phoff >= p.p_offset && e_phoff < p.p_offset + p.p_filesz)
        .map_or(0, |p| {
            main_bias.wrapping_add((p.p_vaddr + (e_phoff - p.p_offset)) as u32)
        });

    let main_entry = main_bias.wrapping_add(elf.ehdr.e_entry as u32);

    // Dynamic: load the interpreter and start execution in it.
    let (entry, at_base) = if let Some(path) = interp_path {
        let mounts = mounts.expect("checked above");
        let interp_bytes = mounts
            .read_file(&path)
            .ok_or_else(|| LoadError::InterpNotFound(path.clone()))?;
        let interp = Elf64File::parse(&interp_bytes)
            .map_err(|e| LoadError::Parse(format!("interp {path}: {e}")))?;
        map_segments(mmu, &interp_bytes, &interp, INTERP_BASE)?;
        (
            INTERP_BASE.wrapping_add(interp.ehdr.e_entry as u32),
            Some(INTERP_BASE),
        )
    } else {
        (main_entry, None)
    };

    let aux = AuxParams {
        phdr: phdr_vaddr,
        phent: u32::from(elf.ehdr.e_phentsize),
        phnum: u32::from(elf.ehdr.e_phnum),
        entry: main_entry,
        base: at_base,
    };
    let stack_ptr = build_stack(mmu, argv, envp, ptr64, &aux)?;

    Ok(ElfImage {
        entry,
        stack_ptr,
        brk,
        machine: elf.ehdr.e_machine,
    })
}

/// The `PT_INTERP` path (the dynamic linker), if this ELF is dynamically
/// linked.
fn interp_of(elf: &Elf64File, bytes: &[u8]) -> Option<String> {
    let ph = elf.phdrs.iter().find(|p| p.p_type == PT_INTERP)?;
    let s = bytes.get(ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize)?;
    let s = s.split(|&b| b == 0).next().unwrap_or(s);
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Map every `PT_LOAD` of `elf` into `mmu`, offset by `bias` (0 for a
/// fixed-address object). Populates file bytes then enforces the segment's
/// permissions. Returns the page-aligned high-water mark (the program break /
/// end of the object).
fn map_segments(
    mmu: &mut dyn GuestMem,
    bytes: &[u8],
    elf: &Elf64File,
    bias: u32,
) -> Result<u32, LoadError> {
    let mut high = 0u32;
    let mut mapped_any = false;
    for ph in elf.phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        mapped_any = true;
        let vaddr = (ph.p_vaddr as u32).wrapping_add(bias);
        let memsz = ph.p_memsz as u32;
        let filesz = ph.p_filesz as u32;
        let offset = ph.p_offset as usize;

        let start = vaddr & !(PAGE - 1);
        let end = (vaddr.wrapping_add(memsz).wrapping_add(PAGE - 1)) & !(PAGE - 1);
        let perm = seg_perm(ph.p_flags);
        // Map writable first so the initializer can populate it; then enforce
        // the segment's real perms (map() overwrites perms, keeps bytes).
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
        // Zero the `.bss` tail (`[filesz, memsz)`). On a fresh address space the
        // pages are already zero, but an `execve` that reloads over dirty memory
        // leaves stale bytes there — corrupting zero-initialized globals
        // (function pointers, flags) and crashing the program.
        if memsz > filesz {
            let zeros = vec![0u8; (memsz - filesz) as usize];
            let _ = mmu.write_initializer(vaddr.wrapping_add(filesz), &zeros);
        }
        mmu.map(start, end.wrapping_sub(start), perm);

        high = high.max(end);
    }
    if !mapped_any {
        return Err(LoadError::NoLoadable);
    }
    Ok(high)
}

/// True iff `bytes` is an ELF this loader recognises as a Linux i386
/// executable.
#[must_use]
pub fn is_runnable_i386(bytes: &[u8]) -> bool {
    Elf64File::parse(bytes)
        .is_ok_and(|e| e.ehdr.e_machine == EM_386 && matches!(e.ehdr.e_type, ET_EXEC | ET_DYN))
}

/// True iff `bytes` is a static ELF whose `e_machine` an interpreter
/// back-end exists for (i386, x86-64, or aarch64).
#[must_use]
pub fn is_runnable(bytes: &[u8]) -> bool {
    Elf64File::parse(bytes).is_ok_and(|e| {
        matches!(e.ehdr.e_machine, EM_386 | EM_X86_64 | EM_AARCH64)
            && matches!(e.ehdr.e_type, ET_EXEC | ET_DYN)
    })
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

/// Auxiliary-vector values the caller computed from the loaded image(s).
struct AuxParams {
    phdr: u32,
    phent: u32,
    phnum: u32,
    /// Entry point of the **main** object (not the interpreter).
    entry: u32,
    /// `AT_BASE` — the interpreter's load base, for a dynamic binary.
    base: Option<u32>,
}

/// Write the initial stack and return the final `sp` (points at `argc`).
///
/// `ptr64` selects the word size of the argc/argv/envp/auxv vector: 8-byte
/// for x86-64 / aarch64, 4-byte for i386. The string area and AT_RANDOM
/// block are byte-addressed identically either way.
fn build_stack(
    mmu: &mut dyn GuestMem,
    argv: &[&str],
    envp: &[&str],
    ptr64: bool,
    aux: &AuxParams,
) -> Result<u32, LoadError> {
    let word = if ptr64 { 8u32 } else { 4u32 };
    let mut sp = STACK_TOP;
    let mut push_bytes = |mmu: &mut dyn GuestMem, data: &[u8]| -> u32 {
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
    // AT_EXECFN points at argv[0]'s string (the program path).
    let execfn = argv_ptrs.first().copied().unwrap_or(0);

    let mut auxv: Vec<(u32, u32)> = vec![
        (AT_PHDR, aux.phdr),
        (AT_PHENT, aux.phent),
        (AT_PHNUM, aux.phnum),
        (AT_PAGESZ, PAGE),
        (AT_ENTRY, aux.entry),
        (AT_RANDOM, at_random),
        (AT_EXECFN, execfn),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
    ];
    if let Some(base) = aux.base {
        auxv.push((AT_BASE, base));
    }
    auxv.push((AT_NULL, 0));

    // Size of the main vector (words): argc + argv + NULL + envp + NULL
    // + auxv pairs.
    let words = 1 + (argv_ptrs.len() + 1) + (envp_ptrs.len() + 1) + auxv.len() * 2;
    let total = words as u32 * word;
    // 16-byte align the base so sp at entry is aligned.
    let mut wsp = (sp - total) & !0xF;
    let base = wsp;
    let mut put = |mmu: &mut dyn GuestMem, v: u32| {
        if ptr64 {
            let _ = mmu.write_initializer(wsp, &u64::from(v).to_le_bytes());
        } else {
            let _ = mmu.write_initializer(wsp, &v.to_le_bytes());
        }
        wsp += word;
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

    /// An ELF32 `ET_DYN` with a second program header of type `PT_INTERP`
    /// naming `interp`. The first PT_LOAD maps file offset 0 (covering the
    /// headers + interp string + code) at vaddr 0 so it's a clean PIE.
    fn tiny_dyn(code: &[u8], interp: &str) -> Vec<u8> {
        let (ehdr, phdr) = (52u32, 32u32);
        let phnum = 2u32;
        let interp_off = ehdr + phdr * phnum; // 116
        let mut interp_b = interp.as_bytes().to_vec();
        interp_b.push(0);
        let code_off = interp_off + interp_b.len() as u32;
        let filesz = code_off + code.len() as u32;
        let entry = code_off; // vaddr 0 base
        let mut e = Vec::new();
        e.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]);
        e.extend_from_slice(&[0u8; 8]);
        e.extend_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
        e.extend_from_slice(&3u16.to_le_bytes()); // e_machine = EM_386
        e.extend_from_slice(&1u32.to_le_bytes());
        e.extend_from_slice(&entry.to_le_bytes());
        e.extend_from_slice(&ehdr.to_le_bytes()); // e_phoff
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&(ehdr as u16).to_le_bytes());
        e.extend_from_slice(&(phdr as u16).to_le_bytes());
        e.extend_from_slice(&(phnum as u16).to_le_bytes());
        e.extend_from_slice(&[0u8; 6]);
        // phdr[0] PT_LOAD: file [0, filesz] at vaddr 0.
        e.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        e.extend_from_slice(&0u32.to_le_bytes()); // p_offset
        e.extend_from_slice(&0u32.to_le_bytes()); // p_vaddr
        e.extend_from_slice(&0u32.to_le_bytes()); // p_paddr
        e.extend_from_slice(&filesz.to_le_bytes());
        e.extend_from_slice(&filesz.to_le_bytes());
        e.extend_from_slice(&5u32.to_le_bytes()); // R|X
        e.extend_from_slice(&0x1000u32.to_le_bytes());
        // phdr[1] PT_INTERP.
        e.extend_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        e.extend_from_slice(&interp_off.to_le_bytes()); // p_offset
        e.extend_from_slice(&interp_off.to_le_bytes()); // p_vaddr
        e.extend_from_slice(&interp_off.to_le_bytes()); // p_paddr
        e.extend_from_slice(&(interp_b.len() as u32).to_le_bytes());
        e.extend_from_slice(&(interp_b.len() as u32).to_le_bytes());
        e.extend_from_slice(&4u32.to_le_bytes()); // R
        e.extend_from_slice(&1u32.to_le_bytes());
        debug_assert_eq!(e.len() as u32, interp_off);
        e.extend_from_slice(&interp_b);
        e.extend_from_slice(code);
        e
    }

    #[test]
    fn dynamic_loads_interp_from_mounts() {
        use crate::fsmount::MountTable;
        // The interpreter is just another tiny ELF placed in the rootfs.
        let interp = tiny_elf(&[0x90, 0xc3]);
        let interp_entry = u32::from_le_bytes(interp[24..28].try_into().unwrap());
        let mut mounts = MountTable::new();
        mounts.insert("/lib/myld", interp.clone());

        let main = tiny_dyn(&[0xc3], "/lib/myld");
        let mut mmu = Mmu::new();
        let img = load_elf(&mut mmu, Some(&mut mounts), &main, &["prog"], &[]).expect("dyn load");

        // Execution starts in the interpreter (mapped at INTERP_BASE).
        assert_eq!(img.entry, INTERP_BASE.wrapping_add(interp_entry));
        // The interpreter's first instruction is reachable in memory.
        assert_eq!(mmu.load8(img.entry).unwrap(), 0x90);
        // The main object was biased to MAIN_DYN_BASE; its entry byte (0xc3)
        // sits at MAIN_DYN_BASE + code_off.
        assert_eq!(img.machine, EM_386);
    }

    #[test]
    fn dynamic_without_interp_in_mounts_errors() {
        use crate::fsmount::MountTable;
        let main = tiny_dyn(&[0xc3], "/lib/absent");
        let mut mounts = MountTable::new();
        assert!(matches!(
            load_elf(&mut Mmu::new(), Some(&mut mounts), &main, &["p"], &[]),
            Err(LoadError::InterpNotFound(_))
        ));
        // And with no rootfs at all, it's the friendlier Dynamic error.
        assert!(matches!(
            load_elf(&mut Mmu::new(), None, &main, &["p"], &[]),
            Err(LoadError::Dynamic)
        ));
    }
}
