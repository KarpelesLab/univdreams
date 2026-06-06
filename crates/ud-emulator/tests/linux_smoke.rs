//! End-to-end smoke test for the Linux/i386 personality: hand-assemble a
//! tiny *static* ELF that does `write(1, "hi\n", 3); exit(0)` via
//! `int 0x80`, load + run it, and assert the captured stdout + exit code.
//!
//! No external toolchain — the ELF is built byte-for-byte here.

use ud_emulator::Sandbox;

const LOAD: u32 = 0x0804_8000;
const EHDR: u32 = 52; // ELF32 header
const PHDR: u32 = 32; // one program header

/// Build a minimal static i386 ELF whose entry runs `code` (which must end
/// by calling `exit`/`exit_group`). `data` is appended after the code and
/// its load address is returned so the caller can patch a `mov`.
fn build_elf(code: &[u8], data: &[u8]) -> Vec<u8> {
    let code_off = EHDR + PHDR;
    let filesz = code_off + code.len() as u32 + data.len() as u32;
    let entry = LOAD + code_off;

    let mut e = Vec::new();
    // --- ELF header ---
    e.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]); // magic, 32-bit LE
    e.extend_from_slice(&[0u8; 8]); // e_ident pad
    e.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    e.extend_from_slice(&3u16.to_le_bytes()); // e_machine = EM_386
    e.extend_from_slice(&1u32.to_le_bytes()); // e_version
    e.extend_from_slice(&entry.to_le_bytes()); // e_entry
    e.extend_from_slice(&EHDR.to_le_bytes()); // e_phoff (phdr right after ehdr)
    e.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
    e.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    e.extend_from_slice(&(EHDR as u16).to_le_bytes()); // e_ehsize
    e.extend_from_slice(&(PHDR as u16).to_le_bytes()); // e_phentsize
    e.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                              // --- program header (PT_LOAD, whole file, R+X) ---
    e.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    e.extend_from_slice(&0u32.to_le_bytes()); // p_offset
    e.extend_from_slice(&LOAD.to_le_bytes()); // p_vaddr
    e.extend_from_slice(&LOAD.to_le_bytes()); // p_paddr
    e.extend_from_slice(&filesz.to_le_bytes()); // p_filesz
    e.extend_from_slice(&filesz.to_le_bytes()); // p_memsz
    e.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    e.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align
                                                   // --- code + data ---
    e.extend_from_slice(code);
    e.extend_from_slice(data);
    e
}

#[test]
fn static_i386_write_exit() {
    let msg = b"hi\n";
    let code_off = EHDR + PHDR;
    // The data (msg) sits right after the code; compute its load address.
    let code_len: u32 = 31;
    let msg_addr = LOAD + code_off + code_len;

    let mut code = Vec::new();
    code.extend_from_slice(&[0xb8, 4, 0, 0, 0]); // mov eax, 4   (sys_write)
    code.extend_from_slice(&[0xbb, 1, 0, 0, 0]); // mov ebx, 1   (fd = stdout)
    code.push(0xb9); // mov ecx, msg_addr
    code.extend_from_slice(&msg_addr.to_le_bytes());
    code.extend_from_slice(&[0xba, msg.len() as u8, 0, 0, 0]); // mov edx, 3
    code.extend_from_slice(&[0xcd, 0x80]); // int 0x80
    code.extend_from_slice(&[0xb8, 1, 0, 0, 0]); // mov eax, 1   (sys_exit)
    code.extend_from_slice(&[0x31, 0xdb]); // xor ebx, ebx (code = 0)
    code.extend_from_slice(&[0xcd, 0x80]); // int 0x80
    assert_eq!(
        code.len() as u32,
        code_len,
        "code length must match msg_addr calc"
    );

    let elf = build_elf(&code, msg);

    let mut sb = Sandbox::new_linux();
    sb.host.instruction_budget = Some(1_000_000);
    sb.load_linux_elf("hi", &elf).expect("load static ELF");
    let exit = sb.run_linux().expect("run");

    assert_eq!(sb.linux.stdout, b"hi\n", "captured stdout");
    assert_eq!(exit, 0, "exit code");
    assert!(sb.linux.unsupported.is_empty(), "no unsupported syscalls");
}
