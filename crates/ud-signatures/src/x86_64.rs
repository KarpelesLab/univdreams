//! x86-64 signatures.
//!
//! Patterns transcribed from the canonical sequences GCC's linker
//! injects into ELF executables. Wildcards (`_`) cover RIP-relative
//! displacements (which depend on link layout) and short-jump targets
//! (which depend on the function's exact length).

use crate::{pat, Signature};

/// CRT helper functions inserted by GCC into x86-64 ELF executables.
///
/// These don't show up in `.symtab` for typical builds and are not
/// listed in `.eh_frame`; without signature matching they're invisible
/// to the discovery layer.
pub static CRT_HELPERS_X86_64: &[Signature] = &[
    Signature {
        name: "deregister_tm_clones",
        // 48 8d 3d ?? ?? ?? ??     lea rdi, [rip+disp32]      ; __TMC_END__
        // 48 8d 05 ?? ?? ?? ??     lea rax, [rip+disp32]      ; __TMC_END__
        // 48 39 f8                 cmp rdi, rax
        // 74 ??                    je rel8
        // 48 8b 05 ?? ?? ?? ??     mov rax, [rip+disp32]      ; _ITM_deregister
        // 48 85 c0                 test rax, rax
        // 74 ??                    je rel8
        // ff e0                    jmp rax
        pattern: pat!(
            0x48, 0x8d, 0x3d, _, _, _, _, 0x48, 0x8d, 0x05, _, _, _, _, 0x48, 0x39, 0xf8, 0x74, _,
            0x48, 0x8b, 0x05, _, _, _, _, 0x48, 0x85, 0xc0, 0x74, _, 0xff, 0xe0,
        ),
    },
    Signature {
        name: "register_tm_clones",
        // 48 8d 3d ?? ?? ?? ??     lea rdi, [rip+disp32]
        // 48 8d 35 ?? ?? ?? ??     lea rsi, [rip+disp32]
        // 48 29 fe                 sub rsi, rdi
        // 48 89 f0                 mov rax, rsi
        // 48 c1 ee 3f              shr rsi, 0x3f
        // 48 c1 f8 03              sar rax, 3
        // 48 01 c6                 add rsi, rax
        // 48 d1 fe                 sar rsi, 1
        // 74 ??                    je rel8
        pattern: pat!(
            0x48, 0x8d, 0x3d, _, _, _, _, 0x48, 0x8d, 0x35, _, _, _, _, 0x48, 0x29, 0xfe, 0x48,
            0x89, 0xf0, 0x48, 0xc1, 0xee, 0x3f, 0x48, 0xc1, 0xf8, 0x03, 0x48, 0x01, 0xc6, 0x48,
            0xd1, 0xfe, 0x74, _,
        ),
    },
    Signature {
        name: "__do_global_dtors_aux",
        // f3 0f 1e fa              endbr64
        // 80 3d ?? ?? ?? ?? 00     cmp byte ptr [rip+disp32], 0
        // 75 ??                    jne rel8
        // 55                       push rbp
        // 48 83 3d ?? ?? ?? ?? 00  cmp qword ptr [rip+disp32], 0
        // 48 89 e5                 mov rbp, rsp
        // 74 ??                    je rel8
        pattern: pat!(
            0xf3, 0x0f, 0x1e, 0xfa, 0x80, 0x3d, _, _, _, _, 0x00, 0x75, _, 0x55, 0x48, 0x83, 0x3d,
            _, _, _, _, 0x00, 0x48, 0x89, 0xe5, 0x74, _,
        ),
    },
    Signature {
        name: "frame_dummy",
        // f3 0f 1e fa              endbr64
        // e9 ?? ?? ?? ??           jmp rel32  -> register_tm_clones
        //
        // Tiny pattern (9 bytes); could collide with any other
        // function that happens to start with `endbr64; jmp rel32`.
        // Linkers emit frame_dummy with this exact body for GCC ELF
        // executables, so on real binaries it's distinctive.
        pattern: pat!(0xf3, 0x0f, 0x1e, 0xfa, 0xe9, _, _, _, _,),
    },
];
