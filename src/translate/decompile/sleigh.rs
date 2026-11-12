//! Code of architectures without a hand-written decoder, disassembled
//! with Ghidra's SLEIGH specifications ([`crate::arch::sleigh`]).
//!
//! Every instruction becomes `@asm("text", [bytes])` with its bytes
//! pinned, so the source compiles back byte for byte whatever the text
//! says; bytes that don't decode become `@asm(".byte 0xNN", [0xNN])`.
//! Code is split into `code_<addr>` blocks of at most [`BLOCK`]
//! instructions, since nothing yet says where functions start.

use crate::ast::Item;
#[cfg(feature = "sleigh")]
use crate::ast::{FnDecl, Stmt};

/// Instructions per emitted block.
#[cfg(feature = "sleigh")]
const BLOCK: usize = 512;

/// The SLEIGH language for an ELF file's `e_machine`, class and byte
/// order, if one is embedded and compiles.
#[must_use]
pub fn elf_language(machine: u16, is_64: bool, big_endian: bool) -> Option<&'static str> {
    let e = |be: &'static str, le: &'static str| if big_endian { be } else { le };
    Some(match (machine, is_64) {
        (2 | 18, _) => "sparc:BE:32:default",
        (43, _) => "sparc:BE:64:default",
        (4, _) => "68000:BE:32:default",
        (8 | 10, false) => e("MIPS:BE:32:default", "MIPS:LE:32:default"),
        (8, true) => e("MIPS:BE:64:default", "MIPS:LE:64:default"),
        (20, _) => e("PowerPC:BE:32:default", "PowerPC:LE:32:default"),
        (21, _) => e("PowerPC:BE:64:default", "PowerPC:LE:64:default"),
        (40, _) => e("ARM:BE:32:v8", "ARM:LE:32:v8"),
        (42, _) if big_endian => "SuperH:BE:32:SH-2",
        (94, _) => e("Xtensa:BE:32:default", "Xtensa:LE:32:default"),
        (105, _) => "TI_MSP430X:LE:32:default",
        (220, _) => "z80:LE:16:default",
        (258, true) => "Loongarch:LE:64:lp64d",
        (258, false) => "Loongarch:LE:32:ilp32d",
        _ => return None,
    })
}

/// The SLEIGH language for an `arch` name given on the command line:
/// a Ghidra language id (`ARM:LE:32:v8`) or a common short name.
#[must_use]
pub fn named_language(arch: &str) -> Option<&str> {
    if arch.contains(':') {
        return Some(arch);
    }
    Some(match arch.to_ascii_lowercase().as_str() {
        "arm" | "armel" | "arm32" => "ARM:LE:32:v8",
        "armeb" => "ARM:BE:32:v8",
        "mips" | "mipsbe" => "MIPS:BE:32:default",
        "mipsel" | "mipsle" | "mips_rs3_le" => "MIPS:LE:32:default",
        "mips64" => "MIPS:BE:64:default",
        "mips64el" => "MIPS:LE:64:default",
        "ppc" | "powerpc" => "PowerPC:BE:32:default",
        "ppc64" | "powerpc64" => "PowerPC:BE:64:default",
        "ppcle" | "powerpcle" => "PowerPC:LE:32:default",
        "ppc64le" => "PowerPC:LE:64:default",
        "sparc" | "sparc32plus" => "sparc:BE:32:default",
        "sparc64" | "sparcv9" => "sparc:BE:64:default",
        "m68k" | "68000" | "68k" => "68000:BE:32:default",
        "coldfire" => "68000:BE:32:Coldfire",
        "sh" | "sh2" | "superh" => "SuperH:BE:32:SH-2",
        "xtensa" => "Xtensa:LE:32:default",
        "xtensaeb" => "Xtensa:BE:32:default",
        "z80" => "z80:LE:16:default",
        "z180" => "z180:LE:16:default",
        "8051" | "mcs51" => "8051:BE:16:default",
        "8048" => "8048:LE:16:default",
        "8085" => "8085:LE:16:default",
        "6809" => "6809:BE:16:default",
        "hc08" => "HC08:BE:16:default",
        "hcs08" => "HCS08:BE:16:default",
        "hc05" => "HC05:BE:16:default",
        "msp430" => "TI_MSP430:LE:16:default",
        "msp430x" => "TI_MSP430X:LE:32:default",
        "avr32" => "avr32:BE:32:default",
        "cr16" => "CR16AB:LE:16:default",
        "loongarch" | "loongarch64" => "Loongarch:LE:64:lp64d",
        "jvm" => "JVM:BE:32:default",
        _ => return None,
    })
}

/// `bytes`, loaded at `addr`, disassembled with `language` as blocks of
/// pinned instructions. `None` if the language isn't available.
#[must_use]
pub fn code_items(language: &str, addr: u64, bytes: &[u8]) -> Option<Vec<Item>> {
    #[cfg(feature = "sleigh")]
    {
        let lang = crate::arch::sleigh::language(language).ok()?;
        // The engine asserts on some encodings; keep the bytes then.
        std::panic::catch_unwind(|| disassemble(&lang, addr, bytes)).ok()
    }
    #[cfg(not(feature = "sleigh"))]
    {
        let _ = (language, addr, bytes);
        None
    }
}

#[cfg(feature = "sleigh")]
fn disassemble(lang: &crate::arch::sleigh::Language, addr: u64, bytes: &[u8]) -> Vec<Item> {
    let mut d = lang.disassembler();
    let mut items = Vec::new();
    let mut body = Vec::new();
    let mut start = addr;
    let mut off = 0usize;
    while off < bytes.len() {
        let at = addr + off as u64;
        if body.len() >= BLOCK {
            items.push(block(start, std::mem::take(&mut body)));
            start = at;
        }
        if let Some((len, text)) = d.decode(&bytes[off..], at) {
            body.push(Stmt::asm(text, bytes[off..off + len].to_vec()));
            off += len;
        } else {
            body.push(Stmt::asm(
                format!(".byte 0x{:02x}", bytes[off]),
                vec![bytes[off]],
            ));
            off += 1;
        }
    }
    if !body.is_empty() {
        items.push(block(start, body));
    }
    items
}

#[cfg(feature = "sleigh")]
fn block(addr: u64, body: Vec<Stmt>) -> Item {
    Item::Function(FnDecl {
        addr: Some(addr),
        name: format!("code_{addr:x}"),
        attrs: Vec::new(),
        signature: None,
        locals: Vec::new(),
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_map_to_languages() {
        assert_eq!(elf_language(8, false, true), Some("MIPS:BE:32:default"));
        assert_eq!(elf_language(40, false, false), Some("ARM:LE:32:v8"));
        assert_eq!(elf_language(164, false, false), None);
        assert_eq!(named_language("mipsel"), Some("MIPS:LE:32:default"));
        assert_eq!(named_language("ARM:BE:32:v7"), Some("ARM:BE:32:v7"));
        assert_eq!(named_language("hexagon"), None);
    }

    #[cfg(feature = "sleigh")]
    #[test]
    fn arm_code_round_trips_through_source() {
        // mov r0, #1 ; bx lr ; then a byte that is no instruction.
        let bytes = [0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1, 0xff];
        let items = code_items("ARM:LE:32:v8", 0x8000, &bytes).unwrap();
        let file = crate::ast::UdFile {
            module: crate::ast::Module { fields: vec![] },
            items,
        };
        let text = crate::ast::emit(&file);
        assert!(
            text.contains("@asm(\"bx lr\", [0x1e, 0xff, 0x2f, 0xe1])"),
            "{text}"
        );
        assert!(text.contains(".byte 0xff"), "{text}");
        let parsed = crate::translate::compile::parse(&text).unwrap();
        let crate::ast::Item::Function(f) = &parsed.items[0] else {
            panic!("{text}");
        };
        let lowered =
            crate::translate::compile::lower_function_bytes(f, &crate::arch::opaque::OpaqueCodec)
                .unwrap();
        assert_eq!(lowered, bytes);
    }
}
