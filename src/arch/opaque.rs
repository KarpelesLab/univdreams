//! Architectures without an instruction decoder yet.
//!
//! Their code round-trips as `@raw` bytes: the container around it (ELF
//! headers and sections, a raw image's layout) is still decoded and
//! rebuilt, so every file a supported container holds compiles back
//! byte for byte. [`OpaqueCodec`] answers for those architectures at
//! lower time and refuses every encoding request, which keeps any
//! pinned bytes as they are.

use crate::arch::codec::{ArchCodec, ArchError, EncodeHints};

/// Well-known ELF `e_machine` values and the `arch` names `.ud` files
/// use for them.
pub const ELF_MACHINES: &[(u16, &str)] = &[
    (2, "sparc"),
    (3, "i386"),
    (4, "m68k"),
    (5, "m88k"),
    (7, "i860"),
    (8, "mips"),
    (10, "mips_rs3_le"),
    (15, "parisc"),
    (18, "sparc32plus"),
    (20, "ppc"),
    (21, "ppc64"),
    (22, "s390"),
    (40, "arm"),
    (41, "alpha"),
    (42, "sh"),
    (43, "sparcv9"),
    (46, "h8_300"),
    (50, "ia64"),
    (53, "m68hc12"),
    (62, "x86_64"),
    (69, "m68hc11"),
    (70, "m68hc08"),
    (75, "vax"),
    (76, "cris"),
    (83, "avr"),
    (87, "v850"),
    (88, "m32r"),
    (89, "mn10300"),
    (92, "openrisc"),
    (93, "arc_compact"),
    (94, "xtensa"),
    (105, "msp430"),
    (106, "blackfin"),
    (113, "altera_nios2"),
    (115, "crx"),
    (140, "tms320c6000"),
    (164, "hexagon"),
    (167, "nds32"),
    (171, "cr16"),
    (183, "aarch64"),
    (186, "stm8"),
    (189, "microblaze"),
    (190, "cuda"),
    (195, "arc_compact2"),
    (220, "z80"),
    (224, "amdgpu"),
    (243, "riscv"),
    (247, "bpf"),
    (252, "csky"),
    (258, "loongarch"),
    (263, "sbf"),
];

/// The `arch` name for an ELF `e_machine` value.
#[must_use]
pub fn elf_machine_name(e_machine: u16) -> Option<&'static str> {
    ELF_MACHINES
        .iter()
        .find(|(m, _)| *m == e_machine)
        .map(|(_, n)| *n)
}

/// Codec for an architecture univdreams can't decode yet.
#[derive(Debug, Clone, Copy)]
pub struct OpaqueCodec;

impl OpaqueCodec {
    fn unsupported(operation: &'static str) -> ArchError {
        ArchError::Unsupported {
            arch: "opaque",
            operation,
        }
    }
}

impl ArchCodec for OpaqueCodec {
    fn name(&self) -> &'static str {
        "opaque"
    }

    fn assemble_one(&self, _text: &str, _addr: u64) -> Result<Vec<u8>, ArchError> {
        Err(Self::unsupported("assemble"))
    }

    fn encode_jump(&self, _: u64, _: u64, _: EncodeHints) -> Result<Vec<u8>, ArchError> {
        Err(Self::unsupported("jump"))
    }

    fn encode_call(&self, _: u64, _: u64, _: EncodeHints) -> Result<Vec<u8>, ArchError> {
        Err(Self::unsupported("call"))
    }

    fn encode_cond_jump(
        &self,
        _: &str,
        _: u64,
        _: u64,
        _: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        Err(Self::unsupported("cond_jump"))
    }

    fn encoded_jump_size(&self, _: u64, _: u64, _: EncodeHints) -> usize {
        0
    }

    fn encoded_cond_jump_size(&self, _: u64, _: u64, _: EncodeHints) -> usize {
        0
    }

    fn encoded_call_size(&self, _: u64, _: u64, _: EncodeHints) -> usize {
        0
    }
}

/// Register the opaque codec. It must come after every real codec: it
/// answers for any architecture named in [`ELF_MACHINES`] (or
/// `"unknown"`), so a real codec has to claim its own names first.
pub fn register() {
    crate::arch::codec::register(factory);
}

fn factory(arch_name: Option<&str>, e_machine: Option<u64>) -> Option<Box<dyn ArchCodec>> {
    let named =
        arch_name.is_some_and(|n| n == "unknown" || ELF_MACHINES.iter().any(|(_, m)| *m == n));
    let numbered = e_machine
        .and_then(|m| u16::try_from(m).ok())
        .is_some_and(|m| elf_machine_name(m).is_some());
    (named || (arch_name.is_none() && numbered))
        .then(|| Box::new(OpaqueCodec) as Box<dyn ArchCodec>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_names_are_unique() {
        for (i, (m, n)) in ELF_MACHINES.iter().enumerate() {
            for (m2, n2) in &ELF_MACHINES[i + 1..] {
                assert!(m != m2 && n != n2, "{m} {n}");
            }
        }
        assert_eq!(elf_machine_name(164), Some("hexagon"));
        assert_eq!(elf_machine_name(0xfffe), None);
    }

    #[test]
    fn factory_claims_only_known_names() {
        assert!(factory(Some("hexagon"), None).is_some());
        assert!(factory(Some("unknown"), None).is_some());
        assert!(factory(None, Some(40)).is_some());
        assert!(factory(Some("hexagn"), None).is_none());
        assert!(factory(None, Some(0xfffe)).is_none());
    }
}
