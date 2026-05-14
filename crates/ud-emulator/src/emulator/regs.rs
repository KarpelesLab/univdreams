//! 32-bit x86 register file + EFLAGS bookkeeping.
//!
//! References: Intel® 64 and IA-32 Architectures Software
//! Developer's Manual, Volume 1 §3.4 (general-purpose registers)
//! and §3.4.3 (EFLAGS register).

/// General-purpose register index (encoding from ModR/M reg/rm
/// fields; matches Intel's /r convention).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg32 {
    Eax = 0,
    Ecx = 1,
    Edx = 2,
    Ebx = 3,
    Esp = 4,
    Ebp = 5,
    Esi = 6,
    Edi = 7,
}

impl Reg32 {
    /// Decode a 3-bit register selector. The 3-bit space is fully
    /// covered by [`Reg32`] so this is total.
    pub fn from_bits(b: u8) -> Reg32 {
        match b & 0b111 {
            0 => Reg32::Eax,
            1 => Reg32::Ecx,
            2 => Reg32::Edx,
            3 => Reg32::Ebx,
            4 => Reg32::Esp,
            5 => Reg32::Ebp,
            6 => Reg32::Esi,
            7 => Reg32::Edi,
            _ => unreachable!(),
        }
    }

    /// Mnemonic — for trap diagnostics + debug printing.
    pub const fn name(self) -> &'static str {
        match self {
            Reg32::Eax => "eax",
            Reg32::Ecx => "ecx",
            Reg32::Edx => "edx",
            Reg32::Ebx => "ebx",
            Reg32::Esp => "esp",
            Reg32::Ebp => "ebp",
            Reg32::Esi => "esi",
            Reg32::Edi => "edi",
        }
    }
}

/// 16-bit register index (the low halves of the 32-bit GPRs).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg16 {
    Ax = 0,
    Cx = 1,
    Dx = 2,
    Bx = 3,
    Sp = 4,
    Bp = 5,
    Si = 6,
    Di = 7,
}

impl Reg16 {
    pub fn from_bits(b: u8) -> Reg16 {
        match b & 0b111 {
            0 => Reg16::Ax,
            1 => Reg16::Cx,
            2 => Reg16::Dx,
            3 => Reg16::Bx,
            4 => Reg16::Sp,
            5 => Reg16::Bp,
            6 => Reg16::Si,
            7 => Reg16::Di,
            _ => unreachable!(),
        }
    }
}

/// 8-bit register index — encodes as the low or high byte of the
/// 16-bit halves for indices 4..7.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg8 {
    Al = 0,
    Cl = 1,
    Dl = 2,
    Bl = 3,
    Ah = 4,
    Ch = 5,
    Dh = 6,
    Bh = 7,
}

impl Reg8 {
    pub fn from_bits(b: u8) -> Reg8 {
        match b & 0b111 {
            0 => Reg8::Al,
            1 => Reg8::Cl,
            2 => Reg8::Dl,
            3 => Reg8::Bl,
            4 => Reg8::Ah,
            5 => Reg8::Ch,
            6 => Reg8::Dh,
            7 => Reg8::Bh,
            _ => unreachable!(),
        }
    }
}

/// EFLAGS bits we model. Other bits (TF, IF, DF beyond direction
/// flag, IOPL, …) are zero in the sandbox.
///
/// Reference: Intel SDM Vol. 1 §3.4.3 (EFLAGS register).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// Carry flag (CF, bit 0).
    pub cf: bool,
    /// Parity flag (PF, bit 2) — set if low byte of result has
    /// even number of 1 bits.
    pub pf: bool,
    /// Auxiliary-carry / adjust flag (AF, bit 4) — carry out of
    /// bit 3.
    pub af: bool,
    /// Zero flag (ZF, bit 6).
    pub zf: bool,
    /// Sign flag (SF, bit 7) — high bit of result.
    pub sf: bool,
    /// Direction flag (DF, bit 10).
    pub df: bool,
    /// Overflow flag (OF, bit 11).
    pub of: bool,
    /// Identification flag (ID, bit 21). Toggleable via
    /// `pushfd / and / xor / popfd` sequences; software uses this
    /// as the "is CPUID supported" probe (Intel SDM Vol. 1
    /// §3.4.3.4 + the `CPUID` instruction reference). Modern
    /// codecs sniff CPUID feature bits at `DRV_LOAD` time using
    /// exactly this idiom, then branch off to MMX / SSE
    /// specialisations. We model the bit as state so the toggle
    /// round-trips and the codec's "no CPUID, take integer-only
    /// path" branch is correctly **not** taken when our CPU
    /// does support CPUID.
    ///
    /// Round-19 finding: round 13 advertises MMX in CPUID leaf 1
    /// EDX bit 23, but rounds 12..17 reported 0 MMX dispatches
    /// because every Indeo decoder skipped the entire feature
    /// block at the `pushfd / xor 0x200000 / popfd / pushfd`
    /// detection (`Flags::pack` returned a constant value from
    /// modelled bits only, so the toggle test always reported
    /// "ID-bit not settable → no CPUID"). With the bit modelled
    /// the codec reaches CPUID, sees MMX, and takes the MMX
    /// path.
    pub id: bool,
}

impl Flags {
    /// Pack the modelled bits into the canonical EFLAGS layout
    /// for `pushfd` / `lahf` / introspection. Bit 1 is the
    /// "always-1" reserved bit per Intel SDM.
    pub fn pack(self) -> u32 {
        let mut v: u32 = 0b10; // bit 1 reads as 1
        if self.cf {
            v |= 1 << 0;
        }
        if self.pf {
            v |= 1 << 2;
        }
        if self.af {
            v |= 1 << 4;
        }
        if self.zf {
            v |= 1 << 6;
        }
        if self.sf {
            v |= 1 << 7;
        }
        if self.df {
            v |= 1 << 10;
        }
        if self.of {
            v |= 1 << 11;
        }
        if self.id {
            v |= 1 << 21;
        }
        v
    }

    /// Inverse of [`pack`]. Reserved/unmodelled bits silently
    /// dropped.
    pub fn unpack(v: u32) -> Self {
        Flags {
            cf: (v & (1 << 0)) != 0,
            pf: (v & (1 << 2)) != 0,
            af: (v & (1 << 4)) != 0,
            zf: (v & (1 << 6)) != 0,
            sf: (v & (1 << 7)) != 0,
            df: (v & (1 << 10)) != 0,
            of: (v & (1 << 11)) != 0,
            id: (v & (1 << 21)) != 0,
        }
    }

    /// Set ZF / SF / PF from a 32-bit result. Used after most ALU
    /// operations.
    pub fn set_szp_32(&mut self, result: u32) {
        self.zf = result == 0;
        self.sf = (result & 0x8000_0000) != 0;
        self.pf = parity8(result as u8);
    }

    pub fn set_szp_16(&mut self, result: u16) {
        self.zf = result == 0;
        self.sf = (result & 0x8000) != 0;
        self.pf = parity8(result as u8);
    }

    pub fn set_szp_8(&mut self, result: u8) {
        self.zf = result == 0;
        self.sf = (result & 0x80) != 0;
        self.pf = parity8(result);
    }
}

fn parity8(b: u8) -> bool {
    // Return true if `b` has an even number of 1 bits.
    let mut x = b;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    (x & 1) == 0
}

/// 32-bit x86 register file.
#[derive(Clone, Debug, Default)]
pub struct Regs {
    pub gp: [u32; 8], // indexed by Reg32
    pub eip: u32,
    pub flags: Flags,
}

impl Regs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get32(&self, r: Reg32) -> u32 {
        self.gp[r as usize]
    }

    pub fn set32(&mut self, r: Reg32, v: u32) {
        self.gp[r as usize] = v;
    }

    pub fn get16(&self, r: Reg16) -> u16 {
        self.gp[r as usize] as u16
    }

    pub fn set16(&mut self, r: Reg16, v: u16) {
        let idx = r as usize;
        self.gp[idx] = (self.gp[idx] & 0xFFFF_0000) | u32::from(v);
    }

    pub fn get8(&self, r: Reg8) -> u8 {
        let i = r as usize;
        if i < 4 {
            // al / cl / dl / bl — low byte of eax/ecx/edx/ebx
            self.gp[i] as u8
        } else {
            // ah / ch / dh / bh — bits 8..15 of eax/ecx/edx/ebx
            (self.gp[i - 4] >> 8) as u8
        }
    }

    pub fn set8(&mut self, r: Reg8, v: u8) {
        let i = r as usize;
        if i < 4 {
            self.gp[i] = (self.gp[i] & 0xFFFF_FF00) | u32::from(v);
        } else {
            let host = i - 4;
            self.gp[host] = (self.gp[host] & 0xFFFF_00FF) | (u32::from(v) << 8);
        }
    }

    pub fn esp(&self) -> u32 {
        self.gp[Reg32::Esp as usize]
    }

    pub fn set_esp(&mut self, v: u32) {
        self.gp[Reg32::Esp as usize] = v;
    }

    pub fn ebp(&self) -> u32 {
        self.gp[Reg32::Ebp as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_lookup_matches_naive() {
        for b in 0..=255u8 {
            let popcnt = b.count_ones();
            assert_eq!(parity8(b), popcnt % 2 == 0, "parity disagree at {b}");
        }
    }

    #[test]
    fn high_byte_aliases_correctly() {
        let mut r = Regs::new();
        r.set32(Reg32::Eax, 0x1122_3344);
        assert_eq!(r.get8(Reg8::Al), 0x44);
        assert_eq!(r.get8(Reg8::Ah), 0x33);
        r.set8(Reg8::Ah, 0xFF);
        assert_eq!(r.get32(Reg32::Eax), 0x1122_FF44);
    }

    #[test]
    fn flags_pack_unpack_is_identity_on_modelled_bits() {
        let f = Flags {
            cf: true,
            zf: true,
            sf: true,
            of: true,
            ..Flags::default()
        };
        let packed = f.pack();
        let back = Flags::unpack(packed);
        assert_eq!(f, back);
    }

    #[test]
    fn id_flag_round_trips_through_pack_unpack() {
        // Round-19: the codec's `pushfd / xor 0x200000 / popfd /
        // pushfd` toggle test is the canonical CPUID-supported
        // probe (Intel SDM Vol. 1 §3.4.3.4). Until round 19 we
        // dropped bit 21 in `pack()`, so the toggle round-tripped
        // as a no-op and every codec concluded "CPUID not
        // supported". Pin the contract: bit 21 round-trips.
        let f_set = Flags {
            id: true,
            ..Flags::default()
        };
        let packed = f_set.pack();
        assert_ne!(packed & (1 << 21), 0, "ID bit must appear at bit 21");
        let back = Flags::unpack(packed);
        assert!(back.id, "unpack must preserve ID bit");

        let f_clr = Flags {
            id: false,
            ..Flags::default()
        };
        let packed_clr = f_clr.pack();
        assert_eq!(
            packed_clr & (1 << 21),
            0,
            "ID bit must NOT appear when cleared"
        );
        let back_clr = Flags::unpack(packed_clr);
        assert!(!back_clr.id);
    }

    #[test]
    fn set_szp_32_zero_sets_zf_clears_sf() {
        let mut f = Flags::default();
        f.set_szp_32(0);
        assert!(f.zf);
        assert!(!f.sf);
    }

    #[test]
    fn set_szp_32_negative_sets_sf() {
        let mut f = Flags::default();
        f.set_szp_32(0x8000_0000);
        assert!(!f.zf);
        assert!(f.sf);
    }

    #[test]
    fn reg_from_bits_matches_intel_encoding() {
        assert_eq!(Reg32::from_bits(0), Reg32::Eax);
        assert_eq!(Reg32::from_bits(4), Reg32::Esp);
        assert_eq!(Reg32::from_bits(7), Reg32::Edi);
    }
}
