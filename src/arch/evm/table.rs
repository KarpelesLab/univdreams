//! EVM opcode table: mnemonic, immediate width and stack effect for
//! every byte value.
//!
//! Coverage is the mainnet instruction set through the Fusaka fork
//! (Prague/Osaka): `PUSH0` (Shanghai), `TLOAD`/`TSTORE`/`MCOPY`/
//! `BLOBHASH`/`BLOBBASEFEE` (Cancun) and `CLZ` (Osaka). EOF opcodes
//! (`RJUMP`, `CALLF`, …) never activated on mainnet and are left
//! undefined; undefined bytes decode as [`OpInfo::UNDEFINED`].

/// Static description of one opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpInfo {
    /// Canonical upper-case mnemonic (`"PUSH2"`, `"KECCAK256"`).
    /// Empty for undefined opcodes.
    pub name: &'static str,
    /// Number of immediate bytes following the opcode. Non-zero
    /// only for `PUSH1`..`PUSH32`.
    pub imm_len: u8,
    /// Stack items consumed.
    pub pops: u8,
    /// Stack items produced.
    pub pushes: u8,
}

impl OpInfo {
    /// Placeholder for bytes that aren't an assigned opcode.
    pub const UNDEFINED: Self = Self {
        name: "",
        imm_len: 0,
        pops: 0,
        pushes: 0,
    };

    /// Whether this byte is an assigned opcode.
    #[must_use]
    pub fn is_defined(&self) -> bool {
        !self.name.is_empty()
    }
}

const fn op(name: &'static str, pops: u8, pushes: u8) -> OpInfo {
    OpInfo {
        name,
        imm_len: 0,
        pops,
        pushes,
    }
}

const PUSH_NAMES: [&str; 32] = [
    "PUSH1", "PUSH2", "PUSH3", "PUSH4", "PUSH5", "PUSH6", "PUSH7", "PUSH8", "PUSH9", "PUSH10",
    "PUSH11", "PUSH12", "PUSH13", "PUSH14", "PUSH15", "PUSH16", "PUSH17", "PUSH18", "PUSH19",
    "PUSH20", "PUSH21", "PUSH22", "PUSH23", "PUSH24", "PUSH25", "PUSH26", "PUSH27", "PUSH28",
    "PUSH29", "PUSH30", "PUSH31", "PUSH32",
];

const DUP_NAMES: [&str; 16] = [
    "DUP1", "DUP2", "DUP3", "DUP4", "DUP5", "DUP6", "DUP7", "DUP8", "DUP9", "DUP10", "DUP11",
    "DUP12", "DUP13", "DUP14", "DUP15", "DUP16",
];

const SWAP_NAMES: [&str; 16] = [
    "SWAP1", "SWAP2", "SWAP3", "SWAP4", "SWAP5", "SWAP6", "SWAP7", "SWAP8", "SWAP9", "SWAP10",
    "SWAP11", "SWAP12", "SWAP13", "SWAP14", "SWAP15", "SWAP16",
];

const LOG_NAMES: [&str; 5] = ["LOG0", "LOG1", "LOG2", "LOG3", "LOG4"];

/// Indexed by opcode byte.
pub static OPCODE_TABLE: [OpInfo; 256] = build_table();

#[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
const fn build_table() -> [OpInfo; 256] {
    let mut t = [OpInfo::UNDEFINED; 256];

    t[0x00] = op("STOP", 0, 0);
    t[0x01] = op("ADD", 2, 1);
    t[0x02] = op("MUL", 2, 1);
    t[0x03] = op("SUB", 2, 1);
    t[0x04] = op("DIV", 2, 1);
    t[0x05] = op("SDIV", 2, 1);
    t[0x06] = op("MOD", 2, 1);
    t[0x07] = op("SMOD", 2, 1);
    t[0x08] = op("ADDMOD", 3, 1);
    t[0x09] = op("MULMOD", 3, 1);
    t[0x0a] = op("EXP", 2, 1);
    t[0x0b] = op("SIGNEXTEND", 2, 1);

    t[0x10] = op("LT", 2, 1);
    t[0x11] = op("GT", 2, 1);
    t[0x12] = op("SLT", 2, 1);
    t[0x13] = op("SGT", 2, 1);
    t[0x14] = op("EQ", 2, 1);
    t[0x15] = op("ISZERO", 1, 1);
    t[0x16] = op("AND", 2, 1);
    t[0x17] = op("OR", 2, 1);
    t[0x18] = op("XOR", 2, 1);
    t[0x19] = op("NOT", 1, 1);
    t[0x1a] = op("BYTE", 2, 1);
    t[0x1b] = op("SHL", 2, 1);
    t[0x1c] = op("SHR", 2, 1);
    t[0x1d] = op("SAR", 2, 1);
    t[0x1e] = op("CLZ", 1, 1);

    t[0x20] = op("KECCAK256", 2, 1);

    t[0x30] = op("ADDRESS", 0, 1);
    t[0x31] = op("BALANCE", 1, 1);
    t[0x32] = op("ORIGIN", 0, 1);
    t[0x33] = op("CALLER", 0, 1);
    t[0x34] = op("CALLVALUE", 0, 1);
    t[0x35] = op("CALLDATALOAD", 1, 1);
    t[0x36] = op("CALLDATASIZE", 0, 1);
    t[0x37] = op("CALLDATACOPY", 3, 0);
    t[0x38] = op("CODESIZE", 0, 1);
    t[0x39] = op("CODECOPY", 3, 0);
    t[0x3a] = op("GASPRICE", 0, 1);
    t[0x3b] = op("EXTCODESIZE", 1, 1);
    t[0x3c] = op("EXTCODECOPY", 4, 0);
    t[0x3d] = op("RETURNDATASIZE", 0, 1);
    t[0x3e] = op("RETURNDATACOPY", 3, 0);
    t[0x3f] = op("EXTCODEHASH", 1, 1);

    t[0x40] = op("BLOCKHASH", 1, 1);
    t[0x41] = op("COINBASE", 0, 1);
    t[0x42] = op("TIMESTAMP", 0, 1);
    t[0x43] = op("NUMBER", 0, 1);
    t[0x44] = op("PREVRANDAO", 0, 1);
    t[0x45] = op("GASLIMIT", 0, 1);
    t[0x46] = op("CHAINID", 0, 1);
    t[0x47] = op("SELFBALANCE", 0, 1);
    t[0x48] = op("BASEFEE", 0, 1);
    t[0x49] = op("BLOBHASH", 1, 1);
    t[0x4a] = op("BLOBBASEFEE", 0, 1);

    t[0x50] = op("POP", 1, 0);
    t[0x51] = op("MLOAD", 1, 1);
    t[0x52] = op("MSTORE", 2, 0);
    t[0x53] = op("MSTORE8", 2, 0);
    t[0x54] = op("SLOAD", 1, 1);
    t[0x55] = op("SSTORE", 2, 0);
    t[0x56] = op("JUMP", 1, 0);
    t[0x57] = op("JUMPI", 2, 0);
    t[0x58] = op("PC", 0, 1);
    t[0x59] = op("MSIZE", 0, 1);
    t[0x5a] = op("GAS", 0, 1);
    t[0x5b] = op("JUMPDEST", 0, 0);
    t[0x5c] = op("TLOAD", 1, 1);
    t[0x5d] = op("TSTORE", 2, 0);
    t[0x5e] = op("MCOPY", 3, 0);
    t[0x5f] = op("PUSH0", 0, 1);

    let mut i = 0;
    while i < 32 {
        t[0x60 + i] = OpInfo {
            name: PUSH_NAMES[i],
            imm_len: (i + 1) as u8,
            pops: 0,
            pushes: 1,
        };
        i += 1;
    }
    let mut i = 0;
    while i < 16 {
        // DUPn reads n items and leaves n+1; SWAPn touches n+1.
        t[0x80 + i] = op(DUP_NAMES[i], (i + 1) as u8, (i + 2) as u8);
        t[0x90 + i] = op(SWAP_NAMES[i], (i + 2) as u8, (i + 2) as u8);
        i += 1;
    }
    let mut i = 0;
    while i < 5 {
        t[0xa0 + i] = op(LOG_NAMES[i], (i + 2) as u8, 0);
        i += 1;
    }

    t[0xf0] = op("CREATE", 3, 1);
    t[0xf1] = op("CALL", 7, 1);
    t[0xf2] = op("CALLCODE", 7, 1);
    t[0xf3] = op("RETURN", 2, 0);
    t[0xf4] = op("DELEGATECALL", 6, 1);
    t[0xf5] = op("CREATE2", 4, 1);
    t[0xfa] = op("STATICCALL", 6, 1);
    t[0xfd] = op("REVERT", 2, 0);
    t[0xfe] = op("INVALID", 0, 0);
    t[0xff] = op("SELFDESTRUCT", 1, 0);

    t
}

/// Look up an opcode byte by mnemonic. Case-insensitive; accepts the
/// historical aliases `SHA3` (→ `KECCAK256`) and `DIFFICULTY`
/// (→ `PREVRANDAO`).
#[must_use]
pub fn opcode_by_name(name: &str) -> Option<u8> {
    let upper = name.to_ascii_uppercase();
    let canonical = match upper.as_str() {
        "SHA3" => "KECCAK256",
        "DIFFICULTY" => "PREVRANDAO",
        "SUICIDE" => "SELFDESTRUCT",
        other => other,
    };
    (0..=255u8).find(|&b| OPCODE_TABLE[b as usize].name == canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_range_widths() {
        assert_eq!(OPCODE_TABLE[0x5f].name, "PUSH0");
        assert_eq!(OPCODE_TABLE[0x5f].imm_len, 0);
        for n in 1..=32u8 {
            let info = OPCODE_TABLE[0x5f + n as usize];
            assert_eq!(info.imm_len, n);
            assert_eq!(info.name, format!("PUSH{n}"));
        }
    }

    #[test]
    fn names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for info in &OPCODE_TABLE {
            if info.is_defined() {
                assert!(seen.insert(info.name), "duplicate {}", info.name);
            }
        }
        // 0x00-0x0b, 0x10-0x1e, 0x20, 0x30-0x3f, 0x40-0x4a,
        // 0x50-0x5f, PUSH1-32, DUP, SWAP, LOG, 10 system ops.
        assert_eq!(
            seen.len(),
            12 + 15 + 1 + 16 + 11 + 16 + 32 + 16 + 16 + 5 + 10
        );
    }

    #[test]
    fn aliases_resolve() {
        assert_eq!(opcode_by_name("sha3"), Some(0x20));
        assert_eq!(opcode_by_name("DIFFICULTY"), Some(0x44));
        assert_eq!(opcode_by_name("tstore"), Some(0x5d));
        assert_eq!(opcode_by_name("RJUMP"), None);
    }
}
