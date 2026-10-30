//! Keccak-256 (the pre-NIST padding Ethereum uses, not SHA3-256).
//!
//! Only needed to derive ABI selectors and event topics from their
//! text signatures, so a small self-contained implementation beats a
//! crypto dependency.

const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Rate in bytes for a 256-bit output (1600 - 2*256 bits).
const RATE: usize = 136;

fn keccak_f(st: &mut [u64; 25]) {
    for rc in RC {
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }
        let mut t = st[1];
        for i in 0..24 {
            let j = PILN[i];
            let next = st[j];
            st[j] = t.rotate_left(ROTC[i]);
            t = next;
        }
        for j in (0..25).step_by(5) {
            bc.copy_from_slice(&st[j..j + 5]);
            for i in 0..5 {
                st[j + i] ^= !bc[(i + 1) % 5] & bc[(i + 2) % 5];
            }
        }
        st[0] ^= rc;
    }
}

fn absorb_block(st: &mut [u64; 25], block: &[u8; RATE]) {
    for (lane, chunk) in st.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*chunk);
    }
    keccak_f(st);
}

/// Keccak-256 digest of `data`.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut st = [0u64; 25];
    let (blocks, rem) = data.as_chunks::<RATE>();
    for block in blocks {
        absorb_block(&mut st, block);
    }
    let mut last = [0u8; RATE];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] ^= 0x01;
    last[RATE - 1] ^= 0x80;
    absorb_block(&mut st, &last);

    let mut out = [0u8; 32];
    for (chunk, lane) in out.as_chunks_mut::<8>().0.iter_mut().zip(st.iter()) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// The 4-byte ABI function selector for a canonical signature such as
/// `"transfer(address,uint256)"`.
#[must_use]
pub fn selector(signature: &str) -> u32 {
    let h = keccak256(signature.as_bytes());
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn rate_boundaries() {
        // Inputs of 'a' around the 136-byte rate: padding fully inside
        // the last block (135), a padding-only block (136, 272) and a
        // partial second block (200).
        let cases = [
            (
                135,
                "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446",
            ),
            (
                136,
                "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e",
            ),
            (
                200,
                "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d",
            ),
            (
                272,
                "cf7fcd4f705ee749930d19ca84561a9bf62516bd90a471545fa2f49fdc7e63c8",
            ),
        ];
        for (len, want) in cases {
            assert_eq!(hex(&keccak256(&vec![b'a'; len])), want, "len {len}");
        }
    }

    #[test]
    fn erc20_selectors() {
        assert_eq!(selector("transfer(address,uint256)"), 0xa905_9cbb);
        assert_eq!(selector("balanceOf(address)"), 0x70a0_8231);
        assert_eq!(selector("approve(address,uint256)"), 0x095e_a7b3);
    }

    #[test]
    fn transfer_event_topic() {
        assert_eq!(
            hex(&keccak256(b"Transfer(address,address,uint256)")),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }
}
