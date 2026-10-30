//! A small EVM interpreter for tests: enough of the instruction set to
//! run compiled Solidity / Vyper contracts against one call, with a
//! persistent storage map. No gas accounting; external calls succeed
//! without running anything and are recorded.

use std::collections::HashMap;

use super::{JUMPDEST, OPCODE_TABLE, decode_range, keccak256};

/// 256-bit word, little-endian 64-bit limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub(crate) struct U256(pub [u64; 4]);

impl U256 {
    pub(crate) const ZERO: Self = Self([0; 4]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0]);

    pub(crate) fn from_u64(v: u64) -> Self {
        Self([v, 0, 0, 0])
    }

    pub(crate) fn from_be(b: &[u8]) -> Self {
        let mut buf = [0u8; 32];
        let n = b.len().min(32);
        buf[32 - n..].copy_from_slice(&b[b.len() - n..]);
        let mut l = [0u64; 4];
        for (i, limb) in l.iter_mut().enumerate() {
            let off = 32 - 8 * (i + 1);
            *limb = u64::from_be_bytes(buf[off..off + 8].try_into().expect("8"));
        }
        Self(l)
    }

    pub(crate) fn to_be(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&self.0[i].to_be_bytes());
        }
        out
    }

    fn fits_u64(self) -> bool {
        self.0[1..].iter().all(|&x| x == 0)
    }

    fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    fn cmp_u(self, o: Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&o.0[i]) {
                std::cmp::Ordering::Equal => {}
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    }

    fn add(self, o: Self) -> Self {
        let mut r = [0u64; 4];
        let mut carry = false;
        for (i, limb) in r.iter_mut().enumerate() {
            let (s1, c1) = self.0[i].overflowing_add(o.0[i]);
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            *limb = s2;
            carry = c1 || c2;
        }
        Self(r)
    }

    fn not(self) -> Self {
        Self(self.0.map(|x| !x))
    }

    fn sub(self, o: Self) -> Self {
        self.add(o.not()).add(Self::ONE)
    }

    fn mul(self, o: Self) -> Self {
        let mut r = [0u64; 4];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 - i {
                let cur = u128::from(r[i + j]) + u128::from(self.0[i]) * u128::from(o.0[j]) + carry;
                r[i + j] = cur as u64;
                carry = cur >> 64;
            }
        }
        Self(r)
    }

    fn shl(self, n: u32) -> Self {
        if n >= 256 {
            return Self::ZERO;
        }
        let (limbs, bits) = ((n / 64) as usize, n % 64);
        let mut r = [0u64; 4];
        for i in (limbs..4).rev() {
            r[i] = self.0[i - limbs] << bits;
            if bits > 0 && i > limbs {
                r[i] |= self.0[i - limbs - 1] >> (64 - bits);
            }
        }
        Self(r)
    }

    fn shr(self, n: u32) -> Self {
        if n >= 256 {
            return Self::ZERO;
        }
        let (limbs, bits) = ((n / 64) as usize, n % 64);
        let mut r = [0u64; 4];
        for (i, limb) in r.iter_mut().enumerate().take(4 - limbs) {
            *limb = self.0[i + limbs] >> bits;
            if bits > 0 && i + limbs + 1 < 4 {
                *limb |= self.0[i + limbs + 1] << (64 - bits);
            }
        }
        Self(r)
    }

    fn bit(self, i: u32) -> bool {
        self.0[(i / 64) as usize] >> (i % 64) & 1 == 1
    }

    fn divmod(self, d: Self) -> (Self, Self) {
        if d.is_zero() {
            return (Self::ZERO, Self::ZERO);
        }
        let (mut q, mut r) = (Self::ZERO, Self::ZERO);
        for i in (0..256).rev() {
            r = r.shl(1);
            if self.bit(i) {
                r.0[0] |= 1;
            }
            if r.cmp_u(d) != std::cmp::Ordering::Less {
                r = r.sub(d);
                q.0[(i / 64) as usize] |= 1 << (i % 64);
            }
        }
        (q, r)
    }

    fn pow(self, mut e: Self) -> Self {
        let (mut base, mut acc) = (self, Self::ONE);
        while !e.is_zero() {
            if e.0[0] & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            e = e.shr(1);
        }
        acc
    }

    fn shift_amount(self) -> u32 {
        if self.fits_u64() && self.0[0] < 256 {
            self.0[0] as u32
        } else {
            256
        }
    }
}

fn b(v: bool) -> U256 {
    if v { U256::ONE } else { U256::ZERO }
}

/// How a call ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Stop,
    Return(Vec<u8>),
    Revert(Vec<u8>),
    /// `INVALID`, a bad jump, stack underflow, or an opcode this
    /// interpreter doesn't model.
    Fault(String),
}

/// Call context.
#[derive(Debug, Clone, Default)]
pub(crate) struct Call {
    pub caller: U256,
    pub value: U256,
    pub data: Vec<u8>,
    pub address: U256,
    /// What `BALANCE` / `SELFBALANCE` report.
    pub balance: U256,
}

/// A contract with persistent storage.
#[derive(Debug, Clone, Default)]
pub(crate) struct Machine {
    pub code: Vec<u8>,
    pub storage: HashMap<U256, U256>,
    /// `(topics, data)` of every `LOGn`, across calls.
    pub logs: Vec<(Vec<U256>, Vec<u8>)>,
    /// `(to, value)` of every external `CALL`.
    pub calls: Vec<(U256, U256)>,
}

impl Machine {
    pub(crate) fn new(code: &[u8]) -> Self {
        Self {
            code: code.to_vec(),
            ..Self::default()
        }
    }

    /// Run one call. Storage writes and logs of a reverted call are
    /// rolled back.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn run(&mut self, call: &Call) -> Outcome {
        let saved = (self.storage.clone(), self.logs.len(), self.calls.len());
        let out = self.exec(call);
        if !matches!(out, Outcome::Stop | Outcome::Return(_)) {
            self.storage = saved.0;
            self.logs.truncate(saved.1);
            self.calls.truncate(saved.2);
        }
        out
    }

    #[allow(clippy::too_many_lines)]
    fn exec(&mut self, call: &Call) -> Outcome {
        let dests: std::collections::HashSet<usize> = decode_range(&self.code, 0)
            .iter()
            .filter(|i| i.opcode == JUMPDEST)
            .map(|i| i.addr.0 as usize)
            .collect();
        let mut stack: Vec<U256> = Vec::new();
        let mut mem: Vec<u8> = Vec::new();
        let mut pc = 0usize;
        let fault = |m: &str| Outcome::Fault(m.to_string());
        macro_rules! pop {
            () => {
                match stack.pop() {
                    Some(v) => v,
                    None => return fault("stack underflow"),
                }
            };
        }
        let grow = |mem: &mut Vec<u8>, off: usize, len: usize| {
            if len > 0 && off + len > mem.len() {
                mem.resize((off + len).div_ceil(32) * 32, 0);
            }
        };
        let addr = |v: U256| -> Option<usize> {
            (v.fits_u64() && v.0[0] < 1 << 24).then(|| v.0[0] as usize)
        };
        for _ in 0..1_000_000 {
            let Some(&op) = self.code.get(pc) else {
                return Outcome::Stop;
            };
            pc += 1;
            match op {
                0x00 => return Outcome::Stop,
                0x01..=0x07 | 0x0a | 0x10..=0x14 | 0x16..=0x18 | 0x1a..=0x1c => {
                    let (x, y) = (pop!(), pop!());
                    stack.push(match op {
                        0x01 => x.add(y),
                        0x02 => x.mul(y),
                        0x03 => x.sub(y),
                        0x04 => x.divmod(y).0,
                        0x06 => x.divmod(y).1,
                        0x0a => x.pow(y),
                        0x10 => b(x.cmp_u(y).is_lt()),
                        0x11 => b(x.cmp_u(y).is_gt()),
                        0x12 | 0x13 => {
                            // Signed compare: flip the sign bits.
                            let flip = |v: U256| {
                                let mut v = v;
                                v.0[3] ^= 1 << 63;
                                v
                            };
                            let o = flip(x).cmp_u(flip(y));
                            b(if op == 0x12 { o.is_lt() } else { o.is_gt() })
                        }
                        0x14 => b(x == y),
                        0x16 => U256([0, 1, 2, 3].map(|i| x.0[i] & y.0[i])),
                        0x17 => U256([0, 1, 2, 3].map(|i| x.0[i] | y.0[i])),
                        0x18 => U256([0, 1, 2, 3].map(|i| x.0[i] ^ y.0[i])),
                        0x1a => {
                            let i = x.shift_amount();
                            if i < 32 {
                                U256::from_u64(u64::from(y.to_be()[i as usize]))
                            } else {
                                U256::ZERO
                            }
                        }
                        0x1b => y.shl(x.shift_amount()),
                        0x1c => y.shr(x.shift_amount()),
                        _ => return fault("signed division"),
                    });
                }
                0x15 => {
                    let x = pop!();
                    stack.push(b(x.is_zero()));
                }
                0x19 => {
                    let x = pop!();
                    stack.push(x.not());
                }
                0x20 => {
                    let (o, n) = (pop!(), pop!());
                    let (Some(o), Some(n)) = (addr(o), addr(n)) else {
                        return fault("huge keccak");
                    };
                    grow(&mut mem, o, n);
                    let h = if n == 0 {
                        keccak256(&[])
                    } else {
                        keccak256(&mem[o..o + n])
                    };
                    stack.push(U256::from_be(&h));
                }
                0x30 => stack.push(call.address),
                0x31 => {
                    pop!();
                    stack.push(call.balance);
                }
                0x47 => stack.push(call.balance),
                0x32 | 0x33 => stack.push(call.caller),
                0x34 => stack.push(call.value),
                0x35 => {
                    let o = pop!();
                    let mut w = [0u8; 32];
                    if let Some(o) = addr(o) {
                        for (i, x) in w.iter_mut().enumerate() {
                            *x = call.data.get(o + i).copied().unwrap_or(0);
                        }
                    }
                    stack.push(U256::from_be(&w));
                }
                0x36 => stack.push(U256::from_u64(call.data.len() as u64)),
                0x37 | 0x39 => {
                    let (d, o, n) = (pop!(), pop!(), pop!());
                    let (Some(d), Some(o), Some(n)) = (addr(d), addr(o), addr(n)) else {
                        return fault("huge copy");
                    };
                    grow(&mut mem, d, n);
                    let src: &[u8] = if op == 0x37 { &call.data } else { &self.code };
                    for i in 0..n {
                        mem[d + i] = src.get(o + i).copied().unwrap_or(0);
                    }
                }
                0x38 => stack.push(U256::from_u64(self.code.len() as u64)),
                0x3a | 0x3d | 0x41..=0x46 | 0x48 => stack.push(U256::ZERO),
                0x50 => {
                    pop!();
                }
                0x51 => {
                    let Some(o) = addr(pop!()) else {
                        return fault("huge mload");
                    };
                    grow(&mut mem, o, 32);
                    stack.push(U256::from_be(&mem[o..o + 32]));
                }
                0x52 | 0x53 => {
                    let (o, v) = (pop!(), pop!());
                    let Some(o) = addr(o) else {
                        return fault("huge mstore");
                    };
                    if op == 0x52 {
                        grow(&mut mem, o, 32);
                        mem[o..o + 32].copy_from_slice(&v.to_be());
                    } else {
                        grow(&mut mem, o, 1);
                        mem[o] = v.0[0] as u8;
                    }
                }
                0x54 => {
                    let k = pop!();
                    stack.push(self.storage.get(&k).copied().unwrap_or_default());
                }
                0x55 => {
                    let (k, v) = (pop!(), pop!());
                    self.storage.insert(k, v);
                }
                0x56 | 0x57 => {
                    let t = pop!();
                    let go = if op == 0x57 { !pop!().is_zero() } else { true };
                    if go {
                        match addr(t) {
                            Some(t) if dests.contains(&t) => pc = t,
                            _ => return fault("bad jump"),
                        }
                    }
                }
                0x58 => stack.push(U256::from_u64(pc as u64 - 1)),
                0x59 => stack.push(U256::from_u64(mem.len() as u64)),
                0x5a => stack.push(U256::from_u64(1_000_000)),
                0x5b => {}
                0x5f..=0x7f => {
                    let n = usize::from(op - 0x5f);
                    let end = (pc + n).min(self.code.len());
                    let mut imm = self.code[pc..end].to_vec();
                    imm.resize(n, 0);
                    stack.push(U256::from_be(&imm));
                    pc += n;
                }
                0x80..=0x8f => {
                    let n = usize::from(op - 0x80) + 1;
                    let Some(&v) = stack.len().checked_sub(n).map(|i| &stack[i]) else {
                        return fault("stack underflow");
                    };
                    stack.push(v);
                }
                0x90..=0x9f => {
                    let n = usize::from(op - 0x90) + 1;
                    let len = stack.len();
                    if len <= n {
                        return fault("stack underflow");
                    }
                    stack.swap(len - 1, len - 1 - n);
                }
                0xa0..=0xa4 => {
                    let (o, n) = (pop!(), pop!());
                    let mut topics = Vec::new();
                    for _ in 0..op - 0xa0 {
                        topics.push(pop!());
                    }
                    let (Some(o), Some(n)) = (addr(o), addr(n)) else {
                        return fault("huge log");
                    };
                    grow(&mut mem, o, n);
                    self.logs.push((topics, mem[o..o + n].to_vec()));
                }
                0xf1 => {
                    let _gas = pop!();
                    let to = pop!();
                    let value = pop!();
                    for _ in 0..4 {
                        pop!();
                    }
                    self.calls.push((to, value));
                    stack.push(U256::ONE);
                }
                0xf3 | 0xfd => {
                    let (o, n) = (pop!(), pop!());
                    let (Some(o), Some(n)) = (addr(o), addr(n)) else {
                        return fault("huge return");
                    };
                    grow(&mut mem, o, n);
                    let data = mem[o..o + n].to_vec();
                    return if op == 0xf3 {
                        Outcome::Return(data)
                    } else {
                        Outcome::Revert(data)
                    };
                }
                _ => {
                    return Outcome::Fault(format!(
                        "opcode 0x{op:02x} ({})",
                        OPCODE_TABLE[op as usize].name
                    ));
                }
            }
            if stack.len() > 1024 {
                return fault("stack overflow");
            }
        }
        fault("step limit")
    }
}

/// ABI calldata: selector of `sig` then static words.
pub(crate) fn calldata(sig: &str, words: &[U256]) -> Vec<u8> {
    let mut d = super::selector(sig).to_be_bytes().to_vec();
    for w in words {
        d.extend(w.to_be());
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        let a = U256::from_u64(7);
        let m = U256::ZERO.sub(U256::ONE);
        assert_eq!(m.add(U256::ONE), U256::ZERO);
        assert_eq!(a.divmod(U256::from_u64(2)), (U256::from_u64(3), U256::ONE));
        assert_eq!(
            U256::from_u64(2).pow(U256::from_u64(255)),
            U256::ONE.shl(255)
        );
        assert_eq!(U256::ONE.shl(200).shr(199), U256::from_u64(2));
        assert_eq!(m.mul(m), U256::ONE);
    }

    #[test]
    fn runs_a_tiny_program() {
        // PUSH1 2 PUSH1 3 ADD PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN
        let code = [0x60, 2, 0x60, 3, 0x01, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
        let out = Machine::new(&code).run(&Call::default());
        assert_eq!(out, Outcome::Return(U256::from_u64(5).to_be().to_vec()));
    }
}
