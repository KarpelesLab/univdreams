//! A memory abstraction the Linux engine + loader speak to, so the same
//! syscall kernel runs over either the interpreter's sparse [`Mmu`] or a
//! flat host buffer (the KVM backend's guest-physical region).
//!
//! Addresses are `u32` — every region the personality uses lives in the low
//! 4 GiB (non-PIE `gcc -static` text at `0x400000`, stack just under
//! `0xC000_0000`, the mmap arena at `0x4000_0000`). This is the same
//! 4 GiB-flat assumption the long-mode interpreter path already relies on.

use crate::emulator::{Mmu, Perm, Trap};

/// What the syscall kernel and the static-ELF loader need from guest memory.
/// Reads are `&self`; writes and mappings are `&mut self`.
pub trait GuestMem {
    /// # Errors
    /// [`Trap`] on an unmapped / unreadable address.
    fn load8(&self, addr: u32) -> Result<u8, Trap>;
    /// # Errors
    /// See [`load8`](Self::load8).
    fn load16(&self, addr: u32) -> Result<u16, Trap>;
    /// # Errors
    /// See [`load8`](Self::load8).
    fn load32(&self, addr: u32) -> Result<u32, Trap>;
    /// # Errors
    /// See [`load8`](Self::load8).
    fn load64(&self, addr: u32) -> Result<u64, Trap>;
    /// # Errors
    /// [`Trap`] on an unmapped / read-only address.
    fn store8(&mut self, addr: u32, value: u8) -> Result<(), Trap>;
    /// # Errors
    /// See [`store8`](Self::store8).
    fn store16(&mut self, addr: u32, value: u16) -> Result<(), Trap>;
    /// # Errors
    /// See [`store8`](Self::store8).
    fn store32(&mut self, addr: u32, value: u32) -> Result<(), Trap>;
    /// # Errors
    /// See [`store8`](Self::store8).
    fn store64(&mut self, addr: u32, value: u64) -> Result<(), Trap>;
    /// Ensure `[addr, addr+size)` is present with at least `perm`. A flat
    /// backend that is already fully addressable may treat this as a no-op.
    fn map(&mut self, addr: u32, size: u32, perm: Perm);
    /// Like [`map`](Self::map) but the range is backed by fresh **zero** pages
    /// (anonymous-mapping semantics) even if it previously held data.
    fn map_zeroed(&mut self, addr: u32, size: u32, perm: Perm);
    /// Populate memory at load time, ignoring write-permission bits (used by
    /// the loader to lay down read-only segments before the guest runs).
    ///
    /// # Errors
    /// [`Trap`] if the destination range is not addressable.
    fn write_initializer(&mut self, addr: u32, data: &[u8]) -> Result<(), Trap>;
}

/// The interpreter's sparse, permission-checked MMU is the canonical
/// [`GuestMem`].
impl GuestMem for Mmu {
    fn load8(&self, addr: u32) -> Result<u8, Trap> {
        Mmu::load8(self, addr)
    }
    fn load16(&self, addr: u32) -> Result<u16, Trap> {
        Mmu::load16(self, addr)
    }
    fn load32(&self, addr: u32) -> Result<u32, Trap> {
        Mmu::load32(self, addr)
    }
    fn load64(&self, addr: u32) -> Result<u64, Trap> {
        Mmu::load64(self, addr)
    }
    fn store8(&mut self, addr: u32, value: u8) -> Result<(), Trap> {
        Mmu::store8(self, addr, value)
    }
    fn store16(&mut self, addr: u32, value: u16) -> Result<(), Trap> {
        Mmu::store16(self, addr, value)
    }
    fn store32(&mut self, addr: u32, value: u32) -> Result<(), Trap> {
        Mmu::store32(self, addr, value)
    }
    fn store64(&mut self, addr: u32, value: u64) -> Result<(), Trap> {
        Mmu::store64(self, addr, value)
    }
    fn map(&mut self, addr: u32, size: u32, perm: Perm) {
        Mmu::map(self, addr, size, perm);
    }
    fn map_zeroed(&mut self, addr: u32, size: u32, perm: Perm) {
        Mmu::map_zeroed(self, addr, size, perm);
    }
    fn write_initializer(&mut self, addr: u32, data: &[u8]) -> Result<(), Trap> {
        Mmu::write_initializer(self, addr, data)
    }
}
