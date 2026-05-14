//! Flat 4 GiB virtual address space with sparse 4 KiB pages and
//! per-page R / W / X permission bits.
//!
//! The MMU is the only piece of state that holds the codec DLL's
//! memory. Every guest load/store is bounds-checked at the page
//! level. Within a page, byte access is plain safe-Rust slicing;
//! multi-byte accesses use [`u16::from_le_bytes`] /
//! [`u32::from_le_bytes`] / [`u64::from_le_bytes`] (and their
//! `to_le_bytes` counterparts) so the entire MMU is
//! `#![forbid(unsafe_code)]`.
//!
//! x86 permits unaligned multi-byte access. The implementation
//! handles intra-page unaligned accesses by reading individual
//! bytes; cross-page accesses split into per-page sub-accesses so
//! that permission checks happen on every page touched.

use super::Trap;

/// 4 KiB pages — same as the host x86, by design.
pub const PAGE_SIZE: usize = 0x1000;
/// 32-bit address space → 2^20 pages.
pub const NUM_PAGES: usize = 1 << 20;
/// Mask for the page-offset bits.
pub const PAGE_MASK: u32 = (PAGE_SIZE as u32) - 1;
/// Bit shift for converting an address into a page index.
pub const PAGE_SHIFT: u32 = 12;

/// Per-page permission bits.
///
/// A page may be flagged readable, writable, executable, or any
/// combination thereof. The PE loader assigns these per-section.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Perm(u8);

impl Perm {
    /// Page may be read.
    pub const R: Perm = Perm(1 << 0);
    /// Page may be written.
    pub const W: Perm = Perm(1 << 1);
    /// Page may be fetched-from for instruction execution.
    pub const X: Perm = Perm(1 << 2);

    /// Combine two permission sets (set-union of bits).
    pub const fn or(self, other: Perm) -> Perm {
        Perm(self.0 | other.0)
    }

    /// Construct from raw bits (R=1, W=2, X=4).
    pub const fn from_bits(bits: u8) -> Perm {
        Perm(bits & 0b111)
    }

    /// Raw bit pattern for tests / debug printing.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Does this set contain `other`'s bits in full?
    pub const fn contains(self, other: Perm) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for Perm {
    type Output = Perm;
    fn bitor(self, rhs: Perm) -> Perm {
        self.or(rhs)
    }
}

#[derive(Clone, Debug)]
struct Page {
    bytes: Box<[u8; PAGE_SIZE]>,
    perm: Perm,
}

impl Page {
    fn zeroed(perm: Perm) -> Self {
        Page {
            bytes: Box::new([0u8; PAGE_SIZE]),
            perm,
        }
    }
}

/// The emulator's memory.
///
/// The page table is a `Vec<Option<Page>>` of length [`NUM_PAGES`].
/// Each `Option<Page>` is one machine-word; the actual 4 KiB byte
/// arrays are heap-allocated only when first written. A typical
/// codec uses 1–10 MiB of mapped memory, well below the 4 GiB
/// upper bound.
pub struct Mmu {
    pages: Vec<Option<Page>>,
    /// Reverse-engineering trace surface (gated on the `trace`
    /// Cargo feature). When the feature is on but no sink is
    /// configured, watchpoint scanning still happens but emits
    /// drop. See [`crate::trace::TraceState`] +
    /// `docs/winmf/winmf-emulator.md` §"Trace mode".
    #[cfg(feature = "trace")]
    pub trace: crate::trace::TraceState,
}

impl Default for Mmu {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmu {
    /// Create an empty 4 GiB address space. No pages are mapped.
    pub fn new() -> Self {
        // `Vec::resize_with` keeps the inner buffer sparse — only
        // 8 MiB of None markers, not 4 GiB of zero pages.
        let mut pages = Vec::with_capacity(NUM_PAGES);
        pages.resize_with(NUM_PAGES, || None);
        Mmu {
            pages,
            #[cfg(feature = "trace")]
            trace: crate::trace::TraceState::new(),
        }
    }

    /// Map a contiguous range of pages with the given permissions.
    /// `addr` and `size` are rounded down/up to page boundaries.
    /// Existing pages in the range have their bytes preserved but
    /// their permissions overwritten — a deliberate match for the
    /// PE loader, which may set initial bytes via [`Self::write`]
    /// and then re-permission with `R+X` for code or `R+W` for
    /// data.
    pub fn map(&mut self, addr: u32, size: u32, perm: Perm) {
        if size == 0 {
            return;
        }
        let start_page = (addr >> PAGE_SHIFT) as usize;
        // Saturating to avoid wrap when addr is near the top.
        let end_addr = u64::from(addr) + u64::from(size);
        let end_page = end_addr.div_ceil(PAGE_SIZE as u64).min(NUM_PAGES as u64) as usize;
        for p in start_page..end_page {
            if let Some(page) = self.pages[p].as_mut() {
                page.perm = perm;
            } else {
                self.pages[p] = Some(Page::zeroed(perm));
            }
        }
    }

    /// True iff the page containing `addr` is mapped.
    pub fn is_mapped(&self, addr: u32) -> bool {
        self.pages[(addr >> PAGE_SHIFT) as usize].is_some()
    }

    /// Permissions on the page containing `addr`, or `None` if
    /// unmapped.
    pub fn perm_at(&self, addr: u32) -> Option<Perm> {
        self.pages[(addr >> PAGE_SHIFT) as usize]
            .as_ref()
            .map(|p| p.perm)
    }

    /// Force-set the permission bits on the page containing
    /// `addr`. Panics if unmapped — callers should map first.
    pub fn set_perm(&mut self, addr: u32, perm: Perm) {
        if let Some(p) = self.pages[(addr >> PAGE_SHIFT) as usize].as_mut() {
            p.perm = perm;
        } else {
            panic!("mmu::set_perm on unmapped page {:#010x}", addr);
        }
    }

    /// Unmap a contiguous range of pages — the inverse of
    /// [`Self::map`]. `addr` and `size` are rounded down/up to
    /// page boundaries. Pages not currently mapped are silently
    /// skipped. Used by `kernel32!VirtualFree`.
    pub fn unmap(&mut self, addr: u32, size: u32) {
        if size == 0 {
            return;
        }
        let start_page = (addr >> PAGE_SHIFT) as usize;
        let end_addr = u64::from(addr) + u64::from(size);
        let end_page = end_addr.div_ceil(PAGE_SIZE as u64).min(NUM_PAGES as u64) as usize;
        for p in start_page..end_page {
            self.pages[p] = None;
        }
    }

    /// Locate a contiguous range of `size` bytes (page-aligned)
    /// of unmapped pages within `[lo, hi)`. Used by
    /// `kernel32!VirtualAlloc` when the caller passes
    /// `lpAddress = NULL`.
    pub fn find_free_range(&self, lo: u32, hi: u32, size: u32) -> Option<u32> {
        if size == 0 {
            return Some(lo);
        }
        let need_pages = u64::from(size).div_ceil(PAGE_SIZE as u64) as usize;
        let lo_page = (lo >> PAGE_SHIFT) as usize;
        let hi_page = (hi >> PAGE_SHIFT) as usize;
        if lo_page + need_pages > hi_page {
            return None;
        }
        let mut p = lo_page;
        while p + need_pages <= hi_page {
            // Find the first unmapped page at or after p.
            while p < hi_page && self.pages[p].is_some() {
                p += 1;
            }
            if p + need_pages > hi_page {
                return None;
            }
            // Check the next need_pages pages are all unmapped.
            let mut q = p;
            let end = p + need_pages;
            while q < end && self.pages[q].is_none() {
                q += 1;
            }
            if q == end {
                return Some((p as u32) << PAGE_SHIFT);
            }
            p = q + 1;
        }
        None
    }

    /// Write a byte slice into emulator memory. Pages along the
    /// way must be mapped and writable; permission is checked
    /// per-page. Returns [`Trap::WriteProtectFault`] /
    /// [`Trap::MemoryFault`] on failure.
    pub fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), Trap> {
        for (i, b) in data.iter().enumerate() {
            self.store8(addr.wrapping_add(i as u32), *b)?;
        }
        Ok(())
    }

    /// Read `len` bytes out of emulator memory into a fresh
    /// `Vec<u8>`. Pages must be readable.
    pub fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, Trap> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            out.push(self.load8(addr.wrapping_add(i as u32))?);
        }
        Ok(out)
    }

    /// Allow the writer to bypass the per-page W permission check
    /// — used by the PE loader when populating section bytes
    /// before final permissions are stamped on.
    pub fn write_initializer(&mut self, addr: u32, data: &[u8]) -> Result<(), Trap> {
        for (i, b) in data.iter().enumerate() {
            self.store8_raw(addr.wrapping_add(i as u32), *b)?;
        }
        Ok(())
    }

    fn fetch_byte(&self, addr: u32) -> Result<u8, Trap> {
        let page_idx = (addr >> PAGE_SHIFT) as usize;
        let page = self.pages[page_idx]
            .as_ref()
            .ok_or(Trap::MemoryFault { addr })?;
        if !page.perm.contains(Perm::R) {
            return Err(Trap::ReadProtectFault { addr });
        }
        let off = (addr & PAGE_MASK) as usize;
        Ok(page.bytes[off])
    }

    fn put_byte(&mut self, addr: u32, value: u8) -> Result<(), Trap> {
        let page_idx = (addr >> PAGE_SHIFT) as usize;
        let page = self.pages[page_idx]
            .as_mut()
            .ok_or(Trap::MemoryFault { addr })?;
        if !page.perm.contains(Perm::W) {
            return Err(Trap::WriteProtectFault { addr });
        }
        let off = (addr & PAGE_MASK) as usize;
        page.bytes[off] = value;
        Ok(())
    }

    fn put_byte_raw(&mut self, addr: u32, value: u8) -> Result<(), Trap> {
        let page_idx = (addr >> PAGE_SHIFT) as usize;
        let page = self.pages[page_idx]
            .as_mut()
            .ok_or(Trap::MemoryFault { addr })?;
        let off = (addr & PAGE_MASK) as usize;
        page.bytes[off] = value;
        Ok(())
    }

    /// Fetch a byte for instruction decoding. Requires `X` (and
    /// `R` is implied — the page must be readable to be fetched
    /// from). Used by [`super::isa_int::Cpu::step`].
    pub fn fetch_x8(&self, addr: u32) -> Result<u8, Trap> {
        let page_idx = (addr >> PAGE_SHIFT) as usize;
        let page = self.pages[page_idx]
            .as_ref()
            .ok_or(Trap::MemoryFault { addr })?;
        if !page.perm.contains(Perm::X) {
            return Err(Trap::ExecuteProtectFault { addr });
        }
        let off = (addr & PAGE_MASK) as usize;
        Ok(page.bytes[off])
    }

    /// Read a byte from emulator memory.
    pub fn load8(&self, addr: u32) -> Result<u8, Trap> {
        let v = self.fetch_byte(addr)?;
        #[cfg(feature = "trace")]
        self.maybe_emit_read(addr, 1, u64::from(v));
        Ok(v)
    }

    /// Read a 16-bit little-endian word from emulator memory.
    pub fn load16(&self, addr: u32) -> Result<u16, Trap> {
        let b0 = self.fetch_byte(addr)?;
        let b1 = self.fetch_byte(addr.wrapping_add(1))?;
        let v = u16::from_le_bytes([b0, b1]);
        #[cfg(feature = "trace")]
        self.maybe_emit_read(addr, 2, u64::from(v));
        Ok(v)
    }

    /// Read a 32-bit little-endian dword.
    pub fn load32(&self, addr: u32) -> Result<u32, Trap> {
        let b0 = self.fetch_byte(addr)?;
        let b1 = self.fetch_byte(addr.wrapping_add(1))?;
        let b2 = self.fetch_byte(addr.wrapping_add(2))?;
        let b3 = self.fetch_byte(addr.wrapping_add(3))?;
        let v = u32::from_le_bytes([b0, b1, b2, b3]);
        #[cfg(feature = "trace")]
        self.maybe_emit_read(addr, 4, u64::from(v));
        Ok(v)
    }

    /// Read a 64-bit little-endian qword.
    pub fn load64(&self, addr: u32) -> Result<u64, Trap> {
        // Skip recursive trace emission from the inner load32
        // calls to avoid double events; emit a single 8-byte one.
        let lo = u64::from(self.load32_untraced(addr)?);
        let hi = u64::from(self.load32_untraced(addr.wrapping_add(4))?);
        let v = (hi << 32) | lo;
        #[cfg(feature = "trace")]
        self.maybe_emit_read(addr, 8, v);
        Ok(v)
    }

    /// Store a byte. Requires `W` permission.
    pub fn store8(&mut self, addr: u32, value: u8) -> Result<(), Trap> {
        self.put_byte(addr, value)?;
        #[cfg(feature = "trace")]
        self.maybe_emit_write(addr, 1, u64::from(value));
        Ok(())
    }

    /// Store a 16-bit little-endian word.
    pub fn store16(&mut self, addr: u32, value: u16) -> Result<(), Trap> {
        let bytes = value.to_le_bytes();
        self.put_byte(addr, bytes[0])?;
        self.put_byte(addr.wrapping_add(1), bytes[1])?;
        #[cfg(feature = "trace")]
        self.maybe_emit_write(addr, 2, u64::from(value));
        Ok(())
    }

    /// Store a 32-bit little-endian dword.
    pub fn store32(&mut self, addr: u32, value: u32) -> Result<(), Trap> {
        let bytes = value.to_le_bytes();
        self.put_byte(addr, bytes[0])?;
        self.put_byte(addr.wrapping_add(1), bytes[1])?;
        self.put_byte(addr.wrapping_add(2), bytes[2])?;
        self.put_byte(addr.wrapping_add(3), bytes[3])?;
        #[cfg(feature = "trace")]
        self.maybe_emit_write(addr, 4, u64::from(value));
        Ok(())
    }

    /// Store a 64-bit little-endian qword.
    pub fn store64(&mut self, addr: u32, value: u64) -> Result<(), Trap> {
        // Bypass per-half trace events to keep one event per call.
        self.store32_untraced(addr, value as u32)?;
        self.store32_untraced(addr.wrapping_add(4), (value >> 32) as u32)?;
        #[cfg(feature = "trace")]
        self.maybe_emit_write(addr, 8, value);
        Ok(())
    }

    #[cfg(feature = "trace")]
    fn load32_untraced(&self, addr: u32) -> Result<u32, Trap> {
        let b0 = self.fetch_byte(addr)?;
        let b1 = self.fetch_byte(addr.wrapping_add(1))?;
        let b2 = self.fetch_byte(addr.wrapping_add(2))?;
        let b3 = self.fetch_byte(addr.wrapping_add(3))?;
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }

    #[cfg(not(feature = "trace"))]
    fn load32_untraced(&self, addr: u32) -> Result<u32, Trap> {
        self.load32(addr)
    }

    #[cfg(feature = "trace")]
    fn store32_untraced(&mut self, addr: u32, value: u32) -> Result<(), Trap> {
        let bytes = value.to_le_bytes();
        self.put_byte(addr, bytes[0])?;
        self.put_byte(addr.wrapping_add(1), bytes[1])?;
        self.put_byte(addr.wrapping_add(2), bytes[2])?;
        self.put_byte(addr.wrapping_add(3), bytes[3])?;
        Ok(())
    }

    #[cfg(not(feature = "trace"))]
    fn store32_untraced(&mut self, addr: u32, value: u32) -> Result<(), Trap> {
        self.store32(addr, value)
    }

    /// Trace-feature-gated probe: emit a `mem_read` event if any
    /// active watchpoint covers `[addr, addr+size)` in read mode.
    /// Takes `&self` via the [`crate::trace::TraceState`]'s
    /// `RefCell<sink>` interior mutability.
    #[cfg(feature = "trace")]
    fn maybe_emit_read(&self, addr: u32, size: u32, value: u64) {
        if self.trace.matched_for_read(addr, size).is_some() {
            self.trace
                .ev_mem_read(addr, size, value, self.trace.last_eip);
        }
    }

    /// Trace-feature-gated probe: emit a `mem_write` event if any
    /// active watchpoint covers `[addr, addr+size)` in write mode.
    #[cfg(feature = "trace")]
    fn maybe_emit_write(&self, addr: u32, size: u32, value: u64) {
        if self.trace.matched_for_write(addr, size).is_some() {
            self.trace
                .ev_mem_write(addr, size, value, self.trace.last_eip);
        }
    }

    /// Internal: store a byte without consulting permission bits.
    /// Used only by [`Self::write_initializer`] — the PE loader's
    /// section-bytes path.
    fn store8_raw(&mut self, addr: u32, value: u8) -> Result<(), Trap> {
        self.put_byte_raw(addr, value)
    }
}

impl core::fmt::Debug for Mmu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mapped = self.pages.iter().filter(|p| p.is_some()).count();
        f.debug_struct("Mmu")
            .field("mapped_pages", &mapped)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perm_or_and_contains_compose() {
        let rw = Perm::R | Perm::W;
        assert!(rw.contains(Perm::R));
        assert!(rw.contains(Perm::W));
        assert!(!rw.contains(Perm::X));
        assert_eq!(rw.bits(), 0b011);
    }

    #[test]
    fn fresh_mmu_has_no_mapped_pages() {
        let mmu = Mmu::new();
        assert!(!mmu.is_mapped(0));
        assert!(!mmu.is_mapped(0x1000));
        assert!(!mmu.is_mapped(0xFFFF_F000));
    }

    #[test]
    fn map_marks_page_present() {
        let mut mmu = Mmu::new();
        mmu.map(0x1000, PAGE_SIZE as u32, Perm::R | Perm::W);
        assert!(mmu.is_mapped(0x1000));
        assert!(mmu.is_mapped(0x1FFF));
        assert!(!mmu.is_mapped(0x2000));
    }

    #[test]
    fn store_and_load_roundtrip_within_page() {
        let mut mmu = Mmu::new();
        mmu.map(0x1000, PAGE_SIZE as u32, Perm::R | Perm::W);
        mmu.store16(0x1000, 0xCAFE).unwrap();
        assert_eq!(mmu.load16(0x1000).unwrap(), 0xCAFE);
    }

    #[test]
    fn store32_load32_roundtrip_little_endian() {
        let mut mmu = Mmu::new();
        mmu.map(0x2000, PAGE_SIZE as u32, Perm::R | Perm::W);
        mmu.store32(0x2004, 0xDEAD_BEEF).unwrap();
        assert_eq!(mmu.load8(0x2004).unwrap(), 0xEF);
        assert_eq!(mmu.load8(0x2005).unwrap(), 0xBE);
        assert_eq!(mmu.load8(0x2006).unwrap(), 0xAD);
        assert_eq!(mmu.load8(0x2007).unwrap(), 0xDE);
        assert_eq!(mmu.load32(0x2004).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn store64_load64_roundtrip() {
        let mut mmu = Mmu::new();
        mmu.map(0x3000, PAGE_SIZE as u32, Perm::R | Perm::W);
        mmu.store64(0x3000, 0x0123_4567_89AB_CDEF).unwrap();
        assert_eq!(mmu.load64(0x3000).unwrap(), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn load_from_unmapped_page_traps_memory_fault() {
        let mmu = Mmu::new();
        match mmu.load8(0x1000) {
            Err(Trap::MemoryFault { addr }) => assert_eq!(addr, 0x1000),
            other => panic!("expected MemoryFault, got {other:?}"),
        }
    }

    #[test]
    fn store_to_non_w_page_traps_write_protect() {
        let mut mmu = Mmu::new();
        mmu.map(0x1000, PAGE_SIZE as u32, Perm::R); // R only
        match mmu.store8(0x1000, 0x42) {
            Err(Trap::WriteProtectFault { addr }) => assert_eq!(addr, 0x1000),
            other => panic!("expected WriteProtectFault, got {other:?}"),
        }
    }

    #[test]
    fn read_from_non_r_page_traps_read_protect() {
        let mut mmu = Mmu::new();
        // X-only page: rare in practice, but exercises the perm
        // check independently of the W bit.
        mmu.map(0x1000, PAGE_SIZE as u32, Perm::X);
        match mmu.load8(0x1000) {
            Err(Trap::ReadProtectFault { addr }) => assert_eq!(addr, 0x1000),
            other => panic!("expected ReadProtectFault, got {other:?}"),
        }
    }

    #[test]
    fn fetch_x8_requires_x_bit() {
        let mut mmu = Mmu::new();
        mmu.map(0x1000, PAGE_SIZE as u32, Perm::R | Perm::W);
        match mmu.fetch_x8(0x1000) {
            Err(Trap::ExecuteProtectFault { addr }) => assert_eq!(addr, 0x1000),
            other => panic!("expected ExecuteProtectFault, got {other:?}"),
        }
        mmu.map(0x1000, PAGE_SIZE as u32, Perm::R | Perm::X);
        assert_eq!(mmu.fetch_x8(0x1000).unwrap(), 0);
    }

    #[test]
    fn cross_page_store_checks_each_pages_permissions() {
        let mut mmu = Mmu::new();
        mmu.map(0x1000, PAGE_SIZE as u32, Perm::R | Perm::W);
        mmu.map(0x2000, PAGE_SIZE as u32, Perm::R); // RO follower
                                                    // dword straddles the page boundary at 0x2000
        match mmu.store32(0x1FFE, 0x1122_3344) {
            Err(Trap::WriteProtectFault { addr }) => {
                assert!(addr == 0x2000 || addr == 0x2001);
            }
            other => panic!("expected WriteProtectFault, got {other:?}"),
        }
    }

    #[test]
    fn write_initializer_bypasses_w_check() {
        let mut mmu = Mmu::new();
        // R+X page with no W — like a code section the loader is
        // populating.
        mmu.map(0x1000, PAGE_SIZE as u32, Perm::R | Perm::X);
        mmu.write_initializer(0x1000, &[0x90, 0x90, 0xC3]).unwrap();
        assert_eq!(mmu.load8(0x1000).unwrap(), 0x90);
        assert_eq!(mmu.load8(0x1002).unwrap(), 0xC3);
        // But the public write API still respects the bit.
        assert!(matches!(
            mmu.write(0x1000, &[0x00]),
            Err(Trap::WriteProtectFault { .. })
        ));
    }

    #[test]
    fn map_idempotent_preserves_existing_bytes() {
        let mut mmu = Mmu::new();
        mmu.map(0x4000, PAGE_SIZE as u32, Perm::R | Perm::W);
        mmu.store32(0x4000, 0xAABB_CCDD).unwrap();
        mmu.map(0x4000, PAGE_SIZE as u32, Perm::R); // re-permission
        assert_eq!(mmu.load32(0x4000).unwrap(), 0xAABB_CCDD);
    }

    #[test]
    fn unaligned_load_works_within_page() {
        let mut mmu = Mmu::new();
        mmu.map(0x5000, PAGE_SIZE as u32, Perm::R | Perm::W);
        mmu.store32(0x5001, 0x1234_5678).unwrap();
        assert_eq!(mmu.load32(0x5001).unwrap(), 0x1234_5678);
    }
}
