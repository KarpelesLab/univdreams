//! Raw flat-binary container.
//!
//! A `RawImage` is a contiguous byte buffer mapped at a fixed
//! virtual address. The address space outside the buffer is not
//! materialised. This is the format the 6502 stack uses — a 256-byte
//! WozMon ROM at $FF00 is just `RawImage::new(bytes, 0xFF00)`.
//!
//! Vectors aren't part of the container itself; they live in the
//! `.ud` `@module` block and are resolved by reading specific bytes
//! out of the image (e.g. `read_u16_le(0xFFFC)` for the 6502 reset
//! vector). The `read_*` helpers below are the convenience accessors.

#![allow(clippy::cast_possible_truncation)]

use ud_core::VAddr;

/// Errors returned by `RawImage` accessors.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("address {addr:#06x} is outside the image (load=[{load:#06x}, {end:#06x}))")]
    OutOfRange { addr: u64, load: u64, end: u64 },
    #[error("multi-byte read at {addr:#06x} ({len} bytes) crosses the end of the image")]
    Truncated { addr: u64, len: usize },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A flat byte image mapped at `load_addr`.
#[derive(Debug, Clone)]
pub struct RawImage {
    pub bytes: Vec<u8>,
    pub load_addr: u64,
}

impl RawImage {
    /// Construct an image from `bytes` mapped at `load_addr`.
    #[must_use]
    pub fn new(bytes: Vec<u8>, load_addr: u64) -> Self {
        Self { bytes, load_addr }
    }

    /// First valid address.
    #[must_use]
    pub fn start(&self) -> u64 {
        self.load_addr
    }

    /// One past the last valid address.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.load_addr + self.bytes.len() as u64
    }

    /// Whether `addr` lies inside the image.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start() && addr < self.end()
    }

    /// Translate a virtual address into a byte offset, or `None` if
    /// the address is outside the image.
    #[must_use]
    pub fn offset_of(&self, addr: u64) -> Option<usize> {
        if self.contains(addr) {
            Some((addr - self.load_addr) as usize)
        } else {
            None
        }
    }

    /// Read one byte at `addr`.
    pub fn read_u8(&self, addr: u64) -> Result<u8> {
        let off = self.offset_of(addr).ok_or(Error::OutOfRange {
            addr,
            load: self.start(),
            end: self.end(),
        })?;
        Ok(self.bytes[off])
    }

    /// Read a little-endian 16-bit word at `addr`. Used to read 6502
    /// vectors (`read_u16_le(0xFFFC)` is the reset vector).
    pub fn read_u16_le(&self, addr: u64) -> Result<u16> {
        let off = self.offset_of(addr).ok_or(Error::OutOfRange {
            addr,
            load: self.start(),
            end: self.end(),
        })?;
        if off + 2 > self.bytes.len() {
            return Err(Error::Truncated { addr, len: 2 });
        }
        Ok(u16::from_le_bytes([self.bytes[off], self.bytes[off + 1]]))
    }

    /// Borrow a slice starting at `addr`. Returns `None` if `addr` is
    /// outside the image.
    #[must_use]
    pub fn slice_at(&self, addr: u64) -> Option<&[u8]> {
        let off = self.offset_of(addr)?;
        Some(&self.bytes[off..])
    }

    /// Bounds of the image as a `VAddr` pair, in (start, end) order.
    #[must_use]
    pub fn bounds(&self) -> (VAddr, VAddr) {
        (VAddr(self.start()), VAddr(self.end()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_slice() {
        let img = RawImage::new(vec![0xAA, 0xBB, 0xCC, 0xDD], 0xFF00);
        assert_eq!(img.read_u8(0xFF00).unwrap(), 0xAA);
        assert_eq!(img.read_u16_le(0xFF00).unwrap(), 0xBBAA);
        assert_eq!(img.slice_at(0xFF02), Some(&[0xCC, 0xDD][..]));
        assert!(matches!(img.read_u8(0xFEFF), Err(Error::OutOfRange { .. })));
    }

    /// Apple I reset vector: $FFFC reads the low byte of the WozMon
    /// entry address ($FF00). This is the canonical sanity check.
    #[test]
    fn reset_vector_layout() {
        // 256-byte buffer; $FFFC/$FFFD = $00 $FF.
        let mut bytes = vec![0; 256];
        bytes[0xFC] = 0x00; // LSB
        bytes[0xFD] = 0xFF; // MSB
        let img = RawImage::new(bytes, 0xFF00);
        assert_eq!(img.read_u16_le(0xFFFC).unwrap(), 0xFF00);
    }
}
