//! A synthetic `/dev` — the handful of character devices a program expects to
//! find: `null`, `zero`, `full`, `random`, `urandom`, `tty`.
//!
//! Reads/writes are generated, not stored. `random`/`urandom` are a
//! deterministic SplitMix64 stream so a run is reproducible; `/dev/full`
//! reports "out of space" on write the way the real one does.

use std::io;

use super::{Attrs, DirEntry, MountFs, NodeKind};

/// Device names served at the mount root.
const DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

/// Synthetic `/dev` filesystem.
#[derive(Debug)]
pub struct DevFs {
    rng: u64,
}

impl Default for DevFs {
    fn default() -> Self {
        Self::new()
    }
}

impl DevFs {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_byte(&mut self) -> u8 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 24) as u8
    }
}

/// Strip the leading `/` and return the bare device name.
fn name_of(rel: &str) -> &str {
    rel.trim_start_matches('/')
}

impl MountFs for DevFs {
    fn stat(&mut self, rel: &str) -> Option<Attrs> {
        let name = name_of(rel);
        if name.is_empty() {
            return Some(Attrs {
                kind: NodeKind::Dir,
                size: 0,
                mode: 0o040_755,
                mtime: 0,
                inode: 0,
            });
        }
        DEVICES.contains(&name).then_some(Attrs {
            kind: NodeKind::CharDevice,
            size: 0,
            mode: 0o020_666,
            mtime: 0,
            inode: 0,
        })
    }

    fn read_at(&mut self, rel: &str, _off: u64, buf: &mut [u8]) -> io::Result<usize> {
        match name_of(rel) {
            "null" | "tty" => Ok(0), // EOF
            "zero" | "full" => {
                buf.fill(0);
                Ok(buf.len())
            }
            "random" | "urandom" => {
                for b in buf.iter_mut() {
                    *b = self.next_byte();
                }
                Ok(buf.len())
            }
            _ => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }

    fn readdir(&mut self, rel: &str) -> io::Result<Vec<DirEntry>> {
        if !name_of(rel).is_empty() {
            return Err(io::Error::from_raw_os_error(20)); // ENOTDIR
        }
        Ok(DEVICES
            .iter()
            .map(|&n| DirEntry {
                name: n.to_string(),
                kind: NodeKind::CharDevice,
            })
            .collect())
    }

    fn read_only(&self) -> bool {
        false
    }

    fn write_at(&mut self, rel: &str, _off: u64, data: &[u8]) -> io::Result<usize> {
        match name_of(rel) {
            // /dev/full always reports ENOSPC.
            "full" => Err(io::Error::from_raw_os_error(28)),
            "null" | "zero" | "random" | "urandom" | "tty" => Ok(data.len()),
            _ => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }
}
