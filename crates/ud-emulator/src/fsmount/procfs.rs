//! A synthetic, read-only `/proc`.
//!
//! Content is a snapshot the runtime populates at load time
//! ([`ProcFs::set_file`] / [`ProcFs::set_symlink`]): the static `cpuinfo` /
//! `meminfo` / `version`, the process's `self/cmdline` / `self/exe`, and
//! `self/maps` rendered from the MMU region list. Directories (`/`, `/self`)
//! are synthesised from the set of populated paths.

use std::collections::BTreeMap;
use std::io;

use super::{Attrs, DirEntry, MountFs, NodeKind};

#[derive(Debug, Clone)]
enum Node {
    File(Vec<u8>),
    Symlink(String),
}

/// Synthetic `/proc` filesystem. Paths are mount-relative (`"/cpuinfo"`,
/// `"/self/maps"`).
#[derive(Debug, Default)]
pub struct ProcFs {
    nodes: BTreeMap<String, Node>,
}

impl ProcFs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install (or replace) a regular file's bytes at `rel`.
    pub fn set_file(&mut self, rel: &str, bytes: Vec<u8>) {
        self.nodes.insert(norm(rel), Node::File(bytes));
    }

    /// Install a symlink at `rel` pointing at `target`.
    pub fn set_symlink(&mut self, rel: &str, target: &str) {
        self.nodes
            .insert(norm(rel), Node::Symlink(target.to_string()));
    }

    /// Render `/proc/self/maps`-style lines from coalesced MMU regions:
    /// `start-end perms offset dev inode pathname`.
    #[must_use]
    pub fn render_maps(regions: &[(u32, u64, crate::emulator::Perm)], exe: &str) -> Vec<u8> {
        use crate::emulator::Perm;
        let mut s = String::new();
        for &(start, end, perm) in regions {
            let r = if perm.contains(Perm::R) { 'r' } else { '-' };
            let w = if perm.contains(Perm::W) { 'w' } else { '-' };
            let x = if perm.contains(Perm::X) { 'x' } else { '-' };
            // Tag the executable's text/data range with its path; leave the
            // rest anonymous (stack/heap labels are best-effort).
            let path = if perm.contains(Perm::X) { exe } else { "" };
            s.push_str(&format!(
                "{start:08x}-{end:08x} {r}{w}{x}p 00000000 00:00 0 {path}\n"
            ));
        }
        s.into_bytes()
    }

    /// Is `rel` an existing node or a directory prefix of one?
    fn dir_of(&self, rel: &str) -> bool {
        let rel = norm(rel);
        if rel == "/" {
            return true;
        }
        let prefix = format!("{rel}/");
        self.nodes.keys().any(|k| k.starts_with(&prefix))
    }
}

fn norm(rel: &str) -> String {
    let t = rel.trim_end_matches('/');
    if t.is_empty() {
        "/".to_string()
    } else if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
}

impl MountFs for ProcFs {
    fn stat(&mut self, rel: &str) -> Option<Attrs> {
        let key = norm(rel);
        match self.nodes.get(&key) {
            Some(Node::File(b)) => Some(Attrs {
                kind: NodeKind::File,
                size: b.len() as u64,
                mode: 0o100_444,
                mtime: 0,
            }),
            Some(Node::Symlink(t)) => Some(Attrs {
                kind: NodeKind::Symlink,
                size: t.len() as u64,
                mode: 0o120_777,
                mtime: 0,
            }),
            None if self.dir_of(&key) => Some(Attrs {
                kind: NodeKind::Dir,
                size: 0,
                mode: 0o040_555,
                mtime: 0,
            }),
            None => None,
        }
    }

    fn read_at(&mut self, rel: &str, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let key = norm(rel);
        let Some(Node::File(data)) = self.nodes.get(&key) else {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        };
        let off = off as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }

    fn readlink(&mut self, rel: &str) -> io::Result<String> {
        match self.nodes.get(&norm(rel)) {
            Some(Node::Symlink(t)) => Ok(t.clone()),
            _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }

    fn readdir(&mut self, rel: &str) -> io::Result<Vec<DirEntry>> {
        let key = norm(rel);
        if !self.dir_of(&key) {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        let prefix = if key == "/" {
            "/".to_string()
        } else {
            format!("{key}/")
        };
        let mut seen = BTreeMap::new();
        for (path, node) in &self.nodes {
            if let Some(rest) = path.strip_prefix(&prefix) {
                let (first, more) = rest
                    .split_once('/')
                    .map_or((rest, false), |(a, _)| (a, true));
                if first.is_empty() {
                    continue;
                }
                let kind = if more {
                    NodeKind::Dir
                } else {
                    match node {
                        Node::File(_) => NodeKind::File,
                        Node::Symlink(_) => NodeKind::Symlink,
                    }
                };
                seen.entry(first.to_string()).or_insert(kind);
            }
        }
        Ok(seen
            .into_iter()
            .map(|(name, kind)| DirEntry { name, kind })
            .collect())
    }

    fn read_only(&self) -> bool {
        true
    }
}
