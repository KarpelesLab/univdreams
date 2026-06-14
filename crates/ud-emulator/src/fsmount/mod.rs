//! A **mount table** layered over the per-instance virtual filesystem.
//!
//! Historically the guest saw a single flat [`VirtualFs`](crate::context::VirtualFs)
//! (a path→bytes map). This module lets multiple filesystems live at multiple
//! paths: a **root** backend plus prefix-keyed **overlays** (e.g. Linux
//! `/proc`, `/dev`, or a real ext4 image mounted at `/data`). Path lookups
//! pick the longest matching mount point; everything not under an overlay
//! falls through to the root.
//!
//! The table re-exposes the exact [`VirtualFs`] handle API
//! (`open`/`read_handle`/`write_handle`/`seek*`/`size`/`owns` plus the
//! path helpers), so the Win32 / Linux call sites only change their receiver
//! type. With no overlays installed every call delegates straight to the root
//! filesystem — byte-for-byte the previous behaviour.
//!
//! Overlay backends implement [`MountFs`] (a small **path + offset** trait).
//! The per-operation shape — open, seek, do the I/O, drop — is deliberate: it
//! is what real-filesystem backends (via the `fstool` crate) require, because
//! their open handles borrow the filesystem *and* its block device for their
//! whole lifetime, so no long-lived handle can be kept across other calls.

pub mod devfs;
#[cfg(feature = "fstool")]
pub mod fstool;
pub mod procfs;

use std::collections::BTreeMap;

use crate::context::{FileAccess, VirtualFs};

/// Kind of a filesystem node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
    Symlink,
    CharDevice,
}

/// Metadata for a path, as reported by [`MountFs::stat`].
#[derive(Debug, Clone, Copy)]
pub struct Attrs {
    pub kind: NodeKind,
    pub size: u64,
    /// Unix mode bits (type + permissions), e.g. `0o100644`.
    pub mode: u32,
    /// Modification time, seconds since the epoch.
    pub mtime: u64,
    /// Inode number, or `0` when the backend has no per-path identity (the
    /// kernel then synthesises one from the path). The dynamic linker dedups
    /// libraries by inode, so distinct files must report distinct inodes.
    pub inode: u64,
}

/// One entry returned by [`MountFs::readdir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub kind: NodeKind,
}

/// A filesystem mounted at a path. All paths are **mount-relative** and
/// already normalised (leading `/`, forward slashes, no `.`/`..`).
///
/// Only [`stat`](Self::stat), [`read_at`](Self::read_at) and
/// [`readdir`](Self::readdir) are required; the mutating operations default to
/// `EROFS` so a read-only backend (a synthetic `/proc`, an image opened
/// read-only) needs to implement only what it serves.
pub trait MountFs: std::fmt::Debug {
    /// Metadata for `rel`, or `None` if it does not exist.
    fn stat(&mut self, rel: &str) -> Option<Attrs>;

    /// Read into `buf` starting at byte `off`. Returns bytes read (0 at EOF).
    fn read_at(&mut self, rel: &str, off: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// List the directory at `rel`.
    fn readdir(&mut self, rel: &str) -> std::io::Result<Vec<DirEntry>>;

    /// Whether this mount rejects all writes.
    fn read_only(&self) -> bool {
        true
    }

    fn write_at(&mut self, _rel: &str, _off: u64, _data: &[u8]) -> std::io::Result<usize> {
        Err(read_only_err())
    }
    /// Create an empty regular file (for `O_CREAT`). No-op if it exists.
    fn create(&mut self, _rel: &str, _mode: u32) -> std::io::Result<()> {
        Err(read_only_err())
    }
    fn mkdir(&mut self, _rel: &str, _mode: u32) -> std::io::Result<()> {
        Err(read_only_err())
    }
    fn unlink(&mut self, _rel: &str) -> std::io::Result<()> {
        Err(read_only_err())
    }
    fn rmdir(&mut self, _rel: &str) -> std::io::Result<()> {
        Err(read_only_err())
    }
    fn truncate(&mut self, _rel: &str, _len: u64) -> std::io::Result<()> {
        Err(read_only_err())
    }
    fn symlink(&mut self, _target: &str, _rel: &str) -> std::io::Result<()> {
        Err(read_only_err())
    }
    /// Rename `old_rel` to `new_rel` within this filesystem (atomic, preserves
    /// symlinks). Default is unsupported so the caller can fall back to copy +
    /// unlink.
    fn rename(&mut self, _old_rel: &str, _new_rel: &str) -> std::io::Result<()> {
        Err(read_only_err())
    }
    fn readlink(&mut self, _rel: &str) -> std::io::Result<String> {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }

    /// Persist any buffered state to the backing store. The default is a no-op
    /// (in-memory / read-only backends have nothing to flush); a real
    /// writeback filesystem overrides this to commit metadata + data.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn read_only_err() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, "read-only filesystem")
}

/// First handle the table hands back for an **overlay**-backed open. Kept well
/// clear of [`crate::context::HANDLE_BASE`] (root-VFS handles) and the Win32
/// heap / synthetic-HIC ranges so handle kinds never collide.
const OVERLAY_HANDLE_BASE: u32 = 0x6A00_0000;

/// State of one open file on an overlay mount: which mount, the mount-relative
/// path, the cursor, and the access mode.
#[derive(Debug, Clone)]
struct OverlayHandle {
    mount: usize,
    path: String,
    pos: u64,
    access: FileAccess,
}

/// A mount: the absolute mount point (normalised) and its backend.
struct Mount {
    point: String,
    fs: Box<dyn MountFs>,
}

impl std::fmt::Debug for Mount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mount({:?})", self.point)
    }
}

/// The per-instance mount table. Owns the root [`VirtualFs`] plus any overlay
/// mounts, and re-exposes the `VirtualFs` handle/path API with longest-prefix
/// routing.
#[derive(Debug)]
pub struct MountTable {
    /// Default `/` backend. Unchanged in-memory semantics; reached for any path
    /// not under an overlay.
    root: VirtualFs,
    /// Overlay mounts, kept sorted by descending mount-point length so the
    /// first prefix match is the longest (most specific) one.
    overlays: Vec<Mount>,
    /// Open files on overlay mounts (root-VFS handles live in `root`).
    handles: BTreeMap<u32, OverlayHandle>,
    next_handle: u32,
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MountTable {
    #[must_use]
    pub fn new() -> Self {
        Self::with_root(VirtualFs::new())
    }

    /// Build a table whose root `/` is the given in-memory filesystem.
    #[must_use]
    pub fn with_root(root: VirtualFs) -> Self {
        Self {
            root,
            overlays: Vec::new(),
            handles: BTreeMap::new(),
            next_handle: 0,
        }
    }

    /// Borrow the root in-memory filesystem (staging fixtures, dumping output,
    /// legacy direct access from Win16 / MSI).
    #[must_use]
    pub fn root(&self) -> &VirtualFs {
        &self.root
    }
    pub fn root_mut(&mut self) -> &mut VirtualFs {
        &mut self.root
    }

    /// Mount `fs` at the absolute, normalised `point` (e.g. `"/proc"`). The
    /// overlay list stays sorted longest-point-first for resolution.
    pub fn mount(&mut self, point: &str, fs: Box<dyn MountFs>) {
        let point = norm_abs(point);
        self.overlays.retain(|m| m.point != point);
        self.overlays.push(Mount { point, fs });
        self.overlays
            .sort_by(|a, b| b.point.len().cmp(&a.point.len()));
    }

    /// Resolve an absolute path to `(overlay index, mount-relative path)` if it
    /// falls under an overlay, else `None` (use the root).
    fn resolve(&self, abs: &str) -> Option<(usize, String)> {
        let abs = norm_abs(abs);
        for (i, m) in self.overlays.iter().enumerate() {
            if let Some(rel) = under_mount(&m.point, &abs) {
                return Some((i, rel));
            }
        }
        None
    }

    // ---- path API (mirrors VirtualFs) -----------------------------------

    pub fn insert(&mut self, path: &str, bytes: Vec<u8>) {
        self.root.insert(path, bytes);
    }
    #[must_use]
    pub fn read(&self, path: &str) -> Option<&[u8]> {
        // Borrowed-peek is only meaningful for the in-memory root; overlay
        // content is served through handles.
        self.root.read(path)
    }
    #[must_use]
    pub fn contains(&mut self, path: &str) -> bool {
        if let Some((i, rel)) = self.resolve(path) {
            return self.overlays[i].fs.stat(&rel).is_some();
        }
        self.root.contains(path)
    }
    pub fn write_path(&mut self, path: &str, bytes: Vec<u8>) {
        self.root.write_path(path, bytes);
    }
    pub fn remove(&mut self, path: &str) -> bool {
        self.root.remove(path)
    }
    pub fn list(&self) -> impl Iterator<Item = (&str, usize)> {
        self.root.list()
    }

    // ---- handle API (mirrors VirtualFs) ---------------------------------

    pub fn open(&mut self, path: &str, access: FileAccess) -> Option<u32> {
        let Some((mount, rel)) = self.resolve(path) else {
            return self.root.open(path, access);
        };
        let fs = &mut self.overlays[mount].fs;
        let exists = fs.stat(&rel).is_some();
        if !exists {
            if !access_writes(access) || fs.read_only() {
                return None;
            }
            fs.create(&rel, 0o644).ok()?;
        }
        let handle = OVERLAY_HANDLE_BASE.wrapping_add(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        self.handles.insert(
            handle,
            OverlayHandle {
                mount,
                path: rel,
                pos: 0,
                access,
            },
        );
        Some(handle)
    }

    pub fn close(&mut self, handle: u32) -> bool {
        if self.handles.remove(&handle).is_some() {
            return true;
        }
        self.root.close(handle)
    }

    pub fn read_handle(&mut self, handle: u32, buf: &mut [u8]) -> Option<usize> {
        let Some(h) = self.handles.get_mut(&handle) else {
            return self.root.read_handle(handle, buf);
        };
        if !access_reads(h.access) {
            return None;
        }
        let n = self.overlays[h.mount]
            .fs
            .read_at(&h.path, h.pos, buf)
            .ok()?;
        h.pos = h.pos.wrapping_add(n as u64);
        Some(n)
    }

    pub fn write_handle(&mut self, handle: u32, data: &[u8]) -> Option<usize> {
        let Some(h) = self.handles.get_mut(&handle) else {
            return self.root.write_handle(handle, data);
        };
        if !access_writes(h.access) {
            return None;
        }
        let n = self.overlays[h.mount]
            .fs
            .write_at(&h.path, h.pos, data)
            .ok()?;
        h.pos = h.pos.wrapping_add(n as u64);
        Some(n)
    }

    pub fn seek(&mut self, handle: u32, pos: u64) -> Option<u64> {
        if let Some(h) = self.handles.get_mut(&handle) {
            h.pos = pos;
            return Some(pos);
        }
        self.root.seek(handle, pos)
    }

    pub fn seek_handle(&mut self, handle: u32, off: i32, whence: u8) -> Option<u64> {
        let Some(h) = self.handles.get(&handle) else {
            return self.root.seek_handle(handle, off, whence);
        };
        let base = match whence {
            1 => h.pos as i64,
            2 => self.size(handle)? as i64,
            _ => 0,
        };
        let pos = (base + i64::from(off)).max(0) as u64;
        self.handles.get_mut(&handle)?.pos = pos;
        Some(pos)
    }

    #[must_use]
    pub fn size(&mut self, handle: u32) -> Option<u64> {
        if let Some(h) = self.handles.get(&handle) {
            let (mount, path) = (h.mount, h.path.clone());
            return Some(self.overlays[mount].fs.stat(&path)?.size);
        }
        self.root.size(handle)
    }

    #[must_use]
    pub fn owns(&self, handle: u32) -> bool {
        self.handles.contains_key(&handle) || self.root.owns(handle)
    }

    /// Follow symlinks (up to a small depth) and return the absolute path of
    /// the final target. Stops at the first non-symlink (or a dangling link).
    #[must_use]
    pub fn resolve_symlinks(&mut self, path: &str) -> String {
        let mut p = norm_abs(path);
        for _ in 0..16 {
            match self.stat_path(&p) {
                Some(a) if matches!(a.kind, NodeKind::Symlink) => {
                    let Ok(target) = self.readlink_path(&p) else {
                        break;
                    };
                    p = if target.starts_with('/') {
                        norm_abs(&target)
                    } else {
                        let dir = p.rsplit_once('/').map_or("", |(d, _)| d);
                        norm_abs(&format!("{dir}/{target}"))
                    };
                }
                _ => break,
            }
        }
        p
    }

    /// Like [`stat_path`](Self::stat_path) but follows symlinks to their final
    /// target (what `stat`, as opposed to `lstat`, reports).
    #[must_use]
    pub fn stat_follow(&mut self, abs: &str) -> Option<Attrs> {
        let target = self.resolve_symlinks(abs);
        self.stat_path(&target)
    }

    /// Read an entire file by absolute path into memory, resolving symlinks
    /// (up to a small depth). Works for the root and any overlay. Returns
    /// `None` if the path can't be resolved or opened. Used by the dynamic ELF
    /// loader to pull the interpreter / shared objects out of the rootfs.
    #[must_use]
    pub fn read_file(&mut self, path: &str) -> Option<Vec<u8>> {
        let p = self.resolve_symlinks(path);
        let h = self.open(&p, FileAccess::Read)?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(n) = self.read_handle(h, &mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        self.close(h);
        Some(out)
    }

    // ---- path metadata + directory operations ---------------------------

    /// Stat an absolute path, routing to the overlay that owns it (else the
    /// in-memory root, which synthesises directories from stored paths).
    #[must_use]
    pub fn stat_path(&mut self, abs: &str) -> Option<Attrs> {
        if let Some((i, rel)) = self.resolve(abs) {
            return self.overlays[i].fs.stat(&rel);
        }
        let (is_dir, size) = self.root.stat_node(abs)?;
        Some(Attrs {
            kind: if is_dir {
                NodeKind::Dir
            } else {
                NodeKind::File
            },
            size,
            mode: if is_dir { 0o755 } else { 0o644 },
            mtime: 0,
            inode: 0,
        })
    }

    /// List the directory at an absolute path. For the root, overlay mount
    /// points that sit directly under `abs` also appear (so `/` shows `proc`,
    /// `dev`, …). Errors `ENOTDIR` if `abs` is a file.
    pub fn readdir_path(&mut self, abs: &str) -> std::io::Result<Vec<DirEntry>> {
        if let Some((i, rel)) = self.resolve(abs) {
            let mut entries = self.overlays[i].fs.readdir(&rel)?;
            // Backends differ on whether they list "." / ".."; drop them here so
            // the caller (getdents64) owns those uniformly.
            entries.retain(|e| e.name != "." && e.name != "..");
            return Ok(entries);
        }
        let mut out = match self.root.readdir(abs) {
            Some(children) => children
                .into_iter()
                .map(|(name, is_dir)| DirEntry {
                    name,
                    kind: if is_dir {
                        NodeKind::Dir
                    } else {
                        NodeKind::File
                    },
                })
                .collect::<Vec<_>>(),
            None => return Err(std::io::Error::from_raw_os_error(20)), // ENOTDIR
        };
        // Surface overlay mount points whose parent directory is `abs`.
        let parent = norm_abs(abs);
        for m in &self.overlays {
            if let Some((dir, base)) = m.point.rsplit_once('/') {
                let dir = if dir.is_empty() { "/" } else { dir };
                if dir == parent && !out.iter().any(|e| e.name == base) {
                    out.push(DirEntry {
                        name: base.to_string(),
                        kind: NodeKind::Dir,
                    });
                }
            }
        }
        Ok(out)
    }

    pub fn mkdir_path(&mut self, abs: &str, mode: u32) -> std::io::Result<()> {
        if let Some((i, rel)) = self.resolve(abs) {
            return self.overlays[i].fs.mkdir(&rel, mode);
        }
        Ok(()) // root directories are implicit
    }

    pub fn unlink_path(&mut self, abs: &str) -> std::io::Result<()> {
        if let Some((i, rel)) = self.resolve(abs) {
            return self.overlays[i].fs.unlink(&rel);
        }
        if self.root.remove(abs) {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(2)) // ENOENT
        }
    }

    pub fn rmdir_path(&mut self, abs: &str) -> std::io::Result<()> {
        if let Some((i, rel)) = self.resolve(abs) {
            return self.overlays[i].fs.rmdir(&rel);
        }
        Ok(()) // root directories are implicit; nothing to remove
    }

    pub fn symlink_path(&mut self, target: &str, abs: &str) -> std::io::Result<()> {
        if let Some((i, rel)) = self.resolve(abs) {
            return self.overlays[i].fs.symlink(target, &rel);
        }
        Err(read_only_err()) // the in-memory root has no symlink concept
    }

    pub fn readlink_path(&mut self, abs: &str) -> std::io::Result<String> {
        if let Some((i, rel)) = self.resolve(abs) {
            return self.overlays[i].fs.readlink(&rel);
        }
        Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)) // EINVAL: not a link
    }

    /// Rename within a single mount using the backend's native rename (atomic,
    /// symlink-preserving). Errors if the two paths land on different mounts or
    /// the backend lacks rename — the caller then falls back to copy + unlink.
    pub fn rename_path(&mut self, old_abs: &str, new_abs: &str) -> std::io::Result<()> {
        let old = self.resolve(old_abs);
        let new = self.resolve(new_abs);
        if let (Some((i, old_rel)), Some((j, new_rel))) = (old, new) {
            if i == j {
                return self.overlays[i].fs.rename(&old_rel, &new_rel);
            }
        }
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    pub fn truncate_path(&mut self, abs: &str, len: u64) -> std::io::Result<()> {
        if let Some((i, rel)) = self.resolve(abs) {
            return self.overlays[i].fs.truncate(&rel, len);
        }
        if self.root.truncate(abs, len) {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(2)) // ENOENT
        }
    }

    /// Flush every overlay mount, committing buffered writeback to its backing
    /// store. Best-effort: the first error is returned but all mounts are still
    /// attempted. The in-memory root needs no flush.
    pub fn flush_all(&mut self) -> std::io::Result<()> {
        let mut first_err = None;
        for m in &mut self.overlays {
            if let Err(e) = m.fs.flush() {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}

impl Drop for MountTable {
    fn drop(&mut self) {
        // Commit writeback images on teardown even if no explicit flush ran.
        let _ = self.flush_all();
    }
}

fn access_reads(a: FileAccess) -> bool {
    matches!(a, FileAccess::Read | FileAccess::ReadWrite)
}
fn access_writes(a: FileAccess) -> bool {
    matches!(a, FileAccess::Write | FileAccess::ReadWrite)
}

/// Normalise an absolute path for routing: forward slashes, collapse `//`,
/// strip a trailing slash (except root), ensure a leading slash.
fn norm_abs(path: &str) -> String {
    let mut s = String::with_capacity(path.len() + 1);
    if !path.starts_with('/') && !path.starts_with('\\') {
        s.push('/');
    }
    let mut prev_slash = false;
    for c in path.chars() {
        let c = if c == '\\' { '/' } else { c };
        if c == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        s.push(c);
    }
    if s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

/// If `abs` is the mount point `point` or a path under it, return the
/// mount-relative path (always starting with `/`).
fn under_mount(point: &str, abs: &str) -> Option<String> {
    if point == "/" {
        return Some(abs.to_string());
    }
    if abs == point {
        return Some("/".to_string());
    }
    let with_slash = format!("{point}/");
    abs.strip_prefix(&with_slash).map(|rest| format!("/{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_delegates_to_root() {
        let mut t = MountTable::new();
        t.insert("/etc/hosts", b"127.0.0.1 localhost\n".to_vec());
        let h = t.open("/etc/hosts", FileAccess::Read).unwrap();
        let mut buf = [0u8; 9];
        assert_eq!(t.read_handle(h, &mut buf), Some(9));
        assert_eq!(&buf, b"127.0.0.1");
        assert!(t.owns(h));
        assert!(t.close(h));
        assert!(t.contains("/etc/hosts"));
    }

    #[test]
    fn overlay_read_open_routes_to_backend() {
        let mut t = MountTable::new();
        t.mount("/dev", Box::new(crate::fsmount::devfs::DevFs::new()));
        // Read-only open of an existing overlay device must succeed and route.
        let h = t
            .open("/dev/urandom", FileAccess::Read)
            .expect("open urandom");
        assert!(
            h >= OVERLAY_HANDLE_BASE,
            "overlay handle, not a root handle"
        );
        let mut buf = [0u8; 8];
        assert_eq!(t.read_handle(h, &mut buf), Some(8));
        // A non-existent device read-opens to nothing (not auto-created).
        assert!(t.open("/dev/nope", FileAccess::Read).is_none());
        // Root path still goes to the in-memory VFS.
        assert!(t.open("/etc/x", FileAccess::Read).is_none());
    }

    #[test]
    fn root_dir_synthesis_stat_and_readdir() {
        let mut t = MountTable::new();
        t.insert("/work/a.txt", b"hello".to_vec());
        t.insert("/work/sub/c.txt", b"xyz".to_vec());
        // A stored file stats as a regular file with its byte length.
        let a = t.stat_path("/work/a.txt").expect("file stat");
        assert!(matches!(a.kind, NodeKind::File));
        assert_eq!(a.size, 5);
        // A path beneath which files live synthesises as a directory.
        let d = t.stat_path("/work").expect("dir stat");
        assert!(matches!(d.kind, NodeKind::Dir));
        // readdir lists the immediate children: a file and a synthesised dir.
        let mut names: Vec<_> = t
            .readdir_path("/work")
            .unwrap()
            .into_iter()
            .map(|e| (e.name, matches!(e.kind, NodeKind::Dir)))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![("a.txt".to_string(), false), ("sub".to_string(), true)]
        );
        // readdir on a file is ENOTDIR.
        assert!(t.readdir_path("/work/a.txt").is_err());
    }

    #[test]
    fn root_readdir_surfaces_overlay_mount_points() {
        let mut t = MountTable::new();
        t.mount("/dev", Box::new(crate::fsmount::devfs::DevFs::new()));
        let names: Vec<_> = t
            .readdir_path("/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            names.iter().any(|n| n == "dev"),
            "mount point listed: {names:?}"
        );
    }

    #[test]
    fn norm_and_resolution() {
        assert_eq!(norm_abs("/proc//self/"), "/proc/self");
        assert_eq!(norm_abs("proc"), "/proc");
        assert_eq!(
            under_mount("/proc", "/proc/self/maps").as_deref(),
            Some("/self/maps")
        );
        assert_eq!(under_mount("/proc", "/proc").as_deref(), Some("/"));
        assert_eq!(under_mount("/proc", "/process"), None);
        assert_eq!(under_mount("/", "/etc/x").as_deref(), Some("/etc/x"));
    }
}
