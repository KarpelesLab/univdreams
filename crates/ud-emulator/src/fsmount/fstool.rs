//! A real on-disk filesystem mounted into the table, backed by our `fstool`
//! crate (ext2/3/4, NTFS, FAT, exFAT). Off by default — only built with the
//! `fstool` cargo feature.
//!
//! The block device is either a fresh in-memory image ([`FsToolMount::format_empty`],
//! i.e. mkfs) or a host filesystem image opened read-only / read-write
//! ([`FsToolMount::open_image`]).
//!
//! fstool's open handles borrow the filesystem *and* the device for their
//! lifetime, so every [`MountFs`] operation opens, seeks, does the I/O, and
//! drops the handle within the call — never holding one across other ops.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use fstool::block::{BlockDevice, FileBackend, MemoryBackend};
use fstool::fs::{EntryKind, FileMeta, FileSource, Filesystem, FilesystemFactory, OpenFlags};

use super::{Attrs, DirEntry, MountFs, NodeKind};

/// A mounted real filesystem: an fstool [`Filesystem`] over a block device.
pub struct FsToolMount {
    fs: Box<dyn Filesystem>,
    dev: Box<dyn BlockDevice>,
    read_only: bool,
}

impl std::fmt::Debug for FsToolMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FsToolMount(read_only={})", self.read_only)
    }
}

fn to_io(e: fstool::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

/// Format a fresh empty filesystem of `fs_type` onto a `size`-byte `dev`.
fn format_fs(
    fs_type: &str,
    dev: &mut dyn BlockDevice,
    size: u64,
) -> fstool::Result<Box<dyn Filesystem>> {
    use fstool::fs::{exfat, ext, fat, ntfs};
    // ext sizing must be set explicitly (its default is a 1 MiB image with no
    // spare data blocks); 4 KiB blocks, one inode per 4 blocks.
    let ext_opts = |kind| {
        let block_size = 4096u32;
        let blocks_count = (size / u64::from(block_size)).max(64) as u32;
        ext::FormatOpts {
            kind,
            block_size,
            blocks_count,
            inodes_count: (blocks_count / 4).max(16),
            ..Default::default()
        }
    };
    Ok(match fs_type {
        "ext2" => Box::new(ext::Ext::format(dev, &ext_opts(ext::FsKind::Ext2))?),
        "ext3" => Box::new(ext::Ext::format(dev, &ext_opts(ext::FsKind::Ext3))?),
        "ext" | "ext4" => Box::new(ext::Ext::format(dev, &ext_opts(ext::FsKind::Ext4))?),
        "ntfs" => Box::new(ntfs::Ntfs::format(dev, &Default::default())?),
        "fat" | "fat32" | "vfat" => {
            // FAT's default opts leave total_sectors at 0; size it from the device.
            let fat_opts = fat::FatFormatOpts {
                total_sectors: (size / 512).min(u64::from(u32::MAX)) as u32,
                ..Default::default()
            };
            Box::new(fat::Fat32::format(dev, &fat_opts)?)
        }
        "exfat" => Box::new(exfat::Exfat::format(dev, &Default::default())?),
        other => {
            return Err(fstool::Error::Unsupported(format!(
                "unknown / unsupported filesystem type {other:?}"
            )))
        }
    })
}

/// Open an existing filesystem of `fs_type` on `dev`.
fn open_fs(fs_type: &str, dev: &mut dyn BlockDevice) -> fstool::Result<Box<dyn Filesystem>> {
    use fstool::fs::{exfat, ext, fat, ntfs};
    Ok(match fs_type {
        "ext" | "ext2" | "ext3" | "ext4" => Box::new(ext::Ext::open(dev)?),
        "ntfs" => Box::new(ntfs::Ntfs::open(dev)?),
        "fat" | "fat32" | "vfat" => Box::new(fat::Fat32::open(dev)?),
        "exfat" => Box::new(exfat::Exfat::open(dev)?),
        other => {
            return Err(fstool::Error::Unsupported(format!(
                "unknown / unsupported filesystem type {other:?}"
            )))
        }
    })
}

impl FsToolMount {
    /// `mkfs`: format a fresh empty `fs_type` on an in-memory device of `size`
    /// bytes (default 64 MiB if `size` is 0).
    ///
    /// # Errors
    /// fstool error if the type is unknown or formatting fails.
    pub fn format_empty(fs_type: &str, size: u64) -> io::Result<Self> {
        let size = if size == 0 { 64 << 20 } else { size };
        let mut dev = MemoryBackend::new(size);
        let fs = format_fs(fs_type, &mut dev, size).map_err(to_io)?;
        Ok(Self {
            fs,
            dev: Box::new(dev),
            read_only: false,
        })
    }

    /// `mkfs` onto a host file: create a fresh `size`-byte image at `path`,
    /// format it as `fs_type`, and keep it writable so changes flush back to
    /// the file on drop.
    ///
    /// # Errors
    /// I/O error creating the file, or an fstool error formatting it.
    pub fn format_image(path: &Path, fs_type: &str, size: u64) -> io::Result<Self> {
        let size = if size == 0 { 64 << 20 } else { size };
        let mut dev = FileBackend::create(path, size).map_err(to_io)?;
        let fs = format_fs(fs_type, &mut dev, size).map_err(to_io)?;
        Ok(Self {
            fs,
            dev: Box::new(dev),
            read_only: false,
        })
    }

    /// Open a host filesystem image. `writeback` keeps the device writable so
    /// changes flush back to the file on drop; otherwise it is read-only.
    ///
    /// Reads are fully supported on real-world images. Writeback persistence is
    /// solid for *in-place* edits and for images that `fstool` itself formatted
    /// (see [`format_image`](Self::format_image)); persisting a *newly created*
    /// inode back into an image produced by host `mke2fs` can leave metadata a
    /// strict e2fsprogs reader won't follow — an `fstool`-crate gap, not a
    /// routing one. Within a single run the new file reads back correctly.
    ///
    /// # Errors
    /// I/O error opening the file, or an fstool error parsing the filesystem.
    pub fn open_image(path: &Path, fs_type: &str, writeback: bool) -> io::Result<Self> {
        if writeback {
            let mut dev = FileBackend::open(path).map_err(to_io)?;
            let fs = open_fs(fs_type, &mut dev).map_err(to_io)?;
            Ok(Self {
                fs,
                dev: Box::new(dev),
                read_only: false,
            })
        } else {
            let mut dev = FileBackend::open_read_only(path).map_err(to_io)?;
            let fs = open_fs(fs_type, &mut dev).map_err(to_io)?;
            Ok(Self {
                fs,
                dev: Box::new(dev),
                read_only: true,
            })
        }
    }

    /// Persist any buffered state to the backing device.
    pub fn flush(&mut self) -> io::Result<()> {
        self.fs.flush(&mut *self.dev).map_err(to_io)
    }
}

/// Build a fresh **ext** image at `image_path` populated from `source_path`
/// (a `.tar.gz`/`.tar`/directory — auto-detected), sized to fit the source
/// plus `extra_bytes` of writable headroom (for e.g. package installs into the
/// root). Only ext2/3/4 targets are supported here (the sizing planner is
/// ext-specific); `fs_type` selects the variant. The image is flushed and
/// closed — mount it afterwards with [`FsToolMount::open_image`].
///
/// # Errors
/// I/O error creating the file, or an fstool error detecting / sizing /
/// formatting / repacking the source.
pub fn build_ext_image(
    image_path: &Path,
    fs_type: &str,
    source_path: &Path,
    extra_bytes: u64,
) -> io::Result<()> {
    use fstool::fs::ext::{Ext, FsKind};
    use fstool::repack::{
        ext_build_plan_for_source, walk_source_into_sink, FsSink, RepackSink, Source,
    };

    let kind = match fs_type {
        "ext2" => FsKind::Ext2,
        "ext3" => FsKind::Ext3,
        _ => FsKind::Ext4, // "ext" | "ext4" | anything else
    };
    let spec = source_path.to_string_lossy();
    let source = Source::detect(&spec).map_err(to_io)?;

    // Walk once to size the filesystem for the source, then grow it to leave
    // `extra_bytes` of free space so the mounted root is genuinely writable.
    let block_size = 4096u32;
    let plan = ext_build_plan_for_source(&source, block_size, kind).map_err(to_io)?;
    let mut opts = plan.to_format_opts();
    let source_bytes = u64::from(opts.blocks_count) * u64::from(block_size);
    let want_bytes = source_bytes + extra_bytes;
    let want_blocks = (want_bytes / u64::from(block_size)).min(u64::from(u32::MAX)) as u32;
    if want_blocks > opts.blocks_count {
        opts.blocks_count = (want_blocks / 8) * 8;
        // ~one inode per 16 KiB of headroom so apk has inodes to spare.
        let by_density = (u64::from(opts.blocks_count) * u64::from(block_size) / 16_384) as u32;
        opts.inodes_count = opts.inodes_count.max(by_density);
    }
    // The backing file is freshly created (all-zero) and we sparsify holes.
    opts.sparse = true;
    opts.prezeroed = true;

    let dev_bytes = u64::from(opts.blocks_count) * u64::from(block_size);
    let mut dev = FileBackend::create(image_path, dev_bytes).map_err(to_io)?;
    let mut fs = Ext::format_with(&mut dev, &opts).map_err(to_io)?;
    {
        let mut sink = FsSink::new(&mut fs, &mut dev);
        walk_source_into_sink(&source, &mut sink).map_err(to_io)?;
        // walk_source_into_sink leaves finishing to the caller.
        sink.finish().map_err(to_io)?;
    }
    fs.flush(&mut dev).map_err(to_io)?;
    Ok(())
}

fn map_kind(k: EntryKind) -> NodeKind {
    match k {
        EntryKind::Dir => NodeKind::Dir,
        EntryKind::Symlink => NodeKind::Symlink,
        EntryKind::Char | EntryKind::Block => NodeKind::CharDevice,
        _ => NodeKind::File,
    }
}

impl MountFs for FsToolMount {
    fn stat(&mut self, rel: &str) -> Option<Attrs> {
        let a = self.fs.getattr(&mut *self.dev, Path::new(rel)).ok()?;
        Some(Attrs {
            kind: map_kind(a.kind),
            size: a.size,
            mode: u32::from(a.mode),
            mtime: u64::from(a.mtime),
            inode: u64::from(a.inode),
        })
    }

    fn read_at(&mut self, rel: &str, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut h = self
            .fs
            .open_file_ro(&mut *self.dev, Path::new(rel))
            .map_err(to_io)?;
        h.seek(SeekFrom::Start(off))?;
        h.read(buf)
    }

    fn readdir(&mut self, rel: &str) -> io::Result<Vec<DirEntry>> {
        let entries = self
            .fs
            .list(&mut *self.dev, Path::new(rel))
            .map_err(to_io)?;
        Ok(entries
            .into_iter()
            .map(|e| DirEntry {
                name: e.name,
                kind: map_kind(e.kind),
            })
            .collect())
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn write_at(&mut self, rel: &str, off: u64, data: &[u8]) -> io::Result<usize> {
        let mut h = self
            .fs
            .open_file_rw(
                &mut *self.dev,
                Path::new(rel),
                OpenFlags {
                    create: false,
                    truncate: false,
                    append: false,
                },
                None,
            )
            .map_err(to_io)?;
        h.seek(SeekFrom::Start(off))?;
        h.write(data)
    }

    fn create(&mut self, rel: &str, mode: u32) -> io::Result<()> {
        self.fs
            .create_file(
                &mut *self.dev,
                Path::new(rel),
                FileSource::Zero(0),
                FileMeta::with_mode(mode as u16),
            )
            .map_err(to_io)
    }

    fn mkdir(&mut self, rel: &str, mode: u32) -> io::Result<()> {
        self.fs
            .create_dir(
                &mut *self.dev,
                Path::new(rel),
                FileMeta::with_mode(mode as u16),
            )
            .map_err(to_io)
    }

    fn truncate(&mut self, rel: &str, len: u64) -> io::Result<()> {
        self.fs
            .truncate(&mut *self.dev, Path::new(rel), len)
            .map_err(to_io)
    }

    fn readlink(&mut self, rel: &str) -> io::Result<String> {
        let target = self
            .fs
            .read_symlink(&mut *self.dev, Path::new(rel))
            .map_err(to_io)?;
        Ok(target.to_string_lossy().into_owned())
    }

    fn symlink(&mut self, target: &str, rel: &str) -> io::Result<()> {
        self.fs
            .create_symlink(
                &mut *self.dev,
                Path::new(rel),
                Path::new(target),
                FileMeta::with_mode(0o777),
            )
            .map_err(to_io)
    }

    fn unlink(&mut self, rel: &str) -> io::Result<()> {
        self.fs
            .remove(&mut *self.dev, Path::new(rel))
            .map_err(to_io)
    }

    fn rmdir(&mut self, rel: &str) -> io::Result<()> {
        self.fs
            .remove(&mut *self.dev, Path::new(rel))
            .map_err(to_io)
    }

    fn rename(&mut self, old_rel: &str, new_rel: &str) -> io::Result<()> {
        self.fs
            .rename(&mut *self.dev, Path::new(old_rel), Path::new(new_rel))
            .map_err(to_io)
    }

    fn hardlink(&mut self, target_rel: &str, new_rel: &str) -> io::Result<()> {
        self.fs
            .hardlink(&mut *self.dev, Path::new(target_rel), Path::new(new_rel))
            .map_err(to_io)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.read_only {
            return Ok(());
        }
        FsToolMount::flush(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsmount::MountFs;

    #[test]
    fn ext4_mkfs_create_write_read_list() {
        let mut fs = FsToolMount::format_empty("ext4", 16 << 20).expect("mkfs ext4");
        fs.create("/hello.txt", 0o644).expect("create");
        assert_eq!(fs.write_at("/hello.txt", 0, b"hello world").unwrap(), 11);
        let mut buf = [0u8; 11];
        assert_eq!(fs.read_at("/hello.txt", 0, &mut buf).unwrap(), 11);
        assert_eq!(&buf, b"hello world");
        let a = fs.stat("/hello.txt").expect("stat");
        assert_eq!(a.size, 11);
        assert!(matches!(a.kind, NodeKind::File));
        let names: Vec<_> = fs
            .readdir("/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.iter().any(|n| n == "hello.txt"), "listed: {names:?}");
    }

    #[test]
    fn ext4_image_writeback_then_reopen() {
        // Build a fresh ext4 image on a host file, write a file, drop it (flush),
        // then reopen read-only and read the bytes back.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ud_fstool_wb_{}.img", std::process::id()));
        {
            let mut fs = FsToolMount::format_image(&path, "ext4", 16 << 20).expect("mkfs image");
            fs.create("/persisted.txt", 0o644).expect("create");
            assert_eq!(fs.write_at("/persisted.txt", 0, b"on disk").unwrap(), 7);
            fs.flush().expect("flush");
        }
        {
            let mut fs = FsToolMount::open_image(&path, "ext4", false).expect("reopen ro");
            assert!(fs.read_only());
            let mut buf = [0u8; 7];
            assert_eq!(fs.read_at("/persisted.txt", 0, &mut buf).unwrap(), 7);
            assert_eq!(&buf, b"on disk");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn repack_tar_gz_into_ext4_root() {
        // Build a tiny .tar.gz tree (regular file + nested dir + symlink) with
        // the host `tar`, repack it into an ext4 image, then mount and verify
        // the tree round-tripped. Skips when no `tar` is available.
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("ud_repack_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("root");
        if std::fs::create_dir_all(root.join("etc")).is_err() {
            return;
        }
        std::fs::write(root.join("etc/release"), b"alpine-like 1.0\n").unwrap();
        std::fs::write(root.join("bin_busybox"), b"#!busybox\n").unwrap();
        // A symlink ls -> bin_busybox (skip the test if symlinks aren't allowed).
        if std::os::unix::fs::symlink("bin_busybox", root.join("ls")).is_err() {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let tarball = dir.join("rootfs.tar.gz");
        let ok = Command::new("tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&root)
            .arg(".")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("SKIP: no working `tar` on this host");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let image = dir.join("root.ext4");
        build_ext_image(&image, "ext4", &tarball, 8 << 20).expect("repack tar.gz -> ext4");

        let mut fs = FsToolMount::open_image(&image, "ext4", false).expect("mount built image");
        // Regular file content.
        let a = fs.stat("/etc/release").expect("stat release");
        assert!(matches!(a.kind, NodeKind::File));
        let mut buf = vec![0u8; a.size as usize];
        fs.read_at("/etc/release", 0, &mut buf).unwrap();
        assert_eq!(&buf, b"alpine-like 1.0\n");
        // Symlink preserved.
        let l = fs.stat("/ls").expect("stat symlink");
        assert!(
            matches!(l.kind, NodeKind::Symlink),
            "ls is a symlink: {l:?}"
        );
        // Directory listing.
        let names: Vec<_> = fs
            .readdir("/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.iter().any(|n| n == "etc"), "listed: {names:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
