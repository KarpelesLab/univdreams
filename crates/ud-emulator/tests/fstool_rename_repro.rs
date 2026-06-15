//! Minimal reproduction of a fstool ext bug surfaced by `apk add git`: files in
//! a large directory (e.g. /usr/libexec/git-core/, ~100 entries) fail to rename
//! with "ext: entry not found in directory". It mirrors apk's exact pattern —
//! create an empty `.apk.<n>` file, write it, then rename it to the final name.
//!
//! Finding: the first ~100 files rename fine; once the directory's entries
//! outgrow a single 4 KiB directory block, `rename`'s directory lookup can no
//! longer find newly-created entries (it appears to only scan the first block),
//! even though `create_file`/`open_file_rw` placed and wrote them. The threshold
//! tracks the block size: ~100 short names per 4 KiB block.
//!
//! `#[ignore]`d because it documents a *known fstool-crate bug*, not an emulator
//! regression. Drop the `ignore` once fstool's multi-block directory lookup is
//! fixed; the assertion then guards against regressing it. Run explicitly with:
//!   cargo test -p ud-emulator --features fstool --test fstool_rename_repro \
//!     -- --ignored --nocapture
#![cfg(feature = "fstool")]
#![allow(clippy::cast_possible_truncation)]

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use fstool::block::MemoryBackend;
use fstool::fs::ext::{Ext, FormatOpts, FsKind};
use fstool::fs::{FileMeta, FileSource, Filesystem, FilesystemFactory, OpenFlags};

#[test]
#[ignore = "reproduces a known fstool ext bug (rename can't find entries past \
            the first directory block); un-ignore when fstool is fixed"]
fn create_then_rename_in_large_dir() {
    let size = 256u64 << 20;
    let mut dev = MemoryBackend::new(size);
    let block_size = 4096u32;
    let blocks_count = (size / u64::from(block_size)) as u32;
    let mut fs: Box<dyn Filesystem> = Box::new(
        Ext::format(
            &mut dev,
            &FormatOpts {
                kind: FsKind::Ext4,
                block_size,
                blocks_count,
                inodes_count: (blocks_count / 4).max(16),
                ..Default::default()
            },
        )
        .expect("format ext4"),
    );

    fs.create_dir(&mut dev, Path::new("/d"), FileMeta::with_mode(0o755))
        .expect("mkdir /d");

    // apk's loop: for each file, create a `.apk.<n>` temp, write it, rename it
    // to the final name. Report the first rename that the backend can't find.
    let mut first_fail = None;
    let n = 200;
    for i in 0..n {
        let tmp = format!("/d/.apk.{i:08x}");
        let fin = format!("/d/file{i:04}");
        fs.create_file(
            &mut dev,
            Path::new(&tmp),
            FileSource::Zero(0),
            FileMeta::with_mode(0o755),
        )
        .unwrap_or_else(|e| panic!("create {tmp} (#{i}): {e}"));
        {
            let mut h = fs
                .open_file_rw(
                    &mut dev,
                    Path::new(&tmp),
                    OpenFlags {
                        create: false,
                        truncate: false,
                        append: false,
                    },
                    None,
                )
                .unwrap_or_else(|e| panic!("open {tmp} (#{i}): {e}"));
            h.seek(SeekFrom::Start(0)).unwrap();
            h.write_all(&vec![0xabu8; 1024]).unwrap();
        }
        if let Err(e) = fs.rename(&mut dev, Path::new(&tmp), Path::new(&fin)) {
            eprintln!("RENAME FAILED at #{i}: {tmp} -> {fin}: {e}");
            first_fail.get_or_insert(i);
        }
    }

    match first_fail {
        Some(i) => eprintln!("=> first rename failure at index {i} of {n}"),
        None => eprintln!("=> all {n} create+rename succeeded"),
    }
    assert!(
        first_fail.is_none(),
        "fstool ext create+rename failed starting at #{first_fail:?}"
    );
}
