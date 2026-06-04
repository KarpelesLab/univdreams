//! Optional emulation-context layer.
//!
//! Sits on the [`HostState`](crate::win32::HostState) and provides
//! per-instance environmental surfaces the guest can query
//! through Win32 stubs:
//!
//! * [`VirtualFs`] — a read/write in-memory filesystem. The
//!   guest can `CreateFileA` / `ReadFile` / `WriteFile` /
//!   `CloseHandle` against it; nothing ever touches the host
//!   filesystem. Used both for "feed a fixture to the program"
//!   workflows (analyse a sample that wants to load a config
//!   file) and for "capture what the program would write"
//!   workflows (malware that stages payloads).
//! * [`VirtualRegistry`] — a read/write key-value tree
//!   modelling the Windows registry. Same intent: the guest
//!   `Reg*` API calls observe whatever the analyst pre-staged
//!   and writes land in-memory.
//!
//! Both pieces are optional. A sandbox with no `Context`
//! surfaces presents the same fail-soft Win32 stubs as before;
//! attaching one swaps the no-op fail-soft for "consult the
//! virtual surface". Future additions (virtual network,
//! virtual clock, ...) hang off [`Context`] the same way.
//!
//! The contract is bounded-only: no `Context` surface can
//! reach the host's filesystem, registry, network, or
//! clock — every byte the guest sees came from the
//! analyst-controlled `Context` or from the emulator's
//! synthesised state. That's the whole point of running
//! untrusted code through this stack.

use std::collections::BTreeMap;

/// Top-level optional context layer. Owned by
/// [`HostState`](crate::win32::HostState); each guest call to a
/// Win32 stub backed by a virtual surface goes through here.
#[derive(Debug, Default, Clone)]
pub struct Context {
    /// In-memory filesystem, if attached.
    pub vfs: Option<VirtualFs>,
    /// In-memory registry, if attached.
    pub registry: Option<VirtualRegistry>,
}

impl Context {
    /// Empty context — no virtual filesystem, no virtual
    /// registry. Equivalent to [`Default::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: attach the given VFS.
    #[must_use]
    pub fn with_vfs(mut self, vfs: VirtualFs) -> Self {
        self.vfs = Some(vfs);
        self
    }

    /// Builder: attach the given registry.
    #[must_use]
    pub fn with_registry(mut self, reg: VirtualRegistry) -> Self {
        self.registry = Some(reg);
        self
    }
}

// ============================================================
// Virtual filesystem
// ============================================================

/// In-memory filesystem the guest can read and write through
/// the Win32 file APIs. Paths are normalised to lowercase +
/// forward slashes internally so `"C:\\Windows\\foo.ini"`,
/// `"c:/windows/foo.ini"`, and `"C:/WINDOWS/Foo.INI"` all
/// reference the same file — matching the case-insensitive
/// behaviour of Windows.
///
/// The handle space is local to the VFS; opened handles are
/// returned as `u32` values starting at [`HANDLE_BASE`].
#[derive(Debug, Default, Clone)]
pub struct VirtualFs {
    files: BTreeMap<String, Vec<u8>>,
    open: BTreeMap<u32, FileHandle>,
    next_handle: u32,
}

/// One open file handle's state.
#[derive(Debug, Clone)]
pub struct FileHandle {
    /// Normalised path the handle refers to.
    pub path: String,
    /// Current file pointer, in bytes from start.
    pub pos: u64,
    /// Access mode the handle was opened with.
    pub access: FileAccess,
}

/// What the guest asked for when opening the file. Mirrors
/// the Win32 `GENERIC_READ` / `GENERIC_WRITE` axes — the
/// virtual filesystem honours the access bits so a
/// `GENERIC_READ`-only handle can't `WriteFile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    Read,
    Write,
    ReadWrite,
}

impl FileAccess {
    /// Map a Win32 `dwDesiredAccess` bitset to the matching
    /// [`FileAccess`]. `GENERIC_READ = 0x80000000`,
    /// `GENERIC_WRITE = 0x40000000`.
    #[must_use]
    pub fn from_win32_desired_access(flags: u32) -> Self {
        let read = flags & 0x8000_0000 != 0;
        let write = flags & 0x4000_0000 != 0;
        match (read, write) {
            (true, true) => FileAccess::ReadWrite,
            (false, true) => FileAccess::Write,
            _ => FileAccess::Read, // default to read on (0,0) too
        }
    }

    fn allows_read(self) -> bool {
        matches!(self, FileAccess::Read | FileAccess::ReadWrite)
    }
    fn allows_write(self) -> bool {
        matches!(self, FileAccess::Write | FileAccess::ReadWrite)
    }
}

/// First handle [`VirtualFs::open`] hands back. The base is
/// well above the kernel32 heap arena and the synthetic HIC
/// space so the kinds don't collide.
pub const HANDLE_BASE: u32 = 0x6800_0000;

impl VirtualFs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a file. Overwrites whatever was at `path`
    /// before.
    pub fn insert(&mut self, path: &str, bytes: Vec<u8>) {
        self.files.insert(normalize_path(path), bytes);
    }

    /// Read a file by path. Returns `None` if not present.
    /// Doesn't open a handle — just peeks.
    #[must_use]
    pub fn read(&self, path: &str) -> Option<&[u8]> {
        self.files.get(&normalize_path(path)).map(Vec::as_slice)
    }

    /// True iff a file exists at this path.
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.files.contains_key(&normalize_path(path))
    }

    /// Replace a file's bytes by path. Inserts if absent.
    /// Doesn't go through a handle.
    pub fn write_path(&mut self, path: &str, bytes: Vec<u8>) {
        self.files.insert(normalize_path(path), bytes);
    }

    /// Remove a file. Returns `true` if it was present.
    pub fn remove(&mut self, path: &str) -> bool {
        self.files.remove(&normalize_path(path)).is_some()
    }

    /// Iterate over every (path, byte-count) pair.
    pub fn list(&self) -> impl Iterator<Item = (&str, usize)> {
        self.files.iter().map(|(k, v)| (k.as_str(), v.len()))
    }

    /// Open a handle to the file at `path`. Returns `None`
    /// when the file doesn't exist (and the caller asked for
    /// read-only access). For write access, the file is
    /// created if absent.
    pub fn open(&mut self, path: &str, access: FileAccess) -> Option<u32> {
        let key = normalize_path(path);
        let exists = self.files.contains_key(&key);
        if !exists {
            if !access.allows_write() {
                return None;
            }
            self.files.insert(key.clone(), Vec::new());
        }
        let handle = HANDLE_BASE.wrapping_add(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        self.open.insert(
            handle,
            FileHandle {
                path: key,
                pos: 0,
                access,
            },
        );
        Some(handle)
    }

    /// Close a handle. Returns `true` if the handle was
    /// known. Successive `close` calls are tolerated (they
    /// return `false`).
    pub fn close(&mut self, handle: u32) -> bool {
        self.open.remove(&handle).is_some()
    }

    /// Read up to `buf.len()` bytes from the file at the
    /// handle's current position. Advances the position by
    /// the read length. Returns the number of bytes read
    /// (`0` at EOF), or `None` if the handle is unknown or
    /// not readable.
    pub fn read_handle(&mut self, handle: u32, buf: &mut [u8]) -> Option<usize> {
        let fh = self.open.get_mut(&handle)?;
        if !fh.access.allows_read() {
            return None;
        }
        let file = self.files.get(&fh.path)?;
        let pos = fh.pos as usize;
        if pos >= file.len() {
            return Some(0);
        }
        let n = buf.len().min(file.len() - pos);
        buf[..n].copy_from_slice(&file[pos..pos + n]);
        fh.pos = fh.pos.wrapping_add(n as u64);
        Some(n)
    }

    /// Write `data` to the file at the handle's current
    /// position. Extends the file as needed. Returns the
    /// number of bytes written, or `None` if the handle is
    /// unknown or not writable.
    pub fn write_handle(&mut self, handle: u32, data: &[u8]) -> Option<usize> {
        let fh = self.open.get_mut(&handle)?;
        if !fh.access.allows_write() {
            return None;
        }
        let file = self.files.get_mut(&fh.path)?;
        let pos = fh.pos as usize;
        if pos + data.len() > file.len() {
            file.resize(pos + data.len(), 0);
        }
        file[pos..pos + data.len()].copy_from_slice(data);
        fh.pos = fh.pos.wrapping_add(data.len() as u64);
        Some(data.len())
    }

    /// Move the handle's file pointer to `pos`. Returns the
    /// new position, or `None` if the handle is unknown.
    pub fn seek(&mut self, handle: u32, pos: u64) -> Option<u64> {
        let fh = self.open.get_mut(&handle)?;
        fh.pos = pos;
        Some(pos)
    }

    /// Seek by `off` relative to `whence` (0 = SET, 1 = CUR, 2 = END,
    /// matching DOS `INT 21h/42h` / C `SEEK_*`). Returns the new absolute
    /// position, or `None` if the handle is unknown.
    pub fn seek_handle(&mut self, handle: u32, off: i32, whence: u8) -> Option<u64> {
        let base = match whence {
            1 => self.open.get(&handle)?.pos as i64,
            2 => self.size(handle)? as i64,
            _ => 0,
        };
        let pos = (base + i64::from(off)).max(0) as u64;
        let fh = self.open.get_mut(&handle)?;
        fh.pos = pos;
        Some(pos)
    }

    /// Current size of the file the handle refers to.
    /// Returns `None` if the handle is unknown.
    #[must_use]
    pub fn size(&self, handle: u32) -> Option<u64> {
        let fh = self.open.get(&handle)?;
        let file = self.files.get(&fh.path)?;
        Some(file.len() as u64)
    }

    /// True iff `handle` was minted by this VFS (and still
    /// open). Used by the Win32 stubs to disambiguate
    /// VFS-backed handles from heap / event / semaphore
    /// handles when `CloseHandle` is called.
    #[must_use]
    pub fn owns(&self, handle: u32) -> bool {
        self.open.contains_key(&handle)
    }
}

/// Normalise a Windows-style path for case-insensitive lookup.
/// Lowercases the whole string and converts `\` to `/`. Drive
/// letters stay attached (`C:` stays `c:`). For registry paths,
/// rewrites the four well-known hive prefixes
/// (`HKEY_LOCAL_MACHINE`/`HKLM`, …) to their short canonical
/// form so writes via long-name strings and reads via
/// [`predefined_path`] meet at the same key.
fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c == '\\' {
            out.push('/');
        } else {
            out.extend(c.to_lowercase());
        }
    }
    // Rewrite long hive names to their short canonical form.
    // Order matters — `hkey_users` is a prefix of nothing else,
    // but `hkey_local_machine` shares a prefix with the others
    // only at `hkey_`, so any order is fine in practice.
    for (long, short) in [
        ("hkey_local_machine", "hklm"),
        ("hkey_current_user", "hkcu"),
        ("hkey_classes_root", "hkcr"),
        ("hkey_users", "hku"),
    ] {
        if out == long {
            return short.to_string();
        }
        let prefix = format!("{long}/");
        if let Some(rest) = out.strip_prefix(&prefix) {
            return format!("{short}/{rest}");
        }
    }
    out
}

// ============================================================
// Virtual registry
// ============================================================

/// In-memory Windows registry tree. Keys are referenced by
/// their full path (`"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft"`).
/// Each key holds a set of named values; the value names are
/// matched case-insensitively per the Win32 contract.
///
/// The handle space is local to the registry; opened keys
/// return synthetic `HKEY` values starting at
/// [`HKEY_USER_BASE`]. The four predefined hive roots
/// (`HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`,
/// `HKEY_CLASSES_ROOT`, `HKEY_USERS`) live at
/// [`HKLM`] / [`HKCU`] / [`HKCR`] / [`HKU`] respectively.
#[derive(Debug, Default, Clone)]
pub struct VirtualRegistry {
    /// All known keys, indexed by full path (case-folded).
    keys: BTreeMap<String, RegistryKey>,
    /// Open handle → (key path, …).
    open: BTreeMap<u32, OpenKey>,
    next_handle: u32,
}

/// One open registry key.
#[derive(Debug, Clone)]
pub struct OpenKey {
    pub path: String,
}

/// One registry key — a bag of named values.
#[derive(Debug, Default, Clone)]
pub struct RegistryKey {
    values: BTreeMap<String, RegistryValue>,
}

/// One typed registry value. Mirrors the standard `REG_SZ` /
/// `REG_DWORD` / `REG_BINARY` / `REG_MULTI_SZ` shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryValue {
    /// `REG_SZ` — null-terminated string.
    Sz(String),
    /// `REG_EXPAND_SZ` — string with embedded `%VAR%`
    /// references the loader is expected to expand.
    ExpandSz(String),
    /// `REG_DWORD` — 32-bit integer.
    Dword(u32),
    /// `REG_QWORD` — 64-bit integer.
    Qword(u64),
    /// `REG_BINARY` — opaque bytes.
    Binary(Vec<u8>),
    /// `REG_MULTI_SZ` — `\0`-separated list, terminated by
    /// an extra `\0`.
    MultiSz(Vec<String>),
}

/// Predefined hive handles. Win32 docs spell them as negative
/// pointers, but we hand back ordinary `u32` values; the
/// codec doesn't care what the bits are, only that closing
/// + reopening lands a different key correctly.
pub const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
pub const HKEY_CURRENT_USER: u32 = 0x8000_0001;
pub const HKEY_LOCAL_MACHINE: u32 = 0x8000_0002;
pub const HKEY_USERS: u32 = 0x8000_0003;
/// Short aliases the docs use interchangeably.
pub const HKCR: u32 = HKEY_CLASSES_ROOT;
pub const HKCU: u32 = HKEY_CURRENT_USER;
pub const HKLM: u32 = HKEY_LOCAL_MACHINE;
pub const HKU: u32 = HKEY_USERS;

/// First handle [`VirtualRegistry::open_key`] hands back.
pub const HKEY_USER_BASE: u32 = 0x6900_0000;

impl VirtualRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a value on a key, creating the key if absent.
    pub fn set_value(&mut self, key_path: &str, name: &str, value: RegistryValue) {
        let key = normalize_path(key_path);
        let entry = self.keys.entry(key).or_default();
        entry.values.insert(name.to_ascii_lowercase(), value);
    }

    /// Read a value by `(key, name)`. Case-insensitive.
    #[must_use]
    pub fn get_value(&self, key_path: &str, name: &str) -> Option<&RegistryValue> {
        let key = normalize_path(key_path);
        self.keys
            .get(&key)
            .and_then(|k| k.values.get(&name.to_ascii_lowercase()))
    }

    /// Iterate every `(key_path, value_name, value)` triple in
    /// the virtual registry. Suitable for "what did the guest
    /// write?" reports.
    pub fn all_values(&self) -> impl Iterator<Item = (&str, &str, &RegistryValue)> {
        self.keys.iter().flat_map(|(key_path, key)| {
            key.values
                .iter()
                .map(move |(name, value)| (key_path.as_str(), name.as_str(), value))
        })
    }

    /// True iff the named key exists.
    #[must_use]
    pub fn contains_key(&self, key_path: &str) -> bool {
        self.keys.contains_key(&normalize_path(key_path))
    }

    /// Resolve a predefined hive handle to its canonical
    /// path string.
    #[must_use]
    pub fn predefined_path(hkey: u32) -> Option<&'static str> {
        match hkey {
            HKEY_CLASSES_ROOT => Some("hkcr"),
            HKEY_CURRENT_USER => Some("hkcu"),
            HKEY_LOCAL_MACHINE => Some("hklm"),
            HKEY_USERS => Some("hku"),
            _ => None,
        }
    }

    /// Open a subkey under `base_hkey` (which may be a
    /// predefined hive or a previously-returned user handle).
    /// Returns `None` if the key doesn't exist.
    pub fn open_key(&mut self, base_hkey: u32, subkey: &str) -> Option<u32> {
        let base_path = if let Some(p) = Self::predefined_path(base_hkey) {
            p.to_string()
        } else {
            self.open.get(&base_hkey)?.path.clone()
        };
        let combined = if subkey.is_empty() {
            base_path
        } else {
            format!("{}/{}", base_path, normalize_path(subkey))
        };
        if !self.keys.contains_key(&combined) {
            return None;
        }
        let h = HKEY_USER_BASE.wrapping_add(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        self.open.insert(h, OpenKey { path: combined });
        Some(h)
    }

    /// Close a previously-opened handle. Predefined hives
    /// (`HKLM` etc.) are tolerated — the call is a no-op.
    /// Returns `true` if the handle was a user handle that
    /// was closed.
    pub fn close_key(&mut self, hkey: u32) -> bool {
        if Self::predefined_path(hkey).is_some() {
            return true;
        }
        self.open.remove(&hkey).is_some()
    }

    /// True iff `hkey` was minted by this registry (and still
    /// open). Used by the Win32 stubs to disambiguate
    /// registry handles from VFS / heap / event handles when
    /// `CloseHandle` is called.
    #[must_use]
    pub fn owns(&self, hkey: u32) -> bool {
        Self::predefined_path(hkey).is_some() || self.open.contains_key(&hkey)
    }

    /// Map an open handle back to its canonical key path.
    /// Returns `None` if `hkey` isn't known.
    #[must_use]
    pub fn path_of(&self, hkey: u32) -> Option<&str> {
        if let Some(p) = Self::predefined_path(hkey) {
            return Some(p);
        }
        self.open.get(&hkey).map(|k| k.path.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vfs_insert_and_read_case_insensitive() {
        let mut vfs = VirtualFs::new();
        vfs.insert("C:\\Windows\\foo.ini", b"hello".to_vec());
        assert_eq!(vfs.read("C:\\Windows\\foo.ini"), Some(&b"hello"[..]));
        assert_eq!(vfs.read("c:/windows/FOO.INI"), Some(&b"hello"[..]));
        assert_eq!(vfs.read("nope.txt"), None);
    }

    #[test]
    fn vfs_open_read_close() {
        let mut vfs = VirtualFs::new();
        vfs.insert("a.txt", b"hello world".to_vec());
        let h = vfs.open("a.txt", FileAccess::Read).expect("opens");
        let mut buf = [0u8; 5];
        assert_eq!(vfs.read_handle(h, &mut buf), Some(5));
        assert_eq!(&buf, b"hello");
        assert_eq!(vfs.read_handle(h, &mut buf), Some(5));
        assert_eq!(&buf, b" worl");
        let mut tail = [0u8; 5];
        assert_eq!(vfs.read_handle(h, &mut tail), Some(1));
        assert_eq!(&tail[..1], b"d");
        assert_eq!(vfs.read_handle(h, &mut buf), Some(0));
        assert!(vfs.close(h));
    }

    #[test]
    fn vfs_write_extends_and_round_trips() {
        let mut vfs = VirtualFs::new();
        let h = vfs.open("new.txt", FileAccess::Write).expect("opens");
        assert_eq!(vfs.write_handle(h, b"hello").unwrap(), 5);
        assert_eq!(vfs.write_handle(h, b" world").unwrap(), 6);
        vfs.close(h);
        assert_eq!(vfs.read("new.txt"), Some(&b"hello world"[..]));
    }

    #[test]
    fn vfs_read_only_handle_cannot_write() {
        let mut vfs = VirtualFs::new();
        vfs.insert("a.txt", b"hi".to_vec());
        let h = vfs.open("a.txt", FileAccess::Read).unwrap();
        assert!(vfs.write_handle(h, b"!").is_none());
    }

    #[test]
    fn vfs_open_nonexistent_read_returns_none() {
        let mut vfs = VirtualFs::new();
        assert!(vfs.open("missing.txt", FileAccess::Read).is_none());
    }

    #[test]
    fn registry_set_get_case_insensitive() {
        let mut reg = VirtualRegistry::new();
        reg.set_value(
            "HKLM\\Software\\Foo",
            "Version",
            RegistryValue::Sz("1.2.3".into()),
        );
        assert_eq!(
            reg.get_value("hklm/software/foo", "version"),
            Some(&RegistryValue::Sz("1.2.3".into()))
        );
        assert_eq!(
            reg.get_value("HKLM\\Software\\Foo", "VERSION"),
            Some(&RegistryValue::Sz("1.2.3".into()))
        );
    }

    #[test]
    fn registry_open_close_round_trip() {
        let mut reg = VirtualRegistry::new();
        reg.set_value(
            "hkey_local_machine/software/foo",
            "x",
            RegistryValue::Dword(1),
        );
        let h = reg.open_key(HKLM, "Software\\Foo").expect("opens");
        assert!(reg.owns(h));
        assert_eq!(reg.path_of(h), Some("hklm/software/foo"));
        assert!(reg.close_key(h));
    }

    #[test]
    fn context_builders() {
        let mut vfs = VirtualFs::new();
        vfs.insert("a.txt", b"x".to_vec());
        let mut reg = VirtualRegistry::new();
        reg.set_value("hklm", "v", RegistryValue::Dword(1));
        let ctx = Context::new().with_vfs(vfs).with_registry(reg);
        assert!(ctx.vfs.is_some());
        assert!(ctx.registry.is_some());
    }
}
