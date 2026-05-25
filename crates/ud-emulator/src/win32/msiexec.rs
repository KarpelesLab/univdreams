//! Wine-style msiexec: a host-side MSI processor invoked when
//! a sandboxed installer tries to
//! `CreateProcessA("C:\\WINDOWS\\System32\\msiexec.exe", "/i …")`.
//!
//! Lives inside the emulator (rather than as its own crate)
//! because the install effects route directly into the
//! emulator's [`crate::context::VirtualFs`] and
//! [`crate::context::VirtualRegistry`] — there's no reason for
//! an external consumer to take just the MSI walker.
//!
//! The module reads the MSI's database (via the `msi` crate),
//! resolves the standard property + directory + component +
//! file + registry tables, and **reports** what would be
//! installed through a host-supplied [`InstallSink`]. The sink
//! is what gives the emulator (or any analyst harness) full
//! control: it can synthesise the install into a VFS, log every
//! action, redirect files, skip components, override property
//! values, or just dump the plan for offline review.
//!
//! This is NOT a faithful Windows-Installer reimplementation —
//! we don't run InstallExecuteSequence custom actions, we don't
//! evaluate every conditional expression in the database, and
//! we don't write the `Installer` COM surface. What we DO do:
//!
//! 1. Load the MSI's `Property` table (the default values for
//!    `ProgramFilesFolder`, `INSTALLDIR`, `Manufacturer`, etc.)
//!    and merge it with **caller-supplied overrides** (the
//!    `PROP=VAL` tokens from a real msiexec command line, plus
//!    any analyst-staged values).
//! 2. Walk the `Directory` table top-down and resolve each
//!    directory's `DefaultDir` token against the property
//!    namespace, building an absolute path per directory entry.
//! 3. Walk the `Component → File` join and emit one
//!    [`InstallAction::WriteFile`] per file, with the resolved
//!    target path + the file's recorded size + the
//!    **decompressed bytes** pulled out of the MSI's embedded
//!    cab streams via the [`cab`](https://crates.io/crates/cab)
//!    crate (LZX / MSZIP). External (non-embedded) cabs would
//!    need the host VFS plumbed through; for those the action's
//!    `bytes` is `None` and the sink falls back to a zero-byte
//!    marker.
//! 4. Walk the `Registry` table and emit one
//!    [`InstallAction::RegSet`] per row, with the resolved key
//!    path + name + value, honouring `MsiFormatRecord`'s
//!    `[Property]` substitution.
//!
//! The walker is intentionally side-effect-free: every action
//! is pushed into the caller's [`InstallSink`] which decides
//! what to do with it. The CreateProcessA dispatch site in
//! `kernel32.rs` is what actually intercepts the install path
//! and feeds the bytes through here.

use std::collections::BTreeMap;
use std::io::Cursor;

use thiserror::Error;

/// Errors surfaced by [`process_msi`].
#[derive(Debug, Error)]
pub enum Error {
    /// The underlying `msi` crate couldn't open the MSI bytes
    /// (compound-document corruption, truncated payload, bad
    /// signature).
    #[error("MSI open: {0}")]
    Open(std::io::Error),
    /// A required table is missing or has the wrong shape.
    #[error("MSI schema: {0}")]
    Schema(String),
    /// A property reference (`[Foo]`) couldn't be resolved
    /// against the property namespace. Returned only when the
    /// caller's [`InstallOptions::strict_property_refs`] is
    /// set; the default mode leaves the placeholder in place
    /// and continues.
    #[error("unresolved property: [{0}]")]
    UnresolvedProperty(String),
}

/// One install effect the walker emits. The host's
/// [`InstallSink`] decides how to handle each variant
/// (synthesise into a VFS, log, override, skip).
#[derive(Debug, Clone)]
pub enum InstallAction {
    /// A `Directory` table entry resolved to a concrete path —
    /// emitted top-down so the sink can ensure each parent
    /// exists before files land in it. `id` is the
    /// `Directory.Directory` primary key (raw, useful for
    /// later actions that reference the entry by id).
    CreateDirectory {
        /// MSI directory id.
        id: String,
        /// Fully-resolved absolute path.
        path: String,
    },
    /// A `File` row resolved into a concrete target path. The
    /// walker locates the cab the file belongs to (via the
    /// `Media` table's sequence ranges) and includes the
    /// decompressed bytes when extraction succeeds. `bytes =
    /// None` signals "we couldn't unpack the cab" — the sink
    /// can fall back to a zero-byte marker.
    WriteFile {
        /// MSI file id (matches the cab entry name).
        id: String,
        /// Resolved absolute path.
        path: String,
        /// Expected file size in bytes (from the `File.FileSize`
        /// column).
        size: u64,
        /// Component id the file belongs to.
        component: String,
        /// Decompressed file bytes when the cab the file lives
        /// in could be opened + entry was found. `None` when
        /// the row referenced a cab we couldn't load.
        bytes: Option<Vec<u8>>,
    },
    /// One `Registry` row's resolved (root, key, name, value).
    RegSet {
        /// MSI registry id.
        id: String,
        /// MSI registry hive (`HKLM`, `HKCU`, `HKCR`, `HKU`,
        /// `HKEY_LOCAL_MACHINE`, …). Already canonicalised to
        /// the standard form.
        hive: RegHive,
        /// Subkey path (e.g. `Software\\Apple\\QuickTime`).
        key: String,
        /// Value name (`""` for default value).
        name: String,
        /// Value content, already property-expanded.
        value: RegValue,
        /// Component id the entry belongs to.
        component: String,
    },
    /// Property table snapshot — emitted before the
    /// directory/file/registry walk so the sink can record the
    /// effective property namespace for later inspection.
    SnapshotProperties(BTreeMap<String, String>),
    /// A diagnostic log line. The walker emits these for
    /// anything that wouldn't translate cleanly into one of
    /// the structured actions above (unresolved references,
    /// skipped tables, malformed rows).
    Log(String),
    /// A `CustomAction` table row's effective execution.
    /// Property-set / directory-set CAs (types 35, 50, 51) are
    /// executed inline by the walker; this variant surfaces
    /// the *DLL-call* + *EXE-call* + *script* shapes (types
    /// 1/17 DLL, 2/18 EXE, 5/6/21/22/25/26 scripts) for the
    /// sink to dispatch into a full execution sandbox.
    CustomAction {
        /// `CustomAction.Action` primary key.
        name: String,
        /// `CustomAction.Type` (bottom 6 bits are the action
        /// kind, high bits are flags — deferred / rollback /
        /// commit / no-impersonate).
        action_type: i32,
        /// `CustomAction.Source` — meaning depends on
        /// `action_type`: Binary-table key (DLL), File-table
        /// key (installed DLL), property name, etc.
        source: String,
        /// `CustomAction.Target` — meaning depends on
        /// `action_type`: function name (DLL), formatted
        /// string (set/error), command line (EXE).
        target: String,
        /// `Condition` column from `InstallExecuteSequence`
        /// (already evaluated true by the walker).
        condition: String,
    },
}

/// Windows registry hive root, in canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegHive {
    /// HKEY_CLASSES_ROOT
    ClassesRoot,
    /// HKEY_CURRENT_USER
    CurrentUser,
    /// HKEY_LOCAL_MACHINE
    LocalMachine,
    /// HKEY_USERS
    Users,
}

impl RegHive {
    /// Canonical short name (`HKLM`, `HKCU`, etc.) used by the
    /// virtual registry.
    #[must_use]
    pub fn short(self) -> &'static str {
        match self {
            RegHive::ClassesRoot => "HKCR",
            RegHive::CurrentUser => "HKCU",
            RegHive::LocalMachine => "HKLM",
            RegHive::Users => "HKU",
        }
    }

    /// Map an MSI `Registry.Root` column value to a hive. The
    /// MSI integer encoding is documented in MSDN's
    /// "Registry Table" page:
    ///
    /// * `-1` — HKLM if the install is per-machine, HKCU
    ///   otherwise. We pick HKLM (per-machine) since that's
    ///   the default for installers with no per-user opt-in.
    /// * `0` — HKCR
    /// * `1` — HKCU
    /// * `2` — HKLM
    /// * `3` — HKU
    #[must_use]
    pub fn from_msi_root(root: i32) -> RegHive {
        match root {
            0 => RegHive::ClassesRoot,
            1 => RegHive::CurrentUser,
            3 => RegHive::Users,
            // Per-machine (2) and the per-user/-machine
            // toggle (-1) both resolve to HKLM in our model.
            _ => RegHive::LocalMachine,
        }
    }
}

/// One typed registry value. Mirrors the small set of MSI
/// registry-value encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    /// Empty value (`Registry.Value` was NULL — common for
    /// "ensure key exists" rows).
    Empty,
    /// `REG_SZ` — plain string.
    Sz(String),
    /// `REG_EXPAND_SZ` — string with `%VAR%` placeholders the
    /// installer expects expanded at runtime. MSI signals this
    /// shape by prefixing the value with `#%`.
    ExpandSz(String),
    /// `REG_MULTI_SZ` — list of strings. MSI signals this by
    /// prefixing the value with `[~]` and separating entries
    /// with `[~]`.
    MultiSz(Vec<String>),
    /// `REG_DWORD` — 32-bit integer. MSI signals this by
    /// prefixing the value with `#`.
    Dword(u32),
    /// `REG_BINARY` — opaque bytes. MSI signals this by
    /// prefixing the value with `#x` and providing
    /// hex-encoded bytes.
    Binary(Vec<u8>),
}

/// Caller-driven configuration + per-action callback. Anything
/// that needs to alter the install plan — logging, redirecting
/// files, vetoing components, overriding property values for
/// reverse-engineering — lives behind this trait so the walker
/// stays pure.
pub trait InstallSink {
    /// Called for every emitted action. Returning `false`
    /// short-circuits the rest of the walk (the sink can
    /// abort a malformed install or stop early after capturing
    /// what it needs).
    fn emit(&mut self, action: InstallAction) -> bool;

    /// Override a property's effective value before the
    /// directory walk starts. Returning `Some` substitutes the
    /// value; returning `None` keeps the MSI-table default
    /// (which itself may have been preset by the caller via
    /// [`InstallOptions::properties`]).
    fn override_property(&mut self, _name: &str) -> Option<String> {
        None
    }

    /// Decide whether a component is installed. Default: yes.
    /// Returning `false` skips every `File` / `Registry` row
    /// scoped to that component.
    fn install_component(&mut self, _component: &str) -> bool {
        true
    }
}

/// Caller-driven options consumed by [`process_msi`].
#[derive(Debug, Default, Clone)]
pub struct InstallOptions {
    /// Property overrides supplied by the caller (typically
    /// parsed from a `msiexec /i <pkg> PROP=VAL …` command
    /// line). Merged on top of the MSI's `Property` table.
    pub properties: BTreeMap<String, String>,
    /// When `true`, an unresolved `[Property]` reference in a
    /// directory / registry value fails the walk with
    /// [`Error::UnresolvedProperty`]. Default `false` (leave
    /// the placeholder + emit a `Log` line instead).
    pub strict_property_refs: bool,
}

/// Top-level entry point: parse `msi_bytes`, walk the install,
/// and feed every effect into `sink`. Returns the snapshot of
/// the resolved property namespace on success.
pub fn process_msi(
    msi_bytes: &[u8],
    options: &InstallOptions,
    sink: &mut dyn InstallSink,
) -> Result<BTreeMap<String, String>, Error> {
    let cursor = Cursor::new(msi_bytes);
    let mut pkg = msi::Package::open(cursor).map_err(Error::Open)?;
    // ------------------------------------------------------------
    // Property table — load defaults, then apply caller overrides
    // and sink-time overrides.
    // ------------------------------------------------------------
    let mut properties: BTreeMap<String, String> = BTreeMap::new();
    if pkg.has_table("Property") {
        let rows = pkg
            .select_rows(msi::Select::table("Property"))
            .map_err(|e| Error::Schema(format!("Property select: {e}")))?;
        for row in rows {
            let name = row[0].as_str().unwrap_or("").to_string();
            let value = row[1].as_str().unwrap_or("").to_string();
            if !name.is_empty() {
                properties.insert(name, value);
            }
        }
    }
    for (k, v) in &options.properties {
        properties.insert(k.clone(), v.clone());
    }
    // Sink-time overrides last so they win.
    let names: Vec<String> = properties.keys().cloned().collect();
    for name in &names {
        if let Some(v) = sink.override_property(name) {
            properties.insert(name.clone(), v);
        }
    }
    // Seed a few canonical Windows-Installer properties when the
    // MSI didn't define them. Without these, the directory walk
    // would leave them as `[Property]` placeholders.
    seed_default_properties(&mut properties);

    // ------------------------------------------------------------
    // CustomAction + InstallExecuteSequence — run the
    // property-set / directory-set CAs (types 35, 50, 51) inline
    // BEFORE the file / registry walk so subsequent
    // `[Property]` substitutions see their effects. DLL / EXE
    // / script CAs are surfaced via `InstallAction::CustomAction`
    // for the sink to dispatch into a full execution sandbox.
    //
    // Sequence order matters: actions with negative `Sequence`
    // numbers and a NULL/empty condition are termination
    // actions; otherwise we run in ascending-sequence order.
    // Conditions are evaluated with a *very* simple expression
    // engine — see `eval_condition` — that handles the common
    // patterns in the Apple installers (negated property checks,
    // AND/OR chains, equality vs literal). Unknown / malformed
    // conditions are treated as TRUE so we err on running more
    // actions rather than fewer.
    // ------------------------------------------------------------
    let custom_actions = if pkg.has_table("CustomAction") {
        let rows = pkg
            .select_rows(msi::Select::table("CustomAction"))
            .map_err(|e| Error::Schema(format!("CustomAction select: {e}")))?;
        let mut m: BTreeMap<String, (i32, String, String)> = BTreeMap::new();
        for row in rows {
            let name = row[0].as_str().unwrap_or("").to_string();
            let ty = row[1].as_int().unwrap_or(0);
            let source = row[2].as_str().unwrap_or("").to_string();
            let target = row[3].as_str().unwrap_or("").to_string();
            if !name.is_empty() {
                m.insert(name, (ty, source, target));
            }
        }
        m
    } else {
        BTreeMap::new()
    };
    let mut sequence: Vec<(i32, String, String)> = Vec::new();
    if pkg.has_table("InstallExecuteSequence") {
        let rows = pkg
            .select_rows(msi::Select::table("InstallExecuteSequence"))
            .map_err(|e| Error::Schema(format!("InstallExecuteSequence select: {e}")))?;
        for row in rows {
            let name = row[0].as_str().unwrap_or("").to_string();
            let cond = row[1].as_str().unwrap_or("").to_string();
            let seq = row[2].as_int().unwrap_or(0);
            if !name.is_empty() {
                sequence.push((seq, name, cond));
            }
        }
        sequence.sort_by_key(|t| t.0);
    }
    for (seq, name, cond) in &sequence {
        if *seq <= 0 {
            continue; // termination action — skip in install walk
        }
        if !eval_condition(cond, &properties) {
            continue;
        }
        let Some((ty, source, target)) = custom_actions.get(name) else {
            continue; // standard MSI action — handled by the table walks below
        };
        let kind = (*ty) & 0x3F;
        match kind {
            // 51 = msidbCustomActionTypeTextData: property set
            // (Source = property name, Target = formatted value).
            51 => {
                let value = expand_properties(target, &properties, false)
                    .unwrap_or_else(|_| target.clone());
                properties.insert(source.clone(), value);
            }
            // 35 = msidbCustomActionTypeDirectorySet: same shape
            // as 51 but the assignment target is a Directory id.
            // We treat it identically (the directory walk later
            // honours Property-namespace overrides).
            35 => {
                let value = expand_properties(target, &properties, false)
                    .unwrap_or_else(|_| target.clone());
                properties.insert(source.clone(), value);
            }
            // DLL / EXE / script CAs go to the sink.
            1 | 2 | 17 | 18 | 5 | 6 | 21 | 22 | 25 | 26 => {
                if !sink.emit(InstallAction::CustomAction {
                    name: name.clone(),
                    action_type: *ty,
                    source: source.clone(),
                    target: target.clone(),
                    condition: cond.clone(),
                }) {
                    return Ok(properties);
                }
            }
            _ => {
                // Unknown / unsupported (e.g. 19 = error,
                // 23 = nested install, 37 = nested dir).
                // Log and continue.
                if !sink.emit(InstallAction::Log(format!(
                    "CA {name:?}: unsupported action type {ty} ({kind:#x})"
                ))) {
                    return Ok(properties);
                }
            }
        }
    }

    if !sink.emit(InstallAction::SnapshotProperties(properties.clone())) {
        return Ok(properties);
    }

    // ------------------------------------------------------------
    // Directory table — top-down resolve.
    // ------------------------------------------------------------
    let dir_rows = if pkg.has_table("Directory") {
        pkg.select_rows(msi::Select::table("Directory"))
            .map_err(|e| Error::Schema(format!("Directory select: {e}")))?
    } else {
        return Ok(properties);
    };
    let mut dir_parent: BTreeMap<String, String> = BTreeMap::new();
    let mut dir_default: BTreeMap<String, String> = BTreeMap::new();
    for row in dir_rows {
        let id = row[0].as_str().unwrap_or("").to_string();
        let parent = row[1].as_str().unwrap_or("").to_string();
        let default = row[2].as_str().unwrap_or("").to_string();
        if id.is_empty() {
            continue;
        }
        dir_parent.insert(id.clone(), parent);
        dir_default.insert(id, default);
    }
    let mut resolved_dirs: BTreeMap<String, String> = BTreeMap::new();
    let dir_ids: Vec<String> = dir_parent.keys().cloned().collect();
    for id in &dir_ids {
        let path = resolve_dir(
            id,
            &dir_parent,
            &dir_default,
            &properties,
            &mut resolved_dirs,
            options.strict_property_refs,
        )?;
        if !sink.emit(InstallAction::CreateDirectory {
            id: id.clone(),
            path,
        }) {
            return Ok(properties);
        }
    }
    // Inject resolved directory ids into the property namespace
    // so registry / file `[DirId]` references substitute the
    // same way real MSI does. Real Windows-Installer puts
    // properties + directory ids + component states + feature
    // states all into one formatting namespace; we only need
    // directories to unblock the QT case (registry references
    // `[QuickTimeComponentsFolder]` etc.).
    for (id, path) in &resolved_dirs {
        // Don't clobber an explicit Property-table value with
        // the same name — that would override a CA's prior
        // property set.
        properties.entry(id.clone()).or_insert_with(|| path.clone());
    }

    // ------------------------------------------------------------
    // Component table — needed to gate File / Registry rows on
    // the sink's per-component opt-in and to map a File row to
    // its containing directory.
    // ------------------------------------------------------------
    let mut component_dir: BTreeMap<String, String> = BTreeMap::new();
    if pkg.has_table("Component") {
        let rows = pkg
            .select_rows(msi::Select::table("Component"))
            .map_err(|e| Error::Schema(format!("Component select: {e}")))?;
        for row in rows {
            let id = row[0].as_str().unwrap_or("").to_string();
            // Component column layout: Component, ComponentId, Directory_, …
            let dir = row[2].as_str().unwrap_or("").to_string();
            if !id.is_empty() {
                component_dir.insert(id, dir);
            }
        }
    }

    // ------------------------------------------------------------
    // CAB extraction — load every cab the Media table mentions
    // so the File-row walk can read each file's actual bytes.
    // `media` is sorted by LastSequence so we can binary-search
    // a File.Sequence into its containing cab.
    // ------------------------------------------------------------
    let mut media: Vec<(i32, String)> = Vec::new();
    if pkg.has_table("Media") {
        let rows = pkg
            .select_rows(msi::Select::table("Media"))
            .map_err(|e| Error::Schema(format!("Media select: {e}")))?;
        for row in rows {
            let last_sequence = row[1].as_int().unwrap_or(0);
            let cabinet = row[3].as_str().unwrap_or("").to_string();
            if !cabinet.is_empty() {
                media.push((last_sequence, cabinet));
            }
        }
    }
    media.sort_by_key(|(seq, _)| *seq);
    // Open each referenced cab once. Embedded streams use the
    // `#name` form (per MSI convention); external files would
    // need to be looked up in the host VFS — we report Log()
    // on the unsupported external case and treat as a missing
    // cab for the affected files.
    let mut cab_handles: BTreeMap<String, CabHandle> = BTreeMap::new();
    for (_, cab_name) in &media {
        if cab_handles.contains_key(cab_name) {
            continue;
        }
        if let Some(stream_name) = cab_name.strip_prefix('#') {
            match pkg.read_stream(stream_name) {
                Ok(mut reader) => {
                    let mut buf = Vec::new();
                    if std::io::Read::read_to_end(&mut reader, &mut buf).is_ok() {
                        match cab::Cabinet::new(Cursor::new(buf)) {
                            Ok(cab) => {
                                cab_handles.insert(cab_name.clone(), CabHandle::Loaded(cab));
                            }
                            Err(e) => {
                                if !sink
                                    .emit(InstallAction::Log(format!("cab open {cab_name}: {e}")))
                                {
                                    return Ok(properties);
                                }
                                cab_handles.insert(cab_name.clone(), CabHandle::Missing);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !sink.emit(InstallAction::Log(format!("msi stream {stream_name}: {e}"))) {
                        return Ok(properties);
                    }
                    cab_handles.insert(cab_name.clone(), CabHandle::Missing);
                }
            }
        } else {
            // External cab (separate file on the install
            // media). The MSI ships these alongside; we don't
            // currently route the host VFS into the walker so
            // these come up as `Missing`.
            if !sink.emit(InstallAction::Log(format!(
                "external cab {cab_name} not supported; file bytes will be missing"
            ))) {
                return Ok(properties);
            }
            cab_handles.insert(cab_name.clone(), CabHandle::Missing);
        }
    }

    // ------------------------------------------------------------
    // File table — emit one WriteFile per row, gated by the
    // sink's per-component decision. When the file lives in a
    // loaded cab, decompressed bytes are attached.
    // ------------------------------------------------------------
    if pkg.has_table("File") {
        let rows = pkg
            .select_rows(msi::Select::table("File"))
            .map_err(|e| Error::Schema(format!("File select: {e}")))?;
        for row in rows {
            let id = row[0].as_str().unwrap_or("").to_string();
            let component = row[1].as_str().unwrap_or("").to_string();
            // File.FileName is "ShortName|LongName" or just the
            // long name; pick the long form when present.
            let file_name = pick_long_filename(row[2].as_str().unwrap_or(""));
            let size = row[3].as_int().unwrap_or(0).max(0) as u64;
            // File.Sequence — column 7, used to pick the cab.
            let sequence = row[7].as_int().unwrap_or(0);
            if component.is_empty() || !sink.install_component(&component) {
                continue;
            }
            let dir_id = component_dir.get(&component).cloned().unwrap_or_default();
            let dir_path = resolved_dirs.get(&dir_id).cloned().unwrap_or_default();
            let path = join_path(&dir_path, &file_name);
            let bytes = extract_file_bytes(&media, &mut cab_handles, sequence, &id);
            if !sink.emit(InstallAction::WriteFile {
                id,
                path,
                size,
                component,
                bytes,
            }) {
                return Ok(properties);
            }
        }
    }

    // ------------------------------------------------------------
    // Registry table — emit one RegSet per row.
    // ------------------------------------------------------------
    if pkg.has_table("Registry") {
        let rows = pkg
            .select_rows(msi::Select::table("Registry"))
            .map_err(|e| Error::Schema(format!("Registry select: {e}")))?;
        for row in rows {
            let id = row[0].as_str().unwrap_or("").to_string();
            let root = row[1].as_int().unwrap_or(2);
            let key_raw = row[2].as_str().unwrap_or("").to_string();
            let name_raw = row[3].as_str().unwrap_or("").to_string();
            let value_raw = row[4].as_str().unwrap_or("").to_string();
            let component = row[5].as_str().unwrap_or("").to_string();
            if component.is_empty() || !sink.install_component(&component) {
                continue;
            }
            let key = expand_properties(&key_raw, &properties, options.strict_property_refs)?;
            let name = expand_properties(&name_raw, &properties, options.strict_property_refs)?;
            let value_expanded =
                expand_properties(&value_raw, &properties, options.strict_property_refs)?;
            let value = parse_reg_value(&value_expanded);
            if !sink.emit(InstallAction::RegSet {
                id,
                hive: RegHive::from_msi_root(root),
                key,
                name,
                value,
                component,
            }) {
                return Ok(properties);
            }
        }
    }
    Ok(properties)
}

/// Seed the canonical Windows-Installer properties the
/// emulator needs when the MSI didn't define them itself. We
/// give every "well-known folder" property a sensible default
/// rooted at `C:\`.
fn seed_default_properties(props: &mut BTreeMap<String, String>) {
    let defaults: &[(&str, &str)] = &[
        // Root-directory aliases. MSI's Directory table is
        // typically rooted at `TARGETDIR` (the user's chosen
        // install target) or `SourceDir` (the source-media
        // root); we treat both as the root of the virtual
        // filesystem so resolved paths come out as plain
        // `C:\Program Files\...` rather than `SourceDir\...`.
        ("TARGETDIR", "C:\\"),
        ("SourceDir", "C:\\"),
        ("ProgramFilesFolder", "C:\\Program Files"),
        ("ProgramFiles64Folder", "C:\\Program Files"),
        ("CommonFilesFolder", "C:\\Program Files\\Common Files"),
        ("CommonFiles64Folder", "C:\\Program Files\\Common Files"),
        ("WindowsFolder", "C:\\Windows"),
        ("System64Folder", "C:\\Windows\\System32"),
        ("SystemFolder", "C:\\Windows\\System32"),
        ("System16Folder", "C:\\Windows\\System"),
        ("WindowsVolume", "C:\\"),
        ("AppDataFolder", "C:\\Users\\Default\\AppData\\Roaming"),
        ("LocalAppDataFolder", "C:\\Users\\Default\\AppData\\Local"),
        ("DesktopFolder", "C:\\Users\\Public\\Desktop"),
        (
            "StartMenuFolder",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu",
        ),
        (
            "ProgramMenuFolder",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs",
        ),
        ("TempFolder", "C:\\Temp"),
        ("PersonalFolder", "C:\\Users\\Public\\Documents"),
        ("UserProfile", "C:\\Users\\Default"),
        ("ComputerName", "OXIDEAV"),
        ("USERNAME", "Default"),
        ("VersionNT", "603"),
        ("VersionNT64", "603"),
        ("Privileged", "1"),
    ];
    for (name, value) in defaults {
        props
            .entry((*name).into())
            .or_insert_with(|| (*value).into());
    }
}

/// Walk the parent chain for `id`, resolving each `DefaultDir`
/// token against the property namespace. Caches via
/// `resolved`. Roots (parent empty or `TARGETDIR`) terminate
/// Evaluate a tiny subset of the Windows-Installer condition
/// expression language. The full grammar is fairly involved
/// (CONDITION = expression ; expression = symbol | term | ...
/// — see the MSI SDK), but the Apple QT installer uses a small
/// vocabulary:
///
///   * `Installed` / `NOT Installed`
///   * `PROP=value` / `PROP<>value` / `PROP="value"`
///   * `PROP` (truthy if set + non-empty)
///   * `NOT PROP`
///   * `expr AND expr` / `expr OR expr`
///   * `(expr)`
///   * Feature operators (`$X=2`, `?X>2`) — treated as TRUE so
///     feature-state-gated actions don't get suppressed.
///
/// Unknown / malformed conditions return TRUE so we err toward
/// running more actions. This is a *very* permissive evaluator;
/// it is NOT a substitute for the real expression engine.
fn eval_condition(cond: &str, props: &BTreeMap<String, String>) -> bool {
    let s = cond.trim();
    if s.is_empty() {
        return true;
    }
    // OR has the lowest precedence.
    if let Some((l, r)) = split_top_level(s, " OR ") {
        return eval_condition(l, props) || eval_condition(r, props);
    }
    if let Some((l, r)) = split_top_level(s, " AND ") {
        return eval_condition(l, props) && eval_condition(r, props);
    }
    // Parenthesised group.
    if s.starts_with('(') && s.ends_with(')') {
        return eval_condition(&s[1..s.len() - 1], props);
    }
    // NOT.
    if let Some(rest) = s.strip_prefix("NOT ") {
        return !eval_condition(rest, props);
    }
    // Feature / Component state operators ($Foo, ?Foo, &Foo, !Foo) —
    // treat as TRUE since we don't model feature state.
    if matches!(s.chars().next(), Some('$' | '?' | '&' | '!')) {
        return true;
    }
    // PROP=value / PROP<>value / PROP="value"
    for (op, expect_eq) in [("<>", false), ("=", true)] {
        if let Some((lhs, rhs)) = s.split_once(op) {
            let l = lookup(lhs.trim(), props);
            let r = lookup_or_literal(rhs.trim(), props);
            let eq = l.eq_ignore_ascii_case(&r);
            return if expect_eq { eq } else { !eq };
        }
    }
    // Bare property name — truthy if set + non-empty.
    !lookup(s, props).is_empty()
}

/// Split `s` at the first top-level (not inside parens or quotes)
/// occurrence of `sep`.
fn split_top_level<'a>(s: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    let mut depth: i32 = 0;
    let mut in_quote = false;
    let bytes = s.as_bytes();
    let sep_bytes = sep.as_bytes();
    let mut i = 0;
    while i + sep_bytes.len() <= bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            in_quote = !in_quote;
        } else if !in_quote {
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth = depth.saturating_sub(1);
            } else if depth == 0 && bytes[i..i + sep_bytes.len()] == *sep_bytes {
                return Some((&s[..i], &s[i + sep_bytes.len()..]));
            }
        }
        i += 1;
    }
    None
}

fn lookup(name: &str, props: &BTreeMap<String, String>) -> String {
    props.get(name).cloned().unwrap_or_default()
}

fn lookup_or_literal(s: &str, props: &BTreeMap<String, String>) -> String {
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return s[1..s.len() - 1].to_string();
    }
    // Numeric literal stays as-is; otherwise treat as property lookup if defined.
    if s.chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c == '+')
    {
        return s.to_string();
    }
    if let Some(v) = props.get(s) {
        return v.clone();
    }
    s.to_string()
}

/// the walk; the `TARGETDIR` default `[ProgramFilesFolder]\…`
/// is resolved through the property namespace.
fn resolve_dir(
    id: &str,
    parents: &BTreeMap<String, String>,
    defaults: &BTreeMap<String, String>,
    properties: &BTreeMap<String, String>,
    resolved: &mut BTreeMap<String, String>,
    strict: bool,
) -> Result<String, Error> {
    if let Some(p) = resolved.get(id) {
        return Ok(p.clone());
    }
    let parent = parents.get(id).cloned().unwrap_or_default();
    let default = defaults.get(id).cloned().unwrap_or_default();
    let mut segment = parse_default_dir(&default);
    segment = expand_properties(&segment, properties, strict)?;
    let absolute = if parent.is_empty() || parent == id {
        // Root. If a property of the same name exists (e.g.
        // ProgramFilesFolder), use it as the absolute base.
        if let Some(v) = properties.get(id) {
            v.clone()
        } else {
            segment
        }
    } else {
        let parent_path = resolve_dir(&parent, parents, defaults, properties, resolved, strict)?;
        join_path(&parent_path, &segment)
    };
    resolved.insert(id.to_string(), absolute.clone());
    Ok(absolute)
}

/// `Directory.DefaultDir` is `[short|]long[:short_src|long_src]`
/// — we want the long target form (before `:`). `.` is the
/// "this directory" sentinel (e.g. `INSTALLDIR` rows often have
/// `DefaultDir = "."`); empty in that case.
fn parse_default_dir(s: &str) -> String {
    let before_colon = s.split(':').next().unwrap_or("");
    let long = before_colon.split('|').next_back().unwrap_or(before_colon);
    if long == "." {
        String::new()
    } else {
        long.to_string()
    }
}

fn pick_long_filename(s: &str) -> String {
    let long = s.split('|').next_back().unwrap_or(s);
    long.to_string()
}

fn join_path(parent: &str, child: &str) -> String {
    if child.is_empty() {
        return parent.to_string();
    }
    if parent.is_empty() {
        return child.to_string();
    }
    let parent_trim = parent.trim_end_matches('\\').trim_end_matches('/');
    format!("{parent_trim}\\{child}")
}

/// Expand `[Property]` references in `s` using `props`. Bare
/// `[X]` becomes the property's value; nested expansion is
/// resolved iteratively up to a small bound. Bracket-prefixed
/// formatting tokens we don't model (`[\$]`, `[~]`, `[\\]`, …)
/// pass through unchanged.
fn expand_properties(
    s: &str,
    props: &BTreeMap<String, String>,
    strict: bool,
) -> Result<String, Error> {
    if !s.contains('[') {
        return Ok(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(close) = s[i + 1..].find(']') {
                let inside = &s[i + 1..i + 1 + close];
                // The MSI formatter has several special prefixes
                // (e.g. `[~]` multi-sz separator, `[\\]` literal
                // backslash). Leave anything starting with `~`,
                // `\\`, `!`, `#`, `$`, `%` untouched.
                let first = inside.chars().next().unwrap_or(' ');
                if matches!(first, '~' | '\\' | '!' | '#' | '$' | '%') {
                    out.push('[');
                    out.push_str(inside);
                    out.push(']');
                } else if let Some(v) = props.get(inside) {
                    out.push_str(v);
                } else if strict {
                    return Err(Error::UnresolvedProperty(inside.to_string()));
                } else {
                    // Leave the unresolved reference in place
                    // (Win32 paths sometimes embed bracketed
                    // text in normal filenames).
                    out.push('[');
                    out.push_str(inside);
                    out.push(']');
                }
                i = i + 1 + close + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    // One more pass to catch references whose value itself
    // contained `[Property]`. Bound the chain to avoid cycles.
    let mut chained = out;
    for _ in 0..8 {
        if !chained.contains('[') {
            break;
        }
        let next = expand_once(&chained, props, strict)?;
        if next == chained {
            break;
        }
        chained = next;
    }
    Ok(chained)
}

fn expand_once(s: &str, props: &BTreeMap<String, String>, strict: bool) -> Result<String, Error> {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut changed = false;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(close) = s[i + 1..].find(']') {
                let inside = &s[i + 1..i + 1 + close];
                let first = inside.chars().next().unwrap_or(' ');
                if !matches!(first, '~' | '\\' | '!' | '#' | '$' | '%') {
                    if let Some(v) = props.get(inside) {
                        out.push_str(v);
                        i = i + 1 + close + 1;
                        changed = true;
                        continue;
                    } else if strict {
                        return Err(Error::UnresolvedProperty(inside.to_string()));
                    }
                }
                out.push('[');
                out.push_str(inside);
                out.push(']');
                i = i + 1 + close + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    if changed {
        Ok(out)
    } else {
        Ok(s.to_string())
    }
}

/// Parse one MSI registry value-string into a typed
/// [`RegValue`]. The MSI encoding (per MSDN's "Registry Table"
/// page) uses leading sentinels to distinguish types:
///
/// * `#%…` — REG_EXPAND_SZ (rest is the string)
/// * `#x…` — REG_BINARY (rest is hex-encoded bytes)
/// * `#…`  — REG_DWORD (rest is decimal int)
/// * `[~]a[~]b[~]` — REG_MULTI_SZ
/// * anything else (or empty) — REG_SZ / Empty
fn parse_reg_value(s: &str) -> RegValue {
    if s.is_empty() {
        return RegValue::Empty;
    }
    if let Some(rest) = s.strip_prefix("#%") {
        return RegValue::ExpandSz(rest.to_string());
    }
    if let Some(rest) = s.strip_prefix("#x") {
        let mut bytes = Vec::with_capacity(rest.len() / 2);
        let chars: Vec<char> = rest.chars().collect();
        let mut i = 0;
        while i + 1 < chars.len() {
            let hi = chars[i].to_digit(16).unwrap_or(0) as u8;
            let lo = chars[i + 1].to_digit(16).unwrap_or(0) as u8;
            bytes.push(hi << 4 | lo);
            i += 2;
        }
        return RegValue::Binary(bytes);
    }
    if let Some(rest) = s.strip_prefix('#') {
        let n: i64 = rest.parse().unwrap_or(0);
        return RegValue::Dword(n as u32);
    }
    if s.contains("[~]") {
        let parts: Vec<String> = s
            .split("[~]")
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect();
        return RegValue::MultiSz(parts);
    }
    RegValue::Sz(s.to_string())
}

/// One opened cab. Loaded variants hold the decompressor
/// state needed by `Cabinet::read_file`; Missing means we
/// couldn't open this cab (embedded stream wasn't readable,
/// or an external cab the walker doesn't know how to fetch).
enum CabHandle {
    Loaded(cab::Cabinet<Cursor<Vec<u8>>>),
    Missing,
}

/// Find the cab containing the file at `sequence` and read
/// the entry named `file_id`. Returns `None` when the file
/// isn't found in any loaded cab (cab missing, sequence out
/// of every Media row's range, or the cab entry was skipped
/// during compression).
fn extract_file_bytes(
    media: &[(i32, String)],
    cabs: &mut BTreeMap<String, CabHandle>,
    sequence: i32,
    file_id: &str,
) -> Option<Vec<u8>> {
    let cab_name = media
        .iter()
        .find(|(last, _)| *last >= sequence)
        .map(|(_, name)| name.clone())
        // Fall back to the first cab if the sequence is past
        // every recorded LastSequence — defensive against
        // malformed Media rows.
        .or_else(|| media.first().map(|(_, n)| n.clone()))?;
    let handle = cabs.get_mut(&cab_name)?;
    let cab = match handle {
        CabHandle::Loaded(c) => c,
        CabHandle::Missing => return None,
    };
    let mut reader = cab.read_file(file_id).ok()?;
    let mut buf = Vec::new();
    if std::io::Read::read_to_end(&mut reader, &mut buf).is_err() {
        return None;
    }
    Some(buf)
}

/// Default sink that records every action into a `Vec` for the
/// caller to inspect — useful for tests and the
/// `msiexec --report` style CLI flag.
#[derive(Debug, Default)]
pub struct RecordingSink {
    /// Every emitted action in walk order.
    pub actions: Vec<InstallAction>,
}

impl InstallSink for RecordingSink {
    fn emit(&mut self, action: InstallAction) -> bool {
        self.actions.push(action);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_dir_picks_long_target() {
        assert_eq!(parse_default_dir("DOC|Documents"), "Documents");
        assert_eq!(parse_default_dir("DOC|Documents:SRC|Source"), "Documents");
        assert_eq!(parse_default_dir("SourceDir"), "SourceDir");
        assert_eq!(parse_default_dir("."), "");
    }

    #[test]
    fn expand_properties_substitutes_known() {
        let mut props = BTreeMap::new();
        props.insert("ProgramFilesFolder".into(), "C:\\Program Files".into());
        props.insert("Manufacturer".into(), "Apple".into());
        let s = "[ProgramFilesFolder]\\[Manufacturer]\\Foo";
        assert_eq!(
            expand_properties(s, &props, false).unwrap(),
            "C:\\Program Files\\Apple\\Foo"
        );
    }

    #[test]
    fn expand_properties_leaves_unknown_in_lenient_mode() {
        let props = BTreeMap::new();
        let s = "[Bogus]\\file";
        assert_eq!(
            expand_properties(s, &props, false).unwrap(),
            "[Bogus]\\file"
        );
        assert!(matches!(
            expand_properties(s, &props, true).unwrap_err(),
            Error::UnresolvedProperty(_)
        ));
    }

    #[test]
    fn parse_reg_value_decodes_each_sigil() {
        assert!(matches!(parse_reg_value(""), RegValue::Empty));
        assert!(matches!(parse_reg_value("hello"), RegValue::Sz(ref s) if s == "hello"));
        assert!(matches!(parse_reg_value("#42"), RegValue::Dword(42)));
        assert!(matches!(parse_reg_value("#%path"), RegValue::ExpandSz(ref s) if s == "path"));
        let RegValue::Binary(b) = parse_reg_value("#xDEADBEEF") else {
            panic!("expected binary");
        };
        assert_eq!(b, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let RegValue::MultiSz(v) = parse_reg_value("[~]a[~]b[~]") else {
            panic!("expected multi-sz");
        };
        assert_eq!(v, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn reg_hive_from_msi_root_maps_canonical() {
        assert_eq!(RegHive::from_msi_root(0), RegHive::ClassesRoot);
        assert_eq!(RegHive::from_msi_root(1), RegHive::CurrentUser);
        assert_eq!(RegHive::from_msi_root(2), RegHive::LocalMachine);
        assert_eq!(RegHive::from_msi_root(3), RegHive::Users);
        assert_eq!(RegHive::from_msi_root(-1), RegHive::LocalMachine);
    }

    #[test]
    fn parse_command_line_extracts_install_path() {
        let (op, props) =
            parse_msiexec_args("\"C:\\WINDOWS\\System32\\msiexec.exe\" /i \"C:\\foo\\bar.msi\" /quiet PROP=VAL OTHER=1");
        assert_eq!(op, Some(MsiexecOp::Install("C:\\foo\\bar.msi".into())));
        assert_eq!(props.get("PROP").map(String::as_str), Some("VAL"));
        assert_eq!(props.get("OTHER").map(String::as_str), Some("1"));
    }

    #[test]
    fn is_msiexec_target_recognises_canonical_paths() {
        assert!(is_msiexec_target("C:\\Windows\\System32\\msiexec.exe"));
        assert!(is_msiexec_target("C:\\WINDOWS\\System32\\MSIEXEC.EXE"));
        assert!(is_msiexec_target("msiexec.exe"));
        assert!(is_msiexec_target("/usr/share/wine/msiexec"));
        assert!(!is_msiexec_target("C:\\foo\\setup.exe"));
    }
}

// ============================================================
// Emulator integration — sites kernel32::stub_create_process_a
// calls into when the spawned target is msiexec.exe.
// ============================================================

/// True iff `target` names msiexec — either the canonical
/// `C:\Windows\System32\msiexec.exe` (any case / path
/// separator) or bare `msiexec[.exe]`.
#[must_use]
pub fn is_msiexec_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase().replace('\\', "/");
    let tail = lower.rsplit('/').next().unwrap_or(&lower);
    tail == "msiexec.exe" || tail == "msiexec"
}

/// One parsed msiexec operation. We only model the install /
/// uninstall verbs; everything else falls through as `Unknown`
/// so the caller still logs the attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsiexecOp {
    /// `/i <path>` — install the named MSI.
    Install(String),
    /// `/x <path>` — uninstall the named MSI (or product code).
    Uninstall(String),
}

/// Lex a real msiexec command line: the leading token is the
/// executable (ignored), then `/i <path>` or `/x <path>` picks
/// the verb, and the remaining `KEY=VAL` tokens populate the
/// MSI property namespace overrides. Whitespace inside quotes
/// is preserved.
pub fn parse_msiexec_args(cmd: &str) -> (Option<MsiexecOp>, BTreeMap<String, String>) {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in cmd.chars() {
        match ch {
            '"' => in_quote = !in_quote,
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    let mut iter = tokens.into_iter().peekable();
    // Drop the leading exe-path token if any.
    if let Some(first) = iter.peek() {
        if first.to_ascii_lowercase().contains("msiexec") {
            iter.next();
        }
    }
    let mut op = None;
    let mut props = BTreeMap::new();
    while let Some(tok) = iter.next() {
        let lower = tok.to_ascii_lowercase();
        match lower.as_str() {
            "/i" | "-i" => {
                if let Some(path) = iter.next() {
                    op = Some(MsiexecOp::Install(path));
                }
            }
            "/x" | "-x" => {
                if let Some(path) = iter.next() {
                    op = Some(MsiexecOp::Uninstall(path));
                }
            }
            _ if tok.contains('=') => {
                if let Some((k, v)) = tok.split_once('=') {
                    props.insert(k.to_string(), v.to_string());
                }
            }
            // Silent / passive switches are flags we don't model
            // (the install always proceeds non-interactively).
            _ => {}
        }
    }
    (op, props)
}

/// Sink that materialises the install effects into the
/// emulator's [`crate::context::VirtualFs`] and
/// [`crate::context::VirtualRegistry`] and records every
/// action in the host's `debug_log` for analyst visibility.
struct EmulatorInstallSink<'a> {
    /// VFS the install writes resolved file paths into. Files
    /// are created as zero-byte markers (we don't unpack the
    /// CAB streams the MSI references); the path is what
    /// matters for "what would be installed" intel.
    vfs: Option<&'a mut crate::context::VirtualFs>,
    /// Virtual registry the install writes resolved keys into.
    registry: Option<&'a mut crate::context::VirtualRegistry>,
    /// Per-action chatter — flushed back into the host's
    /// debug_log by the dispatch site.
    log: Vec<String>,
    /// Action counts so the dispatch site can log a one-line
    /// summary in addition to the per-action detail.
    n_dirs: usize,
    n_files: usize,
    n_regs: usize,
    /// Sum of `File.FileSize` columns — what the install
    /// would write if every CAB extraction succeeded.
    n_bytes: u64,
    /// Sum of actually-extracted decompressed bytes. Equals
    /// `n_bytes` when every cab entry decompressed cleanly;
    /// smaller when some entries fell back to zero-byte
    /// markers.
    n_real_bytes: u64,
}

impl InstallSink for EmulatorInstallSink<'_> {
    fn emit(&mut self, action: InstallAction) -> bool {
        match action {
            InstallAction::CreateDirectory { path, .. } => {
                self.n_dirs += 1;
                if let Some(vfs) = self.vfs.as_mut() {
                    let marker = format!("{}\\.dir", path.trim_end_matches(['\\', '/']));
                    if !vfs.contains(&marker) {
                        vfs.insert(&marker, Vec::new());
                    }
                }
            }
            InstallAction::WriteFile {
                path, size, bytes, ..
            } => {
                self.n_files += 1;
                self.n_bytes = self.n_bytes.saturating_add(size);
                if let Some(vfs) = self.vfs.as_mut() {
                    // Real decompressed bytes when the walker
                    // could pull them from the cab; zero-byte
                    // marker otherwise so the path still
                    // surfaces in the install report.
                    let payload = bytes.unwrap_or_default();
                    if !payload.is_empty() {
                        self.n_real_bytes = self.n_real_bytes.saturating_add(payload.len() as u64);
                    }
                    vfs.write_path(&path, payload);
                }
            }
            InstallAction::RegSet {
                hive,
                key,
                name,
                value,
                ..
            } => {
                self.n_regs += 1;
                if let Some(reg) = self.registry.as_mut() {
                    let key_path = format!("{}\\{}", hive.short(), key);
                    let v = match value {
                        RegValue::Empty => crate::context::RegistryValue::Sz(String::new()),
                        RegValue::Sz(s) => crate::context::RegistryValue::Sz(s),
                        RegValue::ExpandSz(s) => crate::context::RegistryValue::ExpandSz(s),
                        RegValue::Dword(d) => crate::context::RegistryValue::Dword(d),
                        RegValue::Binary(b) => crate::context::RegistryValue::Binary(b),
                        RegValue::MultiSz(v) => crate::context::RegistryValue::MultiSz(v),
                    };
                    reg.set_value(&key_path, &name, v);
                }
            }
            InstallAction::SnapshotProperties(props) => {
                self.log.push(format!(
                    "msiexec: property snapshot ({} entries)",
                    props.len()
                ));
            }
            InstallAction::Log(line) => {
                self.log.push(format!("msiexec: {line}"));
            }
            InstallAction::CustomAction {
                name,
                action_type,
                source,
                target,
                ..
            } => {
                self.log.push(format!(
                    "msiexec: skipped CA {name:?} type={action_type:#x} src={source:?} tgt={target:?}"
                ));
            }
        }
        true
    }
}

/// Walk `target_msi` (resolved against the VFS) and apply
/// every install action — file create, registry set — into
/// the emulator's context. Writes a one-line summary to the
/// host's `debug_log` on completion; per-action detail is
/// available through the sink's accumulator.
///
/// The dispatch is best-effort: a missing MSI, an unparsable
/// MSI, or an unsupported install verb is logged and ignored
/// (the caller's `CreateProcessA` still returns the synthetic
/// success child so the parent's wait + exit-code flow
/// proceeds).
pub fn dispatch_msiexec_install(
    state: &mut crate::win32::HostState,
    _mmu: &mut crate::emulator::Mmu,
    target: &str,
    cmdline: &str,
) {
    let (op, mut props) = parse_msiexec_args(cmdline);
    let Some(verb) = op else {
        state.debug_log.push(format!(
            "msiexec({target:?}): no install/uninstall verb in cmdline {cmdline:?}"
        ));
        return;
    };
    let msi_path = match &verb {
        MsiexecOp::Install(p) => p.clone(),
        MsiexecOp::Uninstall(p) => {
            state
                .debug_log
                .push(format!("msiexec /x {p:?} — uninstall is a no-op for now"));
            return;
        }
    };
    // Resolve the MSI path against the VFS. We try the literal
    // path first and a couple of normalised forms (case-folded,
    // backslash → forward slash) before giving up.
    let bytes = lookup_msi_bytes(&state.context, &msi_path);
    let Some(bytes) = bytes else {
        state.debug_log.push(format!(
            "msiexec /i {msi_path:?} — MSI not in VFS, install skipped"
        ));
        return;
    };
    let options = InstallOptions {
        properties: std::mem::take(&mut props),
        ..Default::default()
    };
    // SAFETY of borrow-juggling: take the VFS + registry out of
    // `state.context` so we can hand them to the sink as
    // independent &mut, then put them back.
    let mut vfs = state.context.vfs.take();
    let mut reg = state.context.registry.take();
    let mut sink = EmulatorInstallSink {
        vfs: vfs.as_mut(),
        registry: reg.as_mut(),
        log: Vec::new(),
        n_dirs: 0,
        n_files: 0,
        n_regs: 0,
        n_bytes: 0,
        n_real_bytes: 0,
    };
    let result = process_msi(&bytes, &options, &mut sink);
    let dirs = sink.n_dirs;
    let files = sink.n_files;
    let regs = sink.n_regs;
    let bytes_total = sink.n_bytes;
    let real_bytes = sink.n_real_bytes;
    for line in sink.log {
        state.debug_log.push(line);
    }
    state.context.vfs = vfs;
    state.context.registry = reg;
    match result {
        Ok(_) => state.debug_log.push(format!(
            "msiexec /i {msi_path:?} — synthesised {files} files ({real_bytes}/{bytes_total} bytes extracted), {dirs} directories, {regs} registry entries"
        )),
        Err(e) => state
            .debug_log
            .push(format!("msiexec /i {msi_path:?} — walk failed: {e}")),
    }
}

/// Look the MSI bytes up in the VFS. Tries a few path
/// variations so a relative-vs-absolute mismatch between the
/// installer's CreateProcessA arg and how the file was
/// staged into the VFS doesn't fail the lookup.
fn lookup_msi_bytes(ctx: &crate::context::Context, path: &str) -> Option<Vec<u8>> {
    let vfs = ctx.vfs.as_ref()?;
    if let Some(b) = vfs.read(path) {
        return Some(b.to_vec());
    }
    // Try without the "C:\" prefix if any.
    let stripped = path
        .trim_start_matches("C:\\")
        .trim_start_matches("c:\\")
        .trim_start_matches("C:/")
        .trim_start_matches("c:/");
    if stripped != path {
        if let Some(b) = vfs.read(stripped) {
            return Some(b.to_vec());
        }
    }
    // Last resort: walk the VFS list looking for a file with
    // the same basename. Useful when the installer passes
    // `IXP051.TMP\QuickTime.msi` (relative + uppercased) but
    // the VFS stored `ixp051.tmp/quicktime.msi`.
    let needle = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    for (vpath, _) in vfs.list() {
        if vpath.to_ascii_lowercase().ends_with(&needle) {
            return vfs.read(vpath).map(<[u8]>::to_vec);
        }
    }
    None
}
