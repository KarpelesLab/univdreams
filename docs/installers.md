# Running Windows installers in the emulator

This document covers what `ud analyze --monitor` can do with Windows installer-class PE32 binaries (InstallShield wrappers, NSIS, classic MSI setups), and the practical workflow for extracting an installer's payload + capturing what it would install.

The emulator is **headless and sandboxed**. Nothing the guest does reaches the host filesystem, the host registry, or the network. Every side effect lives in an attached in-memory virtual filesystem + virtual registry, which `--dump-vfs` writes to disk on request.

## What's actually inside the box

`ud-emulator` ships a pure-Rust 32-bit x86 interpreter, a PE/COFF loader, and ~250 Win32 stub functions across `kernel32`, `user32`, `gdi32`, `winmm`, `msvcrt`, `ole32`, `advapi32`, `comctl32`, `shell32`, `shlwapi`, `mfplat`, `vfw32`, `version`, and `msi`. The scheduler is preemptive (round-robin with priority + quantum), supports multiple processes through `CreateProcessA`, and models the standard sync surface — Event / Mutex / Semaphore / CriticalSection with real waiter wake-up, named-object registry, anonymous + named pipes, and per-thread TLS / TIB.

`CreateProcessA` targeting `C:\Windows\System32\msiexec.exe` routes into a host-side MSI walker (`win32::msiexec`) that parses the referenced `.msi` via the [`msi`](https://crates.io/crates/msi) crate and synthesises the install effects — resolved file paths *with the actual decompressed file bytes* into the VFS, registry entries into the VirtualRegistry. Embedded `#name.cab` streams referenced by the MSI's `Media` table are unpacked through the [`cab`](https://crates.io/crates/cab) crate (LZX / MSZIP); external CAB files are recognised but require staging through the VFS in a future patch.

It is intentionally not a faithful Windows-Installer reimplementation: no custom-action execution, no conditional-expression evaluator, no `Installer` COM. What it produces is a complete picture of *what* an MSI would install *where*, with the real binary content available on disk after `--dump-vfs`.

One thing the emulator **doesn't** do today:

- **Render a UI.** `MessageBox*` / `DialogBoxParam*` etc. auto-accept with `IDOK`, `GetMessage` returns `WM_QUIT`. The installer's wizard pages headless-advance through their default path.

## The one-shot command

```
ud analyze --monitor <installer.exe>
    --args "<silent flags>"            # e.g. "/quiet /norestart" or "/S"
    --dump-vfs <output-directory>      # everything the install touched
    --max-instructions <budget>        # default 5M; installers want more
    [--json]                           # machine-readable output to stdout
```

The report (text or JSON) covers:

- outcome (clean exit / trap / budget exhausted)
- total instructions executed
- every Win32 call by name + count + the full call stream
- every file the guest produced in the VFS, plus byte counts
- every registry entry written
- a `debug_log` stream of host-side diagnostic events (Msi calls, `CreateProcessA` targets, GS-check workarounds, …)

When `--dump-vfs <dir>` is set, the VFS is also written to disk after the run with path sanitisation (`C:\` becomes a `c_/` subdirectory; `\` becomes `/`).

## Best practice for extracting an installer's payload

The recipe below is what we ran end-to-end against QuickTime 7.7.9 (Apple's `QuickTimeInstaller-7.7.9.exe`).

### 1. Run silent + dump everything

```
$ ud analyze --monitor QuickTimeInstaller-7.7.9.exe \
    --args "/quiet /norestart" \
    --dump-vfs /tmp/qt_dump \
    --max-instructions 3000000000
```

`/quiet /norestart` tells the installer to skip its wizard. Most modern installers (MSI-wrapping, InstallShield, Inno Setup, NSIS) accept some variant of `/S`, `/silent`, `/quiet`, `/qn` — read the binary's `--help` strings or the vendor's silent-install documentation. The `--args` value is prefixed by the input PE's filename so the installer sees `argv[0] = installer.exe; argv[1..] = your flags`.

`--max-instructions` is the budget knob. A 2.2 GHz Cortex-M2 Mac runs ~2 GIPS through the interpreter; a 2-3 billion-instruction budget covers a 30-second install. CAB decompression dominates the cost — extracting a 40 MB MSI bundle from a self-extracting wrapper takes ~2 B instructions on its own.

### 2. Inspect the report

For QuickTime the report looks like:

```
install-monitor report for QuickTimeInstaller-7.7.9.exe
  image base: 0x00400000
  entry point: 0x0040a8c4
  instructions executed: 2,244,168,597
  Win32 calls: 5,970

  VFS writes: 1359 files (754 non-empty)  Total bytes: 82,540,980

    c:/temp/oxideav-vfw1.log                                   1381 bytes
    ixp051.tmp/quicktime.msi                              28,397,568 bytes
    ixp051.tmp/appleapplicationsupport.msi                19,727,040 bytes
    …
    c:/program files/quicktime/quicktimeplayer.exe         1,235,264 bytes
    c:/program files/quicktime/quicktimeplayer.dll         9,287,984 bytes
    c:/program files/quicktime/qtocontrol.dll                895,280 bytes
    …

  Registry writes: 719 entries
    HKCR\quicktime.qt        ::                              = QuickTime Movie
    HKCR\quicktime.qt\shell\open\command :: = "QuickTimePlayer.exe" "%1"
    HKCR\.mov                ::                              = QuickTime.qt
    …

  Debug log:
    CreateProcessA(app="C:\\WINDOWS\\System32\\msiexec.exe",
                   cmd="msiexec.exe /i \"IXP051.TMP\\QuickTime.msi\"")
    msiexec: property snapshot (51 entries)
    msiexec /i "IXP051.TMP\\QuickTime.msi" — synthesised 753 files
            (82,539,599 / 82,539,599 bytes extracted), 683 directories,
            723 registry entries
```

`file /tmp/qt_dump/c_/program\ files/quicktime/quicktimeplayer.exe`
confirms `PE32 executable (GUI) Intel 80386, for MS Windows` — the
binaries on disk are the real QuickTime player ready to feed into a
disassembler / decompiler.

Two things to read out of this:

- **Extracted MSI bundle**: the four `.msi` files + the install helper exe under `ixp051.tmp/` are what the outer installer extracted from its embedded resources. They are real bytes — the dump folder has them on disk and you can analyse them with any standard MSI tool.
- **Synthesised install**: the `c:/program files/quicktime/…` entries + the `HKCR\…` registry entries are what `msiexec /i quicktime.msi` would install. The file bodies are the **real decompressed bytes** pulled out of the MSI's embedded CAB streams — `quicktimeplayer.exe` lands on disk as a 1.2 MB Win32 PE32 binary, `quicktimeplayer.dll` as 9.3 MB, ready to feed into any reverse-engineering tool. The msiexec summary line reports both `extracted / expected` so you can spot any cab entries that fell back to zero-byte markers.

### 3. Chain-load child binaries when needed

Some installers do their install through a helper EXE they extract first (`quicktimeinstalleradmin.exe` in QT's case; `setup.exe` in NSIS wrappers; the embedded MSI in Wise installers). The extracted helper is in the dump directory after step 1 — you can analyse it separately:

```
$ ud analyze --monitor /tmp/qt_dump/ixp051.tmp/quicktimeinstalleradmin.exe \
    --args "<helper-specific args>" \
    --dump-vfs /tmp/qt_dump_admin
```

Helpers that depend on the parent's IPC (named events, parent process PID, named pipes) get partial coverage — the named-object registry is shared across `CreateProcessA`-spawned children, and `OpenEventA` returns a synthetic signaled event for unstaged names so the helper proceeds rather than blocks forever. For deeper IPC analysis (where the parent and helper need to exchange specific bytes), run the parent under a higher budget; Phase 5c loads the helper as a real child PE the scheduler runs alongside the parent.

### 4. When the install is gated by msiexec

If the debug log shows
```
CreateProcessA(app="C:\\WINDOWS\\System32\\msiexec.exe", cmd="...")
msiexec /i "<path>" — synthesised N files (B bytes), D directories, R registry entries
```
the install completed *through our walker*. The file + registry intel in the report is what `msiexec.exe` would have written.

If instead you see
```
CreateProcessA(app="C:\\WINDOWS\\System32\\msiexec.exe", cmd="...")
msiexec /i "<path>" — MSI not in VFS, install skipped
```
the parent gave msiexec a path that wasn't in our VFS (typically a basename mismatch between how the parent constructed the path and how the outer installer staged the file). The walker tries a couple of fallbacks (drive-letter strip, case-insensitive basename match against `vfs.list()`); if those don't catch it, copy the MSI to the expected path inside `--dump-vfs` and re-run with `--args` adjusted to point at the staged location.

### 5. Tuning the budget for partial captures

Running below the budget needed for the full install sometimes captures *more* state than completing it does — installers routinely delete their temp dirs at the end of a successful install. The QuickTime extraction's peak is around 2.2 B instructions (after extraction, before `RemoveDirectoryA` rollback). The full install runs to ~2.24 B before hitting a CRT epilogue.

If you want to inspect the MSI extraction without losing it to cleanup, run with `--max-instructions 2_200_000_000` and dump the VFS at that point.

## Custom install logic — the `InstallSink` trait

The MSI walker emits `InstallAction` events into a caller-supplied sink. For analysis work the default `EmulatorInstallSink` materialises files into the VFS and registry into the VirtualRegistry; for reverse-engineering, override the trait:

```rust
use crate::win32::msiexec::{InstallAction, InstallSink};

struct InvestigateSink {
    suspicious: Vec<InstallAction>,
}

impl InstallSink for InvestigateSink {
    fn emit(&mut self, action: InstallAction) -> bool {
        // Filter for COM registrations that name unfamiliar CLSIDs.
        if let InstallAction::RegSet { key, value, .. } = &action {
            if key.contains("CLSID") && value_is_suspicious(value) {
                self.suspicious.push(action);
            }
        }
        true  // keep walking; return false to abort early
    }

    fn install_component(&mut self, component: &str) -> bool {
        // Skip every component whose id matches "Plugin_*"
        !component.starts_with("Plugin_")
    }

    fn override_property(&mut self, name: &str) -> Option<String> {
        // Force the install root somewhere predictable.
        if name == "INSTALLDIR" {
            return Some("D:\\AnalysisRoot".into());
        }
        None
    }
}
```

The walker calls `override_property` once per property *before* the directory resolution, then `install_component` once per `Component` row, then `emit` for every `CreateDirectory` / `WriteFile` / `RegSet` / `SnapshotProperties` / `Log` action in walk order.

## Known limitations

The big ones, in rough order of how often they surface:

- **External (non-embedded) MSI cabs**. The MSI's `Media` table can reference cabs that ship as separate files on the install media (rather than `#name`-embedded streams). Those rows log `external cab N not supported; file bytes will be missing` and the affected files come out as zero-byte markers. The fix is plumbing the host VFS into the cab-resolution path; the embedded-stream case (which covers QuickTime, every modern self-contained installer, etc.) works.
- **Some installer CRT epilogues hit spurious GS-cookie failures**. The emulator's interpreter perturbs FPU/SSE residue and segment-register shadow state in ways the real CPU doesn't, occasionally tripping `__report_gsfailure`. The `TerminateProcess(STATUS_STACK_BUFFER_OVERRUN)` path is now a logged no-op so the run completes the install before the failure surfaces as a memory fault.
- **`CreateProcessA(child.exe)` with non-MSI children** loads the child via Phase 5c when the binary is in the VFS *and* every IAT import is host-stubbed. Strict import resolution falls through to a synthetic immediate-exit child on any unstubbed import; the `debug_log` records which one.
- **No real Windows Installer custom actions**. The `CustomAction`, `InstallExecuteSequence`, `LaunchCondition`, `ServiceInstall`, `ODBCDataSource` tables are not interpreted. Installers whose install effects are *primarily* through custom actions (rare, but present in some enterprise installers) won't surface in our walker — only the static `File` + `Registry` rows do.
- **Shell integration / file associations** show up as `HKCR\…` registry writes (which we capture), but the side-effect Windows would perform when those writes happen (Shell notify, icon-cache refresh) isn't modelled. For "what extensions does this installer claim" intel the registry dump is enough; for full behavioural reproduction it isn't.
- **User-mode services / RPC** — `StartService`, `OpenSCManagerA`, `RegisterServiceCtrlHandlerA` are stubbed but don't actually run a service worker. An installer that depends on its service to complete its post-install workflow won't get there.

## Reference: the wiring

`crates/ud-emulator/src/win32/msiexec.rs` — the MSI walker and `CreateProcessA(msiexec)` dispatch site.

`crates/ud-emulator/src/win32/kernel32.rs::stub_create_process_a` — Phase 5c child-PE load, msiexec detection, synthetic immediate-exit fallback.

`crates/ud-emulator/src/context.rs` — `VirtualFs` + `VirtualRegistry`, the destinations every install effect routes into.

`crates/ud-emulator/src/sched.rs` — the preemptive scheduler, named-object registry, pipe buffers, wait-condition wake protocol.

`crates/ud-cli/src/main.rs::monitor_install` — the `ud analyze --monitor` driver that stitches the above together and emits the JSON / text report.
