// `LRESULT` / `HRESULT` / Win32 IC* return codes inhabit the u32
// ↔ i32 boundary by design (the negative half encodes errors).
// Allow the cast at module level rather than peppering 14 inline
// attrs across the VfW handlers.
#![allow(clippy::cast_possible_wrap)]
// Guest memory is a 32-bit address space, so `usize`/`u64` offsets
// and lengths are cast down to `u32` throughout by design; the
// truncation is intentional, not a latent bug.
#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};

#[cfg(feature = "script")]
mod script;

#[derive(Parser, Debug)]
#[command(
    name = "ud",
    version,
    about = "univdreams: a universal compiler/decompiler suite",
    long_about = "Decompile binaries to a directive-rich C-like source language and \
                  recompile to byte-identical binaries."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the full pipeline (decompile then compile) and verify byte-equality
    /// with the input.
    ///
    /// Without `--through-source`, routes through `ud-format-elf`'s
    /// parse + write-to-vec — defends the format-level round-trip.
    ///
    /// With `--through-source`, routes through the full source pipeline:
    /// decompile → emit → parse → lower_to_elf. Surfaces verify-asm
    /// warnings and a byte-diff offset when the result diverges; never
    /// fails on warnings, only on hard pipeline errors.
    Roundtrip {
        /// Input binary.
        input: PathBuf,

        /// Where to write the rebuilt binary. Defaults to `<input>.rebuilt`.
        #[arg(long)]
        out: Option<PathBuf>,

        /// Route through the source language (decompile → text → parse →
        /// lower_to_elf) instead of the format-level path.
        #[arg(long)]
        through_source: bool,
    },

    /// Decompile a binary to `.ud` source.
    ///
    /// v0 emits one `fn` block per discovered function with `@asm("…")`
    /// lines for every instruction. Padding between functions and
    /// non-text sections aren't represented yet.
    Decompile {
        /// Input binary.
        input: PathBuf,

        /// Where to write the `.ud` source. Defaults to stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Verify a `.ud` source file: parse, then check every `@asm`
    /// line's text against the canonical form for its pinned bytes.
    /// Warnings go to stderr; the exit code is non-zero only on
    /// parse errors, not on warnings.
    Verify {
        /// `.ud` source file.
        input: PathBuf,
    },

    /// Compile a `.ud` source file back to a binary. Dispatches on
    /// the `@module.format` field — `"elf"` → ELF, `"pe"` → PE,
    /// `"macho"` → Mach-O, `"raw"` → raw image.
    ///
    /// Editing the source between decompile and compile is the
    /// supported workflow: PC-relative encoders (jmp, jcc, call,
    /// switch) re-resolve at lower time so moving a function or
    /// growing its body produces a working binary.
    Compile {
        /// `.ud` source file.
        input: PathBuf,

        /// Where to write the rebuilt binary. Defaults to
        /// `<input>.bin`.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Run a binary inside the bounded i386 emulator and report
    /// what it does — Win32 calls, code coverage, traps. Treats
    /// the input as untrusted (it's the whole point of a
    /// sandboxed run) but inspects the structured execution
    /// trace, not the raw output. Today supports PE32 DLLs;
    /// the run drives `DllMain(PROCESS_ATTACH)` and reports
    /// every Win32 API the codec touched plus a coverage
    /// summary.
    Analyze {
        /// PE32 DLL (or DLL-shaped binary) to analyse.
        input: PathBuf,

        /// Cap the run at this many guest instructions.
        /// `DllMain` of a CRT-driven codec usually fits in a
        /// few million; the cap is just a safety net for
        /// adversarial samples that loop.
        #[arg(long, default_value_t = 5_000_000)]
        max_instructions: u64,

        /// Emit a JSON report on stdout instead of the
        /// human-readable summary. Suitable for piping into
        /// downstream analysis tooling.
        #[arg(long)]
        json: bool,

        /// Run in install-monitor mode: load the PE in fail-
        /// soft import-resolution mode (unknown imports get a
        /// trap-on-call thunk instead of failing at load) and
        /// drive the PE's entry point rather than `DllMain`.
        /// Suitable for EXEs / installers whose import surface
        /// exceeds the codec-class stub registry.
        ///
        /// The trap stream + side-effect log (virtual FS /
        /// registry writes captured through the existing
        /// `Context` layer) surfaces what the installer
        /// touched up to the first unimplemented API.
        #[arg(long)]
        monitor: bool,

        /// In monitor mode, override `GetCommandLineA`'s
        /// return value with this string. Use to pass
        /// installer-specific silent / quiet flags
        /// (`/S` for InstallShield, `/qn` or `/quiet` for
        /// MSI, …) so the installer skips its UI and runs
        /// non-interactively.
        ///
        /// The string is prefixed with the input PE's filename
        /// so the installer sees `argv[0] = setup.exe` and
        /// `argv[1..] = <flags>`, matching how Windows
        /// formats the real `GetCommandLineA` output. For Linux ELFs the
        /// tokens become the guest `argv[1..]` (quote-aware), e.g.
        /// `--args "-c 'echo hi'"`.
        #[arg(long, allow_hyphen_values = true)]
        args: Option<String>,

        /// In monitor mode, after the run finishes write every
        /// file the guest produced in the virtual filesystem
        /// to this host directory. Useful for chain-loading
        /// extracted child binaries (e.g. an installer's
        /// embedded MSI / admin EXE) through a follow-up
        /// `ud analyze --monitor` pass.
        #[arg(long)]
        dump_vfs: Option<PathBuf>,

        /// Run amd64 Linux ELFs natively under KVM (hardware
        /// virtualization) instead of the software interpreter.
        /// Requires a Linux x86-64 host with `/dev/kvm` and a
        /// build with `--features kvm`; falls back to the
        /// interpreter if KVM is unavailable or the guest can't
        /// be run that way.
        #[arg(long)]
        kvm: bool,

        /// Allow the guest to open real **host network** sockets
        /// (TCP/UDP/DNS), e.g. so `apk add` can download packages.
        /// Off by default; enabling it lets the sandboxed program
        /// reach the host's network.
        #[arg(long)]
        net: bool,

        /// Run interactively: wire the guest's stdin/stdout/stderr to
        /// this terminal (raw mode), report a real tty to the guest,
        /// and deliver Ctrl-C as SIGINT — so you can drive a shell.
        /// Off by default (batch: stdin is EOF, output is captured).
        #[arg(short = 'i', long)]
        interactive: bool,

        /// Back the root filesystem with a real on-disk format
        /// (ext4 / ntfs / fat / exfat) via fstool instead of the
        /// flat in-memory store. `auto` picks the per-OS default
        /// (ext4 for a Linux ELF, NTFS for a PE). Requires a build
        /// with `--features fstool`.
        #[arg(long, value_name = "TYPE")]
        fs_type: Option<String>,

        /// Mount a filesystem at a path: `--mount <point>=<spec>`
        /// (repeatable). `<spec>` is a type name (`ext4`, fresh
        /// empty), `@<image>` (open a host image read-only), or
        /// `@<image>:rw` (open writable, flush on exit). Requires
        /// `--features fstool`. Example: `--mount /data=@disk.ext4`.
        #[arg(long, value_name = "POINT=SPEC")]
        mount: Vec<String>,

        /// Don't auto-mount the synthetic `/proc` and `/dev` for
        /// Linux runs.
        #[arg(long)]
        no_default_mounts: bool,

        /// Populate the root from a filesystem image source and mount
        /// it (writable) at `/`. SPEC is a local `*.tar.gz` / `*.tar` /
        /// directory, or `alpine[:VERSION][/ARCH]` to fetch the Alpine
        /// minirootfs from dl-cdn.alpinelinux.org (cached locally). The
        /// source is repacked into a cached ext4 image on first use.
        /// Requires `--features fstool`. Example:
        /// `--rootfs alpine /bin/busybox`.
        #[arg(long, value_name = "SPEC")]
        rootfs: Option<String>,

        /// In monitor mode, silently ignore `DeleteFileA` and
        /// `RemoveDirectoryA` so the post-install rollback
        /// some installers do (cleanup of temp-dir MSIs after
        /// msiexec returns) doesn't drop the extracted
        /// bundle. Defaults to ON because that's almost
        /// always what an analyst running `--monitor` wants;
        /// pass `--preserve-deletes=false` to get true
        /// semantics.
        #[arg(long, default_value_t = true)]
        preserve_deletes: bool,

        /// Load the PE in fail-soft import-resolution mode
        /// even outside `--monitor`. Useful for codecs whose
        /// import surface includes dependent DLLs (Apple's
        /// CoreVideo / CoreAudioToolbox, etc.) that the host
        /// stub registry doesn't yet cover — the DLL still
        /// loads and `DllMain` still runs; calls into the
        /// unimplemented import trap on first use, naming
        /// the missing API. Off by default to keep the
        /// codec-class strict-load guarantee for samples that
        /// fit the registered surface.
        #[arg(long)]
        fail_soft: bool,

        /// Mount one or more host directories into the sandbox
        /// VFS before load. Each `<dir>` is walked recursively;
        /// every file is staged under the path derived from the
        /// directory layout (e.g. a `--dump-vfs <dir>` output
        /// can be passed back here verbatim to re-mount the
        /// previous install's c:/ tree). Combine with
        /// `--vfs-deps` to resolve codec dependencies from the
        /// staged install.
        #[arg(long, value_name = "DIR")]
        stage_vfs: Vec<PathBuf>,

        /// Walk the primary PE's imports and pre-load every
        /// dependent DLL the host stub registry doesn't know
        /// about from the sandbox VFS (recursively, with cycle
        /// detection). Pair with `--stage-vfs` to seed the
        /// VFS from a previous `--dump-vfs` directory. Each
        /// dependent's `DllMain(PROCESS_ATTACH)` runs after it
        /// loads. Implies `--fail-soft`.
        #[arg(long)]
        vfs_deps: bool,

        /// After `DllMain` returns, call every exported symbol
        /// whose name matches this pattern (repeatable). A single
        /// `*` acts as a wildcard, so `--call-export '*InitDecoder'`
        /// drives the codec's decoder-init entry point that CRT
        /// init alone never reaches. Each match is invoked stdcall
        /// with the `--export-arg` values (none by default); its
        /// return value and any trap are added to the report, and
        /// the Win32-call / coverage totals include the calls it
        /// makes. Non-matching patterns emit a warning.
        #[arg(long, value_name = "PATTERN")]
        call_export: Vec<String>,

        /// 32-bit argument pushed (in order, left to right) to
        /// each `--call-export` target. Repeatable; accepts
        /// decimal or `0x`-prefixed hex. Applied uniformly to
        /// every called export.
        #[arg(long, value_name = "N")]
        export_arg: Vec<String>,

        /// Call one export with its own argument list, as an
        /// ordered step in a persistent decode sequence. SPEC is
        /// `NAME[:arg,arg,…]` (args decimal or `0x` hex).
        /// Repeatable; the calls run in command-line order in the
        /// same guest context — so a codec whose decode-time
        /// tables are built only across a call *sequence* can be
        /// driven end to end in one process, e.g.
        /// `--call RAOpenCodec:0x20000000
        ///  --call RAInitDecoder:0x20000000
        ///  --call RADecode:0x30000000,0,0x40000000`.
        /// Stage the descriptor / frame buffers with `--map-blob`
        /// and capture what a call built with `--dump-mem`. Runs
        /// after any `--call-export` matches. Unlike `--call-export`
        /// the name is matched exactly and a repeat re-invokes it
        /// (e.g. decode several frames).
        #[arg(long = "call", value_name = "NAME[:args]")]
        call: Vec<String>,

        /// After the run (including any `--call-export`), dump a
        /// region of guest memory. SPEC is `ADDR:LEN` to hex-dump
        /// to stdout, or `ADDR:LEN=PATH` to write the raw bytes to
        /// a host file. ADDR/LEN take decimal or `0x` hex.
        /// Repeatable — use it to capture the tables / buffers a
        /// decoder-init populated. Unmapped bytes render as `··`
        /// in the hex dump and are zero-filled in file output.
        #[arg(long, value_name = "SPEC")]
        dump_mem: Vec<String>,

        /// Before any `--call-export`, stage a host file's bytes
        /// into guest memory at a chosen VA. SPEC is `VA=PATH`
        /// (VA decimal or `0x` hex). Gap pages are mapped R+W;
        /// the write bypasses page W-protection, so a blob can
        /// land in read-only data too. Repeatable. Use it to
        /// inject a valid init cookie / descriptor an export
        /// expects, then point `--export-arg` at the VA and
        /// `--dump-mem` at the tables it builds.
        #[arg(long, value_name = "SPEC")]
        map_blob: Vec<String>,

        /// Size of the guest malloc / `HeapAlloc` arena in MiB.
        /// Raise it when a decoder-init exhausts the default
        /// (96 MiB) arena. Clamped to `[96, 256]`; the ceiling is
        /// the const-arena region above the heap. Only raise it
        /// for single-DLL codecs — the extra band is where
        /// fixed-base QuickTime helper DLLs would load.
        #[arg(long, value_name = "MiB", default_value_t = ud_emulator::Sandbox::DEFAULT_HEAP_MB)]
        heap_mb: u32,

        /// Watch a guest-memory region and record every store into
        /// it as an ordered write-trace — `ADDR:LEN` (decimal or
        /// `0x` hex), repeatable. Armed after `DllMain` + `--map-blob`
        /// and before the `--call` / `--call-export` sequence, so it
        /// captures exactly what those calls write. Each hit lands in
        /// the report (text + JSON) as `#seq +off [addr] = value`
        /// with the writing EIP — a byte-exact behavioral trace of
        /// how the real codec fills a table.
        #[arg(long, value_name = "ADDR:LEN")]
        watch: Vec<String>,
    },

    /// Video for Windows codec tools — drive a codec DLL
    /// through the VfW `IC*` pipeline inside the sandbox.
    /// See `ud vfw --help` for the per-command list.
    Vfw {
        #[command(subcommand)]
        command: VfwCommand,
    },

    /// QuickTime codec tools — drive a `.qtx` codec through
    /// its `*_ComponentDispatch` entry point. The codec is
    /// loaded with VFS-DLL fallback (so Apple framework deps
    /// resolve from a staged install tree) and a synthetic
    /// `ComponentParameters` is pushed for the requested
    /// selector. See `ud qtcodec --help` for the per-command
    /// list.
    Qtcodec {
        #[command(subcommand)]
        command: QtcodecCommand,
    },

    /// Fetch a Solana on-chain program by its base58 ID and
    /// decompile it. Recognises the three current SBF
    /// loaders (`BPFLoader2`, `BPFLoaderUpgradeable`,
    /// `LoaderV4`) and strips the loader-state header before
    /// feeding the raw ELF into the standard decompile path.
    ///
    /// ELFs are cached under `~/.cache/univdreams/solana/` so
    /// repeated invocations don't hammer the RPC endpoint.
    /// Pass `--no-cache` to force a fresh fetch.
    Solana {
        /// Program ID (base58, 32 bytes).
        program_id: String,

        /// RPC endpoint URL. Defaults to Solana's public
        /// mainnet endpoint.
        #[arg(long, default_value = ud_cli::solana::DEFAULT_RPC)]
        rpc: String,

        /// Skip the local cache and force a fresh fetch.
        #[arg(long)]
        no_cache: bool,

        /// Save the raw ELF bytes to this path *before*
        /// decompiling. Useful for diffing across runs or
        /// hand-inspecting with another tool.
        #[arg(long)]
        save_elf: Option<PathBuf>,

        /// Where to write the `.ud` source. Defaults to stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Drive the sandbox from a JavaScript program (feature `script`).
    /// The script gets host globals — `load`, `dllMain`, `mapBlob`,
    /// `callExport`, `dumpMem`, `readFile`/`writeFile`, `checkpoint`/
    /// `restore`, `print` — over one persistent guest instance, so a
    /// codec Open→Init→Decode sequence (or multi-frame decode) can be
    /// orchestrated with real control flow. See `ud script --help`.
    #[cfg(feature = "script")]
    Script {
        /// JavaScript program to run.
        file: PathBuf,

        /// Guest malloc / `HeapAlloc` arena size in MiB (default 96,
        /// clamped to `[96, 256]`).
        #[arg(long, value_name = "MiB", default_value_t = ud_emulator::Sandbox::DEFAULT_HEAP_MB)]
        heap_mb: u32,

        /// Cap each guest call at this many instructions.
        #[arg(long, default_value_t = 100_000_000)]
        max_instructions: u64,
    },
}

#[derive(Subcommand, Debug)]
enum QtcodecCommand {
    /// Manually register a QT component by loading its `.qtx`
    /// and calling `qtmlclient!RegisterComponent` with a
    /// caller-supplied ComponentDescription pointing at the
    /// codec's `*_ComponentDispatch` export. After registration
    /// the component shows up in `CountComponents` /
    /// `FindNextComponent` and can be opened via
    /// `OpenComponent`. Use this until our MSI walker runs the
    /// post-install registration CustomAction.
    Register {
        /// Codec `.qtx` to register.
        codec: PathBuf,

        /// `*_ComponentDispatch` export to use as the entry point.
        #[arg(long)]
        export: String,

        /// componentType FourCC (e.g. `imdc`).
        #[arg(long)]
        ty: String,

        /// componentSubType FourCC (e.g. `apch`).
        #[arg(long)]
        subtype: String,

        /// componentManufacturer FourCC.
        #[arg(long, default_value = "appl")]
        manufacturer: String,

        /// Mount these host directories into the sandbox VFS.
        #[arg(long, value_name = "DIR")]
        stage_vfs: Vec<PathBuf>,

        /// Cap the run at this many guest instructions.
        #[arg(long, default_value_t = 1_000_000_000)]
        max_instructions: u64,
    },

    /// Count the registered QT components matching a
    /// `ComponentDescription { type, subType, manufacturer,
    /// flags, flagsMask }`. Calls InitializeQTML + EnterMovies
    /// first to bring up the runtime, then constructs a
    /// 20-byte ComponentDescription in guest memory and
    /// invokes `qtmlclient!CountComponents`. Use this to
    /// confirm codecs are visible to the host:
    ///
    /// ```text
    /// ud qtcodec list --type imdc --stage-vfs /tmp/qt_dump
    /// ```
    List {
        /// componentType FourCC. Common: `imdc` (image
        /// decompressor), `imco` (image compressor), `aenc`
        /// (audio encoder), `adec` (audio decoder), `0` to
        /// match every type.
        #[arg(long, default_value = "imdc")]
        ty: String,

        /// componentSubType FourCC, or `0` to match every
        /// subtype.
        #[arg(long, default_value = "0")]
        subtype: String,

        /// componentManufacturer FourCC; `0` matches any.
        #[arg(long, default_value = "0")]
        manufacturer: String,

        /// Mount these host directories into the sandbox VFS
        /// before load.
        #[arg(long, value_name = "DIR")]
        stage_vfs: Vec<PathBuf>,

        /// Optionally run the install of one or more MSIs
        /// before the QT runtime bring-up. The msiexec walker
        /// runs in the SAME sandbox and pumps deferred DLL
        /// CustomActions (QuickTimePostInstallMSIProc), so
        /// the subsequent InitializeQTML / EnterMovies /
        /// CountComponents calls observe the post-install
        /// state.
        #[arg(long, value_name = "MSI")]
        install_msi: Vec<PathBuf>,

        /// Cap the run at this many guest instructions.
        #[arg(long, default_value_t = 1_000_000_000)]
        max_instructions: u64,
    },

    /// Call an arbitrary stdcall (or cdecl — caller cleans
    /// only matters for stack-pop bookkeeping which is a
    /// no-op here) export on a QT runtime DLL. Loads the DLL
    /// (and its VFS-discoverable deps) with the QT runtime
    /// pre-load step, calls DllMain, then invokes the export
    /// with the supplied positional `--arg` values.
    Call {
        /// PE32 DLL to load (typically `qtmlclient.dll`).
        dll: PathBuf,

        /// Export to call (e.g. `InitializeQTML`, `NewPtr`,
        /// `EnterMovies`).
        #[arg(long)]
        export: String,

        /// Positional u32 args (decimal or `0x`-hex). Pushed
        /// right-to-left in stdcall order, so `--arg 1 --arg 2`
        /// produces a stack of `[1, 2]` from the callee's
        /// `[esp+4], [esp+8]` perspective.
        #[arg(long, value_name = "U32", value_parser = parse_u32)]
        arg: Vec<u32>,

        /// Mount these host directories into the sandbox VFS
        /// before load — typically a `--dump-vfs` directory.
        #[arg(long, value_name = "DIR")]
        stage_vfs: Vec<PathBuf>,

        /// Cap the run at this many guest instructions.
        #[arg(long, default_value_t = 200_000_000)]
        max_instructions: u64,
    },

    /// Invoke a single selector on a QuickTime component's
    /// `*_ComponentDispatch` entry. Loads the codec with
    /// VFS-DLL fallback, calls `DllMain(PROCESS_ATTACH)`,
    /// builds a `ComponentParameters` struct in guest memory,
    /// and dispatches with `storage = NULL`. Use this to
    /// probe simple selectors (kComponentVersionSelect = -4,
    /// kComponentCanDoSelect = -3, etc.) before driving a
    /// full open/decompress sequence.
    Dispatch {
        /// Codec `.qtx` (or any PE32 DLL with a
        /// `*_ComponentDispatch` export).
        codec: PathBuf,

        /// Name of the `*_ComponentDispatch` export to call
        /// (e.g. `RPZA_CDComponentDispatch`).
        #[arg(long)]
        export: String,

        /// Selector value (the `what` field of
        /// `ComponentParameters`). Encoded as a signed 16-bit
        /// integer for the negative system selectors.
        #[arg(long, default_value_t = -4)]
        selector: i16,

        /// Optional u32 parameter words placed after the
        /// 4-byte ComponentParameters header (low-to-high on
        /// the param slot). `paramSize` is set to
        /// `params.len() * 4`. Accepts decimal or `0x`-prefixed
        /// hex.
        #[arg(long, value_name = "U32", value_parser = parse_u32)]
        param: Vec<u32>,

        /// Mint a synthetic Mac OS Memory Manager `Handle` of
        /// this byte size and pass its address as the codec's
        /// `storage` argument. A Handle is a `Ptr*` — a pointer
        /// to a pointer to the storage block. Zero (the
        /// default) passes a NULL handle, which works for the
        /// system selectors (kComponentVersionSelect, etc) but
        /// causes a NULL-deref the moment the codec touches
        /// per-instance state.
        #[arg(long, default_value_t = 0, value_parser = parse_u32)]
        storage: u32,

        /// Mount these host directories into the sandbox VFS
        /// before load — typically the `--dump-vfs` output
        /// directories from a prior install. See `ud analyze
        /// --stage-vfs`.
        #[arg(long, value_name = "DIR")]
        stage_vfs: Vec<PathBuf>,

        /// Cap the run at this many guest instructions.
        #[arg(long, default_value_t = 100_000_000)]
        max_instructions: u64,
    },
}

#[derive(Subcommand, Debug)]
enum VfwCommand {
    /// Load a codec DLL + DllMain + DRV_OPEN + ICGetInfo +
    /// ICDecompressQuery (RGB24 default). Quick sanity check
    /// that the codec accepts a reasonable BIH pair.
    Probe {
        /// Codec DLL.
        dll: PathBuf,

        /// FourCC handler override (defaults to the
        /// filename-based heuristic).
        #[arg(long = "fcc-handler", value_name = "FCC")]
        fcc_handler: Option<String>,

        /// Probe-test output pixel format. RGB24 is the
        /// VfW lingua franca and the format every decoder
        /// is expected to support.
        #[arg(long = "pix-format", value_enum, default_value_t = PixFormat::Rgb24)]
        pix_format: PixFormat,

        /// Test frame width (used for the probe BIH only;
        /// the codec usually doesn't care at this stage).
        #[arg(long, default_value_t = 320)]
        width: u32,

        /// Test frame height.
        #[arg(long, default_value_t = 240)]
        height: u32,

        /// Cap the run at this many guest instructions.
        #[arg(long, default_value_t = 100_000_000)]
        max_instructions: u64,
    },

    /// Drive `ICDecompress` on a codec bitstream-only frame:
    /// load the codec DLL, run `DllMain(DLL_PROCESS_ATTACH)`,
    /// open the codec via `ICOpen`, run the full
    /// `ICDecompressQuery → Begin → Decompress → End → Close`
    /// sequence, and write the decoded frame to the output file.
    Decode {
        /// Codec DLL.
        dll: PathBuf,

        /// Raw codec frame(s), bitstream only (no container —
        /// extract from any AVI / MOV wrapper beforehand).
        /// Repeatable: multiple `--input` frames are fed through
        /// `ICDecompress` in order within ONE Open→Begin…End→Close
        /// lifetime, so inter-frame decoder state (indeo5's
        /// inheritance-MV tables, a dispatch table a P-frame
        /// populates) persists across the sequence. An inter frame
        /// that can't decode standalone (`ICDecompress=1` on its
        /// own) decodes once its reference frame has run.
        #[arg(long, value_name = "FILE", required = true)]
        input: Vec<PathBuf>,

        /// Output frame width (pixels).
        #[arg(long)]
        width: u32,

        /// Output frame height (pixels).
        #[arg(long)]
        height: u32,

        /// FourCC handler override (`MP43`, `IV31`, `cvid`, …).
        /// Defaults: derived from the DLL filename.
        #[arg(long = "fcc-handler", value_name = "FCC")]
        fcc_handler: Option<String>,

        /// Output pixel format.
        #[arg(long = "pix-format", value_enum, default_value_t = PixFormat::Rgb24)]
        pix_format: PixFormat,

        /// Write decoded frame here. Defaults to stdout.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Cap the run at this many guest instructions.
        #[arg(long, default_value_t = 100_000_000)]
        max_instructions: u64,

        /// After `ICDecompress` returns (decoder tables built,
        /// before teardown), dump a region of guest memory. SPEC
        /// is `ADDR:LEN` to hex-dump to **stderr** (so it never
        /// corrupts the decoded frame on stdout), or `ADDR:LEN=PATH`
        /// to write the raw bytes to a host file. ADDR/LEN take
        /// decimal or `0x` hex. Repeatable — capture the codec's
        /// window / codebook / coupling tables after a real frame
        /// decode. Unmapped bytes render as `··` / zero-fill.
        #[arg(long, value_name = "SPEC")]
        dump_mem: Vec<String>,

        /// With multiple `--input` frames, take the `--dump-mem`
        /// snapshots after this 1-based frame index instead of
        /// after the last — to capture decoder state at a chosen
        /// point in the sequence (e.g. right after the first inter
        /// frame populates a table). Default: after the final frame.
        #[arg(long, value_name = "N")]
        dump_after_frame: Option<usize>,

        /// Size of the guest malloc / `HeapAlloc` arena in MiB.
        /// Raise it when a decoder exhausts the default (96 MiB)
        /// arena mid-decode. Clamped to `[96, 256]`.
        #[arg(long, value_name = "MiB", default_value_t = ud_emulator::Sandbox::DEFAULT_HEAP_MB)]
        heap_mb: u32,

        /// Watch a guest-memory region and record every store into
        /// it during the decode as an ordered behavioral trace —
        /// `ADDR:LEN` (decimal or `0x` hex), repeatable. Each hit is
        /// printed to **stderr** as `#seq +off [addr] = value (wN)
        /// eip=…`, so you get a byte-exact, per-write account of how
        /// the *real* codec fills a table (window / codebook /
        /// coupling / coefficient buffer) — ud as an instrumented
        /// reference decoder. Watchpoints arm just before the frame
        /// loop; use `--dump-mem` for the final contents.
        #[arg(long, value_name = "ADDR:LEN")]
        watch: Vec<String>,
    },

    /// Drive `ICCompress` on uncompressed pixel input: load
    /// the codec DLL, run `DllMain`, open the codec in
    /// compress mode, query / begin / compress / end / close.
    /// Outputs the encoded codec bitstream.
    Encode {
        /// Codec DLL.
        dll: PathBuf,

        /// Raw uncompressed pixel input (no header — bytes
        /// only). Required.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,

        /// Input frame width (pixels).
        #[arg(long)]
        width: u32,

        /// Input frame height (pixels).
        #[arg(long)]
        height: u32,

        /// FourCC handler override.
        #[arg(long = "fcc-handler", value_name = "FCC")]
        fcc_handler: Option<String>,

        /// Uncompressed-input pixel format.
        #[arg(long = "input-format", value_enum, default_value_t = InputFormat::Bgr24)]
        input_format: InputFormat,

        /// Encoder quality (VfW convention, `0..=10000`).
        #[arg(long, default_value_t = 5000)]
        quality: u32,

        /// Request a keyframe (sets `ICCOMPRESS_KEYFRAME`).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        keyframe: bool,

        /// Write encoded frame here. Defaults to stdout.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Cap the run at this many guest instructions.
        #[arg(long, default_value_t = 100_000_000)]
        max_instructions: u64,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
enum PixFormat {
    Rgb24,
    Rgb32,
    Yuv,
}

impl PixFormat {
    fn bi_bit_count(self) -> u16 {
        match self {
            PixFormat::Rgb24 => 24,
            PixFormat::Rgb32 => 32,
            PixFormat::Yuv => 16,
        }
    }
    fn bi_compression(self) -> [u8; 4] {
        match self {
            PixFormat::Rgb24 | PixFormat::Rgb32 => [0; 4],
            PixFormat::Yuv => *b"YUY2",
        }
    }
    fn bytes_per_pixel(self) -> u32 {
        match self {
            PixFormat::Rgb24 => 3,
            PixFormat::Rgb32 => 4,
            PixFormat::Yuv => 2,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
enum InputFormat {
    Bgr24,
    Bgr32,
    Yv12,
    I420,
    Yuy2,
}

impl InputFormat {
    fn bi_bit_count(self) -> u16 {
        match self {
            InputFormat::Bgr24 => 24,
            InputFormat::Bgr32 => 32,
            InputFormat::Yv12 | InputFormat::I420 => 12,
            InputFormat::Yuy2 => 16,
        }
    }
    fn bi_compression(self) -> [u8; 4] {
        match self {
            InputFormat::Bgr24 | InputFormat::Bgr32 => [0; 4],
            InputFormat::Yv12 => *b"YV12",
            InputFormat::I420 => *b"I420",
            InputFormat::Yuy2 => *b"YUY2",
        }
    }
    fn frame_bytes(self, width: u32, height: u32) -> u32 {
        let pixels = width.saturating_mul(height);
        match self {
            InputFormat::Bgr24 => pixels * 3,
            InputFormat::Bgr32 => pixels * 4,
            InputFormat::Yv12 | InputFormat::I420 => pixels * 3 / 2,
            InputFormat::Yuy2 => pixels * 2,
        }
    }
}

fn main() -> ExitCode {
    // Populate the arch-codec registry. Every binary that uses
    // the framework needs this once at startup; calling it
    // before the CLI parse keeps it out of any subcommand-specific
    // path so the registry is ready regardless of which command
    // ran.
    ud_translate::register_all_arches();

    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ud: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Roundtrip {
            input,
            out,
            through_source,
        } => {
            let output = out.unwrap_or_else(|| {
                let mut p = input.clone().into_os_string();
                p.push(".rebuilt");
                PathBuf::from(p)
            });
            if through_source {
                let report =
                    ud_cli::roundtrip_through_source(&input, &output).with_context(|| {
                        format!(
                            "source round-trip from {} to {}",
                            input.display(),
                            output.display()
                        )
                    })?;
                for w in &report.warnings {
                    eprintln!("warning: {}", format_warning(w));
                }
                if !report.warnings.is_empty() {
                    eprintln!("({} verify warning(s))", report.warnings.len());
                }
                if report.byte_identical {
                    println!(
                        "source round-trip ok: {} == {} ({} bytes)",
                        input.display(),
                        output.display(),
                        report.input_len,
                    );
                } else {
                    let offset = report
                        .first_diff_offset
                        .map_or("?".into(), |o| format!("0x{o:x}"));
                    println!(
                        "source round-trip differs: {} != {} (input {} bytes, output {} bytes; first diff at {})",
                        input.display(),
                        output.display(),
                        report.input_len,
                        report.output_len,
                        offset,
                    );
                    if let Some(ctx) = &report.diff_context {
                        eprintln!(
                            "input  @ 0x{:x}: {}",
                            ctx.window_start,
                            hex_window(&ctx.input_window)
                        );
                        eprintln!(
                            "output @ 0x{:x}: {}",
                            ctx.window_start,
                            hex_window(&ctx.output_window)
                        );
                    }
                }
                Ok(())
            } else {
                ud_cli::roundtrip(&input, &output).with_context(|| {
                    format!(
                        "round-trip from {} to {}",
                        input.display(),
                        output.display()
                    )
                })?;
                println!("round-trip ok: {} == {}", input.display(), output.display());
                Ok(())
            }
        }
        Command::Decompile { input, out } => {
            let bytes =
                std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
            let source = if ud_format::elf::is_elf64_le(&bytes) {
                let elf = ud_format::elf::Elf64File::parse(&bytes)
                    .with_context(|| format!("parse {} as ELF", input.display()))?;
                ud_translate::decompile::decompile_to_text(&elf)
                    .with_context(|| format!("decompile {}", input.display()))?
            } else if ud_format::ne::is_ne(&bytes) {
                // Before PE: both start with `MZ`, and `is_pe` checks only
                // that, so the 16-bit NE has to be detected first.
                let ne = ud_format::ne::NeFile::parse(&bytes)
                    .with_context(|| format!("parse {} as NE", input.display()))?;
                ud_translate::decompile::decompile_ne_to_text(&ne)
            } else if ud_format::pe::is_pe(&bytes) {
                let pe = ud_format::pe::PeFile::parse(&bytes)
                    .with_context(|| format!("parse {} as PE", input.display()))?;
                ud_translate::decompile::decompile_pe_to_text(&pe)
            } else if ud_format::macho::is_macho64(&bytes) {
                let macho = ud_format::macho::MachoFile::parse(&bytes)
                    .with_context(|| format!("parse {} as Mach-O", input.display()))?;
                ud_translate::decompile::decompile_macho_to_text(&macho)
            } else if ud_format::wasm::is_wasm(&bytes) {
                let wasm = ud_format::wasm::WasmFile::parse(&bytes)
                    .with_context(|| format!("parse {} as WASM", input.display()))?;
                ud_translate::decompile::decompile_wasm_to_text(&wasm)
            } else if let Some(load_addr) = ud_cli::raw_6502_load_addr(&bytes) {
                let image = ud_format::raw::RawImage::new(bytes, load_addr);
                ud_translate::decompile::decompile_raw_6502_to_text(&image)
                    .with_context(|| format!("decompile {} as 6502 raw", input.display()))?
            } else {
                anyhow::bail!(
                    "unrecognised binary format: {} (expected ELF, PE, NE, Mach-O, WASM, or 6502 raw image)",
                    input.display()
                );
            };
            if let Some(path) = out {
                std::fs::write(&path, source)
                    .with_context(|| format!("write {}", path.display()))?;
            } else {
                use std::io::Write as _;
                std::io::stdout().write_all(source.as_bytes())?;
            }
            Ok(())
        }
        Command::Verify { input } => {
            let text = std::fs::read_to_string(&input)
                .with_context(|| format!("read {}", input.display()))?;
            let ast = ud_translate::compile::parse(&text)
                .with_context(|| format!("parse {}", input.display()))?;
            let warnings = ud_translate::compile::verify_asm(&ast);
            if warnings.is_empty() {
                println!(
                    "ok: {} ({} item{})",
                    input.display(),
                    ast.items.len(),
                    if ast.items.len() == 1 { "" } else { "s" }
                );
                return Ok(());
            }
            for w in &warnings {
                eprintln!("{}", format_warning(w));
            }
            eprintln!("{} warning(s) in {}", warnings.len(), input.display());
            Ok(())
        }
        Command::Compile { input, out } => {
            let output = out.unwrap_or_else(|| {
                let mut p = input.clone().into_os_string();
                p.push(".bin");
                PathBuf::from(p)
            });
            let text = std::fs::read_to_string(&input)
                .with_context(|| format!("read {}", input.display()))?;
            let ast = ud_translate::compile::parse(&text)
                .with_context(|| format!("parse {}", input.display()))?;
            let format = ast
                .module
                .fields
                .iter()
                .find(|f| f.name == "format")
                .and_then(|f| match &f.value {
                    ud_ast::Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("`@module.format` is missing — expected \"elf\", \"pe\", \"ne\", \"macho\", \"wasm\", or \"raw\"")
                })?;
            let bytes = match format.as_str() {
                "elf" => ud_translate::compile::lower_to_elf(&ast)
                    .with_context(|| format!("lower {} to ELF", input.display()))?,
                "pe" => ud_translate::compile::lower_to_pe(&ast)
                    .with_context(|| format!("lower {} to PE", input.display()))?,
                "ne" => ud_translate::compile::lower_to_ne(&ast)
                    .with_context(|| format!("lower {} to NE", input.display()))?,
                "macho" => ud_translate::compile::lower_to_macho(&ast)
                    .with_context(|| format!("lower {} to Mach-O", input.display()))?,
                "wasm" => ud_translate::compile::lower_to_wasm(&ast)
                    .with_context(|| format!("lower {} to WASM", input.display()))?,
                "raw" => ud_translate::compile::lower_to_raw(&ast)
                    .with_context(|| format!("lower {} to raw", input.display()))?,
                other => anyhow::bail!(
                    "unsupported `@module.format` value {other:?} (expected \"elf\", \"pe\", \"ne\", \"macho\", \"wasm\", or \"raw\")"
                ),
            };
            std::fs::write(&output, &bytes)
                .with_context(|| format!("write {}", output.display()))?;
            println!(
                "compiled: {} → {} ({} bytes, format: {})",
                input.display(),
                output.display(),
                bytes.len(),
                format,
            );
            Ok(())
        }
        Command::Analyze {
            input,
            max_instructions,
            json,
            monitor,
            args,
            dump_vfs,
            kvm,
            net,
            interactive,
            fs_type,
            mount,
            no_default_mounts,
            rootfs,
            preserve_deletes,
            fail_soft,
            stage_vfs,
            vfs_deps,
            call_export,
            export_arg,
            call,
            dump_mem,
            map_blob,
            heap_mb,
            watch,
        } => {
            if monitor {
                monitor_install(
                    &input,
                    max_instructions,
                    json,
                    args.as_deref(),
                    dump_vfs.as_deref(),
                    preserve_deletes,
                    kvm,
                    net,
                    interactive,
                    &FsOpts {
                        fs_type,
                        mounts: mount,
                        no_default_mounts,
                        rootfs,
                    },
                )
            } else {
                analyze(
                    &input,
                    max_instructions,
                    json,
                    fail_soft || vfs_deps,
                    &stage_vfs,
                    vfs_deps,
                    &call_export,
                    &export_arg,
                    &call,
                    &dump_mem,
                    &map_blob,
                    heap_mb,
                    &watch,
                )
            }
        }
        Command::Solana {
            program_id,
            rpc,
            no_cache,
            save_elf,
            out,
        } => solana_cmd(
            &program_id,
            &rpc,
            !no_cache,
            save_elf.as_deref(),
            out.as_deref(),
        ),
        Command::Vfw { command } => match command {
            VfwCommand::Probe {
                dll,
                fcc_handler,
                pix_format,
                width,
                height,
                max_instructions,
            } => vfw_probe(
                &dll,
                fcc_handler.as_deref(),
                pix_format,
                width,
                height,
                max_instructions,
            ),
            VfwCommand::Decode {
                dll,
                input,
                width,
                height,
                fcc_handler,
                pix_format,
                output,
                max_instructions,
                dump_mem,
                dump_after_frame,
                heap_mb,
                watch,
            } => decode_cmd(
                &dll,
                &input,
                width,
                height,
                fcc_handler.as_deref(),
                pix_format,
                output.as_deref(),
                max_instructions,
                &dump_mem,
                dump_after_frame,
                heap_mb,
                &watch,
            ),
            VfwCommand::Encode {
                dll,
                input,
                width,
                height,
                fcc_handler,
                input_format,
                quality,
                keyframe,
                output,
                max_instructions,
            } => encode_cmd(
                &dll,
                &input,
                width,
                height,
                fcc_handler.as_deref(),
                input_format,
                quality,
                keyframe,
                output.as_deref(),
                max_instructions,
            ),
        },
        Command::Qtcodec { command } => match command {
            QtcodecCommand::Register {
                codec,
                export,
                ty,
                subtype,
                manufacturer,
                stage_vfs,
                max_instructions,
            } => qtcodec_register(
                &codec,
                &export,
                &ty,
                &subtype,
                &manufacturer,
                &stage_vfs,
                max_instructions,
            ),
            QtcodecCommand::List {
                ty,
                subtype,
                manufacturer,
                stage_vfs,
                install_msi,
                max_instructions,
            } => qtcodec_list(
                &ty,
                &subtype,
                &manufacturer,
                &stage_vfs,
                &install_msi,
                max_instructions,
            ),
            QtcodecCommand::Call {
                dll,
                export,
                arg,
                stage_vfs,
                max_instructions,
            } => qtcodec_call(&dll, &export, &arg, &stage_vfs, max_instructions),
            QtcodecCommand::Dispatch {
                codec,
                export,
                selector,
                param,
                storage,
                stage_vfs,
                max_instructions,
            } => qtcodec_dispatch(
                &codec,
                &export,
                selector,
                &param,
                storage,
                &stage_vfs,
                max_instructions,
            ),
        },

        #[cfg(feature = "script")]
        Command::Script {
            file,
            heap_mb,
            max_instructions,
        } => script::run_script(&file, heap_mb, max_instructions),
    }
}

fn fourcc_to_u32(s: &str) -> u32 {
    let mut b = [b' '; 4];
    for (i, c) in s.bytes().take(4).enumerate() {
        b[i] = c;
    }
    u32::from_le_bytes(b)
}

fn derive_default_fcc(p: &Path) -> String {
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_uppercase())
        .unwrap_or_default();
    if stem.contains("IR32") {
        "IV31".into()
    } else if stem.contains("IR41") {
        "IV41".into()
    } else if stem.contains("IR50") {
        "IV50".into()
    } else if stem.contains("CVID") || stem.contains("ICCVID") {
        "cvid".into()
    } else if stem.contains("MPG4C32") || stem.contains("MPG4") {
        "MP43".into()
    } else {
        "IV31".into()
    }
}

const ICMODE_DECOMPRESS: u32 = 1;
const ICMODE_COMPRESS: u32 = 2;
const ICCOMPRESS_KEYFRAME: u32 = 0x0000_0001;

/// Scratch address inside the heap arena, chosen so it's above
/// any reasonable codec allocation made during DllMain. The
/// heap allocator grows up from `HEAP_ARENA_START` (0x6000_0000);
/// the slot sits just below `HEAP_ARENA_END` (0x6600_0000) giving
/// the codec ~95 MiB before the scratch range collides.
const QTCODEC_SCRATCH: u32 = 0x65FE_0000;

/// Drive `qtmlclient!InitializeQTML(0)` so the QT runtime's
/// dispatcher slots get repointed from `BogusDispatcher`
/// (return 0xF7D1) to the real `theQuickTimeDispatcher` in
/// quicktime.qts. Must be called AFTER `preload_qt_runtime`.
/// Returns the function's status code (0 = noErr).
fn init_qtml(sandbox: &mut ud_emulator::Sandbox) -> u32 {
    let Some(target) = sandbox.registry.resolve("qtmlclient.dll", "InitializeQTML") else {
        eprintln!("init_qtml: qtmlclient!InitializeQTML not in registry — pre-load missed?");
        return u32::MAX;
    };
    // Clear any sticky exit_requested left from a prior
    // call_guest that hit ExitProcess / TerminateProcess —
    // otherwise run_until_sentinel bails immediately on the
    // next call without executing a single instruction.
    sandbox.host.exit_requested = None;
    let stub_before = sandbox.host.stub_calls.len();
    let result = ud_emulator::win32::call_guest(
        &mut sandbox.cpu,
        &mut sandbox.mmu,
        &mut sandbox.registry,
        &mut sandbox.host,
        target,
        &[0],
    );
    let calls = &sandbox.host.stub_calls[stub_before..];
    if !calls.is_empty() {
        eprintln!("--- {} stub calls during InitializeQTML ---", calls.len());
        for c in calls.iter().take(40) {
            let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
            let eip = c.call_site_eip;
            eprintln!(
                "  {eip:#010x} {}!{}({}) -> {:#x}",
                c.dll,
                c.name,
                args.join(", "),
                c.ret
            );
        }
        if calls.len() > 40 {
            eprintln!("  … ({} more)", calls.len() - 40);
        }
    }
    match result {
        Ok(v) => {
            eprintln!("InitializeQTML(0) = {v:#x}");
            v
        }
        Err(e) => {
            eprintln!(
                "InitializeQTML(0) trapped: {e} (eip={:#010x})",
                sandbox.cpu.regs.eip
            );
            u32::MAX
        }
    }
}

/// Pre-load the QT runtime DLLs (qtmlclient.dll + quicktime.qts)
/// from the sandbox VFS if present. The codec / app doesn't
/// statically import them — they're picked up at runtime via
/// LoadLibraryA / GetProcAddress — and our `LoadLibraryA` stub
/// only consults already-loaded modules in `state.modules`, so
/// pre-loading bridges that gap.
fn preload_qt_runtime(sandbox: &mut ud_emulator::Sandbox) {
    for runtime_dll in &["qtmlclient.dll", "quicktime.qts"] {
        let path = sandbox.context().vfs.as_ref().and_then(|v| {
            for prefix in ud_emulator::win32::dll_vfs_search_paths() {
                let p = format!("{prefix}{runtime_dll}");
                if v.read(&p).is_some() {
                    return Some(p);
                }
            }
            None
        });
        let Some(path) = path else { continue };
        let dll_bytes = sandbox
            .context()
            .vfs
            .as_ref()
            .and_then(|v| v.read(&path))
            .map(<[u8]>::to_vec);
        let Some(dll_bytes) = dll_bytes else { continue };
        match sandbox.load_with_deps(runtime_dll, &dll_bytes) {
            Ok((img, _)) => {
                eprintln!(
                    "pre-loaded {runtime_dll} at {:#010x} ({} exports)",
                    img.image_base,
                    img.exports.len()
                );
                for (name, rva) in &img.exports {
                    sandbox.registry.register_guest_export(
                        runtime_dll,
                        name,
                        img.image_base.wrapping_add(*rva),
                    );
                }
                let stub_before = sandbox.host.stub_calls.len();
                match sandbox.call_dll_main(&img, ud_emulator::DLL_PROCESS_ATTACH) {
                    Ok(rc) => eprintln!("  {runtime_dll}: DllMain returned {rc:#x}"),
                    Err(e) => eprintln!(
                        "  {runtime_dll}: DllMain trapped: {e} (eip={:#010x})",
                        sandbox.cpu.regs.eip
                    ),
                }
                let calls = &sandbox.host.stub_calls[stub_before..];
                if !calls.is_empty() {
                    eprintln!(
                        "  --- {} stub calls during {runtime_dll} DllMain ---",
                        calls.len()
                    );
                    for c in calls.iter().take(500) {
                        let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
                        let eip = c.call_site_eip;
                        eprintln!(
                            "    {eip:#010x} {}!{}({}) -> {:#x}",
                            c.dll,
                            c.name,
                            args.join(", "),
                            c.ret
                        );
                    }
                    if calls.len() > 500 {
                        eprintln!("    … ({} more)", calls.len() - 500);
                    }
                }
            }
            Err(e) => eprintln!("pre-load {runtime_dll}: {e}"),
        }
    }
}

fn fourcc_be(s: &str) -> u32 {
    if let Ok(v) = parse_u32(s) {
        if v == 0 {
            return 0;
        }
    }
    let mut b = [b' '; 4];
    for (i, c) in s.bytes().take(4).enumerate() {
        b[i] = c;
    }
    // OSType is Big-Endian — 'imdc' → 0x696d_6463
    u32::from_be_bytes(b)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn qtcodec_register(
    codec: &Path,
    export: &str,
    ty: &str,
    subtype: &str,
    manufacturer: &str,
    stage_vfs: &[PathBuf],
    max_instructions: u64,
) -> anyhow::Result<()> {
    let codec_bytes = std::fs::read(codec).with_context(|| format!("read {}", codec.display()))?;
    let codec_stem = codec
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("codec.qtx");

    let ty_v = fourcc_be(ty);
    let sub_v = fourcc_be(subtype);
    let man_v = fourcc_be(manufacturer);

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.trace_stubs = true;
    sandbox.host.instruction_budget = Some(max_instructions);
    sandbox
        .context_mut()
        .vfs
        .get_or_insert_with(ud_emulator::fsmount::MountTable::new);
    for d in stage_vfs {
        let n = stage_dir_into_vfs(sandbox.context_mut(), d)
            .with_context(|| format!("stage {}", d.display()))?;
        eprintln!("staged {n} files from {}", d.display());
    }
    preload_qt_runtime(&mut sandbox);

    let init_rc = init_qtml(&mut sandbox);
    if init_rc != 0 {
        anyhow::bail!("InitializeQTML failed: {init_rc:#x}");
    }
    if let Some(target) = sandbox.registry.resolve("qtmlclient.dll", "EnterMovies") {
        match ud_emulator::win32::call_guest(
            &mut sandbox.cpu,
            &mut sandbox.mmu,
            &mut sandbox.registry,
            &mut sandbox.host,
            target,
            &[],
        ) {
            Ok(v) => eprintln!("EnterMovies() = {v:#x}"),
            Err(e) => eprintln!("EnterMovies() trapped: {e}"),
        }
    }

    // Load the codec.
    let (image, _) = sandbox
        .load_with_deps(codec_stem, &codec_bytes)
        .with_context(|| format!("load {}", codec.display()))?;
    eprintln!("loaded {codec_stem} at {:#010x}", image.image_base);
    if let Err(e) = sandbox.call_dll_main(&image, ud_emulator::DLL_PROCESS_ATTACH) {
        eprintln!("{codec_stem}: DllMain trapped: {e}");
    }
    let Some(entry_rva) = image.exports.get(export) else {
        anyhow::bail!("codec doesn't export {export}");
    };
    let entry_va = image.image_base.wrapping_add(*entry_rva);
    eprintln!("dispatch entry {export} @ {entry_va:#010x}");

    // ComponentDescription { type, subType, manufacturer,
    // flags, flagsMask } — 5 dwords.
    let desc_addr = QTCODEC_SCRATCH + 0x10000;
    let words = [ty_v, sub_v, man_v, 0, 0];
    for (i, w) in words.iter().enumerate() {
        sandbox
            .mmu
            .store32(desc_addr + u32::try_from(i).unwrap_or(0) * 4, *w)
            .map_err(|e| anyhow::anyhow!("write CD[{i}]: {e}"))?;
    }
    eprintln!(
        "ComponentDescription @ {desc_addr:#x}: type={ty_v:#x} subType={sub_v:#x} mfr={man_v:#x}"
    );

    // Call RegisterComponent(&desc, entry_va, 0, 0, 0, 0)
    let Some(target) = sandbox
        .registry
        .resolve("qtmlclient.dll", "RegisterComponent")
    else {
        anyhow::bail!("qtmlclient!RegisterComponent missing");
    };
    let result = ud_emulator::win32::call_guest(
        &mut sandbox.cpu,
        &mut sandbox.mmu,
        &mut sandbox.registry,
        &mut sandbox.host,
        target,
        &[desc_addr, entry_va, 0, 0, 0, 0],
    );
    match result {
        Ok(v) => println!("RegisterComponent = {v:#010x} (component handle)"),
        Err(e) => {
            eprintln!("RegisterComponent trapped: {e}");
            return Err(anyhow::anyhow!("{e}"));
        }
    }

    // Now verify with CountComponents
    let Some(target) = sandbox
        .registry
        .resolve("qtmlclient.dll", "CountComponents")
    else {
        anyhow::bail!("CountComponents missing");
    };
    match ud_emulator::win32::call_guest(
        &mut sandbox.cpu,
        &mut sandbox.mmu,
        &mut sandbox.registry,
        &mut sandbox.host,
        target,
        &[desc_addr],
    ) {
        Ok(v) => println!("CountComponents after register = {v}"),
        Err(e) => eprintln!("CountComponents trapped: {e}"),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn qtcodec_list(
    ty: &str,
    subtype: &str,
    manufacturer: &str,
    stage_vfs: &[PathBuf],
    install_msi: &[PathBuf],
    max_instructions: u64,
) -> anyhow::Result<()> {
    let ty_v = fourcc_be(ty);
    let sub_v = fourcc_be(subtype);
    let man_v = fourcc_be(manufacturer);

    // Run any --install-msi installs in a SEPARATE sandbox
    // first, then copy the post-install VFS + registry into a
    // fresh sandbox that brings up the QT runtime. Doing both
    // in the same sandbox leaves residual state (sticky
    // exit_requested, scheduler-side terminated threads, CRT
    // globals in install DLLs) that breaks the qtmlclient.dll
    // bootstrap.
    let mut staged_vfs = ud_emulator::context::VirtualFs::new();
    let mut staged_reg = ud_emulator::context::VirtualRegistry::new();
    // First load the --stage-vfs trees into a temporary
    // context so we can carry their contents across.
    {
        let mut tmp_ctx = ud_emulator::context::Context {
            vfs: Some(ud_emulator::fsmount::MountTable::new()),
            ..ud_emulator::context::Context::default()
        };
        for d in stage_vfs {
            let n = stage_dir_into_vfs(&mut tmp_ctx, d)
                .with_context(|| format!("stage {}", d.display()))?;
            eprintln!("staged {n} files from {}", d.display());
        }
        if let Some(v) = tmp_ctx.vfs.take() {
            for (p, _) in v.list() {
                if let Some(b) = v.read(p) {
                    staged_vfs.insert(p, b.to_vec());
                }
            }
        }
    }
    if !install_msi.is_empty() {
        let mut install_sb = ud_emulator::Sandbox::new();
        install_sb.host.trace_stubs = true;
        install_sb.host.instruction_budget = Some(max_instructions);
        install_sb.context_mut().vfs = Some(ud_emulator::fsmount::MountTable::with_root(
            staged_vfs.clone(),
        ));
        install_sb.context_mut().registry = Some(staged_reg.clone());
        for msi_path in install_msi {
            let bytes =
                std::fs::read(msi_path).with_context(|| format!("read {}", msi_path.display()))?;
            let stage_key = format!(
                "c:/temp/install_{}.msi",
                msi_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("pkg")
            );
            if let Some(vfs) = install_sb.context_mut().vfs.as_mut() {
                vfs.insert(&stage_key, bytes);
            }
            let synth_cmd = format!("msiexec.exe /i \"{stage_key}\"");
            ud_emulator::win32::msiexec::dispatch_msiexec_install(
                &mut install_sb.host,
                &mut install_sb.mmu,
                &stage_key,
                &synth_cmd,
            );
            let pumped = install_sb.pump_pending_msi_install();
            eprintln!(
                "installed {} — pumped {pumped} deferred CustomAction(s)",
                msi_path.display()
            );
        }
        // Carry post-install state into the runtime sandbox.
        if let Some(v) = install_sb.context().vfs.as_ref() {
            for (p, _) in v.list() {
                if let Some(b) = v.read(p) {
                    staged_vfs.insert(p, b.to_vec());
                }
            }
        }
        if let Some(r) = install_sb.context().registry.as_ref() {
            for (k, n, v) in r.all_values() {
                staged_reg.set_value(k, n, v.clone());
            }
        }
    }

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.trace_stubs = true;
    sandbox.host.instruction_budget = Some(max_instructions);
    sandbox.context_mut().vfs = Some(ud_emulator::fsmount::MountTable::with_root(staged_vfs));
    sandbox.context_mut().registry = Some(staged_reg);
    preload_qt_runtime(&mut sandbox);

    let init_rc = init_qtml(&mut sandbox);
    if init_rc != 0 {
        anyhow::bail!("InitializeQTML failed: {init_rc:#x}");
    }
    // EnterMovies
    if let Some(target) = sandbox.registry.resolve("qtmlclient.dll", "EnterMovies") {
        sandbox.host.exit_requested = None;
        let before = sandbox.host.stub_calls.len();
        match ud_emulator::win32::call_guest(
            &mut sandbox.cpu,
            &mut sandbox.mmu,
            &mut sandbox.registry,
            &mut sandbox.host,
            target,
            &[],
        ) {
            Ok(v) => eprintln!("EnterMovies() = {v:#x}"),
            Err(e) => eprintln!(
                "EnterMovies() trapped: {e} (eip={:#010x})",
                sandbox.cpu.regs.eip
            ),
        }
        let calls = &sandbox.host.stub_calls[before..];
        eprintln!("--- {} stub calls during EnterMovies ---", calls.len());
        for c in calls.iter().take(60) {
            let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
            let eip = c.call_site_eip;
            eprintln!(
                "  {eip:#010x} {}!{}({}) -> {:#x}",
                c.dll,
                c.name,
                args.join(", "),
                c.ret
            );
        }
        if calls.len() > 60 {
            eprintln!("  … ({} more)", calls.len() - 60);
        }
    }
    // Build ComponentDescription { type, subType, manufacturer, flags, flagsMask }
    let desc_addr = QTCODEC_SCRATCH + 0x10000;
    let words = [ty_v, sub_v, man_v, 0, 0];
    for (i, w) in words.iter().enumerate() {
        sandbox
            .mmu
            .store32(desc_addr + u32::try_from(i).unwrap_or(0) * 4, *w)
            .map_err(|e| anyhow::anyhow!("write CD[{i}]: {e}"))?;
    }
    eprintln!(
        "ComponentDescription @ {desc_addr:#x}: type={ty_v:#x} subType={sub_v:#x} mfr={man_v:#x}"
    );
    // Call CountComponents(&desc)
    let Some(target) = sandbox
        .registry
        .resolve("qtmlclient.dll", "CountComponents")
    else {
        anyhow::bail!("qtmlclient!CountComponents not in registry");
    };
    let stub_before = sandbox.host.stub_calls.len();
    match ud_emulator::win32::call_guest(
        &mut sandbox.cpu,
        &mut sandbox.mmu,
        &mut sandbox.registry,
        &mut sandbox.host,
        target,
        &[desc_addr],
    ) {
        Ok(v) => {
            println!("CountComponents(type={ty:?}, subType={subtype:?}) = {v}");
        }
        Err(e) => {
            eprintln!("CountComponents trapped: {e}");
        }
    }
    // Show the stubs CountComponents made (if any) — useful
    // to find what scan it needs (FindFirstFile/RegOpenKey/etc).
    let calls = &sandbox.host.stub_calls[stub_before..];
    eprintln!("--- {} stub calls during CountComponents ---", calls.len());
    for c in calls.iter().take(30) {
        let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
        let arg_str = args.join(", ");
        let eip = c.call_site_eip;
        eprintln!(
            "  {eip:#010x} {}!{}({arg_str}) -> {:#x}",
            c.dll, c.name, c.ret
        );
    }
    // Try OpenADefaultComponent — sometimes triggers the
    // component scan as a side effect.
    if let Some(target) = sandbox
        .registry
        .resolve("qtmlclient.dll", "OpenADefaultComponent")
    {
        let stub_before = sandbox.host.stub_calls.len();
        sandbox.host.exit_requested = None;
        match ud_emulator::win32::call_guest(
            &mut sandbox.cpu,
            &mut sandbox.mmu,
            &mut sandbox.registry,
            &mut sandbox.host,
            target,
            &[ty_v, sub_v],
        ) {
            Ok(v) => println!("OpenADefaultComponent({ty:?}, {subtype:?}) = {v:#x}"),
            Err(e) => eprintln!("OpenADefaultComponent trapped: {e}"),
        }
        let calls = &sandbox.host.stub_calls[stub_before..];
        eprintln!(
            "--- {} stub calls during OpenADefaultComponent ---",
            calls.len()
        );
        for c in calls.iter().take(20) {
            let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
            let eip = c.call_site_eip;
            eprintln!(
                "  {eip:#010x} {}!{}({}) -> {:#x}",
                c.dll,
                c.name,
                args.join(", "),
                c.ret
            );
        }
    }
    // Also try FindNextComponent which may lazily scan
    if let Some(target) = sandbox
        .registry
        .resolve("qtmlclient.dll", "FindNextComponent")
    {
        let stub_before = sandbox.host.stub_calls.len();
        match ud_emulator::win32::call_guest(
            &mut sandbox.cpu,
            &mut sandbox.mmu,
            &mut sandbox.registry,
            &mut sandbox.host,
            target,
            &[0, desc_addr], // (NULL, &desc) — find first matching
        ) {
            Ok(v) => println!("FindNextComponent(NULL, &desc) = {v:#x}"),
            Err(e) => eprintln!("FindNextComponent trapped: {e}"),
        }
        let calls = &sandbox.host.stub_calls[stub_before..];
        eprintln!(
            "--- {} stub calls during FindNextComponent ---",
            calls.len()
        );
        for c in calls.iter().take(30) {
            let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
            let arg_str = args.join(", ");
            let eip = c.call_site_eip;
            eprintln!(
                "  {eip:#010x} {}!{}({arg_str}) -> {:#x}",
                c.dll, c.name, c.ret
            );
        }
    }
    // Diagnostic: read qts internal CM state to see what the dispatch
    // table + global state look like at runtime.
    let probe_addrs = &[
        (0x6735_6240u32, "dispatch_table[cat 0..3] (32 bytes)"),
        (0x6738_6860u32, "CM global state struct (32 bytes)"),
        (0x6734_a4ecu32, "[CM global ptr]"),
        (0x6734_a4e0u32, "[QT dispatcher ptr]"),
        (0x6688_45b0u32, "theQuickTimeDispatcher prologue (32 bytes)"),
        (0x6735_6248u32, "cat[1] entry (8 bytes raw)"),
        (0x1004_dcd0u32, "qtmlclient init flag (4 bytes)"),
        (
            0x1004_dcdcu32,
            "qtmlclient->theQuickTimeDispatcher (4 bytes)",
        ),
        (0x1002_4220u32, "qtmlclient!RegisterComponent (16 bytes)"),
        (0x6688_4890u32, "cat[1].subtable stub (16 bytes)"),
        (0x6734_7000u32, "qts CRT-init flag (4 bytes)"),
        (0x6734_7004u32, "qts TLS slot index (4 bytes)"),
        (0x6738_51e8u32, "qts thread-data lock (4 bytes)"),
        (0x6738_51ecu32, "qts thread-data list head (4 bytes)"),
        (0x7FFD_DFF0u32, "page below TEB (32 bytes)"),
        (0x7FFD_E000u32, "TEB start (32 bytes)"),
        (
            0x4003_80a0u32,
            "libdispatch IAT slot range (32 bytes incl _initterm)",
        ),
        (
            0x4003_80e0u32,
            "libdispatch IAT slot range (32 bytes incl pthread_setspecific @ +0x10)",
        ),
    ];
    eprintln!("--- runtime CM state ---");
    for (a, label) in probe_addrs {
        let mut bytes = [0u8; 32];
        let mut ok = true;
        for (i, slot) in bytes.iter_mut().enumerate() {
            if let Ok(b) = sandbox.mmu.load8(a.wrapping_add(i as u32)) {
                *slot = b;
            } else {
                ok = false;
                break;
            }
        }
        if ok {
            let hex: String = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            eprintln!("  0x{a:08x} ({label}): {hex}");
        } else {
            eprintln!("  0x{a:08x} ({label}): UNMAPPED");
        }
    }
    Ok(())
}

fn qtcodec_call(
    dll: &Path,
    export: &str,
    args: &[u32],
    stage_vfs: &[PathBuf],
    max_instructions: u64,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(dll).with_context(|| format!("read {}", dll.display()))?;
    let stem = dll.file_name().and_then(|s| s.to_str()).unwrap_or("qtdll");

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.trace_stubs = true;
    sandbox.host.instruction_budget = Some(max_instructions);
    sandbox
        .context_mut()
        .vfs
        .get_or_insert_with(ud_emulator::fsmount::MountTable::new);
    for d in stage_vfs {
        let n = stage_dir_into_vfs(sandbox.context_mut(), d)
            .with_context(|| format!("stage {}", d.display()))?;
        eprintln!("staged {n} files from {}", d.display());
    }
    preload_qt_runtime(&mut sandbox);
    let (image, _) = sandbox
        .load_with_deps(stem, &bytes)
        .with_context(|| format!("load_with_deps {}", dll.display()))?;
    eprintln!("loaded {} at {:#010x}", stem, image.image_base);
    match sandbox.call_dll_main(&image, ud_emulator::DLL_PROCESS_ATTACH) {
        Ok(v) => eprintln!("DllMain returned {v:#x}"),
        Err(e) => eprintln!("DllMain trapped: {e}"),
    }
    // Bring the QT runtime up so the dispatcher slots are
    // real (theQuickTimeDispatcher in quicktime.qts) — without
    // this every qtmlclient call returns 0xF7D1 from
    // BogusDispatcher. Skip when the user is calling
    // InitializeQTML itself (avoid the double-init).
    if export != "InitializeQTML" {
        init_qtml(&mut sandbox);
    }
    eprintln!("calling {export}({args:?})");
    sandbox.host.stub_calls.clear();
    let res = sandbox.call_export(&image, export, args);
    let calls = std::mem::take(&mut sandbox.host.stub_calls);
    match res {
        Ok(ret) => {
            #[allow(clippy::cast_possible_wrap)]
            let signed = ret as i32;
            println!("{export}: ret = {ret:#010x} ({signed})");
        }
        Err(e) => {
            eprintln!("{export}: trapped: {e}");
        }
    }
    eprintln!("--- {} stub calls during {export} ---", calls.len());
    for c in &calls {
        let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
        let eip = c.call_site_eip;
        let arg_str = args.join(", ");
        eprintln!(
            "  {eip:#010x} {}!{}({arg_str}) -> {:#x}",
            c.dll, c.name, c.ret
        );
    }
    for line in &sandbox.host.debug_log {
        eprintln!("  {line}");
    }
    Ok(())
}

fn parse_u32(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(rest, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u32>().map_err(|e| e.to_string())
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn qtcodec_dispatch(
    codec: &Path,
    export: &str,
    selector: i16,
    params: &[u32],
    storage_size: u32,
    stage_vfs: &[PathBuf],
    max_instructions: u64,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(codec).with_context(|| format!("read {}", codec.display()))?;
    let stem = codec
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("codec");

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.trace_stubs = true;
    sandbox.host.instruction_budget = Some(max_instructions);
    sandbox
        .context_mut()
        .vfs
        .get_or_insert_with(ud_emulator::fsmount::MountTable::new);
    for dir in stage_vfs {
        let n = stage_dir_into_vfs(sandbox.context_mut(), dir)
            .with_context(|| format!("stage {}", dir.display()))?;
        eprintln!("staged {n} files from {}", dir.display());
    }

    preload_qt_runtime(&mut sandbox);

    let (image, _unresolved) = sandbox
        .load_with_deps(stem, &bytes)
        .with_context(|| format!("load_with_deps {}", codec.display()))?;
    eprintln!("loaded {} at {:#010x}", stem, image.image_base);

    // DllMain is best-effort. Many QT codecs return TRUE
    // unconditionally; some trap on first call into an Apple
    // framework DLL. Keep going either way.
    match sandbox.call_dll_main(&image, ud_emulator::DLL_PROCESS_ATTACH) {
        Ok(v) => eprintln!("DllMain returned {v:#x}"),
        Err(e) => eprintln!("DllMain trapped: {e}"),
    }

    // Build ComponentParameters at the scratch address. Layout
    // (Mac OS pascal compiler, packed):
    //   u8  flags
    //   u8  paramSize
    //   i16 what
    //   u32 params[0..paramSize/4]
    let cp_addr = QTCODEC_SCRATCH;
    let param_bytes: u8 = u8::try_from(params.len() * 4).unwrap_or(u8::MAX);
    let what_bits: u16 = u16::from_le_bytes(selector.to_le_bytes());
    sandbox
        .mmu
        .store8(cp_addr, 0)
        .map_err(|e| anyhow::anyhow!("write CP flags: {e}"))?;
    sandbox
        .mmu
        .store8(cp_addr + 1, param_bytes)
        .map_err(|e| anyhow::anyhow!("write CP paramSize: {e}"))?;
    sandbox
        .mmu
        .store16(cp_addr + 2, what_bits)
        .map_err(|e| anyhow::anyhow!("write CP what: {e}"))?;
    for (i, w) in params.iter().enumerate() {
        sandbox
            .mmu
            .store32(cp_addr + 4 + u32::try_from(i).unwrap_or(0) * 4, *w)
            .map_err(|e| anyhow::anyhow!("write CP param {i}: {e}"))?;
    }

    let storage: u32 = if storage_size == 0 {
        0
    } else {
        // Mint a Mac-style Handle: a u32 (master pointer) at
        // `handle_addr` whose value is the address of a
        // zero-initialised `storage_size`-byte data block.
        let handle_addr = QTCODEC_SCRATCH + 0x0001_0000;
        let data_addr = handle_addr + 4;
        sandbox
            .mmu
            .store32(handle_addr, data_addr)
            .map_err(|e| anyhow::anyhow!("write handle master: {e}"))?;
        for off in 0..storage_size {
            sandbox
                .mmu
                .store8(data_addr + off, 0)
                .map_err(|e| anyhow::anyhow!("zero storage[{off}]: {e}"))?;
        }
        eprintln!(
            "minted handle at {handle_addr:#x} → {storage_size}-byte block at {data_addr:#x}"
        );
        handle_addr
    };
    let storage_label = if storage == 0 {
        "NULL".to_string()
    } else {
        format!("{storage:#x}")
    };
    eprintln!(
        "calling {export}(cp={cp_addr:#x} selector={selector}, params={params:?}, storage={storage_label})"
    );
    match sandbox.call_export(&image, export, &[cp_addr, storage]) {
        Ok(ret) => {
            #[allow(clippy::cast_possible_wrap)]
            let signed = ret as i32;
            println!("{export}: ret = {ret:#010x} ({signed})");
        }
        Err(e) => {
            eprintln!("{export}: trapped: {e}");
            return Err(anyhow::anyhow!("{e}"));
        }
    }
    // Surface the debug log so the caller sees what VFS-DLLs
    // were loaded and which stubs were missing.
    for line in &sandbox.host.debug_log {
        eprintln!("  {line}");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn vfw_probe(
    dll_path: &Path,
    fcc_handler: Option<&str>,
    pix_format: PixFormat,
    width: u32,
    height: u32,
    max_instructions: u64,
) -> anyhow::Result<()> {
    let dll_bytes =
        std::fs::read(dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
    let dll_name = dll_path
        .file_name()
        .map_or_else(|| "codec.dll".into(), |n| n.to_string_lossy().into_owned());

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.instruction_budget = Some(max_instructions);
    sandbox.host.trace_stubs = true;

    let img = sandbox
        .load(&dll_name, &dll_bytes)
        .with_context(|| format!("load {}", dll_path.display()))?;
    let _ = sandbox
        .call_dll_main(&img, ud_emulator::DLL_PROCESS_ATTACH)
        .with_context(|| "DllMain")?;
    sandbox
        .install_codec(&img)
        .with_context(|| "install_codec")?;

    let fcc = fcc_handler.map_or_else(|| derive_default_fcc(dll_path), str::to_owned);
    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler_u32 = fourcc_to_u32(&fcc);

    let hic = sandbox
        .ic_open(fcc_type, fcc_handler_u32, ICMODE_DECOMPRESS)
        .context("ICOpen(ICMODE_DECOMPRESS)")?;
    if hic == 0 {
        anyhow::bail!("codec refused DRV_OPEN");
    }
    println!(
        "[probe] loaded {} (image_base 0x{:x})",
        dll_path.display(),
        img.image_base
    );
    println!("[probe] HIC = {hic}; fcc_handler = {fcc:?}");

    // ICGetInfo: codec metadata.
    match sandbox.ic_get_info(hic, 568) {
        Ok(info) => {
            // ICINFO layout: u32 dwSize, u32 fccType, u32 fccHandler,
            //   u32 dwFlags, u32 dwVersion, u32 dwVersionICM, then
            //   szName (utf-16) @ offset 24, szDescription @ offset 88.
            let read_u32 = |off: usize| -> u32 {
                if off + 4 <= info.len() {
                    u32::from_le_bytes(info[off..off + 4].try_into().unwrap_or([0; 4]))
                } else {
                    0
                }
            };
            let read_utf16 = |off: usize, max_chars: usize| -> String {
                let mut out = String::new();
                for i in 0..max_chars {
                    let o = off + i * 2;
                    if o + 2 > info.len() {
                        break;
                    }
                    let c = u16::from_le_bytes([info[o], info[o + 1]]);
                    if c == 0 {
                        break;
                    }
                    if let Some(ch) = char::from_u32(u32::from(c)) {
                        out.push(ch);
                    }
                }
                out
            };
            let fcc_type_bytes = read_u32(4).to_le_bytes();
            let fcc_handler_bytes = read_u32(8).to_le_bytes();
            let flags = read_u32(12);
            let version = read_u32(16);
            let version_icm = read_u32(20);
            let name = read_utf16(24, 16);
            let desc = read_utf16(24 + 32, 128);
            println!("[probe] ICINFO:");
            println!(
                "  fccType      = {:?}",
                std::str::from_utf8(&fcc_type_bytes).unwrap_or("?")
            );
            println!(
                "  fccHandler   = {:?}",
                std::str::from_utf8(&fcc_handler_bytes).unwrap_or("?")
            );
            println!("  dwFlags      = 0x{flags:08x}");
            println!("  dwVersion    = 0x{version:08x}");
            println!("  dwVersionICM = 0x{version_icm:08x}");
            println!("  szName       = {name:?}");
            println!("  szDescription= {desc:?}");
        }
        Err(e) => {
            println!("[probe] ICGetInfo failed: {e}");
        }
    }

    // ICDecompressQuery with an RGB24 default.
    let in_bih = ud_emulator::Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: fcc_handler_u32.to_le_bytes(),
        size_image: 0,
        ..ud_emulator::Bih::default()
    };
    let out_bih = ud_emulator::Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: pix_format.bi_bit_count(),
        compression: pix_format.bi_compression(),
        size_image: width * height * pix_format.bytes_per_pixel(),
        ..ud_emulator::Bih::default()
    };
    match sandbox.ic_decompress_query(hic, &in_bih, Some(&out_bih)) {
        Ok(q) => println!(
            "[probe] ICDecompressQuery({}x{} {:?} → {:?}) = {} (0 = ICERR_OK)",
            width, height, &fcc, pix_format, q as i32
        ),
        Err(e) => println!("[probe] ICDecompressQuery failed: {e}"),
    }

    let _ = sandbox.ic_close(hic);
    println!();
    println!(
        "[probe] Win32 calls: {}; instructions executed: {}",
        sandbox.host.stub_calls.len(),
        sandbox.host.instructions_executed
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn decode_cmd(
    dll_path: &Path,
    inputs: &[PathBuf],
    width: u32,
    height: u32,
    fcc_handler: Option<&str>,
    pix_format: PixFormat,
    output: Option<&Path>,
    max_instructions: u64,
    dump_mem: &[String],
    dump_after_frame: Option<usize>,
    heap_mb: u32,
    watch: &[String],
) -> anyhow::Result<()> {
    // Parse the `--dump-mem` / `--watch` specs up front so a typo
    // fails before the multi-second decode run rather than after it.
    let dump_specs: Vec<DumpSpec> = dump_mem
        .iter()
        .map(|s| parse_dump_spec(s).with_context(|| format!("--dump-mem {s:?}")))
        .collect::<anyhow::Result<_>>()?;
    let watch_specs: Vec<(u32, u32)> = watch
        .iter()
        .map(|s| parse_watch_spec(s).with_context(|| format!("--watch {s:?}")))
        .collect::<anyhow::Result<_>>()?;

    let dll_bytes =
        std::fs::read(dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
    let dll_name = dll_path
        .file_name()
        .map_or_else(|| "codec.dll".into(), |n| n.to_string_lossy().into_owned());
    // Read every frame up front (clap guarantees ≥1). They are fed
    // through the codec in order within one open instance.
    let frames: Vec<Vec<u8>> = inputs
        .iter()
        .map(|p| std::fs::read(p).with_context(|| format!("reading frame {}", p.display())))
        .collect::<anyhow::Result<_>>()?;

    let mut sandbox = ud_emulator::Sandbox::new_with_heap_mb(heap_mb);
    sandbox.host.instruction_budget = Some(max_instructions);

    let img = sandbox
        .load(&dll_name, &dll_bytes)
        .with_context(|| format!("load {}", dll_path.display()))?;
    let _ = sandbox
        .call_dll_main(&img, ud_emulator::DLL_PROCESS_ATTACH)
        .with_context(|| "DllMain")?;
    sandbox
        .install_codec(&img)
        .with_context(|| "install_codec")?;

    let fcc = fcc_handler.map_or_else(|| derive_default_fcc(dll_path), str::to_owned);
    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler_u32 = fourcc_to_u32(&fcc);

    // `in_bih` for the format-query uses the first frame's size; each
    // decode below rebuilds it with that frame's byte length.
    let in_bih = ud_emulator::Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: fcc_handler_u32.to_le_bytes(),
        size_image: u32::try_from(frames[0].len()).unwrap_or(u32::MAX),
        ..ud_emulator::Bih::default()
    };
    let out_bih = ud_emulator::Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: pix_format.bi_bit_count(),
        compression: pix_format.bi_compression(),
        size_image: width * height * pix_format.bytes_per_pixel(),
        ..ud_emulator::Bih::default()
    };

    let hic = sandbox
        .ic_open(fcc_type, fcc_handler_u32, ICMODE_DECOMPRESS)
        .context("ICOpen(ICMODE_DECOMPRESS)")?;
    if hic == 0 {
        anyhow::bail!("codec refused DRV_OPEN");
    }
    eprintln!("[decode] HIC = {hic}; fcc_handler = {fcc:?}");

    let q = sandbox
        .ic_decompress_query(hic, &in_bih, Some(&out_bih))
        .context("ICDecompressQuery")?;
    eprintln!("[decode] ICDecompressQuery = {} (0 = ICERR_OK)", q as i32);

    if (q as i32) != 0 {
        anyhow::bail!("codec rejected the in/out BIH pair");
    }

    let _ = sandbox.ic_decompress_begin(hic, &in_bih, &out_bih);
    let out_capacity = width * height * pix_format.bytes_per_pixel();

    // Arm watchpoints now — after Open/Begin — so the trace is the
    // decode's own stores, not codec setup.
    for &(addr, len) in &watch_specs {
        sandbox.mmu.add_watch(addr, len);
    }

    // Which frame's decode to snapshot after (0-based). Default is
    // the last frame; `--dump-after-frame N` (1-based) targets an
    // earlier point in the sequence.
    let dump_idx = match dump_after_frame {
        Some(n) if (1..=frames.len()).contains(&n) => n - 1,
        Some(n) => {
            eprintln!(
                "warning: --dump-after-frame {n} out of range 1..={}; dumping after the last frame",
                frames.len()
            );
            frames.len() - 1
        }
        None => frames.len() - 1,
    };

    // Feed every frame through ICDecompress in order, in this one
    // open instance — so inter-frame decoder state persists across
    // the sequence. An inter frame that returns ICERR_UNSUPPORTED
    // (1) standalone decodes once its reference frame has run.
    let mut last_decoded: Vec<u8> = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        let frame_bih = ud_emulator::Bih {
            bi_size: 40,
            width: width as i32,
            height: height as i32,
            planes: 1,
            bit_count: 24,
            compression: fcc_handler_u32.to_le_bytes(),
            size_image: u32::try_from(frame.len()).unwrap_or(u32::MAX),
            ..ud_emulator::Bih::default()
        };
        let (rc, decoded) = sandbox
            .ic_decompress(hic, 0, &frame_bih, frame, &out_bih, out_capacity)
            .with_context(|| format!("ICDecompress (frame {}/{})", i + 1, frames.len()))?;
        eprintln!(
            "[decode] frame {}/{}: ICDecompress = {} (output {} bytes)",
            i + 1,
            frames.len(),
            rc as i32,
            decoded.len()
        );

        // Snapshot requested guest-memory regions while the decoder's
        // tables are still live (before ICDecompressEnd/Close tear
        // them down). Hex dumps go to stderr so they never mix into
        // the decoded frame on stdout.
        if i == dump_idx {
            for spec in &dump_specs {
                let dump = capture_dump(&sandbox, spec)?;
                if dump.file.is_none() {
                    if let Some(hex) = &dump.hex {
                        eprintln!(
                            "[decode] memory dump after frame {} [0x{:x}..0x{:x}] ({} of {} bytes mapped):",
                            i + 1,
                            dump.addr,
                            dump.addr.wrapping_add(dump.len as u32),
                            dump.mapped_bytes,
                            dump.len
                        );
                        eprint!("{}", render_hexdump(dump.addr, hex));
                    }
                }
            }
        }
        last_decoded = decoded;
    }

    // Emit the watchpoint write-trace (to stderr — keeps stdout the
    // decoded frame) before teardown.
    if !watch_specs.is_empty() {
        print_watch_trace(&sandbox, &watch_specs);
    }

    // Emit the final frame's pixels (with several frames the point is
    // the persistent-state dump, not every frame's output).
    if let Some(path) = output {
        std::fs::write(path, &last_decoded)
            .with_context(|| format!("writing output {}", path.display()))?;
        eprintln!(
            "[decode] wrote {} bytes to {}",
            last_decoded.len(),
            path.display()
        );
    } else {
        use std::io::Write as _;
        std::io::stdout().write_all(&last_decoded)?;
    }

    let _ = sandbox.ic_decompress_end(hic);
    let _ = sandbox.ic_close(hic);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn encode_cmd(
    dll_path: &Path,
    input: &Path,
    width: u32,
    height: u32,
    fcc_handler: Option<&str>,
    input_format: InputFormat,
    quality: u32,
    keyframe: bool,
    output: Option<&Path>,
    max_instructions: u64,
) -> anyhow::Result<()> {
    let dll_bytes =
        std::fs::read(dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
    let dll_name = dll_path
        .file_name()
        .map_or_else(|| "codec.dll".into(), |n| n.to_string_lossy().into_owned());

    let frame =
        std::fs::read(input).with_context(|| format!("reading input frame {}", input.display()))?;
    let expected_frame_bytes = input_format.frame_bytes(width, height) as usize;
    if frame.len() < expected_frame_bytes {
        anyhow::bail!(
            "input frame is {} bytes but {}x{} {:?} expects {} bytes",
            frame.len(),
            width,
            height,
            input_format,
            expected_frame_bytes
        );
    }

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.instruction_budget = Some(max_instructions);

    let img = sandbox
        .load(&dll_name, &dll_bytes)
        .with_context(|| format!("load {}", dll_path.display()))?;
    let _ = sandbox
        .call_dll_main(&img, ud_emulator::DLL_PROCESS_ATTACH)
        .with_context(|| "DllMain")?;
    sandbox
        .install_codec(&img)
        .with_context(|| "install_codec")?;

    let fcc = fcc_handler.map_or_else(|| derive_default_fcc(dll_path), str::to_owned);
    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler_u32 = fourcc_to_u32(&fcc);

    let in_bih = ud_emulator::Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: input_format.bi_bit_count(),
        compression: input_format.bi_compression(),
        size_image: input_format.frame_bytes(width, height),
        ..ud_emulator::Bih::default()
    };

    let hic = sandbox
        .ic_open(fcc_type, fcc_handler_u32, ICMODE_COMPRESS)
        .context("ICOpen(ICMODE_COMPRESS)")?;
    if hic == 0 {
        anyhow::bail!("codec refused DRV_OPEN(COMPRESS)");
    }
    eprintln!("[encode] HIC = {hic}; fcc_handler = {fcc:?}");

    let (_, out_bih) = sandbox
        .ic_compress_get_format(hic, &in_bih)
        .context("ICCompressGetFormat")?;
    eprintln!(
        "[encode] codec picked output: bit_count={} compression={:?} size_image={}",
        out_bih.bit_count, out_bih.compression, out_bih.size_image
    );

    let q = sandbox
        .ic_compress_query(hic, &in_bih, Some(&out_bih))
        .context("ICCompressQuery")?;
    eprintln!("[encode] ICCompressQuery = {} (0 = ICERR_OK)", q as i32);
    if (q as i32) != 0 {
        anyhow::bail!("codec rejected the input/output BIH pair");
    }

    let cap = sandbox
        .ic_compress_get_size(hic, &in_bih, &out_bih)
        .context("ICCompressGetSize")?;
    eprintln!("[encode] ICCompressGetSize = {cap} bytes");

    let _ = sandbox.ic_compress_begin(hic, &in_bih, &out_bih);
    let flags = if keyframe { ICCOMPRESS_KEYFRAME } else { 0 };
    let frame_slice = &frame[..expected_frame_bytes];
    let result = sandbox
        .ic_compress(
            hic,
            flags,
            &in_bih,
            frame_slice,
            &out_bih,
            cap,
            0, // ckid
            0, // frame_num
            0, // frame_size_limit
            quality,
            None, // prev_bih
            None, // prev_bytes
        )
        .context("ICCompress")?;
    eprintln!(
        "[encode] ICCompress = {} (output {} bytes, output_bih.size_image={})",
        result.lresult as i32,
        result.bytes.len(),
        result.output_bih.size_image,
    );

    if let Some(path) = output {
        std::fs::write(path, &result.bytes)
            .with_context(|| format!("writing output {}", path.display()))?;
        eprintln!(
            "[encode] wrote {} bytes to {}",
            result.bytes.len(),
            path.display()
        );
    } else {
        use std::io::Write as _;
        std::io::stdout().write_all(&result.bytes)?;
    }

    let _ = sandbox.ic_compress_end(hic);
    let _ = sandbox.ic_close(hic);
    Ok(())
}

/// `ud solana <program-id>` — fetch + decompile a Solana
/// on-chain program. Writes the `.ud` text to `out` (or stdout)
/// and optionally saves the raw ELF to `save_elf` for
/// inspection.
fn solana_cmd(
    program_id: &str,
    rpc_url: &str,
    use_cache: bool,
    save_elf: Option<&Path>,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    let elf_bytes = ud_cli::solana::fetch_program_elf(program_id, rpc_url, use_cache)
        .with_context(|| format!("fetch {program_id} from {rpc_url}"))?;
    if let Some(path) = save_elf {
        std::fs::write(path, &elf_bytes).with_context(|| format!("write {}", path.display()))?;
    }
    let elf = ud_format::elf::Elf64File::parse(&elf_bytes)
        .with_context(|| format!("parse stripped ELF from {program_id}"))?;
    let source = ud_translate::decompile::decompile_to_text(&elf)
        .with_context(|| format!("decompile {program_id}"))?;
    if let Some(path) = out {
        std::fs::write(path, source).with_context(|| format!("write {}", path.display()))?;
    } else {
        use std::io::Write as _;
        std::io::stdout().write_all(source.as_bytes())?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn analyze(
    input: &Path,
    max_instructions: u64,
    as_json: bool,
    fail_soft: bool,
    stage_vfs: &[PathBuf],
    vfs_deps: bool,
    call_export: &[String],
    export_arg: &[String],
    call: &[String],
    dump_mem: &[String],
    map_blob: &[String],
    heap_mb: u32,
    watch: &[String],
) -> anyhow::Result<()> {
    // Parse the `--export-arg` / `--call` / `--dump-mem` / `--map-blob`
    // / `--watch` specs up front so a typo fails before we spin up the
    // sandbox rather than after a multi-second run.
    let export_args: Vec<u32> = export_arg
        .iter()
        .map(|s| parse_u32_arg(s).with_context(|| format!("--export-arg {s:?}")))
        .collect::<anyhow::Result<_>>()?;
    let watch_specs: Vec<(u32, u32)> = watch
        .iter()
        .map(|s| parse_watch_spec(s).with_context(|| format!("--watch {s:?}")))
        .collect::<anyhow::Result<_>>()?;
    let call_specs: Vec<CallSpec> = call
        .iter()
        .map(|s| parse_call_spec(s).with_context(|| format!("--call {s:?}")))
        .collect::<anyhow::Result<_>>()?;
    let dump_specs: Vec<DumpSpec> = dump_mem
        .iter()
        .map(|s| parse_dump_spec(s).with_context(|| format!("--dump-mem {s:?}")))
        .collect::<anyhow::Result<_>>()?;
    let blob_specs: Vec<MapBlobSpec> = map_blob
        .iter()
        .map(|s| parse_map_blob_spec(s).with_context(|| format!("--map-blob {s:?}")))
        .collect::<anyhow::Result<_>>()?;
    let bytes = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    if !ud_format::pe::is_pe(&bytes) {
        anyhow::bail!(
            "ud analyze currently only supports PE32 DLLs; {} is not a PE",
            input.display()
        );
    }
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("input");

    let mut sandbox = ud_emulator::Sandbox::new_with_heap_mb(heap_mb);
    sandbox.host.trace_stubs = true;
    sandbox.host.instruction_budget = Some(max_instructions);
    sandbox
        .context_mut()
        .vfs
        .get_or_insert_with(ud_emulator::fsmount::MountTable::new);
    for dir in stage_vfs {
        let n = stage_dir_into_vfs(sandbox.context_mut(), dir)
            .with_context(|| format!("stage {}", dir.display()))?;
        eprintln!("staged {n} files from {}", dir.display());
    }

    let load_result = if vfs_deps {
        sandbox.load_with_deps(stem, &bytes).map(|(img, _)| img)
    } else if fail_soft {
        sandbox.load_fail_soft(stem, &bytes).map(|(img, _)| img)
    } else {
        sandbox.load(stem, &bytes)
    };
    let image = match load_result {
        Ok(img) => img,
        Err(e) => {
            // Surface load failures cleanly in both text and
            // JSON shapes — the front-end consumer cares
            // whether the load even got off the ground.
            if as_json {
                let pe = ud_format::pe::PeFile::parse(&bytes).ok();
                let indicators = pe.as_ref().map(extract_indicators).unwrap_or_default();
                let report = AnalyzeReport {
                    input: input.display().to_string(),
                    image_base: 0,
                    entry_point: 0,
                    dll_main: DllMainOutcome::LoadFailed {
                        message: e.to_string(),
                    },
                    export_calls: Vec::new(),
                    win32_calls: Vec::new(),
                    win32_calls_by_function: Vec::new(),
                    coverage: CoverageSummary::default(),
                    indicators,
                    instructions_executed: 0,
                    instruction_budget: max_instructions,
                    memory_dumps: Vec::new(),
                    watch_trace: Vec::new(),
                    debug_log: std::mem::take(&mut sandbox.host.debug_log),
                };
                let s = serde_json::to_string_pretty(&report)?;
                println!("{s}");
                return Ok(());
            }
            anyhow::bail!("load {}: {}", input.display(), e);
        }
    };

    // Stage any injected blobs (init cookies / descriptors) into
    // guest memory now — after load so the image is mapped, before
    // DllMain/exports so a descriptor an export dereferences is
    // already present.
    for spec in &blob_specs {
        apply_map_blob(&mut sandbox, spec)?;
    }

    let dll_main_result = sandbox.call_dll_main(&image, ud_emulator::DLL_PROCESS_ATTACH);

    // Arm watchpoints now — after DllMain + map-blob, before the call
    // sequence — so the write-trace is the calls' own stores.
    for &(addr, len) in &watch_specs {
        sandbox.mmu.add_watch(addr, len);
    }

    // With CRT init done, drive the requested codec exports
    // (e.g. `*InitDecoder`). These run in the same guest state
    // DllMain left behind, so the Win32-call and coverage totals
    // taken below fold in whatever the exports touched — which is
    // the whole point: DllMain alone never reaches the decoder.
    let mut export_calls = drive_exports(&mut sandbox, &image, call_export, &export_args);

    // Then drive the ordered `--call` sequence in command-line
    // order, each with its own argument list. This is the
    // persistent-instance path: Open→Init→Decode against one live
    // guest context, so decode-time tables built only across a call
    // sequence (cook's MDCT window / coupling coefficients, built in
    // RADecode not RAInitDecoder) come into being before the dumps.
    export_calls.extend(drive_call_sequence(&mut sandbox, &image, &call_specs));

    // Snapshot the requested memory regions before we tear the
    // sandbox down. Files are written here (side effect); the
    // returned records carry the hex preview for the report.
    let memory_dumps = dump_specs
        .iter()
        .map(|spec| capture_dump(&sandbox, spec))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let watch_trace = collect_watch_trace(&sandbox, &watch_specs);

    let stub_calls = std::mem::take(&mut sandbox.host.stub_calls);
    let _: Vec<String> = std::mem::take(&mut sandbox.host.stub_trace);
    let instructions_executed = sandbox.host.instructions_executed;

    let win32_calls: Vec<Win32Call> = stub_calls
        .into_iter()
        .map(|c| Win32Call {
            dll: c.dll,
            name: c.name,
            args: c.args,
            return_value: c.ret,
            call_site_eip: c.call_site_eip,
        })
        .collect();

    let mut by_func: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for c in &win32_calls {
        *by_func.entry(format!("{}!{}", c.dll, c.name)).or_default() += 1;
    }
    let win32_calls_by_function: Vec<Win32CallCount> = by_func
        .into_iter()
        .map(|(function, count)| Win32CallCount { function, count })
        .collect();

    let cov = sandbox.coverage();
    let ranges = cov.executed_ranges();
    let writes = cov.written_addresses().count();
    let smc: Vec<u32> = cov.self_modifying_addresses().collect();
    let coverage = CoverageSummary {
        executed_addresses: cov.executed_count(),
        executed_ranges: ranges.len(),
        bytes_written: writes,
        self_modifying_bytes: smc.len(),
        self_modifying_sample: smc.iter().take(8).copied().collect(),
    };

    let dll_main = match &dll_main_result {
        Ok(ret) => DllMainOutcome::Returned { value: *ret },
        Err(e) => DllMainOutcome::Trapped {
            message: e.to_string(),
        },
    };

    // Static-side indicator extraction: scan the data
    // sections of the parsed PE for printable ASCII / UTF-16
    // strings, classify a few well-known shapes (URLs, file
    // paths, registry keys), and report. Doesn't depend on
    // the run completing, so even codecs that trap mid-DllMain
    // surface their string indicators.
    let pe = ud_format::pe::PeFile::parse(&bytes).ok();
    let indicators = pe.as_ref().map(extract_indicators).unwrap_or_default();

    let report = AnalyzeReport {
        input: input.display().to_string(),
        image_base: image.image_base,
        entry_point: image.entry_point,
        dll_main,
        export_calls,
        win32_calls,
        win32_calls_by_function,
        coverage,
        indicators,
        instructions_executed,
        instruction_budget: max_instructions,
        memory_dumps,
        watch_trace,
        debug_log: std::mem::take(&mut sandbox.host.debug_log),
    };

    if as_json {
        let s = serde_json::to_string_pretty(&report)?;
        println!("{s}");
    } else {
        report.write_text(input);
    }
    Ok(())
}

/// Install-monitor mode (`ud analyze --monitor`): load the PE
/// in fail-soft import-resolution mode, attach an empty
/// virtual filesystem + virtual registry, drive the PE entry
/// point, and report the trap stream + captured side effects.
///
/// Iterative discovery loop: each run names the first
/// unimplemented Win32 API the binary reaches. Implement it,
/// re-run, push the boundary further. The set of stubs needed
/// for a real installer is large; this is the harness that
/// makes the next-step obvious.
/// Walk a bare `.msi` file through the install simulator
/// without spinning up the emulator. Same `--dump-vfs` /
/// report format as the PE path so an analyst can chain
/// `ud analyze --monitor` over every MSI extracted from a
/// previous install run.
#[allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::needless_lifetimes
)]
fn monitor_msi_install(
    input: &Path,
    bytes: &[u8],
    _max_instructions: u64,
    as_json: bool,
    extra_args: Option<&str>,
    dump_vfs: Option<&Path>,
) -> anyhow::Result<()> {
    use ud_emulator::win32::msiexec;

    // Parse `KEY=VAL` tokens out of the property-override
    // string the same way real msiexec would. The leading
    // `/i path` tokens (if any) are ignored since the
    // command line is auxiliary metadata here — we already
    // have the MSI bytes.
    let cmdline = extra_args.unwrap_or("");
    let (_op, properties) = msiexec::parse_msiexec_args(cmdline);

    // Recording sink so we can summarise + emit a report
    // identical in shape to the PE-path one. The dump path
    // also writes through to VFS / VirtualRegistry so the
    // disk dump comes out the same.
    let mut vfs = ud_emulator::context::VirtualFs::new();
    let mut registry = ud_emulator::context::VirtualRegistry::new();
    let mut n_files = 0usize;
    let mut n_dirs = 0usize;
    let mut n_regs = 0usize;
    let mut n_bytes = 0u64;
    let mut n_real_bytes = 0u64;
    let mut debug_log: Vec<String> = Vec::new();

    struct ReportingSink<'a> {
        vfs: &'a mut ud_emulator::context::VirtualFs,
        registry: &'a mut ud_emulator::context::VirtualRegistry,
        n_files: &'a mut usize,
        n_dirs: &'a mut usize,
        n_regs: &'a mut usize,
        n_bytes: &'a mut u64,
        n_real_bytes: &'a mut u64,
        log: &'a mut Vec<String>,
    }
    impl msiexec::InstallSink for ReportingSink<'_> {
        fn emit(&mut self, action: msiexec::InstallAction) -> bool {
            match action {
                msiexec::InstallAction::CreateDirectory { path, .. } => {
                    *self.n_dirs += 1;
                    let marker = format!("{}\\.dir", path.trim_end_matches(['\\', '/']));
                    if !self.vfs.contains(&marker) {
                        self.vfs.insert(&marker, Vec::new());
                    }
                }
                msiexec::InstallAction::WriteFile {
                    path, size, bytes, ..
                } => {
                    *self.n_files += 1;
                    *self.n_bytes = self.n_bytes.saturating_add(size);
                    let payload = bytes.unwrap_or_default();
                    if !payload.is_empty() {
                        *self.n_real_bytes = self.n_real_bytes.saturating_add(payload.len() as u64);
                    }
                    self.vfs.write_path(&path, payload);
                }
                msiexec::InstallAction::RegSet {
                    hive,
                    key,
                    name,
                    value,
                    ..
                } => {
                    *self.n_regs += 1;
                    let key_path = format!("{}\\{}", hive.short(), key);
                    use ud_emulator::context::RegistryValue as RV;
                    let v = match value {
                        msiexec::RegValue::Empty => RV::Sz(String::new()),
                        msiexec::RegValue::Sz(s) => RV::Sz(s),
                        msiexec::RegValue::ExpandSz(s) => RV::ExpandSz(s),
                        msiexec::RegValue::Dword(d) => RV::Dword(d),
                        msiexec::RegValue::Binary(b) => RV::Binary(b),
                        msiexec::RegValue::MultiSz(v) => RV::MultiSz(v),
                    };
                    self.registry.set_value(&key_path, &name, v);
                }
                msiexec::InstallAction::SnapshotProperties(p) => {
                    self.log
                        .push(format!("msiexec: property snapshot ({} entries)", p.len()));
                }
                msiexec::InstallAction::Log(s) => self.log.push(format!("msiexec: {s}")),
                msiexec::InstallAction::CustomAction {
                    name,
                    action_type,
                    source,
                    target,
                    ..
                } => {
                    self.log.push(format!(
                        "msiexec: queued CA {name:?} type={action_type:#x} src={source:?} tgt={target:?}"
                    ));
                }
                msiexec::InstallAction::BinaryStream { name, bytes } => {
                    self.log.push(format!(
                        "msiexec: captured Binary {name:?} ({} bytes)",
                        bytes.len()
                    ));
                }
            }
            true
        }
    }
    let mut sink = ReportingSink {
        vfs: &mut vfs,
        registry: &mut registry,
        n_files: &mut n_files,
        n_dirs: &mut n_dirs,
        n_regs: &mut n_regs,
        n_bytes: &mut n_bytes,
        n_real_bytes: &mut n_real_bytes,
        log: &mut debug_log,
    };
    let options = msiexec::InstallOptions {
        properties,
        ..Default::default()
    };
    let result = msiexec::process_msi(bytes, &options, &mut sink);
    let outcome_label = match &result {
        Ok(_) => format!(
            "msi walk OK — {n_files} files ({n_real_bytes}/{n_bytes} bytes extracted), \
             {n_dirs} directories, {n_regs} registry entries"
        ),
        Err(e) => format!("msi walk failed: {e}"),
    };
    debug_log.push(outcome_label.clone());

    // If the walk queued DLL CustomActions, pump them through a
    // freshly-minted sandbox so msi.dll stubs can answer the
    // DLL's queries from the captured property snapshot. The
    // sandbox starts with the install's VFS + VirtualRegistry
    // pre-staged so CA-side writes (e.g. component registration
    // entries) land in the same trees the report emits.
    if let Ok(props) = &result {
        // Re-walk to extract the pending CAs + binaries — the
        // ReportingSink above only logged them; we need them
        // queued through the Sandbox-side EmulatorInstallSink
        // path.
        // (Simpler: just call dispatch_msiexec_install which
        // re-runs the walk into a sandbox-owned sink that DOES
        // queue them.)
        let mut sandbox = ud_emulator::Sandbox::new();
        sandbox.host.trace_stubs = true;
        sandbox.host.instruction_budget = Some(2_000_000_000);
        // Stage the install's VFS + registry into the sandbox.
        let mut sb_vfs = ud_emulator::context::VirtualFs::new();
        for (p, _) in vfs.list() {
            if let Some(b) = vfs.read(p) {
                sb_vfs.insert(p, b.to_vec());
            }
        }
        // Also stage the MSI bytes at a path dispatch can find.
        sb_vfs.insert("c:/temp/install.msi", bytes.to_vec());
        sandbox.context_mut().vfs = Some(ud_emulator::fsmount::MountTable::with_root(sb_vfs));
        // Stage registry (clone via the all_values iter).
        let mut sb_reg = ud_emulator::context::VirtualRegistry::new();
        for (k, n, v) in registry.all_values() {
            sb_reg.set_value(k, n, v.clone());
        }
        sandbox.context_mut().registry = Some(sb_reg);

        // Dispatch the install through the sandbox's
        // msiexec walker (which queues CAs into HostState).
        // Synthesise a `msiexec /i <path> EXTRA…` command
        // line — the walker uses the verb to decide whether
        // to do an install or a no-op (uninstall).
        let synth_cmd = format!(
            "msiexec.exe /i \"c:/temp/install.msi\" {}",
            extra_args.unwrap_or("")
        );
        ud_emulator::win32::msiexec::dispatch_msiexec_install(
            &mut sandbox.host,
            &mut sandbox.mmu,
            "c:/temp/install.msi",
            &synth_cmd,
        );
        let pumped = sandbox.pump_pending_msi_install();
        if pumped > 0 {
            debug_log.push(format!(
                "msiexec: pumped {pumped} deferred CustomAction(s) post-walk"
            ));
        }
        // Pull effects back from the sandbox.
        if let Some(sb_vfs) = sandbox.context().vfs.as_ref() {
            for (p, _) in sb_vfs.list() {
                if !vfs.contains(p) {
                    if let Some(b) = sb_vfs.read(p) {
                        vfs.insert(p, b.to_vec());
                    }
                }
            }
        }
        if let Some(sb_reg) = sandbox.context().registry.as_ref() {
            for (k, n, v) in sb_reg.all_values() {
                registry.set_value(k, n, v.clone());
            }
        }
        // Propagate any new debug_log lines the sandbox-side
        // walker / pump emitted.
        for line in &sandbox.host.debug_log {
            debug_log.push(line.clone());
        }
        let _ = props;
    }

    // Side-effect capture + optional disk dump.
    let vfs_writes: Vec<VfsEntry> = vfs
        .list()
        .map(|(p, l)| VfsEntry {
            path: p.to_string(),
            bytes: l,
        })
        .collect();
    let registry_writes: Vec<RegistryEntry> = registry
        .all_values()
        .map(|(k, n, v)| RegistryEntry {
            key: k.to_string(),
            name: n.to_string(),
            value: format!("{v:?}"),
        })
        .collect();
    if let Some(dump_root) = dump_vfs {
        std::fs::create_dir_all(dump_root)
            .with_context(|| format!("create --dump-vfs root {}", dump_root.display()))?;
        for (vpath, _) in vfs.list() {
            if vpath.ends_with("/.dir") {
                continue;
            }
            let safe = sanitise_vfs_path(vpath);
            let out = dump_root.join(safe);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            if let Some(data) = vfs.read(vpath) {
                std::fs::write(&out, data)
                    .with_context(|| format!("write VFS dump file {}", out.display()))?;
            }
        }
    }

    let outcome = match result {
        Ok(_) => EntryOutcome::Returned { value: 0 },
        Err(e) => EntryOutcome::Trapped {
            message: e.to_string(),
        },
    };
    let report = MonitorReport {
        input: input.display().to_string(),
        image_base: 0,
        entry_point: 0,
        outcome,
        instructions_executed: 0,
        instruction_budget: 0,
        unresolved_imports: Vec::new(),
        win32_calls: Vec::new(),
        win32_calls_by_function: Vec::new(),
        vfs_writes,
        registry_writes,
        debug_log,
    };
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        report.write_text();
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
/// Monitor a 16-bit Windows NE installer: load it through the Win16
/// loader, drive its entry point in the segmented executor, and report
/// the Win16 API calls / first unimplemented ordinal, plus any virtual
/// FS / registry side effects (with `--dump-vfs`). Phase 1 of NE
/// support: the run reaches the first imported Win16 call (KERNEL.91
/// `InitTask` for an MFC app), which fail-soft surfaces as a trap.
fn monitor_install_ne(
    input: &Path,
    bytes: &[u8],
    max_instructions: u64,
    as_json: bool,
    dump_vfs: Option<&Path>,
    preserve_deletes: bool,
) -> anyhow::Result<()> {
    let stem = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("input.exe");

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.trace_stubs = true;
    sandbox.host.instruction_budget = Some(max_instructions);
    sandbox.host.preserve_deletes = preserve_deletes;
    sandbox
        .context_mut()
        .vfs
        .get_or_insert_with(ud_emulator::fsmount::MountTable::new);
    sandbox
        .context_mut()
        .registry
        .get_or_insert_with(ud_emulator::context::VirtualRegistry::new);

    let image = sandbox
        .load_ne_fail_soft(stem, bytes)
        .with_context(|| format!("NE load {}", input.display()))?;

    // Linear entry address = base of the entry code segment + IP.
    let entry_base = image
        .selectors
        .iter()
        .find(|(sel, _)| *sel == image.entry_cs)
        .map_or(ud_emulator::ne::WIN16_SEG_BASE, |(_, base)| *base);
    let entry_linear = entry_base.wrapping_add(u32::from(image.entry_ip));

    let entry_result = sandbox.call_ne_entry(&image);
    let instructions_executed = sandbox.cpu.instr_count;
    let stub_calls = std::mem::take(&mut sandbox.host.stub_calls);

    let outcome = match &entry_result {
        Ok(ret) => EntryOutcome::Returned { value: *ret },
        Err(e) => EntryOutcome::Trapped {
            message: e.to_string(),
        },
    };

    let win32_calls: Vec<Win32Call> = stub_calls
        .into_iter()
        .map(|c| Win32Call {
            dll: c.dll,
            name: c.name,
            args: c.args,
            return_value: c.ret,
            call_site_eip: c.call_site_eip,
        })
        .collect();
    let mut by_func: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for c in &win32_calls {
        *by_func.entry(format!("{}!{}", c.dll, c.name)).or_default() += 1;
    }
    let win32_calls_by_function: Vec<Win32CallCount> = by_func
        .into_iter()
        .map(|(function, count)| Win32CallCount { function, count })
        .collect();

    let ctx = sandbox.context();
    let vfs_writes: Vec<VfsEntry> = ctx
        .vfs
        .as_ref()
        .map(|vfs| {
            vfs.list()
                .map(|(path, len)| VfsEntry {
                    path: path.to_string(),
                    bytes: len,
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(dump_root) = dump_vfs {
        if let Some(vfs) = ctx.vfs.as_ref() {
            std::fs::create_dir_all(dump_root)
                .with_context(|| format!("create --dump-vfs root {}", dump_root.display()))?;
            for (vpath, _) in vfs.list() {
                if vpath.ends_with("/.dir") {
                    continue;
                }
                let out = dump_root.join(sanitise_vfs_path(vpath));
                if let Some(parent) = out.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                if let Some(data) = vfs.read(vpath) {
                    std::fs::write(&out, data)
                        .with_context(|| format!("write VFS dump file {}", out.display()))?;
                }
            }
        }
    }
    let registry_writes: Vec<RegistryEntry> = ctx
        .registry
        .as_ref()
        .map(|reg| {
            reg.all_values()
                .map(|(key, name, value)| RegistryEntry {
                    key: key.to_string(),
                    name: name.to_string(),
                    value: format!("{value:?}"),
                })
                .collect()
        })
        .unwrap_or_default();

    let unresolved_imports: Vec<UnresolvedImport> = image
        .unresolved
        .iter()
        .cloned()
        .map(|(dll, name)| UnresolvedImport { dll, name })
        .collect();
    let debug_log = std::mem::take(&mut sandbox.host.debug_log);

    let report = MonitorReport {
        input: input.display().to_string(),
        image_base: ud_emulator::ne::WIN16_SEG_BASE,
        entry_point: entry_linear,
        outcome,
        instructions_executed,
        instruction_budget: max_instructions,
        unresolved_imports,
        win32_calls,
        win32_calls_by_function,
        vfs_writes,
        registry_writes,
        debug_log,
    };
    // The headless Win16 GUI transcript — windows, dialogs, message
    // boxes the program put up — for expect-style automation.
    let gui = std::mem::take(&mut sandbox.host.gui);
    if as_json {
        let combined = serde_json::json!({ "report": report, "gui": gui });
        println!("{}", serde_json::to_string_pretty(&combined)?);
    } else {
        report.write_text();
        print_gui_transcript(&gui);
    }
    Ok(())
}

/// Run an ELF binary under the Linux syscall-emulation personality and
/// report what it did (captured stdout/stderr, exit code, unsupported
/// syscalls, files written to the VFS).
/// Resolve a `--fs-type` value, mapping `auto`/`default`/empty to the per-OS
/// default (`ext4` for Linux, `ntfs` for Windows).
#[cfg(feature = "fstool")]
fn resolve_fs_type(ty: &str, default_type: &str) -> String {
    if ty.is_empty() || ty == "auto" || ty == "default" {
        default_type.to_string()
    } else {
        ty.to_string()
    }
}

/// Parse one `--mount` right-hand side into an fstool mount. Grammar:
/// `[type]@path[:rw]` opens a host image; a bare `type` formats a fresh empty
/// 64 MiB filesystem.
#[cfg(feature = "fstool")]
fn parse_mount_spec(
    src: &str,
    default_type: &str,
) -> anyhow::Result<ud_emulator::fsmount::fstool::FsToolMount> {
    use ud_emulator::fsmount::fstool::FsToolMount;
    if let Some((lhs, rhs)) = src.split_once('@') {
        let ty = resolve_fs_type(lhs, default_type);
        let (path, writeback) = rhs.strip_suffix(":rw").map_or((rhs, false), |p| (p, true));
        Ok(FsToolMount::open_image(
            std::path::Path::new(path),
            &ty,
            writeback,
        )?)
    } else {
        Ok(FsToolMount::format_empty(src, 256 << 20)?)
    }
}

/// Default Alpine release fetched for `--rootfs alpine` (override with
/// `alpine:VERSION`). The download branch is derived as `v<MAJ.MIN>`.
#[cfg(feature = "fstool")]
const DEFAULT_ALPINE_VERSION: &str = "3.21.0";

/// Writable headroom added to a repacked `--rootfs` image, on top of the
/// source size, so packages can be installed into the mounted root.
#[cfg(feature = "fstool")]
const ROOTFS_HEADROOM: u64 = 512 << 20;

/// Cache directory for fetched tarballs and built rootfs images.
#[cfg(feature = "fstool")]
fn ud_cache_dir() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("univdreams").join("rootfs")
}

/// Download `url` to `dest` (atomically via a temp file) unless it already
/// exists.
#[cfg(feature = "fstool")]
fn fetch_cached(url: &str, dest: &std::path::Path) -> anyhow::Result<()> {
    if dest.is_file() {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    eprintln!("ud: fetching {url}");
    let resp = ureq::get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    let tmp = dest.with_extension("part");
    {
        let mut out = std::fs::File::create(&tmp)?;
        std::io::copy(&mut resp.into_reader(), &mut out)?;
    }
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

/// Resolve a `--rootfs SPEC` to a local source path (tarball or directory).
/// `alpine[:VERSION][/ARCH]` fetches the minirootfs; anything else is a local
/// path used as-is.
#[cfg(feature = "fstool")]
fn resolve_rootfs_source(spec: &str) -> anyhow::Result<std::path::PathBuf> {
    // alpine[:VERSION][/ARCH]
    if spec == "alpine" || spec.starts_with("alpine:") || spec.starts_with("alpine/") {
        let rest = &spec["alpine".len()..];
        let (ver_part, arch) = match rest.split_once('/') {
            Some((v, a)) => (v, a.to_string()),
            None => (rest, "x86_64".to_string()),
        };
        let version = ver_part
            .strip_prefix(':')
            .filter(|v| !v.is_empty())
            .unwrap_or(DEFAULT_ALPINE_VERSION);
        // Branch v<MAJ.MIN> from the full version.
        let branch = {
            let mut it = version.split('.');
            match (it.next(), it.next()) {
                (Some(maj), Some(min)) => format!("v{maj}.{min}"),
                _ => anyhow::bail!("invalid alpine version {version:?} (want MAJ.MIN.PATCH)"),
            }
        };
        let file = format!("alpine-minirootfs-{version}-{arch}.tar.gz");
        let url = format!("https://dl-cdn.alpinelinux.org/alpine/{branch}/releases/{arch}/{file}");
        let dest = ud_cache_dir().join(&file);
        fetch_cached(&url, &dest)?;
        return Ok(dest);
    }
    let path = std::path::PathBuf::from(spec);
    anyhow::ensure!(path.exists(), "--rootfs source not found: {spec}");
    Ok(path)
}

/// Deterministic cache path for the ext4 image built from `source`, keyed on
/// the source's path + size + mtime + headroom so it rebuilds when the source
/// changes.
#[cfg(feature = "fstool")]
fn rootfs_image_path(source: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    use std::hash::{Hash, Hasher};
    let canon = std::fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf());
    let meta = std::fs::metadata(&canon)?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    canon.hash(&mut h);
    meta.len().hash(&mut h);
    if let Ok(mtime) = meta.modified() {
        if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
            dur.as_secs().hash(&mut h);
        }
    }
    ROOTFS_HEADROOM.hash(&mut h);
    let stem = canon
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("rootfs");
    Ok(ud_cache_dir().join(format!("{stem}-{:016x}.ext4", h.finish())))
}

/// Alpine release branch (`v<MAJ.MIN>`) for an `alpine[:VERSION]` spec, or
/// `None` for a local path / non-alpine source (we don't know its branch).
#[cfg(feature = "fstool")]
fn alpine_branch_for(spec: &str) -> Option<String> {
    if spec != "alpine" && !spec.starts_with("alpine:") && !spec.starts_with("alpine/") {
        return None;
    }
    let rest = &spec["alpine".len()..];
    let ver_part = rest.split_once('/').map_or(rest, |(v, _)| v);
    let version = ver_part
        .strip_prefix(':')
        .filter(|v| !v.is_empty())
        .unwrap_or(DEFAULT_ALPINE_VERSION);
    let mut it = version.split('.');
    match (it.next(), it.next()) {
        (Some(maj), Some(min)) => Some(format!("v{maj}.{min}")),
        _ => None,
    }
}

/// Build (if needed) and mount the `--rootfs` source as a writable ext4 root.
#[cfg(feature = "fstool")]
fn install_rootfs(table: &mut ud_emulator::fsmount::MountTable, spec: &str) -> anyhow::Result<()> {
    use ud_emulator::fsmount::fstool::{build_ext_image, FsToolMount};
    let source = resolve_rootfs_source(spec)?;
    let image = rootfs_image_path(&source)?;
    if !image.is_file() {
        if let Some(parent) = image.parent() {
            std::fs::create_dir_all(parent)?;
        }
        eprintln!(
            "ud: building rootfs image {} from {}",
            image.display(),
            source.display()
        );
        build_ext_image(&image, "ext4", &source, ROOTFS_HEADROOM)
            .with_context(|| format!("repack {} -> ext4", source.display()))?;
    }
    // Mount writable so package installs into the root persist to the image.
    let fm = FsToolMount::open_image(&image, "ext4", true)
        .with_context(|| format!("mount rootfs image {}", image.display()))?;
    table.mount("/", Box::new(fm));

    // Seed a resolver so guest DNS (musl reads /etc/resolv.conf) works; without
    // one musl defaults to 127.0.0.1, which usually goes nowhere and hangs.
    use ud_emulator::context::FileAccess;
    let resolv = b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
    if let Some(h) = table.open("/etc/resolv.conf", FileAccess::ReadWrite) {
        table.write_handle(h, resolv);
        table.close(h);
    }

    // Point apk at `http://` mirrors. The minirootfs ships `https://` repos, but
    // it carries no CA bundle, so TLS cert verification fails ("certificate
    // verify failed"). apk authenticates packages with the RSA keys in
    // `/etc/apk/keys/` (shipped in the rootfs), so plain HTTP is still secure —
    // the index and every .apk are signature-checked regardless of transport.
    if let Some(branch) = alpine_branch_for(spec) {
        let repos = format!(
            "http://dl-cdn.alpinelinux.org/alpine/{branch}/main\n\
             http://dl-cdn.alpinelinux.org/alpine/{branch}/community\n"
        );
        // Truncate first: the shipped `https://` file is longer than our
        // `http://` replacement, so a plain overwrite would leave stale bytes.
        let _ = table.truncate_path("/etc/apk/repositories", 0);
        if let Some(h) = table.open("/etc/apk/repositories", FileAccess::ReadWrite) {
            table.write_handle(h, repos.as_bytes());
            table.close(h);
        }
    }
    Ok(())
}

/// Install `--rootfs` / `--fs-type` (root) and `--mount` overlays into the table.
#[cfg(feature = "fstool")]
fn install_fstool_mounts(
    table: &mut ud_emulator::fsmount::MountTable,
    fs: &FsOpts,
    default_type: &str,
) -> anyhow::Result<()> {
    use ud_emulator::fsmount::fstool::FsToolMount;
    // `--rootfs` wins for `/`; otherwise `--fs-type` formats a fresh root.
    if let Some(spec) = &fs.rootfs {
        install_rootfs(table, spec)?;
    } else if let Some(ty) = &fs.fs_type {
        let ty = resolve_fs_type(ty, default_type);
        let fm = FsToolMount::format_empty(&ty, 256 << 20)
            .with_context(|| format!("mkfs root --fs-type {ty}"))?;
        table.mount("/", Box::new(fm));
    }
    for spec in &fs.mounts {
        let (point, src) = spec
            .split_once('=')
            .with_context(|| format!("--mount expects POINT=SPEC, got {spec:?}"))?;
        let fm =
            parse_mount_spec(src, default_type).with_context(|| format!("--mount {spec:?}"))?;
        table.mount(point, Box::new(fm));
    }
    Ok(())
}

#[cfg(not(feature = "fstool"))]
fn install_fstool_mounts(
    _table: &mut ud_emulator::fsmount::MountTable,
    fs: &FsOpts,
    _default_type: &str,
) -> anyhow::Result<()> {
    if fs.fs_type.is_some() || !fs.mounts.is_empty() || fs.rootfs.is_some() {
        anyhow::bail!("--fs-type / --mount / --rootfs require a build with `--features fstool`");
    }
    Ok(())
}

/// Split a `--args` string into argv tokens, honouring single and double
/// quotes (so `sh -c 'echo hi'` becomes `["sh", "-c", "echo hi"]`).
fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_tok = false;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    in_tok = true;
                }
                c if c.is_whitespace() => {
                    if in_tok {
                        out.push(std::mem::take(&mut cur));
                        in_tok = false;
                    }
                }
                c => {
                    cur.push(c);
                    in_tok = true;
                }
            },
        }
    }
    if in_tok {
        out.push(cur);
    }
    out
}

/// A minimal guest environment for the Linux personality (busybox / apk look
/// at `PATH`, `HOME`, `TERM`).
fn default_linux_env() -> Vec<String> {
    [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        "TERM=dumb",
        "PWD=/",
        "USER=root",
    ]
    .iter()
    .map(ToString::to_string)
    .collect()
}

#[allow(clippy::too_many_arguments)]
/// Puts the host terminal (fd 0) into raw mode for the guard's lifetime and
/// restores the saved settings on drop (including on panic). No-op if stdin is
/// not a tty. With the host raw, every keystroke — including Ctrl-C — reaches
/// the guest, whose line discipline does the echo/editing/signals instead.
struct RawTerminal {
    saved: Option<libc::termios>,
}

impl RawTerminal {
    #[allow(unsafe_code)]
    fn enable() -> Self {
        let fd = libc::STDIN_FILENO;
        // SAFETY: `termios` is plain-old-data; the ioctls act on our own stdin.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::isatty(fd) != 1 || libc::tcgetattr(fd, &mut saved) != 0 {
                return Self { saved: None };
            }
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
            Self { saved: Some(saved) }
        }
    }
}

impl Drop for RawTerminal {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if let Some(saved) = self.saved {
            // SAFETY: restoring the settings we captured in `enable`.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &saved);
            }
        }
    }
}

/// Host terminal size `(rows, cols)` via `TIOCGWINSZ`, or `(0, 0)` if it's not a
/// terminal (the guest's `TIOCGWINSZ` then falls back to 24×80).
#[allow(unsafe_code)]
fn host_term_size() -> (u16, u16) {
    // SAFETY: `winsize` is plain-old-data; the ioctl reads our own stdin.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
            (ws.ws_row, ws.ws_col)
        } else {
            (0, 0)
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools
)]
fn monitor_install_elf(
    input: &Path,
    bytes: &[u8],
    max_instructions: u64,
    as_json: bool,
    extra_args: Option<&str>,
    dump_vfs: Option<&Path>,
    use_kvm: bool,
    use_net: bool,
    use_interactive: bool,
    fs: &FsOpts,
) -> anyhow::Result<()> {
    let stem = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("a.out");
    let argv = shell_split(extra_args.unwrap_or(""));
    // Interactive: put the host terminal in raw mode (restored on drop) and
    // wire the guest's std streams to it; otherwise stdin is EOF + output is
    // captured for the report.
    let term_size = if use_interactive {
        host_term_size()
    } else {
        (0, 0)
    };
    let _raw_guard = if use_interactive {
        Some(RawTerminal::enable())
    } else {
        None
    };

    // i386, x86-64 and aarch64 static ELFs have executors.
    if !ud_emulator::linux::loader::is_runnable(bytes) {
        let machine = ud_format::elf::Elf64File::parse(bytes).map_or(0, |e| e.ehdr.e_machine);
        anyhow::bail!(
            "ELF executor for e_machine={machine} is not implemented yet \
             (i386 / x86-64 / aarch64 run); {} cannot be executed",
            input.display()
        );
    }

    let entry = ud_format::elf::Elf64File::parse(bytes).map_or(0, |e| e.ehdr.e_entry as u32);
    #[cfg(feature = "kvm")]
    let machine = ud_format::elf::Elf64File::parse(bytes)
        .map(|e| e.ehdr.e_machine)
        .unwrap_or(0);

    let new_sandbox = || -> anyhow::Result<ud_emulator::Sandbox> {
        let mut sb = ud_emulator::Sandbox::new_linux();
        sb.host.instruction_budget = Some(max_instructions);
        sb.linux_default_mounts = !fs.no_default_mounts;
        sb.linux_argv.clone_from(&argv);
        sb.linux_env = default_linux_env();
        sb.linux.net_enabled = use_net;
        sb.linux.interactive = use_interactive;
        sb.linux.term_size = term_size;
        let table = sb
            .context_mut()
            .vfs
            .get_or_insert_with(ud_emulator::fsmount::MountTable::new);
        install_fstool_mounts(table, fs, "ext4")?;
        Ok(sb)
    };
    let mut sandbox = new_sandbox()?;

    // Run the guest, optionally accelerated by KVM. `run_with_interp` is the
    // portable software path; `--kvm` (amd64 only, when built with the feature)
    // executes natively and falls back here on any error.
    let run_with_interp = |sandbox: &mut ud_emulator::Sandbox| -> anyhow::Result<Result<i32, _>> {
        sandbox
            .load_linux_elf(stem, bytes)
            .with_context(|| format!("ELF load {}", input.display()))?;
        Ok(sandbox.run_linux())
    };

    #[allow(unused_assignments, unused_mut)]
    let mut used_kvm = false;
    let run;
    #[cfg(feature = "kvm")]
    {
        const EM_X86_64: u16 = 62;
        if use_kvm && machine == EM_X86_64 {
            match sandbox.run_linux_kvm(stem, bytes) {
                Ok(code) => {
                    used_kvm = true;
                    run = Ok(code);
                }
                Err(e) => {
                    eprintln!("kvm: {e} — falling back to the interpreter");
                    sandbox = new_sandbox()?;
                    run = run_with_interp(&mut sandbox)?;
                }
            }
        } else {
            if use_kvm {
                eprintln!("note: --kvm accelerates amd64 only; using the interpreter");
            }
            run = run_with_interp(&mut sandbox)?;
        }
    }
    #[cfg(not(feature = "kvm"))]
    {
        if use_kvm {
            eprintln!("note: this build lacks `--features kvm`; using the interpreter");
        }
        run = run_with_interp(&mut sandbox)?;
    }

    let instructions = if used_kvm {
        0
    } else {
        sandbox
            .aarch64
            .as_ref()
            .map_or(sandbox.cpu.instr_count, |c| c.instr_count)
    };

    // Dump VFS writes if requested.
    if let Some(dump_root) = dump_vfs {
        if let Some(vfs) = sandbox.context().vfs.as_ref() {
            std::fs::create_dir_all(dump_root)
                .with_context(|| format!("create --dump-vfs root {}", dump_root.display()))?;
            for (vpath, _) in vfs.list() {
                if vpath.ends_with("/.dir") {
                    continue;
                }
                let out = dump_root.join(sanitise_vfs_path(vpath));
                if let Some(parent) = out.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                if let Some(data) = vfs.read(vpath) {
                    std::fs::write(&out, data).ok();
                }
            }
        }
    }
    let vfs_writes: Vec<(String, usize)> = sandbox
        .context()
        .vfs
        .as_ref()
        .map(|v| {
            v.list()
                .filter(|(p, _)| !p.ends_with("/.dir"))
                .map(|(p, n)| (p.to_string(), n))
                .collect()
        })
        .unwrap_or_default();

    let k = &sandbox.linux;
    let stdout = String::from_utf8_lossy(&k.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&k.stderr).into_owned();
    let exit = match &run {
        Ok(code) => Some(*code),
        Err(_) => None,
    };
    let trap = run.as_ref().err().map(ToString::to_string);
    let unsupported: Vec<(String, u64)> =
        k.unsupported.iter().map(|(s, n)| (s.clone(), *n)).collect();

    if use_interactive {
        // Output streamed straight to the terminal; no batch report to print.
    } else if as_json {
        let v = serde_json::json!({
            "input": input.display().to_string(),
            "personality": "linux-i386",
            "entry": format!("{entry:#010x}"),
            "instructions_executed": instructions,
            "instruction_budget": max_instructions,
            "exit_code": exit,
            "trap": trap,
            "stdout": stdout,
            "stderr": stderr,
            "unsupported_syscalls": unsupported.iter()
                .map(|(s, n)| serde_json::json!({"syscall": s, "count": n}))
                .collect::<Vec<_>>(),
            "vfs_writes": vfs_writes.iter()
                .map(|(p, n)| serde_json::json!({"path": p, "bytes": n}))
                .collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("ud analyze --monitor (Linux/i386): {}", input.display());
        println!("  entry: {entry:#010x}");
        println!("  instructions executed: {instructions} (budget {max_instructions})");
        match (exit, &trap) {
            (Some(c), _) => println!("  exit code: {c}"),
            (None, Some(t)) => println!("  trapped: {t}"),
            (None, None) => println!("  did not exit"),
        }
        if !unsupported.is_empty() {
            println!("  unsupported syscalls:");
            for (s, n) in &unsupported {
                println!("    {s} ×{n}");
            }
        }
        if !vfs_writes.is_empty() {
            println!("  VFS files ({}):", vfs_writes.len());
            for (p, n) in &vfs_writes {
                println!("    {p} ({n} bytes)");
            }
        }
        if !stdout.is_empty() {
            println!("  ── stdout ──\n{stdout}");
        }
        if !stderr.is_empty() {
            println!("  ── stderr ──\n{stderr}");
        }
    }
    Ok(())
}

/// Render the headless GUI transcript as a readable text section.
fn print_gui_transcript(gui: &ud_emulator::win16::gui::GuiState) {
    use ud_emulator::win16::gui::GuiEvent;
    if gui.events.is_empty() {
        return;
    }
    println!("  ── GUI transcript ── ({} events)", gui.events.len());
    for ev in &gui.events {
        match ev {
            GuiEvent::RegisterClass { name } => println!("    RegisterClass {name}"),
            GuiEvent::CreateWindow {
                hwnd, class, title, ..
            } => println!("    CreateWindow hwnd={hwnd:#06x} [{class}] {title:?}"),
            GuiEvent::ShowWindow { hwnd, cmd } => {
                println!("    ShowWindow hwnd={hwnd:#06x} cmd={cmd}");
            }
            GuiEvent::MessageBox {
                caption,
                text,
                result,
                ..
            } => println!("    MessageBox {caption:?}: {text:?} -> {result}"),
            GuiEvent::DialogStart { title, controls } => {
                println!("    Dialog {title:?} ({} controls):", controls.len());
                for c in controls {
                    println!("      [{}] {:?} id={}", c.class, c.text, c.id);
                }
            }
            GuiEvent::DialogEnd { result } => println!("    DialogEnd -> {result}"),
            GuiEvent::SetWindowText { hwnd, text } => {
                println!("    SetWindowText hwnd={hwnd:#06x} {text:?}");
            }
        }
    }
}

/// Filesystem options collected from `--fs-type` / `--mount` /
/// `--no-default-mounts` / `--rootfs`.
struct FsOpts {
    fs_type: Option<String>,
    mounts: Vec<String>,
    no_default_mounts: bool,
    /// `--rootfs SPEC`: populate `/` from a tarball/dir/`alpine:…` source.
    rootfs: Option<String>,
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools
)]
fn monitor_install(
    input: &Path,
    max_instructions: u64,
    as_json: bool,
    extra_args: Option<&str>,
    dump_vfs: Option<&Path>,
    preserve_deletes: bool,
    use_kvm: bool,
    use_net: bool,
    use_interactive: bool,
    fs: &FsOpts,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    // MSI compound-document magic — when the input is a .msi we
    // skip PE-load entirely and route through the host-side
    // MSI walker. Same --dump-vfs / report format on the other
    // side. Unblocks chained installs (run AppleApplicationSupport.msi
    // after QuickTime.msi etc. by pointing this command at each
    // .msi in the previous run's dump folder).
    let msi_magic = bytes
        .get(..8)
        .is_some_and(|h| h == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    if msi_magic {
        return monitor_msi_install(
            input,
            &bytes,
            max_instructions,
            as_json,
            extra_args,
            dump_vfs,
        );
    }
    // ELF binaries run under the Linux personality (syscall emulation).
    if ud_format::elf::is_elf(&bytes) {
        return monitor_install_elf(
            input,
            &bytes,
            max_instructions,
            as_json,
            extra_args,
            dump_vfs,
            use_kvm,
            use_net,
            use_interactive,
            fs,
        );
    }
    // NE (16-bit Windows) installers run through the Win16 loader +
    // segmented executor. Detect before PE (both carry an `MZ` header).
    if ud_format::ne::is_ne(&bytes) {
        return monitor_install_ne(
            input,
            &bytes,
            max_instructions,
            as_json,
            dump_vfs,
            preserve_deletes,
        );
    }
    if !ud_format::pe::is_pe(&bytes) {
        anyhow::bail!(
            "ud analyze --monitor requires a PE32, NE, ELF, or MSI binary; {} is neither",
            input.display()
        );
    }
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("input");

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.trace_stubs = true;
    sandbox.host.instruction_budget = Some(max_instructions);
    sandbox.host.preserve_deletes = preserve_deletes;
    // Attach empty side-effect captures. Win32 stubs that
    // back onto the Context (CreateFile / Reg* / etc.)
    // record their writes here so the report can summarise
    // what the installer touched.
    sandbox
        .context_mut()
        .vfs
        .get_or_insert_with(ud_emulator::fsmount::MountTable::new);
    sandbox
        .context_mut()
        .registry
        .get_or_insert_with(ud_emulator::context::VirtualRegistry::new);

    let (image, unresolved) = sandbox
        .load_fail_soft(stem, &bytes)
        .with_context(|| format!("fail-soft load {}", input.display()))?;

    // Stage the command line so GetCommandLineA returns a
    // plausible argv. The exe name is the input PE's
    // filename; everything after the first space is `--args`.
    let exe_name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("setup.exe");
    let command_line = match extra_args {
        Some(args) if !args.is_empty() => format!("\"{exe_name}\" {args}"),
        _ => format!("\"{exe_name}\""),
    };
    sandbox.set_command_line(&command_line)?;

    let entry_result = sandbox.call_entry_point(&image);
    // After the installer's entry returns, drain any MSI
    // CustomActions the msiexec walker queued during a
    // `CreateProcessA(msiexec.exe)` dispatch. The walker
    // doesn't have Sandbox-level Cpu/Registry access during
    // a stub call, so it stashes pending DLL/EXE/script CAs
    // in HostState and we pump them here where we DO have the
    // Sandbox. CA effects (registry writes, component
    // registrations) land in the same VirtualFs /
    // VirtualRegistry the installer touched.
    let pumped = sandbox.pump_pending_msi_install();
    if pumped > 0 {
        sandbox
            .host
            .debug_log
            .push(format!("msiexec: pumped {pumped} deferred CustomAction(s)"));
    }
    let stub_calls = std::mem::take(&mut sandbox.host.stub_calls);
    let instructions_executed = sandbox.host.instructions_executed;

    let outcome = match &entry_result {
        Ok(ret) => EntryOutcome::Returned { value: *ret },
        Err(e) => EntryOutcome::Trapped {
            message: e.to_string(),
        },
    };

    let win32_calls: Vec<Win32Call> = stub_calls
        .into_iter()
        .map(|c| Win32Call {
            dll: c.dll,
            name: c.name,
            args: c.args,
            return_value: c.ret,
            call_site_eip: c.call_site_eip,
        })
        .collect();

    let mut by_func: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for c in &win32_calls {
        *by_func.entry(format!("{}!{}", c.dll, c.name)).or_default() += 1;
    }
    let win32_calls_by_function: Vec<Win32CallCount> = by_func
        .into_iter()
        .map(|(function, count)| Win32CallCount { function, count })
        .collect();

    // Side-effect capture: virtual FS writes + virtual
    // registry writes accumulated during the run.
    let ctx = sandbox.context();
    let vfs_writes: Vec<VfsEntry> = ctx
        .vfs
        .as_ref()
        .map(|vfs| {
            vfs.list()
                .map(|(path, len)| VfsEntry {
                    path: path.to_string(),
                    bytes: len,
                })
                .collect()
        })
        .unwrap_or_default();

    // Optional: dump every VFS file to a host directory so the
    // analyst can chain-load extracted child binaries through
    // a follow-up `ud analyze --monitor`. Paths are sanitised
    // (drive letters / forward-slash separators preserved as
    // subdirectories under `dump_root`).
    if let Some(dump_root) = dump_vfs {
        if let Some(vfs) = ctx.vfs.as_ref() {
            std::fs::create_dir_all(dump_root)
                .with_context(|| format!("create --dump-vfs root {}", dump_root.display()))?;
            for (vpath, _) in vfs.list() {
                if vpath.ends_with("/.dir") {
                    continue;
                }
                let safe = sanitise_vfs_path(vpath);
                let out = dump_root.join(safe);
                if let Some(parent) = out.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                if let Some(data) = vfs.read(vpath) {
                    std::fs::write(&out, data)
                        .with_context(|| format!("write VFS dump file {}", out.display()))?;
                }
            }
        }
    }
    let registry_writes: Vec<RegistryEntry> = ctx
        .registry
        .as_ref()
        .map(|reg| {
            reg.all_values()
                .map(|(key, name, value)| RegistryEntry {
                    key: key.to_string(),
                    name: name.to_string(),
                    value: format!("{value:?}"),
                })
                .collect()
        })
        .unwrap_or_default();

    let unresolved_imports: Vec<UnresolvedImport> = unresolved
        .into_iter()
        .map(|(dll, name)| UnresolvedImport { dll, name })
        .collect();

    let debug_log = std::mem::take(&mut sandbox.host.debug_log);

    let report = MonitorReport {
        input: input.display().to_string(),
        image_base: image.image_base,
        entry_point: image.entry_point,
        outcome,
        instructions_executed,
        instruction_budget: max_instructions,
        unresolved_imports,
        win32_calls,
        win32_calls_by_function,
        vfs_writes,
        registry_writes,
        debug_log,
    };

    if as_json {
        let s = serde_json::to_string_pretty(&report)?;
        println!("{s}");
    } else {
        report.write_text();
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct MonitorReport {
    input: String,
    image_base: u32,
    entry_point: u32,
    outcome: EntryOutcome,
    instructions_executed: u64,
    instruction_budget: u64,
    /// Imports the host doesn't have stubs for. Each entry
    /// got a fallback trap-on-call thunk so loading
    /// succeeded; if execution reached one of these it shows
    /// up in `outcome` as a trap naming the function.
    unresolved_imports: Vec<UnresolvedImport>,
    win32_calls: Vec<Win32Call>,
    win32_calls_by_function: Vec<Win32CallCount>,
    /// Files the guest wrote through `CreateFileA` /
    /// `WriteFile` etc. routed to the attached VFS.
    vfs_writes: Vec<VfsEntry>,
    /// Registry values the guest set through `RegSetValueEx`
    /// etc. routed to the attached VirtualRegistry.
    registry_writes: Vec<RegistryEntry>,
    /// `OutputDebugString` lines + any stub-emitted
    /// diagnostic chatter (CreateProcessA target paths,
    /// Msi* arguments, …). Surfaces the path resolution +
    /// MSI call detail an analyst needs to debug what the
    /// installer attempted.
    debug_log: Vec<String>,
}

#[derive(serde::Serialize)]
#[serde(tag = "status")]
enum EntryOutcome {
    Returned { value: u32 },
    Trapped { message: String },
}

#[derive(serde::Serialize)]
struct UnresolvedImport {
    dll: String,
    name: String,
}

#[derive(serde::Serialize)]
struct VfsEntry {
    path: String,
    bytes: usize,
}

#[derive(serde::Serialize)]
struct RegistryEntry {
    key: String,
    name: String,
    value: String,
}

/// Sanitise a virtual filesystem path into a host-safe
/// relative pathname for `--dump-vfs`. Drive letters become
/// directory prefixes (`c:` → `c`), backslashes become
/// forward slashes, and any other suspect characters are
/// stripped so a hostile installer can't write outside the
/// dump root.
/// Inverse of `sanitise_vfs_path` — walk a host directory
/// rooted at `dir` and stage every regular file into the
/// sandbox VFS. The top-level component naming convention is
/// `<drive>_/<path>` (matching `--dump-vfs`'s output); it
/// converts back to `<drive>:/<path>` on the VFS side.
/// Returns the number of files staged.
fn stage_dir_into_vfs(
    ctx: &mut ud_emulator::context::Context,
    dir: &Path,
) -> anyhow::Result<usize> {
    let vfs = ctx
        .vfs
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("VFS not initialised"))?;
    let mut count = 0;
    let root = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let mut stack = vec![root.clone()];
    while let Some(cur) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&cur) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let Ok(rel) = path.strip_prefix(&root) else {
                continue;
            };
            let mut s = String::with_capacity(rel.as_os_str().len() + 1);
            let mut first = true;
            for comp in rel.components() {
                use std::path::Component;
                if let Component::Normal(os) = comp {
                    let part = os.to_string_lossy();
                    if !first {
                        s.push('/');
                    }
                    if first && part.len() == 2 && part.ends_with('_') {
                        s.push(part.chars().next().unwrap().to_ascii_lowercase());
                        s.push(':');
                    } else {
                        s.push_str(&part);
                    }
                    first = false;
                }
            }
            let key = s.to_ascii_lowercase();
            let Ok(data) = std::fs::read(&path) else {
                continue;
            };
            vfs.insert(&key, data);
            count += 1;
        }
    }
    Ok(count)
}

fn sanitise_vfs_path(vpath: &str) -> std::path::PathBuf {
    let mut out = String::with_capacity(vpath.len());
    for ch in vpath.chars() {
        match ch {
            ':' => out.push('_'),
            '\\' => out.push('/'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    // Strip absolute markers — the dump root acts as the
    // anchor.
    let stripped = out.trim_start_matches('/').to_string();
    std::path::PathBuf::from(stripped)
}

impl MonitorReport {
    fn write_text(&self) {
        println!("install-monitor report for {}", self.input);
        println!("  image base: {:#010x}", self.image_base);
        println!("  entry point: {:#010x}", self.entry_point);
        println!(
            "  instructions executed: {} (budget {})",
            self.instructions_executed, self.instruction_budget
        );
        match &self.outcome {
            EntryOutcome::Returned { value } => {
                println!("  entry returned: {value:#010x}");
            }
            EntryOutcome::Trapped { message } => {
                println!("  entry trapped: {message}");
            }
        }
        println!(
            "  unresolved-import fallbacks installed: {}",
            self.unresolved_imports.len()
        );
        if !self.unresolved_imports.is_empty() {
            let mut by_dll: std::collections::BTreeMap<&str, Vec<&str>> =
                std::collections::BTreeMap::new();
            for u in &self.unresolved_imports {
                by_dll.entry(u.dll.as_str()).or_default().push(&u.name);
            }
            for (dll, mut names) in by_dll {
                names.sort_unstable();
                println!("    {} ({} unstubbed):", dll, names.len());
                for n in names.iter().take(10) {
                    println!("      {n}");
                }
                if names.len() > 10 {
                    println!("      … and {} more", names.len() - 10);
                }
            }
        }
        println!("  Win32 calls: {}", self.win32_calls.len());
        for c in self.win32_calls_by_function.iter().take(20) {
            println!("    {} ×{}", c.function, c.count);
        }
        println!("  VFS writes: {}", self.vfs_writes.len());
        for e in self.vfs_writes.iter().take(20) {
            println!("    {} ({} bytes)", e.path, e.bytes);
        }
        println!("  Registry writes: {}", self.registry_writes.len());
        for e in self.registry_writes.iter().take(20) {
            println!("    {}\\{} = {}", e.key, e.name, e.value);
        }
        if !self.debug_log.is_empty() {
            println!("  Debug log ({} entries):", self.debug_log.len());
            for line in self.debug_log.iter().take(20) {
                println!("    {line}");
            }
            if self.debug_log.len() > 20 {
                println!("    … and {} more", self.debug_log.len() - 20);
            }
        }
    }
}

#[derive(serde::Serialize)]
struct AnalyzeReport {
    input: String,
    image_base: u32,
    entry_point: u32,
    dll_main: DllMainOutcome,
    /// Exports driven after `DllMain` via `--call-export` (empty
    /// when the flag isn't used).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    export_calls: Vec<ExportCall>,
    win32_calls: Vec<Win32Call>,
    win32_calls_by_function: Vec<Win32CallCount>,
    coverage: CoverageSummary,
    indicators: Indicators,
    instructions_executed: u64,
    instruction_budget: u64,
    /// Guest-memory regions captured via `--dump-mem` (empty when
    /// the flag isn't used).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    memory_dumps: Vec<MemoryDump>,
    /// Ordered write-trace of stores into any `--watch` region.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    watch_trace: Vec<WatchEventReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    debug_log: Vec<String>,
}

/// One store that hit a `--watch` region, for the analyze report.
#[derive(serde::Serialize)]
struct WatchEventReport {
    seq: u64,
    addr: u32,
    /// Offset from the nearest watch base at or below `addr`.
    offset: u32,
    width: u8,
    value: u64,
    eip: u32,
}

/// Collect the MMU's watch log into report records (offset relative to
/// the nearest watch base).
fn collect_watch_trace(
    sandbox: &ud_emulator::Sandbox,
    watches: &[(u32, u32)],
) -> Vec<WatchEventReport> {
    let bases: Vec<u32> = watches.iter().map(|&(a, _)| a).collect();
    sandbox
        .mmu
        .watch_log()
        .iter()
        .map(|ev| {
            let base = bases
                .iter()
                .filter(|&&b| b <= ev.addr)
                .max()
                .copied()
                .unwrap_or(ev.addr);
            WatchEventReport {
                seq: ev.seq,
                addr: ev.addr,
                offset: ev.addr - base,
                width: ev.width,
                value: ev.value,
                eip: ev.eip,
            }
        })
        .collect()
}

/// One `--call-export` invocation: the resolved export, the args
/// it was handed, and how the guest call ended.
#[derive(serde::Serialize)]
struct ExportCall {
    name: String,
    /// Resolved guest VA of the export entry point.
    va: u32,
    args: Vec<u32>,
    #[serde(flatten)]
    outcome: ExportOutcome,
}

#[derive(serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ExportOutcome {
    /// The export returned; `value` is `EAX` (stdcall return).
    Returned { value: u32 },
    /// The export trapped (unresolved import, fault, budget).
    Trapped { message: String },
}

/// A captured guest-memory region.
#[derive(serde::Serialize)]
struct MemoryDump {
    addr: u32,
    len: usize,
    /// How many of the `len` bytes were actually mapped/readable.
    mapped_bytes: usize,
    /// Host file the raw bytes were written to, if `=PATH` was
    /// given (unmapped bytes are zero-filled on disk).
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    /// Hex string of the region (mapped bytes only, unmapped shown
    /// as `..`). Present only when no `=PATH` was given, so JSON
    /// consumers still get the content.
    #[serde(skip_serializing_if = "Option::is_none")]
    hex: Option<String>,
}

/// Parse a `--watch` spec `ADDR:LEN` into a guest range.
fn parse_watch_spec(s: &str) -> anyhow::Result<(u32, u32)> {
    let (addr, len) = s.split_once(':').with_context(|| "expected ADDR:LEN")?;
    Ok((parse_u32_arg(addr)?, parse_u32_arg(len)?))
}

/// Print a watchpoint write-trace to stderr: one line per store that
/// hit a watched region, in execution order, with the offset from the
/// nearest watch base, the value, the store width, and the writing EIP.
fn print_watch_trace(sandbox: &ud_emulator::Sandbox, watches: &[(u32, u32)]) {
    let log = sandbox.mmu.watch_log();
    let bases: Vec<u32> = watches.iter().map(|&(a, _)| a).collect();
    eprintln!("[watch] {} store(s) hit the watched region(s):", log.len());
    for ev in log {
        // Offset from the greatest watch base at or below this address.
        let base = bases
            .iter()
            .filter(|&&b| b <= ev.addr)
            .max()
            .copied()
            .unwrap_or(ev.addr);
        eprintln!(
            "[watch] #{:<5} +0x{:<6x} [0x{:08x}] = 0x{:0width$x} (w{}) eip=0x{:08x}",
            ev.seq,
            ev.addr - base,
            ev.addr,
            ev.value,
            ev.width,
            ev.eip,
            width = (ev.width as usize) * 2,
        );
    }
    let dropped = sandbox.mmu.watch_dropped();
    if dropped > 0 {
        eprintln!(
            "[watch] … {dropped} further store(s) dropped after the {} cap",
            log.len()
        );
    }
}

/// Parsed `--dump-mem` spec: region plus optional output file.
struct DumpSpec {
    addr: u32,
    len: usize,
    file: Option<PathBuf>,
}

/// Parse a `0x`-hex or decimal 32-bit literal (for `--export-arg`
/// and the ADDR/LEN fields of `--dump-mem`).
fn parse_u32_arg(s: &str) -> anyhow::Result<u32> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    };
    v.with_context(|| format!("not a 32-bit integer: {s:?}"))
}

/// Parse `ADDR:LEN` or `ADDR:LEN=PATH` into a [`DumpSpec`].
fn parse_dump_spec(s: &str) -> anyhow::Result<DumpSpec> {
    let (region, file) = match s.split_once('=') {
        Some((r, p)) => (r, Some(PathBuf::from(p))),
        None => (s, None),
    };
    let (addr, len) = region
        .split_once(':')
        .with_context(|| "expected ADDR:LEN[=PATH]")?;
    Ok(DumpSpec {
        addr: parse_u32_arg(addr)?,
        len: parse_u32_arg(len)? as usize,
        file,
    })
}

/// Parsed `--map-blob` spec: a guest VA and the host file whose
/// bytes get staged there.
struct MapBlobSpec {
    va: u32,
    file: PathBuf,
}

/// Parse `VA=PATH` into a [`MapBlobSpec`].
fn parse_map_blob_spec(s: &str) -> anyhow::Result<MapBlobSpec> {
    let (va, path) = s.split_once('=').with_context(|| "expected VA=PATH")?;
    Ok(MapBlobSpec {
        va: parse_u32_arg(va)?,
        file: PathBuf::from(path),
    })
}

/// Stage a host file's bytes into guest memory at `spec.va`. Any
/// page in the target span that isn't mapped yet is mapped fresh
/// R+W; the write itself goes through `write_initializer`, which
/// bypasses per-page W-protection so a blob can also overwrite a
/// read-only data page without disturbing its permissions.
fn apply_map_blob(sandbox: &mut ud_emulator::Sandbox, spec: &MapBlobSpec) -> anyhow::Result<()> {
    let bytes =
        std::fs::read(&spec.file).with_context(|| format!("read {}", spec.file.display()))?;
    for i in 0..bytes.len() {
        let addr = spec.va.wrapping_add(i as u32);
        if !sandbox.mmu.is_mapped(addr) {
            sandbox.mmu.map(
                addr,
                1,
                ud_emulator::emulator::Perm::R | ud_emulator::emulator::Perm::W,
            );
        }
    }
    sandbox
        .mmu
        .write_initializer(spec.va, &bytes)
        .map_err(|t| anyhow::anyhow!("stage blob at {:#010x}: {t:?}", spec.va))?;
    eprintln!(
        "staged {} bytes at guest {:#010x} from {}",
        bytes.len(),
        spec.va,
        spec.file.display()
    );
    Ok(())
}

/// Match `name` against a pattern that may contain a single `*`
/// wildcard (`*Init`, `Init*`, `Foo*Bar`, or a bare name for an
/// exact match). Case-sensitive, matching PE export semantics.
fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        Some((pre, post)) => {
            name.len() >= pre.len() + post.len() && name.starts_with(pre) && name.ends_with(post)
        }
        None => pattern == name,
    }
}

/// Parsed `--call` spec: an exact export name plus its own
/// (ordered) argument list.
struct CallSpec {
    name: String,
    args: Vec<u32>,
}

/// Parse `NAME[:arg,arg,…]` into a [`CallSpec`]. Args are
/// comma-separated decimal / `0x` hex 32-bit values; a bare
/// `NAME` (no `:`) is a zero-argument call.
fn parse_call_spec(s: &str) -> anyhow::Result<CallSpec> {
    let (name, arglist) = match s.split_once(':') {
        Some((n, a)) => (n, a),
        None => (s, ""),
    };
    if name.is_empty() {
        anyhow::bail!("empty export name");
    }
    let args = if arglist.is_empty() {
        Vec::new()
    } else {
        arglist
            .split(',')
            .map(parse_u32_arg)
            .collect::<anyhow::Result<_>>()?
    };
    Ok(CallSpec {
        name: name.to_owned(),
        args,
    })
}

/// Drive the ordered `--call` sequence: each spec resolves an
/// export by exact name and invokes it stdcall with its own
/// argument list, in order, against the same live guest context.
/// A name that isn't exported records a `Trapped` outcome (rather
/// than aborting the sequence) so the report shows how far the
/// chain got.
fn drive_call_sequence(
    sandbox: &mut ud_emulator::Sandbox,
    image: &ud_emulator::pe::Image,
    specs: &[CallSpec],
) -> Vec<ExportCall> {
    specs
        .iter()
        .map(|spec| {
            let va = image.export(&spec.name).unwrap_or(0);
            let outcome = if va == 0 && !image.exports.contains_key(&spec.name) {
                ExportOutcome::Trapped {
                    message: format!("export {:?} not found in {}", spec.name, image.name),
                }
            } else {
                match sandbox.call_export(image, &spec.name, &spec.args) {
                    Ok(value) => ExportOutcome::Returned { value },
                    Err(e) => ExportOutcome::Trapped {
                        message: e.to_string(),
                    },
                }
            };
            ExportCall {
                name: spec.name.clone(),
                va,
                args: spec.args.clone(),
                outcome,
            }
        })
        .collect()
}

/// Resolve every `--call-export` pattern against the image's
/// export table and drive each match once (stdcall, shared
/// `args`). Deduplicates so overlapping patterns don't call the
/// same export twice; warns on patterns that match nothing.
fn drive_exports(
    sandbox: &mut ud_emulator::Sandbox,
    image: &ud_emulator::pe::Image,
    patterns: &[String],
    args: &[u32],
) -> Vec<ExportCall> {
    let mut names: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for pat in patterns {
        let mut matched = false;
        for name in image.exports.keys() {
            if glob_match(pat, name) {
                matched = true;
                if seen.insert(name.clone()) {
                    names.push(name.clone());
                }
            }
        }
        if !matched {
            eprintln!(
                "warning: --call-export {pat:?} matched no export in {}",
                image.name
            );
        }
    }
    names
        .into_iter()
        .map(|name| {
            let va = image.export(&name).unwrap_or(0);
            let outcome = match sandbox.call_export(image, &name, args) {
                Ok(value) => ExportOutcome::Returned { value },
                Err(e) => ExportOutcome::Trapped {
                    message: e.to_string(),
                },
            };
            ExportCall {
                name,
                va,
                args: args.to_vec(),
                outcome,
            }
        })
        .collect()
}

/// Read a `--dump-mem` region out of guest memory. Unmapped bytes
/// come back as `None`; on file output they're zero-filled, in the
/// report `hex` they render as `..`.
fn capture_dump(sandbox: &ud_emulator::Sandbox, spec: &DumpSpec) -> anyhow::Result<MemoryDump> {
    let bytes: Vec<Option<u8>> = (0..spec.len)
        .map(|i| sandbox.mmu.load8(spec.addr.wrapping_add(i as u32)).ok())
        .collect();
    let mapped_bytes = bytes.iter().filter(|b| b.is_some()).count();

    let (file, hex) = if let Some(path) = &spec.file {
        let raw: Vec<u8> = bytes.iter().map(|b| b.unwrap_or(0)).collect();
        std::fs::write(path, &raw)
            .with_context(|| format!("write memory dump to {}", path.display()))?;
        eprintln!(
            "dumped {} bytes ({} mapped) of guest memory at {:#010x} to {}",
            spec.len,
            mapped_bytes,
            spec.addr,
            path.display()
        );
        (Some(path.display().to_string()), None)
    } else {
        let mut h = String::with_capacity(spec.len * 2);
        for b in &bytes {
            match b {
                Some(v) => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    h.push(HEX[(v >> 4) as usize] as char);
                    h.push(HEX[(v & 0xf) as usize] as char);
                }
                None => h.push_str(".."),
            }
        }
        (None, Some(h))
    };

    Ok(MemoryDump {
        addr: spec.addr,
        len: spec.len,
        mapped_bytes,
        file,
        hex,
    })
}

#[derive(serde::Serialize, Default)]
struct Indicators {
    /// Strings flagged as URLs (`http://…`, `https://…`,
    /// `ftp://…`).
    urls: Vec<String>,
    /// Strings flagged as file paths — anything containing a
    /// drive-letter prefix `X:\\` or matching the Windows
    /// `\\\\?\\` long-path scheme.
    file_paths: Vec<String>,
    /// Strings flagged as registry keys (`HKEY_…`,
    /// `HKCR\\…`).
    registry_keys: Vec<String>,
    /// All printable ASCII strings of length ≥ `STRING_MIN_LEN`
    /// extracted from the PE's data sections. The classified
    /// shapes above are a subset of this list.
    ascii_strings: Vec<String>,
}

const STRING_MIN_LEN: usize = 5;

fn extract_indicators(pe: &ud_format::pe::PeFile) -> Indicators {
    let mut all: Vec<String> = Vec::new();
    for (idx, sh) in pe.sections.iter().enumerate() {
        // Skip executable code sections — strings landing in
        // `.text` are usually false positives off instruction
        // operands. Data and read-only data sections are the
        // primary indicator source.
        let is_exec = sh.characteristics & 0x2000_0000 != 0;
        if is_exec {
            continue;
        }
        let Some(data) = pe.section_data(idx) else {
            continue;
        };
        scan_ascii_strings(data, &mut all);
    }
    all.sort();
    all.dedup();

    let urls = all
        .iter()
        .filter(|s| {
            s.starts_with("http://")
                || s.starts_with("https://")
                || s.starts_with("ftp://")
                || s.starts_with("ws://")
                || s.starts_with("wss://")
        })
        .cloned()
        .collect();
    let file_paths = all
        .iter()
        .filter(|s| {
            // Drive-letter path like `C:\foo` or UNC-style
            // `\\server\share` (with the backslashes preserved
            // in the captured string).
            let bytes = s.as_bytes();
            (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && (bytes[2] == b'\\' || bytes[2] == b'/'))
                || s.starts_with("\\\\?\\")
                || s.starts_with("\\\\.\\")
        })
        .cloned()
        .collect();
    let registry_keys = all
        .iter()
        .filter(|s| {
            s.starts_with("HKEY_")
                || s.starts_with("HKLM\\")
                || s.starts_with("HKCU\\")
                || s.starts_with("HKCR\\")
                || s.starts_with("HKU\\")
        })
        .cloned()
        .collect();
    Indicators {
        urls,
        file_paths,
        registry_keys,
        ascii_strings: all,
    }
}

fn scan_ascii_strings(buf: &[u8], out: &mut Vec<String>) {
    let mut start: Option<usize> = None;
    for (i, &b) in buf.iter().enumerate() {
        let printable = matches!(b, 0x20..=0x7e);
        if printable {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            if i - s >= STRING_MIN_LEN {
                if let Ok(text) = std::str::from_utf8(&buf[s..i]) {
                    out.push(text.to_string());
                }
            }
        }
    }
    if let Some(s) = start {
        let end = buf.len();
        if end - s >= STRING_MIN_LEN {
            if let Ok(text) = std::str::from_utf8(&buf[s..end]) {
                out.push(text.to_string());
            }
        }
    }
}

impl AnalyzeReport {
    #[allow(clippy::too_many_lines)]
    fn write_text(&self, input: &Path) {
        println!(
            "loaded: {} (image_base 0x{:x}, entry 0x{:x})",
            input.display(),
            self.image_base,
            self.entry_point
        );
        println!();
        println!("Win32 calls observed: {}", self.win32_calls.len());
        for c in &self.win32_calls_by_function {
            println!("  {:5}× {}", c.count, c.function);
        }
        println!();
        println!("Coverage:");
        println!(
            "  {} distinct EIP addresses executed",
            self.coverage.executed_addresses
        );
        println!(
            "  {} executed address ranges (contiguous spans)",
            self.coverage.executed_ranges
        );
        println!("  {} guest bytes written", self.coverage.bytes_written);
        println!(
            "  {} bytes were both written and executed (self-modifying / unpacker)",
            self.coverage.self_modifying_bytes
        );
        if !self.coverage.self_modifying_sample.is_empty() {
            let preview: Vec<String> = self
                .coverage
                .self_modifying_sample
                .iter()
                .map(|a| format!("0x{a:x}"))
                .collect();
            println!("    first few: {}", preview.join(", "));
        }
        println!();
        println!(
            "Instructions executed: {} of {}",
            self.instructions_executed, self.instruction_budget
        );
        println!();
        println!("Indicators:");
        println!(
            "  {} ASCII strings extracted from data sections",
            self.indicators.ascii_strings.len()
        );
        if !self.indicators.urls.is_empty() {
            println!("  URLs ({}):", self.indicators.urls.len());
            for u in &self.indicators.urls {
                println!("    {u}");
            }
        }
        if !self.indicators.file_paths.is_empty() {
            println!("  File paths ({}):", self.indicators.file_paths.len());
            for p in self.indicators.file_paths.iter().take(8) {
                println!("    {p}");
            }
            if self.indicators.file_paths.len() > 8 {
                println!("    … {} more", self.indicators.file_paths.len() - 8);
            }
        }
        if !self.indicators.registry_keys.is_empty() {
            println!("  Registry keys ({}):", self.indicators.registry_keys.len());
            for k in &self.indicators.registry_keys {
                println!("    {k}");
            }
        }
        println!();
        match &self.dll_main {
            DllMainOutcome::Returned { value } => {
                println!("DllMain(DLL_PROCESS_ATTACH) returned 0x{value:x}");
            }
            DllMainOutcome::Trapped { message } => {
                println!("DllMain trapped: {message}");
            }
            DllMainOutcome::LoadFailed { message } => {
                println!("load failed: {message}");
            }
        }

        if !self.export_calls.is_empty() {
            println!();
            println!("Export calls ({}):", self.export_calls.len());
            for c in &self.export_calls {
                let args: Vec<String> = c.args.iter().map(|a| format!("0x{a:x}")).collect();
                match &c.outcome {
                    ExportOutcome::Returned { value } => {
                        println!(
                            "  {}(0x{:x})({}) → 0x{value:x}",
                            c.name,
                            c.va,
                            args.join(", ")
                        );
                    }
                    ExportOutcome::Trapped { message } => {
                        println!(
                            "  {}(0x{:x})({}) trapped: {message}",
                            c.name,
                            c.va,
                            args.join(", ")
                        );
                    }
                }
            }
        }

        for d in &self.memory_dumps {
            println!();
            if let Some(file) = &d.file {
                println!(
                    "Memory dump [0x{:x}..0x{:x}] ({} mapped) → {file}",
                    d.addr,
                    d.addr.wrapping_add(d.len as u32),
                    d.mapped_bytes
                );
            } else {
                println!(
                    "Memory dump [0x{:x}..0x{:x}] ({} of {} bytes mapped):",
                    d.addr,
                    d.addr.wrapping_add(d.len as u32),
                    d.mapped_bytes,
                    d.len
                );
                if let Some(hex) = &d.hex {
                    print_hexdump(d.addr, hex);
                }
            }
        }

        if !self.watch_trace.is_empty() {
            println!();
            println!(
                "Watchpoint write-trace ({} stores, in order):",
                self.watch_trace.len()
            );
            for ev in &self.watch_trace {
                println!(
                    "  #{:<5} +0x{:<6x} [0x{:08x}] = 0x{:0width$x} (w{}) eip=0x{:08x}",
                    ev.seq,
                    ev.offset,
                    ev.addr,
                    ev.value,
                    ev.width,
                    ev.eip,
                    width = (ev.width as usize) * 2,
                );
            }
        }
    }
}

/// Render a canonical 16-byte-per-row hex dump from an address
/// and the report's compact hex string (two chars per byte, `..`
/// marking an unmapped byte). Returns the multi-line text (each
/// row newline-terminated) so the caller can route it to stdout
/// or stderr as appropriate.
fn render_hexdump(base: u32, hex: &str) -> String {
    use std::fmt::Write as _;
    let cells: Vec<&str> = hex
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or(".."))
        .collect();
    let mut out = String::new();
    for (row, chunk) in cells.chunks(16).enumerate() {
        let addr = base.wrapping_add((row * 16) as u32);
        let mut hexpart = String::new();
        let mut asciipart = String::new();
        for (i, cell) in chunk.iter().enumerate() {
            if i == 8 {
                hexpart.push(' ');
            }
            hexpart.push_str(cell);
            hexpart.push(' ');
            match u8::from_str_radix(cell, 16) {
                Ok(b) if (0x20..=0x7e).contains(&b) => asciipart.push(b as char),
                Ok(_) => asciipart.push('.'),
                Err(_) => asciipart.push(' '),
            }
        }
        // Pad the hex column so the ASCII gutter lines up on short
        // final rows.
        let width = 16 * 3 + 1;
        for _ in hexpart.len()..width {
            hexpart.push(' ');
        }
        let _ = writeln!(out, "  {addr:08x}  {hexpart} |{asciipart}|");
    }
    out
}

/// Print a hex dump to stdout (used by the `analyze` text report).
fn print_hexdump(base: u32, hex: &str) {
    print!("{}", render_hexdump(base, hex));
}

#[derive(serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DllMainOutcome {
    Returned { value: u32 },
    Trapped { message: String },
    LoadFailed { message: String },
}

#[derive(serde::Serialize)]
struct Win32Call {
    dll: String,
    name: String,
    args: Vec<u32>,
    return_value: u32,
    call_site_eip: u32,
}

#[derive(serde::Serialize)]
struct Win32CallCount {
    function: String,
    count: usize,
}

#[derive(serde::Serialize, Default)]
struct CoverageSummary {
    executed_addresses: usize,
    executed_ranges: usize,
    bytes_written: usize,
    self_modifying_bytes: usize,
    self_modifying_sample: Vec<u32>,
}

fn format_warning(w: &ud_translate::compile::AsmWarning) -> String {
    match w {
        ud_translate::compile::AsmWarning::Divergence {
            location,
            text,
            canonical,
        } => format!(
            "{}: text {:?} disagrees with canonical form {:?}",
            format_location(location),
            text,
            canonical,
        ),
        ud_translate::compile::AsmWarning::Undecodable { location, text } => format!(
            "{}: pinned bytes don't decode as a valid x86 instruction (text was {:?})",
            format_location(location),
            text,
        ),
        ud_translate::compile::AsmWarning::MultipleInsns {
            location,
            text,
            count,
        } => format!(
            "{}: pinned bytes decode to {} instructions, not 1 (text was {:?})",
            format_location(location),
            count,
            text,
        ),
    }
}

fn format_location(l: &ud_translate::compile::AsmLocation) -> String {
    let section = l.section.as_deref().unwrap_or("<top-level>");
    let function = l.function.as_deref().unwrap_or("<no fn>");
    format!("{section}::{function}#{}", l.stmt_index)
}

fn hex_window(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
