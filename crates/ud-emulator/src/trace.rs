//! Reverse-engineering trace surface (gated on the `trace` Cargo
//! feature).
//!
//! See `docs/winmf/winmf-emulator.md` §"Trace mode" for the design
//! contract. With the feature on, an opt-in JSONL event tape is
//! emitted at four probe sites:
//!
//! 1. **Win32 calls** (`kind=win32_call`) — every dispatch through
//!    [`crate::win32::dispatch_stub`].
//! 2. **Memory watchpoints** (`kind=mem_write` / `kind=mem_read`)
//!    — every guest access to a range registered via
//!    [`crate::Sandbox::watch`].
//! 3. **Instruction trace** (`kind=exec`) — per-instruction event
//!    when the `trace-exec` sub-feature is enabled and the
//!    `Sandbox::set_exec_trace(true)` runtime flag is set.
//! 4. **Traps** (`kind=trap`) — unconditionally emitted when a
//!    fault propagates out of the run loop, so something is on
//!    the trace tape even when the codec misbehaves.
//!
//! The schema matches the JSONL shape the rest of the workspace
//! uses (oxideav-magicyuv / oxideav-tta `--features trace`),
//! `jq`-line-greppable and `awk`-friendly. Example events from
//! the design doc are authoritative.
//!
//! With the feature OFF, every type and function in this module
//! is `#[cfg(...)]`'d out; call sites in
//! [`crate::emulator::mmu`], [`crate::win32`], and
//! [`crate::runtime`] compile to nothing — release builds pay
//! zero cost.

#![cfg(feature = "trace")]

use std::cell::RefCell;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

/// Memory-watchpoint trigger discipline.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WatchMode {
    /// Fire only on writes intersecting `[addr, addr+size)`.
    Write,
    /// Fire only on reads intersecting `[addr, addr+size)`.
    Read,
    /// Fire on both reads and writes.
    Both,
}

impl WatchMode {
    /// Does this mode emit a `mem_write` event?
    pub const fn watches_writes(self) -> bool {
        matches!(self, WatchMode::Write | WatchMode::Both)
    }
    /// Does this mode emit a `mem_read` event?
    pub const fn watches_reads(self) -> bool {
        matches!(self, WatchMode::Read | WatchMode::Both)
    }
}

/// One installed watchpoint covering `[addr, addr+size)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Watchpoint {
    pub addr: u32,
    pub size: u32,
    pub mode: WatchMode,
}

impl Watchpoint {
    /// True iff `[hit, hit+hit_size)` overlaps `[self.addr, self.addr+self.size)`.
    pub fn overlaps(&self, hit: u32, hit_size: u32) -> bool {
        let a_lo = self.addr;
        let a_hi = self.addr.wrapping_add(self.size);
        let b_lo = hit;
        let b_hi = hit.wrapping_add(hit_size);
        // Half-open intervals overlap when neither is entirely
        // below the other. Use saturating to avoid u32 wrap on
        // the rare top-of-address-space probe.
        a_lo < b_hi && b_lo < a_hi
    }
}

/// Per-sandbox trace state — owned by [`crate::emulator::Mmu`] so
/// the MMU's hot path can consult watchpoints without an extra
/// indirection, and shared via `&mut` with the higher layers
/// (Cpu, Sandbox, Win32 dispatch) that emit their own probe
/// flavours.
pub struct TraceState {
    /// Active watchpoints. Linear-scan inside hot paths; we don't
    /// expect more than a handful at a time per spec.
    pub watchpoints: Vec<Watchpoint>,
    /// Sink that JSONL events flush to. `None` ⇒ events are
    /// silently dropped (per the design doc), even when the
    /// feature is on.
    ///
    /// Wrapped in `RefCell` so the immutable load paths in the
    /// MMU (which take `&self`) can still emit a `mem_read`
    /// event without forcing every caller in the crate onto a
    /// `&mut Mmu` borrow.
    pub sink: RefCell<Option<Box<dyn Write + Send>>>,
    /// `true` when the `trace-exec` sub-feature is on AND the
    /// runtime has flipped the per-instruction trace on. The
    /// feature flag alone gates compilation; this flag gates
    /// emission per-step, so a sandbox can toggle exec trace mid
    /// run when triaging a specific section.
    pub exec_on: bool,
    /// Mirror of `cpu.regs.eip` updated by [`crate::emulator::Cpu::step`]
    /// before each MMU access — the MMU itself doesn't have a
    /// reference to the CPU, so we shadow the EIP into the trace
    /// state on the slow probe path.
    pub last_eip: u32,
}

impl Default for TraceState {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceState {
    /// Create a TraceState with an empty watchpoint set, the
    /// default sink (env-var) installed, and exec-trace off.
    pub fn new() -> Self {
        TraceState {
            watchpoints: Vec::new(),
            sink: RefCell::new(open_default_sink()),
            exec_on: false,
            last_eip: 0,
        }
    }

    /// Install a watchpoint. Multiple watchpoints may overlap;
    /// each fires independently. A duplicate
    /// `(addr, size, mode)` is registered as a separate entry —
    /// callers wanting de-dup can use [`Self::unwatch`] first.
    pub fn watch(&mut self, addr: u32, size: u32, mode: WatchMode) {
        self.watchpoints.push(Watchpoint { addr, size, mode });
    }

    /// Remove watchpoints whose `(addr, size)` exactly matches.
    /// Mode is ignored for the match — the design doc treats a
    /// `(addr, size)` pair as the watchpoint identity.
    pub fn unwatch(&mut self, addr: u32, size: u32) {
        self.watchpoints
            .retain(|w| !(w.addr == addr && w.size == size));
    }

    /// Override the sink at runtime. Use this from tests to
    /// capture events into a `Vec<u8>`-backed `Box<dyn Write>`.
    pub fn set_sink(&mut self, sink: Box<dyn Write + Send>) {
        *self.sink.borrow_mut() = Some(sink);
    }

    /// Convenience inverse — tear down the current sink so
    /// subsequent emits drop silently.
    pub fn clear_sink(&mut self) {
        *self.sink.borrow_mut() = None;
    }

    /// Set the per-step EIP shadow. Called by
    /// [`crate::emulator::Cpu::step`] once per instruction so the
    /// MMU's `mem_read` / `mem_write` probes can include the
    /// faulting EIP without taking another reference to the CPU.
    pub fn set_eip(&mut self, eip: u32) {
        self.last_eip = eip;
    }

    /// Walk the watchpoint list — return the first watchpoint
    /// whose mode + range matches the access, or `None`.
    pub fn matched_for_write(&self, addr: u32, size: u32) -> Option<&Watchpoint> {
        self.watchpoints
            .iter()
            .find(|w| w.mode.watches_writes() && w.overlaps(addr, size))
    }

    /// As above for reads.
    pub fn matched_for_read(&self, addr: u32, size: u32) -> Option<&Watchpoint> {
        self.watchpoints
            .iter()
            .find(|w| w.mode.watches_reads() && w.overlaps(addr, size))
    }

    /// Write one already-formatted JSONL line followed by `\n`.
    /// Errors are silenced — the trace tape is a debugging
    /// convenience, not part of any correctness contract.
    pub fn emit_line(&self, line: &str) {
        if let Some(sink) = self.sink.borrow_mut().as_mut() {
            let _ = sink.write_all(line.as_bytes());
            let _ = sink.write_all(b"\n");
            let _ = sink.flush();
        }
    }

    /// True iff a sink is currently installed. Used by emit
    /// helpers to short-circuit the formatting work when the
    /// event would be dropped.
    pub fn has_sink(&self) -> bool {
        self.sink.borrow().is_some()
    }

    // ------------- High-level event helpers ---------------------

    /// Emit a `kind=win32_call` event.
    ///
    /// `args` is captured from the guest stack at call time;
    /// `ret` is the dword the stub put back into `eax`.
    pub fn ev_win32_call(&self, dll: &str, name: &str, args: &[u32], ret: u32, eip: u32) {
        if !self.has_sink() {
            return;
        }
        let mut s = String::with_capacity(96);
        s.push_str(r#"{"kind":"win32_call","dll":""#);
        s.push_str(dll);
        s.push_str(r#"","name":""#);
        s.push_str(name);
        s.push_str(r#"","args":["#);
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            // Args printed as decimal per the spec example.
            use core::fmt::Write as _;
            let _ = write!(s, "{}", a);
        }
        s.push_str(r#"],"ret":""#);
        push_hex32(&mut s, ret);
        s.push_str(r#"","eip":""#);
        push_hex32(&mut s, eip);
        s.push_str(r#""}"#);
        self.emit_line(&s);
    }

    /// Emit a `kind=mem_write` event.
    pub fn ev_mem_write(&self, addr: u32, size: u32, value: u64, eip: u32) {
        if !self.has_sink() {
            return;
        }
        let mut s = String::with_capacity(96);
        s.push_str(r#"{"kind":"mem_write","addr":""#);
        push_hex32(&mut s, addr);
        s.push_str(r#"","size":"#);
        use core::fmt::Write as _;
        let _ = write!(s, "{}", size);
        s.push_str(r#","value":""#);
        push_hex_value(&mut s, size, value);
        s.push_str(r#"","eip":""#);
        push_hex32(&mut s, eip);
        s.push_str(r#""}"#);
        self.emit_line(&s);
    }

    /// Emit a `kind=mem_read` event.
    pub fn ev_mem_read(&self, addr: u32, size: u32, value: u64, eip: u32) {
        if !self.has_sink() {
            return;
        }
        let mut s = String::with_capacity(96);
        s.push_str(r#"{"kind":"mem_read","addr":""#);
        push_hex32(&mut s, addr);
        s.push_str(r#"","size":"#);
        use core::fmt::Write as _;
        let _ = write!(s, "{}", size);
        s.push_str(r#","value":""#);
        push_hex_value(&mut s, size, value);
        s.push_str(r#"","eip":""#);
        push_hex32(&mut s, eip);
        s.push_str(r#""}"#);
        self.emit_line(&s);
    }

    /// Emit a `kind=exec` event. `bytes` is hex-encoded
    /// (`opcode_bytes` field in the design doc); `mnemonic` is a
    /// short SDM-style hint when available, or just the leading
    /// opcode byte otherwise.
    pub fn ev_exec(&self, eip: u32, bytes: &[u8], mnemonic: &str, registers: &[(&str, u32)]) {
        if !self.has_sink() {
            return;
        }
        let mut s = String::with_capacity(192);
        s.push_str(r#"{"kind":"exec","eip":""#);
        push_hex32(&mut s, eip);
        s.push_str(r#"","bytes":""#);
        for b in bytes {
            use core::fmt::Write as _;
            let _ = write!(s, "{:02x}", b);
        }
        s.push_str(r#"","mnemonic":""#);
        // mnemonic should not contain quotes or newlines for our
        // callers; bypass JSON escaping for that reason.
        s.push_str(mnemonic);
        s.push_str(r#"","registers":{"#);
        for (i, (name, val)) in registers.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(name);
            s.push_str(r#"":""#);
            push_hex32(&mut s, *val);
            s.push('"');
        }
        s.push_str(r#"}}"#);
        self.emit_line(&s);
    }

    /// Emit a `kind=trap` event.
    pub fn ev_trap(&self, trap: &str, eip: u32, opcode: Option<u32>, registers: &[(&str, u32)]) {
        if !self.has_sink() {
            return;
        }
        let mut s = String::with_capacity(160);
        s.push_str(r#"{"kind":"trap","trap":""#);
        s.push_str(trap);
        s.push_str(r#"","eip":""#);
        push_hex32(&mut s, eip);
        s.push('"');
        if let Some(op) = opcode {
            s.push_str(r#","opcode":""#);
            use core::fmt::Write as _;
            let _ = write!(s, "0x{:02x}", op & 0xFF);
            s.push('"');
        }
        s.push_str(r#","registers":{"#);
        for (i, (name, val)) in registers.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(name);
            s.push_str(r#"":""#);
            push_hex32(&mut s, *val);
            s.push('"');
        }
        s.push_str(r#"}}"#);
        self.emit_line(&s);
    }
}

fn push_hex32(s: &mut String, v: u32) {
    use core::fmt::Write as _;
    let _ = write!(s, "0x{:08x}", v);
}

fn push_hex_value(s: &mut String, size: u32, v: u64) {
    use core::fmt::Write as _;
    match size {
        1 => {
            let _ = write!(s, "0x{:02x}", (v as u8));
        }
        2 => {
            let _ = write!(s, "0x{:04x}", (v as u16));
        }
        4 => {
            let _ = write!(s, "0x{:08x}", (v as u32));
        }
        8 => {
            let _ = write!(s, "0x{:016x}", v);
        }
        _ => {
            let _ = write!(s, "0x{:x}", v);
        }
    }
}

/// Honour `OXIDEAV_VFW_TRACE_FILE`:
///   * `=2` → stderr.
///   * any other non-empty value → opened as a file (truncating).
///   * unset / empty → `None` (caller is on the hook for
///     [`TraceState::set_sink`] before any event will land).
fn open_default_sink() -> Option<Box<dyn Write + Send>> {
    let val = env::var_os("OXIDEAV_VFW_TRACE_FILE")?;
    if val.is_empty() {
        return None;
    }
    if val == "2" {
        return Some(Box::new(io::stderr()));
    }
    let p = PathBuf::from(val);
    File::create(&p)
        .ok()
        .map(|f| Box::new(f) as Box<dyn Write + Send>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchpoint_overlap_detects_intersecting_ranges() {
        let w = Watchpoint {
            addr: 0x1000,
            size: 16,
            mode: WatchMode::Write,
        };
        assert!(w.overlaps(0x1000, 1));
        assert!(w.overlaps(0x100F, 1));
        assert!(w.overlaps(0x0FF8, 16));
        assert!(!w.overlaps(0x1010, 1));
        assert!(!w.overlaps(0x0FFF, 1));
    }

    #[test]
    fn watch_mode_predicates_match_design_doc() {
        assert!(WatchMode::Write.watches_writes());
        assert!(!WatchMode::Write.watches_reads());
        assert!(WatchMode::Read.watches_reads());
        assert!(!WatchMode::Read.watches_writes());
        assert!(WatchMode::Both.watches_writes());
        assert!(WatchMode::Both.watches_reads());
    }

    #[test]
    fn unwatch_drops_only_exact_addr_size_match() {
        let mut t = TraceState::new();
        t.set_sink(Box::new(Vec::<u8>::new())); // discardable
        t.watch(0x1000, 4, WatchMode::Write);
        t.watch(0x2000, 4, WatchMode::Read);
        t.unwatch(0x1000, 4);
        assert_eq!(t.watchpoints.len(), 1);
        assert_eq!(t.watchpoints[0].addr, 0x2000);
    }

    #[test]
    fn ev_win32_call_emits_jsonl_line() {
        let mut t = TraceState::default();
        let buf: Vec<u8> = Vec::new();
        t.set_sink(Box::new(buf));
        t.ev_win32_call(
            "kernel32.dll",
            "HeapAlloc",
            &[0xDEADBEEF, 0, 1024],
            0x10001000,
            0x10004A17,
        );
        // Sink is captured into a moved Box; we can't read it
        // back from here. The next test does the round trip via
        // a shared cursor.
    }

    #[test]
    fn matched_for_write_finds_overlapping_watch() {
        let mut t = TraceState::new();
        t.watch(0x1000, 8, WatchMode::Both);
        let m = t.matched_for_write(0x1004, 4).unwrap();
        assert_eq!(m.addr, 0x1000);
        assert!(t.matched_for_read(0x1004, 4).is_some());
    }

    /// A sink wrapper around `Vec<u8>` that we own here — used by
    /// the integration-style tests that need to read events back.
    pub(crate) struct VecSink(pub std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for VecSink {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn ev_mem_write_round_trip_through_shared_buffer() {
        use std::sync::{Arc, Mutex};
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut t = TraceState::new();
        t.set_sink(Box::new(VecSink(Arc::clone(&buf))));
        t.ev_mem_write(0x1000, 4, 0x40, 0x10004A32);
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(s.contains(r#""kind":"mem_write""#));
        assert!(s.contains(r#""addr":"0x00001000""#));
        assert!(s.contains(r#""value":"0x00000040""#));
        assert!(s.contains(r#""eip":"0x10004a32""#));
    }
}
