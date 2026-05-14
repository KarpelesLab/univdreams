//! i386 integer ISA executor.
//!
//! Each call to [`Cpu::step`] fetches one instruction at `eip`,
//! advances `eip`, and applies the instruction's effect on
//! [`Regs`] / [`Mmu`]. Multi-byte prefixes and ModR/M / SIB /
//! displacement decoding lives in [`super::decode`].
//!
//! This is **not** a complete i386 implementation. It covers
//! enough of the integer ISA for round-1's "load a DLL and run
//! through `DllMain(DLL_PROCESS_ATTACH)`" milestone. The unsupported
//! tail of the opcode space traps as [`Trap::UndefinedOpcode`] —
//! deliberately, so we discover what real codec DLLs need by
//! looking at the trap address and disassembling the surrounding
//! bytes.
//!
//! Reference: Intel® 64 and IA-32 Architectures Software
//! Developer's Manual, Volumes 2A + 2B (instruction set
//! reference), Volume 1 §3 (basic execution environment), Volume
//! 1 Appendix B (EFLAGS Cross-Reference).

use super::decode::{
    read_operand16, read_operand32, resolve_modrm32, sign_ext_8_to_16, sign_ext_8_to_32,
    write_operand16, write_operand32, ModRm, Operand,
};
use super::mmu::Mmu;
use super::regs::{Flags, Reg16, Reg32, Reg8, Regs};
use super::Trap;
use std::collections::BTreeSet;

/// Sentinel return address pushed by host-initiated calls. When
/// `eip` reaches the sentinel after a `ret`, [`Cpu::run`] stops.
pub const RET_SENTINEL: u32 = 0xFFFF_FFF0;

/// Default instruction limit for [`Cpu::run`] — guards against a
/// runaway codec. The limit is configurable via
/// [`Cpu::set_instr_limit`] for tests that intentionally execute
/// long sequences.
pub const DEFAULT_INSTR_LIMIT: u64 = 10_000_000;

/// Outcome of `step` when there is no trap. Mostly informational
/// — used by integration tests to confirm a known instruction
/// dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOk {
    /// Normal advance.
    Continued,
    /// `eip` reached the [`RET_SENTINEL`]. [`Cpu::run`] stops.
    Halted,
}

/// CPU instance — owns its own register file. The [`Mmu`] is
/// passed by mutable reference into every step so that one MMU
/// can be reused across multiple emulator instances.
pub struct Cpu {
    pub regs: Regs,
    pub instr_count: u64,
    instr_limit: u64,
    /// Operand-size override prefix (0x66) applies to one
    /// instruction. Stored as state so that decoding within one
    /// `step` call can examine it.
    op_size_16: bool,
    /// Address-size override prefix (0x67). 32-bit-mode default
    /// already gives us 32-bit addresses; this flag flips to
    /// 16-bit. Round-1 instructions don't exercise it; setting it
    /// is preserved for the future.
    addr_size_16: bool,
    /// REP / REPE / REPNE prefix.
    rep_prefix: Option<RepPrefix>,
    /// Active segment-override prefix for the current instruction.
    /// `None` after each `step` reset; set when the prefix loop
    /// consumes one of `0x26 / 0x2E / 0x36 / 0x3E / 0x64 / 0x65`.
    seg_override: Option<Seg>,
    /// Per-segment linear bases. In flat 32-bit Windows mode, all
    /// segment bases are 0 except FS (TEB) and GS (rarely used in
    /// Indeo-era code). The PE loader / Sandbox primes these via
    /// [`Cpu::set_fs_base`]. References:
    /// Intel SDM Vol. 1 §3.4.4 (segment registers in 32-bit
    /// flat mode); Microsoft "TEB" documentation for FS use.
    fs_base: u32,
    gs_base: u32,
    /// x87 FPU control word — stored as a 16-bit shadow so a
    /// codec's `fnstcw m16 ; (modify) ; fldcw m16` boilerplate
    /// round-trips an exact value. We do not model the FPU stack,
    /// status word, or any FP math — round-10 codecs only set the
    /// CW for rounding-mode preservation, never read it back into
    /// arithmetic.
    ///
    /// Reference: Intel SDM Vol. 1 §8.1.5 (x87 FPU Control Word).
    /// Reset value 0x037F (RC=00 round-to-nearest, PC=11 64-bit
    /// extended precision, all exception masks set).
    pub fpu_cw: u16,
    /// x87 FPU state — eight ST(i) registers + TOP + status
    /// word. Round-21 lights up real FPU semantics so codec
    /// CRT init paths (`_initterm` global-double copy) and
    /// codec inner loops (FADD/FMUL/FDIV chains) execute. See
    /// [`super::isa_fpu`] for the supported subset.
    pub fpu: super::isa_fpu::FpuState,
    /// MMX register file `mm0..mm7`, eight 64-bit registers.
    ///
    /// Per Intel SDM Vol. 1 §9.2.1, the architectural MMX
    /// registers alias to the lower 64 bits of FPU stack
    /// `ST(0)..ST(7)`. We model them as a separate `[u64; 8]`
    /// array because the FPU stack is not modelled in this
    /// crate; codecs that mix x87 + MMX will need an explicit
    /// alias in a later round.
    ///
    /// Round 7 lands the register file + structured-trap
    /// dispatch surface; round 13 implements MMX semantics
    /// (`super::isa_mmx::dispatch`) so reads / writes to
    /// `mm0..mm7` no longer trap for the implemented subset.
    pub mmx: [u64; 8],
    /// Count of MMX (`0F 60..6F | 70..7F | D0..FF`) instructions
    /// successfully dispatched. Round-13 sentinel — lets a test
    /// confirm MMX semantics actually ran rather than the codec
    /// happening to take an integer-only path. Incremented in
    /// [`super::isa_mmx::dispatch`].
    pub mmx_dispatch_count: u64,
    /// Count of `CPUID` (`0F A2`) instructions executed. Round-14
    /// sentinel — when a codec's MMX path stays unreachable
    /// despite our reporting `CPUID.MMX = 1`, this counter lets
    /// the test confirm whether the codec is even querying CPUID
    /// (and therefore whether the gating is via CPUID at all,
    /// versus a static build-time choice or a different feature
    /// bit like SSE). Incremented in `cpuid()`.
    pub cpuid_dispatch_count: u64,
    /// Ring buffer of recently-executed instruction starts (eip
    /// before opcode fetch). Capacity 64. Used by trace mode
    /// (round 9) to surface a "last N opcodes" log when a trap
    /// fires deep inside the codec body. Disabled by default.
    pub trace_ring: Vec<u32>,
    /// Cap on `trace_ring` capacity; once full the oldest entry
    /// rolls off. 0 disables.
    pub trace_ring_cap: usize,
    /// Round-19 instrument: when `true`, every distinct entry-EIP
    /// is inserted into [`Self::visited_eips`]. Lets a research
    /// test answer "did the codec ever step at this RVA?" via a
    /// `BTreeSet::contains` lookup, far cheaper than capturing
    /// every instruction's EIP in a `Vec`. Used by
    /// `tests/round19_mmx_dispatch_analysis.rs` to compute the
    /// set-difference between MMX-byte RVAs in the binary and
    /// EIPs the decode actually reached.
    pub track_visited_eips: bool,
    /// Sorted set of every distinct entry-EIP observed while
    /// [`Self::track_visited_eips`] was on. Capped only by host
    /// memory; a decode of ~10⁷ instructions over a ~10⁶-byte
    /// .text section yields at most ~10⁶ unique entries. Cleared
    /// by [`Self::take_visited_eips`].
    pub visited_eips: BTreeSet<u32>,
    /// Round-40 instrument: when an entry-EIP matches a key in
    /// this set, [`Self::step`] appends a snapshot of the integer
    /// register file to [`Self::register_snapshots`].  Lets a
    /// research test answer "what was `ebx` immediately after
    /// `Transform` returned to its `0x402626` continuation point?"
    /// without recompiling the executor or stitching together a
    /// post-trap register file (which only carries the FAILING
    /// instruction's state, not arbitrary checkpoints inside the
    /// run).  Empty by default; populate via
    /// [`Self::add_register_watchpoint`].
    pub register_watchpoints: BTreeSet<u32>,
    /// Round-40 instrument: ordered list of register snapshots
    /// captured at watchpoint hits.  Each entry is
    /// `(eip, [eax, ecx, edx, ebx, esp, ebp, esi, edi])` in that
    /// fixed order.  Keep small (we cap a hot watchpoint at the
    /// first 8 hits in [`Self::step`]) so a Receive-driven loop
    /// doesn't accumulate megabytes of state.
    pub register_snapshots: Vec<(u32, [u32; 8])>,
    /// Round-40 instrument: parallel list of memory probes
    /// captured at watchpoint hits.  Each entry is
    /// `(eip, [(addr, value); 4])` — the four `[addr]` reads
    /// the watchpoint's host enrichment chose.  Stored as
    /// (addr, value) so the trap-time post-mortem doesn't have
    /// to re-load and possibly see a stale value.  Empty
    /// addr/value tuples (`(0, 0)`) mark unused slots.
    pub memory_snapshots: Vec<(u32, [(u32, u32); 4])>,
    /// Round-40: cap on `register_snapshots`.  After this many
    /// captures, additional watchpoint hits are silently
    /// dropped to keep the diagnostic compact.  Default 16.
    pub register_snapshots_cap: usize,
}

/// Segment-override prefix selector.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RepPrefix {
    Rep,   // 0xF3 — rep / repe (depends on instruction)
    Repne, // 0xF2 — repne / repnz
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpu {
    pub fn new() -> Self {
        Cpu {
            regs: Regs::new(),
            instr_count: 0,
            instr_limit: DEFAULT_INSTR_LIMIT,
            op_size_16: false,
            addr_size_16: false,
            rep_prefix: None,
            seg_override: None,
            fs_base: 0,
            gs_base: 0,
            fpu_cw: 0x037F,
            fpu: super::isa_fpu::FpuState::new(),
            mmx: [0u64; 8],
            mmx_dispatch_count: 0,
            cpuid_dispatch_count: 0,
            trace_ring: Vec::new(),
            trace_ring_cap: 0,
            track_visited_eips: false,
            visited_eips: BTreeSet::new(),
            register_watchpoints: BTreeSet::new(),
            register_snapshots: Vec::new(),
            memory_snapshots: Vec::new(),
            register_snapshots_cap: 16,
        }
    }

    /// Round-40: arm a register-snapshot watchpoint at `eip`.
    /// On the next [`Self::step`] entry that fires at this
    /// address, the integer register file is appended to
    /// [`Self::register_snapshots`] (subject to
    /// [`Self::register_snapshots_cap`]).  Multiple distinct
    /// watchpoints can be armed concurrently.  See
    /// [`Self::clear_register_watchpoints`] to disarm + drain.
    pub fn add_register_watchpoint(&mut self, eip: u32) {
        self.register_watchpoints.insert(eip);
    }

    /// Round-40: drain the captured snapshots and disarm every
    /// watchpoint.  Returns the captures in fire order.
    pub fn clear_register_watchpoints(&mut self) -> Vec<(u32, [u32; 8])> {
        self.register_watchpoints.clear();
        let _ = std::mem::take(&mut self.memory_snapshots);
        std::mem::take(&mut self.register_snapshots)
    }

    /// Round-40: drain memory snapshots captured at watchpoint
    /// hits.  Mirrors [`Self::clear_register_watchpoints`] but
    /// returns the per-hit memory probes (addr, value pairs) so
    /// the post-mortem can inspect the contents at the time the
    /// snapshot fired (NOT at trap time, which may have been
    /// overwritten by intervening writes).
    pub fn take_memory_snapshots(&mut self) -> Vec<(u32, [(u32, u32); 4])> {
        std::mem::take(&mut self.memory_snapshots)
    }

    /// Round-19: enable per-instruction unique-EIP tracking. Every
    /// subsequent [`Self::step`] inserts the entry-EIP into
    /// [`Self::visited_eips`]. Cheap (one `BTreeSet` membership
    /// probe + insert per instruction); the set's memory cost is
    /// proportional to the number of *unique* code addresses the
    /// codec actually steps through, not the total instruction
    /// count.
    pub fn enable_visited_eip_tracking(&mut self) {
        self.track_visited_eips = true;
    }

    /// Round-19: disable tracking. The accumulated set is
    /// preserved; call [`Self::take_visited_eips`] to consume it.
    pub fn disable_visited_eip_tracking(&mut self) {
        self.track_visited_eips = false;
    }

    /// Round-19: drain the accumulated set, returning every
    /// unique EIP recorded since tracking was enabled (or since
    /// the last `take`).
    pub fn take_visited_eips(&mut self) -> BTreeSet<u32> {
        std::mem::take(&mut self.visited_eips)
    }

    /// Enable instruction-level trace ring (capacity = `cap`
    /// last-executed instruction-start EIPs). Set 0 to disable.
    /// Round-9 debugging aid for the LMEM_MOVEABLE handle bug —
    /// lets a failing test print the last-executed N instructions
    /// when the trap surfaces from deep inside the codec body.
    pub fn enable_trace_ring(&mut self, cap: usize) {
        self.trace_ring_cap = cap;
        self.trace_ring.clear();
        if cap > 0 {
            self.trace_ring.reserve(cap);
        }
    }

    /// Override the per-run instruction count limit.
    pub fn set_instr_limit(&mut self, n: u64) {
        self.instr_limit = n;
    }

    /// Configure the linear base of the FS segment. In 32-bit flat
    /// mode every segment base is 0 EXCEPT FS, which Windows uses
    /// to point at the current thread's TEB (Thread Environment
    /// Block). The runtime calls this after mapping the TEB.
    pub fn set_fs_base(&mut self, base: u32) {
        self.fs_base = base;
    }

    /// Configure the linear base of the GS segment. Almost always
    /// 0 in user-mode 32-bit Windows; the setter is provided for
    /// completeness.
    pub fn set_gs_base(&mut self, base: u32) {
        self.gs_base = base;
    }

    /// Translate an effective address according to the current
    /// segment-override prefix. Called by every memory-touching
    /// helper. Returns the final linear address.
    pub(super) fn seg_translate(&self, ea: u32) -> u32 {
        match self.seg_override {
            Some(Seg::Fs) => ea.wrapping_add(self.fs_base),
            Some(Seg::Gs) => ea.wrapping_add(self.gs_base),
            // In 32-bit flat mode all other segment bases are 0,
            // so a CS/DS/ES/SS override is a no-op.
            _ => ea,
        }
    }

    /// Apply the active segment-override to an [`Operand`] —
    /// memory operands get `seg_base` added; register operands
    /// pass through unchanged. Use this on every operand returned
    /// from [`resolve_modrm32`].
    pub(super) fn seg_apply(&self, op: Operand) -> Operand {
        match op {
            Operand::Mem32(a) => Operand::Mem32(self.seg_translate(a)),
            other => other,
        }
    }

    /// Pub re-export for sibling modules ([`super::isa_fpu`]).
    pub(super) fn seg_apply_pub(&self, op: Operand) -> Operand {
        self.seg_apply(op)
    }

    /// Run until the instruction at `eip` is the synthetic return
    /// sentinel (== [`RET_SENTINEL`]) or a trap is raised.
    pub fn run(&mut self, mmu: &mut Mmu) -> Result<(), Trap> {
        loop {
            if self.regs.eip == RET_SENTINEL {
                return Ok(());
            }
            if self.instr_count >= self.instr_limit {
                return Err(Trap::InstructionLimitExceeded {
                    eip: self.regs.eip,
                    count: self.instr_count,
                });
            }
            match self.step(mmu)? {
                StepOk::Continued => continue,
                StepOk::Halted => return Ok(()),
            }
        }
    }

    /// Push a 32-bit value onto the guest stack.
    pub fn push32(&mut self, mmu: &mut Mmu, value: u32) -> Result<(), Trap> {
        let new_esp = self.regs.esp().wrapping_sub(4);
        self.regs.set_esp(new_esp);
        mmu.store32(new_esp, value)
    }

    /// Pop a 32-bit value off the guest stack.
    pub fn pop32(&mut self, mmu: &mut Mmu) -> Result<u32, Trap> {
        let esp = self.regs.esp();
        let v = mmu.load32(esp)?;
        self.regs.set_esp(esp.wrapping_add(4));
        Ok(v)
    }

    /// Push a 16-bit value onto the guest stack — used by 0x66-
    /// prefixed PUSH r16 / PUSH imm16 forms. Decrements ESP by 2.
    pub fn push16(&mut self, mmu: &mut Mmu, value: u16) -> Result<(), Trap> {
        let new_esp = self.regs.esp().wrapping_sub(2);
        self.regs.set_esp(new_esp);
        mmu.store16(new_esp, value)
    }

    /// Pop a 16-bit value off the guest stack — used by 0x66-
    /// prefixed POP r16 forms. Increments ESP by 2.
    pub fn pop16(&mut self, mmu: &mut Mmu) -> Result<u16, Trap> {
        let esp = self.regs.esp();
        let v = mmu.load16(esp)?;
        self.regs.set_esp(esp.wrapping_add(2));
        Ok(v)
    }

    /// Decode + execute one instruction. Returns
    /// [`StepOk::Halted`] when the instruction was a `ret` and
    /// the popped return address was [`RET_SENTINEL`].
    pub fn step(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        // Reset per-instruction prefix state.
        self.op_size_16 = false;
        self.addr_size_16 = false;
        self.rep_prefix = None;
        self.seg_override = None;

        let entry_eip = self.regs.eip;

        // Trace-feature-gated: shadow the entry EIP into the
        // MMU's trace state so memory probes that fire during
        // this instruction's execution carry the correct
        // call-site address. Cheap (a single u32 store).
        #[cfg(feature = "trace")]
        {
            mmu.trace.set_eip(entry_eip);
        }
        // Trace-exec sub-feature: emit a per-instruction event
        // when the runtime has flipped exec-trace on.
        #[cfg(feature = "trace-exec")]
        if mmu.trace.exec_on && mmu.trace.has_sink() {
            // Snapshot the next 1..=8 instruction bytes as best
            // effort — we don't decode here, the executor will
            // decode below. Empty bytes if even the first byte
            // is unfetchable (the executor will trap that
            // separately).
            let mut bytes = Vec::with_capacity(8);
            for i in 0..8u32 {
                match mmu.fetch_x8(entry_eip.wrapping_add(i)) {
                    Ok(b) => bytes.push(b),
                    Err(_) => break,
                }
            }
            let mnemonic = match bytes.first() {
                Some(b) => exec_mnemonic_hint(*b),
                None => "<unfetchable>",
            };
            // Snapshot the integer register file at instruction
            // entry. This matches the design-doc example which
            // includes the CPU state at the point of execution.
            let regs = [
                ("eax", self.regs.get32(Reg32::Eax)),
                ("ecx", self.regs.get32(Reg32::Ecx)),
                ("edx", self.regs.get32(Reg32::Edx)),
                ("ebx", self.regs.get32(Reg32::Ebx)),
                ("esp", self.regs.esp()),
                ("ebp", self.regs.get32(Reg32::Ebp)),
                ("esi", self.regs.get32(Reg32::Esi)),
                ("edi", self.regs.get32(Reg32::Edi)),
            ];
            mmu.trace.ev_exec(entry_eip, &bytes, mnemonic, &regs);
        }

        // Push entry_eip into the trace ring if enabled.
        if self.trace_ring_cap > 0 {
            if self.trace_ring.len() == self.trace_ring_cap {
                self.trace_ring.remove(0);
            }
            self.trace_ring.push(entry_eip);
        }

        // Round-19: record unique EIPs if tracking is on. The
        // BTreeSet's `insert` is idempotent; the per-instruction
        // cost is O(log N) over the visited-set size.
        if self.track_visited_eips {
            self.visited_eips.insert(entry_eip);
        }

        // Round-40: register-snapshot watchpoints.  Captured
        // BEFORE the instruction at `entry_eip` executes, so the
        // snapshot reflects the state at the watchpoint's entry
        // semantics (e.g. a snapshot at `Transform`'s return-to
        // continuation captures the registers as Transform left
        // them, before the next instruction mutates them).
        //
        // Also captures four parallel memory probes — the
        // `[esp]`, `[esp+4]`, `[ebp+8]`, `[ebp-0x50]` slots —
        // resolved at snapshot time, NOT at trap time.  This is
        // essential when a stack slot is later overwritten by
        // intervening writes; reading at trap time would mask
        // the original push.
        if !self.register_watchpoints.is_empty()
            && self.register_snapshots.len() < self.register_snapshots_cap
            && self.register_watchpoints.contains(&entry_eip)
        {
            let esp_now = self.regs.esp();
            let ebp_now = self.regs.get32(Reg32::Ebp);
            let snap = [
                self.regs.get32(Reg32::Eax),
                self.regs.get32(Reg32::Ecx),
                self.regs.get32(Reg32::Edx),
                self.regs.get32(Reg32::Ebx),
                esp_now,
                ebp_now,
                self.regs.get32(Reg32::Esi),
                self.regs.get32(Reg32::Edi),
            ];
            self.register_snapshots.push((entry_eip, snap));
            let probe_addrs = [
                esp_now,
                esp_now.wrapping_add(4),
                ebp_now.wrapping_add(8),
                ebp_now.wrapping_sub(0x50),
            ];
            let mut mem_snap: [(u32, u32); 4] = [(0, 0); 4];
            for (i, addr) in probe_addrs.iter().enumerate() {
                let v = mmu.load32(*addr).unwrap_or(0);
                mem_snap[i] = (*addr, v);
            }
            self.memory_snapshots.push((entry_eip, mem_snap));
        }

        // Consume legacy prefixes (max ~4; we cap at 8 to avoid
        // adversarial loops).
        for _ in 0..8 {
            let b = mmu.fetch_x8(self.regs.eip)?;
            match b {
                0x66 => {
                    self.op_size_16 = true;
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                0x67 => {
                    self.addr_size_16 = true;
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                0xF3 => {
                    self.rep_prefix = Some(RepPrefix::Rep);
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                0xF2 => {
                    self.rep_prefix = Some(RepPrefix::Repne);
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                // Segment-override prefixes. In 32-bit flat mode
                // ES/CS/SS/DS bases are 0 (no-op); FS/GS bases are
                // primed by the runtime (FS → TEB, GS → user-data
                // base). All effective addresses computed for this
                // instruction get `seg_base` added in
                // [`Self::seg_translate`].
                0x26 => {
                    self.seg_override = Some(Seg::Es);
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                0x2E => {
                    self.seg_override = Some(Seg::Cs);
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                0x36 => {
                    self.seg_override = Some(Seg::Ss);
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                0x3E => {
                    self.seg_override = Some(Seg::Ds);
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                0x64 => {
                    self.seg_override = Some(Seg::Fs);
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                0x65 => {
                    self.seg_override = Some(Seg::Gs);
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                // Lock prefix — accepted; the relevant atomic
                // instructions are correct-by-construction in our
                // single-threaded interpreter.
                0xF0 => {
                    self.regs.eip = self.regs.eip.wrapping_add(1);
                }
                _ => break,
            }
        }

        let opcode = mmu.fetch_x8(self.regs.eip)?;
        self.regs.eip = self.regs.eip.wrapping_add(1);
        self.instr_count += 1;

        let res = self.dispatch(opcode, entry_eip, mmu);
        match res {
            Ok(s) => Ok(s),
            Err(Trap::UndefinedOpcode { opcode: op, .. }) => {
                // Restate the trap with the actual entry-eip.
                Err(Trap::UndefinedOpcode {
                    eip: entry_eip,
                    opcode: op,
                })
            }
            Err(e) => Err(e),
        }
    }

    fn dispatch(&mut self, op: u8, entry_eip: u32, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        match op {
            // ----------- ALU r/m, r and r, r/m (group on opcode bits) ------
            // 0x00..=0x05 : ADD
            0x00 => self.alu_rm8_r8(mmu, alu_add_8),
            0x01 => self.alu_rm32_r32(op, mmu, alu_add_32),
            0x02 => self.alu_r8_rm8(mmu, alu_add_8),
            0x03 => self.alu_r32_rm32(op, mmu, alu_add_32),
            0x04 => self.alu_al_imm8(mmu, alu_add_8),
            0x05 => self.alu_eax_imm32(op, mmu, alu_add_32),

            // 0x08..=0x0D : OR
            0x08 => self.alu_rm8_r8(mmu, alu_or_8),
            0x09 => self.alu_rm32_r32(op, mmu, alu_or_32),
            0x0A => self.alu_r8_rm8(mmu, alu_or_8),
            0x0B => self.alu_r32_rm32(op, mmu, alu_or_32),
            0x0C => self.alu_al_imm8(mmu, alu_or_8),
            0x0D => self.alu_eax_imm32(op, mmu, alu_or_32),

            // 0x10..=0x15 : ADC
            0x10 => self.alu_rm8_r8(mmu, alu_adc_8),
            0x11 => self.alu_rm32_r32(op, mmu, alu_adc_32),
            0x12 => self.alu_r8_rm8(mmu, alu_adc_8),
            0x13 => self.alu_r32_rm32(op, mmu, alu_adc_32),
            0x14 => self.alu_al_imm8(mmu, alu_adc_8),
            0x15 => self.alu_eax_imm32(op, mmu, alu_adc_32),

            // 0x18..=0x1D : SBB
            0x18 => self.alu_rm8_r8(mmu, alu_sbb_8),
            0x19 => self.alu_rm32_r32(op, mmu, alu_sbb_32),
            0x1A => self.alu_r8_rm8(mmu, alu_sbb_8),
            0x1B => self.alu_r32_rm32(op, mmu, alu_sbb_32),
            0x1C => self.alu_al_imm8(mmu, alu_sbb_8),
            0x1D => self.alu_eax_imm32(op, mmu, alu_sbb_32),

            // 0x20..=0x25 : AND
            0x20 => self.alu_rm8_r8(mmu, alu_and_8),
            0x21 => self.alu_rm32_r32(op, mmu, alu_and_32),
            0x22 => self.alu_r8_rm8(mmu, alu_and_8),
            0x23 => self.alu_r32_rm32(op, mmu, alu_and_32),
            0x24 => self.alu_al_imm8(mmu, alu_and_8),
            0x25 => self.alu_eax_imm32(op, mmu, alu_and_32),

            // 0x28..=0x2D : SUB
            0x28 => self.alu_rm8_r8(mmu, alu_sub_8),
            0x29 => self.alu_rm32_r32(op, mmu, alu_sub_32),
            0x2A => self.alu_r8_rm8(mmu, alu_sub_8),
            0x2B => self.alu_r32_rm32(op, mmu, alu_sub_32),
            0x2C => self.alu_al_imm8(mmu, alu_sub_8),
            0x2D => self.alu_eax_imm32(op, mmu, alu_sub_32),

            // 0x30..=0x35 : XOR
            0x30 => self.alu_rm8_r8(mmu, alu_xor_8),
            0x31 => self.alu_rm32_r32(op, mmu, alu_xor_32),
            0x32 => self.alu_r8_rm8(mmu, alu_xor_8),
            0x33 => self.alu_r32_rm32(op, mmu, alu_xor_32),
            0x34 => self.alu_al_imm8(mmu, alu_xor_8),
            0x35 => self.alu_eax_imm32(op, mmu, alu_xor_32),

            // 0x38..=0x3D : CMP
            0x38 => self.alu_rm8_r8(mmu, alu_cmp_8),
            0x39 => self.alu_rm32_r32(op, mmu, alu_cmp_32),
            0x3A => self.alu_r8_rm8(mmu, alu_cmp_8),
            0x3B => self.alu_r32_rm32(op, mmu, alu_cmp_32),
            0x3C => self.alu_al_imm8(mmu, alu_cmp_8),
            0x3D => self.alu_eax_imm32(op, mmu, alu_cmp_32),

            // ----------- INC/DEC r32 (single-byte forms 0x40..=0x4F) ------
            // Under 0x66, these become INC/DEC r16 — the destination
            // is the low 16 bits of the corresponding GP reg, and
            // flags are computed at 16-bit width (sign bit at 0x8000).
            0x40..=0x47 => {
                if self.op_size_16 {
                    let r = Reg16::from_bits(op - 0x40);
                    let v = self.regs.get16(r);
                    let cf = self.regs.flags.cf;
                    let out = v.wrapping_add(1);
                    self.regs.set16(r, out);
                    set_flags_inc_dec_16(&mut self.regs.flags, v, 1, out, /*sub*/ false);
                    self.regs.flags.cf = cf; // INC preserves CF
                } else {
                    let r = Reg32::from_bits(op - 0x40);
                    let v = self.regs.get32(r);
                    let (out, carry_unchanged) = (v.wrapping_add(1), self.regs.flags.cf);
                    self.regs.set32(r, out);
                    set_flags_inc_dec_32(&mut self.regs.flags, v, 1, out, /*sub*/ false);
                    self.regs.flags.cf = carry_unchanged; // INC preserves CF
                }
                Ok(StepOk::Continued)
            }
            0x48..=0x4F => {
                if self.op_size_16 {
                    let r = Reg16::from_bits(op - 0x48);
                    let v = self.regs.get16(r);
                    let cf = self.regs.flags.cf;
                    let out = v.wrapping_sub(1);
                    self.regs.set16(r, out);
                    set_flags_inc_dec_16(&mut self.regs.flags, v, 1, out, /*sub*/ true);
                    self.regs.flags.cf = cf; // DEC preserves CF
                } else {
                    let r = Reg32::from_bits(op - 0x48);
                    let v = self.regs.get32(r);
                    let out = v.wrapping_sub(1);
                    let carry_unchanged = self.regs.flags.cf;
                    self.regs.set32(r, out);
                    set_flags_inc_dec_32(&mut self.regs.flags, v, 1, out, /*sub*/ true);
                    self.regs.flags.cf = carry_unchanged; // DEC preserves CF
                }
                Ok(StepOk::Continued)
            }

            // 0x60 — PUSHAD: push eax, ecx, edx, ebx, original esp, ebp, esi, edi
            0x60 => {
                let original_esp = self.regs.esp();
                let to_push = [
                    self.regs.get32(Reg32::Eax),
                    self.regs.get32(Reg32::Ecx),
                    self.regs.get32(Reg32::Edx),
                    self.regs.get32(Reg32::Ebx),
                    original_esp,
                    self.regs.get32(Reg32::Ebp),
                    self.regs.get32(Reg32::Esi),
                    self.regs.get32(Reg32::Edi),
                ];
                for v in to_push.iter() {
                    self.push32(mmu, *v)?;
                }
                Ok(StepOk::Continued)
            }
            // 0x61 — POPAD: edi, esi, ebp, (skip original esp), ebx, edx, ecx, eax
            0x61 => {
                let edi = self.pop32(mmu)?;
                let esi = self.pop32(mmu)?;
                let ebp = self.pop32(mmu)?;
                let _skip_esp = self.pop32(mmu)?;
                let ebx = self.pop32(mmu)?;
                let edx = self.pop32(mmu)?;
                let ecx = self.pop32(mmu)?;
                let eax = self.pop32(mmu)?;
                self.regs.set32(Reg32::Edi, edi);
                self.regs.set32(Reg32::Esi, esi);
                self.regs.set32(Reg32::Ebp, ebp);
                self.regs.set32(Reg32::Ebx, ebx);
                self.regs.set32(Reg32::Edx, edx);
                self.regs.set32(Reg32::Ecx, ecx);
                self.regs.set32(Reg32::Eax, eax);
                Ok(StepOk::Continued)
            }

            // ----------- PUSH / POP r32 (0x50..=0x5F) ------
            // Under 0x66, these become PUSH/POP r16; ESP changes by
            // 2 instead of 4, and the destination of POP is the low
            // 16 bits of the corresponding GP register (upper 16
            // preserved per Intel SDM Vol. 1 §3.4.1.1).
            0x50..=0x57 => {
                if self.op_size_16 {
                    let r = Reg16::from_bits(op - 0x50);
                    let v = self.regs.get16(r);
                    self.push16(mmu, v)?;
                } else {
                    let r = Reg32::from_bits(op - 0x50);
                    let v = self.regs.get32(r);
                    self.push32(mmu, v)?;
                }
                Ok(StepOk::Continued)
            }
            0x58..=0x5F => {
                if self.op_size_16 {
                    let r = Reg16::from_bits(op - 0x58);
                    let v = self.pop16(mmu)?;
                    self.regs.set16(r, v);
                } else {
                    let r = Reg32::from_bits(op - 0x58);
                    let v = self.pop32(mmu)?;
                    self.regs.set32(r, v);
                }
                Ok(StepOk::Continued)
            }

            // PUSH imm32 (0x68) / PUSH imm8 (0x6A) — under 0x66
            // PUSH imm16 / PUSH imm8-sign-extended-to-16, ESP -= 2.
            0x68 => {
                if self.op_size_16 {
                    let v = self.fetch_imm16(mmu)?;
                    self.push16(mmu, v)?;
                } else {
                    let v = self.fetch_imm32(mmu)?;
                    self.push32(mmu, v)?;
                }
                Ok(StepOk::Continued)
            }
            0x6A => {
                if self.op_size_16 {
                    let v = sign_ext_8_to_16(self.fetch_imm8(mmu)?);
                    self.push16(mmu, v)?;
                } else {
                    let v = sign_ext_8_to_32(self.fetch_imm8(mmu)?);
                    self.push32(mmu, v)?;
                }
                Ok(StepOk::Continued)
            }

            // 0x69 — IMUL r32, r/m32, imm32 (no prefix) // IMUL
            // r16, r/m16, imm16 (under 0x66).
            0x69 => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (src_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let src_op = self.seg_apply(src_op);
                if self.op_size_16 {
                    let imm = self.fetch_imm16(mmu)? as i16 as i32;
                    let dst = Reg16::from_bits(mr.reg);
                    let a = read_operand16(src_op, &self.regs, mmu)? as i16 as i32;
                    let prod = a.wrapping_mul(imm);
                    let trunc = prod as i16 as u16;
                    self.regs.set16(dst, trunc);
                    let overflow = prod != prod as i16 as i32;
                    self.regs.flags.cf = overflow;
                    self.regs.flags.of = overflow;
                    self.regs.flags.set_szp_16(trunc);
                } else {
                    let imm = self.fetch_imm32(mmu)? as i32 as i64;
                    let dst = Reg32::from_bits(mr.reg);
                    let a = read_operand32(src_op, &self.regs, mmu)? as i32 as i64;
                    let prod = a.wrapping_mul(imm);
                    let trunc = prod as i32 as u32;
                    self.regs.set32(dst, trunc);
                    let overflow = prod != prod as i32 as i64;
                    self.regs.flags.cf = overflow;
                    self.regs.flags.of = overflow;
                    self.regs.flags.set_szp_32(trunc);
                }
                Ok(StepOk::Continued)
            }
            // 0x6B — IMUL r32, r/m32, imm8 (sign-extended) //
            // IMUL r16, r/m16, imm8 (sign-extended-to-16) under
            // 0x66.
            0x6B => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (src_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let src_op = self.seg_apply(src_op);
                if self.op_size_16 {
                    let imm = sign_ext_8_to_16(self.fetch_imm8(mmu)?) as i16 as i32;
                    let dst = Reg16::from_bits(mr.reg);
                    let a = read_operand16(src_op, &self.regs, mmu)? as i16 as i32;
                    let prod = a.wrapping_mul(imm);
                    let trunc = prod as i16 as u16;
                    self.regs.set16(dst, trunc);
                    let overflow = prod != prod as i16 as i32;
                    self.regs.flags.cf = overflow;
                    self.regs.flags.of = overflow;
                    self.regs.flags.set_szp_16(trunc);
                } else {
                    let imm = sign_ext_8_to_32(self.fetch_imm8(mmu)?) as i32 as i64;
                    let dst = Reg32::from_bits(mr.reg);
                    let a = read_operand32(src_op, &self.regs, mmu)? as i32 as i64;
                    let prod = a.wrapping_mul(imm);
                    let trunc = prod as i32 as u32;
                    self.regs.set32(dst, trunc);
                    let overflow = prod != prod as i32 as i64;
                    self.regs.flags.cf = overflow;
                    self.regs.flags.of = overflow;
                    self.regs.flags.set_szp_32(trunc);
                }
                Ok(StepOk::Continued)
            }

            // ----------- Jcc rel8 (0x70..=0x7F) ------
            0x70..=0x7F => {
                let disp = sign_ext_8_to_32(self.fetch_imm8(mmu)?);
                let cond = condition_holds(op & 0x0F, &self.regs.flags);
                if cond {
                    self.regs.eip = self.regs.eip.wrapping_add(disp);
                }
                Ok(StepOk::Continued)
            }

            // ----------- 0x80 / 0x81 / 0x83 — group 1 ALU r/m, imm ------
            0x80 => self.group1_rm8_imm8(mmu),
            0x81 => self.group1_rm32_imm32(mmu),
            0x83 => self.group1_rm32_imm8(mmu),

            // ----------- 0x84 / 0x85 — TEST ------
            0x84 => self.test_rm8_r8(mmu),
            0x85 => self.alu_rm32_r32(op, mmu, alu_test_32),

            // 0x86 — XCHG r/m8, r8
            0x86 => {
                let mr = self.fetch_modrm(mmu)?;
                let (lhs, dst) = self.resolve_op8(mr, mmu)?;
                let rhs_reg = Reg8::from_bits(mr.reg);
                let rhs = self.regs.get8(rhs_reg);
                self.write_op8(dst, rhs, mmu)?;
                self.regs.set8(rhs_reg, lhs);
                Ok(StepOk::Continued)
            }
            // 0x87 — XCHG r/m32, r32
            0x87 => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (rm_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let rm_op = self.seg_apply(rm_op);
                let rhs_reg = Reg32::from_bits(mr.reg);
                let lhs = read_operand32(rm_op, &self.regs, mmu)?;
                let rhs = self.regs.get32(rhs_reg);
                write_operand32(rm_op, rhs, &mut self.regs, mmu)?;
                self.regs.set32(rhs_reg, lhs);
                Ok(StepOk::Continued)
            }

            // ----------- 0x88..=0x8B — MOV r/m, r // r, r/m ------
            0x88 => self.mov_rm8_r8(mmu),
            0x89 => self.mov_rm32_r32(mmu),
            0x8A => self.mov_r8_rm8(mmu),
            0x8B => self.mov_r32_rm32(mmu),

            // 0x8D — LEA r32, m
            0x8D => self.lea_r32_m(mmu),

            // 0x8F /0 — POP r/m32
            0x8F => self.pop_rm32(mmu),

            // 0x90 — NOP (also XCHG eax, eax)
            0x90 => Ok(StepOk::Continued),

            // 0x91..=0x97 — XCHG eax, r32
            0x91..=0x97 => {
                let r = Reg32::from_bits(op - 0x90);
                let a = self.regs.get32(Reg32::Eax);
                let b = self.regs.get32(r);
                self.regs.set32(Reg32::Eax, b);
                self.regs.set32(r, a);
                Ok(StepOk::Continued)
            }

            // 0x98 — CWDE: sign-extend ax into eax
            0x98 => {
                let v = self.regs.get16(Reg16::Ax) as i16 as i32 as u32;
                self.regs.set32(Reg32::Eax, v);
                Ok(StepOk::Continued)
            }
            // 0x99 — CDQ: sign-extend eax into edx:eax
            0x99 => {
                let v = self.regs.get32(Reg32::Eax);
                let sign = if (v & 0x8000_0000) != 0 {
                    0xFFFF_FFFF
                } else {
                    0
                };
                self.regs.set32(Reg32::Edx, sign);
                Ok(StepOk::Continued)
            }

            // 0x9C — PUSHFD (no prefix) // PUSHF (under 0x66)
            0x9C => {
                let v = self.regs.flags.pack();
                if self.op_size_16 {
                    self.push16(mmu, v as u16)?;
                } else {
                    self.push32(mmu, v)?;
                }
                Ok(StepOk::Continued)
            }
            // 0x9D — POPFD (no prefix) // POPF (under 0x66)
            0x9D => {
                if self.op_size_16 {
                    let lo = self.pop16(mmu)?;
                    let cur = self.regs.flags.pack();
                    self.regs.flags = Flags::unpack((cur & 0xFFFF_0000) | u32::from(lo));
                } else {
                    let v = self.pop32(mmu)?;
                    self.regs.flags = Flags::unpack(v);
                }
                Ok(StepOk::Continued)
            }
            // 0x9E — SAHF: load AH bits 0,2,4,6,7 → SF/ZF/AF/PF/CF
            0x9E => {
                let ah = self.regs.get8(Reg8::Ah);
                self.regs.flags.cf = (ah & 0x01) != 0;
                self.regs.flags.pf = (ah & 0x04) != 0;
                self.regs.flags.af = (ah & 0x10) != 0;
                self.regs.flags.zf = (ah & 0x40) != 0;
                self.regs.flags.sf = (ah & 0x80) != 0;
                Ok(StepOk::Continued)
            }
            // 0x9F — LAHF: store SF/ZF/AF/PF/CF (and bit-1 reserved=1) into AH
            0x9F => {
                let mut ah: u8 = 0b0000_0010; // bit 1 reads as 1
                if self.regs.flags.cf {
                    ah |= 0x01;
                }
                if self.regs.flags.pf {
                    ah |= 0x04;
                }
                if self.regs.flags.af {
                    ah |= 0x10;
                }
                if self.regs.flags.zf {
                    ah |= 0x40;
                }
                if self.regs.flags.sf {
                    ah |= 0x80;
                }
                self.regs.set8(Reg8::Ah, ah);
                Ok(StepOk::Continued)
            }

            // 0xA0 — MOV al, moffs8 ; 0xA1 — MOV eax, moffs32 ; A2/A3 inverse
            0xA0 => {
                let imm = self.fetch_imm32(mmu)?;
                let m = self.seg_translate(imm);
                let v = mmu.load8(m)?;
                self.regs.set8(Reg8::Al, v);
                Ok(StepOk::Continued)
            }
            0xA1 => {
                let imm = self.fetch_imm32(mmu)?;
                let m = self.seg_translate(imm);
                if self.op_size_16 {
                    // 0x66 0xA1 moffs32 — MOV AX, [moffs32]. The
                    // moffs is still 32 bits in 32-bit address mode;
                    // 0x66 only changes the destination width.
                    let v = mmu.load16(m)?;
                    self.regs.set16(Reg16::Ax, v);
                } else {
                    let v = mmu.load32(m)?;
                    self.regs.set32(Reg32::Eax, v);
                }
                Ok(StepOk::Continued)
            }
            0xA2 => {
                let imm = self.fetch_imm32(mmu)?;
                let m = self.seg_translate(imm);
                mmu.store8(m, self.regs.get8(Reg8::Al))?;
                Ok(StepOk::Continued)
            }
            0xA3 => {
                let imm = self.fetch_imm32(mmu)?;
                let m = self.seg_translate(imm);
                if self.op_size_16 {
                    mmu.store16(m, self.regs.get16(Reg16::Ax))?;
                } else {
                    mmu.store32(m, self.regs.get32(Reg32::Eax))?;
                }
                Ok(StepOk::Continued)
            }

            // 0xA4 — MOVSB ; 0xA5 — MOVSD
            0xA4 => self.string_movs(mmu, /*sized_dword*/ false),
            0xA5 => self.string_movs(mmu, /*sized_dword*/ true),

            // 0xA6 — CMPSB ; 0xA7 — CMPSD
            0xA6 => self.string_cmps(mmu, /*sized_dword*/ false),
            0xA7 => self.string_cmps(mmu, /*sized_dword*/ true),

            // 0xAA — STOSB ; 0xAB — STOSD
            0xAA => self.string_stos(mmu, /*sized_dword*/ false),
            0xAB => self.string_stos(mmu, /*sized_dword*/ true),

            // 0xAC — LODSB ; 0xAD — LODSD
            0xAC => self.string_lods(mmu, /*sized_dword*/ false),
            0xAD => self.string_lods(mmu, /*sized_dword*/ true),

            // 0xAE — SCASB ; 0xAF — SCASD
            0xAE => self.string_scas(mmu, /*sized_dword*/ false),
            0xAF => self.string_scas(mmu, /*sized_dword*/ true),

            // 0xA8 — TEST al, imm8
            0xA8 => {
                let imm = self.fetch_imm8(mmu)?;
                let res = self.regs.get8(Reg8::Al) & imm;
                self.regs.flags.cf = false;
                self.regs.flags.of = false;
                self.regs.flags.set_szp_8(res);
                Ok(StepOk::Continued)
            }
            // 0xA9 — TEST eax, imm32 (no prefix) // TEST AX,
            // imm16 (under 0x66).
            0xA9 => {
                if self.op_size_16 {
                    let imm = self.fetch_imm16(mmu)?;
                    let res = self.regs.get16(Reg16::Ax) & imm;
                    self.regs.flags.cf = false;
                    self.regs.flags.of = false;
                    self.regs.flags.set_szp_16(res);
                } else {
                    let imm = self.fetch_imm32(mmu)?;
                    let res = self.regs.get32(Reg32::Eax) & imm;
                    self.regs.flags.cf = false;
                    self.regs.flags.of = false;
                    self.regs.flags.set_szp_32(res);
                }
                Ok(StepOk::Continued)
            }

            // 0xB0..=0xB7 — MOV r8, imm8
            0xB0..=0xB7 => {
                let r = Reg8::from_bits(op - 0xB0);
                let imm = self.fetch_imm8(mmu)?;
                self.regs.set8(r, imm);
                Ok(StepOk::Continued)
            }
            // 0xB8..=0xBF — MOV r32, imm32 (no prefix) // MOV r16,
            // imm16 (under 0x66). Five vs three bytes; per Intel
            // SDM Vol. 1 §3.4.1.1 the upper 16 bits are preserved
            // when writing through the 16-bit alias.
            0xB8..=0xBF => {
                if self.op_size_16 {
                    let r = Reg16::from_bits(op - 0xB8);
                    let imm = self.fetch_imm16(mmu)?;
                    self.regs.set16(r, imm);
                } else {
                    let r = Reg32::from_bits(op - 0xB8);
                    let imm = self.fetch_imm32(mmu)?;
                    self.regs.set32(r, imm);
                }
                Ok(StepOk::Continued)
            }

            // 0xC0 — Group 2 (shifts) r/m8, imm8
            0xC0 => self.group2_rm8(mmu, ShiftCount::Imm8),
            // 0xC1 — Group 2 (shifts) r/m32, imm8
            0xC1 => self.group2_rm32(mmu, ShiftCount::Imm8),
            // 0xD0 — Group 2 (shifts) r/m8, 1
            0xD0 => self.group2_rm8(mmu, ShiftCount::One),
            // 0xD1 — Group 2 (shifts) r/m32, 1
            0xD1 => self.group2_rm32(mmu, ShiftCount::One),
            // 0xD2 — Group 2 (shifts) r/m8, CL
            0xD2 => self.group2_rm8(mmu, ShiftCount::Cl),
            // 0xD3 — Group 2 (shifts) r/m32, CL
            0xD3 => self.group2_rm32(mmu, ShiftCount::Cl),

            // x87 escapes 0xD8..=0xDF. Round 21 dispatches to a
            // real FPU executor in [`super::isa_fpu`]; the
            // executor models an eight-deep f64 stack + the
            // memory and reg-form ops codec DLLs touch. Forms
            // outside the implemented subset trap as
            // `PrivilegedOpcode` with a sub-form-named mnemonic
            // so the next contributor can localise.
            0xD8..=0xDF => super::isa_fpu::dispatch(self, mmu, op, entry_eip),

            // 0xC2 — RETN imm16 ; 0xC3 — RETN
            0xC2 => {
                let pop = self.fetch_imm16(mmu)?;
                let ret = self.pop32(mmu)?;
                self.regs
                    .set_esp(self.regs.esp().wrapping_add(u32::from(pop)));
                self.regs.eip = ret;
                if ret == RET_SENTINEL {
                    Ok(StepOk::Halted)
                } else {
                    Ok(StepOk::Continued)
                }
            }
            0xC3 => {
                let ret = self.pop32(mmu)?;
                self.regs.eip = ret;
                if ret == RET_SENTINEL {
                    Ok(StepOk::Halted)
                } else {
                    Ok(StepOk::Continued)
                }
            }

            // 0xC6 — MOV r/m8, imm8 (group 11 /0)
            0xC6 => {
                let mr = self.fetch_modrm(mmu)?;
                debug_assert!(mr.reg == 0, "group 11 /0");
                // The displacement (if any) follows the ModR/M
                // and *precedes* the imm8. Resolve the operand
                // first so eip advances over the disp, then fetch
                // the immediate.
                let (op_val, addr_or_reg) = self.resolve_op8(mr, mmu)?;
                let _ = op_val;
                let imm = self.fetch_imm8(mmu)?;
                self.write_op8(addr_or_reg, imm, mmu)?;
                Ok(StepOk::Continued)
            }
            // 0xC7 — MOV r/m32, imm32 (no prefix) // MOV r/m16,
            // imm16 (under 0x66). Intel SDM Vol. 2A "MOV":
            // `C7 /0 iw` (16-bit) and `C7 /0 id` (32-bit).
            0xC7 => {
                let mr = self.fetch_modrm(mmu)?;
                debug_assert!(mr.reg == 0, "group 11 /0");
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let op = self.seg_apply(op);
                if self.op_size_16 {
                    let imm = self.fetch_imm16(mmu)?;
                    write_operand16(op, imm, &mut self.regs, mmu)?;
                } else {
                    let imm = self.fetch_imm32(mmu)?;
                    write_operand32(op, imm, &mut self.regs, mmu)?;
                }
                Ok(StepOk::Continued)
            }

            // 0xC8 — ENTER imm16, imm8 (frame setup). We model the
            // common nesting=0 case fully; nesting>0 is rare and
            // pushes copied display links — handle it by tracing.
            0xC8 => {
                let alloc_size = self.fetch_imm16(mmu)?;
                let nesting_level = self.fetch_imm8(mmu)? & 0x1F;
                let frame_temp = self.regs.esp().wrapping_sub(4);
                self.push32(mmu, self.regs.ebp())?;
                if nesting_level == 0 {
                    self.regs.set32(Reg32::Ebp, frame_temp);
                    self.regs
                        .set_esp(self.regs.esp().wrapping_sub(u32::from(alloc_size)));
                } else {
                    let mut current_ebp = self.regs.ebp();
                    for _ in 1..nesting_level {
                        current_ebp = current_ebp.wrapping_sub(4);
                        let display = mmu.load32(current_ebp)?;
                        self.push32(mmu, display)?;
                    }
                    self.push32(mmu, frame_temp)?;
                    self.regs.set32(Reg32::Ebp, frame_temp);
                    self.regs
                        .set_esp(self.regs.esp().wrapping_sub(u32::from(alloc_size)));
                }
                Ok(StepOk::Continued)
            }
            // 0xC9 — LEAVE: mov esp, ebp; pop ebp
            0xC9 => {
                self.regs.set_esp(self.regs.ebp());
                let v = self.pop32(mmu)?;
                self.regs.set32(Reg32::Ebp, v);
                Ok(StepOk::Continued)
            }

            // 0xCC — INT 3 → trap. Codec DLLs do not use INT3
            // outside of debugger breakpoints, which the sandbox
            // cannot service.
            0xCC => Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "int3",
            }),

            // 0xCD — INT imm8 → trap.
            0xCD => Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "int imm8",
            }),

            // 0xCF — IRETD → trap.
            0xCF => Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "iretd",
            }),

            // 0xE8 — CALL rel32
            0xE8 => {
                let disp = self.fetch_imm32(mmu)? as i32;
                let target = (self.regs.eip as i32).wrapping_add(disp) as u32;
                self.push32(mmu, self.regs.eip)?;
                self.regs.eip = target;
                Ok(StepOk::Continued)
            }
            // 0xE9 — JMP rel32
            0xE9 => {
                let disp = self.fetch_imm32(mmu)? as i32;
                self.regs.eip = (self.regs.eip as i32).wrapping_add(disp) as u32;
                Ok(StepOk::Continued)
            }
            // 0xEB — JMP rel8
            0xEB => {
                let disp = sign_ext_8_to_32(self.fetch_imm8(mmu)?);
                self.regs.eip = self.regs.eip.wrapping_add(disp);
                Ok(StepOk::Continued)
            }

            // 0xF4 — HLT → trap
            0xF4 => Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "hlt",
            }),

            // 0xF5 — CMC : invert CF
            0xF5 => {
                self.regs.flags.cf = !self.regs.flags.cf;
                Ok(StepOk::Continued)
            }

            // 0xF6 — Group 3 (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV) r/m8
            0xF6 => self.group3_rm8(mmu, entry_eip),
            // 0xF7 — Group 3 (NEG / NOT / MUL / IMUL / DIV / IDIV) r/m32
            0xF7 => self.group3_rm32(mmu, entry_eip),

            // 0xF8 — CLC ; 0xF9 — STC
            0xF8 => {
                self.regs.flags.cf = false;
                Ok(StepOk::Continued)
            }
            0xF9 => {
                self.regs.flags.cf = true;
                Ok(StepOk::Continued)
            }

            // 0xFA / 0xFB — CLI / STI → trap
            0xFA | 0xFB => Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "cli/sti",
            }),

            // 0xFC — CLD ; 0xFD — STD
            0xFC => {
                self.regs.flags.df = false;
                Ok(StepOk::Continued)
            }
            0xFD => {
                self.regs.flags.df = true;
                Ok(StepOk::Continued)
            }

            // 0xFE — Group 4 (INC / DEC r/m8)
            0xFE => {
                let mr = self.fetch_modrm(mmu)?;
                let (val, dst) = self.resolve_op8(mr, mmu)?;
                match mr.reg {
                    0 => {
                        // INC: preserves CF
                        let r = val.wrapping_add(1);
                        let cf = self.regs.flags.cf;
                        self.regs.flags.af = ((val ^ 1 ^ r) & 0x10) != 0;
                        self.regs.flags.of = (((val ^ r) & (1u8 ^ r)) & 0x80) != 0;
                        self.regs.flags.set_szp_8(r);
                        self.regs.flags.cf = cf;
                        self.write_op8(dst, r, mmu)?;
                    }
                    1 => {
                        // DEC: preserves CF
                        let r = val.wrapping_sub(1);
                        let cf = self.regs.flags.cf;
                        self.regs.flags.af = ((val ^ 1 ^ r) & 0x10) != 0;
                        self.regs.flags.of = (((val ^ 1) & (val ^ r)) & 0x80) != 0;
                        self.regs.flags.set_szp_8(r);
                        self.regs.flags.cf = cf;
                        self.write_op8(dst, r, mmu)?;
                    }
                    other => {
                        return Err(Trap::UndefinedOpcode {
                            eip: entry_eip,
                            opcode: 0xFE00 | u32::from(other),
                        });
                    }
                }
                Ok(StepOk::Continued)
            }
            // 0xFF — Group 5 (INC / DEC / CALL / JMP / PUSH r/m32)
            0xFF => self.group5_rm32(mmu, entry_eip),

            // ----------- 0x0F two-byte escape ------
            0x0F => self.dispatch_0f(entry_eip, mmu),

            // Far-call / far-jmp / segment loads and other
            // non-supported single-byte opcodes trap.
            0x9A | 0xEA => Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "far call/jmp",
            }),
            0x8E | 0x8C => Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "mov sreg",
            }),

            other => Err(Trap::UndefinedOpcode {
                eip: entry_eip,
                opcode: u32::from(other),
            }),
        }
    }

    fn dispatch_0f(&mut self, entry_eip: u32, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let op2 = mmu.fetch_x8(self.regs.eip)?;
        self.regs.eip = self.regs.eip.wrapping_add(1);
        match op2 {
            // 0x0F 0x40..0x4F — CMOVcc r32, r/m32
            0x40..=0x4F => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (src_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let src_op = self.seg_apply(src_op);
                let dst = Reg32::from_bits(mr.reg);
                let src = read_operand32(src_op, &self.regs, mmu)?;
                if condition_holds(op2 & 0x0F, &self.regs.flags) {
                    self.regs.set32(dst, src);
                }
                Ok(StepOk::Continued)
            }
            // 0x0F 0x80..0x8F — Jcc rel32
            0x80..=0x8F => {
                let disp = self.fetch_imm32(mmu)? as i32;
                if condition_holds(op2 & 0x0F, &self.regs.flags) {
                    self.regs.eip = (self.regs.eip as i32).wrapping_add(disp) as u32;
                }
                Ok(StepOk::Continued)
            }
            // 0x0F 0x90..0x9F — SETcc r/m8
            0x90..=0x9F => {
                let mr = self.fetch_modrm(mmu)?;
                let bit = condition_holds(op2 & 0x0F, &self.regs.flags) as u8;
                let (_v, dst) = self.resolve_op8(mr, mmu)?;
                self.write_op8(dst, bit, mmu)?;
                Ok(StepOk::Continued)
            }
            // 0x0F 0x31 — RDTSC. Reads the time-stamp counter
            // into EDX:EAX. Round-19 codecs sometimes use RDTSC
            // to micro-benchmark a candidate decode kernel and
            // pick the fastest at `DRV_LOAD` time. We synthesise
            // a monotonically-increasing counter derived from
            // [`Cpu::instr_count`]: every two instructions
            // advance the TSC by one tick, so a benchmark of N
            // instructions sees ~N/2 ticks. EDX = 0 (we never
            // overflow 32-bit in any plausible decode path).
            //
            // Reference: Intel SDM Vol. 2B `RDTSC` instruction
            // reference.
            0x31 => {
                let tsc = self.instr_count >> 1;
                self.regs.set32(Reg32::Eax, tsc as u32);
                self.regs.set32(Reg32::Edx, (tsc >> 32) as u32);
                Ok(StepOk::Continued)
            }
            // 0x0F 0xA2 — CPUID
            0xA2 => {
                self.cpuid();
                Ok(StepOk::Continued)
            }
            // 0x0F 0xA3 — BT r/m32, r32
            0xA3 => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let op = self.seg_apply(op);
                let v = read_operand32(op, &self.regs, mmu)?;
                let bit = self.regs.get32(Reg32::from_bits(mr.reg)) & 31;
                self.regs.flags.cf = ((v >> bit) & 1) != 0;
                Ok(StepOk::Continued)
            }
            // 0x0F 0xA4 — SHLD r/m32, r32, imm8
            0xA4 => self.shld_imm(mmu),
            // 0x0F 0xA5 — SHLD r/m32, r32, CL
            0xA5 => self.shld_cl(mmu),
            // 0x0F 0xAC — SHRD r/m32, r32, imm8
            0xAC => self.shrd_imm(mmu),
            // 0x0F 0xAD — SHRD r/m32, r32, CL
            0xAD => self.shrd_cl(mmu),
            // 0x0F 0xAB — BTS r/m32, r32 (set bit, copy old value to CF)
            0xAB => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let op = self.seg_apply(op);
                let v = read_operand32(op, &self.regs, mmu)?;
                let bit = self.regs.get32(Reg32::from_bits(mr.reg)) & 31;
                self.regs.flags.cf = ((v >> bit) & 1) != 0;
                let new = v | (1u32 << bit);
                write_operand32(op, new, &mut self.regs, mmu)?;
                Ok(StepOk::Continued)
            }
            // 0x0F 0xB1 — CMPXCHG r/m32, r32
            0xB1 => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let op = self.seg_apply(op);
                let dest = read_operand32(op, &self.regs, mmu)?;
                let acc = self.regs.get32(Reg32::Eax);
                let src = self.regs.get32(Reg32::from_bits(mr.reg));
                let (_, _) = alu_sub_32(acc, dest, &mut self.regs.flags); // sets flags
                if acc == dest {
                    write_operand32(op, src, &mut self.regs, mmu)?;
                } else {
                    self.regs.set32(Reg32::Eax, dest);
                }
                Ok(StepOk::Continued)
            }
            // 0x0F 0xC1 — XADD r/m32, r32
            0xC1 => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let op = self.seg_apply(op);
                let dest = read_operand32(op, &self.regs, mmu)?;
                let src_reg = Reg32::from_bits(mr.reg);
                let src = self.regs.get32(src_reg);
                let (sum, _) = alu_add_32(dest, src, &mut self.regs.flags);
                self.regs.set32(src_reg, dest);
                write_operand32(op, sum, &mut self.regs, mmu)?;
                Ok(StepOk::Continued)
            }
            // 0x0F 0xC8..=0xCF — BSWAP r32
            0xC8..=0xCF => {
                let r = Reg32::from_bits(op2 - 0xC8);
                let v = self.regs.get32(r);
                self.regs.set32(r, v.swap_bytes());
                Ok(StepOk::Continued)
            }
            // 0x0F 0xAF — IMUL r32, r/m32
            0xAF => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let op = self.seg_apply(op);
                let dst = Reg32::from_bits(mr.reg);
                let a = self.regs.get32(dst) as i32 as i64;
                let b = read_operand32(op, &self.regs, mmu)? as i32 as i64;
                let prod = a.wrapping_mul(b);
                let trunc = prod as i32 as u32;
                self.regs.set32(dst, trunc);
                let overflow = prod != prod as i32 as i64;
                self.regs.flags.cf = overflow;
                self.regs.flags.of = overflow;
                self.regs.flags.set_szp_32(trunc);
                Ok(StepOk::Continued)
            }
            // 0x0F 0xB6 — MOVZX r32, r/m8
            0xB6 => {
                let mr = self.fetch_modrm(mmu)?;
                let dst = Reg32::from_bits(mr.reg);
                let (v, _) = self.resolve_op8(mr, mmu)?;
                self.regs.set32(dst, u32::from(v));
                Ok(StepOk::Continued)
            }
            // 0x0F 0xB7 — MOVZX r32, r/m16
            0xB7 => {
                let mr = self.fetch_modrm(mmu)?;
                let dst = Reg32::from_bits(mr.reg);
                let (v, _) = self.resolve_op16(mr, mmu)?;
                self.regs.set32(dst, u32::from(v));
                Ok(StepOk::Continued)
            }
            // 0x0F 0xBA — Group 8 (BT/BTS/BTR/BTC r/m32, imm8)
            0xBA => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let op = self.seg_apply(op);
                let v = read_operand32(op, &self.regs, mmu)?;
                let bit = u32::from(self.fetch_imm8(mmu)? & 0x1F);
                self.regs.flags.cf = ((v >> bit) & 1) != 0;
                let new = match mr.reg {
                    4 => return Ok(StepOk::Continued), // BT — flags only
                    5 => v | (1u32 << bit),            // BTS
                    6 => v & !(1u32 << bit),           // BTR
                    7 => v ^ (1u32 << bit),            // BTC
                    other => {
                        return Err(Trap::UndefinedOpcode {
                            eip: self.regs.eip,
                            opcode: 0x0F_BA00 | u32::from(other),
                        });
                    }
                };
                write_operand32(op, new, &mut self.regs, mmu)?;
                Ok(StepOk::Continued)
            }
            // 0x0F 0xBC — BSF r32, r/m32 ; 0xBD — BSR
            0xBC | 0xBD => {
                let mr = self.fetch_modrm(mmu)?;
                let bytes = self.peek_after_modrm(mmu, 16)?;
                let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
                self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
                let op = self.seg_apply(op);
                let dst = Reg32::from_bits(mr.reg);
                let v = read_operand32(op, &self.regs, mmu)?;
                if v == 0 {
                    self.regs.flags.zf = true;
                } else {
                    self.regs.flags.zf = false;
                    let idx = if op2 == 0xBC {
                        v.trailing_zeros()
                    } else {
                        31 - v.leading_zeros()
                    };
                    self.regs.set32(dst, idx);
                }
                Ok(StepOk::Continued)
            }
            // 0x0F 0xBE — MOVSX r32, r/m8 ; 0xBF — MOVSX r32, r/m16
            0xBE => {
                let mr = self.fetch_modrm(mmu)?;
                let dst = Reg32::from_bits(mr.reg);
                let (v, _) = self.resolve_op8(mr, mmu)?;
                self.regs.set32(dst, v as i8 as i32 as u32);
                Ok(StepOk::Continued)
            }
            0xBF => {
                let mr = self.fetch_modrm(mmu)?;
                let dst = Reg32::from_bits(mr.reg);
                let (v, _) = self.resolve_op16(mr, mmu)?;
                self.regs.set32(dst, v as i16 as i32 as u32);
                Ok(StepOk::Continued)
            }
            // ---- MMX opcode space (Intel SDM Vol. 2, App. A) ----
            // Round 7: structured-trap surface; round 8 will land
            // semantics opcode-by-opcode.
            //
            //   0F 60..6F : PUNPCK*, PACK*, PCMP*, MOVD/MOVQ.
            //   0F 70..7F : PSHUFW, group-12/13/14 shifts (imm8),
            //               EMMS, MOVD/MOVQ.
            //   0F D0..FF : PADD*/PSUB*/PMUL*/PMADD/PCMPEQ/PSL*/
            //               PSR*/PAND/POR/PXOR/PADDS*/PSUBS*.
            0x60..=0x6F | 0x70..=0x7F | 0xD0..=0xFF => {
                super::isa_mmx::dispatch(self, mmu, op2, entry_eip)
            }
            other => Err(Trap::UndefinedOpcode {
                eip: entry_eip,
                opcode: 0x0F00 | u32::from(other),
            }),
        }
    }

    /// CPUID — return a fixed Pentium-class response. Per design
    /// doc §"Instruction set" Phase 1: vendor "GenuineIntel", no
    /// SSE, no AMD extensions.
    fn cpuid(&mut self) {
        self.cpuid_dispatch_count = self.cpuid_dispatch_count.wrapping_add(1);
        let leaf = self.regs.get32(Reg32::Eax);
        match leaf {
            0 => {
                // Max leaf = 1; vendor = "GenuineIntel" (ebx, edx, ecx)
                self.regs.set32(Reg32::Eax, 1);
                self.regs.set32(Reg32::Ebx, u32::from_le_bytes(*b"Genu"));
                self.regs.set32(Reg32::Edx, u32::from_le_bytes(*b"ineI"));
                self.regs.set32(Reg32::Ecx, u32::from_le_bytes(*b"ntel"));
            }
            1 => {
                // Pentium II Klamath (family 6, model 3,
                // stepping 0). Round-19 finding: round-13's Pentium
                // MMX (family 5) reading kept Indeo's MMX block
                // unreached because the codec's
                // `family << 8 ; cmp 0x600` discriminator routes
                // family-5 CPUs to the integer path. Family 6 is
                // the lowest where the MMX dispatcher actually
                // selects MMX kernels. Pentium II is the choice
                // because it supports MMX (CPUID.EDX bit 23) but
                // NOT SSE (bit 25) — the codec's SSE / SSE2
                // paths would trip our integer-only emulator.
                //
                // References: Intel SDM Vol. 2B `CPUID` reference
                // §"Family/Model/Stepping in EAX"; Intel Processor
                // Identification Application Note AP-485 Table 5
                // ("Pentium II Klamath" = family 6, model 3).
                self.regs.set32(Reg32::Eax, (6 << 8) | (3 << 4));
                self.regs.set32(Reg32::Ebx, 0);
                self.regs.set32(Reg32::Ecx, 0);
                // Feature bits: FPU(0)+TSC(4)+CX8(8)+CMOV(15)+MMX(23).
                // CMOV (`0F 40..4F`) is round-5 implemented; we
                // already advertise it implicitly by passing the
                // codec's runtime CMOV path (no codec we've seen
                // gates on this bit, but reporting it matches the
                // Pentium II feature set we claim to be).
                // No SSE (25), no SSE2 (26) — those need a 16-byte
                // SIMD register file and ~150 opcodes we haven't
                // implemented.
                self.regs.set32(
                    Reg32::Edx,
                    (1 << 0) | (1 << 4) | (1 << 8) | (1 << 15) | (1 << 23),
                );
            }
            _ => {
                self.regs.set32(Reg32::Eax, 0);
                self.regs.set32(Reg32::Ebx, 0);
                self.regs.set32(Reg32::Ecx, 0);
                self.regs.set32(Reg32::Edx, 0);
            }
        }
    }

    // ----- helpers ------------------------------------------------

    pub(super) fn fetch_imm8(&mut self, mmu: &Mmu) -> Result<u8, Trap> {
        let v = mmu.fetch_x8(self.regs.eip)?;
        self.regs.eip = self.regs.eip.wrapping_add(1);
        Ok(v)
    }

    fn fetch_imm16(&mut self, mmu: &Mmu) -> Result<u16, Trap> {
        let lo = mmu.fetch_x8(self.regs.eip)?;
        let hi = mmu.fetch_x8(self.regs.eip.wrapping_add(1))?;
        self.regs.eip = self.regs.eip.wrapping_add(2);
        Ok(u16::from_le_bytes([lo, hi]))
    }

    fn fetch_imm32(&mut self, mmu: &Mmu) -> Result<u32, Trap> {
        let b0 = mmu.fetch_x8(self.regs.eip)?;
        let b1 = mmu.fetch_x8(self.regs.eip.wrapping_add(1))?;
        let b2 = mmu.fetch_x8(self.regs.eip.wrapping_add(2))?;
        let b3 = mmu.fetch_x8(self.regs.eip.wrapping_add(3))?;
        self.regs.eip = self.regs.eip.wrapping_add(4);
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }

    pub(super) fn fetch_modrm(&mut self, mmu: &Mmu) -> Result<ModRm, Trap> {
        let b = self.fetch_imm8(mmu)?;
        Ok(ModRm::decode(b))
    }

    pub(super) fn peek_after_modrm(&self, mmu: &Mmu, n: usize) -> Result<Vec<u8>, Trap> {
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            // We tolerate an unmapped/unreadable trailing byte
            // because we may have asked for more than is needed;
            // resolve_modrm32 only reads what the (mod, rm)
            // encoding actually requires. We still propagate
            // execute-protect faults from the first few bytes.
            match mmu.fetch_x8(self.regs.eip.wrapping_add(i as u32)) {
                Ok(b) => out.push(b),
                Err(_) if i >= 1 => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    fn resolve_op8(&mut self, mr: ModRm, mmu: &mut Mmu) -> Result<(u8, Op8Dst), Trap> {
        if mr.mode == 0b11 {
            let r = Reg8::from_bits(mr.rm);
            Ok((self.regs.get8(r), Op8Dst::Reg(r)))
        } else {
            let bytes = self.peek_after_modrm(mmu, 16)?;
            let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
            self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
            match self.seg_apply(op) {
                Operand::Reg32(_) => unreachable!("mod != 11 cannot be reg form"),
                Operand::Mem32(addr) => Ok((mmu.load8(addr)?, Op8Dst::Mem(addr))),
            }
        }
    }

    fn resolve_op16(&mut self, mr: ModRm, mmu: &mut Mmu) -> Result<(u16, Op16Dst), Trap> {
        if mr.mode == 0b11 {
            let r = Reg16::from_bits(mr.rm);
            Ok((self.regs.get16(r), Op16Dst::Reg(r)))
        } else {
            let bytes = self.peek_after_modrm(mmu, 16)?;
            let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
            self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
            match self.seg_apply(op) {
                Operand::Reg32(_) => unreachable!(),
                Operand::Mem32(addr) => Ok((mmu.load16(addr)?, Op16Dst::Mem(addr))),
            }
        }
    }

    fn write_op8(&mut self, dst: Op8Dst, value: u8, mmu: &mut Mmu) -> Result<(), Trap> {
        match dst {
            Op8Dst::Reg(r) => {
                self.regs.set8(r, value);
                Ok(())
            }
            Op8Dst::Mem(addr) => mmu.store8(addr, value),
        }
    }

    // ----- ALU dispatch helpers (32-bit) --------------------------

    fn alu_rm32_r32(&mut self, op: u8, mmu: &mut Mmu, f: AluFn32) -> Result<StepOk, Trap> {
        if self.op_size_16 {
            let f16 = alu_fn16_for_opcode(op);
            return self.alu_rm16_r16(mmu, f16);
        }
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (lhs_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let lhs_op = self.seg_apply(lhs_op);
        let lhs = read_operand32(lhs_op, &self.regs, mmu)?;
        let rhs = self.regs.get32(Reg32::from_bits(mr.reg));
        let (result, write_back) = f(lhs, rhs, &mut self.regs.flags);
        if write_back {
            write_operand32(lhs_op, result, &mut self.regs, mmu)?;
        }
        Ok(StepOk::Continued)
    }

    fn alu_r32_rm32(&mut self, op: u8, mmu: &mut Mmu, f: AluFn32) -> Result<StepOk, Trap> {
        if self.op_size_16 {
            let f16 = alu_fn16_for_opcode(op);
            return self.alu_r16_rm16(mmu, f16);
        }
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (rhs_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let rhs_op = self.seg_apply(rhs_op);
        let dst = Reg32::from_bits(mr.reg);
        let lhs = self.regs.get32(dst);
        let rhs = read_operand32(rhs_op, &self.regs, mmu)?;
        let (result, write_back) = f(lhs, rhs, &mut self.regs.flags);
        if write_back {
            self.regs.set32(dst, result);
        }
        Ok(StepOk::Continued)
    }

    /// 16-bit analogue of [`Self::alu_rm32_r32`] used when 0x66
    /// rewrites the operand width.
    fn alu_rm16_r16(&mut self, mmu: &mut Mmu, f: AluFn16) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (lhs_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let lhs_op = self.seg_apply(lhs_op);
        let lhs = read_operand16(lhs_op, &self.regs, mmu)?;
        let rhs = self.regs.get16(Reg16::from_bits(mr.reg));
        let (result, write_back) = f(lhs, rhs, &mut self.regs.flags);
        if write_back {
            write_operand16(lhs_op, result, &mut self.regs, mmu)?;
        }
        Ok(StepOk::Continued)
    }

    /// 16-bit analogue of [`Self::alu_r32_rm32`] used when 0x66
    /// rewrites the operand width.
    fn alu_r16_rm16(&mut self, mmu: &mut Mmu, f: AluFn16) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (rhs_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let rhs_op = self.seg_apply(rhs_op);
        let dst = Reg16::from_bits(mr.reg);
        let lhs = self.regs.get16(dst);
        let rhs = read_operand16(rhs_op, &self.regs, mmu)?;
        let (result, write_back) = f(lhs, rhs, &mut self.regs.flags);
        if write_back {
            self.regs.set16(dst, result);
        }
        Ok(StepOk::Continued)
    }

    fn alu_eax_imm32(&mut self, op: u8, mmu: &Mmu, f: AluFn32) -> Result<StepOk, Trap> {
        if self.op_size_16 {
            let f16 = alu_fn16_for_opcode(op);
            let imm = self.fetch_imm16(mmu)?;
            let lhs = self.regs.get16(Reg16::Ax);
            let (result, write_back) = f16(lhs, imm, &mut self.regs.flags);
            if write_back {
                self.regs.set16(Reg16::Ax, result);
            }
            return Ok(StepOk::Continued);
        }
        let imm = self.fetch_imm32(mmu)?;
        let lhs = self.regs.get32(Reg32::Eax);
        let (result, write_back) = f(lhs, imm, &mut self.regs.flags);
        if write_back {
            self.regs.set32(Reg32::Eax, result);
        }
        Ok(StepOk::Continued)
    }

    // 0x80 — group 1 r/m8, imm8 (covers ADD/OR/ADC/SBB/AND/SUB/XOR/CMP)
    fn group1_rm8_imm8(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let (lhs, dst) = self.resolve_op8(mr, mmu)?;
        let imm = self.fetch_imm8(mmu)?;
        let (result, write_back) = group1_op_8(mr.reg, lhs, imm, &mut self.regs.flags);
        if write_back {
            self.write_op8(dst, result, mmu)?;
        }
        Ok(StepOk::Continued)
    }

    // 0x81 — group 1 r/m32, imm32 (no prefix) // r/m16, imm16
    // (under 0x66). Intel SDM Vol. 2A "Group 1": `81 /n iw`
    // (16-bit) and `81 /n id` (32-bit).
    fn group1_rm32_imm32(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (lhs_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let lhs_op = self.seg_apply(lhs_op);
        if self.op_size_16 {
            let lhs = read_operand16(lhs_op, &self.regs, mmu)?;
            let imm = self.fetch_imm16(mmu)?;
            let (result, write_back) = group1_op_16(mr.reg, lhs, imm, &mut self.regs.flags);
            if write_back {
                write_operand16(lhs_op, result, &mut self.regs, mmu)?;
            }
        } else {
            let lhs = read_operand32(lhs_op, &self.regs, mmu)?;
            let imm = self.fetch_imm32(mmu)?;
            let (result, write_back) = group1_op_32(mr.reg, lhs, imm, &mut self.regs.flags);
            if write_back {
                write_operand32(lhs_op, result, &mut self.regs, mmu)?;
            }
        }
        Ok(StepOk::Continued)
    }

    // 0x83 — group 1 r/m32, imm8 (sign-extended) // r/m16, imm8
    // (sign-extended-to-16) under 0x66. `83` always has an imm8;
    // 0x66 only changes the destination size, not the immediate.
    fn group1_rm32_imm8(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (lhs_op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let lhs_op = self.seg_apply(lhs_op);
        if self.op_size_16 {
            let lhs = read_operand16(lhs_op, &self.regs, mmu)?;
            let imm = sign_ext_8_to_16(self.fetch_imm8(mmu)?);
            let (result, write_back) = group1_op_16(mr.reg, lhs, imm, &mut self.regs.flags);
            if write_back {
                write_operand16(lhs_op, result, &mut self.regs, mmu)?;
            }
        } else {
            let lhs = read_operand32(lhs_op, &self.regs, mmu)?;
            let imm = sign_ext_8_to_32(self.fetch_imm8(mmu)?);
            let (result, write_back) = group1_op_32(mr.reg, lhs, imm, &mut self.regs.flags);
            if write_back {
                write_operand32(lhs_op, result, &mut self.regs, mmu)?;
            }
        }
        Ok(StepOk::Continued)
    }

    fn test_rm8_r8(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let (lhs, _dst) = self.resolve_op8(mr, mmu)?;
        let rhs = self.regs.get8(Reg8::from_bits(mr.reg));
        let res = lhs & rhs;
        self.regs.flags.cf = false;
        self.regs.flags.of = false;
        self.regs.flags.set_szp_8(res);
        Ok(StepOk::Continued)
    }

    fn mov_rm8_r8(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let (_v, dst) = self.resolve_op8(mr, mmu)?;
        let src = self.regs.get8(Reg8::from_bits(mr.reg));
        self.write_op8(dst, src, mmu)?;
        Ok(StepOk::Continued)
    }

    fn mov_rm32_r32(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        if self.op_size_16 {
            // 0x66 prefix: MOV r/m16, r16. The reg field still
            // selects from the same r0..r7 quadrant — we reinterpret
            // it as the low-16 of the corresponding GP reg.
            let src = self.regs.get32(Reg32::from_bits(mr.reg)) as u16;
            write_operand16(op, src, &mut self.regs, mmu)?;
        } else {
            let src = self.regs.get32(Reg32::from_bits(mr.reg));
            write_operand32(op, src, &mut self.regs, mmu)?;
        }
        Ok(StepOk::Continued)
    }

    fn mov_r8_rm8(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let (v, _dst) = self.resolve_op8(mr, mmu)?;
        self.regs.set8(Reg8::from_bits(mr.reg), v);
        Ok(StepOk::Continued)
    }

    fn mov_r32_rm32(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        if self.op_size_16 {
            // 0x66 prefix: MOV r16, r/m16. Preserves the upper 16
            // bits of the destination register per Intel SDM
            // Vol. 1 §3.4.1.1 (general-purpose register access in
            // 32-bit mode; 16-bit register operations leave bits
            // 31:16 unchanged).
            let src = read_operand16(op, &self.regs, mmu)?;
            let dst = Reg32::from_bits(mr.reg);
            let prev = self.regs.get32(dst);
            self.regs.set32(dst, (prev & 0xFFFF_0000) | u32::from(src));
        } else {
            let src = read_operand32(op, &self.regs, mmu)?;
            self.regs.set32(Reg32::from_bits(mr.reg), src);
        }
        Ok(StepOk::Continued)
    }

    fn lea_r32_m(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        if mr.mode == 0b11 {
            return Err(Trap::UndefinedOpcode {
                eip: self.regs.eip,
                opcode: 0x8D,
            });
        }
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        // LEA computes the effective address WITHOUT applying any
        // segment-base — Intel SDM Vol. 2A LEA.
        let addr = match op {
            Operand::Mem32(a) => a,
            Operand::Reg32(_) => unreachable!(),
        };
        self.regs.set32(Reg32::from_bits(mr.reg), addr);
        Ok(StepOk::Continued)
    }

    fn pop_rm32(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        if mr.reg != 0 {
            return Err(Trap::UndefinedOpcode {
                eip: self.regs.eip,
                opcode: 0x8F,
            });
        }
        let v = self.pop32(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        write_operand32(op, v, &mut self.regs, mmu)?;
        Ok(StepOk::Continued)
    }

    fn group2_rm32(&mut self, mmu: &mut Mmu, source: ShiftCount) -> Result<StepOk, Trap> {
        if self.op_size_16 {
            return self.group2_rm16(mmu, source);
        }
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let val = read_operand32(op, &self.regs, mmu)?;
        let count = match source {
            ShiftCount::One => 1u32,
            ShiftCount::Cl => u32::from(self.regs.get8(Reg8::Cl)) & 0x1F,
            ShiftCount::Imm8 => u32::from(self.fetch_imm8(mmu)? & 0x1F),
        };
        let result = match mr.reg {
            // 0=ROL 1=ROR 2=RCL 3=RCR 4=SHL 5=SHR 6=SAL 7=SAR
            4 | 6 => {
                let r = if count >= 32 { 0 } else { val << count };
                if count != 0 {
                    self.regs.flags.cf = if count <= 32 {
                        (val >> (32 - count)) & 1 != 0
                    } else {
                        false
                    };
                    self.regs.flags.set_szp_32(r);
                }
                r
            }
            5 => {
                let r = if count >= 32 { 0 } else { val >> count };
                if count != 0 {
                    self.regs.flags.cf = ((val >> (count - 1)) & 1) != 0;
                    self.regs.flags.set_szp_32(r);
                }
                r
            }
            7 => {
                let signed = val as i32;
                let r = if count >= 32 {
                    if signed < 0 {
                        -1i32 as u32
                    } else {
                        0
                    }
                } else {
                    (signed >> count) as u32
                };
                if count != 0 {
                    self.regs.flags.cf = ((val >> (count - 1)) & 1) != 0;
                    self.regs.flags.set_szp_32(r);
                }
                r
            }
            0 => {
                // ROL
                let c = count % 32;
                let r = if c == 0 { val } else { val.rotate_left(c) };
                if count != 0 {
                    self.regs.flags.cf = (r & 1) != 0;
                }
                r
            }
            1 => {
                // ROR
                let c = count % 32;
                let r = if c == 0 { val } else { val.rotate_right(c) };
                if count != 0 {
                    self.regs.flags.cf = (r & 0x8000_0000) != 0;
                }
                r
            }
            2 => {
                // RCL — rotate through carry. Per Intel SDM
                // Vol. 2A "RCL/RCR" the 32-bit count is masked
                // to 5 bits before the rotate; the carry-out
                // is the high bit pre-rotate, the carry-in
                // becomes the new bit 0.
                let mut v = val;
                let mut cf = self.regs.flags.cf;
                let c = count & 0x1F;
                for _ in 0..c {
                    let new_cf = (v & 0x8000_0000) != 0;
                    v = (v << 1) | (cf as u32);
                    cf = new_cf;
                }
                if count != 0 {
                    self.regs.flags.cf = cf;
                }
                v
            }
            3 => {
                // RCR — rotate through carry, right.
                let mut v = val;
                let mut cf = self.regs.flags.cf;
                let c = count & 0x1F;
                for _ in 0..c {
                    let new_cf = (v & 1) != 0;
                    v = (v >> 1) | ((cf as u32) << 31);
                    cf = new_cf;
                }
                if count != 0 {
                    self.regs.flags.cf = cf;
                }
                v
            }
            other => {
                return Err(Trap::UndefinedOpcode {
                    eip: self.regs.eip,
                    opcode: 0xC100 | u32::from(other),
                })
            }
        };
        write_operand32(op, result, &mut self.regs, mmu)?;
        Ok(StepOk::Continued)
    }

    /// 16-bit group-2 (`C1 / D1 / D3` under 0x66): shift / rotate
    /// r/m16. Per Intel SDM Vol. 2A "C1" entry, the shift count
    /// for 16-bit operands masks to 5 bits (same as 32-bit), but
    /// the operand width and flag-bit positions narrow.
    fn group2_rm16(&mut self, mmu: &mut Mmu, source: ShiftCount) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let val = read_operand16(op, &self.regs, mmu)?;
        let val32 = u32::from(val);
        let count = match source {
            ShiftCount::One => 1u32,
            ShiftCount::Cl => u32::from(self.regs.get8(Reg8::Cl)) & 0x1F,
            ShiftCount::Imm8 => u32::from(self.fetch_imm8(mmu)? & 0x1F),
        };
        let result: u16 = match mr.reg {
            4 | 6 => {
                let r = if count >= 16 { 0u32 } else { val32 << count };
                if count != 0 {
                    self.regs.flags.cf = if count <= 16 {
                        ((val32 >> (16 - count)) & 1) != 0
                    } else {
                        false
                    };
                    self.regs.flags.set_szp_16(r as u16);
                }
                r as u16
            }
            5 => {
                let r = if count >= 16 { 0u32 } else { val32 >> count };
                if count != 0 {
                    self.regs.flags.cf = ((val32 >> (count - 1)) & 1) != 0;
                    self.regs.flags.set_szp_16(r as u16);
                }
                r as u16
            }
            7 => {
                let signed = val as i16 as i32;
                let r = if count >= 16 {
                    if signed < 0 {
                        0xFFFFu16
                    } else {
                        0u16
                    }
                } else {
                    (signed >> count) as u16
                };
                if count != 0 {
                    self.regs.flags.cf = ((val32 >> (count - 1)) & 1) != 0;
                    self.regs.flags.set_szp_16(r);
                }
                r
            }
            0 => {
                let c = count % 16;
                let r = if c == 0 { val } else { val.rotate_left(c) };
                if count != 0 {
                    self.regs.flags.cf = (r & 1) != 0;
                }
                r
            }
            1 => {
                let c = count % 16;
                let r = if c == 0 { val } else { val.rotate_right(c) };
                if count != 0 {
                    self.regs.flags.cf = (r & 0x8000) != 0;
                }
                r
            }
            2 => {
                // 16-bit RCL through carry.
                let mut v = u32::from(val);
                let mut cf = self.regs.flags.cf;
                let c = count & 0x1F;
                for _ in 0..c {
                    let new_cf = (v & 0x8000) != 0;
                    v = ((v << 1) & 0xFFFF) | (cf as u32);
                    cf = new_cf;
                }
                if count != 0 {
                    self.regs.flags.cf = cf;
                }
                v as u16
            }
            3 => {
                // 16-bit RCR through carry.
                let mut v = u32::from(val);
                let mut cf = self.regs.flags.cf;
                let c = count & 0x1F;
                for _ in 0..c {
                    let new_cf = (v & 1) != 0;
                    v = (v >> 1) | ((cf as u32) << 15);
                    cf = new_cf;
                }
                if count != 0 {
                    self.regs.flags.cf = cf;
                }
                v as u16
            }
            other => {
                return Err(Trap::UndefinedOpcode {
                    eip: self.regs.eip,
                    opcode: 0xC100 | u32::from(other),
                });
            }
        };
        write_operand16(op, result, &mut self.regs, mmu)?;
        Ok(StepOk::Continued)
    }

    fn group3_rm32(&mut self, mmu: &mut Mmu, entry_eip: u32) -> Result<StepOk, Trap> {
        if self.op_size_16 {
            return self.group3_rm16(mmu, entry_eip);
        }
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let val = read_operand32(op, &self.regs, mmu)?;
        match mr.reg {
            0 | 1 => {
                // TEST r/m32, imm32
                let imm = self.fetch_imm32(mmu)?;
                let r = val & imm;
                self.regs.flags.cf = false;
                self.regs.flags.of = false;
                self.regs.flags.set_szp_32(r);
            }
            2 => {
                // NOT
                write_operand32(op, !val, &mut self.regs, mmu)?;
            }
            3 => {
                // NEG
                let r = 0u32.wrapping_sub(val);
                self.regs.flags.cf = val != 0;
                self.regs.flags.of = val == 0x8000_0000;
                self.regs.flags.set_szp_32(r);
                write_operand32(op, r, &mut self.regs, mmu)?;
            }
            4 => {
                // MUL eax, r/m32 → edx:eax
                let prod = u64::from(self.regs.get32(Reg32::Eax)) * u64::from(val);
                self.regs.set32(Reg32::Eax, prod as u32);
                self.regs.set32(Reg32::Edx, (prod >> 32) as u32);
                let hi_nonzero = (prod >> 32) != 0;
                self.regs.flags.cf = hi_nonzero;
                self.regs.flags.of = hi_nonzero;
            }
            5 => {
                // IMUL eax, r/m32 → edx:eax (signed)
                let prod = (self.regs.get32(Reg32::Eax) as i32 as i64) * (val as i32 as i64);
                self.regs.set32(Reg32::Eax, prod as u32);
                self.regs.set32(Reg32::Edx, (prod >> 32) as u32);
                let truncated = prod != prod as i32 as i64;
                self.regs.flags.cf = truncated;
                self.regs.flags.of = truncated;
            }
            6 => {
                // DIV r/m32: edx:eax / r/m32
                if val == 0 {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                let dividend = (u64::from(self.regs.get32(Reg32::Edx)) << 32)
                    | u64::from(self.regs.get32(Reg32::Eax));
                let q = dividend / u64::from(val);
                let r = dividend % u64::from(val);
                if q > u32::MAX as u64 {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                self.regs.set32(Reg32::Eax, q as u32);
                self.regs.set32(Reg32::Edx, r as u32);
            }
            7 => {
                // IDIV r/m32 (signed)
                if val == 0 {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                let dividend = (i64::from(self.regs.get32(Reg32::Edx) as i32) << 32)
                    | i64::from(self.regs.get32(Reg32::Eax));
                let divisor = val as i32 as i64;
                let q = dividend / divisor;
                let r = dividend % divisor;
                if !(i32::MIN as i64..=i32::MAX as i64).contains(&q) {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                self.regs.set32(Reg32::Eax, q as u32);
                self.regs.set32(Reg32::Edx, r as u32);
            }
            _ => unreachable!(),
        }
        Ok(StepOk::Continued)
    }

    /// 16-bit group-3 (`F7 /n` under 0x66): TEST/NOT/NEG/MUL/IMUL/
    /// DIV/IDIV r/m16. The TEST sub-form has imm16 not imm32; MUL
    /// targets DX:AX rather than EDX:EAX; the divide narrows.
    fn group3_rm16(&mut self, mmu: &mut Mmu, entry_eip: u32) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let val = read_operand16(op, &self.regs, mmu)?;
        match mr.reg {
            0 | 1 => {
                let imm = self.fetch_imm16(mmu)?;
                let r = val & imm;
                self.regs.flags.cf = false;
                self.regs.flags.of = false;
                self.regs.flags.set_szp_16(r);
            }
            2 => {
                write_operand16(op, !val, &mut self.regs, mmu)?;
            }
            3 => {
                let r = 0u16.wrapping_sub(val);
                self.regs.flags.cf = val != 0;
                self.regs.flags.of = val == 0x8000;
                self.regs.flags.set_szp_16(r);
                write_operand16(op, r, &mut self.regs, mmu)?;
            }
            4 => {
                // MUL ax, r/m16 → dx:ax
                let prod = u32::from(self.regs.get16(Reg16::Ax)) * u32::from(val);
                self.regs.set16(Reg16::Ax, prod as u16);
                self.regs.set16(Reg16::Dx, (prod >> 16) as u16);
                let hi_nonzero = (prod >> 16) != 0;
                self.regs.flags.cf = hi_nonzero;
                self.regs.flags.of = hi_nonzero;
            }
            5 => {
                // IMUL ax, r/m16 → dx:ax (signed)
                let prod = (self.regs.get16(Reg16::Ax) as i16 as i32) * (val as i16 as i32);
                self.regs.set16(Reg16::Ax, prod as u16);
                self.regs.set16(Reg16::Dx, (prod >> 16) as u16);
                let truncated = prod != prod as i16 as i32;
                self.regs.flags.cf = truncated;
                self.regs.flags.of = truncated;
            }
            6 => {
                // DIV dx:ax / r/m16
                if val == 0 {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                let dividend = (u32::from(self.regs.get16(Reg16::Dx)) << 16)
                    | u32::from(self.regs.get16(Reg16::Ax));
                let q = dividend / u32::from(val);
                let r = dividend % u32::from(val);
                if q > u16::MAX as u32 {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                self.regs.set16(Reg16::Ax, q as u16);
                self.regs.set16(Reg16::Dx, r as u16);
            }
            7 => {
                // IDIV dx:ax / r/m16 (signed)
                if val == 0 {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                let dividend = (i32::from(self.regs.get16(Reg16::Dx) as i16) << 16)
                    | (self.regs.get16(Reg16::Ax) as i16 as u16 as i32 & 0xFFFF);
                let divisor = val as i16 as i32;
                let q = dividend / divisor;
                let r = dividend % divisor;
                if !(i16::MIN as i32..=i16::MAX as i32).contains(&q) {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                self.regs.set16(Reg16::Ax, q as u16);
                self.regs.set16(Reg16::Dx, r as u16);
            }
            _ => unreachable!(),
        }
        Ok(StepOk::Continued)
    }

    // ----- ALU dispatch helpers (8-bit) ---------------------------

    fn alu_rm8_r8(&mut self, mmu: &mut Mmu, f: AluFn8) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let (lhs, dst) = self.resolve_op8(mr, mmu)?;
        let rhs = self.regs.get8(Reg8::from_bits(mr.reg));
        let (result, write_back) = f(lhs, rhs, &mut self.regs.flags);
        if write_back {
            self.write_op8(dst, result, mmu)?;
        }
        Ok(StepOk::Continued)
    }

    fn alu_r8_rm8(&mut self, mmu: &mut Mmu, f: AluFn8) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let (rhs, _dst) = self.resolve_op8(mr, mmu)?;
        let dst_reg = Reg8::from_bits(mr.reg);
        let lhs = self.regs.get8(dst_reg);
        let (result, write_back) = f(lhs, rhs, &mut self.regs.flags);
        if write_back {
            self.regs.set8(dst_reg, result);
        }
        Ok(StepOk::Continued)
    }

    fn alu_al_imm8(&mut self, mmu: &Mmu, f: AluFn8) -> Result<StepOk, Trap> {
        let imm = self.fetch_imm8(mmu)?;
        let lhs = self.regs.get8(Reg8::Al);
        let (result, write_back) = f(lhs, imm, &mut self.regs.flags);
        if write_back {
            self.regs.set8(Reg8::Al, result);
        }
        Ok(StepOk::Continued)
    }

    // ----- Group 2 (shifts) r/m8 ----------------------------------

    fn group2_rm8(&mut self, mmu: &mut Mmu, source: ShiftCount) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let (val, dst) = self.resolve_op8(mr, mmu)?;
        let count = match source {
            ShiftCount::One => 1u32,
            ShiftCount::Cl => u32::from(self.regs.get8(Reg8::Cl)) & 0x1F,
            ShiftCount::Imm8 => u32::from(self.fetch_imm8(mmu)? & 0x1F),
        };
        let val32 = u32::from(val);
        let result: u8 = match mr.reg {
            // 0=ROL 1=ROR 2=RCL 3=RCR 4=SHL 5=SHR 6=SAL 7=SAR
            4 | 6 => {
                let r = if count >= 8 { 0u32 } else { val32 << count };
                if count != 0 {
                    self.regs.flags.cf = if count <= 8 {
                        ((val32 >> (8 - count)) & 1) != 0
                    } else {
                        false
                    };
                    self.regs.flags.set_szp_8(r as u8);
                }
                r as u8
            }
            5 => {
                let r = if count >= 8 { 0u32 } else { val32 >> count };
                if count != 0 {
                    self.regs.flags.cf = ((val32 >> (count - 1)) & 1) != 0;
                    self.regs.flags.set_szp_8(r as u8);
                }
                r as u8
            }
            7 => {
                let signed = val as i8 as i32;
                let r = if count >= 8 {
                    if signed < 0 {
                        0xFFu8
                    } else {
                        0u8
                    }
                } else {
                    (signed >> count) as u8
                };
                if count != 0 {
                    self.regs.flags.cf = ((val32 >> (count - 1)) & 1) != 0;
                    self.regs.flags.set_szp_8(r);
                }
                r
            }
            0 => {
                // ROL r/m8
                let c = count % 8;
                let r = if c == 0 { val } else { val.rotate_left(c) };
                if count != 0 {
                    self.regs.flags.cf = (r & 1) != 0;
                }
                r
            }
            1 => {
                // ROR r/m8
                let c = count % 8;
                let r = if c == 0 { val } else { val.rotate_right(c) };
                if count != 0 {
                    self.regs.flags.cf = (r & 0x80) != 0;
                }
                r
            }
            2 => {
                // 8-bit RCL through carry. Per Intel SDM the
                // 9-bit ring (8 data + carry) rotates `count`
                // positions; count is masked to 5 bits, then
                // taken modulo 9.
                let mut v = u32::from(val);
                let mut cf = self.regs.flags.cf;
                let c = count & 0x1F;
                for _ in 0..c {
                    let new_cf = (v & 0x80) != 0;
                    v = ((v << 1) & 0xFF) | (cf as u32);
                    cf = new_cf;
                }
                if count != 0 {
                    self.regs.flags.cf = cf;
                }
                v as u8
            }
            3 => {
                // 8-bit RCR through carry.
                let mut v = u32::from(val);
                let mut cf = self.regs.flags.cf;
                let c = count & 0x1F;
                for _ in 0..c {
                    let new_cf = (v & 1) != 0;
                    v = (v >> 1) | ((cf as u32) << 7);
                    cf = new_cf;
                }
                if count != 0 {
                    self.regs.flags.cf = cf;
                }
                v as u8
            }
            other => {
                return Err(Trap::UndefinedOpcode {
                    eip: self.regs.eip,
                    opcode: 0xC000 | u32::from(other),
                });
            }
        };
        self.write_op8(dst, result, mmu)?;
        Ok(StepOk::Continued)
    }

    // ----- Group 3 r/m8 -------------------------------------------

    fn group3_rm8(&mut self, mmu: &mut Mmu, entry_eip: u32) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let (val, dst) = self.resolve_op8(mr, mmu)?;
        match mr.reg {
            0 | 1 => {
                // TEST r/m8, imm8
                let imm = self.fetch_imm8(mmu)?;
                let r = val & imm;
                self.regs.flags.cf = false;
                self.regs.flags.of = false;
                self.regs.flags.set_szp_8(r);
            }
            2 => {
                // NOT
                self.write_op8(dst, !val, mmu)?;
            }
            3 => {
                // NEG
                let r = 0u8.wrapping_sub(val);
                self.regs.flags.cf = val != 0;
                self.regs.flags.of = val == 0x80;
                self.regs.flags.set_szp_8(r);
                self.write_op8(dst, r, mmu)?;
            }
            4 => {
                // MUL al, r/m8 → ax
                let prod = u16::from(self.regs.get8(Reg8::Al)) * u16::from(val);
                self.regs.set16(Reg16::Ax, prod);
                let hi_nonzero = (prod & 0xFF00) != 0;
                self.regs.flags.cf = hi_nonzero;
                self.regs.flags.of = hi_nonzero;
            }
            5 => {
                // IMUL al, r/m8 → ax (signed)
                let prod = (self.regs.get8(Reg8::Al) as i8 as i16) * (val as i8 as i16);
                self.regs.set16(Reg16::Ax, prod as u16);
                let truncated = prod != prod as i8 as i16;
                self.regs.flags.cf = truncated;
                self.regs.flags.of = truncated;
            }
            6 => {
                // DIV ax / r/m8 → al = quotient, ah = remainder
                if val == 0 {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                let dividend = self.regs.get16(Reg16::Ax);
                let q = dividend / u16::from(val);
                let r = dividend % u16::from(val);
                if q > 0xFF {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                self.regs.set8(Reg8::Al, q as u8);
                self.regs.set8(Reg8::Ah, r as u8);
            }
            7 => {
                // IDIV ax / r/m8 (signed)
                if val == 0 {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                let dividend = self.regs.get16(Reg16::Ax) as i16;
                let divisor = val as i8 as i16;
                let q = dividend / divisor;
                let r = dividend % divisor;
                if !(i8::MIN as i16..=i8::MAX as i16).contains(&q) {
                    return Err(Trap::DivideByZero { eip: entry_eip });
                }
                self.regs.set8(Reg8::Al, q as u8);
                self.regs.set8(Reg8::Ah, r as u8);
            }
            _ => unreachable!(),
        }
        Ok(StepOk::Continued)
    }

    // ----- SHLD / SHRD --------------------------------------------

    fn shld_imm(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let imm = u32::from(self.fetch_imm8(mmu)? & 0x1F);
        self.shld_apply(op, mr.reg, imm, mmu)
    }

    fn shld_cl(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let count = u32::from(self.regs.get8(Reg8::Cl)) & 0x1F;
        self.shld_apply(op, mr.reg, count, mmu)
    }

    fn shld_apply(
        &mut self,
        op: Operand,
        reg_field: u8,
        count: u32,
        mmu: &mut Mmu,
    ) -> Result<StepOk, Trap> {
        let dest = read_operand32(op, &self.regs, mmu)?;
        let src = self.regs.get32(Reg32::from_bits(reg_field));
        if count == 0 {
            return Ok(StepOk::Continued);
        }
        // Per Intel SDM Vol 2A SHLD entry: bits shifted left in;
        // src provides the in-shifting bits from the right. Last
        // bit shifted out goes to CF.
        let combined: u64 = (u64::from(dest) << 32) | u64::from(src);
        let shifted = combined << count;
        let result = (shifted >> 32) as u32;
        self.regs.flags.cf = ((dest >> (32 - count)) & 1) != 0;
        self.regs.flags.set_szp_32(result);
        write_operand32(op, result, &mut self.regs, mmu)?;
        Ok(StepOk::Continued)
    }

    fn shrd_imm(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let imm = u32::from(self.fetch_imm8(mmu)? & 0x1F);
        self.shrd_apply(op, mr.reg, imm, mmu)
    }

    fn shrd_cl(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let count = u32::from(self.regs.get8(Reg8::Cl)) & 0x1F;
        self.shrd_apply(op, mr.reg, count, mmu)
    }

    fn shrd_apply(
        &mut self,
        op: Operand,
        reg_field: u8,
        count: u32,
        mmu: &mut Mmu,
    ) -> Result<StepOk, Trap> {
        let dest = read_operand32(op, &self.regs, mmu)?;
        let src = self.regs.get32(Reg32::from_bits(reg_field));
        if count == 0 {
            return Ok(StepOk::Continued);
        }
        // SHRD: shift `dest` right with bits from `src` shifted in
        // from the left. Last bit shifted out goes to CF.
        let combined: u64 = (u64::from(src) << 32) | u64::from(dest);
        let shifted = combined >> count;
        let result = shifted as u32;
        self.regs.flags.cf = ((dest >> (count - 1)) & 1) != 0;
        self.regs.flags.set_szp_32(result);
        write_operand32(op, result, &mut self.regs, mmu)?;
        Ok(StepOk::Continued)
    }

    // ----- String operations --------------------------------------
    //
    // Reference: Intel SDM Vol. 2 — entries for MOVS, CMPS, STOS,
    // LODS, SCAS. The DF flag determines pre-step direction. REP
    // / REPE / REPNE prefixes are honoured here; we model the
    // single-step semantics in helpers and loop only for REP.

    fn string_movs(&mut self, mmu: &mut Mmu, sized_dword: bool) -> Result<StepOk, Trap> {
        let size = self.string_size(sized_dword);
        let step = self.string_step_for(size);
        let do_one = |this: &mut Self, mmu: &mut Mmu| -> Result<(), Trap> {
            // Source uses DS (overridable); destination uses ES
            // (NOT overridable). seg_translate captures the
            // override on the source side; ES base is 0 in flat
            // 32-bit mode so the destination is unmodified.
            let src = this.seg_translate(this.regs.get32(Reg32::Esi));
            let dst = this.regs.get32(Reg32::Edi);
            match size {
                StringSize::B8 => {
                    let v = mmu.load8(src)?;
                    mmu.store8(dst, v)?;
                }
                StringSize::W16 => {
                    let v = mmu.load16(src)?;
                    mmu.store16(dst, v)?;
                }
                StringSize::D32 => {
                    let v = mmu.load32(src)?;
                    mmu.store32(dst, v)?;
                }
            }
            this.regs.set32(
                Reg32::Esi,
                this.regs.get32(Reg32::Esi).wrapping_add(step as u32),
            );
            this.regs.set32(
                Reg32::Edi,
                this.regs.get32(Reg32::Edi).wrapping_add(step as u32),
            );
            Ok(())
        };
        self.string_loop(mmu, do_one, /*compare*/ false)
    }

    fn string_stos(&mut self, mmu: &mut Mmu, sized_dword: bool) -> Result<StepOk, Trap> {
        let size = self.string_size(sized_dword);
        let step = self.string_step_for(size);
        let do_one = |this: &mut Self, mmu: &mut Mmu| -> Result<(), Trap> {
            let dst = this.regs.get32(Reg32::Edi);
            match size {
                StringSize::B8 => mmu.store8(dst, this.regs.get8(Reg8::Al))?,
                StringSize::W16 => mmu.store16(dst, this.regs.get16(Reg16::Ax))?,
                StringSize::D32 => mmu.store32(dst, this.regs.get32(Reg32::Eax))?,
            }
            this.regs.set32(Reg32::Edi, dst.wrapping_add(step as u32));
            Ok(())
        };
        self.string_loop(mmu, do_one, /*compare*/ false)
    }

    fn string_lods(&mut self, mmu: &mut Mmu, sized_dword: bool) -> Result<StepOk, Trap> {
        let size = self.string_size(sized_dword);
        let step = self.string_step_for(size);
        let do_one = |this: &mut Self, mmu: &mut Mmu| -> Result<(), Trap> {
            let src = this.regs.get32(Reg32::Esi);
            match size {
                StringSize::B8 => {
                    let v = mmu.load8(src)?;
                    this.regs.set8(Reg8::Al, v);
                }
                StringSize::W16 => {
                    let v = mmu.load16(src)?;
                    this.regs.set16(Reg16::Ax, v);
                }
                StringSize::D32 => {
                    let v = mmu.load32(src)?;
                    this.regs.set32(Reg32::Eax, v);
                }
            }
            this.regs.set32(Reg32::Esi, src.wrapping_add(step as u32));
            Ok(())
        };
        self.string_loop(mmu, do_one, /*compare*/ false)
    }

    fn string_cmps(&mut self, mmu: &mut Mmu, sized_dword: bool) -> Result<StepOk, Trap> {
        let size = self.string_size(sized_dword);
        let step = self.string_step_for(size);
        let do_one = |this: &mut Self, mmu: &mut Mmu| -> Result<(), Trap> {
            let src = this.regs.get32(Reg32::Esi);
            let dst = this.regs.get32(Reg32::Edi);
            match size {
                StringSize::B8 => {
                    let a = mmu.load8(src)?;
                    let b = mmu.load8(dst)?;
                    let _ = alu_sub_8(a, b, &mut this.regs.flags);
                }
                StringSize::W16 => {
                    let a = mmu.load16(src)?;
                    let b = mmu.load16(dst)?;
                    let _ = alu_sub_16(a, b, &mut this.regs.flags);
                }
                StringSize::D32 => {
                    let a = mmu.load32(src)?;
                    let b = mmu.load32(dst)?;
                    let _ = alu_sub_32(a, b, &mut this.regs.flags);
                }
            }
            this.regs.set32(Reg32::Esi, src.wrapping_add(step as u32));
            this.regs.set32(Reg32::Edi, dst.wrapping_add(step as u32));
            Ok(())
        };
        self.string_loop(mmu, do_one, /*compare*/ true)
    }

    fn string_scas(&mut self, mmu: &mut Mmu, sized_dword: bool) -> Result<StepOk, Trap> {
        let size = self.string_size(sized_dword);
        let step = self.string_step_for(size);
        let do_one = |this: &mut Self, mmu: &mut Mmu| -> Result<(), Trap> {
            let dst = this.regs.get32(Reg32::Edi);
            match size {
                StringSize::B8 => {
                    let v = mmu.load8(dst)?;
                    let acc = this.regs.get8(Reg8::Al);
                    let _ = alu_sub_8(acc, v, &mut this.regs.flags);
                }
                StringSize::W16 => {
                    let v = mmu.load16(dst)?;
                    let acc = this.regs.get16(Reg16::Ax);
                    let _ = alu_sub_16(acc, v, &mut this.regs.flags);
                }
                StringSize::D32 => {
                    let v = mmu.load32(dst)?;
                    let acc = this.regs.get32(Reg32::Eax);
                    let _ = alu_sub_32(acc, v, &mut this.regs.flags);
                }
            }
            this.regs.set32(Reg32::Edi, dst.wrapping_add(step as u32));
            Ok(())
        };
        self.string_loop(mmu, do_one, /*compare*/ true)
    }

    /// Resolve the operand size for a string opcode whose decoded
    /// table-form is "dword" but which 0x66 narrows to "word".
    /// 8-bit string ops (`A4/A6/AA/AC/AE`) ignore 0x66.
    fn string_size(&self, sized_dword: bool) -> StringSize {
        if !sized_dword {
            StringSize::B8
        } else if self.op_size_16 {
            StringSize::W16
        } else {
            StringSize::D32
        }
    }

    /// +N or -N depending on DF and operand size. Returned as i32
    /// so callers can sign-extend it via `as u32` for
    /// wrapping_add.
    fn string_step_for(&self, size: StringSize) -> i32 {
        let inc: i32 = match size {
            StringSize::B8 => 1,
            StringSize::W16 => 2,
            StringSize::D32 => 4,
        };
        if self.regs.flags.df {
            -inc
        } else {
            inc
        }
    }

    /// Common REP/REPE/REPNE wrapper. `compare` selects the
    /// repeat-while-flag termination semantics for CMPS/SCAS.
    fn string_loop(
        &mut self,
        mmu: &mut Mmu,
        mut step: impl FnMut(&mut Self, &mut Mmu) -> Result<(), Trap>,
        compare: bool,
    ) -> Result<StepOk, Trap> {
        match self.rep_prefix {
            None => {
                step(self, mmu)?;
                Ok(StepOk::Continued)
            }
            Some(rep) => {
                while self.regs.get32(Reg32::Ecx) != 0 {
                    step(self, mmu)?;
                    let new_ecx = self.regs.get32(Reg32::Ecx).wrapping_sub(1);
                    self.regs.set32(Reg32::Ecx, new_ecx);
                    if compare {
                        let zf = self.regs.flags.zf;
                        let stop = match rep {
                            RepPrefix::Rep => !zf,  // REPE: stop if !ZF
                            RepPrefix::Repne => zf, // REPNE: stop if ZF
                        };
                        if stop {
                            break;
                        }
                    }
                }
                Ok(StepOk::Continued)
            }
        }
    }

    fn group5_rm32(&mut self, mmu: &mut Mmu, entry_eip: u32) -> Result<StepOk, Trap> {
        let mr = self.fetch_modrm(mmu)?;
        let bytes = self.peek_after_modrm(mmu, 16)?;
        let (op, consumed) = resolve_modrm32(mr, &bytes, &self.regs)?;
        self.regs.eip = self.regs.eip.wrapping_add(consumed as u32);
        let op = self.seg_apply(op);
        let val = read_operand32(op, &self.regs, mmu)?;
        match mr.reg {
            0 => {
                let r = val.wrapping_add(1);
                let cf = self.regs.flags.cf;
                set_flags_inc_dec_32(&mut self.regs.flags, val, 1, r, false);
                self.regs.flags.cf = cf;
                write_operand32(op, r, &mut self.regs, mmu)?;
            }
            1 => {
                let r = val.wrapping_sub(1);
                let cf = self.regs.flags.cf;
                set_flags_inc_dec_32(&mut self.regs.flags, val, 1, r, true);
                self.regs.flags.cf = cf;
                write_operand32(op, r, &mut self.regs, mmu)?;
            }
            2 => {
                // CALL r/m32 (near, absolute)
                self.push32(mmu, self.regs.eip)?;
                self.regs.eip = val;
            }
            3 | 5 => {
                return Err(Trap::PrivilegedOpcode {
                    eip: entry_eip,
                    mnemonic: "far call/jmp m",
                })
            }
            4 => {
                // JMP r/m32 (near, absolute)
                self.regs.eip = val;
            }
            6 => {
                // PUSH r/m32
                self.push32(mmu, val)?;
            }
            _ => {
                return Err(Trap::UndefinedOpcode {
                    eip: entry_eip,
                    opcode: 0xFF00 | u32::from(mr.reg),
                })
            }
        }
        Ok(StepOk::Continued)
    }
}

#[derive(Copy, Clone, Debug)]
enum Op8Dst {
    Reg(Reg8),
    Mem(u32),
}

#[derive(Copy, Clone, Debug)]
enum Op16Dst {
    #[allow(dead_code)]
    Reg(Reg16),
    #[allow(dead_code)]
    Mem(u32),
}

/// String-operation operand size. The dword-form opcodes
/// (`A5/A7/AB/AD/AF`) honor the 0x66 prefix to narrow to word; the
/// byte-form opcodes (`A4/A6/AA/AC/AE`) always use [`Self::B8`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StringSize {
    B8,
    W16,
    D32,
}

/// Shift-count source for Group-2 (rotate / shift) opcodes.
#[derive(Copy, Clone, Debug)]
enum ShiftCount {
    /// Implicit count of 1 (`D0` / `D1`).
    One,
    /// Count from the `CL` register (`D2` / `D3`).
    Cl,
    /// 8-bit immediate following the ModR/M (`C0` / `C1`).
    Imm8,
}

// Helper signature: (lhs, rhs, flags) -> (result, write_back).
type AluFn32 = fn(u32, u32, &mut Flags) -> (u32, bool);
type AluFn16 = fn(u16, u16, &mut Flags) -> (u16, bool);
type AluFn8 = fn(u8, u8, &mut Flags) -> (u8, bool);

fn alu_add_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let (result, carry) = lhs.overflowing_add(rhs);
    f.cf = carry;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ result) & (rhs ^ result)) & 0x8000_0000) != 0;
    f.set_szp_32(result);
    (result, true)
}

fn alu_sub_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let (result, borrow) = lhs.overflowing_sub(rhs);
    f.cf = borrow;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ rhs) & (lhs ^ result)) & 0x8000_0000) != 0;
    f.set_szp_32(result);
    (result, true)
}

fn alu_cmp_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let (result, _w) = alu_sub_32(lhs, rhs, f);
    (result, false)
}

fn alu_and_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let r = lhs & rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_32(r);
    (r, true)
}

fn alu_or_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let r = lhs | rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_32(r);
    (r, true)
}

fn alu_xor_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let r = lhs ^ rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_32(r);
    (r, true)
}

fn alu_test_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let r = lhs & rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_32(r);
    (r, false)
}

fn alu_adc_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let cf = f.cf as u32;
    let s1 = lhs.wrapping_add(rhs);
    let result = s1.wrapping_add(cf);
    let new_cf = result < lhs || (cf == 1 && rhs == u32::MAX);
    f.cf = new_cf;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ result) & (rhs ^ result)) & 0x8000_0000) != 0;
    f.set_szp_32(result);
    (result, true)
}

fn alu_sbb_32(lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    let cf = f.cf as u32;
    let s1 = lhs.wrapping_sub(rhs);
    let result = s1.wrapping_sub(cf);
    // Borrow: lhs < rhs + cf (extended).
    let total = u64::from(rhs) + u64::from(cf);
    f.cf = u64::from(lhs) < total;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ rhs) & (lhs ^ result)) & 0x8000_0000) != 0;
    f.set_szp_32(result);
    (result, true)
}

// ----- 16-bit ALU primitives ----------------------------------
//
// Used by opcodes that took the operand-size override prefix
// (`0x66`). Same flag semantics as the 32-bit primitives, just
// the sign-bit moves from bit 31 to bit 15.

fn alu_add_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let (result, carry) = lhs.overflowing_add(rhs);
    f.cf = carry;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ result) & (rhs ^ result)) & 0x8000) != 0;
    f.set_szp_16(result);
    (result, true)
}

fn alu_sub_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let (result, borrow) = lhs.overflowing_sub(rhs);
    f.cf = borrow;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ rhs) & (lhs ^ result)) & 0x8000) != 0;
    f.set_szp_16(result);
    (result, true)
}

fn alu_cmp_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let (_r, _w) = alu_sub_16(lhs, rhs, f);
    (0, false)
}

fn alu_and_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let r = lhs & rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_16(r);
    (r, true)
}

fn alu_or_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let r = lhs | rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_16(r);
    (r, true)
}

fn alu_xor_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let r = lhs ^ rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_16(r);
    (r, true)
}

fn alu_test_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let r = lhs & rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_16(r);
    (r, false)
}

fn alu_adc_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let cf = f.cf as u16;
    let s1 = lhs.wrapping_add(rhs);
    let result = s1.wrapping_add(cf);
    let total = u32::from(rhs) + u32::from(cf);
    f.cf = u32::from(lhs) + total > 0xFFFF;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ result) & (rhs ^ result)) & 0x8000) != 0;
    f.set_szp_16(result);
    (result, true)
}

fn alu_sbb_16(lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    let cf = f.cf as u16;
    let s1 = lhs.wrapping_sub(rhs);
    let result = s1.wrapping_sub(cf);
    let total = u32::from(rhs) + u32::from(cf);
    f.cf = u32::from(lhs) < total;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ rhs) & (lhs ^ result)) & 0x8000) != 0;
    f.set_szp_16(result);
    (result, true)
}

/// Map a one-byte opcode in the 32-bit ALU range
/// (`0x00..=0x3D` even/odd pattern, plus `0x85` TEST) to its
/// 16-bit primitive. Used when the operand-size override prefix
/// (`0x66`) rewrites the operand width. The opcode encodes both
/// the operation and the direction (rm←r vs r←rm vs accum←imm);
/// the operation lives in bits 5:3 except for `0x85` which is a
/// special-case.
fn alu_fn16_for_opcode(op: u8) -> AluFn16 {
    if op == 0x85 {
        return alu_test_16;
    }
    match (op >> 3) & 0b111 {
        0 => alu_add_16,
        1 => alu_or_16,
        2 => alu_adc_16,
        3 => alu_sbb_16,
        4 => alu_and_16,
        5 => alu_sub_16,
        6 => alu_xor_16,
        7 => alu_cmp_16,
        _ => unreachable!(),
    }
}

fn group1_op_16(reg: u8, lhs: u16, rhs: u16, f: &mut Flags) -> (u16, bool) {
    match reg {
        0 => alu_add_16(lhs, rhs, f),
        1 => alu_or_16(lhs, rhs, f),
        2 => alu_adc_16(lhs, rhs, f),
        3 => alu_sbb_16(lhs, rhs, f),
        4 => alu_and_16(lhs, rhs, f),
        5 => alu_sub_16(lhs, rhs, f),
        6 => alu_xor_16(lhs, rhs, f),
        7 => alu_cmp_16(lhs, rhs, f),
        _ => unreachable!(),
    }
}

fn set_flags_inc_dec_16(f: &mut Flags, lhs: u16, rhs: u16, result: u16, sub: bool) {
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = if sub {
        (((lhs ^ rhs) & (lhs ^ result)) & 0x8000) != 0
    } else {
        (((lhs ^ result) & (rhs ^ result)) & 0x8000) != 0
    };
    f.set_szp_16(result);
}

// ----- 8-bit ALU primitives -----------------------------------

fn alu_add_8(lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    let (result, carry) = lhs.overflowing_add(rhs);
    f.cf = carry;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ result) & (rhs ^ result)) & 0x80) != 0;
    f.set_szp_8(result);
    (result, true)
}

fn alu_sub_8(lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    let (result, borrow) = lhs.overflowing_sub(rhs);
    f.cf = borrow;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ rhs) & (lhs ^ result)) & 0x80) != 0;
    f.set_szp_8(result);
    (result, true)
}

fn alu_cmp_8(lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    let (_r, _w) = alu_sub_8(lhs, rhs, f);
    (0, false)
}

fn alu_and_8(lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    let r = lhs & rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_8(r);
    (r, true)
}

fn alu_or_8(lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    let r = lhs | rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_8(r);
    (r, true)
}

fn alu_xor_8(lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    let r = lhs ^ rhs;
    f.cf = false;
    f.of = false;
    f.set_szp_8(r);
    (r, true)
}

fn alu_adc_8(lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    let cf = f.cf as u8;
    let s1 = lhs.wrapping_add(rhs);
    let result = s1.wrapping_add(cf);
    let total = u16::from(rhs) + u16::from(cf);
    f.cf = u16::from(lhs) + total > 0xFF;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ result) & (rhs ^ result)) & 0x80) != 0;
    f.set_szp_8(result);
    (result, true)
}

fn alu_sbb_8(lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    let cf = f.cf as u8;
    let s1 = lhs.wrapping_sub(rhs);
    let result = s1.wrapping_sub(cf);
    let total = u16::from(rhs) + u16::from(cf);
    f.cf = u16::from(lhs) < total;
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = (((lhs ^ rhs) & (lhs ^ result)) & 0x80) != 0;
    f.set_szp_8(result);
    (result, true)
}

/// /reg subop dispatch for 0x80 (r/m8, imm8). Returns (result,
/// write_back). 0=ADD 1=OR 2=ADC 3=SBB 4=AND 5=SUB 6=XOR 7=CMP.
fn group1_op_8(reg: u8, lhs: u8, rhs: u8, f: &mut Flags) -> (u8, bool) {
    match reg {
        0 => alu_add_8(lhs, rhs, f),
        1 => alu_or_8(lhs, rhs, f),
        2 => alu_adc_8(lhs, rhs, f),
        3 => alu_sbb_8(lhs, rhs, f),
        4 => alu_and_8(lhs, rhs, f),
        5 => alu_sub_8(lhs, rhs, f),
        6 => alu_xor_8(lhs, rhs, f),
        7 => alu_cmp_8(lhs, rhs, f),
        _ => unreachable!(),
    }
}

fn group1_op_32(reg: u8, lhs: u32, rhs: u32, f: &mut Flags) -> (u32, bool) {
    match reg {
        0 => alu_add_32(lhs, rhs, f),
        1 => alu_or_32(lhs, rhs, f),
        2 => alu_adc_32(lhs, rhs, f),
        3 => alu_sbb_32(lhs, rhs, f),
        4 => alu_and_32(lhs, rhs, f),
        5 => alu_sub_32(lhs, rhs, f),
        6 => alu_xor_32(lhs, rhs, f),
        7 => alu_cmp_32(lhs, rhs, f),
        _ => unreachable!(),
    }
}

fn set_flags_inc_dec_32(f: &mut Flags, lhs: u32, rhs: u32, result: u32, sub: bool) {
    f.af = ((lhs ^ rhs ^ result) & 0x10) != 0;
    f.of = if sub {
        (((lhs ^ rhs) & (lhs ^ result)) & 0x8000_0000) != 0
    } else {
        (((lhs ^ result) & (rhs ^ result)) & 0x8000_0000) != 0
    };
    f.set_szp_32(result);
}

/// Evaluate an Intel `Jcc` condition (4-bit selector). Reference:
/// Intel SDM Vol. 2A §B.1 (EFLAGS Condition Codes for Jcc).
fn condition_holds(cc: u8, f: &Flags) -> bool {
    match cc & 0x0F {
        0x0 => f.of,                    // JO
        0x1 => !f.of,                   // JNO
        0x2 => f.cf,                    // JB / JC / JNAE
        0x3 => !f.cf,                   // JAE / JNB / JNC
        0x4 => f.zf,                    // JE / JZ
        0x5 => !f.zf,                   // JNE / JNZ
        0x6 => f.cf || f.zf,            // JBE / JNA
        0x7 => !f.cf && !f.zf,          // JA / JNBE
        0x8 => f.sf,                    // JS
        0x9 => !f.sf,                   // JNS
        0xA => f.pf,                    // JP / JPE
        0xB => !f.pf,                   // JNP / JPO
        0xC => f.sf != f.of,            // JL / JNGE
        0xD => f.sf == f.of,            // JGE / JNL
        0xE => f.zf || (f.sf != f.of),  // JLE / JNG
        0xF => !f.zf && (f.sf == f.of), // JG / JNLE
        _ => unreachable!(),
    }
}

/// SDM-derived mnemonic hint for `0F xx` MMX opcodes.
///
/// Reference: Intel® 64 and IA-32 Architectures Software
/// Developer's Manual, Volume 2 Appendix A Table A-3
/// ("Two-byte Opcode Map"). Coverage:
///
/// * `0F 60..6F` — punpck/pack/pcmp/movd/movq family.
/// * `0F 70..7F` — pshufw, group-12/13/14 imm shifts, EMMS,
///   movd/movq.
/// * `0F D0..FF` — full PADD/PSUB/PMUL/PMADD/PCMP/PSL/PSR/PAND/
///   POR/PXOR/PADDS/PSUBS family.
///
/// Some slots in `0F 70..7F` (notably `0F 71/72/73`) are
/// "group" opcodes whose `/r` field disambiguates the actual
/// mnemonic (e.g. `0F 73 /6` is `PSLLQ imm8`, `0F 73 /2` is
/// `PSRLQ imm8`). We surface the umbrella mnemonic here; the
/// round-8 implementer reads `mr.reg` to disambiguate.
pub(crate) fn mmx_mnemonic(op2: u8) -> &'static str {
    match op2 {
        // 0F 60..6F — unpack / pack / compare / move-MMX
        0x60 => "PUNPCKLBW MMX",
        0x61 => "PUNPCKLWD MMX",
        0x62 => "PUNPCKLDQ MMX",
        0x63 => "PACKSSWB MMX",
        0x64 => "PCMPGTB MMX",
        0x65 => "PCMPGTW MMX",
        0x66 => "PCMPGTD MMX",
        0x67 => "PACKUSWB MMX",
        0x68 => "PUNPCKHBW MMX",
        0x69 => "PUNPCKHWD MMX",
        0x6A => "PUNPCKHDQ MMX",
        0x6B => "PACKSSDW MMX",
        0x6C => "PUNPCKLQDQ (SSE2)",
        0x6D => "PUNPCKHQDQ (SSE2)",
        0x6E => "MOVD MMX",
        0x6F => "MOVQ MMX",

        // 0F 70..7F — shuf / group-12/13/14 / EMMS / movd / movq
        0x70 => "PSHUFW MMX",
        0x71 => "MMX group-12 (PSLLW/PSRAW/PSRLW imm8)",
        0x72 => "MMX group-13 (PSLLD/PSRAD/PSRLD imm8)",
        0x73 => "MMX group-14 (PSLLQ/PSRLQ imm8)",
        0x74 => "PCMPEQB MMX",
        0x75 => "PCMPEQW MMX",
        0x76 => "PCMPEQD MMX",
        0x77 => "EMMS",
        0x78..=0x7D => "MMX/SSE reserved",
        0x7E => "MOVD r/m32, mm",
        0x7F => "MOVQ mm/m64, mm",

        // 0F D0..DF
        0xD1 => "PSRLW MMX",
        0xD2 => "PSRLD MMX",
        0xD3 => "PSRLQ MMX",
        0xD4 => "PADDQ MMX",
        0xD5 => "PMULLW MMX",
        0xD7 => "PMOVMSKB MMX",
        0xD8 => "PSUBUSB MMX",
        0xD9 => "PSUBUSW MMX",
        0xDA => "PMINUB MMX",
        0xDB => "PAND MMX",
        0xDC => "PADDUSB MMX",
        0xDD => "PADDUSW MMX",
        0xDE => "PMAXUB MMX",
        0xDF => "PANDN MMX",

        // 0F E0..EF
        0xE0 => "PAVGB MMX",
        0xE1 => "PSRAW MMX",
        0xE2 => "PSRAD MMX",
        0xE3 => "PAVGW MMX",
        0xE4 => "PMULHUW MMX",
        0xE5 => "PMULHW MMX",
        0xE7 => "MOVNTQ MMX",
        0xE8 => "PSUBSB MMX",
        0xE9 => "PSUBSW MMX",
        0xEA => "PMINSW MMX",
        0xEB => "POR MMX",
        0xEC => "PADDSB MMX",
        0xED => "PADDSW MMX",
        0xEE => "PMAXSW MMX",
        0xEF => "PXOR MMX",

        // 0F F0..FF
        0xF1 => "PSLLW MMX",
        0xF2 => "PSLLD MMX",
        0xF3 => "PSLLQ MMX",
        0xF4 => "PMULUDQ MMX",
        0xF5 => "PMADDWD MMX",
        0xF6 => "PSADBW MMX",
        0xF7 => "MASKMOVQ MMX",
        0xF8 => "PSUBB MMX",
        0xF9 => "PSUBW MMX",
        0xFA => "PSUBD MMX",
        0xFB => "PSUBQ MMX",
        0xFC => "PADDB MMX",
        0xFD => "PADDW MMX",
        0xFE => "PADDD MMX",

        _ => "MMX (unmapped slot)",
    }
}

// Round-7 helpers `mmx_consumes_modrm` / `mmx_has_imm8` were
// removed in round 13 once the structured-trap dispatcher was
// replaced by the real MMX semantics in `super::isa_mmx`. The
// per-opcode arms there know exactly what ModR/M / imm8 they
// consume; no umbrella table is needed.

/// Coarse first-byte mnemonic hint for the `trace-exec` event.
/// Not a full disassembler; just enough to make the JSONL
/// readable when `jq`-grepping for "what kind of instruction
/// fired?". Intel SDM Vol. 2A Table A-2 is the reference.
#[cfg(feature = "trace-exec")]
pub(crate) fn exec_mnemonic_hint(b: u8) -> &'static str {
    match b {
        0x00..=0x05 => "ADD",
        0x08..=0x0D => "OR",
        0x0F => "0F-prefix",
        0x10..=0x15 => "ADC",
        0x18..=0x1D => "SBB",
        0x20..=0x25 => "AND",
        0x28..=0x2D => "SUB",
        0x30..=0x35 => "XOR",
        0x38..=0x3D => "CMP",
        0x40..=0x47 => "INC r32",
        0x48..=0x4F => "DEC r32",
        0x50..=0x57 => "PUSH r32",
        0x58..=0x5F => "POP r32",
        0x68 | 0x6A => "PUSH imm",
        0x69 | 0x6B => "IMUL imm",
        0x70..=0x7F => "Jcc imm8",
        0x80..=0x83 => "ALU r/m, imm",
        0x84..=0x85 => "TEST r/m, r",
        0x86..=0x87 => "XCHG r/m, r",
        0x88..=0x8B => "MOV r/m, r",
        0x8D => "LEA",
        0x8F => "POP r/m",
        0x90 => "NOP",
        0x9C => "PUSHF",
        0x9D => "POPF",
        0xA0..=0xA3 => "MOV moffs",
        0xA4..=0xA7 => "MOVS/CMPS",
        0xA8..=0xA9 => "TEST imm",
        0xAA..=0xAF => "STOS/LODS/SCAS",
        0xB0..=0xB7 => "MOV r8, imm8",
        0xB8..=0xBF => "MOV r32, imm32",
        0xC0..=0xC1 => "shift r/m, imm8",
        0xC2..=0xC3 => "RET",
        0xC6..=0xC7 => "MOV r/m, imm",
        0xC8 => "ENTER",
        0xC9 => "LEAVE",
        0xCC => "INT3",
        0xD0..=0xD3 => "shift r/m, 1/cl",
        0xD8..=0xDF => "x87 FPU",
        0xE8 => "CALL rel32",
        0xE9 => "JMP rel32",
        0xEB => "JMP rel8",
        0xF4 => "HLT",
        0xF5 => "CMC",
        0xF6..=0xF7 => "group3 r/m",
        0xFA => "CLI",
        0xFB => "STI",
        0xFC => "CLD",
        0xFD => "STD",
        0xFE => "group4 r/m8",
        0xFF => "group5 r/m32",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::super::mmu::Perm;
    use super::*;

    fn make() -> (Cpu, Mmu) {
        let mut mmu = Mmu::new();
        mmu.map(0x1000, 0x2000, Perm::R | Perm::X); // code
        mmu.map(0x4000, 0x4000, Perm::R | Perm::W); // stack/data
        let mut cpu = Cpu::new();
        cpu.regs.eip = 0x1000;
        // Stack near top of stack page, growing down.
        cpu.regs.set_esp(0x7FF0);
        // Push the sentinel return address so the first ret stops.
        cpu.push32(&mut mmu, RET_SENTINEL).unwrap();
        (cpu, mmu)
    }

    fn write_code(mmu: &mut Mmu, addr: u32, bytes: &[u8]) {
        mmu.write_initializer(addr, bytes).unwrap();
    }

    #[test]
    fn xor_mov_add_ret_returns_0x43() {
        let (mut cpu, mut mmu) = make();
        // xor eax, eax       -> 0x33 0xC0
        // mov eax, 0x42      -> 0xB8 0x42 0x00 0x00 0x00
        // add eax, 1         -> 0x83 0xC0 0x01
        // ret                -> 0xC3
        write_code(
            &mut mmu,
            0x1000,
            &[
                0x33, 0xC0, 0xB8, 0x42, 0x00, 0x00, 0x00, 0x83, 0xC0, 0x01, 0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x43);
        assert_eq!(cpu.regs.eip, RET_SENTINEL);
    }

    #[test]
    fn push_pop_roundtrip_through_stack() {
        let (mut cpu, mut mmu) = make();
        // mov eax, 0xCAFEBABE -> B8 BE BA FE CA
        // push eax            -> 50
        // pop ebx             -> 5B
        // ret                 -> C3
        write_code(
            &mut mmu,
            0x1000,
            &[0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0x50, 0x5B, 0xC3],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Ebx), 0xCAFE_BABE);
    }

    #[test]
    fn call_relative_then_ret_unwinds_correctly() {
        let (mut cpu, mut mmu) = make();
        // 0x1000: call rel32 +5 ; 0xE8 05 00 00 00 (target = 0x100A)
        // 0x1005: mov eax, 1   ; 0xB8 01 00 00 00
        // 0x100A: mov eax, 0x99 ; 0xB8 99 00 00 00
        //         ret           ; 0xC3
        write_code(
            &mut mmu,
            0x1000,
            &[
                0xE8, 0x05, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xB8, 0x99, 0x00, 0x00,
                0x00, 0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        // The RET inside the callee returns to 0x1005, which sets
        // eax=1 and falls through to the bytes at 0x100A again
        // (re-setting eax=0x99) and rets to sentinel.
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x99);
    }

    #[test]
    fn cmp_je_taken() {
        let (mut cpu, mut mmu) = make();
        // mov eax, 5   -> B8 05 00 00 00
        // cmp eax, 5   -> 83 F8 05
        // je +2        -> 74 02
        // mov eax, 0   -> B8 00 00 00 00 (skipped by JE)
        // ... but je +2 skips 2 bytes after the jump → lands on
        //     mov ebx, 7
        // Layout:
        //   0x1000: B8 05 00 00 00   (mov eax, 5)
        //   0x1005: 83 F8 05         (cmp eax, 5)
        //   0x1008: 74 03            (je +3)
        //   0x100A: B8 00 00 00 00   (mov eax, 0)  - skipped
        //   0x100F: BB 07 00 00 00   (mov ebx, 7)  - landing
        //   0x1014: C3                (ret)
        write_code(
            &mut mmu,
            0x1000,
            &[
                0xB8, 0x05, 0x00, 0x00, 0x00, 0x83, 0xF8, 0x05, 0x74, 0x05, 0xB8, 0x00, 0x00, 0x00,
                0x00, 0xBB, 0x07, 0x00, 0x00, 0x00, 0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 5);
        assert_eq!(cpu.regs.get32(Reg32::Ebx), 7);
    }

    #[test]
    fn lea_resolves_displacement_arithmetic() {
        let (mut cpu, mut mmu) = make();
        // mov ebx, 0x100 -> BB 00 01 00 00
        // lea eax, [ebx + 0x40] -> 8D 43 40
        // ret
        write_code(
            &mut mmu,
            0x1000,
            &[0xBB, 0x00, 0x01, 0x00, 0x00, 0x8D, 0x43, 0x40, 0xC3],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x140);
    }

    #[test]
    fn imul_eax_sets_eax_only_low_32() {
        let (mut cpu, mut mmu) = make();
        // mov eax, 7 ; mov edx, 3 ; imul eax, edx ; ret
        // The 0x0F 0xAF form is two-operand IMUL; result low 32 in dst.
        write_code(
            &mut mmu,
            0x1000,
            &[
                0xB8, 0x07, 0x00, 0x00, 0x00, 0xBA, 0x03, 0x00, 0x00, 0x00, 0x0F, 0xAF, 0xC2, 0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 21);
    }

    #[test]
    fn cpuid_leaf_0_returns_genuineintel() {
        let (mut cpu, mut mmu) = make();
        // mov eax, 0 ; cpuid ; ret
        write_code(
            &mut mmu,
            0x1000,
            &[0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xA2, 0xC3],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 1);
        let bytes = [
            cpu.regs.get32(Reg32::Ebx).to_le_bytes(),
            cpu.regs.get32(Reg32::Edx).to_le_bytes(),
            cpu.regs.get32(Reg32::Ecx).to_le_bytes(),
        ];
        let mut joined = Vec::new();
        for arr in bytes.iter() {
            joined.extend_from_slice(arr);
        }
        assert_eq!(&joined, b"GenuineIntel");
    }

    #[test]
    fn hlt_traps_as_privileged() {
        let (mut cpu, mut mmu) = make();
        write_code(&mut mmu, 0x1000, &[0xF4]); // hlt
        match cpu.run(&mut mmu) {
            Err(Trap::PrivilegedOpcode {
                mnemonic: "hlt", ..
            }) => (),
            other => panic!("expected hlt trap, got {other:?}"),
        }
    }

    #[test]
    fn rdtsc_returns_monotonic_counter_in_edx_eax() {
        // Round-19: `0F 31` RDTSC reads the time-stamp counter.
        // We synthesise it from `instr_count >> 1`, so two calls
        // separated by N integer instructions produce a delta of
        // floor(N/2). Pin the contract: returns non-zero, second
        // call > first.
        let (mut cpu, mut mmu) = make();
        write_code(
            &mut mmu,
            0x1000,
            &[
                0x0F, 0x31, // rdtsc — first read
                0x89, 0xC1, // mov ecx, eax (save EAX from first read)
                0x90, 0x90, 0x90, 0x90, // four nop fillers
                0x0F, 0x31, // rdtsc — second read
                0xC3, // ret
            ],
        );
        cpu.run(&mut mmu).unwrap();
        let second = cpu.regs.get32(Reg32::Eax);
        let first = cpu.regs.get32(Reg32::Ecx);
        assert!(
            second > first,
            "TSC must be monotonic ({first} -> {second})"
        );
    }

    #[test]
    fn pushfd_popfd_toggles_id_bit_for_cpuid_detection() {
        // Round-19: this is the round-19 unblocking sequence —
        // the codec's CPUID-supported probe. Without modelling
        // bit 21 of EFLAGS, this sequence concluded "no CPUID"
        // and skipped the entire MMX-feature block.
        //
        //   pushfd ; pop eax           ; eax = original EFLAGS
        //   mov ebx, eax               ; save baseline
        //   xor eax, 0x200000          ; toggle ID bit
        //   push eax ; popfd           ; load toggled EFLAGS
        //   pushfd ; pop eax           ; read back EFLAGS
        //   xor eax, ebx               ; diff
        //   and eax, 0x200000          ; isolate ID-bit difference
        //
        // The contract: eax must be NON-ZERO at the end, meaning
        // the toggle survived the round-trip. Pre-round-19 the
        // diff was always 0 (bit 21 never showed up in pack()).
        let (mut cpu, mut mmu) = make();
        write_code(
            &mut mmu,
            0x1000,
            &[
                0x9C, // pushfd
                0x58, // pop eax
                0x89, 0xC3, // mov ebx, eax
                0x35, 0x00, 0x00, 0x20, 0x00, // xor eax, 0x00200000
                0x50, // push eax
                0x9D, // popfd
                0x9C, // pushfd
                0x58, // pop eax
                0x31, 0xD8, // xor eax, ebx
                0x25, 0x00, 0x00, 0x20, 0x00, // and eax, 0x00200000
                0xC3, // ret
            ],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(
            cpu.regs.get32(Reg32::Eax),
            0x0020_0000,
            "ID-bit toggle must round-trip through pushfd/popfd",
        );
    }

    #[test]
    fn cpuid_leaf_1_reports_pentium_ii_with_mmx() {
        // Round-19: leaf 1 must report family >= 6 (Intel SDM
        // family-codes) so the IR41/IR50 codec's
        // `cmp ebx, 0x600` family discriminator picks the
        // post-PPro path. Round-13 reported family 5 (Pentium
        // MMX), which IS itself MMX-capable, but the codec's
        // SSE/MMX dispatcher requires family-6+.
        let (mut cpu, mut mmu) = make();
        write_code(
            &mut mmu,
            0x1000,
            &[
                0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
                0x0F, 0xA2, // cpuid
                0xC3, // ret
            ],
        );
        cpu.run(&mut mmu).unwrap();
        let eax = cpu.regs.get32(Reg32::Eax);
        let edx = cpu.regs.get32(Reg32::Edx);
        // Family bits = (eax & 0xF00) >> 8 must be 6.
        assert_eq!((eax & 0xF00) >> 8, 6, "family must be 6 (Pentium II/III)");
        // MMX bit (23 of EDX) must be set.
        assert_ne!(edx & (1 << 23), 0, "CPUID.EDX.MMX must be set");
        // SSE bit (25 of EDX) must NOT be set — we don't have
        // a 16-byte SIMD register file, so reporting SSE would
        // route the codec into an emulator-trapping path.
        assert_eq!(edx & (1 << 25), 0, "CPUID.EDX.SSE must NOT be set");
    }

    #[test]
    fn unknown_opcode_traps() {
        let (mut cpu, mut mmu) = make();
        write_code(&mut mmu, 0x1000, &[0xD6]); // SALC: unimplemented in our table
        match cpu.run(&mut mmu) {
            Err(Trap::UndefinedOpcode { opcode: 0xD6, .. }) => (),
            other => panic!("expected undefined-opcode trap for 0xD6, got {other:?}"),
        }
    }

    #[test]
    fn mov_rm16_imm16_with_66_prefix_consumes_2byte_imm() {
        // Round-9 regression: `66 c7 ...` was decoded as if the
        // immediate were 32 bits, advancing eip by 2 bytes too
        // many and corrupting all subsequent instruction
        // decoding. Lifted directly from `IR50_32.DLL` ICOpen:
        //
        //   66 c7 46 62 02 00     ; mov word [esi+0x62], 2
        //   c7 46 64 0d 00 00 00  ; mov [esi+0x64], 0xd
        //
        // Asserts:
        //   * exactly 2 bytes of memory at [esi+0x62] are written
        //     (high half of dword stays zero from initial map)
        //   * eip lands on the next instruction's first byte
        //   * the dword write at [esi+0x64] = 0xd is then visible
        //     intact at the right address.
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Esi, 0x4000);
        // Pre-stamp 0xFF over [0x4060..0x4080] so we can see
        // exactly which bytes the 16-bit MOV touches.
        for i in 0..0x20u32 {
            mmu.store8(0x4060 + i, 0xFF).unwrap();
        }
        write_code(
            &mut mmu,
            0x1000,
            &[
                0x66, 0xC7, 0x46, 0x62, 0x02, 0x00, // mov word [esi+0x62], 2
                0xC7, 0x46, 0x64, 0x0D, 0x00, 0x00, 0x00, // mov [esi+0x64], 0xd
                0xC3, // ret
            ],
        );
        cpu.run(&mut mmu).unwrap();
        // [esi+0x62..0x64] = 02 00; [esi+0x64..0x68] = 0d 00 00 00
        assert_eq!(mmu.load8(0x4062).unwrap(), 0x02);
        assert_eq!(mmu.load8(0x4063).unwrap(), 0x00);
        assert_eq!(mmu.load32(0x4064).unwrap(), 0x0000_000D);
        // The 16-bit MOV must NOT have spilled into [esi+0x64].
        // Pre-fill was 0xFF; if the bug were present it'd write
        // 0x46470002 (4 bytes) and clobber [esi+0x64..0x66].
    }

    #[test]
    fn mov_rm16_r16_with_66_prefix_writes_only_low_half() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Esi, 0x4000);
        cpu.regs.set32(Reg32::Eax, 0xDEAD_BEEF);
        for i in 0..8u32 {
            mmu.store8(0x401C + i, 0xFF).unwrap();
        }
        write_code(
            &mut mmu,
            0x1000,
            &[
                0x66, 0x89, 0x46, 0x1C, // mov word [esi+0x1c], ax
                0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        // ax = 0xBEEF. Should write `EF BE` at [0x401C..0x401E].
        // [0x401E..0x4020] should remain 0xFF.
        assert_eq!(mmu.load8(0x401C).unwrap(), 0xEF);
        assert_eq!(mmu.load8(0x401D).unwrap(), 0xBE);
        assert_eq!(mmu.load8(0x401E).unwrap(), 0xFF);
        assert_eq!(mmu.load8(0x401F).unwrap(), 0xFF);
    }

    #[test]
    fn mov_r16_rm16_with_66_prefix_preserves_high_half() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Esi, 0x4000);
        cpu.regs.set32(Reg32::Eax, 0xCAFE_BABE);
        // Stage [esi+4..esi+6] = 0x1234 (LE).
        mmu.store16(0x4004, 0x1234).unwrap();
        write_code(
            &mut mmu,
            0x1000,
            &[
                0x66, 0x8B, 0x46, 0x04, // mov ax, word [esi+4]
                0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        // eax bits 31:16 stay 0xCAFE; bits 15:0 become 0x1234.
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xCAFE_1234);
    }

    #[test]
    fn ret_with_imm_pops_n_bytes() {
        let (mut cpu, mut mmu) = make();
        // mov eax, 0x77 ; push 0xAAAA ; ret 4
        // The ret 4 should skip the 0xAAAA argument off the stack.
        write_code(
            &mut mmu,
            0x1000,
            &[
                0xB8, 0x77, 0x00, 0x00, 0x00, 0x68, 0xAA, 0xAA, 0x00, 0x00, 0xC2, 0x04, 0x00,
            ],
        );
        // The retn 4 will pop 0xAAAA as return address, which is
        // not the sentinel, so the run loop will continue from that
        // bad eip. We expect the run to error with a memory fault.
        match cpu.run(&mut mmu) {
            Err(Trap::MemoryFault { .. }) | Err(Trap::ExecuteProtectFault { .. }) => (),
            other => panic!("expected fault after misdirected ret 4, got {other:?}"),
        }
    }

    #[test]
    fn shl_shifts_and_sets_flags() {
        let (mut cpu, mut mmu) = make();
        // mov eax, 1 ; shl eax, 4 ; ret  → 0x10
        write_code(
            &mut mmu,
            0x1000,
            &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC1, 0xE0, 0x04, 0xC3],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x10);
    }

    #[test]
    fn condition_holds_cross_check() {
        let mut f = Flags {
            zf: true,
            ..Flags::default()
        };
        assert!(condition_holds(0x4, &f)); // JE
        assert!(!condition_holds(0x5, &f)); // JNE
        f.zf = false;
        f.cf = true;
        assert!(condition_holds(0x2, &f)); // JB
        assert!(!condition_holds(0x3, &f)); // JAE
    }

    #[test]
    fn instr_limit_enforced() {
        let (mut cpu, mut mmu) = make();
        // jmp -2 forever → "EB FE"
        write_code(&mut mmu, 0x1000, &[0xEB, 0xFE]);
        cpu.set_instr_limit(100);
        match cpu.run(&mut mmu) {
            Err(Trap::InstructionLimitExceeded { .. }) => (),
            other => panic!("expected instr-limit trap, got {other:?}"),
        }
    }

    // ----- round 5 opcode regression tests --------------------------

    #[test]
    fn add_al_imm8_wraps_and_sets_carry() {
        let (mut cpu, mut mmu) = make();
        // mov al, 0xFE   B0 FE
        // add al, 5      04 05  ; 0xFE + 5 = 0x103 → AL=0x03 CF=1
        // ret            C3
        write_code(&mut mmu, 0x1000, &[0xB0, 0xFE, 0x04, 0x05, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get8(Reg8::Al), 0x03);
        assert!(cpu.regs.flags.cf, "AL+imm8 carry not set");
    }

    #[test]
    fn cmp_al_imm8_sets_zf_when_equal() {
        let (mut cpu, mut mmu) = make();
        // mov al, 0x42 ; cmp al, 0x42 ; ret
        write_code(&mut mmu, 0x1000, &[0xB0, 0x42, 0x3C, 0x42, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert!(cpu.regs.flags.zf);
        assert!(!cpu.regs.flags.cf);
    }

    #[test]
    fn imul_r32_imm8_signed() {
        let (mut cpu, mut mmu) = make();
        // mov ebx, 0xFFFFFFFF (-1) ; imul eax, ebx, 7 ; ret  → eax = -7 = 0xFFFFFFF9
        // BB FF FF FF FF       6B C3 07     C3
        write_code(
            &mut mmu,
            0x1000,
            &[0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0x6B, 0xC3, 0x07, 0xC3],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xFFFF_FFF9);
    }

    #[test]
    fn rep_movs_d_copies_dword_per_step_until_ecx_zero() {
        let (mut cpu, mut mmu) = make();
        // Lay out two 8-byte buffers in the data page.
        mmu.write_initializer(0x4100, &[1, 2, 3, 4, 5, 6, 7, 8])
            .unwrap();
        // mov esi, 0x4100   BE 00 41 00 00
        // mov edi, 0x4200   BF 00 42 00 00
        // mov ecx, 2        B9 02 00 00 00
        // rep movsd         F3 A5
        // ret               C3
        write_code(
            &mut mmu,
            0x1000,
            &[
                0xBE, 0x00, 0x41, 0x00, 0x00, 0xBF, 0x00, 0x42, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00,
                0x00, 0xF3, 0xA5, 0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        for i in 0..8 {
            assert_eq!(mmu.load8(0x4200 + i).unwrap(), (i + 1) as u8);
        }
        assert_eq!(cpu.regs.get32(Reg32::Ecx), 0);
    }

    #[test]
    fn fs_segment_translates_address() {
        let (mut cpu, mut mmu) = make();
        // Map a "TEB" page at 0x5000 and seed FS:[0]=0xCAFE.
        mmu.map(0x5000, 0x1000, Perm::R | Perm::W);
        mmu.write_initializer(0x5000, &0xCAFEu32.to_le_bytes())
            .unwrap();
        cpu.set_fs_base(0x5000);
        // mov eax, fs:[0]  64 A1 00 00 00 00
        // ret              C3
        write_code(
            &mut mmu,
            0x1000,
            &[0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0xC3],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xCAFE);
    }

    #[test]
    fn cmovz_copies_when_zf_set() {
        let (mut cpu, mut mmu) = make();
        // xor eax, eax    33 C0           ; eax=0, ZF=1
        // mov ebx, 0x77   BB 77 00 00 00
        // cmovz eax, ebx  0F 44 C3        ; ZF=1 → eax=ebx=0x77
        // ret             C3
        write_code(
            &mut mmu,
            0x1000,
            &[
                0x33, 0xC0, 0xBB, 0x77, 0x00, 0x00, 0x00, 0x0F, 0x44, 0xC3, 0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x77);
    }

    #[test]
    fn bswap_swaps_byte_order() {
        let (mut cpu, mut mmu) = make();
        // mov eax, 0x11223344  ; bswap eax  ; ret  → 0x44332211
        write_code(
            &mut mmu,
            0x1000,
            &[0xB8, 0x44, 0x33, 0x22, 0x11, 0x0F, 0xC8, 0xC3],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x4433_2211);
    }

    #[test]
    fn group2_rm8_shl_sets_flags() {
        let (mut cpu, mut mmu) = make();
        // mov al, 0x40  B0 40
        // shl al, 2     C0 E0 02   → al = 0x100 truncated = 0x00, CF = bit 6 (1)
        // ret           C3
        write_code(&mut mmu, 0x1000, &[0xB0, 0x40, 0xC0, 0xE0, 0x02, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get8(Reg8::Al), 0x00);
        assert!(cpu.regs.flags.cf);
    }

    #[test]
    fn pushad_popad_round_trip() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0xAAA);
        cpu.regs.set32(Reg32::Ecx, 0xCCC);
        cpu.regs.set32(Reg32::Edx, 0xDDD);
        cpu.regs.set32(Reg32::Ebx, 0xBBB);
        cpu.regs.set32(Reg32::Ebp, 0x1BB);
        cpu.regs.set32(Reg32::Esi, 0x1EE);
        cpu.regs.set32(Reg32::Edi, 0x1DD);
        // pushad ; popad ; ret  →  60 61 C3
        write_code(&mut mmu, 0x1000, &[0x60, 0x61, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xAAA);
        assert_eq!(cpu.regs.get32(Reg32::Ecx), 0xCCC);
        assert_eq!(cpu.regs.get32(Reg32::Edx), 0xDDD);
        assert_eq!(cpu.regs.get32(Reg32::Ebx), 0xBBB);
        assert_eq!(cpu.regs.get32(Reg32::Ebp), 0x1BB);
        assert_eq!(cpu.regs.get32(Reg32::Esi), 0x1EE);
        assert_eq!(cpu.regs.get32(Reg32::Edi), 0x1DD);
    }

    /// Round-10 regression: `66 81 7C 24 14 41 53` is `cmp word
    /// [esp+0x14], 0x5341` — 7 bytes, imm16 not imm32. The
    /// pre-round-10 decoder always treated 0x81 as imm32 even
    /// under 0x66 and consumed 9 bytes, mis-parsing the next 2
    /// bytes downstream. This is the exact opcode that produced
    /// the round-9 ICDecompressQuery memory fault inside
    /// IR50_32.DLL.
    #[test]
    fn group1_rm16_imm16_with_66_prefix_consumes_2byte_imm() {
        let (mut cpu, mut mmu) = make();
        // Place a known 2-byte value at [esp+0x14] = 0x4000 +
        // 0x14 = 0x4014. We'll cmp it against 0x5341.
        cpu.regs.set_esp(0x4000);
        mmu.write_initializer(0x4014, &[0x41u8, 0x53]).unwrap();
        // 66 81 7C 24 14 41 53  CMP word [esp+0x14], 0x5341
        // C3                    RET
        write_code(
            &mut mmu,
            0x1000,
            &[0x66, 0x81, 0x7C, 0x24, 0x14, 0x41, 0x53, 0xC3],
        );
        // We pre-pushed the sentinel onto the stack; the cmp's
        // [esp+0x14] address is unaffected by the sentinel push
        // because we set esp explicitly above. Re-prime after
        // overwriting esp:
        cpu.regs.set_esp(0x4000);
        // Run by stepping; we cannot use cpu.run because we did
        // not push the sentinel at this esp. Step exactly 1
        // instruction, then check eip and zf.
        cpu.step(&mut mmu).unwrap();
        assert_eq!(cpu.regs.eip, 0x1007, "0x66 81 ... iw must be 7 bytes");
        assert!(
            cpu.regs.flags.zf,
            "cmp 0x5341 against [esp+0x14]=0x5341 must set ZF"
        );
    }

    /// `66 83 C0 01` is `add ax, 1` under 0x66. Verify EAX hi
    /// bits are preserved.
    #[test]
    fn group1_rm16_imm8_with_66_prefix_preserves_high_half() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0xAABB_FFFF);
        // 66 83 C0 01  add ax, 1
        // C3
        write_code(&mut mmu, 0x1000, &[0x66, 0x83, 0xC0, 0x01, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(
            cpu.regs.get32(Reg32::Eax),
            0xAABB_0000,
            "0x66 0x83 must wrap at 16 bits"
        );
        assert!(cpu.regs.flags.cf, "16-bit overflow sets CF");
    }

    /// `66 BB 34 12` is `mov bx, 0x1234` — 4 bytes.
    #[test]
    fn mov_r16_imm16_with_66_prefix_preserves_high_half() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Ebx, 0xDEAD_BEEF);
        // 66 BB 34 12  mov bx, 0x1234
        // C3
        write_code(&mut mmu, 0x1000, &[0x66, 0xBB, 0x34, 0x12, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Ebx), 0xDEAD_1234);
    }

    /// `66 50 ; 58` is `push ax ; pop ax` — esp moves by 2 each.
    /// We single-step push16 / pop16 directly so the test's
    /// expectation isn't entangled with the make() stack
    /// sentinel.
    #[test]
    fn push_pop_r16_with_66_prefix_moves_esp_by_2() {
        let (mut cpu, mut mmu) = make();
        let esp_before = cpu.regs.esp();
        // 66 53        push bx (1 step)
        // 66 5B        pop  bx (1 step)
        write_code(&mut mmu, 0x1000, &[0x66, 0x53, 0x66, 0x5B]);
        cpu.regs.set32(Reg32::Ebx, 0xCAFE_BABE);
        // After PUSH BX, esp -= 2.
        cpu.step(&mut mmu).unwrap();
        assert_eq!(cpu.regs.esp(), esp_before - 2);
        // After POP BX, esp += 2 (back to original).
        cpu.step(&mut mmu).unwrap();
        assert_eq!(cpu.regs.esp(), esp_before);
        // BX low-half preserved (32-bit upper half preserved
        // unchanged by push16 + pop16).
        assert_eq!(cpu.regs.get32(Reg32::Ebx), 0xCAFE_BABE);
    }

    /// `66 40` is `inc ax`. The 32-bit inc would be `40` only.
    #[test]
    fn inc_r16_with_66_prefix() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0x1111_FFFF);
        // 66 40  inc ax  ; C3 ret
        write_code(&mut mmu, 0x1000, &[0x66, 0x40, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x1111_0000);
        assert!(cpu.regs.flags.zf, "inc to zero sets ZF");
    }

    /// `66 A9 02 00` is `test ax, 0x0002` — 4 bytes; the imm is
    /// 16-bit not 32-bit.
    #[test]
    fn test_ax_imm16_with_66_prefix_consumes_2byte_imm() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0x0000_0002);
        // 66 A9 02 00  test ax, 2
        // C3
        write_code(&mut mmu, 0x1000, &[0x66, 0xA9, 0x02, 0x00, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert!(!cpu.regs.flags.zf, "test ax,2 against 2 sets none-of");
        assert_eq!(cpu.regs.eip, RET_SENTINEL);
    }

    /// `66 6B C0 02` is `imul ax, ax, 2` under 0x66.
    #[test]
    fn imul_r16_imm8_with_66_prefix_preserves_high_half() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0xDEAD_0003);
        // 66 6B C0 02  imul ax, ax, 2  →  ax = 6
        // C3
        write_code(&mut mmu, 0x1000, &[0x66, 0x6B, 0xC0, 0x02, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xDEAD_0006);
    }

    /// `66 35 02 00` is `xor ax, 2` — 4 bytes; the EAX-imm form
    /// (`0x35`) under 0x66.
    #[test]
    fn xor_ax_imm16_with_66_prefix() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0xCAFE_FFFF);
        // 66 35 02 00  xor ax, 2
        // C3
        write_code(&mut mmu, 0x1000, &[0x66, 0x35, 0x02, 0x00, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xCAFE_FFFD);
    }

    /// `66 03 C3` is `add ax, bx` under 0x66 (the r↔r/m direction
    /// of the standard ALU ADD). Verifies the
    /// `alu_r32_rm32` 16-bit branch.
    #[test]
    fn add_r16_rm16_with_66_prefix() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0xCAFE_0010);
        cpu.regs.set32(Reg32::Ebx, 0xDEAD_0020);
        // 66 03 C3  add ax, bx
        // C3
        write_code(&mut mmu, 0x1000, &[0x66, 0x03, 0xC3, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xCAFE_0030);
    }

    /// `66 F7 D0` is `not ax` under 0x66 (group-3 r/m16 /2 NOT).
    #[test]
    fn group3_rm16_not_with_66_prefix() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0xDEAD_0F0F);
        // 66 F7 D0  not ax
        // C3
        write_code(&mut mmu, 0x1000, &[0x66, 0xF7, 0xD0, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xDEAD_F0F0);
    }

    /// `66 F7 C0 03 00` is `test ax, 3` under 0x66. The TEST sub-
    /// form of group-3 takes imm16, NOT imm32, so it is 5 bytes
    /// total.
    #[test]
    fn group3_rm16_test_imm16_with_66_prefix_consumes_2byte_imm() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Eax, 0x0000_0003);
        // 66 F7 C0 03 00  test ax, 3
        // C3
        write_code(&mut mmu, 0x1000, &[0x66, 0xF7, 0xC0, 0x03, 0x00, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert!(!cpu.regs.flags.zf);
        assert_eq!(cpu.regs.eip, RET_SENTINEL);
    }

    /// FPU control word round-trip: `D9 7D F8 ; D9 6D F8` is
    /// `fnstcw [ebp-8] ; fldcw [ebp-8]`. This is the codec-
    /// prologue idiom we model via the [`Cpu::fpu_cw`] shadow.
    #[test]
    fn fpu_fnstcw_then_fldcw_round_trip_via_shadow() {
        let (mut cpu, mut mmu) = make();
        cpu.regs.set32(Reg32::Ebp, 0x5000);
        cpu.fpu_cw = 0x027F;
        // C7 45 F8 7F 03 00 00  mov dword [ebp-8], 0x37F
        // D9 6D F8              fldcw [ebp-8]   (loads 0x37F into shadow)
        // D9 7D F0              fnstcw [ebp-0x10]
        // C3
        write_code(
            &mut mmu,
            0x1000,
            &[
                0xC7, 0x45, 0xF8, 0x7F, 0x03, 0x00, 0x00, 0xD9, 0x6D, 0xF8, 0xD9, 0x7D, 0xF0, 0xC3,
            ],
        );
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.fpu_cw, 0x037F, "fldcw must update shadow");
        assert_eq!(
            mmu.load16(0x5000 - 0x10).unwrap(),
            0x037F,
            "fnstcw must store shadow to memory"
        );
    }

    /// Round-10: REP MOVSW under 0x66. Each step copies a word
    /// (2 bytes), advancing ESI/EDI by 2.
    #[test]
    fn rep_movs_w_with_66_prefix_copies_word_per_step() {
        let (mut cpu, mut mmu) = make();
        // Source @ 0x4100 = "ABCD" (4 bytes). Dest @ 0x4200.
        mmu.write_initializer(0x4100, b"ABCD").unwrap();
        cpu.regs.set32(Reg32::Esi, 0x4100);
        cpu.regs.set32(Reg32::Edi, 0x4200);
        cpu.regs.set32(Reg32::Ecx, 2);
        // F3 66 A5  rep movsw   (2 words = 4 bytes)
        // C3
        write_code(&mut mmu, 0x1000, &[0xF3, 0x66, 0xA5, 0xC3]);
        cpu.run(&mut mmu).unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Ecx), 0);
        assert_eq!(cpu.regs.get32(Reg32::Esi), 0x4104);
        assert_eq!(cpu.regs.get32(Reg32::Edi), 0x4204);
        let mut got = [0u8; 4];
        for (i, slot) in got.iter_mut().enumerate() {
            *slot = mmu.load8(0x4200 + i as u32).unwrap();
        }
        assert_eq!(&got, b"ABCD");
    }
}
