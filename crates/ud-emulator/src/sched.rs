//! Preemptive scheduler for the Win32 emulator.
//!
//! Phase 3 of the scheduler refactor — see
//! `.claude/plans/magical-popping-oasis.md`. This module owns
//! the **synchronization-object** table, the **wait-condition**
//! type a thread can be parked on, and the small **yield
//! protocol** through which a stub asks the run loop to switch
//! threads.
//!
//! Thread + process tables live on [`crate::win32::HostState`]
//! itself (so every stub has direct access); this module owns
//! only the types they reference and the helpers that operate
//! over them.
//!
//! Stub → scheduler interaction:
//!
//! 1. A stub like `Sleep(ms)` or `WaitForSingleObject(h, t)`
//!    finds that it cannot complete immediately, populates
//!    `HostState.yield_requested = Some(YieldRequest { kind })`,
//!    and returns its placeholder return value (typically 0 /
//!    `WAIT_OBJECT_0` — the run loop overwrites EAX after the
//!    wake).
//! 2. The run loop, on return from
//!    [`crate::win32::dispatch_stub`], sees the request, parks
//!    the live `Cpu` into the active thread's `parked_cpu`,
//!    records the requested `WaitCondition` on that thread,
//!    transitions it to `ThreadStatus::Waiting`, picks the next
//!    `Ready` thread via [`Scheduler::pick_next`], and restores
//!    its parked `Cpu`.
//! 3. Wake-up: stubs that signal a wait object (`SetEvent`,
//!    `ReleaseMutex`, `ReleaseSemaphore`, …) call
//!    [`wake_waiters_on`] which moves matching threads back to
//!    `Ready`. The Sleep wake-up is driven by the run loop
//!    polling [`reap_sleep_wakeups`] on each scheduler tick.

use std::collections::BTreeMap;

/// First synthetic wait-object handle. Chosen well above the
/// `HKEY_USER_BASE` / `HANDLE_BASE` ranges used by the virtual
/// registry and filesystem so the dispatch sites can
/// disambiguate handle kinds by numeric value.
pub const WAIT_OBJECT_HANDLE_BASE: u32 = 0x6B00_0000;

/// Default thread priority (matches Windows
/// `THREAD_PRIORITY_NORMAL`).
pub const PRIORITY_NORMAL: i32 = 0;

/// Sleep wake-ups are driven by a monotonic instruction counter
/// kept on [`crate::win32::HostState::instructions_global`].
/// One Windows millisecond is approximated as
/// [`INSTRUCTIONS_PER_MS`] guest instructions — chosen so a
/// `Sleep(100)` doesn't stall the scheduler for an eternity in
/// short tests, but is large enough that a `Sleep(0)` /
/// `Sleep(1)` does observably interrupt the caller's quantum.
pub const INSTRUCTIONS_PER_MS: u64 = 1_000;

/// Lifecycle states a thread can be in. The naming and
/// transitions mirror the Windows kernel's thread-state machine:
///
/// * `Ready` — eligible for the next scheduler pick.
/// * `Running` — currently executing on the live `Cpu`.
/// * `Waiting` — blocked on a [`WaitCondition`].
/// * `Suspended` — explicitly paused via `CREATE_SUSPENDED` or
///   `SuspendThread`; only `ResumeThread` un-pauses.
/// * `Terminated` — `ExitThread` / `TerminateThread` ran (or the
///   `Cpu` returned to `RET_SENTINEL`). Stays in the thread
///   table so an outstanding `WaitForSingleObject` on this TID
///   can resolve, but is never picked again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStatus {
    Ready,
    Running,
    Waiting,
    Suspended,
    Terminated,
}

/// Condition a waiting thread is blocked on. Cleared when the
/// scheduler wakes the thread (either because the condition
/// resolved, or because the wait timed out).
#[derive(Debug, Clone)]
pub enum WaitCondition {
    /// `Sleep(ms)` — wake when
    /// `instructions_global >= resume_after_instructions`.
    Sleep { resume_after_instructions: u64 },
    /// `WaitForSingleObject(h, timeout)` — wake when the object
    /// signals or `instructions_global >= timeout_after` (if
    /// set).
    Object {
        handle: u32,
        timeout_after: Option<u64>,
    },
    /// `WaitForMultipleObjects(handles, wait_all, timeout)` —
    /// wake when any (or all) handles signal, or on timeout.
    Multiple {
        handles: Vec<u32>,
        wait_all: bool,
        timeout_after: Option<u64>,
    },
}

/// One Win32 synchronization object owned by the scheduler.
/// Handles minted by `CreateEvent` / `CreateMutex` /
/// `CreateSemaphore` (and the synthetic handles minted for
/// process + thread waits) are integers `≥ WAIT_OBJECT_HANDLE_BASE`
/// that index this table.
#[derive(Debug, Clone)]
pub enum WaitObject {
    /// `CreateEventA` / `CreateEventW`. `manual_reset = false`
    /// means `WaitForSingleObject` consumes the signal (only
    /// one waiter wakes per `SetEvent`); `true` means the
    /// signal stays set until `ResetEvent`.
    Event { signaled: bool, manual_reset: bool },
    /// `CreateMutexA` — owned by a thread, reentrant.
    Mutex { owner: Option<u32>, recursion: u32 },
    /// `CreateSemaphoreA` — count goes down on wake, up on
    /// release; max is informational.
    Semaphore { count: u32, max: u32 },
    /// Synthetic handle minted at `CreateThread` / for the
    /// primary thread of `CreateProcessA`. Signals when the
    /// thread terminates.
    Thread { tid: u32 },
    /// Synthetic handle minted at `CreateProcessA`. Signals
    /// when every thread in the process has terminated.
    Process { pid: u32 },
    /// Implicit handle for `LPCRITICAL_SECTION` (its guest
    /// address). Mutex-shaped but allocated lazily by
    /// `EnterCriticalSection` on first touch.
    CriticalSection {
        guest_addr: u32,
        owner: Option<u32>,
        recursion: u32,
    },
}

/// What a stub is asking the scheduler to do on return. Set on
/// [`crate::win32::HostState::yield_requested`] and consumed by
/// the run loop.
#[derive(Debug, Clone)]
pub enum YieldRequest {
    /// Block the current thread on the given condition. The
    /// run loop transitions the thread to `Waiting`, parks the
    /// live `Cpu`, and picks the next runnable thread.
    Wait(WaitCondition),
    /// Voluntarily release the rest of the quantum without
    /// blocking — used by `SwitchToThread`. The current thread
    /// goes back into `Ready` immediately.
    Yield,
    /// The current thread is exiting (`ExitThread` /
    /// `RET_SENTINEL`-by-return). The run loop marks it
    /// `Terminated`, signals any pending Thread / Process
    /// waits on it, and picks the next runnable.
    Exit { code: u32 },
}

/// Scheduler-owned bookkeeping that lives alongside the
/// [`crate::win32::HostState::threads`] table.
#[derive(Default)]
pub struct Scheduler {
    /// Wait-object table. Handles are
    /// `WAIT_OBJECT_HANDLE_BASE + next_handle_index`.
    pub objects: BTreeMap<u32, WaitObject>,
    /// Reverse lookup: implicit critical-section handle keyed
    /// by `LPCRITICAL_SECTION` guest address. Populated on the
    /// first `EnterCriticalSection` against that address.
    pub critical_sections: BTreeMap<u32, u32>,
    /// Next index for a freshly-minted wait object.
    pub next_handle_index: u32,
    /// Monotonic instruction counter driving sleep wake-ups.
    /// Distinct from `instructions_executed` (which resets on
    /// every top-level run-loop entry); this one only
    /// increases.
    pub instructions_global: u64,
    /// Default quantum a Ready thread receives when scheduled.
    pub quantum_default: u32,
}

impl Scheduler {
    #[must_use]
    pub fn new() -> Self {
        Scheduler {
            objects: BTreeMap::new(),
            critical_sections: BTreeMap::new(),
            next_handle_index: 0,
            instructions_global: 0,
            quantum_default: crate::win32::DEFAULT_QUANTUM,
        }
    }

    /// Mint a fresh handle and stash the given object under it.
    pub fn insert_object(&mut self, object: WaitObject) -> u32 {
        let handle = WAIT_OBJECT_HANDLE_BASE.wrapping_add(self.next_handle_index);
        self.next_handle_index = self.next_handle_index.wrapping_add(1);
        self.objects.insert(handle, object);
        handle
    }

    /// True iff `handle` is in this scheduler's wait-object
    /// table. Used by `CloseHandle` to disambiguate.
    #[must_use]
    pub fn owns(&self, handle: u32) -> bool {
        self.objects.contains_key(&handle)
    }

    /// Resolve `LPCRITICAL_SECTION` `guest_addr` to its
    /// implicit handle, creating the underlying
    /// [`WaitObject::CriticalSection`] on first touch.
    pub fn critical_section_handle(&mut self, guest_addr: u32) -> u32 {
        if let Some(&h) = self.critical_sections.get(&guest_addr) {
            return h;
        }
        let h = self.insert_object(WaitObject::CriticalSection {
            guest_addr,
            owner: None,
            recursion: 0,
        });
        self.critical_sections.insert(guest_addr, h);
        h
    }
}

/// True iff the given object is currently "signaled" from the
/// perspective of a waiting thread (i.e. a `WaitForSingleObject`
/// call would return immediately).
///
/// Does NOT consume the signal — that's the caller's job (see
/// [`consume_signal_if_auto_reset`]).
#[must_use]
pub fn object_is_signaled(obj: &WaitObject) -> bool {
    match obj {
        WaitObject::Event { signaled, .. } => *signaled,
        WaitObject::Mutex { owner, .. } => owner.is_none(),
        WaitObject::Semaphore { count, .. } => *count > 0,
        WaitObject::Thread { .. } | WaitObject::Process { .. } => {
            // Resolved by the scheduler when the target thread /
            // process moves to Terminated; the state machine
            // updates these objects' shape rather than tracking
            // a signaled flag.
            false
        }
        WaitObject::CriticalSection { owner, .. } => owner.is_none(),
    }
}

/// Iterate over every thread that is currently waiting on the
/// given handle (either as a single-object wait or as one of
/// the handles in a multi-object wait). Used by signal-side
/// stubs (`SetEvent`, `ReleaseMutex`, `ReleaseSemaphore`, …)
/// to find waiters to wake.
///
/// Returns TIDs in sorted order so wake-up is deterministic
/// across runs.
pub fn waiters_on(
    threads: &std::collections::BTreeMap<u32, crate::win32::ThreadState>,
    handle: u32,
) -> Vec<u32> {
    let mut out: Vec<u32> = threads
        .iter()
        .filter(|(_, t)| matches!(t.status, ThreadStatus::Waiting))
        .filter(|(_, t)| match &t.wait {
            Some(WaitCondition::Object { handle: h, .. }) => *h == handle,
            Some(WaitCondition::Multiple { handles, .. }) => handles.contains(&handle),
            _ => false,
        })
        .map(|(tid, _)| *tid)
        .collect();
    out.sort_unstable();
    out
}

/// Take the side effect implied by a successful wait. For an
/// auto-reset Event the signal flips back off; for a Semaphore
/// the count drops; for a Mutex / CriticalSection ownership
/// transfers to the waking thread.
pub fn consume_signal_if_auto_reset(obj: &mut WaitObject, waker_tid: u32) {
    match obj {
        WaitObject::Event {
            signaled,
            manual_reset,
        } => {
            if !*manual_reset {
                *signaled = false;
            }
        }
        WaitObject::Mutex { owner, recursion } => {
            *owner = Some(waker_tid);
            *recursion = 1;
        }
        WaitObject::Semaphore { count, .. } => {
            *count = count.saturating_sub(1);
        }
        WaitObject::CriticalSection {
            owner, recursion, ..
        } => {
            *owner = Some(waker_tid);
            *recursion = 1;
        }
        WaitObject::Thread { .. } | WaitObject::Process { .. } => {
            // No side effect — terminated stays terminated.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_signaled_state_round_trip() {
        let e_manual = WaitObject::Event {
            signaled: true,
            manual_reset: true,
        };
        let e_auto = WaitObject::Event {
            signaled: true,
            manual_reset: false,
        };
        assert!(object_is_signaled(&e_manual));
        assert!(object_is_signaled(&e_auto));

        // Manual-reset stays signaled after a wake; auto-reset
        // clears.
        let mut a = e_auto.clone();
        consume_signal_if_auto_reset(&mut a, 1);
        assert!(!object_is_signaled(&a));

        let mut m = e_manual.clone();
        consume_signal_if_auto_reset(&mut m, 1);
        assert!(object_is_signaled(&m));
    }

    #[test]
    fn mutex_signaled_iff_unowned() {
        let mut m = WaitObject::Mutex {
            owner: None,
            recursion: 0,
        };
        assert!(object_is_signaled(&m));
        consume_signal_if_auto_reset(&mut m, 7);
        assert!(!object_is_signaled(&m));
        match m {
            WaitObject::Mutex { owner, recursion } => {
                assert_eq!(owner, Some(7));
                assert_eq!(recursion, 1);
            }
            _ => panic!("not a mutex"),
        }
    }

    #[test]
    fn semaphore_decrements_on_consume() {
        let mut s = WaitObject::Semaphore { count: 3, max: 10 };
        consume_signal_if_auto_reset(&mut s, 1);
        match s {
            WaitObject::Semaphore { count, .. } => assert_eq!(count, 2),
            _ => panic!(),
        }
    }

    #[test]
    fn scheduler_insert_handles_are_unique() {
        let mut s = Scheduler::new();
        let h1 = s.insert_object(WaitObject::Event {
            signaled: false,
            manual_reset: false,
        });
        let h2 = s.insert_object(WaitObject::Mutex {
            owner: None,
            recursion: 0,
        });
        assert_ne!(h1, h2);
        assert!(s.owns(h1));
        assert!(s.owns(h2));
        assert!(!s.owns(0xDEAD_BEEF));
    }

    #[test]
    fn critical_section_minted_once_per_guest_addr() {
        let mut s = Scheduler::new();
        let a = s.critical_section_handle(0x1000);
        let b = s.critical_section_handle(0x1000);
        let c = s.critical_section_handle(0x2000);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn sleep_yield_request_shape() {
        // Sanity: the YieldRequest::Wait(Sleep) variant
        // constructs as documented in the doc comment.
        let r = YieldRequest::Wait(WaitCondition::Sleep {
            resume_after_instructions: 1234,
        });
        match r {
            YieldRequest::Wait(WaitCondition::Sleep {
                resume_after_instructions,
            }) => {
                assert_eq!(resume_after_instructions, 1234);
            }
            _ => panic!("unexpected variant shape"),
        }
    }
}
