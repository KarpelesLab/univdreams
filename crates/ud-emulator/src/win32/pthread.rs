//! `pthreadVC2.dll` stubs (POSIX threads port for Windows).
//!
//! Apple's CoreFoundation / libdispatch use pthread heavily —
//! pthread_key_create / pthread_setspecific / pthread_getspecific
//! for thread-local storage; pthread_once for double-checked
//! init; pthread_mutex_* for locking. Real implementations are
//! complex (allocate heap structs, walk Windows TLS, fall back
//! to FLS, etc.).
//!
//! These host stubs intercept the IMPORT side: when libdispatch
//! or CoreFoundation IAT-resolves `pthreadVC2.dll!pthread_setspecific`,
//! our host stub address wins over the real pthread export
//! (because [`Registry::register_guest_export`] is idempotent —
//! the stub is registered first via `register_all`). Pthread's
//! own internal calls to its own functions use direct `call rel32`
//! within the same DLL and are unaffected.
//!
//! The minimal contract each stub upholds:
//!
//! * `pthread_*_init` / `pthread_*_create` — return 0 (success).
//! * `pthread_setspecific` — store in a per-thread map keyed by
//!   the pthread key value; return 0.
//! * `pthread_getspecific` — read from that map; return NULL when
//!   unset.
//! * Locking primitives — no-op (single-threaded analyser).
//!
//! Reference: POSIX `pthread.h` —
//! `https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/pthread.h.html`.

use super::{HostState, Registry, StubFn, Win32Error, arg_dword};
use crate::emulator::{Cpu, Mmu};

/// Register the host-side pthread stubs under
/// `pthreadVC2.dll` (the name Apple's distribution uses). All
/// pthread functions follow `__cdecl` — `arg_dwords = 0` so
/// the dispatcher does not pop args off the stack.
pub fn register(registry: &mut Registry) {
    let dll = "pthreadVC2.dll";
    // Thread-local storage.
    registry.register(dll, "pthread_key_create", stub_key_create as StubFn, 0);
    registry.register(dll, "pthread_key_delete", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_setspecific", stub_setspecific as StubFn, 0);
    registry.register(dll, "pthread_getspecific", stub_getspecific as StubFn, 0);
    // One-time init.
    registry.register(dll, "pthread_once", stub_once as StubFn, 0);
    // Mutexes — no-op in a single-threaded analyser. Return 0
    // for success-shaped APIs.
    registry.register(dll, "pthread_mutex_init", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_mutex_destroy", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_mutex_lock", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_mutex_trylock", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_mutex_unlock", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_mutexattr_init", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_mutexattr_destroy", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_mutexattr_settype", stub_zero as StubFn, 0);
    // Condition variables.
    registry.register(dll, "pthread_cond_init", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_cond_destroy", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_cond_signal", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_cond_broadcast", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_cond_wait", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_cond_timedwait", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_condattr_init", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_condattr_destroy", stub_zero as StubFn, 0);
    // RW locks.
    registry.register(dll, "pthread_rwlock_init", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_rwlock_destroy", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_rwlock_rdlock", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_rwlock_wrlock", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_rwlock_unlock", stub_zero as StubFn, 0);
    // Thread identity / attributes.
    registry.register(dll, "pthread_self", stub_self as StubFn, 0);
    registry.register(dll, "pthread_equal", stub_equal as StubFn, 0);
    registry.register(dll, "pthread_create", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_join", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_detach", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_attr_init", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_attr_destroy", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_attr_setstacksize", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_attr_setdetachstate", stub_zero as StubFn, 0);
    // Cancellation — codecs don't cancel themselves.
    registry.register(dll, "pthread_setcancelstate", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_setcanceltype", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_testcancel", stub_zero as StubFn, 0);
    registry.register(dll, "pthread_cancel", stub_zero as StubFn, 0);
}

/// `int pthread_key_create(pthread_key_t *key, void (*destructor)(void*))`.
/// Allocates a fresh slot index and writes it into `*key`.
/// We map each key to its destructor — but never run destructors
/// in a single-threaded analyser. Returns 0 on success.
fn stub_key_create(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let key_ptr = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_key_create", t))?;
    let _destructor = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_key_create", t))?;
    // Allocate a fresh non-zero slot id. We start at 1 so that
    // callers using NULL/0 as "unset" find a clear difference.
    if state.next_pthread_key == 0 {
        state.next_pthread_key = 1;
    }
    let slot = state.next_pthread_key;
    state.next_pthread_key = state.next_pthread_key.saturating_add(1);
    if key_ptr != 0 {
        mmu.store32(key_ptr, slot)
            .map_err(|t| crate::win32::trap_to_win32_local("pthread_key_create", t))?;
    }
    Ok(0)
}

/// `int pthread_setspecific(pthread_key_t key, const void *value)`.
/// Store `value` in the current thread's pthread slot `key`.
/// Returns 0 on success.
fn stub_setspecific(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let key = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_setspecific", t))?;
    let value = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_setspecific", t))?;
    state.cur_thread_mut().pthread_slots.insert(key, value);
    Ok(0)
}

/// `void *pthread_getspecific(pthread_key_t key)`. Reads the
/// current thread's pthread slot for `key`. Returns NULL when
/// unset.
fn stub_getspecific(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let key = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_getspecific", t))?;
    Ok(state
        .cur_thread()
        .pthread_slots
        .get(&key)
        .copied()
        .unwrap_or(0))
}

/// `int pthread_once(pthread_once_t *once, void (*init)(void))`.
/// `pthread_once_t` is a small integer flag (0 = not yet run).
/// We CAS-style: read, if 0 invoke init then write 1; if 1 skip.
/// The init callback is invoked synchronously through call_guest
/// so it can re-enter any number of sub-stubs cleanly. Returns 0.
fn stub_once(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let once_ptr =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("pthread_once", t))?;
    let init_fn =
        arg_dword(cpu, mmu, 1).map_err(|t| crate::win32::trap_to_win32_local("pthread_once", t))?;
    if once_ptr == 0 || init_fn == 0 {
        return Ok(0);
    }
    let state_word = mmu
        .load32(once_ptr)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_once", t))?;
    if state_word != 0 {
        // Already initialised.
        return Ok(0);
    }
    // Mark as initialised BEFORE the call to break recursion if
    // the init body re-enters pthread_once for the same flag.
    mmu.store32(once_ptr, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_once", t))?;
    if let Err(crate::Error::Win32(e)) =
        crate::win32::call_guest(cpu, mmu, registry, state, init_fn, &[])
    {
        return Err(e);
    }
    Ok(0)
}

/// `pthread_t pthread_self(void)`. Returns the synthetic
/// per-thread handle we track elsewhere — the active TID.
fn stub_self(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(state.active_tid)
}

/// `int pthread_equal(pthread_t a, pthread_t b)`. Returns
/// non-zero iff the two handles refer to the same thread.
fn stub_equal(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let a = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_equal", t))?;
    let b = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("pthread_equal", t))?;
    Ok(if a == b { 1 } else { 0 })
}

/// Catch-all that returns 0 — POSIX convention for success.
fn stub_zero(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}
