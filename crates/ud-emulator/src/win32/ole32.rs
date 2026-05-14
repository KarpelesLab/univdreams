//! `ole32.dll` stubs — round-8 surface for IR50_32.DLL, expanded
//! in round 25 to drive `DllGetClassObject` / `IClassFactory`
//! through the DirectShow filter binaries.
//!
//! Round 8 only needed enough COM bootstrapping to satisfy IR50's
//! "Configure" dialog code path.  Round 25 turns
//! `CoCreateInstance` into a real lookup against the in-process
//! class-factory cache populated by [`crate::Sandbox::dll_get_class_object`].
//!
//! Reference: MSDN "Component Object Model (COM)" —
//! <https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com->.
//! `CoInitialize{,Ex}` semantics: STA / MTA distinction is not
//! observable to a single-threaded sandbox, so both return
//! `S_OK`.  `CoCreateInstance` semantics: when given a CLSID we
//! have a host-cached `IClassFactory` for, drive
//! `IClassFactory::CreateInstance(NULL, riid, ppv)` to fulfil
//! the request; otherwise return `CLASS_E_CLASSNOTAVAILABLE`.

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::com::{
    call::vtable_is_plausible, call_method, Guid, CLASS_E_CLASSNOTAVAILABLE, E_POINTER,
    SLOT_CLASS_FACTORY_CREATE_INSTANCE,
};
use crate::emulator::{Cpu, Mmu};

const S_OK: u32 = 0;

/// Register every ole32 stub.
pub fn register(registry: &mut Registry) {
    registry.register(
        "ole32.dll",
        "CoCreateInstance",
        stub_co_create_instance as StubFn,
        5,
    );
    registry.register(
        "ole32.dll",
        "CoFreeUnusedLibraries",
        stub_co_free_unused_libraries as StubFn,
        0,
    );
    registry.register("ole32.dll", "CoInitialize", stub_co_initialize as StubFn, 1);
    registry.register(
        "ole32.dll",
        "CoInitializeEx",
        stub_co_initialize_ex as StubFn,
        2,
    );
    registry.register(
        "ole32.dll",
        "CoTaskMemAlloc",
        stub_co_task_mem_alloc as StubFn,
        1,
    );
    registry.register(
        "ole32.dll",
        "CoTaskMemFree",
        stub_co_task_mem_free as StubFn,
        1,
    );
    registry.register(
        "ole32.dll",
        "CoTaskMemRealloc",
        stub_co_task_mem_realloc as StubFn,
        2,
    );
    registry.register(
        "ole32.dll",
        "CoUninitialize",
        stub_co_uninitialize as StubFn,
        0,
    );
    registry.register(
        "ole32.dll",
        "StringFromGUID2",
        stub_string_from_guid2 as StubFn,
        3,
    );
}

/// `HRESULT CoCreateInstance(REFCLSID rclsid, LPUNKNOWN
/// pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv)`.
///
/// Round-8 returned `E_NOTIMPL` blindly — the IR50 path the
/// stub was written for did not exercise this.  Round 25 turns
/// it into a real lookup:
///
/// 1. Read `*rclsid` and `*riid` from guest memory.
/// 2. Search [`HostState::com.class_factories`] for `rclsid`.
/// 3. If hit, drive
///    `IClassFactory::CreateInstance(pUnkOuter, riid, ppv)` to
///    fulfil the request.  The COM ABI says `pUnkOuter` is the
///    aggregate's outer IUnknown (almost always NULL); we pass
///    it through unchanged.  Bookkeep the new pointer in
///    `state.com`.
/// 4. If miss, return `CLASS_E_CLASSNOTAVAILABLE` per MSDN —
///    "the requested CLSID is not registered".
///
/// Note: arguments are popped via the standard stdcall
/// convention; the stub itself does not re-enter the run-loop
/// when it bails (the host-side `CreateInstance` re-entry
/// happens through `crate::com::call::call_method`, which uses
/// the same `call_guest` infrastructure as `dispatch_stub`).
fn stub_co_create_instance(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
) -> Result<u32, Win32Error> {
    let rclsid = arg_dword(cpu, mmu, 0).map_err(|t| trap("CoCreateInstance", t))?;
    let p_unk_outer = arg_dword(cpu, mmu, 1).map_err(|t| trap("CoCreateInstance", t))?;
    let _dw_cls_ctx = arg_dword(cpu, mmu, 2).map_err(|t| trap("CoCreateInstance", t))?;
    let riid = arg_dword(cpu, mmu, 3).map_err(|t| trap("CoCreateInstance", t))?;
    let ppv = arg_dword(cpu, mmu, 4).map_err(|t| trap("CoCreateInstance", t))?;
    if rclsid == 0 || riid == 0 || ppv == 0 {
        return Ok(E_POINTER);
    }
    let clsid = Guid::load(mmu, rclsid).map_err(|t| trap("CoCreateInstance", t))?;
    let _iid = Guid::load(mmu, riid).map_err(|t| trap("CoCreateInstance", t))?;
    let Some(factory) = state.com.lookup_class_factory(&clsid) else {
        return Ok(CLASS_E_CLASSNOTAVAILABLE);
    };
    if !vtable_is_plausible(mmu, factory) {
        return Ok(CLASS_E_CLASSNOTAVAILABLE);
    }
    // Drive IClassFactory::CreateInstance(pUnkOuter, riid, ppv).
    let r = call_method(
        cpu,
        mmu,
        registry,
        state,
        factory,
        SLOT_CLASS_FACTORY_CREATE_INSTANCE,
        &[p_unk_outer, riid, ppv],
    )
    .map_err(|e| Win32Error::InvalidArgument {
        stub: "CoCreateInstance",
        reason: format!("IClassFactory::CreateInstance failed: {e}"),
    })?;
    if r == S_OK {
        if let Ok(out_ptr) = mmu.load32(ppv) {
            if out_ptr != 0 {
                state.com.intern(out_ptr, None);
            }
        }
    }
    Ok(r)
}

/// `void CoFreeUnusedLibraries(void)`. No-op.
fn stub_co_free_unused_libraries(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `HRESULT CoInitialize(LPVOID pvReserved)`. S_OK.
fn stub_co_initialize(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// `HRESULT CoInitializeEx(LPVOID pvReserved, DWORD
/// dwCoInit)`.  S_OK; STA / MTA distinction is not observable
/// in a single-threaded sandbox.
fn stub_co_initialize_ex(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// `LPVOID CoTaskMemAlloc(SIZE_T cb)`. Forward to the heap arena.
fn stub_co_task_mem_alloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let n = arg_dword(cpu, mmu, 0).map_err(|t| trap("CoTaskMemAlloc", t))?;
    if n == 0 {
        return Ok(0);
    }
    let addr = state.arena_alloc(n)?;
    let buf = vec![0u8; n as usize];
    mmu.write_initializer(addr, &buf)
        .map_err(|t| trap("CoTaskMemAlloc", t))?;
    Ok(addr)
}

/// `void CoTaskMemFree(LPVOID pv)`. No-op (we don't free arena
/// allocations).
fn stub_co_task_mem_free(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `LPVOID CoTaskMemRealloc(LPVOID pv, SIZE_T cb)`.
///
/// Round-25 semantics: for `pv == NULL` behaves like
/// `CoTaskMemAlloc(cb)`; for `cb == 0` returns NULL (the
/// documented behaviour when the existing block should be
/// freed).  Otherwise allocate a fresh `cb`-byte slab, copy the
/// old bytes (we have to assume `min(cb, prior_size)` is fine
/// since we lack a real free-list — over-copy is bounded by
/// `cb` so we never read past the new buffer).  Returns NULL on
/// arena exhaustion.
fn stub_co_task_mem_realloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let pv = arg_dword(cpu, mmu, 0).map_err(|t| trap("CoTaskMemRealloc", t))?;
    let cb = arg_dword(cpu, mmu, 1).map_err(|t| trap("CoTaskMemRealloc", t))?;
    if cb == 0 {
        return Ok(0);
    }
    let new_addr = state.arena_alloc(cb)?;
    let zero = vec![0u8; cb as usize];
    mmu.write_initializer(new_addr, &zero)
        .map_err(|t| trap("CoTaskMemRealloc", t))?;
    if pv != 0 {
        // Copy at most `cb` bytes from the prior block.  We
        // don't track the prior size; a faithful realloc would
        // copy `min(cb, prior_size)` so we cap at `cb`.  This
        // matches what the Windows heap reports back and is a
        // safe upper bound for the test scope.
        for i in 0..cb {
            let b = mmu.load8(pv + i).unwrap_or(0);
            mmu.store8(new_addr + i, b)
                .map_err(|t| trap("CoTaskMemRealloc", t))?;
        }
    }
    Ok(new_addr)
}

/// `void CoUninitialize(void)`. No-op.
fn stub_co_uninitialize(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `int StringFromGUID2(REFGUID rguid, LPOLESTR lpsz, int
/// cchMax)`. Format the 16-byte GUID into the canonical
/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` UTF-16 string and
/// write it into `lpsz`. Returns the number of UTF-16 code units
/// written including the trailing NUL (39 = 38 + 1 for the
/// canonical form), or 0 on failure.
fn stub_string_from_guid2(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let pguid = arg_dword(cpu, mmu, 0).map_err(|t| trap("StringFromGUID2", t))?;
    let psz = arg_dword(cpu, mmu, 1).map_err(|t| trap("StringFromGUID2", t))?;
    let cch = arg_dword(cpu, mmu, 2).map_err(|t| trap("StringFromGUID2", t))?;
    if pguid == 0 || psz == 0 || cch < 39 {
        return Ok(0);
    }
    // Read the 16-byte GUID.
    let mut g = [0u8; 16];
    for (i, b) in g.iter_mut().enumerate() {
        *b = mmu
            .load8(pguid + i as u32)
            .map_err(|t| trap("StringFromGUID2", t))?;
    }
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    let d4 = &g[8..16];
    let s = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7],
    );
    // Encode as UTF-16LE.
    for (i, c) in s.encode_utf16().enumerate() {
        let off = (i as u32) * 2;
        mmu.store16(psz + off, c)
            .map_err(|t| trap("StringFromGUID2", t))?;
    }
    let len = s.encode_utf16().count() as u32;
    mmu.store16(psz + len * 2, 0)
        .map_err(|t| trap("StringFromGUID2", t))?;
    Ok(len + 1)
}

fn trap(stub: &'static str, t: crate::emulator::Trap) -> Win32Error {
    Win32Error::InvalidArgument {
        stub,
        reason: format!("{t}"),
    }
}
