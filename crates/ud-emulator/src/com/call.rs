//! COM vtable-method dispatch — round 25, stage 2/3 helper.
//!
//! Every COM object is laid out as `[lpVtbl, …per-instance fields…]`,
//! where `lpVtbl` is itself an array of `void(*)(…)` function
//! pointers indexed by interface slot.  To call a method we:
//!
//! 1. Read `[obj]` to get the vtable VA.
//! 2. Read `[vtable + 4*slot]` to get the method's guest VA.
//! 3. Push `(this, …args)` right-to-left onto the guest stack
//!    (stdcall convention: callee cleans the stack).
//! 4. Push the synthetic `RET_SENTINEL` so the run loop knows
//!    when the callee has returned.
//! 5. Run the emulator until `eip == RET_SENTINEL`.
//! 6. Read `eax` for the return value (HRESULT for the methods
//!    we drive in round-25; a refcount for `AddRef` / `Release`).
//!
//! The `this` pointer is always the first stdcall argument.  This
//! is the same convention MIDL emits for C++ `__stdcall` virtual
//! methods on Windows.
//!
//! Reference: Itanium / MSVC C++ ABI for vtable layout, plus
//! Microsoft's "stdcall calling convention" page on MSDN for the
//! argument-push order.

use super::{method_va, vtable_ptr, SLOT_ADD_REF, SLOT_QUERY_INTERFACE, SLOT_RELEASE};
use crate::emulator::{Cpu, Mmu};
use crate::win32::{HostState, Registry};

/// Call vtable slot `slot` on object `obj` with `extra_args` as
/// the post-`this` stdcall arguments.  Returns the dword in `eax`
/// at the point the callee returned to the synthetic
/// `RET_SENTINEL` (the COM-method HRESULT for most methods).
///
/// `extra_args` are pushed right-to-left, then `this = obj`, then
/// the synthetic return-address sentinel — i.e. the same calling
/// convention `crate::win32::call_guest` already implements, so
/// this is a thin wrapper that prepends `obj` as the first arg.
///
/// For `Release` / `AddRef` `extra_args` is `&[]`.  For
/// `QueryInterface(REFIID, void**)` it is `&[piid_ptr,
/// out_ptr_ptr]`.  See the SLOT_* constants in the parent module
/// for the documented slot indices and signatures.
pub fn call_method(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    obj: u32,
    slot: u32,
    extra_args: &[u32],
) -> Result<u32, crate::Error> {
    let target = method_va(mmu, obj, slot)?;
    let mut args: Vec<u32> = Vec::with_capacity(1 + extra_args.len());
    args.push(obj);
    args.extend_from_slice(extra_args);
    super::drive_guest(cpu, mmu, registry, state, target, &args)
}

/// Convenience wrapper for `IUnknown::AddRef()`.  Returns the new
/// refcount the callee reports.
pub fn add_ref(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    obj: u32,
) -> Result<u32, crate::Error> {
    let r = call_method(cpu, mmu, registry, state, obj, SLOT_ADD_REF, &[])?;
    state.com.record_addref(obj);
    Ok(r)
}

/// Convenience wrapper for `IUnknown::Release()`.  Returns the
/// new refcount the callee reports (which is also our signal that
/// the object has been destroyed when it returns 0).
pub fn release(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    obj: u32,
) -> Result<u32, crate::Error> {
    let r = call_method(cpu, mmu, registry, state, obj, SLOT_RELEASE, &[])?;
    state.com.record_release(obj);
    Ok(r)
}

/// `IUnknown::QueryInterface(REFIID, void**)`.
///
/// The IID must already be staged as 16 bytes at `iid_addr` in
/// guest memory (see [`super::Guid::stage`]).  `out_ptr_ptr` must
/// be a writable 4-byte slot the callee can store the resulting
/// interface pointer into.
///
/// Returns the HRESULT (`S_OK = 0` on success, `E_NOINTERFACE` if
/// the object does not satisfy that IID).  On success the caller
/// reads `[out_ptr_ptr]` to recover the new interface pointer.
pub fn query_interface(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    obj: u32,
    iid_addr: u32,
    out_ptr_ptr: u32,
) -> Result<u32, crate::Error> {
    call_method(
        cpu,
        mmu,
        registry,
        state,
        obj,
        SLOT_QUERY_INTERFACE,
        &[iid_addr, out_ptr_ptr],
    )
}

/// Pre-flight check: does `obj`'s vtable look "real" (= the first
/// 12 bytes are three readable function pointers, all in mapped
/// memory)?  Used by tests to bail early when a codec returned a
/// zeroed-out interface stub instead of a real object.
pub fn vtable_is_plausible(mmu: &Mmu, obj: u32) -> bool {
    let Ok(vtbl) = vtable_ptr(mmu, obj) else {
        return false;
    };
    if vtbl == 0 {
        return false;
    }
    for slot in 0..3 {
        match mmu.load32(vtbl.wrapping_add(slot * 4)) {
            Ok(p) if p != 0 => continue,
            _ => return false,
        }
    }
    true
}
