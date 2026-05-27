//! Media Foundation platform DLL (`mfplat.dll`) stubs.
//!
//! Round-1 surface — just the heap entry points the
//! `wmfdist11` codecs (`mp43decd`, `mp4sdecd`, `wmvdecod`, …)
//! pick up from mfplat instead of msvcrt. The runtime
//! semantics are the same as `HeapAlloc` / `HeapFree`; we
//! delegate to the existing kernel32 heap so the allocation
//! tracking is unified.

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every mfplat stub.
pub fn register(registry: &mut Registry) {
    registry.register("mfplat.dll", "MFHeapAlloc", stub_mf_heap_alloc as StubFn, 4);
    registry.register("mfplat.dll", "MFHeapFree", stub_mf_heap_free as StubFn, 1);
}

/// `void *MFHeapAlloc(SIZE_T nSize, ULONG dwFlags, char *pszFile,
///                    int line, EAllocationType eat)`. The
/// codec call shape is `MFHeapAlloc(size, flags, NULL, 0, 0)`
/// — same first-two-args as `HeapAlloc(GetProcessHeap(), flags,
/// size)`. Delegate to the kernel32 heap arena.
fn stub_mf_heap_alloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let size = arg_dword(cpu, mmu, 0).map_err(|t| trap("MFHeapAlloc", t))?;
    let _flags = arg_dword(cpu, mmu, 1).map_err(|t| trap("MFHeapAlloc", t))?;
    // The heap-alloc machinery lives on HostState; mirror its
    // bump-allocator behaviour so the resulting pointer is in
    // the heap arena.
    let aligned = (size + 7) & !7;
    let addr = state.heap_cursor;
    let end = addr.wrapping_add(aligned);
    if end > state.heap_arena_end {
        return Ok(0);
    }
    state.heap_cursor = end;
    state.heap.insert(addr, vec![0u8; aligned as usize]);
    let zeros = vec![0u8; size as usize];
    mmu.write(addr, &zeros)
        .map_err(|t| trap("MFHeapAlloc", t))?;
    Ok(addr)
}

/// `void MFHeapFree(void *p)`. Drop the host bookkeeping; the
/// arena bytes are left mapped (we don't reclaim — the heap
/// is bump-allocated).
fn stub_mf_heap_free(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap("MFHeapFree", t))?;
    state.heap.remove(&p);
    Ok(0)
}

fn trap(stub: &'static str, t: crate::emulator::Trap) -> Win32Error {
    Win32Error::InvalidArgument {
        stub,
        reason: format!("{t}"),
    }
}
