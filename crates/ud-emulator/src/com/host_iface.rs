//! Round 27 — host-side COM interface stubs.
//!
//! When a guest codec calls `IBaseFilter::JoinFilterGraph(pGraph,
//! pName)` we want the codec to believe it is hosted by a
//! real `IFilterGraph`.  But there is nothing on the host
//! side to back that pointer — the test process is not running a
//! real DirectShow filter graph manager.
//!
//! This module mints a *host-side* COM object: a vtable laid out
//! in arena memory whose function-pointer slots point at
//! synthetic thunk addresses registered with [`crate::win32::Registry`].
//! When the codec calls one of those slots, the existing
//! `dispatch_stub` machinery routes control into a Rust handler
//! that returns a sensible HRESULT (typically `E_NOTIMPL` or
//! `S_OK`).
//!
//! Refcounting is intentionally minimal — the host object lives
//! for the duration of the sandbox, so `AddRef` / `Release` just
//! increment / decrement an internal counter without ever
//! deallocating.  The codec sees the contract:
//!
//! * `QueryInterface(IID_IUnknown | IID_IFilterGraph)` → `S_OK`
//! * `QueryInterface(other)` → `E_NOINTERFACE`
//! * `AddRef` → previous_refcount + 1
//! * `Release` → previous_refcount - 1 (never reaching 0 in
//!   practice; we floor at 1 so a buggy codec that double-releases
//!   doesn't kill the host stub mid-test).
//! * Every IFilterGraph method (`AddFilter` / `RemoveFilter` /
//!   `EnumFilters` / `FindFilterByName` / `ConnectDirect` /
//!   `Reconnect` / `Disconnect` / `SetDefaultSyncSource`) →
//!   `E_NOTIMPL`.  None of these are called during the codec's
//!   `JoinFilterGraph` → `ReceiveConnection` path; they exist so
//!   if the codec *does* probe one of them later, it gets a
//!   well-formed reply rather than crashing on an uninitialised
//!   slot.
//!
//! Reference: MSDN
//! "[IFilterGraph (DirectShow)](https://learn.microsoft.com/en-us/windows/win32/api/strmif/nn-strmif-ifiltergraph)"
//! interface — slots 0..2 are IUnknown's; slots 3..10 are
//! IFilterGraph's eight methods in declaration order.

use super::{
    Guid, IID_ICLASSFACTORY, IID_IFILTERGRAPH, IID_IMEDIASAMPLE, IID_IMEDIASAMPLE2,
    IID_IMEMALLOCATOR, IID_IPIN, IID_IUNKNOWN,
};
use crate::emulator::{Cpu, Mmu};
use crate::win32::{HostState, Registry, StubFn, Win32Error};

/// `S_OK = 0` — locally redefined to keep this module
/// self-contained.
const S_OK: u32 = 0x0000_0000;
/// `E_NOINTERFACE = 0x80004002`.
const E_NOINTERFACE: u32 = 0x8000_4002;
/// `E_NOTIMPL = 0x80004001`.
const E_NOTIMPL: u32 = 0x8000_4001;

/// Pseudo-DLL name used when registering host-COM thunks with the
/// stub `Registry`.  The guest never imports from this name;
/// `dispatch_stub` only reads it for tracing.
const HOST_DLL: &str = "host-com.host";

/// Register every host-COM thunk with the stub registry.  Idempotent.
///
/// Each method is a separate registration so the trace-feature
/// `kind=win32_call` events name the IFilterGraph slot directly.
pub fn register(registry: &mut Registry) {
    // IUnknown trio — present on every host vtable.
    registry.register(HOST_DLL, "IFilterGraph::QueryInterface", qi as StubFn, 3);
    registry.register(HOST_DLL, "IFilterGraph::AddRef", addref as StubFn, 1);
    registry.register(HOST_DLL, "IFilterGraph::Release", release as StubFn, 1);
    // IFilterGraph methods — see MSDN strmif.h.
    registry.register(HOST_DLL, "IFilterGraph::AddFilter", notimpl_3 as StubFn, 3);
    registry.register(
        HOST_DLL,
        "IFilterGraph::RemoveFilter",
        notimpl_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IFilterGraph::EnumFilters",
        notimpl_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IFilterGraph::FindFilterByName",
        notimpl_3 as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IFilterGraph::ConnectDirect",
        notimpl_4 as StubFn,
        4,
    );
    registry.register(HOST_DLL, "IFilterGraph::Reconnect", notimpl_2 as StubFn, 2);
    registry.register(HOST_DLL, "IFilterGraph::Disconnect", notimpl_2 as StubFn, 2);
    registry.register(
        HOST_DLL,
        "IFilterGraph::SetDefaultSyncSource",
        notimpl_1 as StubFn,
        1,
    );

    // ---- HostIPin (output-pin role) — round-27 A.2/B reach -----
    //
    // The codec calls `pConnector->QueryDirection()` etc. from
    // inside its own `ReceiveConnection`.  If `pConnector` is the
    // codec's own input pin (round-26's self-loop), QueryDirection
    // reports INPUT and the codec falls into a no-acceptable-type
    // branch.  HostIPin lets a test pass a non-self IPin pointer
    // that QueryDirection's as OUTPUT.
    registry.register(HOST_DLL, "IPin::QueryInterface", pin_qi as StubFn, 3);
    registry.register(HOST_DLL, "IPin::AddRef", addref as StubFn, 1);
    registry.register(HOST_DLL, "IPin::Release", release as StubFn, 1);
    registry.register(HOST_DLL, "IPin::Connect", notimpl_3 as StubFn, 3);
    registry.register(HOST_DLL, "IPin::ReceiveConnection", notimpl_3 as StubFn, 3);
    registry.register(HOST_DLL, "IPin::Disconnect", pin_s_ok_1 as StubFn, 1);
    registry.register(HOST_DLL, "IPin::ConnectedTo", pin_connected_to as StubFn, 2);
    registry.register(
        HOST_DLL,
        "IPin::ConnectionMediaType",
        pin_connection_media_type as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin::QueryPinInfo",
        pin_query_pin_info as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin::QueryDirection",
        pin_query_direction as StubFn,
        2,
    );
    registry.register(HOST_DLL, "IPin::QueryId", notimpl_2 as StubFn, 2);
    registry.register(HOST_DLL, "IPin::QueryAccept", pin_s_ok_2 as StubFn, 2);
    registry.register(
        HOST_DLL,
        "IPin::EnumMediaTypes",
        pin_enum_media_types as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin::QueryInternalConnections",
        notimpl_3 as StubFn,
        3,
    );
    registry.register(HOST_DLL, "IPin::EndOfStream", pin_s_ok_1 as StubFn, 1);
    registry.register(HOST_DLL, "IPin::BeginFlush", pin_s_ok_1 as StubFn, 1);
    registry.register(HOST_DLL, "IPin::EndFlush", pin_s_ok_1 as StubFn, 1);
    registry.register(HOST_DLL, "IPin::NewSegment", pin_s_ok_5 as StubFn, 5);

    // HostIEnumMediaTypes — vended by HostIPin::EnumMediaTypes.
    registry.register(
        HOST_DLL,
        "IEnumMediaTypes::QueryInterface",
        enum_qi as StubFn,
        3,
    );
    registry.register(HOST_DLL, "IEnumMediaTypes::AddRef", addref as StubFn, 1);
    registry.register(HOST_DLL, "IEnumMediaTypes::Release", release as StubFn, 1);
    registry.register(HOST_DLL, "IEnumMediaTypes::Next", enum_next as StubFn, 4);
    registry.register(HOST_DLL, "IEnumMediaTypes::Skip", enum_skip as StubFn, 2);
    registry.register(HOST_DLL, "IEnumMediaTypes::Reset", enum_reset as StubFn, 1);
    registry.register(HOST_DLL, "IEnumMediaTypes::Clone", notimpl_2 as StubFn, 2);

    // ---- HostIMemAllocator (round 30) ------------------------
    registry.register(
        HOST_DLL,
        "IMemAllocator::QueryInterface",
        alloc_qi as StubFn,
        3,
    );
    registry.register(HOST_DLL, "IMemAllocator::AddRef", addref as StubFn, 1);
    registry.register(HOST_DLL, "IMemAllocator::Release", release as StubFn, 1);
    registry.register(
        HOST_DLL,
        "IMemAllocator::SetProperties",
        alloc_set_properties as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IMemAllocator::GetProperties",
        alloc_get_properties as StubFn,
        2,
    );
    registry.register(HOST_DLL, "IMemAllocator::Commit", alloc_commit as StubFn, 1);
    registry.register(
        HOST_DLL,
        "IMemAllocator::Decommit",
        alloc_decommit as StubFn,
        1,
    );
    // Round 41 — `IMemAllocator::GetBuffer(this, IMediaSample
    // **ppBuffer, REFERENCE_TIME *pStartTime, REFERENCE_TIME
    // *pStopTime, DWORD dwFlags)` is FIVE pushed dwords (this
    // + four arguments), not four.  The earlier registration
    // with `arg_dwords=4` left the dispatcher 4 bytes short on
    // its stdcall callee-cleanup, so every Transform call site
    // that invoked GetBuffer (`mpg4ds32` RVA `0x4064d4`) ended
    // with esp 4 bytes too low.  Transform's matched
    // `pop ebx` at `0x4065c4` then read the wrong slot —
    // exactly the imbalance round 40's snapshots localised.
    registry.register(
        HOST_DLL,
        "IMemAllocator::GetBuffer",
        alloc_get_buffer as StubFn,
        5,
    );
    registry.register(
        HOST_DLL,
        "IMemAllocator::ReleaseBuffer",
        alloc_release_buffer as StubFn,
        2,
    );

    // ---- HostIMediaSample (round 30) -------------------------
    registry.register(
        HOST_DLL,
        "IMediaSample::QueryInterface",
        sample_qi as StubFn,
        3,
    );
    registry.register(HOST_DLL, "IMediaSample::AddRef", addref as StubFn, 1);
    // Round 43 — dedicated `sample_release` thunk recycles the
    // sample back into its allocator's pool (clears `in_use` at
    // `+36`) when the refcount transitions through 1 → 0.  The
    // generic `release` thunk would floor the refcount at 1 and
    // never recycle, exhausting the pool after `cBuffers` calls
    // (round 42 saw `0x80040211 = VFW_E_NOT_COMMITTED` on frame 4
    // of the gop-30-352x288 fixture for exactly this reason).  Per
    // the standard `CMediaSample` implementation, the destructor
    // is the side-effect that returns the buffer to the allocator;
    // we replicate that contract by recycling on the rc==0
    // transition.
    registry.register(
        HOST_DLL,
        "IMediaSample::Release",
        sample_release as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::GetPointer",
        sample_get_pointer as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::GetSize",
        sample_get_size as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::GetTime",
        sample_get_time as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::SetTime",
        sample_set_time as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::IsSyncPoint",
        sample_is_sync_point as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::SetSyncPoint",
        sample_set_sync_point as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::IsPreroll",
        sample_returns_s_false_1 as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::SetPreroll",
        sample_returns_s_ok_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::GetActualDataLength",
        sample_get_actual_data_length as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::SetActualDataLength",
        sample_set_actual_data_length as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::GetMediaType",
        sample_get_media_type as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::SetMediaType",
        sample_returns_s_ok_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::IsDiscontinuity",
        sample_returns_s_false_1 as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::SetDiscontinuity",
        sample_returns_s_ok_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::GetMediaTime",
        sample_get_media_time as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample::SetMediaTime",
        sample_set_media_time as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample2::GetProperties",
        sample_get_properties as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IMediaSample2::SetProperties",
        sample_set_properties as StubFn,
        3,
    );

    // ---- Round 35 — host class factory for CLSID_MemoryAllocator -
    //
    // The IUnknown trio is shared with the IFilterGraph thunks
    // (`qi` / `addref` / `release`) at the registry level — but we
    // still need a dedicated `IClassFactory::QueryInterface` thunk
    // because the QI handler must accept `IID_IClassFactory` (which
    // the `IFilterGraph::QueryInterface` thunk above does not).
    // CreateInstance dispatches to a fresh `HostIMemAllocator`.
    //
    // `arg_dwords` here counts every dword the codec pushes onto
    // the stack, INCLUDING the `this` pointer (first stdcall arg
    // for every COM method).  CreateInstance ABI is
    // `HRESULT CreateInstance(this, IUnknown* pUnkOuter, REFIID,
    // void** ppv)` = 4 dwords; LockServer is `(this, BOOL)` =
    // 2 dwords.  Mismatching this leaves a stack-cleanup hole
    // that surfaces as a wild EIP after the next `ret`.
    registry.register(
        HOST_DLL,
        "IClassFactory::QueryInterface",
        alloc_factory_qi as StubFn,
        3,
    );
    registry.register(HOST_DLL, "IClassFactory::AddRef", addref as StubFn, 1);
    registry.register(HOST_DLL, "IClassFactory::Release", release as StubFn, 1);
    registry.register(
        HOST_DLL,
        "IClassFactory::CreateInstance",
        alloc_factory_create_instance as StubFn,
        4,
    );
    registry.register(
        HOST_DLL,
        "IClassFactory::LockServer",
        alloc_factory_lock_server as StubFn,
        2,
    );
}

// ---- HostIMemAllocator + HostIMediaSample minting helpers --------------
//
// Reference: MSDN "DirectShow Reference":
// * IMemAllocator —
//   <https://learn.microsoft.com/en-us/windows/win32/api/strmif/nn-strmif-imemallocator>
// * IMediaSample —
//   <https://learn.microsoft.com/en-us/windows/win32/api/strmif/nn-strmif-imediasample>
// * ALLOCATOR_PROPERTIES —
//   <https://learn.microsoft.com/en-us/windows/win32/api/strmif/ns-strmif-allocator_properties>
//
// Layouts (all 16-byte aligned via `arena_alloc`):
//
// HostIMemAllocator @ obj (96 bytes total):
// | offset | content                                   |
// |--------|--------------------------------------------|
// | obj    | vtbl_ptr (= obj + 16)                     |
// | obj+4  | refcount = 1                              |
// | obj+8  | sample_pool_head (= guest VA of first sample, 0 if not yet minted) |
// | obj+12 | committed flag (0 = decommitted, 1 = committed) — round 32 |
// | obj+16 | vtbl[0..9] (36 bytes; rest of 96 unused)  |
//
// Round 32 — Commit/Decommit state machine (per IMemAllocator
// MSDN semantics): the allocator starts decommitted; GetBuffer
// returns VFW_E_NOT_COMMITTED until Commit() flips obj+12 to 1.
// Decommit() flips it back to 0. ReleaseBuffer is allowed in
// either state (codec may still hold samples it acquired before
// Decommit).
//
// HostIMediaSample @ obj (64 bytes header + payload region):
// | offset | content                                   |
// |--------|--------------------------------------------|
// | obj    | vtbl_ptr (= obj + 64)                     |
// | obj+4  | refcount                                   |
// | obj+8  | data_ptr (guest VA of underlying byte region) |
// | obj+12 | data_capacity                              |
// | obj+16 | data_actual_length                         |
// | obj+20 | sync_point flag (0 or 1)                  |
// | obj+24 | media_type_ptr (guest VA of AM_MEDIA_TYPE, 0 = none) |
// | obj+28 | reserved (cookie / pool linkage)           |
// | obj+32 | next_pool_link (guest VA of next pool sample, 0 = end) |
// | obj+36 | in_use flag (1 = checked out via GetBuffer) |
// | obj+40 | reserved                                   |
// | obj+44 | reserved                                   |
// | obj+48 | reserved                                   |
// | obj+52 | reserved                                   |
// | obj+56 | reserved                                   |
// | obj+60 | reserved                                   |
// | obj+64 | vtbl[0..18] (72 bytes)                    |

/// Mint a host IMemAllocator with `pool_size` IMediaSample slots,
/// each backed by a fresh `sample_capacity`-byte data region. The
/// returned guest VA is suitable as the `pAllocator` argument of
/// `IMemInputPin::NotifyAllocator`.
///
/// Each minted sample carries `media_type_ptr` as its
/// `GetMediaType` return value (typically the AMT the upstream pin
/// negotiated through `IPin::ReceiveConnection`); pass `0` if no
/// AMT should be reported.
pub fn mint_host_mem_allocator(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
    pool_size: u32,
    sample_capacity: u32,
    media_type_ptr: u32,
) -> Result<u32, crate::Error> {
    let obj = state.arena_alloc(96).map_err(crate::Error::Win32)?;
    let vtbl = obj.wrapping_add(16);
    mmu.write_initializer(obj, &vtbl.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 4, &1u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    // sample_pool_head — set after minting the pool below.
    mmu.write_initializer(obj + 8, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 12, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;

    let methods: [&str; 9] = [
        "IMemAllocator::QueryInterface",
        "IMemAllocator::AddRef",
        "IMemAllocator::Release",
        "IMemAllocator::SetProperties",
        "IMemAllocator::GetProperties",
        "IMemAllocator::Commit",
        "IMemAllocator::Decommit",
        "IMemAllocator::GetBuffer",
        "IMemAllocator::ReleaseBuffer",
    ];
    for (i, name) in methods.iter().enumerate() {
        let thunk = registry
            .resolve(HOST_DLL, name)
            .ok_or_else(|| Win32Error::InvalidArgument {
                stub: "mint_host_mem_allocator",
                reason: format!("thunk {name:?} not registered"),
            })
            .map_err(crate::Error::Win32)?;
        mmu.write_initializer(vtbl + (i as u32) * 4, &thunk.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }

    // Mint the pool: a singly-linked list anchored at obj+8.
    let mut prev_link_addr: u32 = obj + 8;
    for _ in 0..pool_size {
        let sample = mint_host_media_sample(state, mmu, registry, sample_capacity, media_type_ptr)?;
        // Patch prev's next-pool-link to point at this sample.
        mmu.write_initializer(prev_link_addr, &sample.to_le_bytes())
            .map_err(crate::Error::Trap)?;
        // Next iteration links from this sample's `next_pool_link`.
        prev_link_addr = sample + 32;
    }
    // Terminate.
    mmu.write_initializer(prev_link_addr, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    Ok(obj)
}

/// Mint a single host IMediaSample wrapping a fresh
/// `data_capacity`-byte region. `media_type_ptr` (may be 0) is
/// returned by `GetMediaType`. Initial `actual_length` is 0;
/// callers populate the bytes + length via [`media_sample_set_payload`]
/// before passing the sample to the codec's `Receive`.
pub fn mint_host_media_sample(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
    data_capacity: u32,
    media_type_ptr: u32,
) -> Result<u32, crate::Error> {
    // Round capacity up to 16 to keep arena alignment predictable.
    let cap = data_capacity.div_ceil(16) * 16;
    // Round 39 — vtable extended from 18 → 21 entries to cover
    // `SetMediaTime` (slot 18) + `IMediaSample2::GetProperties`
    // (slot 19) + `IMediaSample2::SetProperties` (slot 20).  Header
    // sized accordingly.
    let header_size = 64u32 + 21 * 4; // 64-byte header + 84-byte vtable
    let obj = state
        .arena_alloc(header_size.div_ceil(16) * 16)
        .map_err(crate::Error::Win32)?;
    let data_region = state
        .arena_alloc(cap.max(16))
        .map_err(crate::Error::Win32)?;
    let vtbl = obj.wrapping_add(64);

    mmu.write_initializer(obj, &vtbl.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 4, &1u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 8, &data_region.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 12, &cap.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 16, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 20, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 24, &media_type_ptr.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 28, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 32, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 36, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    for off in [40u32, 44, 48, 52, 56, 60] {
        mmu.write_initializer(obj + off, &0u32.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }

    let methods: [&str; 21] = [
        "IMediaSample::QueryInterface",
        "IMediaSample::AddRef",
        "IMediaSample::Release",
        "IMediaSample::GetPointer",
        "IMediaSample::GetSize",
        "IMediaSample::GetTime",
        "IMediaSample::SetTime",
        "IMediaSample::IsSyncPoint",
        "IMediaSample::SetSyncPoint",
        "IMediaSample::IsPreroll",
        "IMediaSample::SetPreroll",
        "IMediaSample::GetActualDataLength",
        "IMediaSample::SetActualDataLength",
        "IMediaSample::GetMediaType",
        "IMediaSample::SetMediaType",
        "IMediaSample::IsDiscontinuity",
        "IMediaSample::SetDiscontinuity",
        "IMediaSample::GetMediaTime",
        // Round 39 — slots 18..20 (last IMediaSample method +
        // IMediaSample2 extension).  Codecs that QI for
        // IID_IMEDIASAMPLE2 expect these to be live thunks.
        "IMediaSample::SetMediaTime",
        "IMediaSample2::GetProperties",
        "IMediaSample2::SetProperties",
    ];
    for (i, name) in methods.iter().enumerate() {
        let thunk = registry
            .resolve(HOST_DLL, name)
            .ok_or_else(|| Win32Error::InvalidArgument {
                stub: "mint_host_media_sample",
                reason: format!("thunk {name:?} not registered"),
            })
            .map_err(crate::Error::Win32)?;
        mmu.write_initializer(vtbl + (i as u32) * 4, &thunk.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }
    Ok(obj)
}

/// Copy `payload` into a previously-minted sample's data region
/// + update the sample's actual-length / sync-point flags.
///
/// The payload must fit in the sample's `data_capacity`.
pub fn media_sample_set_payload(
    mmu: &mut Mmu,
    sample: u32,
    payload: &[u8],
    sync_point: bool,
) -> Result<(), crate::Error> {
    let cap = mmu.load32(sample + 12).map_err(crate::Error::Trap)?;
    if (payload.len() as u32) > cap {
        return Err(crate::Error::Win32(Win32Error::InvalidArgument {
            stub: "media_sample_set_payload",
            reason: format!("payload {} > sample cap {}", payload.len(), cap),
        }));
    }
    let data = mmu.load32(sample + 8).map_err(crate::Error::Trap)?;
    for (i, &b) in payload.iter().enumerate() {
        mmu.store8(data + i as u32, b).map_err(crate::Error::Trap)?;
    }
    mmu.write_initializer(sample + 16, &(payload.len() as u32).to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(sample + 20, &(sync_point as u32).to_le_bytes())
        .map_err(crate::Error::Trap)?;
    Ok(())
}

/// Lay out a host IFilterGraph in arena memory.  Returns the
/// guest VA of the object pointer — suitable as the `pGraph`
/// argument of `IBaseFilter::JoinFilterGraph`.
///
/// Layout:
///
/// | offset | content                          |
/// |--------|-----------------------------------|
/// | obj    | vtbl_ptr (= obj + 8)             |
/// | obj+4  | refcount (initialised to 1)      |
/// | obj+8  | vtbl[0] = QueryInterface thunk   |
/// | obj+12 | vtbl[1] = AddRef thunk           |
/// | obj+16 | vtbl[2] = Release thunk          |
/// | obj+20 | vtbl[3] = AddFilter thunk        |
/// | …      | …                                |
/// | obj+48 | vtbl[10] = SetDefaultSyncSource  |
///
/// Total footprint is `8 + 11*4 = 52 bytes`; the arena allocator
/// rounds to 16 so we consume 64 bytes per host filter graph.
pub fn mint_host_filter_graph(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
) -> Result<u32, crate::Error> {
    let obj = state.arena_alloc(64).map_err(crate::Error::Win32)?;
    let vtbl = obj.wrapping_add(8);
    // [obj] = vtbl
    mmu.write_initializer(obj, &vtbl.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    // [obj+4] = refcount = 1
    mmu.write_initializer(obj + 4, &1u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    // Build the vtable.
    let methods: [&str; 11] = [
        "IFilterGraph::QueryInterface",
        "IFilterGraph::AddRef",
        "IFilterGraph::Release",
        "IFilterGraph::AddFilter",
        "IFilterGraph::RemoveFilter",
        "IFilterGraph::EnumFilters",
        "IFilterGraph::FindFilterByName",
        "IFilterGraph::ConnectDirect",
        "IFilterGraph::Reconnect",
        "IFilterGraph::Disconnect",
        "IFilterGraph::SetDefaultSyncSource",
    ];
    for (i, name) in methods.iter().enumerate() {
        let thunk = registry.resolve(HOST_DLL, name).ok_or_else(|| {
            crate::Error::Win32(Win32Error::InvalidArgument {
                stub: "mint_host_filter_graph",
                reason: format!("host-com thunk {name:?} not registered"),
            })
        })?;
        mmu.write_initializer(vtbl + (i as u32) * 4, &thunk.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }
    Ok(obj)
}

/// Round 27 A.2/B — mint a host-side `IPin` that pretends to be
/// an OUTPUT pin advertising `amt_addr` (a guest pointer to a
/// staged `AM_MEDIA_TYPE`).  Returned guest pointer is suitable
/// as the `pConnector` argument of `IPin::ReceiveConnection`.
///
/// **Round 37** — extended with parent-filter + connected-pin slots
/// so [`pin_query_pin_info`] / [`pin_connected_to`] can answer the
/// codec's introspection of the upstream pin.  Per MSDN
/// `IPin::QueryPinInfo` returns a `PIN_INFO { IBaseFilter* pFilter,
/// PIN_DIRECTION dir, WCHAR achName[128] }`; the codec uses
/// `pFilter` to call back into the upstream filter (e.g. via
/// `IBaseFilter::QueryFilterInfo`).
///
/// Object layout (16-byte aligned):
///
/// | offset | content                    |
/// |--------|-----------------------------|
/// | obj    | vtbl_ptr (= obj + 24)      |
/// | obj+4  | refcount = 1               |
/// | obj+8  | advertised_amt = amt_addr  |
/// | obj+12 | connected_pin (codec input pin we'll be connected to, or 0) |
/// | obj+16 | parent_filter (host IBaseFilter wrapping `self`, or 0)      |
/// | obj+20 | reserved (0)               |
/// | obj+24 | vtbl[0..18] (72 bytes)     |
///
/// Total = 24 + 72 = 96 bytes; arena allocator rounds to 112 with
/// some headroom for future fields.
///
/// Round-27/30/32 callers that don't track the codec's input pin
/// pass `0` for `connected_pin` and the synthesized
/// `parent_filter`; the layout still holds.  Round 37's discovery
/// path uses [`mint_host_output_pin_with_connection`] to plumb the
/// real codec input pin through.
pub fn mint_host_output_pin(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
    amt_addr: u32,
) -> Result<u32, crate::Error> {
    mint_host_output_pin_with_connection(state, mmu, registry, amt_addr, 0)
}

/// Round 37 — same as [`mint_host_output_pin`] but also stamps the
/// codec's input-pin pointer (`connected_pin`) into the new pin
/// object so [`pin_connected_to`] can return it, and synthesizes a
/// host `IBaseFilter` parent so [`pin_query_pin_info`] can fill in
/// `PIN_INFO::pFilter`.
///
/// `connected_pin == 0` is allowed (pre-r37 behaviour); in that
/// case `pin_connected_to` reports `VFW_E_NOT_CONNECTED`.
///
/// The synthesized parent filter is minted through
/// [`crate::com::host_iface_r31::mint_host_base_filter`] (round-31
/// helper) — it exposes `obj+8 = self_pin` so a codec walking
/// `pFilter->EnumPins → IPin*` reaches back to the same host pin
/// it called `QueryPinInfo` on.
pub fn mint_host_output_pin_with_connection(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
    amt_addr: u32,
    connected_pin: u32,
) -> Result<u32, crate::Error> {
    let obj = state.arena_alloc(112).map_err(crate::Error::Win32)?;
    let vtbl = obj.wrapping_add(24);
    mmu.write_initializer(obj, &vtbl.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 4, &1u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 8, &amt_addr.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 12, &connected_pin.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    // Mint a parent IBaseFilter wrapping `self` (obj+8 of the
    // r31 base-filter struct holds the pin pointer; we point it
    // at our own pin so a recursive walk closes back here).
    let parent_filter = super::host_iface_r31::mint_host_base_filter(state, mmu, registry, obj)?;
    mmu.write_initializer(obj + 16, &parent_filter.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 20, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    let methods: [&str; 18] = [
        "IPin::QueryInterface",
        "IPin::AddRef",
        "IPin::Release",
        "IPin::Connect",
        "IPin::ReceiveConnection",
        "IPin::Disconnect",
        "IPin::ConnectedTo",
        "IPin::ConnectionMediaType",
        "IPin::QueryPinInfo",
        "IPin::QueryDirection",
        "IPin::QueryId",
        "IPin::QueryAccept",
        "IPin::EnumMediaTypes",
        "IPin::QueryInternalConnections",
        "IPin::EndOfStream",
        "IPin::BeginFlush",
        "IPin::EndFlush",
        "IPin::NewSegment",
    ];
    for (i, name) in methods.iter().enumerate() {
        let thunk = registry.resolve(HOST_DLL, name).ok_or_else(|| {
            crate::Error::Win32(Win32Error::InvalidArgument {
                stub: "mint_host_output_pin",
                reason: format!("host-com thunk {name:?} not registered"),
            })
        })?;
        mmu.write_initializer(vtbl + (i as u32) * 4, &thunk.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }
    Ok(obj)
}

// ---- Round 35 — host class factory for CLSID_MemoryAllocator -------
//
// Reference: MSDN
//  * `IClassFactory` —
//    <https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nn-unknwn-iclassfactory>
//  * `CoCreateInstance` —
//    <https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance>
//  * `CLSID_MemoryAllocator` GUID — Windows SDK header
//    `axextend.h` (`{1E651CC0-B199-11D0-8212-00C04FC32C45}`).
//
// Layout — 16-byte aligned (arena allocator rounds to 16):
//
// HostIClassFactory @ obj (48 bytes total):
// | offset | content                         |
// |--------|----------------------------------|
// | obj    | vtbl_ptr (= obj + 8)            |
// | obj+4  | refcount = 1                    |
// | obj+8  | vtbl[0..4] = QI / AddRef /      |
// |        |   Release / CreateInstance /    |
// |        |   LockServer (5 slots = 20 B)   |
// | obj+28 | reserved (0)                    |
//
// Round 35 — `CreateInstance(pUnkOuter, REFIID, void** ppv)`
// validates `riid == IID_IUnknown || riid == IID_IMemAllocator`,
// mints a fresh `HostIMemAllocator` with default pool shape
// (`DEFAULT_MEM_ALLOCATOR_FACTORY_POOL` slots × 256 KiB), writes
// the new pointer to `*ppv`, and returns `S_OK`.  Aggregation
// (`pUnkOuter != NULL`) is rejected with `CLASS_E_NOAGGREGATION`
// per MSDN — DirectShow allocators do not aggregate.

/// Default sample-pool size for the [`mint_host_mem_allocator_class_factory`]
/// `CreateInstance` reply.  Matches the round-30+ host-allocator
/// pool shape (4 slots = enough for codec-side queueing without
/// exhausting the arena).
pub const DEFAULT_MEM_ALLOCATOR_FACTORY_POOL: u32 = 4;
/// Default per-sample data capacity for the
/// [`mint_host_mem_allocator_class_factory`] `CreateInstance`
/// reply.  256 KiB covers 320×240 RGB24 + headroom; the codec
/// will SetProperties + Commit immediately afterwards anyway.
pub const DEFAULT_MEM_ALLOCATOR_FACTORY_CAPACITY: u32 = 256 * 1024;

/// `CLASS_E_NOAGGREGATION = 0x80040110` — `IClassFactory::
/// CreateInstance` rejects aggregation when `pUnkOuter != NULL`
/// and the class doesn't support being aggregated.  Source:
/// `winerror.h`.
const CLASS_E_NOAGGREGATION: u32 = 0x8004_0110;

/// Round 35 — mint a host-side `IClassFactory` whose
/// `CreateInstance` mints fresh `HostIMemAllocator` instances.
///
/// Pre-registered in [`crate::Sandbox::new`]'s class-factory
/// cache under `CLSID_MemoryAllocator` so codec-side
/// `CoCreateInstance(CLSID_MemoryAllocator, NULL, _,
/// IID_IMemAllocator, &alloc)` calls succeed without going
/// through the (nonexistent) Windows SCM.  This lets codecs that
/// rely on the canonical DShow memory-allocator class
/// (`mpg4ds32` from inside `IMemInputPin::GetAllocator`)
/// surface a usable allocator pointer instead of the round-34
/// baseline `CLASS_E_CLASSNOTAVAILABLE` (`0x80040111`).
pub fn mint_host_mem_allocator_class_factory(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
) -> Result<u32, crate::Error> {
    let obj = state.arena_alloc(48).map_err(crate::Error::Win32)?;
    let vtbl = obj.wrapping_add(8);
    mmu.write_initializer(obj, &vtbl.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 4, &1u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    let methods: [&str; 5] = [
        "IClassFactory::QueryInterface",
        "IClassFactory::AddRef",
        "IClassFactory::Release",
        "IClassFactory::CreateInstance",
        "IClassFactory::LockServer",
    ];
    for (i, name) in methods.iter().enumerate() {
        let thunk = registry.resolve(HOST_DLL, name).ok_or_else(|| {
            crate::Error::Win32(Win32Error::InvalidArgument {
                stub: "mint_host_mem_allocator_class_factory",
                reason: format!("host-com thunk {name:?} not registered"),
            })
        })?;
        mmu.write_initializer(vtbl + (i as u32) * 4, &thunk.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }
    Ok(obj)
}

/// `IClassFactory::QueryInterface(this, REFIID, void**)`.
///
/// Resolves `IID_IUnknown` and `IID_IClassFactory` to `this`;
/// every other IID returns `E_NOINTERFACE` and zeros `*ppv`.
fn alloc_factory_qi(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let piid = arg(cpu, mmu, 1)?;
    let ppv = arg(cpu, mmu, 2)?;
    if ppv == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let _ = mmu.write_initializer(ppv, &0u32.to_le_bytes());
    if piid == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIClassFactory::QI", t))?;
    if iid == IID_IUNKNOWN || iid == IID_ICLASSFACTORY {
        if let Ok(rc) = mmu.load32(this + 4) {
            let _ = mmu.write_initializer(this + 4, &rc.saturating_add(1).to_le_bytes());
        }
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

/// `IClassFactory::CreateInstance(this, IUnknown* pUnkOuter,
/// REFIID riid, void** ppv)` — slot 3.
///
/// Per MSDN
/// <https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iclassfactory-createinstance>:
///
/// * `pUnkOuter != NULL` and the class doesn't support
///   aggregation → `CLASS_E_NOAGGREGATION`.
/// * `ppv == NULL` → `E_POINTER`.
/// * Successful instantiation → write the new pointer into `*ppv`,
///   return `S_OK`.
/// * Requested IID not satisfied by the class → `E_NOINTERFACE`.
///
/// We mint a fresh `HostIMemAllocator` (default 4-slot pool ×
/// 256 KiB capacity) and accept `IID_IUnknown` /
/// `IID_IMemAllocator`.  The codec is expected to drive
/// `SetProperties + Commit` on the returned allocator immediately;
/// the default capacity is large enough to survive any
/// `GetBuffer` call before that.
fn alloc_factory_create_instance(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let p_unk_outer = arg(cpu, mmu, 1)?;
    let p_iid = arg(cpu, mmu, 2)?;
    let ppv = arg(cpu, mmu, 3)?;
    if ppv == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let _ = mmu.write_initializer(ppv, &0u32.to_le_bytes());
    if p_unk_outer != 0 {
        return Ok(CLASS_E_NOAGGREGATION);
    }
    if p_iid == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let iid = Guid::load(mmu, p_iid).map_err(|t| trap("HostIClassFactory::CreateInstance", t))?;
    if iid != IID_IUNKNOWN && iid != IID_IMEMALLOCATOR {
        return Ok(E_NOINTERFACE);
    }
    // Mint a fresh allocator. Errors propagate as Win32Error so
    // dispatch_stub can report a meaningful diagnostic; this never
    // happens in practice once Sandbox::new has registered the
    // host-COM thunks.
    let alloc = match super::mint_host_mem_allocator(
        state,
        mmu,
        registry,
        DEFAULT_MEM_ALLOCATOR_FACTORY_POOL,
        DEFAULT_MEM_ALLOCATOR_FACTORY_CAPACITY,
        0,
    ) {
        Ok(a) => a,
        Err(crate::Error::Win32(e)) => return Err(e),
        Err(other) => {
            return Err(Win32Error::InvalidArgument {
                stub: "HostIClassFactory::CreateInstance",
                reason: format!("mint_host_mem_allocator: {other}"),
            });
        }
    };
    state.com.intern(alloc, Some(iid));
    mmu.write_initializer(ppv, &alloc.to_le_bytes())
        .map_err(|t| trap("HostIClassFactory::CreateInstance", t))?;
    Ok(S_OK)
}

/// `IClassFactory::LockServer(this, BOOL fLock)` — slot 4.  No-op
/// success in our single-threaded sandbox; the lock-count concept
/// only matters when CoFreeUnusedLibraries needs to know whether
/// the in-process server has any outstanding factories.
fn alloc_factory_lock_server(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// Mint a fresh HostIEnumMediaTypes that yields `amt_addr` once
/// (and `S_FALSE` thereafter).  Used by HostIPin::EnumMediaTypes.
fn mint_host_enum_media_types(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
    amt_addr: u32,
) -> Result<u32, Win32Error> {
    let obj = state.arena_alloc(48)?;
    let vtbl = obj.wrapping_add(16);
    let _ = mmu.write_initializer(obj, &vtbl.to_le_bytes());
    let _ = mmu.write_initializer(obj + 4, &1u32.to_le_bytes());
    let _ = mmu.write_initializer(obj + 8, &amt_addr.to_le_bytes());
    let _ = mmu.write_initializer(obj + 12, &0u32.to_le_bytes()); // cursor
    let methods: [&str; 7] = [
        "IEnumMediaTypes::QueryInterface",
        "IEnumMediaTypes::AddRef",
        "IEnumMediaTypes::Release",
        "IEnumMediaTypes::Next",
        "IEnumMediaTypes::Skip",
        "IEnumMediaTypes::Reset",
        "IEnumMediaTypes::Clone",
    ];
    for (i, name) in methods.iter().enumerate() {
        let thunk =
            registry
                .resolve(HOST_DLL, name)
                .ok_or_else(|| Win32Error::InvalidArgument {
                    stub: "mint_host_enum_media_types",
                    reason: format!("thunk {name:?} not registered"),
                })?;
        let _ = mmu.write_initializer(vtbl + (i as u32) * 4, &thunk.to_le_bytes());
    }
    Ok(obj)
}

// ---- Stub implementations ---------------------------------------------

/// `QueryInterface(this, REFIID, void**)`.
///
/// `[esp+4]` = `this`, `[esp+8]` = `REFIID*`, `[esp+12]` = `ppv*`.
///
/// We resolve `IID_IUnknown` and `IID_IFilterGraph` to `this`;
/// every other IID returns `E_NOINTERFACE` and zeros `*ppv`.
fn qi(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let piid = arg(cpu, mmu, 1)?;
    let ppv = arg(cpu, mmu, 2)?;
    if ppv == 0 {
        return Ok(crate::com::E_POINTER);
    }
    // Default *ppv = NULL.
    let _ = mmu.write_initializer(ppv, &0u32.to_le_bytes());
    if piid == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIFilterGraph::QI", t))?;
    if iid == IID_IUNKNOWN || iid == IID_IFILTERGRAPH {
        // Bump refcount.
        if let Ok(rc) = mmu.load32(this + 4) {
            let _ = mmu.write_initializer(this + 4, &rc.saturating_add(1).to_le_bytes());
        }
        // *ppv = this.
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        // Bookkeep on the host side too — same rules as a guest-
        // returned object.
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

/// `AddRef(this)`. Returns the new refcount.
fn addref(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let rc = mmu
        .load32(this + 4)
        .map_err(|t| trap("HostIFilterGraph::AddRef", t))?;
    let nrc = rc.saturating_add(1);
    mmu.write_initializer(this + 4, &nrc.to_le_bytes())
        .map_err(|t| trap("HostIFilterGraph::AddRef", t))?;
    Ok(nrc)
}

/// `Release(this)`. Returns the new refcount; floors at 1 (the
/// host object lives forever).
fn release(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let rc = mmu
        .load32(this + 4)
        .map_err(|t| trap("HostIFilterGraph::Release", t))?;
    let nrc = if rc > 1 { rc - 1 } else { 1 };
    mmu.write_initializer(this + 4, &nrc.to_le_bytes())
        .map_err(|t| trap("HostIFilterGraph::Release", t))?;
    Ok(nrc)
}

/// Generic `E_NOTIMPL` stub for an N-arg IFilterGraph method.
/// Each method has a distinct registration so the trace event
/// names the slot.
fn notimpl_1(_: &mut Cpu, _: &mut Mmu, _: &mut HostState, _: &Registry) -> Result<u32, Win32Error> {
    Ok(E_NOTIMPL)
}
fn notimpl_2(_: &mut Cpu, _: &mut Mmu, _: &mut HostState, _: &Registry) -> Result<u32, Win32Error> {
    Ok(E_NOTIMPL)
}
fn notimpl_3(_: &mut Cpu, _: &mut Mmu, _: &mut HostState, _: &Registry) -> Result<u32, Win32Error> {
    Ok(E_NOTIMPL)
}
fn notimpl_4(_: &mut Cpu, _: &mut Mmu, _: &mut HostState, _: &Registry) -> Result<u32, Win32Error> {
    Ok(E_NOTIMPL)
}

// ---- HostIPin stubs --------------------------------------------------

/// `IPin::QueryInterface(this, REFIID, void**)`.
/// Resolves IUnknown / IPin to `this`; everything else fails.
fn pin_qi(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let piid = arg(cpu, mmu, 1)?;
    let ppv = arg(cpu, mmu, 2)?;
    if ppv == 0 || piid == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let _ = mmu.write_initializer(ppv, &0u32.to_le_bytes());
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIPin::QI", t))?;
    if iid == IID_IUNKNOWN || iid == IID_IPIN {
        if let Ok(rc) = mmu.load32(this + 4) {
            let _ = mmu.write_initializer(this + 4, &rc.saturating_add(1).to_le_bytes());
        }
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

/// `IPin::QueryDirection(this, PIN_DIRECTION* pPinDir)`.  Always
/// reports `PIN_OUTPUT (1)` — that is the role the host pin plays
/// for the codec's downstream-input-pin handshake.
fn pin_query_direction(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let p_pin_dir = arg(cpu, mmu, 1)?;
    if p_pin_dir == 0 {
        return Ok(crate::com::E_POINTER);
    }
    // PIN_OUTPUT = 1.
    mmu.write_initializer(p_pin_dir, &1u32.to_le_bytes())
        .map_err(|t| trap("HostIPin::QueryDirection", t))?;
    Ok(S_OK)
}

/// `IPin::QueryAccept(this, AM_MEDIA_TYPE* pmt)` → `S_OK`.  We
/// pretend to accept any type the codec offers — this method is
/// only called when the codec is renegotiating, which the round-27
/// scope doesn't exercise.
fn pin_s_ok_2(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// 1-arg `S_OK` stub for `EndOfStream`/`BeginFlush`/`EndFlush`/
/// `Disconnect` — fire-and-forget control messages.
fn pin_s_ok_1(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// 5-arg `S_OK` stub for `IPin::NewSegment(this, tStart_lo,
/// tStart_hi, tStop_lo, tStop_hi, double rate-as-2-dwords)`.
/// Stdcall passes the LONGLONG `tStart` / `tStop` as adjacent
/// dword pairs; `double` rate is also two dwords on stdcall.
fn pin_s_ok_5(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// `IPin::ConnectionMediaType(this, AM_MEDIA_TYPE* pmt)` — copy
/// the host-pin's advertised AMT (72 bytes) into `pmt`.  Used by
/// the codec when it wants to inspect the upstream's connected
/// type.  Per MSDN, the caller is responsible for freeing the
/// `pbFormat` allocation; we leave `pbFormat` pointing at the
/// host arena (read-only as far as the codec is concerned).
fn pin_connection_media_type(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let pmt = arg(cpu, mmu, 1)?;
    if pmt == 0 {
        return Ok(crate::com::E_POINTER);
    }
    // Read the advertised AMT pointer from this+8.
    let amt_src = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIPin::ConnectionMediaType", t))?;
    if amt_src == 0 {
        return Ok(0x8004_0211 /* VFW_E_NOT_CONNECTED */);
    }
    // Bulk copy 72 bytes.
    for i in 0..72u32 {
        let b = mmu
            .load8(amt_src + i)
            .map_err(|t| trap("HostIPin::ConnectionMediaType", t))?;
        mmu.store8(pmt + i, b)
            .map_err(|t| trap("HostIPin::ConnectionMediaType", t))?;
    }
    Ok(S_OK)
}

/// `IPin::EnumMediaTypes(this, IEnumMediaTypes** ppEnum)`.  Mints
/// a fresh HostIEnumMediaTypes that yields the advertised AMT
/// once.
fn pin_enum_media_types(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let pp = arg(cpu, mmu, 1)?;
    if pp == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let amt_src = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIPin::EnumMediaTypes", t))?;
    let new_enum = mint_host_enum_media_types(state, mmu, registry, amt_src)?;
    mmu.write_initializer(pp, &new_enum.to_le_bytes())
        .map_err(|t| trap("HostIPin::EnumMediaTypes", t))?;
    Ok(S_OK)
}

/// Round 37 — `IPin::QueryPinInfo(this, PIN_INFO* pInfo)`.
///
/// Per `axextend.h` the `PIN_INFO` struct is 132 bytes:
///
/// ```c
/// typedef struct _PinInfo {
///     IBaseFilter* pFilter;          // offset 0  (4 bytes)
///     PIN_DIRECTION dir;             // offset 4  (4 bytes)
///     WCHAR achName[128];            // offset 8  (256 bytes)
/// } PIN_INFO;
/// ```
///
/// Total: 4 + 4 + 256 = 264 bytes (the WCHAR field is `MAX_PIN_NAME
/// = 128` `WCHAR`s = 256 bytes).
///
/// We populate:
///  * `pFilter` ← the synthesized `HostIBaseFilter` parent stamped
///    at `this + 16` by [`mint_host_output_pin_with_connection`].
///    Per MSDN the caller is responsible for `Release`-ing this
///    pointer; the host-side floor at refcount=1 keeps the object
///    alive past any over-release.
///  * `dir` ← `PIN_OUTPUT (1)` — host pin is the source feeding
///    the codec's input pin.
///  * `achName` ← UTF-16 LE `"HostOutPin"` followed by NUL +
///    zero padding to 256 bytes.
///
/// Returns `S_OK` on success, `E_POINTER` if `pInfo == 0`.
fn pin_query_pin_info(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let p_info = arg(cpu, mmu, 1)?;
    if p_info == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let parent_filter = mmu
        .load32(this + 16)
        .map_err(|t| trap("HostIPin::QueryPinInfo", t))?;
    // pFilter
    mmu.write_initializer(p_info, &parent_filter.to_le_bytes())
        .map_err(|t| trap("HostIPin::QueryPinInfo", t))?;
    // Per MSDN, QueryPinInfo's pFilter is AddRef'd before return.
    if parent_filter != 0 {
        if let Ok(rc) = mmu.load32(parent_filter + 4) {
            let _ = mmu.write_initializer(parent_filter + 4, &rc.saturating_add(1).to_le_bytes());
        }
        state
            .com
            .intern(parent_filter, Some(crate::com::IID_IBASEFILTER));
    }
    // PIN_DIRECTION = PIN_OUTPUT (1)
    mmu.write_initializer(p_info + 4, &1u32.to_le_bytes())
        .map_err(|t| trap("HostIPin::QueryPinInfo", t))?;
    // achName: WCHAR[128] = UTF-16 "HostOutPin\0" + zero pad.
    let name_utf16: [u16; 11] = [
        b'H' as u16,
        b'o' as u16,
        b's' as u16,
        b't' as u16,
        b'O' as u16,
        b'u' as u16,
        b't' as u16,
        b'P' as u16,
        b'i' as u16,
        b'n' as u16,
        0,
    ];
    for (i, w) in name_utf16.iter().enumerate() {
        mmu.write_initializer(p_info + 8 + (i as u32) * 2, &w.to_le_bytes())
            .map_err(|t| trap("HostIPin::QueryPinInfo", t))?;
    }
    // Zero-pad the rest of achName (offsets 8 + 22 .. 8 + 256).
    for off in (8 + 22)..(8 + 256u32) {
        mmu.store8(p_info + off, 0)
            .map_err(|t| trap("HostIPin::QueryPinInfo", t))?;
    }
    record_query_pin_info_call(state, this);
    Ok(S_OK)
}

/// Round 37 — `IPin::ConnectedTo(this, IPin** ppPin)`.
///
/// Per MSDN: returns the pin this one is connected to in the
/// filter graph.  When the host output pin has been wired against
/// the codec's input pin via [`mint_host_output_pin_with_connection`],
/// `connected_pin` (= codec input pin) is stamped at `this + 12`
/// and we return it AddRef'd through `*ppPin`.  When no connection
/// has been recorded, returns `VFW_E_NOT_CONNECTED = 0x80040209`
/// — the canonical HRESULT for "this pin has no peer".
fn pin_connected_to(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let pp = arg(cpu, mmu, 1)?;
    if pp == 0 {
        return Ok(crate::com::E_POINTER);
    }
    // Default *ppPin = NULL.
    let _ = mmu.write_initializer(pp, &0u32.to_le_bytes());
    let connected = mmu
        .load32(this + 12)
        .map_err(|t| trap("HostIPin::ConnectedTo", t))?;
    if connected == 0 {
        // VFW_E_NOT_CONNECTED — canonical "no peer pin" HRESULT
        // per MSDN (`vfwmsgs.h`, `0x80040209`).
        return Ok(0x8004_0209);
    }
    // Bump refcount per COM ABI rule that ConnectedTo returns an
    // AddRef'd pointer.  This is the *codec's* input pin, so we
    // are reaching into guest-managed memory; it's safe to bump
    // because the codec's IPin vtable's AddRef will be called by
    // the caller.  We pre-AddRef here because the codec sees the
    // ABI contract "pointer comes back AddRef'd"; the codec then
    // calls Release when done.
    if let Ok(rc) = mmu.load32(connected + 4) {
        let _ = mmu.write_initializer(connected + 4, &rc.saturating_add(1).to_le_bytes());
    }
    state.com.intern(connected, Some(crate::com::IID_IPIN));
    mmu.write_initializer(pp, &connected.to_le_bytes())
        .map_err(|t| trap("HostIPin::ConnectedTo", t))?;
    Ok(S_OK)
}

// ---- HostIEnumMediaTypes stubs ---------------------------------------

/// `QueryInterface` for the enumerator.  Same shape as the pin's
/// QI but no IPin acceptance — only IUnknown.
fn enum_qi(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let piid = arg(cpu, mmu, 1)?;
    let ppv = arg(cpu, mmu, 2)?;
    if ppv == 0 || piid == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let _ = mmu.write_initializer(ppv, &0u32.to_le_bytes());
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIEnum::QI", t))?;
    if iid == IID_IUNKNOWN {
        if let Ok(rc) = mmu.load32(this + 4) {
            let _ = mmu.write_initializer(this + 4, &rc.saturating_add(1).to_le_bytes());
        }
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

/// `IEnumMediaTypes::Next(this, ULONG cMediaTypes, AM_MEDIA_TYPE**
/// ppMediaTypes, ULONG* pcFetched)`.
///
/// Returns `S_OK` with `*pcFetched = 1` on the first call (yields
/// the AMT pointer the host pin was minted with), `S_FALSE` on
/// subsequent calls.  `cMediaTypes > 1` is treated as "give me up
/// to N" — we only ever yield 1.
fn enum_next(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let c = arg(cpu, mmu, 1)?;
    let pp = arg(cpu, mmu, 2)?;
    let p_fetched = arg(cpu, mmu, 3)?;
    if pp == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let cursor = mmu.load32(this + 12).unwrap_or(0);
    if c == 0 {
        if p_fetched != 0 {
            let _ = mmu.write_initializer(p_fetched, &0u32.to_le_bytes());
        }
        return Ok(S_OK);
    }
    if cursor == 0 {
        let amt = mmu
            .load32(this + 8)
            .map_err(|t| trap("HostIEnum::Next", t))?;
        mmu.write_initializer(pp, &amt.to_le_bytes())
            .map_err(|t| trap("HostIEnum::Next", t))?;
        if p_fetched != 0 {
            let _ = mmu.write_initializer(p_fetched, &1u32.to_le_bytes());
        }
        let _ = mmu.write_initializer(this + 12, &1u32.to_le_bytes());
        // S_OK only when we returned exactly the requested count;
        // when caller asks for >1 we return S_FALSE per the spec.
        if c == 1 {
            return Ok(S_OK);
        }
        return Ok(crate::com::S_FALSE);
    }
    // Exhausted.
    let _ = mmu.write_initializer(pp, &0u32.to_le_bytes());
    if p_fetched != 0 {
        let _ = mmu.write_initializer(p_fetched, &0u32.to_le_bytes());
    }
    Ok(crate::com::S_FALSE)
}

/// `IEnumMediaTypes::Skip(this, ULONG cMediaTypes)`.  Advances
/// the cursor.  We only have one item so any non-zero `cMediaTypes`
/// exhausts.
fn enum_skip(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let _ = mmu.write_initializer(this + 12, &1u32.to_le_bytes());
    Ok(S_OK)
}

/// `IEnumMediaTypes::Reset(this)`.  Cursor → 0.
fn enum_reset(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let _ = mmu.write_initializer(this + 12, &0u32.to_le_bytes());
    Ok(S_OK)
}

// ---- HostIMemAllocator stubs -----------------------------------------

/// `IMemAllocator::QueryInterface(this, REFIID, void**)`. Resolves
/// IUnknown / IMemAllocator to `this`; everything else fails.
fn alloc_qi(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let piid = arg(cpu, mmu, 1)?;
    let ppv = arg(cpu, mmu, 2)?;
    if ppv == 0 || piid == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let _ = mmu.write_initializer(ppv, &0u32.to_le_bytes());
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIMemAllocator::QI", t))?;
    if iid == IID_IUNKNOWN || iid == IID_IMEMALLOCATOR {
        if let Ok(rc) = mmu.load32(this + 4) {
            let _ = mmu.write_initializer(this + 4, &rc.saturating_add(1).to_le_bytes());
        }
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

/// `IMemAllocator::SetProperties(this, ALLOCATOR_PROPERTIES* pRequest,
/// ALLOCATOR_PROPERTIES* pActual)`.
///
/// `ALLOCATOR_PROPERTIES` layout (per `strmif.h`):
///
/// ```c
/// typedef struct _AllocatorProperties {
///   long cBuffers;
///   long cbBuffer;
///   long cbAlign;
///   long cbPrefix;
/// } ALLOCATOR_PROPERTIES;
/// ```
///
/// We accept whatever the codec asks for (copy `pRequest` into
/// `pActual` and return `S_OK`).  Round 33 — additionally captures
/// the four LONG fields into a host-side per-`HostState` log via
/// [`record_set_properties`], so tests / decoder paths can inspect
/// what shape `mpg4ds32` (or any codec) actually requested.
fn alloc_set_properties(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let p_request = arg(cpu, mmu, 1)?;
    let p_actual = arg(cpu, mmu, 2)?;
    if p_actual != 0 && p_request != 0 {
        for i in 0..16u32 {
            let b = mmu
                .load8(p_request + i)
                .map_err(|t| trap("HostIMemAllocator::SetProperties", t))?;
            mmu.store8(p_actual + i, b)
                .map_err(|t| trap("HostIMemAllocator::SetProperties", t))?;
        }
    }
    // Round 33 — capture the codec-requested allocator shape.
    if p_request != 0 {
        let c_buffers = mmu
            .load32(p_request)
            .map_err(|t| trap("HostIMemAllocator::SetProperties", t))?;
        let cb_buffer = mmu
            .load32(p_request + 4)
            .map_err(|t| trap("HostIMemAllocator::SetProperties", t))?;
        let cb_align = mmu
            .load32(p_request + 8)
            .map_err(|t| trap("HostIMemAllocator::SetProperties", t))?;
        let cb_prefix = mmu
            .load32(p_request + 12)
            .map_err(|t| trap("HostIMemAllocator::SetProperties", t))?;
        record_set_properties(
            state,
            AllocatorPropertiesCapture {
                this,
                c_buffers,
                cb_buffer,
                cb_align,
                cb_prefix,
            },
        );
    }
    Ok(S_OK)
}

/// One `IMemAllocator::SetProperties` capture — the four LONG
/// fields of `ALLOCATOR_PROPERTIES` plus the `this` pointer of the
/// allocator the codec called us through.  Round 33 logs every call
/// so the decoder path can introspect what `mpg4ds32` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocatorPropertiesCapture {
    /// Guest VA of the host allocator the codec called us through.
    pub this: u32,
    /// `cBuffers` — number of pool slots requested.
    pub c_buffers: u32,
    /// `cbBuffer` — bytes per sample.
    pub cb_buffer: u32,
    /// `cbAlign` — required byte alignment.
    pub cb_align: u32,
    /// `cbPrefix` — pre-payload header bytes the codec wants to
    /// reserve in front of every sample's data region.
    pub cb_prefix: u32,
}

/// Per-`HostState` capture log of every `SetProperties` call the
/// codec drove against any host allocator.  Lives behind a static
/// mutex keyed by `&HostState as usize` (same pattern the round-31
/// `host_iface_r31` queue uses).
fn set_properties_log(
) -> &'static std::sync::Mutex<std::collections::HashMap<usize, Vec<AllocatorPropertiesCapture>>> {
    static L: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, Vec<AllocatorPropertiesCapture>>>,
    > = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn host_key(state: &HostState) -> usize {
    state as *const HostState as usize
}

fn record_set_properties(state: &HostState, cap: AllocatorPropertiesCapture) {
    if let Ok(mut l) = set_properties_log().lock() {
        l.entry(host_key(state)).or_default().push(cap);
    }
}

/// Return the most recent `SetProperties` capture observed for
/// `state`, or `None` if no codec has called `SetProperties` yet.
pub fn last_set_properties(state: &HostState) -> Option<AllocatorPropertiesCapture> {
    set_properties_log()
        .lock()
        .ok()
        .and_then(|l| l.get(&host_key(state)).and_then(|v| v.last().copied()))
}

/// Return every `SetProperties` capture observed for `state`, in
/// arrival order.  Empty `Vec` if no codec has called yet.
pub fn all_set_properties(state: &HostState) -> Vec<AllocatorPropertiesCapture> {
    set_properties_log()
        .lock()
        .ok()
        .map(|l| l.get(&host_key(state)).cloned().unwrap_or_default())
        .unwrap_or_default()
}

/// Drop every captured `SetProperties` for `state`.  Tests call
/// this to reset the per-sandbox state between scenarios.
pub fn clear_set_properties_log(state: &HostState) {
    if let Ok(mut l) = set_properties_log().lock() {
        l.remove(&host_key(state));
    }
}

// ---- Round 37 — IPin::QueryPinInfo / IBaseFilter::QueryFilterInfo
// call counters.  Tests / decoder paths use these to confirm the
// codec actually drives the introspection methods r37 wired up.

fn query_pin_info_log() -> &'static std::sync::Mutex<std::collections::HashMap<usize, Vec<u32>>> {
    static L: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<usize, Vec<u32>>>> =
        std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn query_filter_info_log() -> &'static std::sync::Mutex<std::collections::HashMap<usize, Vec<u32>>>
{
    static L: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<usize, Vec<u32>>>> =
        std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn record_query_pin_info_call(state: &HostState, this: u32) {
    if let Ok(mut l) = query_pin_info_log().lock() {
        l.entry(host_key(state)).or_default().push(this);
    }
}

pub(crate) fn record_query_filter_info_call(state: &HostState, this: u32) {
    if let Ok(mut l) = query_filter_info_log().lock() {
        l.entry(host_key(state)).or_default().push(this);
    }
}

/// Round 37 — number of `IPin::QueryPinInfo` calls the codec has
/// driven against any host pin during this sandbox's lifetime.
pub fn query_pin_info_call_count(state: &HostState) -> usize {
    query_pin_info_log()
        .lock()
        .ok()
        .map(|l| l.get(&host_key(state)).map(|v| v.len()).unwrap_or(0))
        .unwrap_or(0)
}

/// Round 37 — number of `IBaseFilter::QueryFilterInfo` calls the
/// codec has driven against any host base filter during this
/// sandbox's lifetime.
pub fn query_filter_info_call_count(state: &HostState) -> usize {
    query_filter_info_log()
        .lock()
        .ok()
        .map(|l| l.get(&host_key(state)).map(|v| v.len()).unwrap_or(0))
        .unwrap_or(0)
}

/// Round 37 — `this` pointers of every `IPin::QueryPinInfo` call
/// observed for `state`, in arrival order.
pub fn query_pin_info_calls(state: &HostState) -> Vec<u32> {
    query_pin_info_log()
        .lock()
        .ok()
        .map(|l| l.get(&host_key(state)).cloned().unwrap_or_default())
        .unwrap_or_default()
}

/// Round 37 — `this` pointers of every `IBaseFilter::QueryFilterInfo`
/// call observed for `state`, in arrival order.
pub fn query_filter_info_calls(state: &HostState) -> Vec<u32> {
    query_filter_info_log()
        .lock()
        .ok()
        .map(|l| l.get(&host_key(state)).cloned().unwrap_or_default())
        .unwrap_or_default()
}

/// Round 37 — drop every captured introspection call (both
/// QueryPinInfo and QueryFilterInfo) for `state`.
pub fn clear_query_info_log(state: &HostState) {
    if let Ok(mut l) = query_pin_info_log().lock() {
        l.remove(&host_key(state));
    }
    if let Ok(mut l) = query_filter_info_log().lock() {
        l.remove(&host_key(state));
    }
}

/// `IMemAllocator::GetProperties(this, ALLOCATOR_PROPERTIES* pProps)`.
/// Reports the pool's actual shape: cBuffers = pool length walked
/// through `obj+8`, cbBuffer = first sample's data_capacity,
/// cbAlign = 1, cbPrefix = 0.
fn alloc_get_properties(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let p_props = arg(cpu, mmu, 1)?;
    if p_props == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let mut count: u32 = 0;
    let mut cur = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIMemAllocator::GetProperties", t))?;
    let mut buf_size: u32 = 0;
    while cur != 0 && count < 1024 {
        if count == 0 {
            buf_size = mmu
                .load32(cur + 12)
                .map_err(|t| trap("HostIMemAllocator::GetProperties", t))?;
        }
        count += 1;
        cur = mmu
            .load32(cur + 32)
            .map_err(|t| trap("HostIMemAllocator::GetProperties", t))?;
    }
    mmu.write_initializer(p_props, &count.to_le_bytes())
        .map_err(|t| trap("HostIMemAllocator::GetProperties", t))?;
    mmu.write_initializer(p_props + 4, &buf_size.to_le_bytes())
        .map_err(|t| trap("HostIMemAllocator::GetProperties", t))?;
    mmu.write_initializer(p_props + 8, &1u32.to_le_bytes())
        .map_err(|t| trap("HostIMemAllocator::GetProperties", t))?;
    mmu.write_initializer(p_props + 12, &0u32.to_le_bytes())
        .map_err(|t| trap("HostIMemAllocator::GetProperties", t))?;
    Ok(S_OK)
}

/// `IMemAllocator::Commit(this)` — round 32 transitions the
/// allocator from *decommitted* to *committed*. Sets the flag at
/// `obj+12` to 1; subsequent `GetBuffer` calls observe live state.
/// Idempotent (re-committing an already-committed allocator
/// returns S_OK without side effects). Returns S_OK.
///
/// Per MSDN
/// <https://learn.microsoft.com/en-us/windows/win32/api/strmif/nf-strmif-imemallocator-commit>
/// — Commit() is the canonical way for an upstream filter to
/// "lock in" the pool shape that `SetProperties()` requested,
/// after which downstream filters' `Receive()` calls may legally
/// observe samples drawn from the pool.
fn alloc_commit(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    mmu.write_initializer(this + 12, &1u32.to_le_bytes())
        .map_err(|t| trap("HostIMemAllocator::Commit", t))?;
    Ok(S_OK)
}

/// `IMemAllocator::Decommit(this)` — round 32 transitions the
/// allocator back to *decommitted*. Sets the flag at `obj+12` to
/// 0; subsequent `GetBuffer` calls return VFW_E_NOT_COMMITTED
/// until the next `Commit()`.
///
/// Per MSDN
/// <https://learn.microsoft.com/en-us/windows/win32/api/strmif/nf-strmif-imemallocator-decommit>
/// — Decommit() unwinds the Commit(); the host pool memory is
/// permanently mapped (no actual deallocation), but the state
/// flag enforces the contract.
fn alloc_decommit(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    mmu.write_initializer(this + 12, &0u32.to_le_bytes())
        .map_err(|t| trap("HostIMemAllocator::Decommit", t))?;
    Ok(S_OK)
}

/// `IMemAllocator::GetBuffer(this, IMediaSample** ppBuffer,
/// REFERENCE_TIME* pStartTime, REFERENCE_TIME* pEndTime,
/// DWORD dwFlags)`.
///
/// Walk the sample pool linked list at `obj+8 → sample+32 → …`
/// looking for a sample with `in_use == 0` (offset +36); mark it
/// in-use, store its address into `*ppBuffer`, return S_OK. If
/// the pool is exhausted return `VFW_E_TIMEOUT = 0x80040211`.
///
/// Round 32 — refuses to return a buffer when the allocator is
/// in the *decommitted* state (`obj+12 == 0`); returns
/// `VFW_E_NOT_COMMITTED = 0x80040209`. Codecs that QI for
/// IMemAllocator and check Commit state before pushing samples
/// downstream depend on this check.
fn alloc_get_buffer(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let pp = arg(cpu, mmu, 1)?;
    let _p_start = arg(cpu, mmu, 2)?;
    let _p_end = arg(cpu, mmu, 3)?;
    // Round 41 — `dwFlags` (AM_GBF_NOTASYNCPOINT /
    // AM_GBF_PREVFRAMESKIPPED / AM_GBF_NOWAIT bits per `strmif.h`).
    // Read so the dispatcher's per-arg trace surfaces all five
    // pushed dwords; the host pool ignores the bits.
    let _dw_flags = arg(cpu, mmu, 4)?;
    if pp == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let _ = mmu.write_initializer(pp, &0u32.to_le_bytes());
    // Round 32 — gate on Commit state.
    let committed = mmu
        .load32(this + 12)
        .map_err(|t| trap("HostIMemAllocator::GetBuffer", t))?;
    if committed == 0 {
        return Ok(0x8004_0209 /* VFW_E_NOT_COMMITTED */);
    }
    let mut cur = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIMemAllocator::GetBuffer", t))?;
    let mut steps = 0u32;
    while cur != 0 && steps < 1024 {
        // Round 43 — sanity-check the pool pointer before reading
        // through it.  Without this, a corrupted `next_pool_link`
        // (e.g. a codec that overwrote a sample's `+32` slot, or a
        // junk head we never wrote) would surface as a memory-fault
        // trap inside our stub rather than a clean
        // `VFW_E_TIMEOUT`.  Round 42 saw exactly this at
        // `cur+36 = 0xffff0223` (so `cur ≈ 0xffff_01ff`) for the
        // codec's output allocator on the second `Receive` call;
        // the trap masked the underlying issue and left no
        // recovery path.
        //
        // The sanity criterion: `cur` plus the sample header
        // (`+36`) plus the next-link slot (`+32`) MUST be readable.
        // If either load fails, treat the pool as exhausted and
        // return `VFW_E_TIMEOUT` — letting the codec react with
        // the standard "no buffer available" backoff instead of
        // crashing the entire pipeline.
        let in_use = match mmu.load32(cur + 36) {
            Ok(v) => v,
            Err(_) => {
                // Corrupted pool pointer — treat as exhaustion.
                return Ok(0x8004_0211 /* VFW_E_TIMEOUT */);
            }
        };
        if in_use == 0 {
            mmu.write_initializer(cur + 36, &1u32.to_le_bytes())
                .map_err(|t| trap("HostIMemAllocator::GetBuffer", t))?;
            // Round 43 — `IMemAllocator::GetBuffer` returns a
            // sample with refcount = 1 per the canonical
            // `CMediaSample::GetBuffer` implementation in the DShow
            // base classes.  The previous behaviour (bump rc by 1
            // on every issue) interacted badly with the round-43
            // recycle-on-Release path: the codec's standard one
            // AddRef + one Release pattern would only get the rc
            // back down to 1, never 0, so the sample never
            // recycled.  We now FORCE the rc to 1 so the cycle
            // closes deterministically.
            mmu.write_initializer(cur + 4, &1u32.to_le_bytes())
                .map_err(|t| trap("HostIMemAllocator::GetBuffer", t))?;
            mmu.write_initializer(pp, &cur.to_le_bytes())
                .map_err(|t| trap("HostIMemAllocator::GetBuffer", t))?;
            return Ok(S_OK);
        }
        cur = match mmu.load32(cur + 32) {
            Ok(v) => v,
            Err(_) => {
                // Corrupted next-link — same recovery as above.
                return Ok(0x8004_0211 /* VFW_E_TIMEOUT */);
            }
        };
        steps += 1;
    }
    // Pool exhausted.
    Ok(0x8004_0211 /* VFW_E_TIMEOUT */)
}

/// `IMemAllocator::ReleaseBuffer(this, IMediaSample* pBuffer)` —
/// return the sample to the pool. Clears `in_use` and decrements
/// refcount.
fn alloc_release_buffer(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let sample = arg(cpu, mmu, 1)?;
    if sample == 0 {
        return Ok(crate::com::E_POINTER);
    }
    mmu.write_initializer(sample + 36, &0u32.to_le_bytes())
        .map_err(|t| trap("HostIMemAllocator::ReleaseBuffer", t))?;
    if let Ok(rc) = mmu.load32(sample + 4) {
        let nrc = if rc > 1 { rc - 1 } else { 1 };
        let _ = mmu.write_initializer(sample + 4, &nrc.to_le_bytes());
    }
    Ok(S_OK)
}

// ---- HostIMediaSample stubs ------------------------------------------

/// `IMediaSample::Release(this)` — round 43 dedicated implementation
/// that closes the sample-release cycle gap surfaced on the
/// `gop-30-352x288` fixture.
///
/// Per Microsoft's reference `CMediaSample` implementation in
/// the DirectShow base classes (header references in `strmif.h` /
/// `wxutil.h`), the canonical destructor flow is:
///
/// ```c
/// ULONG CMediaSample::Release() {
///     LONG cRef = InterlockedDecrement(&m_cRef);
///     if (cRef == 0 && m_pAllocator)
///         m_pAllocator->ReleaseBuffer(this);
///     return cRef;
/// }
/// ```
///
/// We replicate that contract: when this `Release` call would have
/// driven the refcount through `1 → 0`, clear the sample's `in_use`
/// flag at `+36` (the same field [`alloc_release_buffer`] clears)
/// so the next `GetBuffer` walk on the owning allocator finds the
/// slot free.  The sample object itself stays alive in arena
/// memory; what changes is the pool-availability bit.
///
/// Floors the returned refcount at 0 (instead of the round-30
/// `release` thunk's floor at 1) so the codec's own
/// `if (cRef == 0)` checks fire correctly.
fn sample_release(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let rc = mmu
        .load32(this + 4)
        .map_err(|t| trap("HostIMediaSample::Release", t))?;
    let nrc = rc.saturating_sub(1);
    mmu.write_initializer(this + 4, &nrc.to_le_bytes())
        .map_err(|t| trap("HostIMediaSample::Release", t))?;
    if nrc == 0 {
        // Refcount transitioned through 1 → 0.  Recycle the
        // sample to its owning allocator's pool by clearing the
        // `in_use` flag at `+36`.  The sample's object memory is
        // not freed (the arena allocator never frees), so the
        // next `GetBuffer` walk on this allocator can re-issue
        // it directly.
        let _ = mmu.write_initializer(this + 36, &0u32.to_le_bytes());
    }
    Ok(nrc)
}

/// `IMediaSample::QueryInterface(this, REFIID, void**)`. Resolves
/// IUnknown / IMediaSample / IMediaSample2 to `this`; everything
/// else fails.
///
/// Round 39 — accept `IID_IMEDIASAMPLE2` so codecs that QI for
/// the extended interface (notably `mpg4ds32` from inside its
/// `CTransformFilter::Transform` at RVA `0x4064f3`) get a usable
/// pointer.  Slots 19/20 of our host vtable implement
/// `GetProperties` / `SetProperties` per the public
/// `AM_SAMPLE2_PROPERTIES` ABI documented in `strmif.h`.
fn sample_qi(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let piid = arg(cpu, mmu, 1)?;
    let ppv = arg(cpu, mmu, 2)?;
    if ppv == 0 || piid == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let _ = mmu.write_initializer(ppv, &0u32.to_le_bytes());
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIMediaSample::QI", t))?;
    if iid == IID_IUNKNOWN || iid == IID_IMEDIASAMPLE || iid == IID_IMEDIASAMPLE2 {
        if let Ok(rc) = mmu.load32(this + 4) {
            let _ = mmu.write_initializer(this + 4, &rc.saturating_add(1).to_le_bytes());
        }
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

/// `IMediaSample::GetPointer(this, BYTE** ppBuffer)`. Stores the
/// underlying data region's guest VA into `*ppBuffer`.
fn sample_get_pointer(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let pp = arg(cpu, mmu, 1)?;
    if pp == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let data = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIMediaSample::GetPointer", t))?;
    mmu.write_initializer(pp, &data.to_le_bytes())
        .map_err(|t| trap("HostIMediaSample::GetPointer", t))?;
    Ok(S_OK)
}

/// `IMediaSample::GetSize(this)` — returns the data region's
/// capacity (LONG, treated as the dword in EAX). Real DirectShow
/// returns LONG; HRESULT-style callers also treat the dword as
/// the size in bytes.
fn sample_get_size(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let cap = mmu
        .load32(this + 12)
        .map_err(|t| trap("HostIMediaSample::GetSize", t))?;
    Ok(cap)
}

/// `IMediaSample::GetTime(this, REFERENCE_TIME* pStart,
/// REFERENCE_TIME* pEnd)`. Returns `VFW_S_NO_STOP_TIME = 0x00040007`
/// (success but no stop time available) and writes 0 into each
/// timestamp slot. Codecs use this for A/V sync; round 30 doesn't
/// drive real timing, so all-zeros is acceptable.
fn sample_get_time(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let p_start = arg(cpu, mmu, 1)?;
    let p_end = arg(cpu, mmu, 2)?;
    if p_start != 0 {
        let _ = mmu.write_initializer(p_start, &[0u8; 8]);
    }
    if p_end != 0 {
        let _ = mmu.write_initializer(p_end, &[0u8; 8]);
    }
    Ok(0x0004_0007 /* VFW_S_NO_STOP_TIME */)
}

/// `IMediaSample::SetTime(this, REFERENCE_TIME* pStart,
/// REFERENCE_TIME* pEnd)`. No-op success.
fn sample_set_time(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// `IMediaSample::IsSyncPoint(this)`. Returns `S_OK` when the
/// sync_point flag at `obj+20` is non-zero, `S_FALSE` otherwise.
fn sample_is_sync_point(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let flag = mmu
        .load32(this + 20)
        .map_err(|t| trap("HostIMediaSample::IsSyncPoint", t))?;
    if flag != 0 {
        Ok(S_OK)
    } else {
        Ok(crate::com::S_FALSE)
    }
}

/// `IMediaSample::SetSyncPoint(this, BOOL bIsSyncPoint)`. Updates
/// the flag at `obj+20`. Returns `S_OK`.
fn sample_set_sync_point(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let v = arg(cpu, mmu, 1)?;
    mmu.write_initializer(this + 20, &(if v != 0 { 1u32 } else { 0 }).to_le_bytes())
        .map_err(|t| trap("HostIMediaSample::SetSyncPoint", t))?;
    Ok(S_OK)
}

/// `IMediaSample::GetActualDataLength(this)` — returns the dword
/// at `obj+16`.
fn sample_get_actual_data_length(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let len = mmu
        .load32(this + 16)
        .map_err(|t| trap("HostIMediaSample::GetActualDataLength", t))?;
    Ok(len)
}

/// `IMediaSample::SetActualDataLength(this, LONG cbLength)`. Writes
/// `cbLength` to `obj+16` (clamped to capacity), returns S_OK.
fn sample_set_actual_data_length(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let cb = arg(cpu, mmu, 1)?;
    let cap = mmu
        .load32(this + 12)
        .map_err(|t| trap("HostIMediaSample::SetActualDataLength", t))?;
    let n = cb.min(cap);
    mmu.write_initializer(this + 16, &n.to_le_bytes())
        .map_err(|t| trap("HostIMediaSample::SetActualDataLength", t))?;
    Ok(S_OK)
}

/// `IMediaSample::GetMediaType(this, AM_MEDIA_TYPE** ppMediaType)`.
///
/// If the sample has no per-sample media type (`obj+24 == 0`),
/// returns `S_FALSE` and writes NULL — meaning "use the upstream's
/// connection media type". Otherwise writes the cached AMT
/// pointer and returns `S_OK`.
fn sample_get_media_type(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let pp = arg(cpu, mmu, 1)?;
    if pp == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let mt = mmu
        .load32(this + 24)
        .map_err(|t| trap("HostIMediaSample::GetMediaType", t))?;
    mmu.write_initializer(pp, &mt.to_le_bytes())
        .map_err(|t| trap("HostIMediaSample::GetMediaType", t))?;
    if mt == 0 {
        Ok(crate::com::S_FALSE)
    } else {
        Ok(S_OK)
    }
}

/// `IMediaSample::GetMediaTime(this, LONGLONG* pStart, LONGLONG*
/// pEnd)`. Returns `VFW_E_MEDIA_TIME_NOT_SET = 0x80040251`.
fn sample_get_media_time(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let _p_start = arg(cpu, mmu, 1)?;
    let _p_end = arg(cpu, mmu, 2)?;
    Ok(0x8004_0251 /* VFW_E_MEDIA_TIME_NOT_SET */)
}

/// 1-arg sample stub returning `S_FALSE` — used by IsPreroll /
/// IsDiscontinuity (we never advertise either).
fn sample_returns_s_false_1(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(crate::com::S_FALSE)
}

/// 2-arg sample stub returning `S_OK` — used by SetPreroll /
/// SetDiscontinuity / SetMediaType. We accept whatever the codec
/// asks (round 30 doesn't introspect the payload).
fn sample_returns_s_ok_2(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// `IMediaSample::SetMediaTime(this, LONGLONG* pStart,
/// LONGLONG* pEnd)`.
///
/// Round 39 — last method of `IMediaSample` (slot 18); accepts
/// whatever the codec asks but ignores it (we have no consumer
/// for media-time on host samples).  Also addresses round-38 gap
/// where slot 18 had been unset on the host vtable, leaving the
/// codec's cleanup-branch `[ecx+0x48]` call dispatching to NULL
/// when it followed the `IMediaSample2`-QI-failure path.
fn sample_set_media_time(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}

/// `IMediaSample2::GetProperties(this, DWORD cb, BYTE* pProps)` —
/// slot 19.
///
/// Fills the first `cb` bytes of `pProps` with an
/// `AM_SAMPLE2_PROPERTIES` view of `this`.  Layout per the public
/// `strmif.h`:
///
/// ```c
/// typedef struct {
///   DWORD             cbData;                  // 0x00
///   DWORD             dwTypeSpecificFlags;     // 0x04
///   DWORD             dwSampleFlags;           // 0x08
///   LONG              lActual;                 // 0x0c
///   REFERENCE_TIME    tStart;                  // 0x10
///   REFERENCE_TIME    tStop;                   // 0x18
///   DWORD             dwStreamId;              // 0x20
///   AM_MEDIA_TYPE *   pMediaType;              // 0x24
///   BYTE *            pbBuffer;                // 0x28
///   LONG              cbBuffer;                // 0x2c
/// } AM_SAMPLE2_PROPERTIES;                     // sizeof = 0x30
/// ```
///
/// Round 39 — `mpg4ds32`'s `CTransformFilter::Transform` calls
/// this with `cb = 0x10` (only the first 4 fields).  We therefore
/// always populate at least those four fields and write up to
/// `min(cb, 0x30)` bytes total.
fn sample_get_properties(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let cb = arg(cpu, mmu, 1)?;
    let p_props = arg(cpu, mmu, 2)?;
    if p_props == 0 {
        return Ok(crate::com::E_POINTER);
    }
    // Pull host-sample fields.
    let actual_len = mmu
        .load32(this + 16)
        .map_err(|t| trap("HostIMediaSample2::GetProperties", t))?;
    let sync_flag = mmu
        .load32(this + 20)
        .map_err(|t| trap("HostIMediaSample2::GetProperties", t))?;
    let media_type_ptr = mmu
        .load32(this + 24)
        .map_err(|t| trap("HostIMediaSample2::GetProperties", t))?;
    let data_region = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIMediaSample2::GetProperties", t))?;
    let cap = mmu
        .load32(this + 12)
        .map_err(|t| trap("HostIMediaSample2::GetProperties", t))?;
    // sync_flag → AM_SAMPLE_SPLICEPOINT (0x10) per strmif.h.
    let sample_flags = if sync_flag != 0 { 0x10u32 } else { 0u32 };
    // Build the 0x30-byte struct in a stack buffer.
    let mut props = [0u8; 0x30];
    let mut put = |off: usize, v: u32| {
        props[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put(0x00, 0x30); // cbData
    put(0x04, 0); // dwTypeSpecificFlags
    put(0x08, sample_flags); // dwSampleFlags
    put(0x0c, actual_len); // lActual
                           // tStart / tStop kept zero — we don't track timestamps on
                           // the host-sample side.
    put(0x20, 0); // dwStreamId
    put(0x24, media_type_ptr); // pMediaType
    put(0x28, data_region); // pbBuffer
    put(0x2c, cap); // cbBuffer
    let n = (cb as usize).min(0x30);
    for (i, &b) in props.iter().take(n).enumerate() {
        mmu.store8(p_props + (i as u32), b)
            .map_err(|t| trap("HostIMediaSample2::GetProperties", t))?;
    }
    Ok(S_OK)
}

/// `IMediaSample2::SetProperties(this, DWORD cb, const BYTE*
/// pProps)` — slot 20.
///
/// Round 39 — accept the round-trip from `GetProperties`.
/// Mirrors `lActual` (`pProps[+0x0c]`) into the host sample's
/// actual-data-length field at `obj+16`, and `dwSampleFlags`
/// (`pProps[+0x08]`)'s `AM_SAMPLE_SPLICEPOINT` bit (0x10) into
/// the sync-flag at `obj+20`.  Other fields ignored per the
/// minimal `mpg4ds32` write surface (`cb` = 0x20 in the codec's
/// success-branch).
fn sample_set_properties(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let cb = arg(cpu, mmu, 1)?;
    let p_props = arg(cpu, mmu, 2)?;
    if p_props == 0 {
        return Ok(crate::com::E_POINTER);
    }
    if cb >= 0x10 {
        let flags = mmu
            .load32(p_props + 0x08)
            .map_err(|t| trap("HostIMediaSample2::SetProperties", t))?;
        let actual = mmu
            .load32(p_props + 0x0c)
            .map_err(|t| trap("HostIMediaSample2::SetProperties", t))?;
        let cap = mmu
            .load32(this + 12)
            .map_err(|t| trap("HostIMediaSample2::SetProperties", t))?;
        let n = actual.min(cap);
        let _ = mmu.write_initializer(this + 16, &n.to_le_bytes());
        let sync = u32::from(flags & 0x10 != 0);
        let _ = mmu.write_initializer(this + 20, &sync.to_le_bytes());
    }
    Ok(S_OK)
}

fn arg(cpu: &Cpu, mmu: &Mmu, n: u32) -> Result<u32, Win32Error> {
    crate::win32::arg_dword(cpu, mmu, n).map_err(|t| trap("HostIFilterGraph::arg", t))
}

fn trap(stub: &'static str, t: crate::emulator::Trap) -> Win32Error {
    Win32Error::InvalidArgument {
        stub,
        reason: format!("{t}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::com::call::call_method;
    use crate::Sandbox;

    #[test]
    fn host_filter_graph_layout_has_eleven_method_slots() {
        let mut sb = Sandbox::new();
        let g = mint_host_filter_graph(&mut sb.host, &mut sb.mmu, &sb.registry).unwrap();
        // [g] = vtbl_ptr; vtbl_ptr = g + 8 by construction.
        let vtbl = sb.mmu.load32(g).unwrap();
        assert_eq!(vtbl, g + 8);
        // 11 slots populated with non-zero thunk addresses (the
        // IUnknown trio + 8 IFilterGraph methods).
        for i in 0..11u32 {
            let m = sb.mmu.load32(vtbl + i * 4).unwrap();
            assert!(m != 0, "vtbl slot {i} unmapped");
            assert!(
                sb.registry.is_thunk(m),
                "vtbl slot {i} = {m:#010x} not a registered thunk"
            );
        }
    }

    #[test]
    fn host_filter_graph_addref_release_round_trip() {
        let mut sb = Sandbox::new();
        let g = mint_host_filter_graph(&mut sb.host, &mut sb.mmu, &sb.registry).unwrap();
        // Initial refcount = 1.
        assert_eq!(sb.mmu.load32(g + 4).unwrap(), 1);
        // AddRef → 2.
        let r = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            g,
            crate::com::SLOT_ADD_REF,
            &[],
        )
        .unwrap();
        assert_eq!(r, 2);
        assert_eq!(sb.mmu.load32(g + 4).unwrap(), 2);
        // Release → 1.
        let r = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            g,
            crate::com::SLOT_RELEASE,
            &[],
        )
        .unwrap();
        assert_eq!(r, 1);
        // Release floors at 1.
        let r = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            g,
            crate::com::SLOT_RELEASE,
            &[],
        )
        .unwrap();
        assert_eq!(r, 1);
    }

    #[test]
    fn host_filter_graph_query_interface_for_iunknown_returns_self() {
        let mut sb = Sandbox::new();
        let g = mint_host_filter_graph(&mut sb.host, &mut sb.mmu, &sb.registry).unwrap();
        let scratch = sb.host.arena_alloc(20).unwrap();
        IID_IUNKNOWN.stage(&mut sb.mmu, scratch).unwrap();
        sb.mmu
            .write_initializer(scratch + 16, &0u32.to_le_bytes())
            .unwrap();
        let r = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            g,
            crate::com::SLOT_QUERY_INTERFACE,
            &[scratch, scratch + 16],
        )
        .unwrap();
        assert_eq!(r, S_OK);
        assert_eq!(sb.mmu.load32(scratch + 16).unwrap(), g);
    }

    #[test]
    fn host_filter_graph_query_interface_unknown_iid_rejected() {
        let mut sb = Sandbox::new();
        let g = mint_host_filter_graph(&mut sb.host, &mut sb.mmu, &sb.registry).unwrap();
        let scratch = sb.host.arena_alloc(20).unwrap();
        // IID_IBaseFilter — not satisfied by the host filter graph.
        crate::com::IID_IBASEFILTER
            .stage(&mut sb.mmu, scratch)
            .unwrap();
        sb.mmu
            .write_initializer(scratch + 16, &0u32.to_le_bytes())
            .unwrap();
        let r = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            g,
            crate::com::SLOT_QUERY_INTERFACE,
            &[scratch, scratch + 16],
        )
        .unwrap();
        assert_eq!(r, E_NOINTERFACE);
        assert_eq!(sb.mmu.load32(scratch + 16).unwrap(), 0);
    }

    #[test]
    fn host_filter_graph_addfilter_returns_e_notimpl() {
        let mut sb = Sandbox::new();
        let g = mint_host_filter_graph(&mut sb.host, &mut sb.mmu, &sb.registry).unwrap();
        // AddFilter(this, IBaseFilter*, LPCWSTR) — slot 3.
        let r = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            g,
            3,
            &[0xDEAD_BEEF, 0xCAFE_F00D],
        )
        .unwrap();
        assert_eq!(r, E_NOTIMPL);
    }
}
