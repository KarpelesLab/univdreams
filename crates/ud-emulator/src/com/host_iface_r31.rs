//! Round 31 — downstream HostIBaseFilter / HostIPin (input role) /
//! HostIMemInputPin / HostIEnumPins stubs + AMT enumeration walker.
//!
//! Built as a separate module so the round-30 `host_iface` is
//! untouched.  The `register` function below registers all the
//! new thunks into [`crate::win32::Registry`]; sandbox
//! initialisation calls it after the round-30 register.
//!
//! Reference material:
//!
//! * MSDN — IPin / IMemInputPin / IBaseFilter / IEnumPins /
//!   AM_MEDIA_TYPE.
//! * Windows SDK headers `axextend.h` / `strmif.h` / `amvideo.h`
//!   (header ABI declarations only).

use super::{
    Guid, IID_IBASEFILTER, IID_IMEDIAFILTER, IID_IMEMINPUTPIN, IID_IPERSIST, IID_IPIN, IID_IUNKNOWN,
};
use crate::emulator::{Cpu, Mmu};
use crate::win32::{HostState, Registry, StubFn, Win32Error};

const S_OK: u32 = 0x0000_0000;
const E_NOINTERFACE: u32 = 0x8000_4002;
const E_NOTIMPL: u32 = 0x8000_4001;
const HOST_DLL: &str = "host-com-r31.host";

/// One AMT captured from the codec's `IPin::EnumMediaTypes` walk.
#[derive(Debug, Clone)]
pub struct CapturedAmt {
    pub amt_addr: u32,
    pub majortype: Guid,
    pub subtype: Guid,
    pub b_fixed_size_samples: u32,
    pub l_sample_size: u32,
    pub formattype: Guid,
    pub cb_format: u32,
    pub pb_format: u32,
}

impl CapturedAmt {
    /// Read the 4-byte FourCC out of the subtype's Data1 field.
    pub fn fourcc(&self) -> [u8; 4] {
        self.subtype.data1.to_le_bytes()
    }
}

/// One decoded sample captured by `HostIMemInputPin::Receive`.
#[derive(Debug, Clone)]
pub struct ReceivedSample {
    pub data: Vec<u8>,
    pub sync_point: bool,
    pub start_time: Option<i64>,
    pub media_type_ptr: u32,
}

/// Singleton host-side queue keyed by `&HostState as usize`.  We
/// store received samples here rather than in `HostState` because
/// the round-30 `HostState` ABI is tracked-file and we cannot
/// extend it from this round-31 module.  Mutex is uncontended in
/// the common single-sandbox case.
fn queues() -> &'static std::sync::Mutex<
    std::collections::HashMap<usize, std::collections::VecDeque<ReceivedSample>>,
> {
    static Q: std::sync::OnceLock<
        std::sync::Mutex<
            std::collections::HashMap<usize, std::collections::VecDeque<ReceivedSample>>,
        >,
    > = std::sync::OnceLock::new();
    Q.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn host_key(state: &HostState) -> usize {
    state as *const HostState as usize
}

fn push_sample(state: &HostState, s: ReceivedSample) {
    if let Ok(mut q) = queues().lock() {
        q.entry(host_key(state)).or_default().push_back(s);
    }
}

/// Pop the oldest sample (FIFO) from the per-state queue.
pub fn pop_sample(state: &HostState) -> Option<ReceivedSample> {
    queues()
        .lock()
        .ok()
        .and_then(|mut q| q.get_mut(&host_key(state)).and_then(|d| d.pop_front()))
}

/// Number of samples currently queued for `state`.
pub fn queue_len(state: &HostState) -> usize {
    queues()
        .lock()
        .ok()
        .map(|q| q.get(&host_key(state)).map(|d| d.len()).unwrap_or(0))
        .unwrap_or(0)
}

/// Drop all samples for `state`.
pub fn clear_queue(state: &HostState) {
    if let Ok(mut q) = queues().lock() {
        q.remove(&host_key(state));
    }
}

/// Idempotent — register every round-31 thunk into `registry`.
pub fn register(registry: &mut Registry) {
    // HostIMemInputPin (9 slots).
    registry.register(
        HOST_DLL,
        "IMemInputPin::QueryInterface",
        meminput_qi as StubFn,
        3,
    );
    registry.register(HOST_DLL, "IMemInputPin::AddRef", common_addref as StubFn, 1);
    registry.register(
        HOST_DLL,
        "IMemInputPin::Release",
        common_release as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IMemInputPin::GetAllocator",
        meminput_get_allocator as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMemInputPin::NotifyAllocator",
        common_s_ok_3 as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IMemInputPin::GetAllocatorRequirements",
        common_e_notimpl_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMemInputPin::Receive",
        meminput_receive as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IMemInputPin::ReceiveMultiple",
        meminput_receive_multiple as StubFn,
        4,
    );
    registry.register(
        HOST_DLL,
        "IMemInputPin::ReceiveCanBlock",
        common_s_ok_1 as StubFn,
        1,
    );

    // HostIPin (input-role) — 18 slots.
    registry.register(
        HOST_DLL,
        "IPin(input)::QueryInterface",
        pin_input_qi as StubFn,
        3,
    );
    registry.register(HOST_DLL, "IPin(input)::AddRef", common_addref as StubFn, 1);
    registry.register(
        HOST_DLL,
        "IPin(input)::Release",
        common_release as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::Connect",
        common_e_notimpl_3 as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::ReceiveConnection",
        pin_input_receive_connection as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::Disconnect",
        common_s_ok_1 as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::ConnectedTo",
        common_e_notimpl_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::ConnectionMediaType",
        pin_input_connection_media_type as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::QueryPinInfo",
        common_e_notimpl_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::QueryDirection",
        pin_input_query_direction as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::QueryId",
        common_e_notimpl_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::QueryAccept",
        common_s_ok_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::EnumMediaTypes",
        common_e_notimpl_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::QueryInternalConnections",
        common_e_notimpl_3 as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::EndOfStream",
        common_s_ok_1 as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::BeginFlush",
        common_s_ok_1 as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::EndFlush",
        common_s_ok_1 as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IPin(input)::NewSegment",
        common_s_ok_5 as StubFn,
        5,
    );

    // HostIBaseFilter — 15 slots.
    registry.register(
        HOST_DLL,
        "IBaseFilter::QueryInterface",
        filter_qi as StubFn,
        3,
    );
    registry.register(HOST_DLL, "IBaseFilter::AddRef", common_addref as StubFn, 1);
    registry.register(
        HOST_DLL,
        "IBaseFilter::Release",
        common_release as StubFn,
        1,
    );
    registry.register(
        HOST_DLL,
        "IBaseFilter::GetClassID",
        common_e_notimpl_2 as StubFn,
        2,
    );
    registry.register(HOST_DLL, "IBaseFilter::Stop", common_s_ok_1 as StubFn, 1);
    registry.register(HOST_DLL, "IBaseFilter::Pause", common_s_ok_1 as StubFn, 1);
    registry.register(HOST_DLL, "IBaseFilter::Run", common_s_ok_2 as StubFn, 2);
    registry.register(
        HOST_DLL,
        "IBaseFilter::GetState",
        filter_get_state as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IBaseFilter::SetSyncSource",
        common_s_ok_2 as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IBaseFilter::GetSyncSource",
        filter_get_sync_source as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IBaseFilter::EnumPins",
        filter_enum_pins as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IBaseFilter::FindPin",
        filter_find_pin as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IBaseFilter::QueryFilterInfo",
        filter_query_filter_info as StubFn,
        2,
    );
    registry.register(
        HOST_DLL,
        "IBaseFilter::JoinFilterGraph",
        common_s_ok_3 as StubFn,
        3,
    );
    registry.register(
        HOST_DLL,
        "IBaseFilter::QueryVendorInfo",
        common_e_notimpl_2 as StubFn,
        2,
    );

    // HostIEnumPins — 7 slots.
    registry.register(HOST_DLL, "IEnumPins::QueryInterface", enum_qi as StubFn, 3);
    registry.register(HOST_DLL, "IEnumPins::AddRef", common_addref as StubFn, 1);
    registry.register(HOST_DLL, "IEnumPins::Release", common_release as StubFn, 1);
    registry.register(HOST_DLL, "IEnumPins::Next", enum_pins_next as StubFn, 4);
    registry.register(HOST_DLL, "IEnumPins::Skip", common_s_ok_2 as StubFn, 2);
    registry.register(HOST_DLL, "IEnumPins::Reset", enum_pins_reset as StubFn, 1);
    registry.register(
        HOST_DLL,
        "IEnumPins::Clone",
        common_e_notimpl_2 as StubFn,
        2,
    );
}

// ---- mint helpers --------------------------------------------------

/// Mint a paired (HostIPin (input role), HostIMemInputPin) and
/// cross-reference them so QI on either resolves to the other.
/// Returns `(host_input_pin, host_meminputpin)`.
pub fn mint_host_input_pin_pair(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
) -> Result<(u32, u32), crate::Error> {
    let mip_obj = state.arena_alloc(64).map_err(crate::Error::Win32)?;
    let mip_vtbl = mip_obj.wrapping_add(12);
    mmu.write_initializer(mip_obj, &mip_vtbl.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(mip_obj + 4, &1u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(mip_obj + 8, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    let mip_methods: [&str; 9] = [
        "IMemInputPin::QueryInterface",
        "IMemInputPin::AddRef",
        "IMemInputPin::Release",
        "IMemInputPin::GetAllocator",
        "IMemInputPin::NotifyAllocator",
        "IMemInputPin::GetAllocatorRequirements",
        "IMemInputPin::Receive",
        "IMemInputPin::ReceiveMultiple",
        "IMemInputPin::ReceiveCanBlock",
    ];
    for (i, name) in mip_methods.iter().enumerate() {
        let thunk = registry.resolve(HOST_DLL, name).ok_or_else(|| {
            crate::Error::Win32(Win32Error::InvalidArgument {
                stub: "mint_host_input_pin_pair",
                reason: format!("thunk {name:?} not registered"),
            })
        })?;
        mmu.write_initializer(mip_vtbl + (i as u32) * 4, &thunk.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }
    let pin_obj = state.arena_alloc(96).map_err(crate::Error::Win32)?;
    let pin_vtbl = pin_obj.wrapping_add(16);
    mmu.write_initializer(pin_obj, &pin_vtbl.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(pin_obj + 4, &1u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(pin_obj + 8, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(pin_obj + 12, &mip_obj.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    let pin_methods: [&str; 18] = [
        "IPin(input)::QueryInterface",
        "IPin(input)::AddRef",
        "IPin(input)::Release",
        "IPin(input)::Connect",
        "IPin(input)::ReceiveConnection",
        "IPin(input)::Disconnect",
        "IPin(input)::ConnectedTo",
        "IPin(input)::ConnectionMediaType",
        "IPin(input)::QueryPinInfo",
        "IPin(input)::QueryDirection",
        "IPin(input)::QueryId",
        "IPin(input)::QueryAccept",
        "IPin(input)::EnumMediaTypes",
        "IPin(input)::QueryInternalConnections",
        "IPin(input)::EndOfStream",
        "IPin(input)::BeginFlush",
        "IPin(input)::EndFlush",
        "IPin(input)::NewSegment",
    ];
    for (i, name) in pin_methods.iter().enumerate() {
        let thunk = registry.resolve(HOST_DLL, name).ok_or_else(|| {
            crate::Error::Win32(Win32Error::InvalidArgument {
                stub: "mint_host_input_pin_pair",
                reason: format!("thunk {name:?} not registered"),
            })
        })?;
        mmu.write_initializer(pin_vtbl + (i as u32) * 4, &thunk.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }
    mmu.write_initializer(mip_obj + 8, &pin_obj.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    Ok((pin_obj, mip_obj))
}

/// Mint a minimal HostIBaseFilter exposing `input_pin`.
pub fn mint_host_base_filter(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
    input_pin: u32,
) -> Result<u32, crate::Error> {
    let obj = state.arena_alloc(80).map_err(crate::Error::Win32)?;
    let vtbl = obj.wrapping_add(12);
    mmu.write_initializer(obj, &vtbl.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 4, &1u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    mmu.write_initializer(obj + 8, &input_pin.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    let methods: [&str; 15] = [
        "IBaseFilter::QueryInterface",
        "IBaseFilter::AddRef",
        "IBaseFilter::Release",
        "IBaseFilter::GetClassID",
        "IBaseFilter::Stop",
        "IBaseFilter::Pause",
        "IBaseFilter::Run",
        "IBaseFilter::GetState",
        "IBaseFilter::SetSyncSource",
        "IBaseFilter::GetSyncSource",
        "IBaseFilter::EnumPins",
        "IBaseFilter::FindPin",
        "IBaseFilter::QueryFilterInfo",
        "IBaseFilter::JoinFilterGraph",
        "IBaseFilter::QueryVendorInfo",
    ];
    for (i, name) in methods.iter().enumerate() {
        let thunk = registry.resolve(HOST_DLL, name).ok_or_else(|| {
            crate::Error::Win32(Win32Error::InvalidArgument {
                stub: "mint_host_base_filter",
                reason: format!("thunk {name:?} not registered"),
            })
        })?;
        mmu.write_initializer(vtbl + (i as u32) * 4, &thunk.to_le_bytes())
            .map_err(crate::Error::Trap)?;
    }
    Ok(obj)
}

fn mint_host_enum_pins(
    state: &mut HostState,
    mmu: &mut Mmu,
    registry: &Registry,
    pin_addr: u32,
) -> Result<u32, Win32Error> {
    let obj = state.arena_alloc(48)?;
    let vtbl = obj.wrapping_add(16);
    let _ = mmu.write_initializer(obj, &vtbl.to_le_bytes());
    let _ = mmu.write_initializer(obj + 4, &1u32.to_le_bytes());
    let _ = mmu.write_initializer(obj + 8, &pin_addr.to_le_bytes());
    let _ = mmu.write_initializer(obj + 12, &0u32.to_le_bytes());
    let methods: [&str; 7] = [
        "IEnumPins::QueryInterface",
        "IEnumPins::AddRef",
        "IEnumPins::Release",
        "IEnumPins::Next",
        "IEnumPins::Skip",
        "IEnumPins::Reset",
        "IEnumPins::Clone",
    ];
    for (i, name) in methods.iter().enumerate() {
        let thunk =
            registry
                .resolve(HOST_DLL, name)
                .ok_or_else(|| Win32Error::InvalidArgument {
                    stub: "mint_host_enum_pins",
                    reason: format!("thunk {name:?} not registered"),
                })?;
        let _ = mmu.write_initializer(vtbl + (i as u32) * 4, &thunk.to_le_bytes());
    }
    Ok(obj)
}

// ---- IMemInputPin stubs -------------------------------------------

fn meminput_qi(
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
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIMemInputPin::QI", t))?;
    if iid == IID_IUNKNOWN || iid == IID_IMEMINPUTPIN {
        bump_refcount(mmu, this);
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    if iid == IID_IPIN {
        let sib = mmu
            .load32(this + 8)
            .map_err(|t| trap("HostIMemInputPin::QI", t))?;
        if sib == 0 {
            return Ok(E_NOINTERFACE);
        }
        bump_refcount(mmu, sib);
        let _ = mmu.write_initializer(ppv, &sib.to_le_bytes());
        state.com.intern(sib, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

fn meminput_get_allocator(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let pp = arg(cpu, mmu, 1)?;
    if pp != 0 {
        let _ = mmu.write_initializer(pp, &0u32.to_le_bytes());
    }
    // VFW_E_NO_ALLOCATOR
    Ok(0x8004_0261)
}

fn meminput_receive(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let sample = arg(cpu, mmu, 1)?;
    if sample == 0 {
        return Ok(crate::com::E_POINTER);
    }
    capture_sample(cpu, mmu, state, registry, sample)?;
    Ok(S_OK)
}

fn meminput_receive_multiple(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let pp_samples = arg(cpu, mmu, 1)?;
    let n_samples = arg(cpu, mmu, 2)?;
    let p_processed = arg(cpu, mmu, 3)?;
    let mut processed: u32 = 0;
    if pp_samples != 0 && n_samples > 0 {
        for i in 0..n_samples {
            let sample = mmu
                .load32(pp_samples + i * 4)
                .map_err(|t| trap("HostIMemInputPin::ReceiveMultiple", t))?;
            if sample != 0 {
                capture_sample(cpu, mmu, state, registry, sample)?;
                processed += 1;
            }
        }
    }
    if p_processed != 0 {
        let _ = mmu.write_initializer(p_processed, &processed.to_le_bytes());
    }
    Ok(S_OK)
}

/// Pull a sample's bytes + metadata into the host queue by
/// re-entering the guest to call the IMediaSample vtable.
fn capture_sample(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
    sample: u32,
) -> Result<(), Win32Error> {
    // Slot indices on IMediaSample: 3=GetPointer, 5=GetTime,
    // 7=IsSyncPoint, 11=GetActualDataLength, 13=GetMediaType.
    let vtbl = mmu.load32(sample).map_err(|t| trap("capture (vtbl)", t))?;
    let get_actual = mmu
        .load32(vtbl + 4 * 11)
        .map_err(|t| trap("capture (actual)", t))?;
    let get_pointer = mmu
        .load32(vtbl + 4 * 3)
        .map_err(|t| trap("capture (ptr)", t))?;
    let is_sync = mmu
        .load32(vtbl + 4 * 7)
        .map_err(|t| trap("capture (sync)", t))?;
    let get_time = mmu
        .load32(vtbl + 4 * 5)
        .map_err(|t| trap("capture (time)", t))?;
    let get_mt = mmu
        .load32(vtbl + 4 * 13)
        .map_err(|t| trap("capture (mt)", t))?;

    let length = crate::win32::call_guest(cpu, mmu, registry, state, get_actual, &[sample])
        .map_err(|e| Win32Error::InvalidArgument {
            stub: "capture_sample (GetActualDataLength)",
            reason: format!("re-entry: {e}"),
        })?;
    if length == 0 {
        push_sample(
            state,
            ReceivedSample {
                data: Vec::new(),
                sync_point: false,
                start_time: None,
                media_type_ptr: 0,
            },
        );
        return Ok(());
    }
    let pp = state.arena_alloc(4)?;
    let _ = mmu.write_initializer(pp, &0u32.to_le_bytes());
    let _ = crate::win32::call_guest(cpu, mmu, registry, state, get_pointer, &[sample, pp])
        .map_err(|e| Win32Error::InvalidArgument {
            stub: "capture_sample (GetPointer)",
            reason: format!("re-entry: {e}"),
        })?;
    let data_ptr = mmu.load32(pp).unwrap_or(0);
    if data_ptr == 0 {
        return Ok(());
    }
    let sync_hr =
        crate::win32::call_guest(cpu, mmu, registry, state, is_sync, &[sample]).map_err(|e| {
            Win32Error::InvalidArgument {
                stub: "capture_sample (IsSyncPoint)",
                reason: format!("re-entry: {e}"),
            }
        })?;
    let p_start = state.arena_alloc(8)?;
    let p_end = state.arena_alloc(8)?;
    let _ = mmu.write_initializer(p_start, &[0u8; 8]);
    let _ = mmu.write_initializer(p_end, &[0u8; 8]);
    let time_hr = crate::win32::call_guest(
        cpu,
        mmu,
        registry,
        state,
        get_time,
        &[sample, p_start, p_end],
    )
    .map_err(|e| Win32Error::InvalidArgument {
        stub: "capture_sample (GetTime)",
        reason: format!("re-entry: {e}"),
    })?;
    let start_time = if time_hr & 0x8000_0000 == 0 {
        let lo = mmu.load32(p_start).unwrap_or(0);
        let hi = mmu.load32(p_start + 4).unwrap_or(0);
        Some(((hi as i64) << 32) | (lo as i64))
    } else {
        None
    };
    let pp_mt = state.arena_alloc(4)?;
    let _ = mmu.write_initializer(pp_mt, &0u32.to_le_bytes());
    let _ = crate::win32::call_guest(cpu, mmu, registry, state, get_mt, &[sample, pp_mt]).map_err(
        |e| Win32Error::InvalidArgument {
            stub: "capture_sample (GetMediaType)",
            reason: format!("re-entry: {e}"),
        },
    )?;
    let media_type_ptr = mmu.load32(pp_mt).unwrap_or(0);
    let mut data = Vec::with_capacity(length as usize);
    for i in 0..length {
        match mmu.load8(data_ptr + i) {
            Ok(b) => data.push(b),
            Err(_) => break,
        }
    }
    push_sample(
        state,
        ReceivedSample {
            data,
            sync_point: sync_hr == S_OK,
            start_time,
            media_type_ptr,
        },
    );
    Ok(())
}

// ---- IPin (input role) stubs ----------------------------------------

fn pin_input_qi(
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
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIPin(input)::QI", t))?;
    if iid == IID_IUNKNOWN || iid == IID_IPIN {
        bump_refcount(mmu, this);
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    if iid == IID_IMEMINPUTPIN {
        let sib = mmu
            .load32(this + 12)
            .map_err(|t| trap("HostIPin(input)::QI", t))?;
        if sib == 0 {
            return Ok(E_NOINTERFACE);
        }
        bump_refcount(mmu, sib);
        let _ = mmu.write_initializer(ppv, &sib.to_le_bytes());
        state.com.intern(sib, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

fn pin_input_query_direction(
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
    // PIN_INPUT = 0
    mmu.write_initializer(p_pin_dir, &0u32.to_le_bytes())
        .map_err(|t| trap("HostIPin(input)::QueryDirection", t))?;
    Ok(S_OK)
}

fn pin_input_receive_connection(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let _connector = arg(cpu, mmu, 1)?;
    let pmt = arg(cpu, mmu, 2)?;
    let _ = mmu.write_initializer(this + 8, &pmt.to_le_bytes());
    Ok(S_OK)
}

fn pin_input_connection_media_type(
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
    let amt_src = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIPin(input)::ConnectionMediaType", t))?;
    if amt_src == 0 {
        return Ok(0x8004_0211 /* VFW_E_NOT_CONNECTED */);
    }
    for i in 0..72u32 {
        let b = mmu
            .load8(amt_src + i)
            .map_err(|t| trap("HostIPin(input)::ConnectionMediaType", t))?;
        mmu.store8(pmt + i, b)
            .map_err(|t| trap("HostIPin(input)::ConnectionMediaType", t))?;
    }
    Ok(S_OK)
}

// ---- IBaseFilter stubs ---------------------------------------------

fn filter_qi(
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
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIBaseFilter::QI", t))?;
    if iid == IID_IUNKNOWN
        || iid == IID_IPERSIST
        || iid == IID_IMEDIAFILTER
        || iid == IID_IBASEFILTER
    {
        bump_refcount(mmu, this);
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

fn filter_enum_pins(
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
    let pin = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIBaseFilter::EnumPins", t))?;
    let new_enum = mint_host_enum_pins(state, mmu, registry, pin)?;
    mmu.write_initializer(pp, &new_enum.to_le_bytes())
        .map_err(|t| trap("HostIBaseFilter::EnumPins", t))?;
    Ok(S_OK)
}

fn filter_find_pin(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let _id = arg(cpu, mmu, 1)?;
    let pp = arg(cpu, mmu, 2)?;
    if pp == 0 {
        return Ok(crate::com::E_POINTER);
    }
    let pin = mmu
        .load32(this + 8)
        .map_err(|t| trap("HostIBaseFilter::FindPin", t))?;
    mmu.write_initializer(pp, &pin.to_le_bytes())
        .map_err(|t| trap("HostIBaseFilter::FindPin", t))?;
    Ok(S_OK)
}

/// Round 37 — `IBaseFilter::QueryFilterInfo(this, FILTER_INFO* pInfo)`.
///
/// Per `axextend.h`:
///
/// ```c
/// typedef struct _FilterInfo {
///     WCHAR achName[128];      // offset 0   (256 bytes)
///     IFilterGraph* pGraph;    // offset 256 (4 bytes)
/// } FILTER_INFO;
/// ```
///
/// Total: 260 bytes.
///
/// Round 37 populates `achName` with UTF-16 LE `"HostFilter\0"` so
/// any codec that diagnostically dumps the filter name doesn't see
/// raw zero garbage; `pGraph` stays NULL (we don't yet vend a host
/// IFilterGraph from this slot).  Records the call into the
/// per-state log so tests can introspect whether the codec drove
/// it during init.
fn filter_query_filter_info(
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
    // Zero the whole 260-byte struct first.
    for i in 0..260u32 {
        let _ = mmu.store8(p_info + i, 0);
    }
    // achName (WCHAR[128]) = "HostFilter\0".
    let name_utf16: [u16; 11] = [
        b'H' as u16,
        b'o' as u16,
        b's' as u16,
        b't' as u16,
        b'F' as u16,
        b'i' as u16,
        b'l' as u16,
        b't' as u16,
        b'e' as u16,
        b'r' as u16,
        0,
    ];
    for (i, w) in name_utf16.iter().enumerate() {
        let _ = mmu.write_initializer(p_info + (i as u32) * 2, &w.to_le_bytes());
    }
    // pGraph at offset 256 stays NULL — already zeroed above.
    crate::com::host_iface::record_query_filter_info_call(state, this);
    Ok(S_OK)
}

fn filter_get_state(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let _ms = arg(cpu, mmu, 1)?;
    let p_state = arg(cpu, mmu, 2)?;
    if p_state != 0 {
        let _ = mmu.write_initializer(p_state, &0u32.to_le_bytes());
    }
    Ok(S_OK)
}

fn filter_get_sync_source(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _this = arg(cpu, mmu, 0)?;
    let pp = arg(cpu, mmu, 1)?;
    if pp != 0 {
        let _ = mmu.write_initializer(pp, &0u32.to_le_bytes());
    }
    Ok(S_OK)
}

// ---- IEnumPins stubs -----------------------------------------------

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
    let iid = Guid::load(mmu, piid).map_err(|t| trap("HostIEnumPins::QI", t))?;
    if iid == IID_IUNKNOWN {
        bump_refcount(mmu, this);
        let _ = mmu.write_initializer(ppv, &this.to_le_bytes());
        state.com.intern(this, Some(iid));
        return Ok(S_OK);
    }
    Ok(E_NOINTERFACE)
}

fn enum_pins_next(
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
        let pin = mmu
            .load32(this + 8)
            .map_err(|t| trap("HostIEnumPins::Next", t))?;
        mmu.write_initializer(pp, &pin.to_le_bytes())
            .map_err(|t| trap("HostIEnumPins::Next", t))?;
        if p_fetched != 0 {
            let _ = mmu.write_initializer(p_fetched, &1u32.to_le_bytes());
        }
        let _ = mmu.write_initializer(this + 12, &1u32.to_le_bytes());
        if c == 1 {
            return Ok(S_OK);
        }
        return Ok(crate::com::S_FALSE);
    }
    let _ = mmu.write_initializer(pp, &0u32.to_le_bytes());
    if p_fetched != 0 {
        let _ = mmu.write_initializer(p_fetched, &0u32.to_le_bytes());
    }
    Ok(crate::com::S_FALSE)
}

fn enum_pins_reset(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let _ = mmu.write_initializer(this + 12, &0u32.to_le_bytes());
    Ok(S_OK)
}

// ---- A: EnumMediaTypes walk ----------------------------------------

/// Round 31 — drive the codec's input pin's `EnumMediaTypes` chain
/// and capture every AMT it advertises (up to `max`).
pub fn walk_codec_input_pin_amts(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    input_pin: u32,
    max: usize,
) -> Result<Vec<CapturedAmt>, crate::Error> {
    use crate::com::call::call_method;
    let pp = state.arena_alloc(4)?;
    mmu.write_initializer(pp, &0u32.to_le_bytes())
        .map_err(crate::Error::Trap)?;
    let r = call_method(
        cpu,
        mmu,
        registry,
        state,
        input_pin,
        /*EnumMediaTypes=*/ 12,
        &[pp],
    )?;
    if r != S_OK {
        return Ok(Vec::new());
    }
    let enum_ptr = mmu.load32(pp).map_err(crate::Error::Trap)?;
    if enum_ptr == 0 {
        return Ok(Vec::new());
    }
    state.com.intern(enum_ptr, None);

    let mut out = Vec::new();
    for _ in 0..max {
        let p_amt = state.arena_alloc(4)?;
        let p_fetched = state.arena_alloc(4)?;
        mmu.write_initializer(p_amt, &0u32.to_le_bytes())
            .map_err(crate::Error::Trap)?;
        mmu.write_initializer(p_fetched, &0u32.to_le_bytes())
            .map_err(crate::Error::Trap)?;
        let r = call_method(
            cpu,
            mmu,
            registry,
            state,
            enum_ptr,
            /*Next=*/ 3,
            &[1, p_amt, p_fetched],
        )?;
        let fetched = mmu.load32(p_fetched).unwrap_or(0);
        let amt_addr = mmu.load32(p_amt).unwrap_or(0);
        if r == crate::com::S_FALSE || fetched == 0 || amt_addr == 0 {
            break;
        }
        let majortype = Guid::load(mmu, amt_addr).map_err(crate::Error::Trap)?;
        let subtype = Guid::load(mmu, amt_addr + 16).map_err(crate::Error::Trap)?;
        let b_fixed_size_samples = mmu.load32(amt_addr + 32).map_err(crate::Error::Trap)?;
        let l_sample_size = mmu.load32(amt_addr + 40).map_err(crate::Error::Trap)?;
        let formattype = Guid::load(mmu, amt_addr + 44).map_err(crate::Error::Trap)?;
        let cb_format = mmu.load32(amt_addr + 64).map_err(crate::Error::Trap)?;
        let pb_format = mmu.load32(amt_addr + 68).map_err(crate::Error::Trap)?;
        out.push(CapturedAmt {
            amt_addr,
            majortype,
            subtype,
            b_fixed_size_samples,
            l_sample_size,
            formattype,
            cb_format,
            pb_format,
        });
    }
    let _ = crate::com::call::release(cpu, mmu, registry, state, enum_ptr);
    Ok(out)
}

// ---- common shared stubs ------------------------------------------

fn common_addref(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let rc = mmu.load32(this + 4).map_err(|t| trap("AddRef", t))?;
    let nrc = rc.saturating_add(1);
    mmu.write_initializer(this + 4, &nrc.to_le_bytes())
        .map_err(|t| trap("AddRef", t))?;
    Ok(nrc)
}

fn common_release(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let this = arg(cpu, mmu, 0)?;
    let rc = mmu.load32(this + 4).map_err(|t| trap("Release", t))?;
    let nrc = if rc > 1 { rc - 1 } else { 1 };
    mmu.write_initializer(this + 4, &nrc.to_le_bytes())
        .map_err(|t| trap("Release", t))?;
    Ok(nrc)
}

fn common_s_ok_1(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}
fn common_s_ok_2(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}
fn common_s_ok_3(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}
fn common_s_ok_5(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(S_OK)
}
fn common_e_notimpl_2(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(E_NOTIMPL)
}
fn common_e_notimpl_3(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(E_NOTIMPL)
}

fn arg(cpu: &Cpu, mmu: &Mmu, n: u32) -> Result<u32, Win32Error> {
    crate::win32::arg_dword(cpu, mmu, n).map_err(|t| trap("r31::arg", t))
}

fn trap(stub: &'static str, t: crate::emulator::Trap) -> Win32Error {
    Win32Error::InvalidArgument {
        stub,
        reason: format!("{t}"),
    }
}

fn bump_refcount(mmu: &mut Mmu, this: u32) {
    if let Ok(rc) = mmu.load32(this + 4) {
        let _ = mmu.write_initializer(this + 4, &rc.saturating_add(1).to_le_bytes());
    }
}
