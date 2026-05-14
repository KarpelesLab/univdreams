//! COM (Component Object Model) scaffolding — round 25, stage 1.
//!
//! Round 24 closed with the verdict that `WMVDS32.AX` and
//! `MPG4DS32.AX` lack a `DriverProc` export entirely: they are
//! pure DirectShow filters that expose `DllGetClassObject` plus
//! a family of `IBaseFilter`-derived COM objects.  The VfW
//! `DriverProc` ABI is fundamentally absent in the wmpcdcs8-2001
//! bundle for those two binaries, so any path that wants to
//! decode WMV through them must reach in through the DirectShow
//! IBaseFilter ABI instead.
//!
//! This module is the foundation for that work.  It introduces
//! just enough COM machinery to:
//!
//! * Describe an interface identifier ([`Guid`]) — including a
//!   parser from the canonical MIDL `{xxxxxxxx-xxxx-xxxx-xxxx-…}`
//!   string form so the IID constants below read like the
//!   header files.
//! * Hardcode the IIDs we will care about (IUnknown,
//!   IClassFactory, IBaseFilter, IPin, IMemInputPin, IEnumPins,
//!   IMemAllocator, IMediaSample, IFilterGraph) so later stages
//!   can cite them without re-quoting the GUIDs in three places.
//! * Track guest-side COM objects ([`ComObjectTable`]) — when a
//!   guest interface pointer leaves the sandbox into our test
//!   harness, we register it here so `Release` semantics are
//!   bookkept on the host side: the table records the refcount
//!   each side believes the object holds.  We do **not** crack
//!   the guest vtable pointer — calls into vtable methods just
//!   reach through guest memory like any other indirect call,
//!   driven by [`call_method`].
//! * Public ABI HRESULT constants so test assertions read like
//!   the MSDN reference (`S_OK`, `E_NOINTERFACE`, `E_NOTIMPL`).
//!
//! ### Reference material
//!
//! All interface signatures, GUID values, and HRESULT semantics
//! come from Microsoft's public ABI documentation:
//!
//! * "Component Object Model (COM)" — IUnknown reference.
//!   <https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com-->
//! * "DirectShow Reference" — IBaseFilter / IPin / IMemInputPin /
//!   IMemAllocator / IMediaSample / IFilterGraph interface
//!   references.
//!   <https://learn.microsoft.com/en-us/windows/win32/directshow/directshow-reference>
//! * Windows SDK headers (`unknwn.h`, `axextend.h`, `strmif.h`,
//!   `amvideo.h`) — header ABI declarations only.
//!
//! We do NOT consult the DirectShow BaseClasses sample source
//! (`CBaseFilter` / `CTransformFilter` `.cpp`); only the public
//! interface signatures, GUID values, and HRESULT semantics from
//! MSDN + the MIDL-generated header declarations.

use crate::emulator::{Cpu, Mmu};

pub mod asf_amt;
pub mod call;
pub mod host_iface;
pub mod host_iface_r31;

pub use asf_amt::{
    extract_wma_amt_from_asf, locate_first_data_packet, AmtBlueprint, AsfParseError,
    ASF_AUDIO_MEDIA, ASF_HEADER_OBJECT, ASF_STREAM_PROPERTIES_OBJECT,
};
pub use call::{add_ref, call_method, query_interface, release};
pub use host_iface::{
    all_set_properties, clear_query_info_log, clear_set_properties_log, last_set_properties,
    media_sample_set_payload, mint_host_filter_graph, mint_host_media_sample,
    mint_host_mem_allocator, mint_host_mem_allocator_class_factory,
    mint_host_output_pin_with_connection, query_filter_info_call_count, query_filter_info_calls,
    query_pin_info_call_count, query_pin_info_calls, AllocatorPropertiesCapture,
    DEFAULT_MEM_ALLOCATOR_FACTORY_CAPACITY, DEFAULT_MEM_ALLOCATOR_FACTORY_POOL,
};

/// Canonical 128-bit globally-unique identifier.  Layout matches
/// the MIDL `GUID` struct in `guiddef.h`:
///
/// ```c
/// typedef struct _GUID {
///     unsigned long  Data1;
///     unsigned short Data2;
///     unsigned short Data3;
///     unsigned char  Data4[8];
/// } GUID;
/// ```
///
/// Stored canonically (little-endian on `Data1..3`, raw bytes on
/// `Data4`) so that [`Self::write_le`] / [`Self::read_le`]
/// round-trip with the in-memory layout the codec sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Build a `Guid` from its four wire-form fields.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Guid {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Parse the canonical MIDL string form
    /// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.  Both the curly
    /// braces and the hyphens at the standard positions are
    /// required; case-insensitive on hex digits.  Returns
    /// [`GuidParseError`] on any deviation.
    ///
    /// This is a `const`-style parser used in tests to stage
    /// canned IIDs without writing out the four-field struct
    /// literal.  The hardcoded IID constants below use
    /// [`Self::new`] for readability + `const` evaluability.
    pub fn parse(s: &str) -> Result<Self, GuidParseError> {
        let bytes = s.as_bytes();
        if bytes.len() != 38 {
            return Err(GuidParseError::WrongLength { len: bytes.len() });
        }
        if bytes[0] != b'{' || bytes[37] != b'}' {
            return Err(GuidParseError::MissingBraces);
        }
        // Hyphen positions: 9, 14, 19, 24 (1-based, after '{').
        for &i in &[9usize, 14, 19, 24] {
            if bytes[i] != b'-' {
                return Err(GuidParseError::MissingHyphen { at: i });
            }
        }
        let hex = |start: usize, len: usize| -> Result<u64, GuidParseError> {
            let mut acc: u64 = 0;
            for i in 0..len {
                let c = bytes[start + i];
                let nib = match c {
                    b'0'..=b'9' => (c - b'0') as u64,
                    b'a'..=b'f' => (c - b'a' + 10) as u64,
                    b'A'..=b'F' => (c - b'A' + 10) as u64,
                    _ => {
                        return Err(GuidParseError::BadHex {
                            at: start + i,
                            byte: c,
                        });
                    }
                };
                acc = (acc << 4) | nib;
            }
            Ok(acc)
        };
        let data1 = hex(1, 8)? as u32;
        let data2 = hex(10, 4)? as u16;
        let data3 = hex(15, 4)? as u16;
        let mut data4 = [0u8; 8];
        for (i, slot) in data4.iter_mut().enumerate().take(2) {
            *slot = hex(20 + 2 * i, 2)? as u8;
        }
        for (i, slot) in data4.iter_mut().enumerate().skip(2) {
            *slot = hex(25 + 2 * (i - 2), 2)? as u8;
        }
        Ok(Guid {
            data1,
            data2,
            data3,
            data4,
        })
    }

    /// Format back into the canonical MIDL string form, in
    /// upper-case hex (which is what `StringFromGUID2` emits).
    pub fn to_braced_string(self) -> String {
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }

    /// Encode the GUID into 16 bytes in the wire layout (LE on
    /// the first three fields, raw on `Data4`).  Suitable for
    /// staging the GUID into guest memory before passing the
    /// pointer to a vtable method.
    pub fn write_le(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.data1.to_le_bytes());
        out[4..6].copy_from_slice(&self.data2.to_le_bytes());
        out[6..8].copy_from_slice(&self.data3.to_le_bytes());
        out[8..16].copy_from_slice(&self.data4);
        out
    }

    /// Decode 16 bytes laid out per [`Self::write_le`].  Returns
    /// `None` if `bytes.len() < 16`.
    pub fn read_le(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
        let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&bytes[8..16]);
        Some(Guid {
            data1,
            data2,
            data3,
            data4,
        })
    }

    /// Stage `self` at `addr` in guest memory.  Caller must have
    /// mapped the destination region R+W.
    pub fn stage(self, mmu: &mut Mmu, addr: u32) -> Result<(), crate::emulator::Trap> {
        mmu.write_initializer(addr, &self.write_le())
    }

    /// Read 16 bytes back from guest memory at `addr`.
    pub fn load(mmu: &Mmu, addr: u32) -> Result<Self, crate::emulator::Trap> {
        let mut buf = [0u8; 16];
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = mmu.load8(addr + i as u32)?;
        }
        Self::read_le(&buf).ok_or(crate::emulator::Trap::MemoryFault { addr })
    }
}

impl core::fmt::Display for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_braced_string())
    }
}

/// Error returned by [`Guid::parse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuidParseError {
    /// String length is not exactly 38 bytes.
    WrongLength { len: usize },
    /// Missing the leading `{` or trailing `}`.
    MissingBraces,
    /// Missing a `-` separator at one of the standard positions.
    MissingHyphen { at: usize },
    /// Encountered a non-hex byte where a hex digit was expected.
    BadHex { at: usize, byte: u8 },
}

impl core::fmt::Display for GuidParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GuidParseError::WrongLength { len } => {
                write!(f, "GUID string must be 38 chars (got {len})")
            }
            GuidParseError::MissingBraces => f.write_str("GUID string missing { … } braces"),
            GuidParseError::MissingHyphen { at } => {
                write!(f, "GUID string missing '-' at position {at}")
            }
            GuidParseError::BadHex { at, byte } => {
                write!(f, "GUID string non-hex byte {byte:#x} at position {at}")
            }
        }
    }
}

impl std::error::Error for GuidParseError {}

// ---- Hardcoded IIDs ----------------------------------------------------
//
// Values are transcribed from the public Windows SDK MIDL-
// generated headers (`unknwn.h`, `objbase.h`, `strmif.h`,
// `axextend.h`).  Only the GUID values + the interface method
// signatures we reproduce in `call.rs` are referenced — never
// the BaseClasses sample source.

/// `IID_IUnknown` — the universal COM base interface
/// (`{00000000-0000-0000-C000-000000000046}`).  Vtable slots:
/// `0=QueryInterface`, `1=AddRef`, `2=Release`.  Source:
/// `unknwn.h` from the Windows SDK.
pub const IID_IUNKNOWN: Guid = Guid::new(
    0x0000_0000,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);

/// `IID_IClassFactory` (`{00000001-0000-0000-C000-000000000046}`).
/// Vtable adds slots 3=`CreateInstance`, 4=`LockServer`.
pub const IID_ICLASSFACTORY: Guid = Guid::new(
    0x0000_0001,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);

/// `IID_IPersist` (`{0000010C-0000-0000-C000-000000000046}`).
/// One method beyond IUnknown: 3=`GetClassID`.
pub const IID_IPERSIST: Guid = Guid::new(
    0x0000_010C,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);

/// `IID_IMediaFilter` (`{56A86899-0AD4-11CE-B03A-0020AF0BA770}`).
/// Adds (after IPersist's GetClassID):
/// 4=`Stop`, 5=`Pause`, 6=`Run`, 7=`GetState`, 8=`SetSyncSource`,
/// 9=`GetSyncSource`.  Source: `strmif.h`.
pub const IID_IMEDIAFILTER: Guid = Guid::new(
    0x56A8_6899,
    0x0AD4,
    0x11CE,
    [0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70],
);

/// `IID_IBaseFilter` (`{56A86895-0AD4-11CE-B03A-0020AF0BA770}`).
/// Adds (after IMediaFilter's 6 methods):
/// 10=`EnumPins`, 11=`FindPin`, 12=`QueryFilterInfo`,
/// 13=`JoinFilterGraph`, 14=`QueryVendorInfo`.
pub const IID_IBASEFILTER: Guid = Guid::new(
    0x56A8_6895,
    0x0AD4,
    0x11CE,
    [0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70],
);

/// `IID_IPin` (`{56A86891-0AD4-11CE-B03A-0020AF0BA770}`).
/// Vtable slots beyond IUnknown:
/// 3=`Connect`, 4=`ReceiveConnection`, 5=`Disconnect`,
/// 6=`ConnectedTo`, 7=`ConnectionMediaType`, 8=`QueryPinInfo`,
/// 9=`QueryDirection`, 10=`QueryId`, 11=`QueryAccept`,
/// 12=`EnumMediaTypes`, 13=`QueryInternalConnections`,
/// 14=`EndOfStream`, 15=`BeginFlush`, 16=`EndFlush`,
/// 17=`NewSegment`.
pub const IID_IPIN: Guid = Guid::new(
    0x56A8_6891,
    0x0AD4,
    0x11CE,
    [0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70],
);

/// `IID_IMemInputPin` (`{56A8689D-0AD4-11CE-B03A-0020AF0BA770}`).
/// Slots beyond IUnknown:
/// 3=`GetAllocator`, 4=`NotifyAllocator`,
/// 5=`GetAllocatorRequirements`, 6=`Receive`,
/// 7=`ReceiveMultiple`, 8=`ReceiveCanBlock`.
pub const IID_IMEMINPUTPIN: Guid = Guid::new(
    0x56A8_689D,
    0x0AD4,
    0x11CE,
    [0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70],
);

/// `IID_IEnumPins` (`{56A86892-0AD4-11CE-B03A-0020AF0BA770}`).
/// Slots beyond IUnknown:
/// 3=`Next`, 4=`Skip`, 5=`Reset`, 6=`Clone`.
pub const IID_IENUMPINS: Guid = Guid::new(
    0x56A8_6892,
    0x0AD4,
    0x11CE,
    [0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70],
);

/// `IID_IMemAllocator` (`{56A8689C-0AD4-11CE-B03A-0020AF0BA770}`).
/// Slots beyond IUnknown:
/// 3=`SetProperties`, 4=`GetProperties`, 5=`Commit`, 6=`Decommit`,
/// 7=`GetBuffer`, 8=`ReleaseBuffer`.
pub const IID_IMEMALLOCATOR: Guid = Guid::new(
    0x56A8_689C,
    0x0AD4,
    0x11CE,
    [0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70],
);

/// `IID_IMediaSample` (`{56A8689A-0AD4-11CE-B03A-0020AF0BA770}`).
/// 17 slots beyond IUnknown.  Source: `strmif.h`.
pub const IID_IMEDIASAMPLE: Guid = Guid::new(
    0x56A8_689A,
    0x0AD4,
    0x11CE,
    [0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70],
);

/// `IID_IMediaSample2` (`{36B73884-C2C8-11CF-8B46-00805F6CEF60}`).
///
/// Extends [`IID_IMEDIASAMPLE`] with two methods at slots 19 and 20
/// (after IMediaSample's 19 = 3 IUnknown + 16 IMediaSample):
/// `19=GetProperties(DWORD cb, BYTE* pProps)`,
/// `20=SetProperties(DWORD cb, const BYTE* pProps)`.  Both transport
/// the public `AM_SAMPLE2_PROPERTIES` struct (64 bytes per
/// `strmif.h`).
///
/// Source: Microsoft Platform SDK `strmif.h`.  Reverse-engineered
/// from the disassembly of MPG4DS32.AX RVA `0x4064f3` (round 39):
/// `CTransformFilter::Transform` calls `pSampleOut->QueryInterface(
/// IID_IMediaSample2, &p2)` immediately after fetching the output
/// buffer; on success it reads the AMT properties via slots 19/20
/// of the returned interface.  Returning `E_NOINTERFACE` forces the
/// codec down a fallback branch that ends up trapping in the GUID-
/// equality helper at RVA `0x7176`.
pub const IID_IMEDIASAMPLE2: Guid = Guid::new(
    0x36B7_3884,
    0xC2C8,
    0x11CF,
    [0x8B, 0x46, 0x00, 0x80, 0x5F, 0x6C, 0xEF, 0x60],
);

/// `IID_IFilterGraph` (`{56A8689F-0AD4-11CE-B03A-0020AF0BA770}`).
/// Slots beyond IUnknown:
/// 3=`AddFilter`, 4=`RemoveFilter`, 5=`EnumFilters`,
/// 6=`FindFilterByName`, 7=`ConnectDirect`, 8=`Reconnect`,
/// 9=`Disconnect`, 10=`SetDefaultSyncSource`.
pub const IID_IFILTERGRAPH: Guid = Guid::new(
    0x56A8_689F,
    0x0AD4,
    0x11CE,
    [0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70],
);

/// `MSADDS_AUDIO_DECODER_CLSID` (`{22E24591-49D0-11D2-BB50-006008320064}`).
///
/// The CLSID under which `msadds32.ax`'s "Windows Media Audio
/// Decoder" DirectShow filter is registered.  Discovered by
/// reverse-engineering the splitter's `DllGetClassObject`
/// prologue (RVA `0x3635` in the wmpcdcs8-2001 bundle) — the
/// prologue compares `*rclsid` against an in-`.rdata` table at
/// RVA `0x11000`, count word at RVA `0x11028`.  Entry 0 of that
/// table (count = 2, stride = 20 bytes) points to the GUID
/// literal at `.rdata` offset `0xf248`, which decodes to this
/// value.
///
/// The companion "Microsoft MS Audio Decompressor Control Property
/// page" CLSID is [`MSADDS_AUDIO_PROPERTY_PAGE_CLSID`] below.
///
/// Clean-room reverse engineering only: prologue disassembled
/// from raw bytes against Intel SDM Vol. 2A opcode encodings; no
/// Wine / ReactOS / MinGW source consulted.  The CLSID itself is
/// public installation metadata (the splitter's `DllRegisterServer`
/// writes it to `HKCR\CLSID\{...}\InprocServer32` at install).
pub const MSADDS_AUDIO_DECODER_CLSID: Guid = Guid::new(
    0x22E2_4591,
    0x49D0,
    0x11D2,
    [0xBB, 0x50, 0x00, 0x60, 0x08, 0x32, 0x00, 0x64],
);

/// `MSADDS_AUDIO_PROPERTY_PAGE_CLSID`
/// (`{8FE7E181-BB96-11D2-A1CB-00609778EA66}`).
///
/// Entry 1 of the `msadds32.ax` `DllGetClassObject` CLSID table —
/// the property-page UI vestige for "Microsoft MS Audio
/// Decompressor Control".  Not exercised on the audio-decode
/// path; pinned here so a probe that lands on it (e.g. dynamic
/// `DllRegisterServer` walk in a future round) can identify
/// what it found.
pub const MSADDS_AUDIO_PROPERTY_PAGE_CLSID: Guid = Guid::new(
    0x8FE7_E181,
    0xBB96,
    0x11D2,
    [0xA1, 0xCB, 0x00, 0x60, 0x97, 0x78, 0xEA, 0x66],
);

/// `CLSID_MemoryAllocator` (`{1E651CC0-B199-11D0-8212-00C04FC32C45}`).
///
/// Source: Windows SDK header `axextend.h`.  This is the canonical
/// DirectShow memory-allocator class — `CoCreateInstance(this CLSID,
/// NULL, CLSCTX_INPROC_SERVER, IID_IMemAllocator, &alloc)` is how
/// every DirectShow input/output pin instantiates a fresh
/// IMemAllocator backed by host-managed buffer pool.
///
/// Round 35 — registered in the host class-factory cache at
/// `Sandbox::new` so codecs that internally call CoCreateInstance
/// for it (mpg4ds32 from inside `IMemInputPin::GetAllocator`) get a
/// usable allocator pointer rather than the round-34 baseline
/// `CLASS_E_CLASSNOTAVAILABLE` (`0x80040111`).
pub const CLSID_MEMORY_ALLOCATOR: Guid = Guid::new(
    0x1E65_1CC0,
    0xB199,
    0x11D0,
    [0x82, 0x12, 0x00, 0xC0, 0x4F, 0xC3, 0x2C, 0x45],
);

// ---- Public HRESULT codes ----------------------------------------------
//
// Subset that the round-25 tests assert against.  Source:
// `winerror.h` from the Windows SDK.  Cited values are public
// constants documented on every MSDN HRESULT page.

/// `S_OK = 0x00000000` — success.
pub const S_OK: u32 = 0x0000_0000;
/// `S_FALSE = 0x00000001` — operation succeeded but did not need
/// to do anything (e.g. `IBaseFilter::Run` returned because the
/// filter was already running).
pub const S_FALSE: u32 = 0x0000_0001;
/// `E_NOINTERFACE = 0x80004002` — `QueryInterface` rejected the
/// requested IID.
pub const E_NOINTERFACE: u32 = 0x8000_4002;
/// `E_NOTIMPL = 0x80004001` — method not implemented.
pub const E_NOTIMPL: u32 = 0x8000_4001;
/// `E_POINTER = 0x80004003` — caller passed a NULL/invalid
/// pointer.
pub const E_POINTER: u32 = 0x8000_4003;
/// `E_FAIL = 0x80004005` — generic failure.
pub const E_FAIL: u32 = 0x8000_4005;
/// `E_UNEXPECTED = 0x8000FFFF`.
pub const E_UNEXPECTED: u32 = 0x8000_FFFF;
/// `CLASS_E_CLASSNOTAVAILABLE = 0x80040111` — the CLSID is not
/// registered with our in-process class-factory cache.
pub const CLASS_E_CLASSNOTAVAILABLE: u32 = 0x8004_0111;

// ---- Vtable-method slot numbers ----------------------------------------
//
// Standard COM ABI: every interface inherits IUnknown's three
// methods at slots 0..3, then adds its own at slot 3 onward.

/// Slot 0 of every COM vtable: `QueryInterface(REFIID, void**)`.
pub const SLOT_QUERY_INTERFACE: u32 = 0;
/// Slot 1: `AddRef()`.
pub const SLOT_ADD_REF: u32 = 1;
/// Slot 2: `Release()`.
pub const SLOT_RELEASE: u32 = 2;

/// `IClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID,
/// void** ppv)` — vtable slot 3.
pub const SLOT_CLASS_FACTORY_CREATE_INSTANCE: u32 = 3;
/// `IClassFactory::LockServer(BOOL fLock)` — vtable slot 4.
pub const SLOT_CLASS_FACTORY_LOCK_SERVER: u32 = 4;

/// `IBaseFilter::Stop()` — slot 4 (after IPersist::GetClassID at
/// slot 3).
pub const SLOT_BASEFILTER_STOP: u32 = 4;
/// `IBaseFilter::Pause()` — slot 5.
pub const SLOT_BASEFILTER_PAUSE: u32 = 5;
/// `IBaseFilter::Run(REFERENCE_TIME tStart)` — slot 6.  `tStart`
/// is a 64-bit integer; passed as two adjacent dwords on the
/// stdcall stack (low dword first, high dword next).
pub const SLOT_BASEFILTER_RUN: u32 = 6;
/// `IBaseFilter::GetState(DWORD dwMilliSecsTimeout, FILTER_STATE
/// *State)` — slot 7.
pub const SLOT_BASEFILTER_GET_STATE: u32 = 7;
/// `IBaseFilter::EnumPins(IEnumPins** ppEnum)` — slot 10.
pub const SLOT_BASEFILTER_ENUM_PINS: u32 = 10;
/// `IBaseFilter::FindPin(LPCWSTR Id, IPin** ppPin)` — slot 11.
pub const SLOT_BASEFILTER_FIND_PIN: u32 = 11;
/// `IBaseFilter::JoinFilterGraph(IFilterGraph* pGraph,
/// LPCWSTR pName)` — slot 13.
pub const SLOT_BASEFILTER_JOIN_FILTER_GRAPH: u32 = 13;

/// `IMediaFilter::Stop()` — slot 4 (after IPersist::GetClassID at
/// slot 3).  Same numeric slot as `IBaseFilter::Stop` because
/// `IBaseFilter` extends `IMediaFilter`.
pub const SLOT_MEDIAFILTER_STOP: u32 = 4;
/// `IMediaFilter::Pause()` — slot 5.
pub const SLOT_MEDIAFILTER_PAUSE: u32 = 5;
/// `IMediaFilter::Run(REFERENCE_TIME tStart)` — slot 6.  `tStart`
/// is a 64-bit integer marshalled as two adjacent dwords on the
/// stdcall stack (low dword first, high dword next).
pub const SLOT_MEDIAFILTER_RUN: u32 = 6;
/// `IMediaFilter::GetState(DWORD dwMilliSecsTimeout, FILTER_STATE
/// *State)` — slot 7.
pub const SLOT_MEDIAFILTER_GET_STATE: u32 = 7;

/// `IMemAllocator::SetProperties(ALLOCATOR_PROPERTIES* pRequest,
/// ALLOCATOR_PROPERTIES* pActual)` — slot 3.
pub const SLOT_MEMALLOCATOR_SET_PROPERTIES: u32 = 3;
/// `IMemAllocator::Commit()` — slot 5.
pub const SLOT_MEMALLOCATOR_COMMIT: u32 = 5;
/// `IMemAllocator::Decommit()` — slot 6.
pub const SLOT_MEMALLOCATOR_DECOMMIT: u32 = 6;
/// `IMemAllocator::GetBuffer(IMediaSample** ppBuffer,
/// REFERENCE_TIME* pStartTime, REFERENCE_TIME* pEndTime,
/// DWORD dwFlags)` — slot 7.
pub const SLOT_MEMALLOCATOR_GET_BUFFER: u32 = 7;
/// `IMemAllocator::ReleaseBuffer(IMediaSample* pBuffer)` — slot 8.
pub const SLOT_MEMALLOCATOR_RELEASE_BUFFER: u32 = 8;

/// `IMediaSample::GetPointer(BYTE** ppBuffer)` — slot 3 (after
/// IUnknown).  Returns the start address of the sample's payload
/// buffer through `*ppBuffer`.
pub const SLOT_MEDIASAMPLE_GET_POINTER: u32 = 3;
/// `IMediaSample::GetSize()` — slot 4.  Returns the buffer
/// capacity in bytes (NOT the actual data length).
pub const SLOT_MEDIASAMPLE_GET_SIZE: u32 = 4;
/// `IMediaSample::IsSyncPoint()` — slot 7.  Returns `S_OK` for
/// sync (key) frames, `S_FALSE` otherwise.
pub const SLOT_MEDIASAMPLE_IS_SYNC_POINT: u32 = 7;
/// `IMediaSample::SetSyncPoint(BOOL bIsSyncPoint)` — slot 8.
pub const SLOT_MEDIASAMPLE_SET_SYNC_POINT: u32 = 8;
/// `IMediaSample::GetActualDataLength()` — slot 11.  Returns the
/// number of valid bytes currently in the sample's buffer.
pub const SLOT_MEDIASAMPLE_GET_ACTUAL_DATA_LENGTH: u32 = 11;
/// `IMediaSample::SetActualDataLength(LONG lLen)` — slot 12.
/// Caller declares the count of valid bytes the codec should
/// process from the buffer.  Must be ≤ `GetSize()`.
pub const SLOT_MEDIASAMPLE_SET_ACTUAL_DATA_LENGTH: u32 = 12;
/// `IMediaSample::GetMediaType(AM_MEDIA_TYPE** ppMediaType)` —
/// slot 13.
pub const SLOT_MEDIASAMPLE_GET_MEDIA_TYPE: u32 = 13;
/// `IMediaSample::SetMediaType(AM_MEDIA_TYPE* pMediaType)` —
/// slot 14.
pub const SLOT_MEDIASAMPLE_SET_MEDIA_TYPE: u32 = 14;
/// `IMediaSample::GetMediaTime(LONGLONG* pStart, LONGLONG* pEnd)`
/// — slot 17.
pub const SLOT_MEDIASAMPLE_GET_MEDIA_TIME: u32 = 17;
/// `IMediaSample::SetMediaTime(LONGLONG* pStart, LONGLONG* pEnd)`
/// — slot 18.  Last method of `IMediaSample`.
pub const SLOT_MEDIASAMPLE_SET_MEDIA_TIME: u32 = 18;

/// `IMediaSample2::GetProperties(DWORD cb, BYTE* pProps)` — slot 19.
/// Round 39 — first method beyond `IMediaSample`'s vtable.
pub const SLOT_MEDIASAMPLE2_GET_PROPERTIES: u32 = 19;
/// `IMediaSample2::SetProperties(DWORD cb, const BYTE* pProps)` —
/// slot 20.  Round 39 — second method beyond `IMediaSample`'s
/// vtable.
pub const SLOT_MEDIASAMPLE2_SET_PROPERTIES: u32 = 20;

/// `IMemInputPin::GetAllocator(IMemAllocator** ppAllocator)` —
/// slot 3.  Per MSDN
/// <https://learn.microsoft.com/en-us/windows/win32/api/strmif/nf-strmif-imeminputpin-getallocator>:
/// "Retrieves the memory allocator proposed by this input pin."
/// Most input pins create their own allocator and return it
/// here; the upstream filter then calls `SetProperties` +
/// `Commit` on it, then `NotifyAllocator(this, FALSE)` to
/// confirm both ends agreed.  Returns `VFW_E_NO_ALLOCATOR` if
/// the pin has no preference.
pub const SLOT_MEMINPUTPIN_GET_ALLOCATOR: u32 = 3;
/// `IMemInputPin::NotifyAllocator(IMemAllocator*, BOOL bReadOnly)`
/// — slot 4.
pub const SLOT_MEMINPUTPIN_NOTIFY_ALLOCATOR: u32 = 4;
/// `IMemInputPin::Receive(IMediaSample*)` — slot 6.
pub const SLOT_MEMINPUTPIN_RECEIVE: u32 = 6;

/// `IPin::ReceiveConnection(IPin* pConnector, AM_MEDIA_TYPE* pmt)`
/// — slot 4.
pub const SLOT_PIN_RECEIVE_CONNECTION: u32 = 4;
/// `IPin::QueryDirection(PIN_DIRECTION*)` — slot 9. Codec-side
/// pins return `PIN_INPUT (0)` or `PIN_OUTPUT (1)`.
pub const SLOT_PIN_QUERY_DIRECTION: u32 = 9;
/// `IPin::QueryAccept(AM_MEDIA_TYPE* pmt)` — slot 11.  Returns
/// `S_OK` if the pin will accept a connection with the given
/// media type, `S_FALSE` or an error HRESULT otherwise.  Round 60
/// disassembles this method on `msadds32.ax`'s audio splitter
/// input pin to identify the AMT validation criteria its
/// internal decoder enforces.
pub const SLOT_PIN_QUERY_ACCEPT: u32 = 11;
/// `IPin::EnumMediaTypes(IEnumMediaTypes**)` — slot 12.
pub const SLOT_PIN_ENUM_MEDIA_TYPES: u32 = 12;
/// `IPin::EndOfStream()` — slot 14.  Tells a downstream pin no
/// more samples will arrive on the current segment.
pub const SLOT_PIN_END_OF_STREAM: u32 = 14;
/// `IPin::BeginFlush()` — slot 15.  Signals that subsequent
/// samples on this pin will be flushed; the receiver should
/// discard any in-flight work.
pub const SLOT_PIN_BEGIN_FLUSH: u32 = 15;
/// `IPin::EndFlush()` — slot 16.  Pairs with `BeginFlush`.
pub const SLOT_PIN_END_FLUSH: u32 = 16;
/// `IPin::NewSegment(REFERENCE_TIME start, REFERENCE_TIME stop,
/// double rate)` — slot 17.  Driven by the upstream filter at the
/// start of each playback segment; some audio decoders won't
/// process the first `Receive` until they've seen a `NewSegment`
/// to seed their internal time-base + buffer-pool initialisation.
pub const SLOT_PIN_NEW_SEGMENT: u32 = 17;

/// `IEnumPins::Next(ULONG cPins, IPin** ppPins, ULONG* pcFetched)`
/// — slot 3.
pub const SLOT_ENUMPINS_NEXT: u32 = 3;

/// `PIN_DIRECTION` enum: input pin.  Source: `strmif.h` `PINDIR_INPUT`.
pub const PIN_DIRECTION_INPUT: u32 = 0;
/// `PIN_DIRECTION` enum: output pin.
pub const PIN_DIRECTION_OUTPUT: u32 = 1;

/// `FILTER_STATE` enum value `State_Stopped = 0` (per `strmif.h`).
/// `IMediaFilter::GetState` returns this when the filter is not
/// running and not paused.
pub const FILTER_STATE_STOPPED: u32 = 0;
/// `FILTER_STATE` enum value `State_Paused = 1`.
pub const FILTER_STATE_PAUSED: u32 = 1;
/// `FILTER_STATE` enum value `State_Running = 2`.
pub const FILTER_STATE_RUNNING: u32 = 2;

/// `VFW_S_STATE_INTERMEDIATE = 0x00040003` —
/// `IMediaFilter::GetState` returns this when the filter is
/// transitioning (caller should retry, possibly with a longer
/// timeout).  See MSDN
/// <https://learn.microsoft.com/en-us/windows/win32/api/strmif/nf-strmif-imediafilter-getstate>.
pub const VFW_S_STATE_INTERMEDIATE: u32 = 0x0004_0003;
/// `VFW_S_CANT_CUE = 0x00040004` — Run() returned but the filter
/// graph could not seek; non-fatal.
pub const VFW_S_CANT_CUE: u32 = 0x0004_0004;

/// `VFW_E_NOT_COMMITTED = 0x80040209` — IMemAllocator::GetBuffer
/// returns this when the allocator has not been Commit()'d.
pub const VFW_E_NOT_COMMITTED: u32 = 0x8004_0209;
/// `VFW_E_NOT_CONNECTED = 0x80040209`'s sibling at 0x80040211 —
/// also reused by IMemAllocator::GetBuffer for "pool exhausted"
/// in our host stub (real DShow uses `VFW_E_TIMEOUT` here).
pub const VFW_E_TIMEOUT: u32 = 0x8004_0211;
/// `VFW_E_NO_ALLOCATOR = 0x80040261`.
pub const VFW_E_NO_ALLOCATOR: u32 = 0x8004_0261;

// ---- Host-side object-handle table -------------------------------------
//
// Round-25 stage 1 keeps this minimal: a counter for how many
// distinct guest interface pointers the host has handed out, and
// per-pointer reference-count bookkeeping so a leak in our
// `Release` calls would surface as a non-zero refcount at
// `Sandbox::drop`.  The counter is the total number of `AddRef`
// calls we have driven minus the total number of `Release`
// calls; once we wire `IClassFactory::CreateInstance` we will
// register every freshly-minted object here.

/// Per-object COM bookkeeping the host keeps so it can detect
/// `AddRef` / `Release` imbalances and reuse pointers across
/// `QueryInterface` calls.
#[derive(Debug, Clone)]
pub struct ComObjectInfo {
    /// Guest virtual address of the COM object (= the pointer
    /// the codec returned to us).  For multiple-interface
    /// objects, the same underlying object surfaces at multiple
    /// addresses; we treat each as its own entry.
    pub guest_addr: u32,
    /// Net AddRef–Release count we have driven.  Excludes
    /// refcount changes the codec performs internally; the
    /// host's view starts at 1 (the `CreateInstance` /
    /// `QueryInterface` returned the pointer with refcount 1
    /// per the COM ABI contract).
    pub host_refcount: i32,
    /// The IID we last asserted this object satisfies, for
    /// diagnostic logging.  `None` means "not yet probed".
    pub last_iid: Option<Guid>,
}

/// Host-side directory of COM objects the codec has handed back
/// to the test harness.  Lives inside [`crate::win32::HostState`]
/// once round-25 wires it up.  Round-25 stage 1 is the type
/// definition + lookups; stage-2 onward populates entries from
/// `CoCreateInstance` / `IClassFactory::CreateInstance` /
/// `QueryInterface` returns.
#[derive(Debug, Default, Clone)]
pub struct ComObjectTable {
    objects: std::collections::BTreeMap<u32, ComObjectInfo>,
    /// Optional in-process class-factory registrations: CLSID →
    /// guest-side IClassFactory pointer that was returned by
    /// `DllGetClassObject(CLSID, IID_IClassFactory)`.  Used by
    /// `ole32!CoCreateInstance` to satisfy the codec's request
    /// without going through SCM / the registry.
    pub class_factories: std::collections::BTreeMap<Guid, u32>,
}

impl ComObjectTable {
    /// Construct an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or look up a COM object.  Returns the existing
    /// entry when `addr` is already present (multiple
    /// `QueryInterface` calls for the same IID return the same
    /// pointer per COM ABI rules); otherwise inserts a fresh
    /// entry with refcount 1.
    pub fn intern(&mut self, addr: u32, iid: Option<Guid>) -> &mut ComObjectInfo {
        self.objects.entry(addr).or_insert(ComObjectInfo {
            guest_addr: addr,
            host_refcount: 0,
            last_iid: iid,
        })
    }

    /// Total number of distinct guest pointers the host has
    /// observed so far.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Total live host refcount across every registered object.
    pub fn total_refcount(&self) -> i32 {
        self.objects.values().map(|o| o.host_refcount).sum()
    }

    /// True iff no objects are registered.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Iterate over registered objects.
    pub fn iter(&self) -> impl Iterator<Item = (&u32, &ComObjectInfo)> {
        self.objects.iter()
    }

    /// Look up an object's host-side bookkeeping, immutable.
    pub fn get(&self, addr: u32) -> Option<&ComObjectInfo> {
        self.objects.get(&addr)
    }

    /// Look up an object's host-side bookkeeping, mutable.
    pub fn get_mut(&mut self, addr: u32) -> Option<&mut ComObjectInfo> {
        self.objects.get_mut(&addr)
    }

    /// Bump the host refcount.
    pub fn record_addref(&mut self, addr: u32) {
        if let Some(o) = self.objects.get_mut(&addr) {
            o.host_refcount = o.host_refcount.saturating_add(1);
        }
    }

    /// Drop the host refcount.  Returns the new value.
    pub fn record_release(&mut self, addr: u32) -> i32 {
        if let Some(o) = self.objects.get_mut(&addr) {
            o.host_refcount = o.host_refcount.saturating_sub(1);
            return o.host_refcount;
        }
        0
    }

    /// Register an in-process class factory under `clsid`.  The
    /// runtime calls this after a successful
    /// `DllGetClassObject(CLSID, IID_IClassFactory)`.
    pub fn register_class_factory(&mut self, clsid: Guid, factory: u32) {
        self.class_factories.insert(clsid, factory);
    }

    /// Look up a registered class factory.
    pub fn lookup_class_factory(&self, clsid: &Guid) -> Option<u32> {
        self.class_factories.get(clsid).copied()
    }
}

/// Read the vtable pointer (the first 4 bytes of a COM object).
/// COM objects are laid out as `[lpVtbl, …fields…]`; the vtable
/// itself is an array of function pointers, indexed by slot.
///
/// This is the canonical pattern for calling into a guest COM
/// object: load `[obj]` to get the vtable VA, then load
/// `[vtable + 4*slot]` to get the method's guest VA.
pub fn vtable_ptr(mmu: &Mmu, obj: u32) -> Result<u32, crate::emulator::Trap> {
    mmu.load32(obj)
}

/// Resolve a vtable slot to the guest VA of the underlying
/// method.  Returns `Err(MemoryFault)` when either dereference
/// touches an unmapped page.
pub fn method_va(mmu: &Mmu, obj: u32, slot: u32) -> Result<u32, crate::emulator::Trap> {
    let vtbl = vtable_ptr(mmu, obj)?;
    mmu.load32(vtbl.wrapping_add(slot.wrapping_mul(4)))
}

/// Free helper used by [`crate::win32::ole32::stub_co_create_instance`]:
/// search the host class-factory cache for `clsid` and report
/// whether the requested IID is one of `IUnknown`, `IClassFactory`
/// — the only IIDs `CoCreateInstance` accepts when caller passes
/// a class factory directly without an explicit `pUnkOuter`.
///
/// Returns the guest factory address on success, or `None` to
/// signal `CLASS_E_CLASSNOTAVAILABLE` to the codec.
pub fn lookup_in_process_class(table: &ComObjectTable, clsid: Guid, iid: Guid) -> Option<u32> {
    if iid != IID_IUNKNOWN && iid != IID_ICLASSFACTORY {
        return None;
    }
    table.lookup_class_factory(&clsid)
}

// ---- Cpu / Mmu glue used by `call::*` ---------------------------------
//
// `call::call_method` re-uses the existing `crate::win32::call_guest`
// to drive the vtable target.  We re-export the symbol here so
// the `com::call` submodule does not have to reach across the
// `win32` module boundary.

#[doc(hidden)]
pub(crate) fn drive_guest(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &crate::win32::Registry,
    state: &mut crate::win32::HostState,
    target: u32,
    args: &[u32],
) -> Result<u32, crate::Error> {
    crate::win32::call_guest(cpu, mmu, registry, state, target, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iunknown_braced_form() {
        let g = Guid::parse("{00000000-0000-0000-C000-000000000046}").unwrap();
        assert_eq!(g, IID_IUNKNOWN);
    }

    #[test]
    fn parse_iclassfactory_braced_form() {
        let g = Guid::parse("{00000001-0000-0000-c000-000000000046}").unwrap();
        assert_eq!(g, IID_ICLASSFACTORY);
    }

    #[test]
    fn parse_ibasefilter_braced_form() {
        let g = Guid::parse("{56A86895-0AD4-11CE-B03A-0020AF0BA770}").unwrap();
        assert_eq!(g, IID_IBASEFILTER);
    }

    #[test]
    fn msadds_audio_decoder_clsid_round_trips() {
        // Pinned by round 57 — reverse-engineered from the
        // splitter's `DllGetClassObject` CLSID table at RVA
        // `0x11000`, entry 0 → CLSID pointer at `.rdata`
        // offset `0xf248`.  See [`MSADDS_AUDIO_DECODER_CLSID`].
        let g = Guid::parse("{22E24591-49D0-11D2-BB50-006008320064}").unwrap();
        assert_eq!(g, MSADDS_AUDIO_DECODER_CLSID);
        assert_eq!(
            MSADDS_AUDIO_DECODER_CLSID.to_braced_string(),
            "{22E24591-49D0-11D2-BB50-006008320064}"
        );
    }

    #[test]
    fn msadds_audio_property_page_clsid_round_trips() {
        let g = Guid::parse("{8FE7E181-BB96-11D2-A1CB-00609778EA66}").unwrap();
        assert_eq!(g, MSADDS_AUDIO_PROPERTY_PAGE_CLSID);
        assert_eq!(
            MSADDS_AUDIO_PROPERTY_PAGE_CLSID.to_braced_string(),
            "{8FE7E181-BB96-11D2-A1CB-00609778EA66}"
        );
    }

    #[test]
    fn parse_rejects_missing_braces() {
        assert!(matches!(
            Guid::parse("00000000-0000-0000-C000-000000000046").unwrap_err(),
            GuidParseError::WrongLength { .. }
        ));
        assert!(matches!(
            Guid::parse("[00000000-0000-0000-C000-000000000046]").unwrap_err(),
            GuidParseError::MissingBraces
        ));
    }

    #[test]
    fn parse_rejects_missing_hyphen() {
        // hyphen at offset 9 missing
        let bad = "{00000000+0000-0000-C000-000000000046}";
        assert!(matches!(
            Guid::parse(bad).unwrap_err(),
            GuidParseError::MissingHyphen { at: 9 }
        ));
    }

    #[test]
    fn parse_rejects_non_hex_byte() {
        let bad = "{0000000Z-0000-0000-C000-000000000046}";
        assert!(matches!(
            Guid::parse(bad).unwrap_err(),
            GuidParseError::BadHex { .. }
        ));
    }

    #[test]
    fn write_le_round_trips_via_read_le() {
        let bytes = IID_IBASEFILTER.write_le();
        assert_eq!(Guid::read_le(&bytes), Some(IID_IBASEFILTER));
    }

    #[test]
    fn to_braced_string_matches_string_from_guid2_format() {
        // Upper-case canonical form, which is what
        // `ole32!StringFromGUID2` emits.
        assert_eq!(
            IID_IUNKNOWN.to_braced_string(),
            "{00000000-0000-0000-C000-000000000046}"
        );
        assert_eq!(
            IID_IBASEFILTER.to_braced_string(),
            "{56A86895-0AD4-11CE-B03A-0020AF0BA770}"
        );
    }

    #[test]
    fn stage_and_load_round_trip_via_mmu() {
        use crate::emulator::mmu::Perm;
        let mut mmu = Mmu::new();
        mmu.map(0x9000_0000, 0x1000, Perm::R | Perm::W);
        IID_IPIN.stage(&mut mmu, 0x9000_0000).unwrap();
        let g = Guid::load(&mmu, 0x9000_0000).unwrap();
        assert_eq!(g, IID_IPIN);
    }

    #[test]
    fn com_object_table_intern_starts_with_zero_refcount() {
        let mut t = ComObjectTable::new();
        let info = t.intern(0xCAFE_BABE, Some(IID_IUNKNOWN));
        assert_eq!(info.guest_addr, 0xCAFE_BABE);
        assert_eq!(info.host_refcount, 0);
        assert_eq!(info.last_iid, Some(IID_IUNKNOWN));
    }

    #[test]
    fn com_object_table_addref_release_balance() {
        let mut t = ComObjectTable::new();
        t.intern(0x1000, None);
        t.record_addref(0x1000);
        t.record_addref(0x1000);
        assert_eq!(t.total_refcount(), 2);
        let now = t.record_release(0x1000);
        assert_eq!(now, 1);
        let now = t.record_release(0x1000);
        assert_eq!(now, 0);
        assert_eq!(t.total_refcount(), 0);
    }

    #[test]
    fn com_object_table_register_and_lookup_class_factory() {
        let mut t = ComObjectTable::new();
        let clsid = Guid::parse("{4F03ADBE-9F75-4970-B9C8-EAB6A2E0EE96}").unwrap();
        t.register_class_factory(clsid, 0x1234_5678);
        assert_eq!(t.lookup_class_factory(&clsid), Some(0x1234_5678));
        let other = Guid::parse("{00000000-0000-0000-C000-000000000046}").unwrap();
        assert_eq!(t.lookup_class_factory(&other), None);
    }

    #[test]
    fn lookup_in_process_class_only_for_iunknown_or_iclassfactory() {
        let mut t = ComObjectTable::new();
        let clsid = Guid::parse("{4F03ADBE-9F75-4970-B9C8-EAB6A2E0EE96}").unwrap();
        t.register_class_factory(clsid, 0xAA);
        assert_eq!(lookup_in_process_class(&t, clsid, IID_IUNKNOWN), Some(0xAA));
        assert_eq!(
            lookup_in_process_class(&t, clsid, IID_ICLASSFACTORY),
            Some(0xAA)
        );
        assert_eq!(lookup_in_process_class(&t, clsid, IID_IBASEFILTER), None);
    }
}
