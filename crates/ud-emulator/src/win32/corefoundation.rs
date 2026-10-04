//! `CoreFoundation.dll` (Apple's CF port for Windows) stubs.
//!
//! Apple's QuickTime 7.7.9 for Windows ships CF as part of the
//! Apple Application Support installer. qts/qtcf reach it via
//! `LoadLibraryA("CoreFoundation.dll")` + `GetProcAddress` —
//! it's never a static import. Real CF's DllMain on Windows
//! drags in libdispatch and ICU, and that chain crashes our
//! vanilla PE loader (write-protect violations between
//! libdispatch and libicuuc, then a final ret-to-stack-address
//! out of CF's `_DllMainCRTStartup` after ICU's string init).
//!
//! Rather than emulate that whole framework convention we
//! host-stub the small surface qtcf actually calls. The PE
//! loader skips loading CF (via [`crate::win32::is_host_stub_dll`])
//! and the synthetic handle pre-seeded in
//! [`crate::Sandbox::new`]'s `state.modules` lets
//! `GetModuleHandleA("CoreFoundation.dll")` return non-NULL.
//! `GetProcAddress` then resolves names through this stub set.
//!
//! Reference: Apple's open-source CF (libraries `kCFAllocator*`,
//! `CFString*`, `CFArray*`, `CFDictionary*`, `CFNumber*`,
//! `CFRunLoop*`, `CFType*`) —
//! `https://opensource.apple.com/source/CF/`.

use super::{HostState, Registry, StubFn, Win32Error, arg_dword};
use crate::emulator::{Cpu, Mmu};

/// Magic word that lives at the head of every synthetic CF
/// allocation. Lets a future stub check "is this pointer a
/// CFTypeRef we minted?" without keeping a side table.
const CF_TAG: u32 = 0x4346_5453; // "CFTS"

/// Synthetic [`CFTypeID`] values handed back by `CFGetTypeID`.
/// Apple's headers don't promise these are stable across
/// releases, so any unique non-zero integer suffices.
const CF_TYPE_ID_STRING: u32 = 0x0001;
const CF_TYPE_ID_NUMBER: u32 = 0x0002;
const CF_TYPE_ID_BOOLEAN: u32 = 0x0003;
const CF_TYPE_ID_DICTIONARY: u32 = 0x0004;
const CF_TYPE_ID_ARRAY: u32 = 0x0005;
const CF_TYPE_ID_DATE: u32 = 0x0006;
const CF_TYPE_ID_DATA: u32 = 0x0007;
const CF_TYPE_ID_URL: u32 = 0x0008;
const CF_TYPE_ID_BUNDLE: u32 = 0x0009;
const CF_TYPE_ID_UUID: u32 = 0x000A;

/// Register every CoreFoundation host stub.
pub fn register(registry: &mut Registry) {
    let dll = "corefoundation.dll";

    // ---- Allocators ------------------------------------------------
    registry.register_data(dll, "kCFAllocatorDefault", 0);
    registry.register_data(dll, "kCFAllocatorSystemDefault", 0);
    registry.register_data(dll, "kCFAllocatorMalloc", 0);
    registry.register_data(dll, "kCFAllocatorMallocZone", 0);
    registry.register_data(dll, "kCFAllocatorNull", 0);
    registry.register_data(dll, "kCFAllocatorUseContext", 0);
    registry.register(
        dll,
        "CFAllocatorAllocate",
        stub_allocator_allocate as StubFn,
        0,
    );
    registry.register(dll, "CFAllocatorDeallocate", stub_zero as StubFn, 0);
    registry.register(dll, "CFAllocatorGetDefault", stub_returns_zero as StubFn, 0);
    registry.register(
        dll,
        "CFAllocatorGetTypeID",
        stub_type_id_string as StubFn,
        0,
    );

    // ---- Strings ---------------------------------------------------
    registry.register(
        dll,
        "__CFStringMakeConstantString",
        stub_make_constant_string as StubFn,
        0,
    );
    registry.register(
        dll,
        "CFStringCreateWithCString",
        stub_string_create as StubFn,
        0,
    );
    registry.register(
        dll,
        "CFStringCreateWithCStringNoCopy",
        stub_string_create as StubFn,
        0,
    );
    registry.register(
        dll,
        "CFStringCreateWithCharacters",
        stub_string_create as StubFn,
        0,
    );
    registry.register(
        dll,
        "CFStringCreateWithBytes",
        stub_string_create as StubFn,
        0,
    );
    registry.register(dll, "CFStringCreateCopy", stub_returns_arg1 as StubFn, 0);
    registry.register(dll, "CFStringGetTypeID", stub_type_id_string as StubFn, 0);
    registry.register(dll, "CFStringGetLength", stub_returns_zero as StubFn, 0);
    registry.register(dll, "CFStringGetCStringPtr", stub_returns_zero as StubFn, 0);
    registry.register(
        dll,
        "CFStringGetCString",
        stub_string_get_cstring as StubFn,
        0,
    );
    registry.register(dll, "CFStringCompare", stub_returns_zero as StubFn, 0);

    // ---- Numbers / Booleans ---------------------------------------
    registry.register_data(dll, "kCFBooleanTrue", 0);
    registry.register_data(dll, "kCFBooleanFalse", 0);
    registry.register(dll, "CFNumberCreate", stub_string_create as StubFn, 0);
    registry.register(dll, "CFNumberGetTypeID", stub_type_id_number as StubFn, 0);
    registry.register(dll, "CFBooleanGetTypeID", stub_type_id_boolean as StubFn, 0);
    registry.register(dll, "CFNumberGetValue", stub_zero as StubFn, 0);

    // ---- Dictionary / Array ---------------------------------------
    registry.register_data(dll, "kCFTypeDictionaryKeyCallBacks", 0);
    registry.register_data(dll, "kCFTypeDictionaryValueCallBacks", 0);
    registry.register_data(dll, "kCFCopyStringDictionaryKeyCallBacks", 0);
    registry.register_data(dll, "kCFTypeArrayCallBacks", 0);
    registry.register(dll, "CFDictionaryCreate", stub_string_create as StubFn, 0);
    registry.register(
        dll,
        "CFDictionaryCreateMutable",
        stub_string_create as StubFn,
        0,
    );
    registry.register(dll, "CFDictionaryGetValue", stub_returns_zero as StubFn, 0);
    registry.register(dll, "CFDictionarySetValue", stub_zero as StubFn, 0);
    registry.register(dll, "CFDictionaryAddValue", stub_zero as StubFn, 0);
    registry.register(
        dll,
        "CFDictionaryGetTypeID",
        stub_type_id_dictionary as StubFn,
        0,
    );
    registry.register(dll, "CFArrayCreate", stub_string_create as StubFn, 0);
    registry.register(dll, "CFArrayCreateMutable", stub_string_create as StubFn, 0);
    registry.register(dll, "CFArrayAppendValue", stub_zero as StubFn, 0);
    registry.register(dll, "CFArrayGetCount", stub_returns_zero as StubFn, 0);
    registry.register(
        dll,
        "CFArrayGetValueAtIndex",
        stub_returns_zero as StubFn,
        0,
    );
    registry.register(dll, "CFArrayGetTypeID", stub_type_id_array as StubFn, 0);

    // ---- Data ------------------------------------------------------
    registry.register(dll, "CFDataCreate", stub_string_create as StubFn, 0);
    registry.register(
        dll,
        "CFDataCreateWithBytesNoCopy",
        stub_string_create as StubFn,
        0,
    );
    registry.register(dll, "CFDataGetBytePtr", stub_returns_zero as StubFn, 0);
    registry.register(dll, "CFDataGetLength", stub_returns_zero as StubFn, 0);
    registry.register(dll, "CFDataGetTypeID", stub_type_id_data as StubFn, 0);

    // ---- Date ------------------------------------------------------
    registry.register(dll, "CFDateCreate", stub_string_create as StubFn, 0);
    registry.register(dll, "CFDateGetTypeID", stub_type_id_date as StubFn, 0);

    // ---- URL -------------------------------------------------------
    registry.register(
        dll,
        "CFURLCreateWithString",
        stub_string_create as StubFn,
        0,
    );
    registry.register(
        dll,
        "CFURLCreateWithFileSystemPath",
        stub_string_create as StubFn,
        0,
    );
    registry.register(dll, "CFURLGetTypeID", stub_type_id_url as StubFn, 0);

    // ---- UUID / Bundle --------------------------------------------
    registry.register(dll, "CFUUIDCreate", stub_string_create as StubFn, 0);
    registry.register(dll, "CFUUIDGetTypeID", stub_type_id_uuid as StubFn, 0);
    registry.register(dll, "CFBundleCreate", stub_string_create as StubFn, 0);
    registry.register(dll, "CFBundleGetMainBundle", stub_returns_zero as StubFn, 0);
    registry.register(
        dll,
        "CFBundleGetBundleWithIdentifier",
        stub_returns_zero as StubFn,
        0,
    );
    registry.register(dll, "CFBundleCopyBundleURL", stub_returns_zero as StubFn, 0);
    registry.register(dll, "CFBundleGetTypeID", stub_type_id_bundle as StubFn, 0);

    // ---- Generic CFType -------------------------------------------
    registry.register(dll, "CFRetain", stub_returns_arg0 as StubFn, 0);
    registry.register(dll, "CFRelease", stub_zero as StubFn, 0);
    registry.register(dll, "CFGetRetainCount", stub_returns_one as StubFn, 0);
    registry.register(dll, "CFGetTypeID", stub_type_id_string as StubFn, 0);
    registry.register(
        dll,
        "CFCopyTypeIDDescription",
        stub_string_create as StubFn,
        0,
    );
    registry.register(dll, "CFEqual", stub_cf_equal as StubFn, 0);
    registry.register(dll, "CFHash", stub_returns_zero as StubFn, 0);

    // ---- RunLoop (no-op) ------------------------------------------
    registry.register(dll, "CFRunLoopGetCurrent", stub_returns_one as StubFn, 0);
    registry.register(dll, "CFRunLoopGetMain", stub_returns_one as StubFn, 0);
    registry.register(dll, "CFRunLoopRun", stub_zero as StubFn, 0);
    registry.register(dll, "CFRunLoopStop", stub_zero as StubFn, 0);
    registry.register(dll, "CFRunLoopRunInMode", stub_returns_one as StubFn, 0);

    // ---- Preferences (return NULL — no plist) ---------------------
    registry.register(
        dll,
        "CFPreferencesCopyAppValue",
        stub_returns_zero as StubFn,
        0,
    );
    registry.register(dll, "CFPreferencesSetAppValue", stub_zero as StubFn, 0);
    registry.register(dll, "CFPreferencesAppSynchronize", stub_zero as StubFn, 0);

    // ---- Locale / Timezone (return NULL — formatter takes default) -
    registry.register(dll, "CFLocaleCopyCurrent", stub_returns_zero as StubFn, 0);
    registry.register(dll, "CFTimeZoneCopySystem", stub_returns_zero as StubFn, 0);

    // ---- Notification center (no-op) ------------------------------
    registry.register(
        dll,
        "CFNotificationCenterGetLocalCenter",
        stub_returns_one as StubFn,
        0,
    );
    registry.register(
        dll,
        "CFNotificationCenterAddObserver",
        stub_zero as StubFn,
        0,
    );
    registry.register(
        dll,
        "CFNotificationCenterRemoveObserver",
        stub_zero as StubFn,
        0,
    );
    registry.register(
        dll,
        "CFNotificationCenterPostNotification",
        stub_zero as StubFn,
        0,
    );
}

// ---- stubs --------------------------------------------------------

/// Allocate a synthetic `CFTypeRef` from the heap arena, big
/// enough to hold the CF magic tag and a type id.
fn synth_cf_object(state: &mut HostState, mmu: &mut Mmu, type_id: u32) -> Result<u32, Win32Error> {
    let addr = state.arena_alloc(16)?;
    mmu.store32(addr, CF_TAG)
        .map_err(|t| super::trap_to_win32_local("CF synth_object", t))?;
    mmu.store32(addr.wrapping_add(4), type_id)
        .map_err(|t| super::trap_to_win32_local("CF synth_object", t))?;
    Ok(addr)
}

/// `CFStringRef __CFStringMakeConstantString(const char *cstr)`.
/// Real CF interns the string in a process-wide cache; the
/// analyser doesn't need that — return a fresh synthetic
/// CFStringRef every call. qtcf/qts treat the result as opaque.
fn stub_make_constant_string(
    _cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    synth_cf_object(state, mmu, CF_TYPE_ID_STRING)
}

/// Generic factory for the typed CF*Create family. Returns a
/// fresh synthetic CFTypeRef; callers never inspect the contents.
fn stub_string_create(
    _cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    synth_cf_object(state, mmu, CF_TYPE_ID_STRING)
}

/// `void *CFAllocatorAllocate(CFAllocatorRef, CFIndex size, CFOptionFlags)`.
/// Delegate to the heap arena.
fn stub_allocator_allocate(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _alloc =
        arg_dword(cpu, mmu, 0).map_err(|t| super::trap_to_win32_local("CFAllocatorAllocate", t))?;
    let size =
        arg_dword(cpu, mmu, 1).map_err(|t| super::trap_to_win32_local("CFAllocatorAllocate", t))?;
    if size == 0 {
        return Ok(0);
    }
    let addr = state.arena_alloc(size)?;
    Ok(addr)
}

/// `Boolean CFStringGetCString(CFStringRef, char *buffer, CFIndex max, CFStringEncoding)`.
/// Write an empty C string into the buffer and return TRUE so
/// callers fall through to the "got a name" path with `strlen` 0.
fn stub_string_get_cstring(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let buf =
        arg_dword(cpu, mmu, 1).map_err(|t| super::trap_to_win32_local("CFStringGetCString", t))?;
    if buf != 0 {
        mmu.store8(buf, 0)
            .map_err(|t| super::trap_to_win32_local("CFStringGetCString", t))?;
    }
    Ok(1)
}

/// `Boolean CFEqual(CFTypeRef a, CFTypeRef b)`. Pointer equality
/// suffices for the synthetic objects we hand out.
fn stub_cf_equal(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let a = arg_dword(cpu, mmu, 0).map_err(|t| super::trap_to_win32_local("CFEqual", t))?;
    let b = arg_dword(cpu, mmu, 1).map_err(|t| super::trap_to_win32_local("CFEqual", t))?;
    Ok(if a == b { 1 } else { 0 })
}

// ---- generic helpers ----------------------------------------------

fn stub_zero(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

fn stub_returns_zero(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

fn stub_returns_one(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

fn stub_returns_arg0(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    arg_dword(cpu, mmu, 0).map_err(|t| super::trap_to_win32_local("CF stub", t))
}

fn stub_returns_arg1(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    arg_dword(cpu, mmu, 1).map_err(|t| super::trap_to_win32_local("CF stub", t))
}

fn stub_type_id_string(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_STRING)
}

fn stub_type_id_number(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_NUMBER)
}

fn stub_type_id_boolean(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_BOOLEAN)
}

fn stub_type_id_dictionary(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_DICTIONARY)
}

fn stub_type_id_array(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_ARRAY)
}

fn stub_type_id_date(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_DATE)
}

fn stub_type_id_data(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_DATA)
}

fn stub_type_id_url(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_URL)
}

fn stub_type_id_uuid(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_UUID)
}

fn stub_type_id_bundle(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(CF_TYPE_ID_BUNDLE)
}
