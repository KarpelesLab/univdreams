//! `kernel32.dll` stubs — the minimum surface a Cinepak-class
//! codec DLL imports.
//!
//! Round-1 set per design doc §"`kernel32.dll` essentials" and
//! §"Milestone 1":
//!
//! * `GetProcessHeap`
//! * `HeapAlloc`, `HeapFree`, `HeapReAlloc`
//! * `LocalAlloc`, `LocalFree`
//! * `OutputDebugStringA`
//! * `GetTickCount`
//! * `InterlockedIncrement`, `InterlockedDecrement`
//! * `LoadLibraryA`, `GetProcAddress`
//!
//! Round-4 adds the additional 24 `kernel32` stubs an Indeo 3
//! class DLL imports through its CRT init: `ExitProcess`,
//! `GetACP` / `GetOEMCP` / `GetCPInfo`, `GetCommandLineA`,
//! `GetEnvironmentStrings`, `GetFileType`, `GetLastError` /
//! `SetLastError`, `GetModuleFileNameA` / `GetModuleHandleA`,
//! `GetStartupInfoA` / `GetStdHandle` / `GetSystemInfo` /
//! `GetVersion`, `GlobalAlloc` / `GlobalFree` / `GlobalLock` /
//! `GlobalUnlock`, `MultiByteToWideChar` / `WideCharToMultiByte`,
//! `RtlUnwind`, `VirtualAlloc` / `VirtualFree`, `WriteFile`.
//!
//! Each stub references its MSDN page in a comment for review;
//! the implementations honour the public contract (return
//! values, error semantics, side effects on `lastError`).

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::mmu::{Perm, PAGE_SIZE};
use crate::emulator::{Cpu, Mmu};

/// Register every kernel32 stub into `registry`.
pub fn register(registry: &mut Registry) {
    // The list mirrors the design doc §Milestone 1; comments
    // cite the MSDN page.

    // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap
    registry.register(
        "kernel32.dll",
        "GetProcessHeap",
        stub_get_process_heap as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
    registry.register("kernel32.dll", "HeapAlloc", stub_heap_alloc as StubFn, 3);
    // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree
    registry.register("kernel32.dll", "HeapFree", stub_heap_free as StubFn, 3);
    // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc
    registry.register(
        "kernel32.dll",
        "HeapReAlloc",
        stub_heap_realloc as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapsize
    // Round 15 — IR41_32.AX uses HeapSize to query the live size
    // of an allocation it returned from HeapAlloc / HeapReAlloc.
    registry.register("kernel32.dll", "HeapSize", stub_heap_size as StubFn, 3);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc
    registry.register("kernel32.dll", "LocalAlloc", stub_local_alloc as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree
    registry.register("kernel32.dll", "LocalFree", stub_local_free as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-outputdebugstringa
    registry.register(
        "kernel32.dll",
        "OutputDebugStringA",
        stub_output_debug_string_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount
    registry.register(
        "kernel32.dll",
        "GetTickCount",
        stub_get_tick_count as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-interlockedincrement
    registry.register(
        "kernel32.dll",
        "InterlockedIncrement",
        stub_interlocked_increment as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-interlockeddecrement
    registry.register(
        "kernel32.dll",
        "InterlockedDecrement",
        stub_interlocked_decrement as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
    registry.register(
        "kernel32.dll",
        "LoadLibraryA",
        stub_load_library_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    registry.register(
        "kernel32.dll",
        "GetProcAddress",
        stub_get_proc_address as StubFn,
        2,
    );

    // ---- Round-4 additions (24 stubs) -----------------------------

    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess
    registry.register(
        "kernel32.dll",
        "ExitProcess",
        stub_exit_process as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getacp
    registry.register("kernel32.dll", "GetACP", stub_get_acp as StubFn, 0);
    // https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getoemcp
    registry.register("kernel32.dll", "GetOEMCP", stub_get_oem_cp as StubFn, 0);
    // https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getcpinfo
    registry.register("kernel32.dll", "GetCPInfo", stub_get_cp_info as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinea
    registry.register(
        "kernel32.dll",
        "GetCommandLineA",
        stub_get_command_line_a as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentstrings
    registry.register(
        "kernel32.dll",
        "GetEnvironmentStrings",
        stub_get_environment_strings as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype
    registry.register(
        "kernel32.dll",
        "GetFileType",
        stub_get_file_type as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
    registry.register(
        "kernel32.dll",
        "GetLastError",
        stub_get_last_error as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setlasterror
    registry.register(
        "kernel32.dll",
        "SetLastError",
        stub_set_last_error as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamea
    registry.register(
        "kernel32.dll",
        "GetModuleFileNameA",
        stub_get_module_file_name_a as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
    registry.register(
        "kernel32.dll",
        "GetModuleHandleA",
        stub_get_module_handle_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getstartupinfoa
    registry.register(
        "kernel32.dll",
        "GetStartupInfoA",
        stub_get_startup_info_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getstdhandle
    registry.register(
        "kernel32.dll",
        "GetStdHandle",
        stub_get_std_handle as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo
    registry.register(
        "kernel32.dll",
        "GetSystemInfo",
        stub_get_system_info as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversion
    registry.register("kernel32.dll", "GetVersion", stub_get_version as StubFn, 0);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalalloc
    registry.register(
        "kernel32.dll",
        "GlobalAlloc",
        stub_global_alloc as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalfree
    registry.register("kernel32.dll", "GlobalFree", stub_global_free as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globallock
    registry.register("kernel32.dll", "GlobalLock", stub_global_lock as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalunlock
    registry.register(
        "kernel32.dll",
        "GlobalUnlock",
        stub_global_unlock as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
    registry.register(
        "kernel32.dll",
        "MultiByteToWideChar",
        stub_multi_byte_to_wide_char as StubFn,
        6,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte
    registry.register(
        "kernel32.dll",
        "WideCharToMultiByte",
        stub_wide_char_to_multi_byte as StubFn,
        8,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind
    registry.register("kernel32.dll", "RtlUnwind", stub_rtl_unwind as StubFn, 4);
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    registry.register(
        "kernel32.dll",
        "VirtualAlloc",
        stub_virtual_alloc as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
    registry.register(
        "kernel32.dll",
        "VirtualFree",
        stub_virtual_free as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
    registry.register("kernel32.dll", "WriteFile", stub_write_file as StubFn, 5);

    // ---- Round-8 additions (IR50_32.DLL needs) --------------------
    //
    // Most of these are fail-soft "the DLL imports it but the
    // decode path doesn't actually exercise it". Each returns the
    // canonical "no-op success" / "no error" value per MSDN.

    // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    registry.register(
        "kernel32.dll",
        "CloseHandle",
        stub_close_handle as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
    registry.register(
        "kernel32.dll",
        "CreateFileMappingA",
        stub_create_file_mapping_a as StubFn,
        6,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createsemaphorea
    registry.register(
        "kernel32.dll",
        "CreateSemaphoreA",
        stub_create_semaphore_a as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-deletecriticalsection
    registry.register(
        "kernel32.dll",
        "DeleteCriticalSection",
        stub_delete_critical_section as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls
    registry.register(
        "kernel32.dll",
        "DisableThreadLibraryCalls",
        stub_disable_thread_library_calls as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection
    registry.register(
        "kernel32.dll",
        "EnterCriticalSection",
        stub_enter_critical_section as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-leavecriticalsection
    registry.register(
        "kernel32.dll",
        "LeaveCriticalSection",
        stub_leave_critical_section as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection
    registry.register(
        "kernel32.dll",
        "InitializeCriticalSection",
        stub_initialize_critical_section as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourcea
    registry.register(
        "kernel32.dll",
        "FindResourceA",
        stub_find_resource_a as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
    registry.register(
        "kernel32.dll",
        "FlushFileBuffers",
        stub_flush_file_buffers as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-freeenvironmentstringsa
    registry.register(
        "kernel32.dll",
        "FreeEnvironmentStringsA",
        stub_free_environment_strings as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-freeenvironmentstringsw
    registry.register(
        "kernel32.dll",
        "FreeEnvironmentStringsW",
        stub_free_environment_strings as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary
    registry.register(
        "kernel32.dll",
        "FreeLibrary",
        stub_free_library as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freeresource
    registry.register(
        "kernel32.dll",
        "FreeResource",
        stub_free_resource as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
    registry.register(
        "kernel32.dll",
        "GetCurrentProcess",
        stub_get_current_process as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid
    registry.register(
        "kernel32.dll",
        "GetCurrentThreadId",
        stub_get_current_thread_id as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentstringsw
    registry.register(
        "kernel32.dll",
        "GetEnvironmentStringsW",
        stub_get_environment_strings_w as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getlocaleinfoa
    registry.register(
        "kernel32.dll",
        "GetLocaleInfoA",
        stub_get_locale_info_a as StubFn,
        4,
    );
    registry.register(
        "kernel32.dll",
        "GetLocaleInfoW",
        stub_get_locale_info_a as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getshortpathnamea
    registry.register(
        "kernel32.dll",
        "GetShortPathNameA",
        stub_get_short_path_name_a as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getstringtypea
    registry.register(
        "kernel32.dll",
        "GetStringTypeA",
        stub_get_string_type as StubFn,
        5,
    );
    registry.register(
        "kernel32.dll",
        "GetStringTypeW",
        stub_get_string_type as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya
    registry.register(
        "kernel32.dll",
        "GetSystemDirectoryA",
        stub_get_system_directory_a as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexa
    registry.register(
        "kernel32.dll",
        "GetVersionExA",
        stub_get_version_ex_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalhandle
    registry.register(
        "kernel32.dll",
        "GlobalHandle",
        stub_global_handle as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalrealloc
    registry.register(
        "kernel32.dll",
        "GlobalReAlloc",
        stub_global_realloc as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate
    registry.register("kernel32.dll", "HeapCreate", stub_heap_create as StubFn, 3);
    // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapdestroy
    registry.register(
        "kernel32.dll",
        "HeapDestroy",
        stub_heap_destroy as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-isbadcodeptr
    registry.register("kernel32.dll", "IsBadCodePtr", stub_is_bad_ptr as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-isbadreadptr
    registry.register("kernel32.dll", "IsBadReadPtr", stub_is_bad_ptr as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-isbadwriteptr
    registry.register(
        "kernel32.dll",
        "IsBadWritePtr",
        stub_is_bad_ptr as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-lcmapstringa
    registry.register(
        "kernel32.dll",
        "LCMapStringA",
        stub_lc_map_string as StubFn,
        6,
    );
    registry.register(
        "kernel32.dll",
        "LCMapStringW",
        stub_lc_map_string as StubFn,
        6,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource
    registry.register(
        "kernel32.dll",
        "LoadResource",
        stub_load_resource as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localhandle
    registry.register(
        "kernel32.dll",
        "LocalHandle",
        stub_local_handle as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-locallock
    registry.register("kernel32.dll", "LocalLock", stub_local_lock as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localunlock
    registry.register(
        "kernel32.dll",
        "LocalUnlock",
        stub_local_unlock as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-lockresource
    registry.register(
        "kernel32.dll",
        "LockResource",
        stub_lock_resource as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource
    // Round 13 — round 12 added the impl with `#[allow(dead_code)]`
    // because IR50_32.DLL doesn't import it. Now wired into the
    // dispatch registry so future codecs that DO import it pick
    // up a real implementation rather than tripping the
    // unresolved-import trap.
    registry.register(
        "kernel32.dll",
        "SizeofResource",
        stub_sizeof_resource as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
    registry.register(
        "kernel32.dll",
        "MapViewOfFile",
        stub_map_view_of_file as StubFn,
        5,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilemappinga
    registry.register(
        "kernel32.dll",
        "OpenFileMappingA",
        stub_open_file_mapping_a as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter
    registry.register(
        "kernel32.dll",
        "QueryPerformanceCounter",
        stub_query_performance_counter as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency
    registry.register(
        "kernel32.dll",
        "QueryPerformanceFrequency",
        stub_query_performance_frequency as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raiseexception
    registry.register(
        "kernel32.dll",
        "RaiseException",
        stub_raise_exception as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-releasesemaphore
    registry.register(
        "kernel32.dll",
        "ReleaseSemaphore",
        stub_release_semaphore as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointer
    registry.register(
        "kernel32.dll",
        "SetFilePointer",
        stub_set_file_pointer as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-sethandlecount
    registry.register(
        "kernel32.dll",
        "SetHandleCount",
        stub_set_handle_count as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-setstdhandle
    registry.register(
        "kernel32.dll",
        "SetStdHandle",
        stub_set_std_handle as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
    registry.register(
        "kernel32.dll",
        "SetUnhandledExceptionFilter",
        stub_set_unhandled_exception_filter as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep
    registry.register("kernel32.dll", "Sleep", stub_sleep as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
    registry.register(
        "kernel32.dll",
        "TerminateProcess",
        stub_terminate_process as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsalloc
    registry.register("kernel32.dll", "TlsAlloc", stub_tls_alloc as StubFn, 0);
    registry.register("kernel32.dll", "TlsFree", stub_tls_free as StubFn, 1);
    registry.register(
        "kernel32.dll",
        "TlsGetValue",
        stub_tls_get_value as StubFn,
        1,
    );
    registry.register(
        "kernel32.dll",
        "TlsSetValue",
        stub_tls_set_value as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile
    registry.register(
        "kernel32.dll",
        "UnmapViewOfFile",
        stub_unmap_view_of_file as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    registry.register(
        "kernel32.dll",
        "WaitForSingleObject",
        stub_wait_for_single_object as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-writeprivateprofilestringa
    registry.register(
        "kernel32.dll",
        "WritePrivateProfileStringA",
        stub_write_private_profile_string_a as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrlena
    registry.register("kernel32.dll", "lstrlenA", stub_lstrlen_a as StubFn, 1);

    // ---- Round-20 additions (mpg4c32.dll DllMain reach) -----------
    //
    // Per `docs/winmf/winmf-emulator.md` §"Milestone 3.1". The
    // MSMPEG4 v3 codec adds a thread-creation surface its
    // C++ runtime touches at static-init time; because our
    // sandbox is single-threaded, `CreateThread` is implemented
    // synchronously (call the start address, return a fake
    // HANDLE).
    //
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa
    registry.register(
        "kernel32.dll",
        "CreateEventA",
        stub_create_event_a as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
    registry.register(
        "kernel32.dll",
        "CreateThread",
        stub_create_thread as StubFn,
        6,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitthread
    registry.register("kernel32.dll", "ExitThread", stub_exit_thread as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setevent
    registry.register("kernel32.dll", "SetEvent", stub_set_event as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority
    // Single-threaded sandbox — no-op TRUE. Pre-emptively
    // registered (mpg4ds32.ax / msadds32.ax both import it).
    registry.register(
        "kernel32.dll",
        "SetThreadPriority",
        stub_set_thread_priority as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
    registry.register(
        "kernel32.dll",
        "ResumeThread",
        stub_resume_thread as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-muldiv
    registry.register("kernel32.dll", "MulDiv", stub_muldiv as StubFn, 3);
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprofileinta
    registry.register(
        "kernel32.dll",
        "GetProfileIntA",
        stub_get_profile_int_a as StubFn,
        3,
    );

    // ----- Corpus-driven additions ----------------------------------
    // Stubs added in response to the codec-corpus test
    // (`tests/codec_corpus.rs`) showing high-frequency
    // unresolved-import counts. Each entry below was missing
    // from ≥6 codecs in the manifest; closing them unblocks
    // those codecs' `Sandbox::load`.

    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
    registry.register(
        "kernel32.dll",
        "GetCurrentProcessId",
        stub_get_current_process_id as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime
    registry.register(
        "kernel32.dll",
        "GetSystemTimeAsFileTime",
        stub_get_system_time_as_file_time as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread
    registry.register(
        "kernel32.dll",
        "GetCurrentThread",
        stub_get_current_thread as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-interlockedexchange
    registry.register(
        "kernel32.dll",
        "InterlockedExchange",
        stub_interlocked_exchange as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-interlockedcompareexchange
    registry.register(
        "kernel32.dll",
        "InterlockedCompareExchange",
        stub_interlocked_compare_exchange as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter
    registry.register(
        "kernel32.dll",
        "UnhandledExceptionFilter",
        stub_unhandled_exception_filter as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode
    registry.register(
        "kernel32.dll",
        "SetErrorMode",
        stub_set_error_mode as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-resetevent
    registry.register("kernel32.dll", "ResetEvent", stub_reset_event as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjects
    registry.register(
        "kernel32.dll",
        "WaitForMultipleObjects",
        stub_wait_for_multiple_objects as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw
    registry.register(
        "kernel32.dll",
        "CreateEventW",
        stub_create_event_w as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createsemaphorew
    registry.register(
        "kernel32.dll",
        "CreateSemaphoreW",
        stub_create_semaphore_w as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlocaltime
    registry.register(
        "kernel32.dll",
        "GetLocalTime",
        stub_get_local_time as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew
    registry.register(
        "kernel32.dll",
        "GetModuleHandleW",
        stub_get_module_handle_w as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprivateprofileinta
    registry.register(
        "kernel32.dll",
        "GetPrivateProfileIntA",
        stub_get_private_profile_int_a as StubFn,
        4,
    );
    // `DelayLoadFailureHook` — DELAYLOAD glue called by the
    // VC++ delay-load helper when an import resolves at run
    // time. Synthetic stub returns 0 (loader treats this as
    // "handled"). https://learn.microsoft.com/en-us/cpp/build/reference/error-handling-and-notification
    registry.register(
        "kernel32.dll",
        "DelayLoadFailureHook",
        stub_delay_load_failure_hook as StubFn,
        2,
    );

    // ---- Corpus round 2 --------------------------------------------
    registry.register(
        "kernel32.dll",
        "GetVersionExW",
        stub_get_version_ex_w as StubFn,
        1,
    );
    registry.register(
        "kernel32.dll",
        "SignalObjectAndWait",
        stub_signal_object_and_wait as StubFn,
        4,
    );
    registry.register(
        "kernel32.dll",
        "InitializeCriticalSectionAndSpinCount",
        stub_init_cs_spin as StubFn,
        2,
    );
    registry.register(
        "kernel32.dll",
        "IsDebuggerPresent",
        stub_is_debugger_present as StubFn,
        0,
    );
    registry.register(
        "kernel32.dll",
        "VirtualProtect",
        stub_virtual_protect as StubFn,
        4,
    );
    registry.register(
        "kernel32.dll",
        "InterlockedExchangeAdd",
        stub_interlocked_exchange_add as StubFn,
        2,
    );
    registry.register(
        "kernel32.dll",
        "GetComputerNameA",
        stub_get_computer_name_a as StubFn,
        2,
    );
    registry.register(
        "kernel32.dll",
        "GetEnvironmentVariableW",
        stub_get_environment_variable_w as StubFn,
        3,
    );
    registry.register(
        "kernel32.dll",
        "GetProcessAffinityMask",
        stub_get_process_affinity_mask as StubFn,
        3,
    );
    registry.register(
        "kernel32.dll",
        "GetThreadPriority",
        stub_get_thread_priority as StubFn,
        1,
    );
    registry.register(
        "kernel32.dll",
        "SetThreadAffinityMask",
        stub_set_thread_affinity_mask as StubFn,
        2,
    );
    registry.register(
        "kernel32.dll",
        "LoadLibraryW",
        stub_load_library_w as StubFn,
        1,
    );
    registry.register("kernel32.dll", "ReadFile", stub_read_file as StubFn, 5);

    // ---- Codec-corpus probe additions --------------------------
    //
    // The 30 stubs below close the kernel32 import gap for the
    // VfW codecs whose `ICOpen` probe was previously blocked by
    // unresolved imports: Cinepak (`iccvid`), Indeo Audio
    // (`IAC25`), HuffYUV, Lagarith, MagicYUV. Most are pulled in
    // by CRT startup or the codec's config-dialog path — not the
    // decode core — so they are fail-soft by design.

    // lstrcat / lstrcpy / lstrcmpi — kernel32's string helpers.
    registry.register("kernel32.dll", "lstrcatA", stub_lstrcat_a as StubFn, 2);
    registry.register("kernel32.dll", "lstrcpyA", stub_lstrcpy_a as StubFn, 2);
    registry.register("kernel32.dll", "lstrcmpiA", stub_lstrcmpi_a as StubFn, 2);
    // CompareString — locale-aware string compare (CRT collate).
    registry.register(
        "kernel32.dll",
        "CompareStringA",
        stub_compare_string_a as StubFn,
        6,
    );
    registry.register(
        "kernel32.dll",
        "CompareStringW",
        stub_compare_string_w as StubFn,
        6,
    );
    // FatalAppExitA — CRT abort path; no-op (never hit on the
    // happy path, just needs to resolve).
    registry.register(
        "kernel32.dll",
        "FatalAppExitA",
        stub_fatal_app_exit_a as StubFn,
        2,
    );
    // GetSystemTime / GetTimeZoneInformation — wall-clock surface.
    registry.register(
        "kernel32.dll",
        "GetSystemTime",
        stub_get_system_time as StubFn,
        1,
    );
    registry.register(
        "kernel32.dll",
        "GetTimeZoneInformation",
        stub_get_time_zone_information as StubFn,
        1,
    );
    // LoadLibraryExA — like LoadLibraryA, ignores the flags.
    registry.register(
        "kernel32.dll",
        "LoadLibraryExA",
        stub_load_library_ex_a as StubFn,
        3,
    );
    // SetEnvironmentVariableA — no-op success.
    registry.register(
        "kernel32.dll",
        "SetEnvironmentVariableA",
        stub_returns_true as StubFn,
        2,
    );
    // Console surface — codecs that link a console-subsystem
    // config tool. All no-op success.
    registry.register(
        "kernel32.dll",
        "AllocConsole",
        stub_returns_true as StubFn,
        0,
    );
    registry.register(
        "kernel32.dll",
        "SetConsoleScreenBufferSize",
        stub_returns_true as StubFn,
        2,
    );
    registry.register(
        "kernel32.dll",
        "SetConsoleCtrlHandler",
        stub_returns_true as StubFn,
        2,
    );
    registry.register(
        "kernel32.dll",
        "WriteConsoleA",
        stub_write_console_a as StubFn,
        5,
    );
    // EncodePointer / DecodePointer — pointer obfuscation. We
    // model them as the identity transform, which is a valid
    // (no-op) implementation: encode then decode round-trips.
    registry.register(
        "kernel32.dll",
        "EncodePointer",
        stub_identity_pointer as StubFn,
        1,
    );
    registry.register(
        "kernel32.dll",
        "DecodePointer",
        stub_identity_pointer as StubFn,
        1,
    );
    // EnumSystemLocalesA — report success without invoking the
    // callback (the CRT only needs the call to not fail).
    registry.register(
        "kernel32.dll",
        "EnumSystemLocalesA",
        stub_returns_true as StubFn,
        2,
    );
    // GetModuleFileNameW / GetStartupInfoW — wide twins of the
    // existing ANSI stubs.
    registry.register(
        "kernel32.dll",
        "GetModuleFileNameW",
        stub_get_module_file_name_w as StubFn,
        3,
    );
    registry.register(
        "kernel32.dll",
        "GetStartupInfoW",
        stub_get_startup_info_w as StubFn,
        1,
    );
    // GetUserDefaultLCID — en-US.
    registry.register(
        "kernel32.dll",
        "GetUserDefaultLCID",
        stub_get_user_default_lcid as StubFn,
        0,
    );
    // HeapQueryInformation — report "not supported" (return 0);
    // the caller treats the heap as a plain heap.
    registry.register(
        "kernel32.dll",
        "HeapQueryInformation",
        stub_returns_zero as StubFn,
        5,
    );
    // IsProcessorFeaturePresent — report every feature ABSENT
    // (return 0). That steers SIMD-dispatching codecs onto their
    // scalar fallback, which the emulator decodes reliably.
    registry.register(
        "kernel32.dll",
        "IsProcessorFeaturePresent",
        stub_returns_zero as StubFn,
        1,
    );
    // IsValidCodePage / IsValidLocale — accept anything.
    registry.register(
        "kernel32.dll",
        "IsValidCodePage",
        stub_returns_true as StubFn,
        1,
    );
    registry.register(
        "kernel32.dll",
        "IsValidLocale",
        stub_returns_true as StubFn,
        2,
    );
    // WaitForMultipleObjectsEx — like WaitForMultipleObjects,
    // ignoring the extra `bAlertable` arg.
    registry.register(
        "kernel32.dll",
        "WaitForMultipleObjectsEx",
        stub_wait_for_multiple_objects as StubFn,
        5,
    );
    // FreeLibraryAndExitThread — thread-teardown path; no-op.
    registry.register(
        "kernel32.dll",
        "FreeLibraryAndExitThread",
        stub_returns_zero as StubFn,
        2,
    );
    // GetLongPathNameA — no long/short distinction in the
    // sandbox: echo the input path back.
    registry.register(
        "kernel32.dll",
        "GetLongPathNameA",
        stub_get_long_path_name_a as StubFn,
        3,
    );
    // GetModuleHandleExA — resolve like GetModuleHandleA and
    // write the handle through the out-pointer.
    registry.register(
        "kernel32.dll",
        "GetModuleHandleExA",
        stub_get_module_handle_ex_a as StubFn,
        3,
    );
    // IsDBCSLeadByteEx — single-byte code page: no lead bytes.
    registry.register(
        "kernel32.dll",
        "IsDBCSLeadByteEx",
        stub_returns_zero as StubFn,
        2,
    );
    // VirtualQuery — report "query failed" (return 0); codecs
    // use it for an optional guard-page probe.
    registry.register(
        "kernel32.dll",
        "VirtualQuery",
        stub_returns_zero as StubFn,
        3,
    );

    // ---- Install-monitor additions (QuickTime 7.7.9 trail) --------
    //
    // The file-IO / directory / temp-path stubs below route through
    // [`crate::context::VirtualFs`] when one is attached, so an
    // installer's writes land in the monitor report. Without a VFS
    // attached they fall back to conservative success values.
    //
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppatha
    registry.register(
        "kernel32.dll",
        "GetTempPathA",
        stub_get_temp_path_a as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettempfilenamea
    registry.register(
        "kernel32.dll",
        "GetTempFileNameA",
        stub_get_temp_file_name_a as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
    registry.register(
        "kernel32.dll",
        "CreateFileA",
        stub_create_file_a as StubFn,
        7,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectorya
    registry.register(
        "kernel32.dll",
        "CreateDirectoryA",
        stub_create_directory_a as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilea
    registry.register(
        "kernel32.dll",
        "DeleteFileA",
        stub_delete_file_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesa
    registry.register(
        "kernel32.dll",
        "GetFileAttributesA",
        stub_get_file_attributes_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize
    registry.register(
        "kernel32.dll",
        "GetFileSize",
        stub_get_file_size as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime
    registry.register(
        "kernel32.dll",
        "DosDateTimeToFileTime",
        stub_dos_date_time_to_file_time as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa
    registry.register(
        "kernel32.dll",
        "CreateMutexA",
        stub_create_mutex_a as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-releasemutex
    registry.register(
        "kernel32.dll",
        "ReleaseMutex",
        stub_returns_true as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
    registry.register(
        "kernel32.dll",
        "CreateProcessA",
        stub_create_process_a as StubFn,
        10,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
    registry.register(
        "kernel32.dll",
        "GetExitCodeProcess",
        stub_get_exit_code_process as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/wincon/nf-wincon-getconsolecp
    registry.register(
        "kernel32.dll",
        "GetConsoleCP",
        stub_get_console_cp as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/wincon/nf-wincon-getconsoleoutputcp
    registry.register(
        "kernel32.dll",
        "GetConsoleOutputCP",
        stub_get_console_cp as StubFn,
        0,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/consoleapi/nf-consoleapi-getconsolemode
    registry.register(
        "kernel32.dll",
        "GetConsoleMode",
        stub_get_console_mode as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-localfiletimetofiletime
    registry.register(
        "kernel32.dll",
        "LocalFileTimeToFileTime",
        stub_local_file_time_to_file_time as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-removedirectorya
    registry.register(
        "kernel32.dll",
        "RemoveDirectoryA",
        stub_remove_directory_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setendoffile
    registry.register(
        "kernel32.dll",
        "SetEndOfFile",
        stub_returns_true as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesa
    registry.register(
        "kernel32.dll",
        "SetFileAttributesA",
        stub_returns_true as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime
    registry.register(
        "kernel32.dll",
        "SetFileTime",
        stub_returns_true as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsize
    registry.register(
        "kernel32.dll",
        "SetProcessWorkingSetSize",
        stub_returns_true as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/consoleapi/nf-consoleapi-writeconsolew
    registry.register(
        "kernel32.dll",
        "WriteConsoleW",
        stub_write_console_w as StubFn,
        5,
    );
}

// ----- Heap ----------------------------------------------------------

/// `HANDLE GetProcessHeap(void)` — return the canned handle.
fn stub_get_process_heap(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(state.process_heap_handle)
}

const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

/// `LPVOID HeapAlloc(HANDLE, DWORD dwFlags, SIZE_T dwBytes)`.
fn stub_heap_alloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h_heap = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("HeapAlloc", t))?;
    let flags = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("HeapAlloc", t))?;
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("HeapAlloc", t))?;
    let addr = bump_alloc(state, n)?;
    let buf = state.heap.entry(addr).or_default();
    buf.resize(n as usize, 0);
    if (flags & HEAP_ZERO_MEMORY) != 0 {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    // Mirror the bytes into emulator memory so the codec can use
    // them directly.
    let bytes = buf.clone();
    mmu.write_initializer(addr, &bytes)
        .map_err(|t| trap_to_win32("HeapAlloc", t))?;
    Ok(addr)
}

/// `BOOL HeapFree(HANDLE, DWORD dwFlags, LPVOID lpMem)`.
fn stub_heap_free(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("HeapFree", t))?;
    let _flags = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("HeapFree", t))?;
    let addr = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("HeapFree", t))?;
    if addr == 0 {
        return Ok(1); // BOOL TRUE; freeing NULL is a no-op
    }
    state
        .heap
        .remove(&addr)
        .ok_or(Win32Error::InvalidHeapBlock {
            stub: "HeapFree",
            addr,
        })?;
    Ok(1)
}

/// `LPVOID HeapReAlloc(HANDLE, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)`.
fn stub_heap_realloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("HeapReAlloc", t))?;
    let flags = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("HeapReAlloc", t))?;
    let addr = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("HeapReAlloc", t))?;
    let n = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("HeapReAlloc", t))?;
    if addr == 0 {
        // MSDN: passing NULL for lpMem is undefined; we choose to
        // treat as fresh alloc for resilience.
        return stub_heap_alloc(cpu, mmu, state, _registry);
    }
    let old = state
        .heap
        .remove(&addr)
        .ok_or(Win32Error::InvalidHeapBlock {
            stub: "HeapReAlloc",
            addr,
        })?;
    let new_addr = bump_alloc(state, n)?;
    let mut buf = vec![0u8; n as usize];
    let copy_n = old.len().min(n as usize);
    buf[..copy_n].copy_from_slice(&old[..copy_n]);
    if (flags & HEAP_ZERO_MEMORY) != 0 {
        for b in buf.iter_mut().skip(copy_n) {
            *b = 0;
        }
    }
    mmu.write_initializer(new_addr, &buf)
        .map_err(|t| trap_to_win32("HeapReAlloc", t))?;
    state.heap.insert(new_addr, buf);
    Ok(new_addr)
}

/// `SIZE_T HeapSize(HANDLE, DWORD dwFlags, LPCVOID lpMem)` —
/// MSDN "Heap functions / HeapSize": returns the size, in bytes,
/// of the memory block pointed to by `lpMem`, or `(SIZE_T)-1`
/// (`0xFFFF_FFFF` on a 32-bit guest) on failure. Round 15 —
/// `IR41_32.AX` queries the live block size after a `HeapAlloc`
/// to size a follow-up copy.
fn stub_heap_size(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("HeapSize", t))?;
    let _flags = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("HeapSize", t))?;
    let addr = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("HeapSize", t))?;
    if addr == 0 {
        return Ok(0xFFFF_FFFF);
    }
    Ok(state
        .heap
        .get(&addr)
        .map(|v| v.len() as u32)
        .unwrap_or(0xFFFF_FFFF))
}

fn bump_alloc(state: &mut HostState, n: u32) -> Result<u32, Win32Error> {
    // Round up to 16 to keep allocations roughly cache-line aligned.
    let aligned = n
        .checked_add(15)
        .map(|v| v & !15u32)
        .ok_or(Win32Error::InvalidArgument {
            stub: "HeapAlloc",
            reason: "size overflow".into(),
        })?;
    let addr = state.heap_cursor;
    let next = addr
        .checked_add(aligned)
        .ok_or(Win32Error::InvalidArgument {
            stub: "HeapAlloc",
            reason: "heap address-space overflow".into(),
        })?;
    if next > state.heap_arena_end {
        return Err(Win32Error::InvalidArgument {
            stub: "HeapAlloc",
            reason: format!(
                "arena exhausted (need {n}, have {})",
                state.heap_arena_end - addr
            ),
        });
    }
    state.heap_cursor = next;
    Ok(addr)
}

const LMEM_ZEROINIT: u32 = 0x0040;

/// `HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes)`.
fn stub_local_alloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let flags = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LocalAlloc", t))?;
    let n = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("LocalAlloc", t))?;
    let addr = bump_alloc(state, n)?;
    let mut buf = vec![0u8; n as usize];
    if (flags & LMEM_ZEROINIT) != 0 {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    mmu.write_initializer(addr, &buf)
        .map_err(|t| trap_to_win32("LocalAlloc", t))?;
    state.heap.insert(addr, buf);
    if state.trace_stubs {
        state
            .stub_trace
            .push(format!("  LocalAlloc(flags={flags:#x}, n={n}) → {addr:#x}"));
    }
    Ok(addr)
}

/// `HLOCAL LocalFree(HLOCAL hMem)`.
fn stub_local_free(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let addr = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LocalFree", t))?;
    if addr == 0 {
        return Ok(0);
    }
    state
        .heap
        .remove(&addr)
        .ok_or(Win32Error::InvalidHeapBlock {
            stub: "LocalFree",
            addr,
        })?;
    Ok(0) // Returns NULL on success per MSDN.
}

// ----- Debug + time --------------------------------------------------

/// `void OutputDebugStringA(LPCSTR lpOutputString)`. We log into
/// `state.debug_log` so the fixture-gated end-to-end test can
/// assert the codec emitted a known boot string.
fn stub_output_debug_string_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("OutputDebugStringA", t))?;
    let s = read_cstr(mmu, p, 4096)?;
    state.debug_log.push(s);
    Ok(0)
}

/// `DWORD GetTickCount(void)`. Returns a monotonically-increasing
/// pseudo-tick. Real wall-clock time is not modelled; many codecs
/// only use the tick as a seed.
fn stub_get_tick_count(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state.tick = state.tick.wrapping_add(1);
    Ok(state.tick)
}

// ----- Atomics -------------------------------------------------------

/// `LONG InterlockedIncrement(LONG volatile *Addend)`.
fn stub_interlocked_increment(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("InterlockedIncrement", t))?;
    let v = mmu
        .load32(p)
        .map_err(|t| trap_to_win32("InterlockedIncrement", t))?;
    let new = v.wrapping_add(1);
    mmu.store32(p, new)
        .map_err(|t| trap_to_win32("InterlockedIncrement", t))?;
    Ok(new)
}

/// `LONG InterlockedDecrement(LONG volatile *Addend)`.
fn stub_interlocked_decrement(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("InterlockedDecrement", t))?;
    let v = mmu
        .load32(p)
        .map_err(|t| trap_to_win32("InterlockedDecrement", t))?;
    let new = v.wrapping_sub(1);
    mmu.store32(p, new)
        .map_err(|t| trap_to_win32("InterlockedDecrement", t))?;
    Ok(new)
}

// ----- Library / function lookup -------------------------------------

/// `HMODULE LoadLibraryA(LPCSTR lpLibFileName)`.
///
/// Round-1 only acknowledges loaded modules in the registry; it
/// does not attempt to load a fresh DLL on demand. The PE loader
/// records every successfully-loaded DLL in `state.modules`.
fn stub_load_library_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LoadLibraryA", t))?;
    let name = read_cstr(mmu, p, 260)?.to_ascii_lowercase();
    if let Some(base) = state.modules.get(&name) {
        return Ok(*base);
    }
    // We pretend the module did not load. Many codecs handle
    // NULL gracefully; the ones that don't will raise a clear
    // trap downstream.
    Ok(0)
}

/// `FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)`.
///
/// Reverse-resolves `hModule` through `state.modules` (the
/// system-DLL pre-registration in `Sandbox::new` plus the
/// codec's own load entry from `Sandbox::load`) and looks the
/// name up in the stub registry under that DLL. Returns the
/// thunk address on hit, NULL otherwise. Lookup-by-ordinal
/// (low-bit-set name pointer) is not supported.
fn stub_get_proc_address(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetProcAddress", t))?;
    let name_p = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetProcAddress", t))?;
    if name_p < 0x10000 {
        // Pointer is an ordinal (HIWORD == 0) — unsupported.
        return Ok(0);
    }
    let name = read_cstr(mmu, name_p, 260)?;
    // Reverse-map handle -> dll name.
    let dll = state
        .modules
        .iter()
        .find(|(_, &base)| base == h)
        .map(|(n, _)| n.clone());
    let Some(dll) = dll else {
        return Ok(0);
    };
    Ok(registry.resolve(&dll, &name).unwrap_or(0))
}

// ----- Round-4 stubs -------------------------------------------------

/// `void ExitProcess(UINT uExitCode)`. Sets `state.exit_requested`,
/// which the run-loop converts into a clean RET_SENTINEL exit so
/// the host caller can introspect the codec's exit code without
/// having to handle a panic. Codecs *should* never call this from
/// their loaded path; if one does, the entire emulator session is
/// over.
fn stub_exit_process(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let code = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("ExitProcess", t))?;
    state.exit_requested = Some(code);
    Ok(0)
}

/// `UINT GetACP(void)`. Returns Windows-1252 (the canonical code
/// page for the Indeo 3 era).
fn stub_get_acp(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1252)
}

/// `UINT GetOEMCP(void)`. Returns 437 (US English code page).
fn stub_get_oem_cp(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(437)
}

/// `BOOL GetCPInfo(UINT codepage, LPCPINFO lpCPInfo)`. Fills the
/// `CPINFO` struct with `MaxCharSize=1`, `DefaultChar={'?',0}`,
/// `LeadByte=[0;12]`. Returns TRUE.
fn stub_get_cp_info(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _cp = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetCPInfo", t))?;
    let p = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetCPInfo", t))?;
    if p == 0 {
        return Ok(0);
    }
    // CPINFO layout (per winnls.h):
    //   UINT  MaxCharSize;        // 4
    //   BYTE  DefaultChar[2];     // 2
    //   BYTE  LeadByte[12];       // 12
    // total: 18 bytes, then padded — we explicitly write each
    // field so layout-padding is irrelevant.
    mmu.store32(p, 1)
        .map_err(|t| trap_to_win32("GetCPInfo", t))?;
    mmu.store8(p + 4, b'?')
        .map_err(|t| trap_to_win32("GetCPInfo", t))?;
    mmu.store8(p + 5, 0)
        .map_err(|t| trap_to_win32("GetCPInfo", t))?;
    for i in 0..12 {
        mmu.store8(p + 6 + i, 0)
            .map_err(|t| trap_to_win32("GetCPInfo", t))?;
    }
    Ok(1)
}

/// `LPSTR GetCommandLineA(void)`. Returns a guest-side pointer
/// to the canned `"oxideav-vfw\0"` string.
fn stub_get_command_line_a(
    _cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    if state.command_line_ptr == 0 {
        let s = b"oxideav-vfw\0";
        let addr = state.arena_const_alloc(s.len() as u32)?;
        mmu.write_initializer(addr, s)
            .map_err(|t| trap_to_win32("GetCommandLineA", t))?;
        state.command_line_ptr = addr;
    }
    Ok(state.command_line_ptr)
}

/// `LPCH GetEnvironmentStrings(void)`. Returns a guest-side
/// pointer to a static block `"\0\0"` (empty environment,
/// double-null-terminated).
fn stub_get_environment_strings(
    _cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    if state.environment_strings_ptr == 0 {
        let s = b"\0\0";
        let addr = state.arena_const_alloc(s.len() as u32)?;
        mmu.write_initializer(addr, s)
            .map_err(|t| trap_to_win32("GetEnvironmentStrings", t))?;
        state.environment_strings_ptr = addr;
    }
    Ok(state.environment_strings_ptr)
}

/// `DWORD GetFileType(HANDLE hFile)`. Returns
/// `FILE_TYPE_UNKNOWN = 0` for any handle. Codecs typically only
/// call this for stdin/stdout, which they don't actually use.
fn stub_get_file_type(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `DWORD GetLastError(void)` — returns `state.last_error`.
fn stub_get_last_error(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(state.last_error)
}

/// `void SetLastError(DWORD dwErrCode)` — writes `state.last_error`.
fn stub_set_last_error(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let code = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("SetLastError", t))?;
    state.last_error = code;
    Ok(0)
}

/// `DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename,
/// DWORD nSize)`. Writes `"oxideav-vfw\0"` into the buffer up to
/// `nSize`, returns the number of bytes written (excluding NUL).
fn stub_get_module_file_name_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetModuleFileNameA", t))?;
    let dst = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetModuleFileNameA", t))?;
    let n_size = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GetModuleFileNameA", t))?;
    if dst == 0 || n_size == 0 {
        return Ok(0);
    }
    let s = b"oxideav-vfw";
    let mut written = 0u32;
    for (i, b) in s.iter().enumerate() {
        if (i as u32) >= n_size.saturating_sub(1) {
            break;
        }
        mmu.store8(dst + i as u32, *b)
            .map_err(|t| trap_to_win32("GetModuleFileNameA", t))?;
        written = written.saturating_add(1);
    }
    // Always NUL-terminate (within nSize).
    if n_size > 0 {
        let nul_off = written.min(n_size - 1);
        mmu.store8(dst + nul_off, 0)
            .map_err(|t| trap_to_win32("GetModuleFileNameA", t))?;
    }
    Ok(written)
}

/// `HMODULE GetModuleHandleA(LPCSTR lpModuleName)`. NULL =>
/// the primary loaded DLL's image base; otherwise look up via
/// `state.modules`.
fn stub_get_module_handle_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetModuleHandleA", t))?;
    if p == 0 {
        return Ok(state.primary_module_base);
    }
    let name = read_cstr(mmu, p, 260)?.to_ascii_lowercase();
    Ok(state.modules.get(&name).copied().unwrap_or(0))
}

/// `void GetStartupInfoA(LPSTARTUPINFO lpStartupInfo)`. Fills
/// the `STARTUPINFO` struct with `cb=68`, all other fields zero.
fn stub_get_startup_info_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetStartupInfoA", t))?;
    if p == 0 {
        return Ok(0);
    }
    // STARTUPINFOA is 68 bytes — zero all of it, then stamp cb.
    for i in 0..68u32 {
        mmu.store8(p + i, 0)
            .map_err(|t| trap_to_win32("GetStartupInfoA", t))?;
    }
    mmu.store32(p, 68)
        .map_err(|t| trap_to_win32("GetStartupInfoA", t))?;
    Ok(0)
}

/// `HANDLE GetStdHandle(DWORD nStdHandle)`. Returns
/// `INVALID_HANDLE_VALUE = 0xFFFFFFFF`. Codecs that branch on
/// this fall through to a no-stdio path.
fn stub_get_std_handle(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0xFFFF_FFFF)
}

/// `void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)`. Fills the
/// `SYSTEM_INFO` struct with sensible defaults — single Pentium
/// processor, 4 KiB pages.
fn stub_get_system_info(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetSystemInfo", t))?;
    if p == 0 {
        return Ok(0);
    }
    let trap = |t: crate::emulator::Trap| trap_to_win32("GetSystemInfo", t);
    // SYSTEM_INFO layout (winbase.h):
    //   union { DWORD dwOemId;
    //           struct { WORD wProcessorArchitecture;
    //                    WORD wReserved; } };           // 4
    //   DWORD dwPageSize;                               // 4
    //   LPVOID lpMinimumApplicationAddress;             // 4
    //   LPVOID lpMaximumApplicationAddress;             // 4
    //   DWORD_PTR dwActiveProcessorMask;                // 4 (32-bit)
    //   DWORD dwNumberOfProcessors;                     // 4
    //   DWORD dwProcessorType;                          // 4
    //   DWORD dwAllocationGranularity;                  // 4
    //   WORD wProcessorLevel;                           // 2
    //   WORD wProcessorRevision;                        // 2
    // total: 36 bytes.
    mmu.store32(p, 0).map_err(trap)?; // dwOemId = PROCESSOR_ARCHITECTURE_INTEL = 0
    mmu.store32(p + 4, PAGE_SIZE as u32).map_err(trap)?;
    mmu.store32(p + 8, 0x10000).map_err(trap)?;
    mmu.store32(p + 12, 0x7FFF_FFFF).map_err(trap)?;
    mmu.store32(p + 16, 1).map_err(trap)?; // ActiveProcessorMask
    mmu.store32(p + 20, 1).map_err(trap)?; // NumberOfProcessors
    mmu.store32(p + 24, 586).map_err(trap)?; // dwProcessorType (PROCESSOR_INTEL_PENTIUM)
    mmu.store32(p + 28, 0x10000).map_err(trap)?; // dwAllocationGranularity
    mmu.store16(p + 32, 0).map_err(trap)?; // wProcessorLevel
    mmu.store16(p + 34, 0).map_err(trap)?; // wProcessorRevision
    Ok(0)
}

/// `DWORD GetVersion(void)`. Returns Win98-shaped value: low
/// word = (minor << 8) | major, high word = build (= 0).
/// `0x00000A04` = major=4, minor=10 → Windows 98.
fn stub_get_version(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0x0000_0A04)
}

/// `HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes)`. The
/// `Global*` family is a legacy alias for `Local*` — same heap.
const GMEM_ZEROINIT: u32 = 0x0040;

fn stub_global_alloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let flags = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GlobalAlloc", t))?;
    let n = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GlobalAlloc", t))?;
    let addr = bump_alloc(state, n)?;
    let mut buf = vec![0u8; n as usize];
    if (flags & GMEM_ZEROINIT) != 0 {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    mmu.write_initializer(addr, &buf)
        .map_err(|t| trap_to_win32("GlobalAlloc", t))?;
    state.heap.insert(addr, buf);
    Ok(addr)
}

/// `HGLOBAL GlobalFree(HGLOBAL hMem)`. Removes the slab; returns
/// NULL on success per MSDN.
fn stub_global_free(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let addr = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GlobalFree", t))?;
    if addr == 0 {
        return Ok(0);
    }
    state
        .heap
        .remove(&addr)
        .ok_or(Win32Error::InvalidHeapBlock {
            stub: "GlobalFree",
            addr,
        })?;
    Ok(0)
}

/// `LPVOID GlobalLock(HGLOBAL hMem)`. We don't move handles, so
/// we return the address itself.
fn stub_global_lock(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let addr = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GlobalLock", t))?;
    Ok(addr)
}

/// `BOOL GlobalUnlock(HGLOBAL hMem)`. Returns FALSE per MSDN
/// when "the memory object is no longer locked" — but with our
/// no-op-lock model we always return FALSE+last_error=NO_ERROR
/// so the caller's reference count goes to zero cleanly.
fn stub_global_unlock(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _addr = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GlobalUnlock", t))?;
    state.last_error = 0; // NO_ERROR
    Ok(0)
}

/// `int MultiByteToWideChar(UINT codepage, DWORD dwFlags,
/// LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR
/// lpWideCharStr, int cchWideChar)`.
///
/// Implements code pages CP_ACP (1252), CP_OEMCP (437), and
/// CP_UTF8 (65001) by zero-extending each input byte to a
/// UTF-16 code unit. Honours the cchWideChar=0 case (return
/// required length without writing).
fn stub_multi_byte_to_wide_char(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _cp = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
    let _flags = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
    let src = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
    let cb = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
    let dst = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
    let cch = arg_dword(cpu, mmu, 5).map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
    if src == 0 {
        return Ok(0);
    }
    // cbMultiByte = -1 means "include the NUL terminator and stop
    // at it"; i.e. compute strlen+1.
    let n = if cb == 0xFFFF_FFFF {
        let mut p = src;
        let mut k: u32 = 0;
        loop {
            let b = mmu
                .load8(p)
                .map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
            k = k.saturating_add(1);
            if b == 0 {
                break;
            }
            p = p.wrapping_add(1);
            if k > 0x0010_0000 {
                break; // safety bound (1 MiB)
            }
        }
        k
    } else {
        cb
    };

    if cch == 0 {
        // Caller wants the required length, no write.
        return Ok(n);
    }
    if dst == 0 {
        return Ok(0);
    }
    let to_write = core::cmp::min(n, cch);
    for i in 0..to_write {
        let b = mmu
            .load8(src + i)
            .map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
        mmu.store16(dst + i * 2, u16::from(b))
            .map_err(|t| trap_to_win32("MultiByteToWideChar", t))?;
    }
    Ok(to_write)
}

/// `int WideCharToMultiByte(UINT codepage, DWORD dwFlags,
/// LPCWSTR lpWideCharStr, int cchWideChar, LPSTR
/// lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar,
/// LPBOOL lpUsedDefaultChar)`.
///
/// Inverse of `MultiByteToWideChar`: writes the low byte if
/// the UTF-16 unit fits in 8 bits, else uses lpDefaultChar
/// (or `'?'` if lpDefaultChar is NULL) and sets
/// `*lpUsedDefaultChar = TRUE`.
#[allow(clippy::too_many_arguments)]
fn stub_wide_char_to_multi_byte(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _cp = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    let _flags = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    let src = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    let cch = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    let dst = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    let cb = arg_dword(cpu, mmu, 5).map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    let p_default = arg_dword(cpu, mmu, 6).map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    let p_used = arg_dword(cpu, mmu, 7).map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    if src == 0 {
        return Ok(0);
    }

    // cchWideChar = -1 ⇒ stop at NUL (and include it in count).
    let n = if cch == 0xFFFF_FFFF {
        let mut p = src;
        let mut k: u32 = 0;
        loop {
            let u = mmu
                .load16(p)
                .map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
            k = k.saturating_add(1);
            if u == 0 {
                break;
            }
            p = p.wrapping_add(2);
            if k > 0x0010_0000 {
                break;
            }
        }
        k
    } else {
        cch
    };

    let default_char: u8 = if p_default != 0 {
        mmu.load8(p_default)
            .map_err(|t| trap_to_win32("WideCharToMultiByte", t))?
    } else {
        b'?'
    };

    if cb == 0 {
        return Ok(n);
    }
    if dst == 0 {
        return Ok(0);
    }

    let to_write = core::cmp::min(n, cb);
    let mut used_default = false;
    for i in 0..to_write {
        let u = mmu
            .load16(src + i * 2)
            .map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
        let b = if u <= 0xFF {
            u as u8
        } else {
            used_default = true;
            default_char
        };
        mmu.store8(dst + i, b)
            .map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    }
    if p_used != 0 {
        mmu.store32(p_used, if used_default { 1 } else { 0 })
            .map_err(|t| trap_to_win32("WideCharToMultiByte", t))?;
    }
    Ok(to_write)
}

/// `void RtlUnwind(PVOID TargetFrame, PVOID TargetIp,
/// PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)`.
///
/// SEH-stub per the design doc's "out of scope until specifically
/// needed" entry. The codec's `__try` blocks effectively become
/// no-ops; if a codec actually relies on SEH for control flow
/// (rather than only for cleanup), the trap will surface on the
/// first instruction past the try-body it expected to skip.
fn stub_rtl_unwind(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
#[allow(dead_code)]
const MEM_RELEASE: u32 = 0x0000_8000;
#[allow(dead_code)]
const MEM_DECOMMIT: u32 = 0x0000_4000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
#[allow(dead_code)]
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

fn page_protect_to_perm(flprot: u32) -> Perm {
    // Mask out PAGE_GUARD / PAGE_NOCACHE / PAGE_WRITECOMBINE.
    let base = flprot & 0xFF;
    match base {
        PAGE_NOACCESS => Perm::from_bits(0),
        PAGE_READONLY => Perm::R,
        PAGE_READWRITE => Perm::R | Perm::W,
        PAGE_EXECUTE_READ => Perm::R | Perm::X,
        PAGE_EXECUTE_READWRITE => Perm::R | Perm::W | Perm::X,
        PAGE_EXECUTE => Perm::R | Perm::X,
        _ => Perm::R | Perm::W,
    }
}

/// Inverse of [`page_protect_to_perm`] for the `lpflOldProtect`
/// out-parameter of `VirtualProtect`.
fn perm_to_page_protect(perm: Perm) -> u32 {
    let r = perm.contains(Perm::R);
    let w = perm.contains(Perm::W);
    let x = perm.contains(Perm::X);
    match (r, w, x) {
        (false, false, false) => PAGE_NOACCESS,
        (true, false, false) => PAGE_READONLY,
        (true, true, false) => PAGE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        // No-read combos are rare under Win32 protection
        // taxonomy; report the closest match.
        (false, _, true) => PAGE_EXECUTE,
        (false, true, false) => PAGE_READWRITE,
    }
}

/// Region [0xA000_0000, 0xC000_0000) reserved for VirtualAlloc
/// when the caller passes lpAddress=NULL. Kept well above the
/// heap/stack regions configured by `Sandbox::new`.
const VIRTUAL_ALLOC_LO: u32 = 0xA000_0000;
const VIRTUAL_ALLOC_HI: u32 = 0xC000_0000;

/// `LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
/// DWORD flAllocationType, DWORD flProtect)`.
///
/// MEM_RESERVE alone reserves address space without committing
/// pages; MEM_COMMIT (alone or together) maps the pages with
/// the `flProtect` permissions. We honour MEM_COMMIT by mapping
/// real pages; MEM_RESERVE-only is treated the same way (we
/// don't model the reserve/commit split distinctly).
fn stub_virtual_alloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let lp_addr = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("VirtualAlloc", t))?;
    let size = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("VirtualAlloc", t))?;
    let alloc_type = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("VirtualAlloc", t))?;
    let prot = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("VirtualAlloc", t))?;

    if size == 0 {
        return Ok(0);
    }
    let perm = page_protect_to_perm(prot);
    let aligned_size = ((size + (PAGE_SIZE as u32 - 1)) & !(PAGE_SIZE as u32 - 1)).max(size);

    let base = if lp_addr == 0 {
        match mmu.find_free_range(VIRTUAL_ALLOC_LO, VIRTUAL_ALLOC_HI, aligned_size) {
            Some(b) => b,
            None => return Ok(0),
        }
    } else {
        // Round down to a page boundary.
        lp_addr & !(PAGE_SIZE as u32 - 1)
    };

    if (alloc_type & (MEM_COMMIT | MEM_RESERVE)) != 0 || alloc_type == 0 {
        mmu.map(base, aligned_size, perm);
    }
    Ok(base)
}

/// `BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)`.
fn stub_virtual_free(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let lp_addr = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("VirtualFree", t))?;
    let size = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("VirtualFree", t))?;
    let _free_type = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("VirtualFree", t))?;
    if lp_addr == 0 {
        return Ok(0);
    }
    // For MEM_RELEASE, MSDN requires dwSize == 0 — we ignore that
    // detail and unmap whatever range the caller supplied. If
    // size == 0 (release of the whole allocation), do nothing —
    // we don't track per-allocation extents.
    if size > 0 {
        let aligned_size = (size + (PAGE_SIZE as u32 - 1)) & !(PAGE_SIZE as u32 - 1);
        mmu.unmap(lp_addr & !(PAGE_SIZE as u32 - 1), aligned_size);
    }
    Ok(1)
}

/// `BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer,
/// DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
/// LPOVERLAPPED lpOverlapped)`. When the handle was minted by the
/// virtual filesystem, the bytes flow through it so the monitor
/// can report what was written. Unknown handles fall through to
/// fail-soft "wrote nothing".
const ERROR_INVALID_HANDLE: u32 = 6;
fn stub_write_file(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("WriteFile", t))?;
    let lp_buf = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("WriteFile", t))?;
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("WriteFile", t))?;
    let lp_written = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("WriteFile", t))?;
    let _lp_ovl = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("WriteFile", t))?;
    if let Some(vfs) = state.context.vfs.as_mut() {
        if vfs.owns(h) && lp_buf != 0 {
            let mut buf = vec![0u8; n as usize];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = mmu
                    .load8(lp_buf + i as u32)
                    .map_err(|t| trap_to_win32("WriteFile", t))?;
            }
            let written = vfs.write_handle(h, &buf).unwrap_or(0) as u32;
            if lp_written != 0 {
                mmu.store32(lp_written, written)
                    .map_err(|t| trap_to_win32("WriteFile", t))?;
            }
            return Ok(1);
        }
    }
    if lp_written != 0 {
        mmu.store32(lp_written, 0)
            .map_err(|t| trap_to_win32("WriteFile", t))?;
    }
    state.last_error = ERROR_INVALID_HANDLE;
    Ok(0)
}

// ----- helpers -------------------------------------------------------

fn read_cstr(mmu: &Mmu, mut addr: u32, max: u32) -> Result<String, Win32Error> {
    let mut bytes = Vec::new();
    for _ in 0..max {
        let b = mmu.load8(addr).map_err(|t| trap_to_win32("read_cstr", t))?;
        if b == 0 {
            break;
        }
        bytes.push(b);
        addr = addr.wrapping_add(1);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn trap_to_win32(stub: &'static str, t: crate::emulator::Trap) -> Win32Error {
    Win32Error::InvalidArgument {
        stub,
        reason: format!("{t}"),
    }
}

// ====================================================================
// Round-8 fail-soft stubs.
// ====================================================================
//
// Each function below is the "minimum viable" implementation: it
// honours the public ABI (return value semantics + arg-count for
// stdcall cleanup) but performs no real Windows operation. Codecs
// that genuinely depend on a side effect (e.g. a real critical
// section excluding a phantom thread) would surface a fault later;
// in practice IR50_32.DLL imports many of these for rarely-taken
// branches (registry, dialog config, error-popup paths) that the
// `IC*` decode pipeline never executes.

/// `BOOL CloseHandle(HANDLE)`. Closes the corresponding VFS or
/// registry handle when one is owned by [`crate::context`]; falls
/// through to a no-op success otherwise (the historical
/// behaviour, used by the wide set of synthetic handles minted
/// elsewhere in the kernel32 stub family).
fn stub_close_handle(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("CloseHandle", t))?;
    if let Some(vfs) = state.context.vfs.as_mut() {
        if vfs.owns(h) {
            vfs.close(h);
            return Ok(1);
        }
    }
    if let Some(reg) = state.context.registry.as_mut() {
        if reg.owns(h) {
            reg.close_key(h);
            return Ok(1);
        }
    }
    Ok(1)
}

/// `HANDLE CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES,
/// DWORD flProtect, DWORD dwMaxSizeHigh, DWORD dwMaxSizeLow,
/// LPCSTR lpName)`. Round 12 — for `hFile == INVALID_HANDLE_VALUE`
/// (-1) the call requests a pagefile-backed anonymous mapping;
/// `IR50_32.DLL` uses this to share its huffman / DCT tables
/// between concurrent decoder instances. Our sandbox is
/// single-instance so we just allocate a fresh buffer of size
/// `dwMaxSizeLow` and return its address as the handle. The
/// matching `MapViewOfFile` returns the same address.
fn stub_create_file_mapping_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h_file = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("CreateFileMappingA", t))?;
    let _attrs = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("CreateFileMappingA", t))?;
    let _protect = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("CreateFileMappingA", t))?;
    let _size_hi = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("CreateFileMappingA", t))?;
    let size_lo = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("CreateFileMappingA", t))?;
    let _name = arg_dword(cpu, mmu, 5).map_err(|t| trap_to_win32("CreateFileMappingA", t))?;
    if size_lo == 0 {
        return Ok(0);
    }
    let addr = bump_alloc(state, size_lo)?;
    let buf = vec![0u8; size_lo as usize];
    mmu.write_initializer(addr, &buf)
        .map_err(|t| trap_to_win32("CreateFileMappingA", t))?;
    state.heap.insert(addr, buf);
    Ok(addr)
}

/// `HANDLE CreateSemaphoreA(...)`. Returns a non-zero pseudo
/// handle so the codec's RAII wrappers don't bail on NULL. We
/// don't actually model semaphores.
fn stub_create_semaphore_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0xC0DE_5E3A) // pseudo-handle
}

/// `void DeleteCriticalSection(LPCRITICAL_SECTION)`. No-op.
fn stub_delete_critical_section(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL DisableThreadLibraryCalls(HMODULE)`. We don't model
/// per-thread DllMain calls; success is the right answer.
fn stub_disable_thread_library_calls(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `void EnterCriticalSection(LPCRITICAL_SECTION)`. We are
/// single-threaded; the section is always free.
fn stub_enter_critical_section(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `void LeaveCriticalSection(LPCRITICAL_SECTION)`. No-op.
fn stub_leave_critical_section(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `void InitializeCriticalSection(LPCRITICAL_SECTION lpcs)`.
/// Real initialisation zeroes the structure (20 bytes for x86
/// CRITICAL_SECTION). We mimic the zero-fill so callers that
/// inspect the structure see a clean state.
fn stub_initialize_critical_section(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("InitializeCriticalSection", t))?;
    if p != 0 {
        // 24-byte CRITICAL_SECTION on x86. Touching pages outside
        // the structure would WriteProtectFault — the codec
        // always allocates this from its heap, so writes succeed.
        for i in 0..24u32 {
            // Best-effort: ignore individual byte faults so a
            // truncated mapping doesn't blow up the test. The
            // structure is opaque from the codec's POV.
            let _ = mmu.store8(p + i, 0);
        }
    }
    Ok(0)
}

/// Walk a `IMAGE_RESOURCE_DIRECTORY` looking for an entry matching
/// `key`. The directory's entries (named first, then ID-keyed) are
/// laid out immediately after the 16-byte header. `dir_va` is the
/// VA of the directory itself; `rsrc_base` is the VA of the
/// top-level resource directory (used to resolve sub-directory
/// offsets, which are relative to it).
///
/// Returns `Some((offset_to_data_or_dir, is_directory))` on match,
/// where `offset_to_data_or_dir` is relative to `rsrc_base`.
///
/// `key` may be either an ID (`name & 0x8000_0000 == 0`, low 16
/// bits = id) or a string-name (`name & 0x8000_0000 != 0`,
/// low 31 bits = offset relative to `rsrc_base` of a UTF-16
/// length-prefixed name). Round 12 only walks ID-keyed entries
/// because `IR50_32.DLL`'s codec resources are all ID-keyed
/// (RT_BITMAP / 112).
fn rsrc_dir_lookup_id(
    mmu: &Mmu,
    _rsrc_base: u32,
    dir_va: u32,
    target_id: u32,
) -> Option<(u32, bool)> {
    // Header: NumberOfNamedEntries at offset 12, NumberOfIdEntries at 14.
    let n_named = mmu.load16(dir_va + 12).ok()? as u32;
    let n_id = mmu.load16(dir_va + 14).ok()? as u32;
    let entries_va = dir_va + 16;
    // ID entries follow the named ones.
    for i in 0..n_id {
        let e_va = entries_va + (n_named + i) * 8;
        let name = mmu.load32(e_va).ok()?;
        // Defensive: skip name-keyed entries in the ID table
        // (PE format guarantees they don't appear there, but
        // a malformed image shouldn't fault us).
        if (name & 0x8000_0000) != 0 {
            continue;
        }
        if name == target_id {
            let off = mmu.load32(e_va + 4).ok()?;
            let is_dir = (off & 0x8000_0000) != 0;
            return Some((off & 0x7FFF_FFFF, is_dir));
        }
    }
    None
}

/// Resolve a `(hModule, lpName, lpType)` triple to the VA of the
/// `IMAGE_RESOURCE_DATA_ENTRY` for that resource. Returns `None`
/// if the module has no resource directory or no matching entry.
///
/// Both `lpName` and `lpType` are interpreted as
/// `MAKEINTRESOURCE`-style integers when their high 16 bits are
/// zero (this is how `IR50_32.DLL` invokes us — type 2 = RT_BITMAP,
/// name 112). Round 12 doesn't yet support string-keyed
/// resources; if either argument is a pointer, return `None`.
pub(crate) fn find_resource_data_entry(
    state: &HostState,
    mmu: &Mmu,
    h_module: u32,
    lp_name: u32,
    lp_type: u32,
) -> Option<u32> {
    // hModule = 0 means "the calling module" — use the primary.
    let h = if h_module == 0 {
        state.primary_module_base
    } else {
        h_module
    };
    let rsrc_base = *state.module_resource_dirs.get(&h)?;
    // MAKEINTRESOURCE check: high word zero → integer ID. PE
    // resource tables store integer IDs as the low 31 bits with
    // the high bit clear. lpName=112 fits in u16; same for lpType.
    if lp_name & 0xFFFF_0000 != 0 || lp_type & 0xFFFF_0000 != 0 {
        return None;
    }
    // Top-level: keyed by type. PE format guarantees the high
    // bit of the offset is set (each top-level entry points to a
    // sub-directory).
    let (off_type, is_dir) = rsrc_dir_lookup_id(mmu, rsrc_base, rsrc_base, lp_type)?;
    if !is_dir {
        return None;
    }
    // Second-level: keyed by name (or ID).
    let (off_name, is_dir) = rsrc_dir_lookup_id(mmu, rsrc_base, rsrc_base + off_type, lp_name)?;
    if !is_dir {
        return None;
    }
    // Third-level: keyed by language. We pick the first entry
    // (LANG_NEUTRAL would be ideal but real codecs ship one
    // language; IR50 ships 1033 = en-US).
    let lang_dir_va = rsrc_base + off_name;
    let n_named = mmu.load16(lang_dir_va + 12).ok()? as u32;
    let n_id = mmu.load16(lang_dir_va + 14).ok()? as u32;
    if n_named + n_id == 0 {
        return None;
    }
    let first_entry = lang_dir_va + 16;
    let off = mmu.load32(first_entry + 4).ok()?;
    if (off & 0x8000_0000) != 0 {
        // Should be a leaf, not another directory.
        return None;
    }
    Some(rsrc_base + (off & 0x7FFF_FFFF))
}

/// `HRSRC FindResourceA(HMODULE, LPCSTR lpName, LPCSTR lpType)`.
/// Round-12 walks the PE resource directory of `hModule` (or the
/// primary module if NULL) looking for an `(lpType, lpName)`
/// match. Returns the VA of the `IMAGE_RESOURCE_DATA_ENTRY`
/// (the on-disk struct that points to the actual resource bytes)
/// — `LoadResource` then dereferences this to a pointer.
fn stub_find_resource_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let h_module = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("FindResourceA", t))?;
    let lp_name = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("FindResourceA", t))?;
    let lp_type = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("FindResourceA", t))?;
    Ok(find_resource_data_entry(state, mmu, h_module, lp_name, lp_type).unwrap_or(0))
}

/// `BOOL FlushFileBuffers(HANDLE)`. Always succeeds.
fn stub_flush_file_buffers(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `BOOL FreeEnvironmentStringsA/W(LPCSTR/LPCWSTR)`. No-op
/// success.
fn stub_free_environment_strings(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `BOOL FreeLibrary(HMODULE)`. We don't actually unload modules
/// inside the sandbox; success keeps the codec's RAII shims happy.
fn stub_free_library(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `BOOL FreeResource(HGLOBAL hResData)`. No-op success.
fn stub_free_resource(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `HANDLE GetCurrentProcess(void)`. Pseudo-handle 0xFFFFFFFF
/// per MSDN (a magic constant the codec only compares to itself).
fn stub_get_current_process(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0xFFFF_FFFF)
}

/// `DWORD GetCurrentThreadId(void)`. Returns the scheduler's
/// active TID. The bootstrap thread is `1`; subsequent
/// `CreateThread` calls mint monotonically increasing values.
fn stub_get_current_thread_id(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(state.active_tid)
}

/// `LPWCH GetEnvironmentStringsW(void)`. We hand back the same
/// pointer as `GetEnvironmentStrings` (an empty UTF-16 block).
fn stub_get_environment_strings_w(
    _cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    if state.environment_strings_ptr != 0 {
        return Ok(state.environment_strings_ptr);
    }
    // 4 bytes: two UTF-16 NULs (one to end the last entry, one to
    // terminate the block).
    let p = state.arena_const_alloc(4)?;
    mmu.write_initializer(p, &[0, 0, 0, 0])
        .map_err(|t| trap_to_win32("GetEnvironmentStringsW", t))?;
    state.environment_strings_ptr = p;
    Ok(p)
}

/// `int GetLocaleInfoA/W(LCID, LCTYPE, LPSTR/LPWSTR, int)`.
/// Return 0 (= "no data") and let the CRT use the default locale.
fn stub_get_locale_info_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `DWORD GetShortPathNameA(LPCSTR, LPSTR, DWORD)`. No filesystem
/// is modelled — return 0 = "fail". The codec falls back to the
/// long-path string.
fn stub_get_short_path_name_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL GetStringTypeA/W(...)`. Return 1 = "success", with no
/// type bits actually written. Some CRTs use this for is_alpha;
/// the codec's decode body doesn't, so leaving the buffer
/// untouched is benign.
fn stub_get_string_type(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `UINT GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize)`.
/// Writes "C:\\WINDOWS\\System32" into `lpBuffer` and returns the
/// length. Codecs use this to locate sibling DLLs; we don't
/// actually load them, but the returned string keeps the codec's
/// path-construction code happy.
fn stub_get_system_directory_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let buf = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetSystemDirectoryA", t))?;
    let size = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetSystemDirectoryA", t))?;
    let s = b"C:\\WINDOWS\\System32";
    if buf == 0 || size == 0 {
        return Ok(s.len() as u32 + 1);
    }
    let n = (size as usize).saturating_sub(1).min(s.len());
    for (i, &b) in s.iter().take(n).enumerate() {
        mmu.store8(buf + i as u32, b)
            .map_err(|t| trap_to_win32("GetSystemDirectoryA", t))?;
    }
    mmu.store8(buf + n as u32, 0)
        .map_err(|t| trap_to_win32("GetSystemDirectoryA", t))?;
    Ok(n as u32)
}

/// `BOOL GetVersionExA(LPOSVERSIONINFOA)`. Fills in a Windows 95
/// shape: 4.00.0950, VER_PLATFORM_WIN32_WINDOWS = 1.
///
/// OSVERSIONINFOA layout (148 bytes):
///   DWORD dwOSVersionInfoSize     (in)
///   DWORD dwMajorVersion
///   DWORD dwMinorVersion
///   DWORD dwBuildNumber
///   DWORD dwPlatformId
///   CHAR  szCSDVersion[128]
fn stub_get_version_ex_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetVersionExA", t))?;
    if p == 0 {
        return Ok(0);
    }
    // Skip dwOSVersionInfoSize at offset 0 (caller-supplied).
    mmu.store32(p + 4, 4)
        .map_err(|t| trap_to_win32("GetVersionExA", t))?; // dwMajorVersion
    mmu.store32(p + 8, 0)
        .map_err(|t| trap_to_win32("GetVersionExA", t))?; // dwMinorVersion
    mmu.store32(p + 12, 950)
        .map_err(|t| trap_to_win32("GetVersionExA", t))?; // dwBuildNumber
    mmu.store32(p + 16, 1)
        .map_err(|t| trap_to_win32("GetVersionExA", t))?; // dwPlatformId
                                                          // szCSDVersion: ""
    mmu.store8(p + 20, 0)
        .map_err(|t| trap_to_win32("GetVersionExA", t))?;
    Ok(1)
}

/// `HGLOBAL GlobalHandle(LPCVOID pMem)`. Return the same pointer
/// — our heap is single-flat-arena, so `pMem` and the "handle"
/// are the same value.
fn stub_global_handle(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GlobalHandle", t))?;
    Ok(p)
}

/// `HGLOBAL GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT
/// uFlags)`. Same shape as `HeapReAlloc` minus the `dwFlags`
/// argument; reuse the heap re-alloc path.
fn stub_global_realloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let addr = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GlobalReAlloc", t))?;
    let n = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GlobalReAlloc", t))?;
    let _flags = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GlobalReAlloc", t))?;
    if addr == 0 {
        let new_addr = bump_alloc(state, n)?;
        let buf = vec![0u8; n as usize];
        mmu.write_initializer(new_addr, &buf)
            .map_err(|t| trap_to_win32("GlobalReAlloc", t))?;
        state.heap.insert(new_addr, buf);
        return Ok(new_addr);
    }
    let old = state
        .heap
        .remove(&addr)
        .ok_or(Win32Error::InvalidHeapBlock {
            stub: "GlobalReAlloc",
            addr,
        })?;
    let new_addr = bump_alloc(state, n)?;
    let mut buf = vec![0u8; n as usize];
    let copy_n = old.len().min(n as usize);
    buf[..copy_n].copy_from_slice(&old[..copy_n]);
    mmu.write_initializer(new_addr, &buf)
        .map_err(|t| trap_to_win32("GlobalReAlloc", t))?;
    state.heap.insert(new_addr, buf);
    Ok(new_addr)
}

/// `HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize,
/// SIZE_T dwMaximumSize)`. Hand back the global heap handle —
/// codecs don't typically pin to a private heap.
fn stub_heap_create(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(state.process_heap_handle)
}

/// `BOOL HeapDestroy(HANDLE)`. No-op success.
fn stub_heap_destroy(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `BOOL IsBadCodePtr/IsBadReadPtr/IsBadWritePtr(...)`. Return 0
/// (= "the pointer is fine"); we trust the codec to read/write
/// only validly-mapped pages.
fn stub_is_bad_ptr(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `int LCMapStringA/W(...)`. Return 0 = failure; CRTs fall back
/// to byte-by-byte processing.
fn stub_lc_map_string(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `HGLOBAL LoadResource(HMODULE hModule, HRSRC hResInfo)`.
/// Round 12 — `hResInfo` is the `IMAGE_RESOURCE_DATA_ENTRY` VA
/// returned by `FindResourceA`. The Win32 contract is that
/// `LoadResource` returns an `HGLOBAL` whose only contract is
/// being a valid argument to `LockResource` / `SizeofResource`;
/// we simply return `hResInfo` itself (Wine and several MSDN
/// samples do the same — both `LoadResource` and `LockResource`
/// are no-ops on modern Windows since the resource bytes are
/// already memory-mapped).
fn stub_load_resource(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h_module = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LoadResource", t))?;
    let h_res_info = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("LoadResource", t))?;
    Ok(h_res_info)
}

/// `HLOCAL LocalHandle(LPCVOID pMem)`. Round-tripping a
/// `LocalAlloc` pointer.
fn stub_local_handle(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LocalHandle", t))?;
    Ok(p)
}

/// `LPVOID LocalLock(HLOCAL)`. The handle IS the pointer for our
/// heap arena. Real LocalLock is a no-op for fixed (= LMEM_FIXED)
/// allocations, which the CRT defaults to.
fn stub_local_lock(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LocalLock", t))?;
    Ok(p)
}

/// `BOOL LocalUnlock(HLOCAL)`. No-op success.
fn stub_local_unlock(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `LPVOID LockResource(HGLOBAL)`. Round 12 — the `HGLOBAL` is
/// the `IMAGE_RESOURCE_DATA_ENTRY` VA we returned from
/// `FindResourceA` / `LoadResource`. The first dword of that
/// struct is `OffsetToData` (an RVA, NOT relative to .rsrc),
/// the second is `Size`. We resolve the RVA against the module
/// base — since all sections including `.rsrc` are mapped into
/// emulator memory at their preferred VA, the resource bytes
/// are directly addressable.
fn stub_lock_resource(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LockResource", t))?;
    if h == 0 {
        return Ok(0);
    }
    // First dword of IMAGE_RESOURCE_DATA_ENTRY = RVA.
    let rva = match mmu.load32(h) {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };
    // The RVA is relative to the module image base. We don't
    // know exactly which module the resource belongs to; the
    // primary module's base is the right answer for a
    // single-codec sandbox (round 12). For multi-codec we'd
    // need to thread hModule through.
    if state.primary_module_base == 0 {
        return Ok(0);
    }
    Ok(state.primary_module_base.wrapping_add(rva))
}

/// `DWORD SizeofResource(HMODULE, HRSRC)`. Round 12 — the
/// `HRSRC` is the `IMAGE_RESOURCE_DATA_ENTRY` VA from
/// `FindResourceA`; second dword is `Size`. We're asked to
/// return the byte count. Round 13 wires it into the dispatch
/// registry; IR50_32 doesn't import it, but other codecs (and
/// future round-14+ targets) will.
fn stub_sizeof_resource(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h_module = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("SizeofResource", t))?;
    let h_res_info = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("SizeofResource", t))?;
    if h_res_info == 0 {
        return Ok(0);
    }
    match mmu.load32(h_res_info + 4) {
        Ok(v) => Ok(v),
        Err(_) => Ok(0),
    }
}

/// `LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD desiredAccess,
/// DWORD offsetHigh, DWORD offsetLow, SIZE_T numBytesToMap)`. Round
/// 12 — `CreateFileMappingA` returned the buffer's start VA as
/// the handle; the view is the entire buffer, so we return
/// `hFileMappingObject` directly (offset 0, full size). Round-13
/// might add real offset support if a codec ever calls with
/// non-zero offset.
fn stub_map_view_of_file(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("MapViewOfFile", t))?;
    let _access = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("MapViewOfFile", t))?;
    let _off_hi = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("MapViewOfFile", t))?;
    let off_lo = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("MapViewOfFile", t))?;
    let _num = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("MapViewOfFile", t))?;
    if h == 0 {
        return Ok(0);
    }
    Ok(h.wrapping_add(off_lo))
}

/// `HANDLE OpenFileMappingA(...)`. Return NULL.
fn stub_open_file_mapping_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)`.
/// Synthesise a monotonically-increasing 64-bit tick by chaining
/// `state.tick`.
fn stub_query_performance_counter(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("QueryPerformanceCounter", t))?;
    state.tick = state.tick.wrapping_add(1);
    if p != 0 {
        mmu.store32(p, state.tick)
            .map_err(|t| trap_to_win32("QueryPerformanceCounter", t))?;
        mmu.store32(p + 4, 0)
            .map_err(|t| trap_to_win32("QueryPerformanceCounter", t))?;
    }
    Ok(1)
}

/// `BOOL QueryPerformanceFrequency(LARGE_INTEGER* lpFreq)`. We
/// model 1 MHz (one tick per microsecond). The codec uses this as
/// a divisor for elapsed-time calculations.
fn stub_query_performance_frequency(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("QueryPerformanceFrequency", t))?;
    if p != 0 {
        mmu.store32(p, 1_000_000)
            .map_err(|t| trap_to_win32("QueryPerformanceFrequency", t))?;
        mmu.store32(p + 4, 0)
            .map_err(|t| trap_to_win32("QueryPerformanceFrequency", t))?;
    }
    Ok(1)
}

/// `void RaiseException(DWORD, DWORD, DWORD, const ULONG_PTR*)`.
/// Real Windows raises a structured exception that the codec's
/// SEH handler may catch. We have no SEH unwinder; logging the
/// event keeps the test diagnosable while the call returns.
fn stub_raise_exception(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let code = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("RaiseException", t))?;
    state
        .debug_log
        .push(format!("RaiseException code={code:#010x}"));
    Ok(0)
}

/// `BOOL ReleaseSemaphore(HANDLE, LONG, LPLONG)`. No-op success.
fn stub_release_semaphore(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `DWORD SetFilePointer(...)`. We have no real file system;
/// return INVALID_SET_FILE_POINTER (= 0xFFFFFFFF).
fn stub_set_file_pointer(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0xFFFF_FFFF)
}

/// `UINT SetHandleCount(UINT)`. Return the input (= "we honoured
/// the request"). The CRT uses this to bump its FILE table size.
fn stub_set_handle_count(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let n = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("SetHandleCount", t))?;
    Ok(n)
}

/// `BOOL SetStdHandle(DWORD nStdHandle, HANDLE hHandle)`. No-op
/// success.
fn stub_set_std_handle(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(...)`.
/// Return NULL (= "no previous filter installed"). We don't run
/// the filter on a fault.
fn stub_set_unhandled_exception_filter(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `void Sleep(DWORD ms)`. Asks the scheduler to suspend the
/// current thread until `INSTRUCTIONS_PER_MS * ms` more guest
/// instructions have elapsed. With a single thread, the run
/// loop fast-forwards the global clock to the wake target so
/// `Sleep` returns roughly immediately in wall-clock time but
/// the `tick` / `GetTickCount` chain advances correctly.
fn stub_sleep(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let ms = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("Sleep", t))?;
    let now = state.scheduler.instructions_global;
    let resume_after_instructions =
        now.saturating_add(u64::from(ms).saturating_mul(crate::sched::INSTRUCTIONS_PER_MS));
    state.yield_requested = Some(crate::sched::YieldRequest::Wait(
        crate::sched::WaitCondition::Sleep {
            resume_after_instructions,
        },
    ));
    // Mirror to the legacy tick counter so `GetTickCount` from
    // inside the same Sleep run sees a plausible advance.
    state.tick = state.tick.wrapping_add(ms);
    Ok(0)
}

/// `BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)`.
/// Mirror `ExitProcess` — set the exit-requested flag so the run
/// loop returns cleanly.
fn stub_terminate_process(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("TerminateProcess", t))?;
    let code = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("TerminateProcess", t))?;
    state.exit_requested = Some(code);
    Ok(1)
}

/// `DWORD TlsAlloc(void)`. Mints a fresh process-scoped TLS slot
/// index. The slot's value is stored per-thread (see
/// [`ThreadState::tls_slots`]); calling threads start with the
/// slot reading back zero.
fn stub_tls_alloc(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let proc_ = state.cur_process_mut();
    let slot = proc_.next_tls_slot;
    proc_.next_tls_slot = proc_.next_tls_slot.wrapping_add(1);
    Ok(slot)
}

/// `BOOL TlsFree(DWORD)`. Removes the slot from every thread's
/// TLS map (releasing whatever value was stored). Returns TRUE
/// even when the slot was never assigned in any thread.
fn stub_tls_free(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let idx = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("TlsFree", t))?;
    for t in state.threads.values_mut() {
        t.tls_slots.remove(&idx);
    }
    Ok(1)
}

/// `LPVOID TlsGetValue(DWORD)`. Reads the current thread's TLS
/// slot. Slots that were never assigned read back zero — matching
/// the MSDN "indeterminate, but typically NULL" contract.
fn stub_tls_get_value(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let idx = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("TlsGetValue", t))?;
    Ok(state.cur_thread().tls_slots.get(&idx).copied().unwrap_or(0))
}

/// `BOOL TlsSetValue(DWORD, LPVOID)`. Writes the current thread's
/// TLS slot.
fn stub_tls_set_value(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let idx = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("TlsSetValue", t))?;
    let value = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("TlsSetValue", t))?;
    state.cur_thread_mut().tls_slots.insert(idx, value);
    Ok(1)
}

/// `BOOL UnmapViewOfFile(LPCVOID)`. No-op success.
fn stub_unmap_view_of_file(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `DWORD WaitForSingleObject(HANDLE, DWORD)`. Return
/// `WAIT_OBJECT_0` (= 0) — the object is "signaled" immediately.
/// Single-threaded sandbox: any wait succeeds without blocking.
fn stub_wait_for_single_object(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL WritePrivateProfileStringA(...)`. No-op success — we
/// have no INI files.
fn stub_write_private_profile_string_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `int lstrlenA(LPCSTR)`. Real strlen on the guest pointer.
fn stub_lstrlen_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("lstrlenA", t))?;
    if p == 0 {
        return Ok(0);
    }
    let mut n: u32 = 0;
    while n < 0x10000 {
        match mmu.load8(p + n) {
            Ok(0) => break,
            Ok(_) => n = n.wrapping_add(1),
            Err(_) => break,
        }
    }
    Ok(n)
}

// ====================================================================
// Round-20 stubs — `mpg4c32.dll` PE-load surface (Milestone 3.1).
// ====================================================================

/// `HANDLE CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes,
/// BOOL bManualReset, BOOL bInitialState, LPCSTR lpName)`. The
/// codec only uses the returned HANDLE as an opaque key for
/// `SetEvent` / `WaitForSingleObject`. We return a non-zero
/// pseudo-handle (`0xCAFE_E001` + a tick-driven offset) so
/// every distinct call site sees a fresh value.
fn stub_create_event_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _attrs = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("CreateEventA", t))?;
    let _manual = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("CreateEventA", t))?;
    let _init = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("CreateEventA", t))?;
    let _name = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("CreateEventA", t))?;
    state.tick = state.tick.wrapping_add(1);
    Ok(0xCAFE_E000u32.wrapping_add(state.tick))
}

/// `HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
/// SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
/// LPVOID lpParameter, DWORD dwCreationFlags,
/// LPDWORD lpThreadId)`.
///
/// Mints a fresh [`crate::win32::ThreadState`] with its own CPU
/// register file + stack region, parks the CPU on the start
/// routine (one stdcall argument: `lpParameter`, RET_SENTINEL
/// as the return-to address), marks the thread `Ready`, and
/// hands back a Thread `WaitObject` handle. The scheduler
/// switches into the new thread the next time the current one
/// yields or hits a `Wait*` / quantum boundary.
///
/// `CREATE_SUSPENDED` (0x0000_0004) parks the thread in
/// `Suspended` state instead — `ResumeThread` moves it to
/// `Ready`.
fn stub_create_thread(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    use crate::emulator::isa_int::RET_SENTINEL;
    use crate::sched::{ThreadStatus, WaitObject};
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    let _attrs = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("CreateThread", t))?;
    let _stack = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("CreateThread", t))?;
    let start = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("CreateThread", t))?;
    let param = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("CreateThread", t))?;
    let flags = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("CreateThread", t))?;
    let p_tid = arg_dword(cpu, mmu, 5).map_err(|t| trap_to_win32("CreateThread", t))?;
    if start == 0 {
        return Ok(0);
    }
    // Reserve the next slot in the thread-stack arena.
    let arena_top = state.cur_process().next_thread_stack_top;
    let arena_bottom = state.cur_process().thread_stack_pool_bottom;
    if arena_top == 0 || arena_top.saturating_sub(arena_bottom) < crate::win32::THREAD_STACK_SIZE {
        return Err(Win32Error::InvalidArgument {
            stub: "CreateThread",
            reason:
                "thread-stack pool exhausted (configure with HostState::with_thread_stack_pool)"
                    .into(),
        });
    }
    let stack_top = arena_top;
    state.cur_process_mut().next_thread_stack_top = stack_top - crate::win32::THREAD_STACK_SIZE;
    // Build the new thread's CPU state.
    let mut new_cpu = Cpu::new();
    new_cpu.regs.set_esp(stack_top - 0x10); // small guard
    new_cpu.regs.eip = start;
    // stdcall: one DWORD argument (lpParameter). Push param +
    // RET_SENTINEL so a plain RET inside the start routine
    // returns to the sentinel, which the run loop catches as
    // "thread done".
    new_cpu
        .push32(mmu, param)
        .map_err(|t| trap_to_win32("CreateThread", t))?;
    new_cpu
        .push32(mmu, RET_SENTINEL)
        .map_err(|t| trap_to_win32("CreateThread", t))?;
    // Allocate a TID + register the thread.
    let tid = state.next_tid;
    state.next_tid = state.next_tid.wrapping_add(1);
    let pid = state.cur_thread().pid;
    let mut t = crate::win32::ThreadState::new(tid, pid);
    t.parked_cpu = Some(new_cpu);
    t.status = if (flags & CREATE_SUSPENDED) != 0 {
        ThreadStatus::Suspended
    } else {
        ThreadStatus::Ready
    };
    state.threads.insert(tid, t);
    // Mint a Thread wait object for parent-side
    // WaitForSingleObject. Phase 3c wires this into Wait*; for
    // now we just hand back the handle.
    let handle = state.scheduler.insert_object(WaitObject::Thread { tid });
    if p_tid != 0 {
        mmu.store32(p_tid, tid)
            .map_err(|t| trap_to_win32("CreateThread", t))?;
    }
    Ok(handle)
}

/// `void ExitThread(DWORD dwExitCode)`. Marks the current
/// thread `Terminated` and asks the scheduler to switch. Never
/// returns (the run loop catches the yield request and the
/// next thread runs in place of this one).
fn stub_exit_thread(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let code = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("ExitThread", t))?;
    state.yield_requested = Some(crate::sched::YieldRequest::Exit { code });
    Ok(0)
}

/// `BOOL SetEvent(HANDLE)`. Single-threaded sandbox: the event
/// is "signaled" but no one is waiting on it. Return TRUE.
fn stub_set_event(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `BOOL SetThreadPriority(HANDLE, int)`. Single-threaded
/// sandbox: priority changes have no effect, return TRUE.
fn stub_set_thread_priority(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `DWORD ResumeThread(HANDLE)`. Looks up the Thread wait
/// object behind the handle; if the corresponding thread is
/// `Suspended`, moves it to `Ready`. Returns the previous
/// suspend count (always 0 or 1 in our model).
fn stub_resume_thread(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    use crate::sched::{ThreadStatus, WaitObject};
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("ResumeThread", t))?;
    let tid = match state.scheduler.objects.get(&h) {
        Some(WaitObject::Thread { tid }) => *tid,
        _ => return Ok(0xFFFF_FFFF),
    };
    let Some(t) = state.threads.get_mut(&tid) else {
        return Ok(0xFFFF_FFFF);
    };
    if matches!(t.status, ThreadStatus::Suspended) {
        t.status = ThreadStatus::Ready;
        return Ok(1);
    }
    Ok(0)
}

/// `int MulDiv(int nNumber, int nNumerator, int nDenominator)`.
/// Returns `(i64)nNumber * nNumerator / nDenominator` rounded
/// to nearest, half away from zero. Returns -1 on
/// `nDenominator == 0` or i32 overflow.
fn stub_muldiv(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let a = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("MulDiv", t))? as i32;
    let b = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("MulDiv", t))? as i32;
    let c = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("MulDiv", t))? as i32;
    if c == 0 {
        return Ok((-1i32) as u32);
    }
    let prod = (a as i64).wrapping_mul(b as i64);
    let cb = c as i64;
    // Half-away-from-zero rounding: add cb/2 (with sign of
    // prod * sign of c) before the divide.
    let sign_match = (prod < 0) == (cb < 0);
    let half = cb.wrapping_abs() / 2;
    let adj = if sign_match { half } else { -half };
    let result = prod.wrapping_add(adj) / cb;
    if result > i32::MAX as i64 || result < i32::MIN as i64 {
        return Ok((-1i32) as u32);
    }
    Ok((result as i32) as u32)
}

/// `UINT GetProfileIntA(LPCSTR lpAppName, LPCSTR lpKeyName,
/// INT nDefault)`. We have no `win.ini` to consult, so always
/// return the caller's default. (Pre-XP API; modern codecs
/// only use it for legacy compatibility settings.)
fn stub_get_profile_int_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _app = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetProfileIntA", t))?;
    let _key = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetProfileIntA", t))?;
    let default = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GetProfileIntA", t))?;
    Ok(default)
}

// ----- Corpus-driven additions --------------------------------------

/// `DWORD GetCurrentProcessId(void)`. Returns the PID owning
/// the active thread (`1` for the bootstrap process; Phase 5
/// will mint child PIDs).
fn stub_get_current_process_id(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(state.cur_thread().pid)
}

/// `void GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)`.
/// Writes a `FILETIME` (two `DWORD`s, little-endian: low then
/// high) representing 100-ns intervals since 1601-01-01 UTC.
/// We derive the value from `state.tick` so successive calls
/// return monotonically increasing timestamps without modelling
/// real wall-clock time. Most codecs use this for seeding RNGs
/// or for performance counters that just need monotonicity.
fn stub_get_system_time_as_file_time(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetSystemTimeAsFileTime", t))?;
    if p == 0 {
        return Ok(0);
    }
    // Synthesise a monotonically-increasing FILETIME by
    // multiplying the tick by 10000 (one tick ≈ 1 ms ≈ 10000
    // 100-ns units) and adding a base offset roughly equal to
    // 2024-01-01 in FILETIME units. Codecs that compare two
    // calls see strictly-increasing values.
    state.tick = state.tick.wrapping_add(1);
    let base: u64 = 133_482_240_000_000_000; // 2024-01-01 UTC in 100-ns ticks since 1601
    let ft = base.wrapping_add(u64::from(state.tick).wrapping_mul(10_000));
    let low = ft as u32;
    let high = (ft >> 32) as u32;
    mmu.store32(p, low)
        .map_err(|t| trap_to_win32("GetSystemTimeAsFileTime", t))?;
    mmu.store32(p.wrapping_add(4), high)
        .map_err(|t| trap_to_win32("GetSystemTimeAsFileTime", t))?;
    Ok(0)
}

/// `HANDLE GetCurrentThread(void)`. Pseudo-handle `-2` per the
/// Win32 ABI (current thread).
fn stub_get_current_thread(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0xFFFF_FFFE)
}

/// `LONG InterlockedExchange(LONG volatile *Target, LONG Value)`.
/// Atomically writes `Value` to `*Target` and returns the
/// previous value. Single-threaded emulator → no atomicity
/// dance needed.
fn stub_interlocked_exchange(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let target = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("InterlockedExchange", t))?;
    let value = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("InterlockedExchange", t))?;
    let prev = mmu
        .load32(target)
        .map_err(|t| trap_to_win32("InterlockedExchange", t))?;
    mmu.store32(target, value)
        .map_err(|t| trap_to_win32("InterlockedExchange", t))?;
    Ok(prev)
}

/// `LONG InterlockedCompareExchange(LONG volatile *Destination,
/// LONG Exchange, LONG Comparand)`. Returns the original value
/// at `*Destination`; if it equalled `Comparand`, writes
/// `Exchange` over it.
fn stub_interlocked_compare_exchange(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let dest =
        arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("InterlockedCompareExchange", t))?;
    let exchange =
        arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("InterlockedCompareExchange", t))?;
    let comparand =
        arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("InterlockedCompareExchange", t))?;
    let prev = mmu
        .load32(dest)
        .map_err(|t| trap_to_win32("InterlockedCompareExchange", t))?;
    if prev == comparand {
        mmu.store32(dest, exchange)
            .map_err(|t| trap_to_win32("InterlockedCompareExchange", t))?;
    }
    Ok(prev)
}

/// `LONG UnhandledExceptionFilter(EXCEPTION_POINTERS *)`. Real
/// behaviour: pops the system "this program has stopped working"
/// dialog. We return `EXCEPTION_CONTINUE_SEARCH = 0` so the SEH
/// chain keeps unwinding; codecs that wrap their entire init in
/// `__try` / `__except(UnhandledExceptionFilter(GetExceptionInformation()))`
/// won't intercept anything.
fn stub_unhandled_exception_filter(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `UINT SetErrorMode(UINT uMode)`. We don't model the system
/// error dialog so any mode is fine. Returns the previous mode
/// (synthetic 0).
fn stub_set_error_mode(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _new_mode = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("SetErrorMode", t))?;
    Ok(0)
}

/// `BOOL ResetEvent(HANDLE hEvent)`. Single-threaded emulator
/// has no real event objects; return 1 (success).
fn stub_reset_event(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("ResetEvent", t))?;
    Ok(1)
}

/// `DWORD WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles,
/// BOOL bWaitAll, DWORD dwMilliseconds)`. Always returns
/// `WAIT_OBJECT_0 = 0` — everything is "ready" in our
/// single-threaded sandbox.
fn stub_wait_for_multiple_objects(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _ncount = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("WaitForMultipleObjects", t))?;
    let _phandles =
        arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("WaitForMultipleObjects", t))?;
    let _waitall =
        arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("WaitForMultipleObjects", t))?;
    let _ms = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("WaitForMultipleObjects", t))?;
    Ok(0)
}

/// `HANDLE CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR)`.
/// Returns a synthetic non-NULL handle. Codecs use this to
/// coordinate between threads — we don't model threads, but the
/// codec just needs a non-zero handle to signal/wait on.
fn stub_create_event_w(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state.tick = state.tick.wrapping_add(1);
    Ok(0xE000_0000u32.wrapping_add(state.tick))
}

/// `HANDLE CreateSemaphoreW(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR)`.
/// Synthetic handle like [`stub_create_event_w`]; the codec
/// gets a non-NULL value, releases/waits are no-ops.
fn stub_create_semaphore_w(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state.tick = state.tick.wrapping_add(1);
    Ok(0xE100_0000u32.wrapping_add(state.tick))
}

/// `void GetLocalTime(LPSYSTEMTIME)`. Writes a 16-byte
/// `SYSTEMTIME` (wYear, wMonth, wDayOfWeek, wDay, wHour,
/// wMinute, wSecond, wMilliseconds — each `WORD`). We hand
/// back a fixed canned value (2024-01-01 00:00:00.000) so
/// codec-output bitstreams that embed timestamps are
/// deterministic across runs.
fn stub_get_local_time(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetLocalTime", t))?;
    if p == 0 {
        return Ok(0);
    }
    // wYear=2024, wMonth=1, wDayOfWeek=1 (Mon), wDay=1,
    // wHour=0, wMinute=0, wSecond=0, wMilliseconds=0
    let fields: [u16; 8] = [2024, 1, 1, 1, 0, 0, 0, 0];
    for (i, w) in fields.iter().enumerate() {
        mmu.store16(p.wrapping_add(i as u32 * 2), *w)
            .map_err(|t| trap_to_win32("GetLocalTime", t))?;
    }
    Ok(0)
}

/// `HMODULE GetModuleHandleW(LPCWSTR lpModuleName)`. Wide-char
/// sibling of `GetModuleHandleA`. `NULL` returns the primary
/// module base; otherwise resolve via `state.modules` (lower-cased
/// — `Sandbox::new` pre-registers the canonical system DLLs there
/// so codec CRTs that probe `GetModuleHandleW(L"KERNEL32.DLL")`
/// during init get a non-NULL handle back).
fn stub_get_module_handle_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetModuleHandleW", t))?;
    if p == 0 {
        return Ok(state.primary_module_base);
    }
    let name = read_wcstr(mmu, p, 260)?.to_ascii_lowercase();
    Ok(state.modules.get(&name).copied().unwrap_or(0))
}

/// Read a NUL-terminated wide (UTF-16LE) string from guest
/// memory and return it as a host `String` (lossily, ASCII-bias
/// — codec module names and CRT probes are all ASCII-clean).
fn read_wcstr(mmu: &Mmu, mut addr: u32, max: u32) -> Result<String, Win32Error> {
    let mut bytes = Vec::with_capacity(64);
    for _ in 0..max {
        let c = mmu
            .load16(addr)
            .map_err(|t| trap_to_win32("read_wcstr", t))?;
        if c == 0 {
            break;
        }
        bytes.push(c);
        addr = addr.wrapping_add(2);
    }
    Ok(String::from_utf16_lossy(&bytes))
}

/// `UINT GetPrivateProfileIntA(LPCSTR lpAppName, LPCSTR lpKeyName,
/// INT nDefault, LPCSTR lpFileName)`. We have no INI file to
/// consult; return the caller's default.
fn stub_get_private_profile_int_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _app = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetPrivateProfileIntA", t))?;
    let _key = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetPrivateProfileIntA", t))?;
    let default = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GetPrivateProfileIntA", t))?;
    let _file = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("GetPrivateProfileIntA", t))?;
    Ok(default)
}

/// `FARPROC WINAPI DelayLoadFailureHook(LPCSTR pszDllName,
/// LPCSTR pszProcName)`. VC++ delay-load glue. Real handler
/// returns 0 to signal "let the runtime raise an exception";
/// the codec sees a NULL pointer and either bails or falls
/// through to its own backup path. We do the same.
fn stub_delay_load_failure_hook(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _dll = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("DelayLoadFailureHook", t))?;
    let _proc = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("DelayLoadFailureHook", t))?;
    Ok(0)
}

// ----- Corpus round 2 -----------------------------------------------

/// `BOOL GetVersionExW(LPOSVERSIONINFOW lpVersionInformation)`.
/// Fills the OSVERSIONINFO[EX]W struct with values that
/// announce "Windows 7" (major 6.1, build 7600). Codecs that
/// gate on minimum-Windows-version checks pass.
fn stub_get_version_ex_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetVersionExW", t))?;
    if p == 0 {
        return Ok(0);
    }
    // First DWORD = dwOSVersionInfoSize. Codecs set this to
    // either sizeof(OSVERSIONINFOW)=276 or
    // sizeof(OSVERSIONINFOEXW)=284 before the call; we don't
    // overwrite it. Then: dwMajorVersion, dwMinorVersion,
    // dwBuildNumber, dwPlatformId (VER_PLATFORM_WIN32_NT = 2),
    // then szCSDVersion (128 wide chars). If the caller passed
    // a too-small struct we still write the first 5 dwords —
    // it's the caller's responsibility to set dwOSVersionInfoSize
    // correctly.
    mmu.store32(p.wrapping_add(4), 6)
        .map_err(|t| trap_to_win32("GetVersionExW", t))?;
    mmu.store32(p.wrapping_add(8), 1)
        .map_err(|t| trap_to_win32("GetVersionExW", t))?;
    mmu.store32(p.wrapping_add(12), 7600)
        .map_err(|t| trap_to_win32("GetVersionExW", t))?;
    mmu.store32(p.wrapping_add(16), 2)
        .map_err(|t| trap_to_win32("GetVersionExW", t))?;
    // Zero szCSDVersion[128] = 256 bytes
    let zeros = [0u8; 256];
    mmu.write(p.wrapping_add(20), &zeros)
        .map_err(|t| trap_to_win32("GetVersionExW", t))?;
    Ok(1)
}

/// `DWORD SignalObjectAndWait(HANDLE, HANDLE, DWORD, BOOL)`.
/// Single-threaded sandbox → return `WAIT_OBJECT_0`.
fn stub_signal_object_and_wait(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION,
/// DWORD)`. Returns 1; we model critical sections as no-ops.
fn stub_init_cs_spin(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `BOOL IsDebuggerPresent(void)`. We say "no" — codecs that
/// gate anti-analysis behaviour on this take the non-debugger
/// branch. https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent
fn stub_is_debugger_present(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize,
/// DWORD flNewProtect, PDWORD lpflOldProtect)`. Actually
/// updates the MMU permissions for every page in
/// `[lpAddress, lpAddress + dwSize)`. The bytes are preserved
/// — `Mmu::map` rewrites the perm slot without touching page
/// contents. Required by codecs (e.g. `wmvdecod.dll`) that
/// self-patch a thunk inside their own `.text` section during
/// `DllMain` by flipping it RW, writing, then flipping it
/// back. `lpflOldProtect` receives the prior protection of the
/// first page in the range — sufficient for the
/// flip-write-flip pattern.
fn stub_virtual_protect(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let addr = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("VirtualProtect", t))?;
    let size = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("VirtualProtect", t))?;
    let new = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("VirtualProtect", t))?;
    let out = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("VirtualProtect", t))?;
    // MSDN: all pages in the range must already be committed;
    // return FALSE if any unmapped page is hit.
    if size == 0 || !mmu.is_mapped(addr) {
        return Ok(0);
    }
    let old_perm = mmu.perm_at(addr).unwrap_or(Perm::from_bits(0));
    if out != 0 {
        mmu.store32(out, perm_to_page_protect(old_perm))
            .map_err(|t| trap_to_win32("VirtualProtect", t))?;
    }
    let new_perm = page_protect_to_perm(new);
    mmu.map(addr, size, new_perm);
    Ok(1)
}

/// `LONG InterlockedExchangeAdd(LONG volatile *Addend, LONG Value)`.
/// Atomically adds `Value` to `*Addend` and returns the
/// previous value.
fn stub_interlocked_exchange_add(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let addend = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("InterlockedExchangeAdd", t))?;
    let value = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("InterlockedExchangeAdd", t))?;
    let prev = mmu
        .load32(addend)
        .map_err(|t| trap_to_win32("InterlockedExchangeAdd", t))?;
    let new = prev.wrapping_add(value);
    mmu.store32(addend, new)
        .map_err(|t| trap_to_win32("InterlockedExchangeAdd", t))?;
    Ok(prev)
}

/// `BOOL GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize)`.
/// Writes a canned ASCII name and updates `*nSize`.
fn stub_get_computer_name_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let buf = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetComputerNameA", t))?;
    let n_ptr = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetComputerNameA", t))?;
    let name = b"UDEMULATOR\0";
    let mut cap = 0u32;
    if n_ptr != 0 {
        cap = mmu
            .load32(n_ptr)
            .map_err(|t| trap_to_win32("GetComputerNameA", t))?;
        mmu.store32(n_ptr, name.len() as u32 - 1)
            .map_err(|t| trap_to_win32("GetComputerNameA", t))?;
    }
    if buf != 0 && cap as usize >= name.len() {
        mmu.write(buf, name)
            .map_err(|t| trap_to_win32("GetComputerNameA", t))?;
    }
    Ok(1)
}

/// `DWORD GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR
/// lpBuffer, DWORD nSize)`. We have no environment — return 0
/// and let the caller take its default branch.
fn stub_get_environment_variable_w(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL GetProcessAffinityMask(HANDLE hProcess,
/// PDWORD_PTR lpProcessAffinityMask,
/// PDWORD_PTR lpSystemAffinityMask)`. Reports a single-CPU
/// system (mask 1). Codecs use this to decide how many worker
/// threads to spawn.
fn stub_get_process_affinity_mask(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetProcessAffinityMask", t))?;
    let proc_mask =
        arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetProcessAffinityMask", t))?;
    let sys_mask =
        arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GetProcessAffinityMask", t))?;
    if proc_mask != 0 {
        mmu.store32(proc_mask, 1)
            .map_err(|t| trap_to_win32("GetProcessAffinityMask", t))?;
    }
    if sys_mask != 0 {
        mmu.store32(sys_mask, 1)
            .map_err(|t| trap_to_win32("GetProcessAffinityMask", t))?;
    }
    Ok(1)
}

/// `int GetThreadPriority(HANDLE hThread)`. Returns `THREAD_PRIORITY_NORMAL = 0`.
fn stub_get_thread_priority(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `DWORD_PTR SetThreadAffinityMask(HANDLE, DWORD_PTR)`.
/// Returns the previous affinity mask (synthetic 1).
fn stub_set_thread_affinity_mask(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `HMODULE LoadLibraryW(LPCWSTR lpLibFileName)`. We don't
/// load arbitrary host DLLs into the guest; return 0 (failure)
/// so the codec falls through to a backup path. Codecs that
/// require a successful LoadLibrary tend to be the optional-
/// codec-pack splitter shapes we don't try to fully drive.
fn stub_load_library_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LoadLibraryW", t))?;
    if p == 0 {
        return Ok(0);
    }
    let name = read_wcstr(mmu, p, 260)?.to_ascii_lowercase();
    Ok(state.modules.get(&name).copied().unwrap_or(0))
}

/// `BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)`.
/// When the handle was minted by the virtual filesystem, copies
/// the bytes into the guest buffer; otherwise reports "read 0
/// bytes" success (the historical no-FS fallback).
fn stub_read_file(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("ReadFile", t))?;
    let buf = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("ReadFile", t))?;
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("ReadFile", t))?;
    let out = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("ReadFile", t))?;
    if let Some(vfs) = state.context.vfs.as_mut() {
        if vfs.owns(h) && buf != 0 {
            let mut tmp = vec![0u8; n as usize];
            let got = vfs.read_handle(h, &mut tmp).unwrap_or(0);
            if got > 0 {
                mmu.write(buf, &tmp[..got])
                    .map_err(|t| trap_to_win32("ReadFile", t))?;
            }
            if out != 0 {
                mmu.store32(out, got as u32)
                    .map_err(|t| trap_to_win32("ReadFile", t))?;
            }
            return Ok(1);
        }
    }
    if out != 0 {
        mmu.store32(out, 0)
            .map_err(|t| trap_to_win32("ReadFile", t))?;
    }
    Ok(1)
}

// ============================================================
// Codec-corpus probe stubs
// ============================================================

/// Generic fail-soft stub: returns 0 (FALSE / NULL / "no").
fn stub_returns_zero(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// Generic success stub: returns 1 (TRUE).
fn stub_returns_true(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// Bound for the in-stub C-string scan loops below.
const CSTR_SCAN_CAP: u32 = 0x1_0000;

/// `LPSTR lstrcatA(LPSTR lpString1, LPCSTR lpString2)`. Appends
/// `lpString2` onto the NUL-terminated `lpString1`. Returns
/// `lpString1`.
fn stub_lstrcat_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let dst = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("lstrcatA", t))?;
    let src = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("lstrcatA", t))?;
    if dst == 0 {
        return Ok(0);
    }
    let mut end = dst;
    let mut scanned = 0u32;
    while scanned < CSTR_SCAN_CAP && mmu.load8(end).map_err(|t| trap_to_win32("lstrcatA", t))? != 0
    {
        end = end.wrapping_add(1);
        scanned += 1;
    }
    if src != 0 {
        let mut i = 0u32;
        loop {
            let b = mmu
                .load8(src.wrapping_add(i))
                .map_err(|t| trap_to_win32("lstrcatA", t))?;
            mmu.store8(end.wrapping_add(i), b)
                .map_err(|t| trap_to_win32("lstrcatA", t))?;
            if b == 0 || i >= CSTR_SCAN_CAP {
                break;
            }
            i += 1;
        }
    } else {
        mmu.store8(end, 0)
            .map_err(|t| trap_to_win32("lstrcatA", t))?;
    }
    Ok(dst)
}

/// `LPSTR lstrcpyA(LPSTR lpString1, LPCSTR lpString2)`. Copies
/// `lpString2` (incl. NUL) into `lpString1`. Returns
/// `lpString1`.
fn stub_lstrcpy_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let dst = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("lstrcpyA", t))?;
    let src = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("lstrcpyA", t))?;
    if dst == 0 {
        return Ok(0);
    }
    if src == 0 {
        mmu.store8(dst, 0)
            .map_err(|t| trap_to_win32("lstrcpyA", t))?;
        return Ok(dst);
    }
    let mut i = 0u32;
    loop {
        let b = mmu
            .load8(src.wrapping_add(i))
            .map_err(|t| trap_to_win32("lstrcpyA", t))?;
        mmu.store8(dst.wrapping_add(i), b)
            .map_err(|t| trap_to_win32("lstrcpyA", t))?;
        if b == 0 || i >= CSTR_SCAN_CAP {
            break;
        }
        i += 1;
    }
    Ok(dst)
}

/// Read a NUL-terminated ASCII string, lower-cased, for the
/// case-insensitive comparisons below.
fn read_cstr_lower(mmu: &Mmu, base: u32) -> Vec<u8> {
    let mut out = Vec::new();
    if base == 0 {
        return out;
    }
    for i in 0..CSTR_SCAN_CAP {
        match mmu.load8(base.wrapping_add(i)) {
            Ok(0) | Err(_) => break,
            Ok(b) => out.push(b.to_ascii_lowercase()),
        }
    }
    out
}

/// `int lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2)`. Case-
/// insensitive ordinal compare; returns a negative / zero /
/// positive value like the C `strcmp` family.
fn stub_lstrcmpi_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let s1 = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("lstrcmpiA", t))?;
    let s2 = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("lstrcmpiA", t))?;
    let a = read_cstr_lower(mmu, s1);
    let b = read_cstr_lower(mmu, s2);
    Ok(match a.cmp(&b) {
        std::cmp::Ordering::Less => (-1i32) as u32,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}

// CompareString return values — `winnls.h`.
const CSTR_LESS_THAN: u32 = 1;
const CSTR_EQUAL: u32 = 2;
const CSTR_GREATER_THAN: u32 = 3;

fn cmp_to_cstr(ord: std::cmp::Ordering) -> u32 {
    match ord {
        std::cmp::Ordering::Less => CSTR_LESS_THAN,
        std::cmp::Ordering::Equal => CSTR_EQUAL,
        std::cmp::Ordering::Greater => CSTR_GREATER_THAN,
    }
}

/// `int CompareStringA(LCID, DWORD dwCmpFlags, LPCSTR lpString1,
/// int cchCount1, LPCSTR lpString2, int cchCount2)`. Ordinal
/// compare of the two NUL-terminated strings (explicit lengths
/// ignored — the CRT collate path passes `-1`). Returns
/// `CSTR_LESS_THAN` / `CSTR_EQUAL` / `CSTR_GREATER_THAN`.
fn stub_compare_string_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let s1 = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("CompareStringA", t))?;
    let s2 = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("CompareStringA", t))?;
    let a = read_cstr_lower(mmu, s1);
    let b = read_cstr_lower(mmu, s2);
    Ok(cmp_to_cstr(a.cmp(&b)))
}

/// `int CompareStringW(...)`. Wide twin of [`stub_compare_string_a`].
fn stub_compare_string_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let s1 = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("CompareStringW", t))?;
    let s2 = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("CompareStringW", t))?;
    let read_w = |base: u32| -> Vec<u16> {
        let mut out = Vec::new();
        if base == 0 {
            return out;
        }
        for i in 0..CSTR_SCAN_CAP {
            match mmu.load16(base.wrapping_add(i * 2)) {
                Ok(0) | Err(_) => break,
                Ok(c) => out.push(c),
            }
        }
        out
    };
    let a = read_w(s1);
    let b = read_w(s2);
    Ok(cmp_to_cstr(a.cmp(&b)))
}

/// `void FatalAppExitA(UINT uAction, LPCSTR lpMessageText)`.
/// The CRT links this for its abort path; the sandbox never
/// reaches it on a healthy decode. No-op.
fn stub_fatal_app_exit_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `void GetSystemTime(LPSYSTEMTIME lpSystemTime)`. Fills the
/// 16-byte `SYSTEMTIME` with a fixed 2024-01-01T00:00:00 stamp.
fn stub_get_system_time(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetSystemTime", t))?;
    if p == 0 {
        return Ok(0);
    }
    // wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond,
    // wMilliseconds — 2024-01-01 was a Monday (wDayOfWeek = 1).
    let fields: [u16; 8] = [2024, 1, 1, 1, 0, 0, 0, 0];
    for (i, v) in fields.iter().enumerate() {
        mmu.store16(p.wrapping_add(i as u32 * 2), *v)
            .map_err(|t| trap_to_win32("GetSystemTime", t))?;
    }
    Ok(0)
}

/// `DWORD GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTzi)`.
/// Zeroes the 172-byte struct and reports `TIME_ZONE_ID_UNKNOWN`
/// (0) — the sandbox runs in a fixed, DST-free UTC.
fn stub_get_time_zone_information(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetTimeZoneInformation", t))?;
    if p != 0 {
        mmu.write(p, &[0u8; 172])
            .map_err(|t| trap_to_win32("GetTimeZoneInformation", t))?;
    }
    Ok(0)
}

/// `HMODULE LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile,
/// DWORD dwFlags)`. Resolves like `LoadLibraryA`, ignoring the
/// flags — a loaded module returns its image base, otherwise 0.
fn stub_load_library_ex_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LoadLibraryExA", t))?;
    let name = read_cstr(mmu, p, 260)?.to_ascii_lowercase();
    Ok(state.modules.get(&name).copied().unwrap_or(0))
}

/// `BOOL WriteConsoleA(HANDLE, const VOID*, DWORD nNumberOfChars,
/// LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved)`. Discards
/// the output, reports all characters written.
fn stub_write_console_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("WriteConsoleA", t))?;
    let written = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("WriteConsoleA", t))?;
    if written != 0 {
        mmu.store32(written, n)
            .map_err(|t| trap_to_win32("WriteConsoleA", t))?;
    }
    Ok(1)
}

/// `PVOID EncodePointer/DecodePointer(PVOID Ptr)`. Modelled as
/// the identity transform — a valid no-op implementation, since
/// `Decode(Encode(p)) == p` holds trivially.
fn stub_identity_pointer(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("EncodePointer/DecodePointer", t))
}

/// `DWORD GetModuleFileNameW(HMODULE, LPWSTR lpFilename,
/// DWORD nSize)`. Wide twin of `GetModuleFileNameA` — writes
/// `"oxideav-vfw"` as UTF-16, returns the character count.
fn stub_get_module_file_name_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetModuleFileNameW", t))?;
    let dst = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetModuleFileNameW", t))?;
    let n_size = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GetModuleFileNameW", t))?;
    if dst == 0 || n_size == 0 {
        return Ok(0);
    }
    let s = "oxideav-vfw";
    let mut written = 0u32;
    for (i, c) in s.chars().enumerate() {
        if (i as u32) >= n_size.saturating_sub(1) {
            break;
        }
        mmu.store16(dst + i as u32 * 2, c as u16)
            .map_err(|t| trap_to_win32("GetModuleFileNameW", t))?;
        written += 1;
    }
    let nul_off = written.min(n_size - 1);
    mmu.store16(dst + nul_off * 2, 0)
        .map_err(|t| trap_to_win32("GetModuleFileNameW", t))?;
    Ok(written)
}

/// `void GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)`. Wide
/// twin of `GetStartupInfoA` — `STARTUPINFOW` is also 68 bytes
/// on 32-bit; zero it and stamp `cb`.
fn stub_get_startup_info_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetStartupInfoW", t))?;
    if p == 0 {
        return Ok(0);
    }
    mmu.write(p, &[0u8; 68])
        .map_err(|t| trap_to_win32("GetStartupInfoW", t))?;
    mmu.store32(p, 68)
        .map_err(|t| trap_to_win32("GetStartupInfoW", t))?;
    Ok(0)
}

/// `LCID GetUserDefaultLCID(void)`. Reports `en-US` (0x0409).
fn stub_get_user_default_lcid(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0x0409)
}

/// `DWORD GetLongPathNameA(LPCSTR lpszShortPath,
/// LPSTR lpszLongPath, DWORD cchBuffer)`. The sandbox draws no
/// short/long distinction — echo the input path back and report
/// its length.
fn stub_get_long_path_name_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let short = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetLongPathNameA", t))?;
    let long = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetLongPathNameA", t))?;
    let cch = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GetLongPathNameA", t))?;
    let path = read_cstr(mmu, short, CSTR_SCAN_CAP)?;
    let len = path.len() as u32;
    // MSDN: when the buffer is too small (or NULL) the return
    // value is the required size, including the terminating NUL.
    if long == 0 || cch < len + 1 {
        return Ok(len + 1);
    }
    let mut bytes = path.into_bytes();
    bytes.push(0);
    mmu.write(long, &bytes)
        .map_err(|t| trap_to_win32("GetLongPathNameA", t))?;
    Ok(len)
}

/// `BOOL GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName,
/// HMODULE *phModule)`. Resolves like `GetModuleHandleA` and
/// writes the handle through `phModule`. Returns TRUE.
fn stub_get_module_handle_ex_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let name_p = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetModuleHandleExA", t))?;
    let out = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GetModuleHandleExA", t))?;
    let handle = if name_p == 0 {
        state.primary_module_base
    } else {
        let name = read_cstr(mmu, name_p, 260)?.to_ascii_lowercase();
        state.modules.get(&name).copied().unwrap_or(0)
    };
    if out != 0 {
        mmu.store32(out, handle)
            .map_err(|t| trap_to_win32("GetModuleHandleExA", t))?;
    }
    Ok(1)
}

// ============================================================
// Install-monitor stub implementations
// ============================================================

/// Canonical temp directory string handed back to the guest. Kept
/// in one place so the monitor's "what did the installer write?"
/// report can match `c:/temp/*` paths reliably.
const TEMP_PATH_A: &[u8] = b"C:\\Temp\\\0";

/// Write `s` into the guest buffer at `dst`, capped at `cch`
/// bytes (including the NUL). Returns the number of bytes
/// actually written (excluding the NUL).
fn write_cstr(
    mmu: &mut Mmu,
    dst: u32,
    cch: u32,
    s: &[u8],
    stub: &'static str,
) -> Result<u32, Win32Error> {
    if dst == 0 || cch == 0 {
        return Ok(0);
    }
    let cap = cch.saturating_sub(1) as usize;
    let n = s.len().min(cap);
    if n > 0 {
        mmu.write(dst, &s[..n])
            .map_err(|t| trap_to_win32(stub, t))?;
    }
    mmu.store8(dst + n as u32, 0)
        .map_err(|t| trap_to_win32(stub, t))?;
    Ok(n as u32)
}

/// `DWORD GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer)`.
/// Writes `"C:\\Temp\\"` (length 8) plus a NUL into the buffer.
/// Returns the path length (excluding NUL). If the buffer is too
/// small, returns the required length including NUL — matching
/// the MSDN contract.
fn stub_get_temp_path_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let n_buf = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetTempPathA", t))?;
    let lp_buf = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetTempPathA", t))?;
    let path = &TEMP_PATH_A[..TEMP_PATH_A.len() - 1]; // strip trailing NUL
    let need = path.len() as u32 + 1; // including NUL
    if lp_buf == 0 || n_buf < need {
        return Ok(need);
    }
    write_cstr(mmu, lp_buf, n_buf, path, "GetTempPathA")?;
    Ok(path.len() as u32)
}

/// `UINT GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString,
/// UINT uUnique, LPSTR lpTempFileName)`. Builds a deterministic
/// `pathname\prefix<unique>.tmp` string and writes it back. When
/// `uUnique == 0`, picks a fresh counter from the tick. Creates a
/// zero-byte entry in the VFS so a follow-up `CreateFileA` sees
/// the file.
fn stub_get_temp_file_name_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_path = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetTempFileNameA", t))?;
    let p_prefix = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetTempFileNameA", t))?;
    let mut unique = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("GetTempFileNameA", t))?;
    let dst = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("GetTempFileNameA", t))?;
    let path = if p_path != 0 {
        read_cstr(mmu, p_path, 260)?
    } else {
        String::new()
    };
    let prefix = if p_prefix != 0 {
        read_cstr(mmu, p_prefix, 3)?
    } else {
        String::new()
    };
    if unique == 0 {
        state.tick = state.tick.wrapping_add(1);
        unique = state.tick;
    }
    let trimmed = path.trim_end_matches(['\\', '/']);
    let full = if trimmed.is_empty() {
        format!("{prefix}{unique:04X}.tmp")
    } else {
        format!("{trimmed}\\{prefix}{unique:04X}.tmp")
    };
    if let Some(vfs) = state.context.vfs.as_mut() {
        vfs.insert(&full, Vec::new());
    }
    write_cstr(mmu, dst, 260, full.as_bytes(), "GetTempFileNameA")?;
    Ok(unique)
}

/// `HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
/// DWORD dwShareMode, LPSECURITY_ATTRIBUTES, DWORD dwCreationDisposition,
/// DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)`. Routes the
/// open through the VFS when one is attached; returns
/// `INVALID_HANDLE_VALUE` (= `0xFFFFFFFF`) otherwise. The MSDN
/// `dwCreationDisposition` axis is honoured at a coarse level —
/// `CREATE_ALWAYS` / `CREATE_NEW` / `TRUNCATE_EXISTING` truncate
/// the backing file; `OPEN_EXISTING` fails when the file is
/// absent.
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const TRUNCATE_EXISTING: u32 = 5;
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_FILE_EXISTS: u32 = 80;

fn stub_create_file_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_name = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("CreateFileA", t))?;
    let access = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("CreateFileA", t))?;
    let _share = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("CreateFileA", t))?;
    let _sa = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("CreateFileA", t))?;
    let disp = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("CreateFileA", t))?;
    let _attrs = arg_dword(cpu, mmu, 5).map_err(|t| trap_to_win32("CreateFileA", t))?;
    let _tmpl = arg_dword(cpu, mmu, 6).map_err(|t| trap_to_win32("CreateFileA", t))?;
    if p_name == 0 {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(INVALID_HANDLE_VALUE);
    }
    let name = read_cstr(mmu, p_name, 260)?;
    let Some(vfs) = state.context.vfs.as_mut() else {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(INVALID_HANDLE_VALUE);
    };
    let exists = vfs.contains(&name);
    match disp {
        OPEN_EXISTING => {
            if !exists {
                state.last_error = ERROR_FILE_NOT_FOUND;
                return Ok(INVALID_HANDLE_VALUE);
            }
        }
        CREATE_NEW => {
            if exists {
                state.last_error = ERROR_FILE_EXISTS;
                return Ok(INVALID_HANDLE_VALUE);
            }
            vfs.insert(&name, Vec::new());
        }
        CREATE_ALWAYS | TRUNCATE_EXISTING => {
            vfs.write_path(&name, Vec::new());
        }
        _ => {
            // OPEN_ALWAYS (4) and unknown values: open if exists,
            // create empty otherwise.
            if !exists {
                vfs.insert(&name, Vec::new());
            }
        }
    }
    let fa = crate::context::FileAccess::from_win32_desired_access(access);
    match vfs.open(&name, fa) {
        Some(h) => Ok(h),
        None => {
            state.last_error = ERROR_FILE_NOT_FOUND;
            Ok(INVALID_HANDLE_VALUE)
        }
    }
}

/// `BOOL CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES
/// lpSecurityAttributes)`. Creates a `<path>/.dir` marker in the
/// VFS so directory existence is observable; otherwise reports
/// success. Returns FALSE only when the path is NULL or already
/// recorded.
fn stub_create_directory_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_name = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("CreateDirectoryA", t))?;
    let _sa = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("CreateDirectoryA", t))?;
    if p_name == 0 {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(0);
    }
    let name = read_cstr(mmu, p_name, 260)?;
    let marker = format!("{}\\.dir", name.trim_end_matches(['\\', '/']));
    if let Some(vfs) = state.context.vfs.as_mut() {
        if vfs.contains(&marker) {
            state.last_error = ERROR_FILE_EXISTS;
            return Ok(0);
        }
        vfs.insert(&marker, Vec::new());
    }
    Ok(1)
}

/// `BOOL DeleteFileA(LPCSTR lpFileName)`. Removes from the VFS
/// when present; reports success even without a VFS attached.
fn stub_delete_file_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_name = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("DeleteFileA", t))?;
    if p_name == 0 {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(0);
    }
    let name = read_cstr(mmu, p_name, 260)?;
    if let Some(vfs) = state.context.vfs.as_mut() {
        vfs.remove(&name);
    }
    Ok(1)
}

/// `DWORD GetFileAttributesA(LPCSTR lpFileName)`. Reports
/// `FILE_ATTRIBUTE_NORMAL = 0x80` when the path exists in the
/// VFS (file or `.dir` marker); otherwise returns
/// `INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF`.
fn stub_get_file_attributes_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_name = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetFileAttributesA", t))?;
    if p_name == 0 {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(0xFFFF_FFFF);
    }
    let name = read_cstr(mmu, p_name, 260)?;
    let Some(vfs) = state.context.vfs.as_ref() else {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(0xFFFF_FFFF);
    };
    if vfs.contains(&name) {
        return Ok(0x80); // FILE_ATTRIBUTE_NORMAL
    }
    let dir_marker = format!("{}\\.dir", name.trim_end_matches(['\\', '/']));
    if vfs.contains(&dir_marker) {
        return Ok(0x10); // FILE_ATTRIBUTE_DIRECTORY
    }
    state.last_error = ERROR_FILE_NOT_FOUND;
    Ok(0xFFFF_FFFF)
}

/// `DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)`.
/// Returns the low dword of the file size (high dword written
/// through `lpFileSizeHigh` when non-NULL). `INVALID_FILE_SIZE
/// = 0xFFFFFFFF` for unknown handles.
fn stub_get_file_size(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetFileSize", t))?;
    let p_hi = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetFileSize", t))?;
    if let Some(vfs) = state.context.vfs.as_ref() {
        if let Some(sz) = vfs.size(h) {
            if p_hi != 0 {
                mmu.store32(p_hi, (sz >> 32) as u32)
                    .map_err(|t| trap_to_win32("GetFileSize", t))?;
            }
            return Ok(sz as u32);
        }
    }
    state.last_error = ERROR_INVALID_HANDLE;
    Ok(0xFFFF_FFFF)
}

/// `BOOL DosDateTimeToFileTime(WORD wFatDate, WORD wFatTime,
/// LPFILETIME lpFileTime)`. Pure conversion — no environment
/// state. We emit a deterministic FILETIME for the given pair so
/// the installer's archive-extract path proceeds.
fn stub_dos_date_time_to_file_time(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let fat_date =
        arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("DosDateTimeToFileTime", t))? & 0xFFFF;
    let fat_time =
        arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("DosDateTimeToFileTime", t))? & 0xFFFF;
    let p_out = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("DosDateTimeToFileTime", t))?;
    if p_out == 0 {
        return Ok(0);
    }
    let year = 1980 + ((fat_date >> 9) & 0x7F) as i32;
    let month = ((fat_date >> 5) & 0x0F).max(1) as i32;
    let day = (fat_date & 0x1F).max(1) as i32;
    let hour = ((fat_time >> 11) & 0x1F) as i32;
    let minute = ((fat_time >> 5) & 0x3F) as i32;
    let second = ((fat_time & 0x1F) * 2) as i32;
    // Days from 1601-01-01 to year-01-01 (approx — ignore leap-day
    // distribution beyond Gregorian arithmetic). This is the
    // "FILETIME = 100-ns ticks since 1601-01-01" surface; the
    // installer only needs a strictly-increasing reproducible
    // value, not a precise calendar conversion.
    let days_from_1601 = (year - 1601) as i64 * 365 + ((year - 1601) / 4) as i64
        - ((year - 1601) / 100) as i64
        + ((year - 1601) / 400) as i64;
    let month_days = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut day_of_year = month_days[(month - 1).clamp(0, 11) as usize] as i64;
    if month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        day_of_year += 1;
    }
    day_of_year += day as i64 - 1;
    let total_days = days_from_1601 + day_of_year;
    let total_seconds =
        total_days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
    let ticks = (total_seconds * 10_000_000) as u64;
    mmu.store32(p_out, ticks as u32)
        .map_err(|t| trap_to_win32("DosDateTimeToFileTime", t))?;
    mmu.store32(p_out + 4, (ticks >> 32) as u32)
        .map_err(|t| trap_to_win32("DosDateTimeToFileTime", t))?;
    Ok(1)
}

/// `HANDLE CreateMutexA(LPSECURITY_ATTRIBUTES, BOOL bInitialOwner,
/// LPCSTR lpName)`. We don't model mutexes; hand back a non-zero
/// synthetic handle so the installer's RAII wrapper doesn't bail.
fn stub_create_mutex_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state.next_hic = state.next_hic.wrapping_add(1);
    Ok(0x6A00_0000 | state.next_hic)
}

/// `BOOL CreateProcessA(...)`. The installer occasionally spawns
/// a helper (verifier, rollback agent). The sandbox can't actually
/// fork — we report failure with `ERROR_FILE_NOT_FOUND` so the
/// caller falls into its single-process fallback path.
fn stub_create_process_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state.last_error = ERROR_FILE_NOT_FOUND;
    Ok(0)
}

/// `BOOL GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode)`.
/// Always reports `STILL_ACTIVE = 259` so callers that block on
/// the spawned process don't observe a misleading 0 exit code.
fn stub_get_exit_code_process(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetExitCodeProcess", t))?;
    let p = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetExitCodeProcess", t))?;
    if p != 0 {
        mmu.store32(p, 259)
            .map_err(|t| trap_to_win32("GetExitCodeProcess", t))?;
    }
    Ok(1)
}

/// `UINT GetConsoleCP(void)` / `UINT GetConsoleOutputCP(void)`.
/// CP_OEMCP = 437 — the historical US OEM code page. Installers
/// only consult this to choose a banner-string encoding.
fn stub_get_console_cp(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(437)
}

/// `BOOL GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode)`.
/// No console attached — report failure so the caller's
/// "redirected to file" branch runs.
fn stub_get_console_mode(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetConsoleMode", t))?;
    let p = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetConsoleMode", t))?;
    if p != 0 {
        mmu.store32(p, 0)
            .map_err(|t| trap_to_win32("GetConsoleMode", t))?;
    }
    state.last_error = ERROR_INVALID_HANDLE;
    Ok(0)
}

/// `BOOL LocalFileTimeToFileTime(const FILETIME *lpLocalFileTime,
/// LPFILETIME lpFileTime)`. Single-timezone sandbox — copy the
/// 8-byte FILETIME through unchanged.
fn stub_local_file_time_to_file_time(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_src = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("LocalFileTimeToFileTime", t))?;
    let p_dst = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("LocalFileTimeToFileTime", t))?;
    if p_src == 0 || p_dst == 0 {
        return Ok(0);
    }
    let lo = mmu
        .load32(p_src)
        .map_err(|t| trap_to_win32("LocalFileTimeToFileTime", t))?;
    let hi = mmu
        .load32(p_src + 4)
        .map_err(|t| trap_to_win32("LocalFileTimeToFileTime", t))?;
    mmu.store32(p_dst, lo)
        .map_err(|t| trap_to_win32("LocalFileTimeToFileTime", t))?;
    mmu.store32(p_dst + 4, hi)
        .map_err(|t| trap_to_win32("LocalFileTimeToFileTime", t))?;
    Ok(1)
}

/// `BOOL RemoveDirectoryA(LPCSTR lpPathName)`. Drops the
/// directory marker from the VFS; success either way.
fn stub_remove_directory_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_name = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("RemoveDirectoryA", t))?;
    if p_name == 0 {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(0);
    }
    let name = read_cstr(mmu, p_name, 260)?;
    let marker = format!("{}\\.dir", name.trim_end_matches(['\\', '/']));
    if let Some(vfs) = state.context.vfs.as_mut() {
        vfs.remove(&marker);
    }
    Ok(1)
}

/// `BOOL WriteConsoleW(HANDLE hConsoleOutput, const VOID *lpBuffer,
/// DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten,
/// LPVOID lpReserved)`. Captures the UTF-16 buffer into the
/// `debug_log` so the monitor's "what did the installer say?"
/// view picks it up. Reports the full count as written.
fn stub_write_console_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("WriteConsoleW", t))?;
    let p_buf = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("WriteConsoleW", t))?;
    let n_chars = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("WriteConsoleW", t))?;
    let lp_written = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("WriteConsoleW", t))?;
    let _resv = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("WriteConsoleW", t))?;
    if p_buf != 0 && n_chars > 0 {
        let cap = (n_chars as usize).min(4096);
        let mut units = Vec::with_capacity(cap);
        for i in 0..cap {
            units.push(
                mmu.load16(p_buf + (i as u32) * 2)
                    .map_err(|t| trap_to_win32("WriteConsoleW", t))?,
            );
        }
        let s = String::from_utf16_lossy(&units);
        state.debug_log.push(s);
    }
    if lp_written != 0 {
        mmu.store32(lp_written, n_chars)
            .map_err(|t| trap_to_win32("WriteConsoleW", t))?;
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::mmu::Perm;
    use crate::emulator::regs::Reg32;
    use crate::win32::Registry;

    fn make_env() -> (Cpu, Mmu, Registry, HostState) {
        let mut mmu = Mmu::new();
        // Heap arena
        mmu.map(0x4000, 0x4000, Perm::R | Perm::W);
        // Stack
        mmu.map(0x9000, 0x1000, Perm::R | Perm::W);
        let mut cpu = Cpu::new();
        cpu.regs.set_esp(0x9F00);
        let mut registry = Registry::new();
        registry.register_kernel32();
        let state = HostState::new(0x4000, 0x8000);
        (cpu, mmu, registry, state)
    }

    fn push_args_and_call(
        cpu: &mut Cpu,
        mmu: &mut Mmu,
        registry: &Registry,
        state: &mut HostState,
        dll: &str,
        name: &str,
        args: &[u32],
    ) -> Result<(), crate::Error> {
        // Push args right-to-left.
        for a in args.iter().rev() {
            cpu.push32(mmu, *a)?;
        }
        // Push synthetic ret addr.
        cpu.push32(mmu, 0xDEAD_DEAD)?;
        cpu.regs.eip = registry.resolve(dll, name).expect("registered");
        crate::win32::dispatch_stub(cpu, mmu, registry, state)
    }

    #[test]
    fn registers_at_least_twelve_kernel32_stubs() {
        let mut r = Registry::new();
        let n = r.register_kernel32();
        assert!(n >= 12, "expected ≥ 12 round-1 stubs, got {n}");
    }

    #[test]
    fn get_process_heap_returns_canned_handle() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "GetProcessHeap",
            &[],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xDEAD_BEEF);
    }

    #[test]
    fn heap_alloc_then_heap_free_roundtrip() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "HeapAlloc",
            &[0xDEAD_BEEF, 0, 64],
        )
        .unwrap();
        let addr = cpu.regs.get32(Reg32::Eax);
        assert_ne!(addr, 0);
        assert!(state.heap.contains_key(&addr));

        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "HeapFree",
            &[0xDEAD_BEEF, 0, addr],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 1);
        assert!(!state.heap.contains_key(&addr));
    }

    #[test]
    fn heap_alloc_zero_fills_when_flag_set() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "HeapAlloc",
            &[0xDEAD_BEEF, HEAP_ZERO_MEMORY, 16],
        )
        .unwrap();
        let addr = cpu.regs.get32(Reg32::Eax);
        for i in 0..16 {
            assert_eq!(mmu.load8(addr + i).unwrap(), 0);
        }
    }

    #[test]
    fn heap_free_invalid_pointer_errors() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let bad = 0xBAD_ADD00u32;
        let r = push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "HeapFree",
            &[0xDEAD_BEEF, 0, bad],
        );
        match r {
            Err(crate::Error::Win32(Win32Error::InvalidHeapBlock { addr, .. })) if addr == bad => {}
            other => panic!("expected InvalidHeapBlock, got {other:?}"),
        }
    }

    #[test]
    fn local_alloc_local_free() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "LocalAlloc",
            &[LMEM_ZEROINIT, 32],
        )
        .unwrap();
        let addr = cpu.regs.get32(Reg32::Eax);
        assert_ne!(addr, 0);
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "LocalFree",
            &[addr],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0);
    }

    #[test]
    fn output_debug_string_a_logs() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // Lay out "hi\0" at 0x4000 (heap arena start, R+W).
        mmu.write(0x4000, b"hi\0").unwrap();
        // Bump the heap_cursor to skip those bytes for cleanliness.
        state.heap_cursor = 0x4010;
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "OutputDebugStringA",
            &[0x4000],
        )
        .unwrap();
        assert_eq!(state.debug_log.last().unwrap(), "hi");
    }

    #[test]
    fn get_tick_count_monotonic() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "GetTickCount",
            &[],
        )
        .unwrap();
        let t1 = cpu.regs.get32(Reg32::Eax);
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "GetTickCount",
            &[],
        )
        .unwrap();
        let t2 = cpu.regs.get32(Reg32::Eax);
        assert!(t2 > t1);
    }

    #[test]
    fn interlocked_increment_decrement_roundtrip() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // Place a u32 = 5 at 0x4000.
        mmu.store32(0x4000, 5).unwrap();
        state.heap_cursor = 0x4010;

        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "InterlockedIncrement",
            &[0x4000],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 6);
        assert_eq!(mmu.load32(0x4000).unwrap(), 6);

        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "InterlockedDecrement",
            &[0x4000],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 5);
    }

    #[test]
    fn load_library_a_returns_known_module_or_null() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        state.modules.insert("kernel32.dll".into(), 0x10000);
        // Lay out "kernel32.dll\0"
        let s = b"kernel32.dll\0";
        mmu.write(0x4000, s).unwrap();
        state.heap_cursor = 0x4020;

        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "LoadLibraryA",
            &[0x4000],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x10000);

        // Unknown module → 0
        let s = b"unknown.dll\0";
        mmu.write(0x4040, s).unwrap();
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "LoadLibraryA",
            &[0x4040],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0);
    }

    #[test]
    fn heap_realloc_preserves_old_bytes() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "HeapAlloc",
            &[0xDEAD_BEEF, 0, 8],
        )
        .unwrap();
        let addr = cpu.regs.get32(Reg32::Eax);
        for i in 0..8u32 {
            mmu.store8(addr + i, (i + 1) as u8).unwrap();
            // Mirror in heap-state buffer too.
            state.heap.get_mut(&addr).unwrap()[i as usize] = (i + 1) as u8;
        }
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "HeapReAlloc",
            &[0xDEAD_BEEF, 0, addr, 16],
        )
        .unwrap();
        let new_addr = cpu.regs.get32(Reg32::Eax);
        for i in 0..8u32 {
            assert_eq!(mmu.load8(new_addr + i).unwrap(), (i + 1) as u8);
        }
    }

    /// Round 12 — `FindResourceA` should walk a synthetic
    /// 3-level resource directory and return the data-entry VA.
    #[test]
    fn find_resource_a_walks_synthetic_resource_directory() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // Build a tiny resource directory at 0x10000:
        //   level 1 (type=2 → level 2)
        //   level 2 (id=112 → level 3)
        //   level 3 (lang=1033 → data entry @ 0x10080)
        // …all relative to 0x10000.
        // Map a region for it.
        mmu.map(0x10000, 0x1000, Perm::R | Perm::W);
        let rsrc_base = 0x10000u32;

        // Level-1 dir at 0x10000 (16-byte hdr + 1 entry @ 0x10010).
        mmu.store32(rsrc_base, 0).unwrap(); // characteristics
        mmu.store32(rsrc_base + 4, 0).unwrap(); // timestamp
        mmu.store32(rsrc_base + 8, 0).unwrap(); // versions (2x u16)
        mmu.store16(rsrc_base + 12, 0).unwrap(); // num named
        mmu.store16(rsrc_base + 14, 1).unwrap(); // num id
        mmu.store32(rsrc_base + 16, 2).unwrap(); // entry: id = 2
        mmu.store32(rsrc_base + 20, 0x8000_0020).unwrap(); // offset = 0x20, is_dir=1

        // Level-2 dir at 0x10020 (= rsrc_base + 0x20). Same shape.
        mmu.store16(rsrc_base + 0x20 + 12, 0).unwrap();
        mmu.store16(rsrc_base + 0x20 + 14, 1).unwrap();
        mmu.store32(rsrc_base + 0x20 + 16, 112).unwrap(); // id = 112
        mmu.store32(rsrc_base + 0x20 + 20, 0x8000_0040).unwrap(); // → 0x40, is_dir=1

        // Level-3 dir at 0x10040.
        mmu.store16(rsrc_base + 0x40 + 12, 0).unwrap();
        mmu.store16(rsrc_base + 0x40 + 14, 1).unwrap();
        mmu.store32(rsrc_base + 0x40 + 16, 1033).unwrap(); // lang
        mmu.store32(rsrc_base + 0x40 + 20, 0x60).unwrap(); // → 0x60, is_data

        // Data entry at 0x10060: rva, size, codepage, reserved.
        mmu.store32(rsrc_base + 0x60, 0xC000).unwrap();
        mmu.store32(rsrc_base + 0x60 + 4, 0x1234).unwrap();

        // Register a fake module @ 0x10000000 with rsrc at our test base.
        let h_module = 0x10000000u32;
        state.modules.insert("synth.dll".into(), h_module);
        state.module_resource_dirs.insert(h_module, rsrc_base);

        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "FindResourceA",
            &[h_module, 112, 2],
        )
        .unwrap();
        // Should land on the data-entry VA.
        assert_eq!(cpu.regs.get32(Reg32::Eax), rsrc_base + 0x60);
    }

    /// `VirtualProtect` must actually update the MMU page
    /// permissions. The previous version only returned success
    /// + a canned old-protection value, which caused
    /// `wmvdecod.dll` / `wmvsdecd.dll` / CamStudio's DllMain to
    /// fault on a self-patch into `.text` — they call
    /// `VirtualProtect(.text, _, PAGE_READWRITE)`, write a
    /// thunk, then flip back.
    #[test]
    fn virtual_protect_flips_text_page_to_writable_and_back() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // Mark a fake "code" page as R+X (mirrors how the PE
        // loader stamps a real .text section).
        let code = 0x20000u32;
        mmu.map(code, 0x1000, Perm::R | Perm::X);
        assert_eq!(mmu.perm_at(code), Some(Perm::R | Perm::X));

        // Out-param for old-protection.
        mmu.map(0x30000, 0x1000, Perm::R | Perm::W);
        let old_out = 0x30000u32;

        // Flip code → PAGE_READWRITE (0x04).
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "VirtualProtect",
            &[code, 0x100, 0x04, old_out],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 1, "should return TRUE");
        assert_eq!(mmu.perm_at(code), Some(Perm::R | Perm::W));
        // Old protection should encode the prior R+X state =
        // PAGE_EXECUTE_READ (0x20).
        assert_eq!(mmu.load32(old_out).unwrap(), 0x20);

        // Now the codec writes through the page — must not trap.
        mmu.store32(code, 0xDEAD_BEEF).expect("writable after flip");

        // Flip back to PAGE_EXECUTE_READ (0x20).
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "VirtualProtect",
            &[code, 0x100, 0x20, old_out],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 1);
        assert_eq!(mmu.perm_at(code), Some(Perm::R | Perm::X));
        // Old protection now reports PAGE_READWRITE (0x04).
        assert_eq!(mmu.load32(old_out).unwrap(), 0x04);

        // Bytes survive the flip-write-flip round-trip.
        assert_eq!(mmu.load32(code).unwrap(), 0xDEAD_BEEF);
    }

    /// `VirtualProtect` on an unmapped address must fail
    /// (`MSDN`: returns FALSE if any page in the range isn't
    /// committed).
    #[test]
    fn virtual_protect_rejects_unmapped_address() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // Out-param scratch.
        mmu.map(0x30000, 0x1000, Perm::R | Perm::W);
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "VirtualProtect",
            &[0x5000_0000, 0x100, 0x04, 0x30000],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0, "should return FALSE");
    }

    /// Phase 2 of the scheduler refactor: `TlsAlloc` returns
    /// distinct process-scoped slot indices, and `TlsSetValue` /
    /// `TlsGetValue` round-trip a value through the current
    /// thread's `tls_slots` map.
    #[test]
    fn tls_alloc_set_get_value_round_trip() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // First TlsAlloc mints slot 0.
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsAlloc",
            &[],
        )
        .unwrap();
        let slot = cpu.regs.get32(Reg32::Eax);
        // Second TlsAlloc mints slot 1 — the cursor is sticky.
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsAlloc",
            &[],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), slot + 1);

        // Fresh slot reads back zero.
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsGetValue",
            &[slot],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0);

        // Set + get the value back.
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsSetValue",
            &[slot, 0xDEAD_F00D],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 1);
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsGetValue",
            &[slot],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xDEAD_F00D);
    }

    /// Phase 3a of the scheduler refactor: `Sleep(ms)` parks
    /// the active thread on a sleep wait, the run loop advances
    /// the global instruction clock past the wake target, and
    /// the thread comes back to Ready. With a single thread we
    /// observe this through state inspection rather than via a
    /// real context switch.
    #[test]
    fn sleep_records_a_wait_on_the_current_thread() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let before = state.scheduler.instructions_global;
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "Sleep",
            &[100],
        )
        .unwrap();
        // Sleep returns the placeholder 0; the real semantics
        // are observable via the yield request the stub left
        // for the run loop.
        let yr = state.yield_requested.clone().expect("yield was requested");
        match yr {
            crate::sched::YieldRequest::Wait(crate::sched::WaitCondition::Sleep {
                resume_after_instructions,
            }) => {
                assert_eq!(
                    resume_after_instructions,
                    before.saturating_add(100 * crate::sched::INSTRUCTIONS_PER_MS),
                );
            }
            other => panic!("expected Sleep wait, got {other:?}"),
        }
        // Tick mirrors the requested duration so GetTickCount
        // sees an advance.
        assert_eq!(state.tick, 100);
    }

    /// TLS slots are isolated per thread: a value set on the
    /// active thread is invisible after the scheduler switches
    /// `active_tid` to a different thread (single-process model).
    #[test]
    fn tls_value_is_isolated_per_thread() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // Mint a slot + set a value on the bootstrap thread.
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsAlloc",
            &[],
        )
        .unwrap();
        let slot = cpu.regs.get32(Reg32::Eax);
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsSetValue",
            &[slot, 0x1234],
        )
        .unwrap();

        // Inject a second thread + switch the scheduler to it.
        // (Phase 3 will add CreateThread for guests; here we
        // just exercise the state directly to verify the
        // isolation property.)
        state
            .threads
            .insert(2, crate::win32::ThreadState::new(2, 1));
        state.active_tid = 2;

        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsGetValue",
            &[slot],
        )
        .unwrap();
        assert_eq!(
            cpu.regs.get32(Reg32::Eax),
            0,
            "the second thread must see a fresh (zero) slot"
        );

        // Switch back: bootstrap thread still has its value.
        state.active_tid = 1;
        push_args_and_call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "kernel32.dll",
            "TlsGetValue",
            &[slot],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x1234);
    }
}
