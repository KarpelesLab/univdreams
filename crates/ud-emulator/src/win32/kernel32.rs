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
/// Round-1 returns a registered thunk for the (module, name)
/// pair if one exists; otherwise NULL. Lookup-by-ordinal is not
/// supported in round 1 (low-bit-set address) — a target codec
/// that needs it will surface as a clean trap.
fn stub_get_proc_address(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("GetProcAddress", t))?;
    let name_p = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("GetProcAddress", t))?;
    if name_p < 0x10000 {
        // Pointer is an ordinal (HIWORD == 0) — unsupported.
        return Ok(0);
    }
    // We don't know which DLL was identified, so always return
    // NULL for round-1; callers fall back to import-table
    // resolution.
    Ok(0)
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
        _ => Perm::R | Perm::W,
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
/// LPOVERLAPPED lpOverlapped)`. Stub failure: returns FALSE,
/// sets last error to ERROR_INVALID_HANDLE.
const ERROR_INVALID_HANDLE: u32 = 6;
fn stub_write_file(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("WriteFile", t))?;
    let _lp_buf = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("WriteFile", t))?;
    let _n = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("WriteFile", t))?;
    let lp_written = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("WriteFile", t))?;
    let _lp_ovl = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("WriteFile", t))?;
    if lp_written != 0 {
        // Best-effort write zero into bytes-written so the
        // caller's error path doesn't UB-read garbage.
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

/// `BOOL CloseHandle(HANDLE)`. Always succeeds.
fn stub_close_handle(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
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

/// `DWORD GetCurrentThreadId(void)`. Synthetic 1 (single thread).
fn stub_get_current_thread_id(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
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

/// `void Sleep(DWORD)`. We're synchronous — drop the call.
fn stub_sleep(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
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

/// `DWORD TlsAlloc(void)`. Return a synthetic TLS index. TLS in
/// our single-threaded sandbox is just a key/value map keyed by
/// index; we use small integers and store via the host state's
/// debug-log channel for visibility.
fn stub_tls_alloc(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    // tick doubles as a monotonic counter for TLS index minting.
    state.tick = state.tick.wrapping_add(1);
    Ok(state.tick)
}

/// `BOOL TlsFree(DWORD)`. No-op success.
fn stub_tls_free(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `LPVOID TlsGetValue(DWORD)`. Always returns NULL — codecs use
/// this for per-thread caches we don't model.
fn stub_tls_get_value(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL TlsSetValue(DWORD, LPVOID)`. No-op success.
fn stub_tls_set_value(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
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
/// Single-threaded sandbox semantics: invoke the start routine
/// synchronously (stdcall, one parameter) using
/// [`crate::win32::call_guest`], then return a non-zero
/// pseudo-HANDLE. If the caller passed `lpThreadId`, write a
/// pseudo-thread-id (the same numeric value as the handle).
///
/// `dwCreationFlags & CREATE_SUSPENDED (0x4)` is honoured by
/// returning *without* running the start address; a paired
/// `ResumeThread` does nothing in our model. This mirrors the
/// MSDN contract closely enough for codec init, which only
/// uses the suspend bit to set thread priority before letting
/// the thread run.
fn stub_create_thread(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
) -> Result<u32, Win32Error> {
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    let _attrs = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32("CreateThread", t))?;
    let _stack = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32("CreateThread", t))?;
    let start = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32("CreateThread", t))?;
    let param = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32("CreateThread", t))?;
    let flags = arg_dword(cpu, mmu, 4).map_err(|t| trap_to_win32("CreateThread", t))?;
    let p_tid = arg_dword(cpu, mmu, 5).map_err(|t| trap_to_win32("CreateThread", t))?;

    state.tick = state.tick.wrapping_add(1);
    let handle = 0xCAFE_C000u32.wrapping_add(state.tick);
    if p_tid != 0 {
        mmu.store32(p_tid, handle)
            .map_err(|t| trap_to_win32("CreateThread", t))?;
    }
    if start != 0 && (flags & CREATE_SUSPENDED) == 0 {
        // stdcall: one DWORD argument. The thread proc returns
        // its exit code in eax; we discard it.
        let _ = crate::win32::call_guest(cpu, mmu, registry, state, start, &[param]);
    }
    Ok(handle)
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

/// `DWORD ResumeThread(HANDLE)`. Single-threaded sandbox: thread
/// is already "running" (we ran it synchronously inside
/// `CreateThread`), so resume returns the previous suspend count
/// 0. Real `ResumeThread` returns `(DWORD)-1` on failure but
/// codecs don't check.
fn stub_resume_thread(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
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
}
