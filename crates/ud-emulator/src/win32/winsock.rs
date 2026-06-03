//! `wsock32.dll` / `ws2_32.dll` stubs.
//!
//! Most Apple QT code paths reach Winsock through delay-loaded
//! initialisers that QT only really cares about as
//! "DLL load succeeded, init returned 0". Real socket I/O is
//! never reached in the codec / Component-Manager paths we
//! drive. Returning success without doing anything keeps the
//! init chain unblocked.
//!
//! Both DLLs share a flat 1-based ordinal export table on real
//! Windows. We register the most commonly imported names AND
//! the matching `@<ord>` keys so unnamed (ordinal-only) imports
//! also resolve cleanly. Reference: Microsoft "Winsock 2 API
//! Reference" — `https://learn.microsoft.com/en-us/windows/win32/api/winsock2/`.

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register both `wsock32.dll` and `ws2_32.dll` stubs.
pub fn register(registry: &mut Registry) {
    // (name, ordinal, arg_dwords, stub_fn) — register each
    // entry under both the symbolic name and its ordinal
    // (`@<n>`) so PE imports of either form resolve.
    let entries: &[(&str, u32, u32, StubFn)] = &[
        // Connection / handle lifecycle.
        ("accept", 1, 3, stub_zero as StubFn),
        ("bind", 2, 3, stub_zero as StubFn),
        ("closesocket", 3, 1, stub_zero as StubFn),
        ("connect", 4, 3, stub_minus_one as StubFn),
        ("getpeername", 5, 3, stub_minus_one as StubFn),
        ("getsockname", 6, 3, stub_minus_one as StubFn),
        ("getsockopt", 7, 5, stub_minus_one as StubFn),
        ("htonl", 8, 1, stub_passthrough_dword as StubFn),
        ("htons", 9, 1, stub_passthrough_word as StubFn),
        ("inet_addr", 10, 1, stub_minus_one as StubFn),
        ("inet_ntoa", 11, 1, stub_zero as StubFn),
        ("ioctlsocket", 12, 3, stub_minus_one as StubFn),
        ("listen", 13, 2, stub_minus_one as StubFn),
        ("ntohl", 14, 1, stub_passthrough_dword as StubFn),
        ("ntohs", 15, 1, stub_passthrough_word as StubFn),
        ("recv", 16, 4, stub_zero as StubFn),
        ("recvfrom", 17, 6, stub_zero as StubFn),
        ("select", 18, 5, stub_zero as StubFn),
        ("send", 19, 4, stub_zero as StubFn),
        ("sendto", 20, 6, stub_zero as StubFn),
        ("setsockopt", 21, 5, stub_zero as StubFn),
        ("shutdown", 22, 2, stub_zero as StubFn),
        ("socket", 23, 3, stub_minus_one as StubFn),
        ("gethostbyaddr", 51, 3, stub_zero as StubFn),
        ("gethostbyname", 52, 1, stub_zero as StubFn),
        ("gethostname", 57, 2, stub_zero as StubFn),
        ("getservbyport", 55, 2, stub_zero as StubFn),
        ("getservbyname", 56, 2, stub_zero as StubFn),
        ("getprotobynumber", 53, 1, stub_zero as StubFn),
        ("getprotobyname", 54, 1, stub_zero as StubFn),
        // Async / blocking-call extensions (Winsock 1 specifics).
        ("WSAAsyncSelect", 101, 4, stub_zero as StubFn),
        ("WSACancelBlockingCall", 111, 0, stub_zero as StubFn),
        ("WSACleanup", 112, 0, stub_zero as StubFn),
        ("WSAGetLastError", 111, 0, stub_zero as StubFn),
        ("WSASetBlockingHook", 109, 1, stub_zero as StubFn),
        ("WSAStartup", 115, 2, stub_zero as StubFn),
        ("WSASetLastError", 116, 1, stub_zero as StubFn),
        ("__WSAFDIsSet", 151, 2, stub_zero as StubFn),
    ];
    for dll in &["wsock32.dll", "ws2_32.dll"] {
        for (name, ord, arg_dwords, func) in entries {
            registry.register(dll, name, *func, *arg_dwords);
            let ord_name = format!("@{ord}");
            registry.register(dll, &ord_name, *func, *arg_dwords);
        }
    }
}

/// Return 0.
fn stub_zero(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// Return -1 (`SOCKET_ERROR` / `INVALID_SOCKET`).
fn stub_minus_one(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0xFFFF_FFFF)
}

/// `u_long htonl(u_long hostlong)` / `u_long ntohl(...)`. Pass
/// through unchanged — our emulator is little-endian and the
/// guest doesn't read the byte order; what matters is that
/// `ntohl(htonl(x)) == x`, which `passthrough(passthrough(x))`
/// trivially satisfies.
fn stub_passthrough_dword(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let v = arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("htonl", t))?;
    Ok(v)
}

/// `u_short htons(u_short hostshort)` / `u_short ntohs(...)`.
/// Same pass-through reasoning as `htonl`.
fn stub_passthrough_word(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let v = arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("htons", t))?;
    Ok(v & 0xFFFF)
}
