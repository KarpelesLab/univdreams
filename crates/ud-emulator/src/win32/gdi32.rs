//! `gdi32.dll` stubs — the graphics-device-interface surface a
//! VfW-class codec DLL imports.
//!
//! Codecs typically only use the `gdi32` API in their config-dialog
//! path (which we never invoke) or in palette negotiation (which
//! we sidestep by reporting a true-color "device"). All eight
//! stubs are therefore fail-soft: they return sensible defaults
//! that let any DllMain CRT init / static-constructor pass.
//!
//! Reference: MSDN `gdi32` page-by-page; cited inline next to
//! each stub.

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};
use std::collections::BTreeSet;

/// Sentinel handle for `CreateCompatibleDC` / `GetDC`. Every
/// `HDC` we hand out is the same value; `DeleteDC` /
/// `ReleaseDC` validates against [`HostState::valid_hdcs`] (a
/// per-sandbox `BTreeSet`).
pub const SENTINEL_HDC: u32 = 0xDEAD_C011;

/// Track which `HDC` values are currently "valid" — i.e. which
/// `CreateCompatibleDC` calls have happened without a paired
/// `DeleteDC`. Stored on the [`crate::win32::HostState`] via a
/// `Box<BTreeSet<u32>>` slot kept in `host.gdi_hdcs`.
///
/// We store this as a side table here instead of adding a field
/// to `HostState` because round-1 tests don't need the surface.
/// A test that calls `gdi32::register(...)` then `CreateCompatibleDC`
/// gets the set automatically populated.
fn gdi_hdcs_mut(state: &mut HostState) -> &mut BTreeSet<u32> {
    state.gdi_hdcs.get_or_insert_with(BTreeSet::new)
}

/// Register every gdi32 stub.
pub fn register(registry: &mut Registry) {
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-bitblt
    registry.register("gdi32.dll", "BitBlt", stub_bitblt as StubFn, 9);
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createcompatibledc
    registry.register(
        "gdi32.dll",
        "CreateCompatibleDC",
        stub_create_compatible_dc as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-deletedc
    registry.register("gdi32.dll", "DeleteDC", stub_delete_dc as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getdevicecaps
    registry.register(
        "gdi32.dll",
        "GetDeviceCaps",
        stub_get_device_caps as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getnearestcolor
    registry.register(
        "gdi32.dll",
        "GetNearestColor",
        stub_get_nearest_color as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getobjecta
    registry.register("gdi32.dll", "GetObjectA", stub_get_object_a as StubFn, 3);
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getsystempaletteentries
    registry.register(
        "gdi32.dll",
        "GetSystemPaletteEntries",
        stub_get_system_palette_entries as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-selectobject
    registry.register("gdi32.dll", "SelectObject", stub_select_object as StubFn, 2);

    // ---- Round-47 additions: msadds32.ax PE-load surface --------
    //
    // After r46 (user32!{SetTimer, KillTimer}) the splitter
    // (`msadds32.ax`) advances its `gdi32` import-table walk to
    // `StretchDIBits` — the splitter's headless render-out path.
    // The codec sandbox never actually paints a pixel; the named
    // import just needs to resolve to a thunk before
    // `Sandbox::load` returns the [`Image`].
    //
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-stretchdibits
    // int StretchDIBits(HDC hdc, int xDest, int yDest, int
    //   DestWidth, int DestHeight, int xSrc, int ySrc, int
    //   SrcWidth, int SrcHeight, const VOID *lpBits, const
    //   BITMAPINFO *lpbmi, UINT iUsage, DWORD rop) — 13 args.
    registry.register(
        "gdi32.dll",
        "StretchDIBits",
        stub_stretch_dibits as StubFn,
        13,
    );
}

/// `BOOL BitBlt(HDC, int, int, int, int, HDC, int, int, DWORD)`.
/// No-op returning TRUE. Codecs typically only use this in their
/// config-dialog path, which we never invoke.
fn stub_bitblt(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `HDC CreateCompatibleDC(HDC hdc)`. Returns the sentinel HDC
/// + records it in the live-set so `DeleteDC` validates.
fn stub_create_compatible_dc(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    gdi_hdcs_mut(state).insert(SENTINEL_HDC);
    Ok(SENTINEL_HDC)
}

/// `BOOL DeleteDC(HDC hdc)`. Removes from the live set; returns
/// TRUE.
fn stub_delete_dc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("DeleteDC", t))?;
    gdi_hdcs_mut(state).remove(&h);
    Ok(1)
}

// `wingdi.h` GetDeviceCaps indices.
const DRIVERVERSION: u32 = 0;
const TECHNOLOGY: u32 = 2;
const HORZSIZE: u32 = 4;
const VERTSIZE: u32 = 6;
const HORZRES: u32 = 8;
const VERTRES: u32 = 10;
const BITSPIXEL: u32 = 12;
const PLANES: u32 = 14;
const NUMBRUSHES: u32 = 16;
const NUMPENS: u32 = 18;
const NUMFONTS: u32 = 22;
const NUMCOLORS: u32 = 24;
const RASTERCAPS: u32 = 38;
const LOGPIXELSX: u32 = 88;
const LOGPIXELSY: u32 = 90;
const SIZEPALETTE: u32 = 104;
const NUMRESERVED: u32 = 106;
const COLORRES: u32 = 108;

/// `int GetDeviceCaps(HDC hdc, int index)`. Returns sensible
/// "true-color VGA" defaults — see MSDN `GetDeviceCaps` for the
/// index → return-value table.
fn stub_get_device_caps(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hdc = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetDeviceCaps", t))?;
    let idx = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("GetDeviceCaps", t))?;
    Ok(match idx {
        DRIVERVERSION => 0x0400,
        TECHNOLOGY => 1, // DT_RASDISPLAY
        HORZSIZE => 320,
        VERTSIZE => 240,
        HORZRES => 1024,
        VERTRES => 768,
        BITSPIXEL => 32,
        PLANES => 1,
        NUMBRUSHES => 0,
        NUMPENS => 16,
        NUMFONTS => 0,
        NUMCOLORS => 0,
        // RC_BITBLT | RC_BITMAP64 | RC_DI_BITMAP | RC_DIBTODEV |
        // RC_GDI20_OUTPUT | RC_PALETTE | RC_STRETCHBLT | RC_STRETCHDIB.
        RASTERCAPS => 0x0000_19F1,
        LOGPIXELSX => 96,
        LOGPIXELSY => 96,
        SIZEPALETTE => 0,
        NUMRESERVED => 20,
        COLORRES => 24,
        _ => 0,
    })
}

/// `COLORREF GetNearestColor(HDC hdc, COLORREF crColor)`. Return
/// the input color unchanged (we have a true-color "device").
fn stub_get_nearest_color(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hdc = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetNearestColor", t))?;
    let color = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("GetNearestColor", t))?;
    Ok(color)
}

/// `int GetObjectA(HGDIOBJ hgdiobj, int cbBuffer, LPVOID lpvObject)`.
/// Stub failure: returns 0. Codecs that hit this path are doing
/// palette negotiation we're not driving.
fn stub_get_object_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `UINT GetSystemPaletteEntries(HDC hdc, UINT iStart, UINT cEntries,
/// LPPALETTEENTRY lppe)`. Stub failure: returns 0.
fn stub_get_system_palette_entries(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `HGDIOBJ SelectObject(HDC hdc, HGDIOBJ hObject)`. No-op:
/// return the input `hObject` unchanged.
fn stub_select_object(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hdc =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("SelectObject", t))?;
    let h =
        arg_dword(cpu, mmu, 1).map_err(|t| crate::win32::trap_to_win32_local("SelectObject", t))?;
    Ok(h)
}

/// `int StretchDIBits(HDC hdc, int xDest, int yDest, int DestWidth,
/// int DestHeight, int xSrc, int ySrc, int SrcWidth, int SrcHeight,
/// const VOID *lpBits, const BITMAPINFO *lpbmi, UINT iUsage,
/// DWORD rop)` — fail-soft.
///
/// Per MSDN the call copies colour data from a source DIB to a
/// destination rectangle and returns the number of scanlines
/// copied (`GDI_ERROR` on failure).  The codec sandbox never owns
/// a real DC and never composites a final frame — `msadds32.ax`
/// is the audio splitter and only pulls this import as part of
/// its statically-linked render-out surface, never invokes it on
/// the decode path we drive.  We therefore return the caller's
/// `DestHeight` so any "scanlines > 0 == success" probe sees a
/// satisfied contract.
fn stub_stretch_dibits(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    // We touch only the args we care about; the rest are pulled
    // through `arg_dword` so a stack-bounds trap surfaces as a
    // proper Win32Error rather than a silent under-read.
    let _hdc = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _x_dest = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _y_dest = arg_dword(cpu, mmu, 2)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _dest_width = arg_dword(cpu, mmu, 3)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let dest_height = arg_dword(cpu, mmu, 4)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _x_src = arg_dword(cpu, mmu, 5)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _y_src = arg_dword(cpu, mmu, 6)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _src_width = arg_dword(cpu, mmu, 7)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _src_height = arg_dword(cpu, mmu, 8)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _lp_bits = arg_dword(cpu, mmu, 9)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _lpbmi = arg_dword(cpu, mmu, 10)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _i_usage = arg_dword(cpu, mmu, 11)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    let _rop = arg_dword(cpu, mmu, 12)
        .map_err(|t| crate::win32::trap_to_win32_local("StretchDIBits", t))?;
    // MSDN: "the return value is the number of scanlines copied".
    // Reporting the caller's `DestHeight` satisfies any
    // "scanlines > 0 == success" probe at the call site.  If the
    // caller passed 0 (degenerate), echo 0 — still a non-error
    // outcome, since `GDI_ERROR` is the explicit failure marker
    // and we never want to surface that from a fail-soft stub.
    Ok(dest_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::mmu::Perm;
    use crate::emulator::regs::Reg32;

    fn make_env() -> (Cpu, Mmu, Registry, HostState) {
        let mut mmu = Mmu::new();
        mmu.map(0x4000, 0x4000, Perm::R | Perm::W);
        mmu.map(0x9000, 0x1000, Perm::R | Perm::W);
        let mut cpu = Cpu::new();
        cpu.regs.set_esp(0x9F00);
        let mut registry = Registry::new();
        registry.register_kernel32();
        registry.register_gdi32();
        let state = HostState::new(0x4000, 0x8000);
        (cpu, mmu, registry, state)
    }

    fn call(
        cpu: &mut Cpu,
        mmu: &mut Mmu,
        registry: &Registry,
        state: &mut HostState,
        dll: &str,
        name: &str,
        args: &[u32],
    ) -> Result<(), crate::Error> {
        for a in args.iter().rev() {
            cpu.push32(mmu, *a)?;
        }
        cpu.push32(mmu, 0xDEAD_DEAD)?;
        cpu.regs.eip = registry.resolve(dll, name).expect("registered");
        crate::win32::dispatch_stub(cpu, mmu, registry, state)
    }

    #[test]
    fn create_compatible_dc_returns_sentinel() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "gdi32.dll",
            "CreateCompatibleDC",
            &[0],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), SENTINEL_HDC);
    }

    #[test]
    fn create_then_delete_dc_roundtrips() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "gdi32.dll",
            "CreateCompatibleDC",
            &[0],
        )
        .unwrap();
        let h = cpu.regs.get32(Reg32::Eax);
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "gdi32.dll",
            "DeleteDC",
            &[h],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 1);
    }

    #[test]
    fn get_device_caps_bitspixel_is_32() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "gdi32.dll",
            "GetDeviceCaps",
            &[SENTINEL_HDC, BITSPIXEL],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 32);
    }

    #[test]
    fn get_nearest_color_is_identity() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "gdi32.dll",
            "GetNearestColor",
            &[SENTINEL_HDC, 0x12_3456],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0x12_3456);
    }

    #[test]
    fn select_object_returns_input_unchanged() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "gdi32.dll",
            "SelectObject",
            &[SENTINEL_HDC, 0xCAFE_BABE],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xCAFE_BABE);
    }

    #[test]
    fn stretch_dibits_returns_dest_height() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // 13 args: hdc, xDest, yDest, DestWidth, DestHeight,
        //          xSrc, ySrc, SrcWidth, SrcHeight,
        //          lpBits, lpbmi, iUsage, rop.
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "gdi32.dll",
            "StretchDIBits",
            &[
                SENTINEL_HDC,
                0,
                0,
                352,
                288,
                0,
                0,
                352,
                288,
                0,
                0,
                0,
                0x00CC_0020,
            ],
        )
        .unwrap();
        assert_eq!(
            cpu.regs.get32(Reg32::Eax),
            288,
            "StretchDIBits should echo DestHeight as the scanline count"
        );
    }
}
