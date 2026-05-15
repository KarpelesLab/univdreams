//! FFI-style front end for calling into an emulated guest.
//!
//! [`Sandbox`] is the low-level engine — it owns the MMU, the
//! CPU, the Win32 stub registry. Driving a guest export through
//! it means juggling an [`Image`], packing every argument into
//! a `&[u32]`, and reading `eax` back as a bare `u32`.
//!
//! [`Guest`] is the ergonomic layer on top. It reads the way a
//! Rust consumer expects a foreign library to: `load` a module
//! like `dlopen`, then `call` its exports like `extern`
//! functions — typed argument tuples in, a typed return out:
//!
//! ```no_run
//! # fn run() -> Result<(), ud_emulator::Error> {
//! use ud_emulator::Guest;
//!
//! let bytes = std::fs::read("codec.dll").unwrap();
//! let mut guest = Guest::load("codec.dll", &bytes)?;
//!
//! // Call an export — reads like an FFI call.
//! let version: u32 = guest.call("GetCodecVersion", ())?;
//!
//! // Marshal a buffer into guest memory, pass the pointer.
//! let frame = vec![0u8; 4096];
//! let ptr = guest.alloc(&frame)?;
//! let rc: i32 = guest.call("Decode", (ptr, frame.len() as u32))?;
//! # let _ = (version, rc);
//! # Ok(())
//! # }
//! ```
//!
//! The call convention is **stdcall** (the Win32 default — args
//! pushed right-to-left, callee cleans the stack). cdecl
//! exports work too: the run-loop unwinds to a synthetic
//! return sentinel, so who-cleans-the-stack doesn't change the
//! observed return value.
//!
//! Pointers and buffers are explicit, exactly as they are in
//! real FFI: [`Guest::alloc`] / [`Guest::alloc_cstr`] marshal a
//! Rust value into guest memory and hand back the guest
//! pointer; [`Guest::read`] / [`Guest::write`] move bytes
//! across the boundary afterward. There is no hidden
//! copy-back — an out-parameter is "alloc, pass the pointer,
//! `read` it afterward".

use crate::pe::Image;
use crate::runtime::{Sandbox, DLL_PROCESS_ATTACH};
use crate::Error;

/// A loaded guest module — the FFI-style handle a Rust
/// consumer holds. Owns the [`Sandbox`] it runs in plus the
/// loaded [`Image`].
pub struct Guest {
    sandbox: Sandbox,
    image: Image,
}

impl Guest {
    /// Load a PE32 module into a fresh sandbox and run its
    /// `DllMain(DLL_PROCESS_ATTACH)` — the "open the library"
    /// step. The returned handle is ready for [`Guest::call`].
    pub fn load(name: &str, bytes: &[u8]) -> Result<Self, Error> {
        Self::load_into(Sandbox::new(), name, bytes)
    }

    /// Like [`Guest::load`] but into a caller-provided
    /// [`Sandbox`] — lets the caller pre-attach a virtual
    /// filesystem / registry, set an instruction budget, seed
    /// the RNG, etc. before the module's `DllMain` runs.
    pub fn load_into(mut sandbox: Sandbox, name: &str, bytes: &[u8]) -> Result<Self, Error> {
        let image = sandbox.load(name, bytes)?;
        sandbox.call_dll_main(&image, DLL_PROCESS_ATTACH)?;
        Ok(Self { sandbox, image })
    }

    /// Load a PE32 module **without** running `DllMain`. Use
    /// when the caller wants to inspect or instrument the
    /// module before any guest code runs.
    pub fn load_raw(name: &str, bytes: &[u8]) -> Result<Self, Error> {
        Self::load_raw_into(Sandbox::new(), name, bytes)
    }

    /// [`Guest::load_raw`] into a caller-provided sandbox.
    pub fn load_raw_into(mut sandbox: Sandbox, name: &str, bytes: &[u8]) -> Result<Self, Error> {
        let image = sandbox.load(name, bytes)?;
        Ok(Self { sandbox, image })
    }

    /// Run `DllMain(DLL_PROCESS_ATTACH)` explicitly — only
    /// needed after [`Guest::load_raw`].
    pub fn run_dll_main(&mut self) -> Result<u32, Error> {
        self.sandbox.call_dll_main(&self.image, DLL_PROCESS_ATTACH)
    }

    /// Call an exported function by name with a typed argument
    /// tuple, returning the typed result.
    ///
    /// Arguments are any tuple (`()` through 8-arity) of
    /// dword-sized values — `u32`, `i32`, `bool`, or a guest
    /// pointer (`u32`). The return type `R` is inferred from
    /// the binding: `u32`, `i32`, `bool`, or `()`.
    ///
    /// ```no_run
    /// # fn run(guest: &mut ud_emulator::Guest) -> Result<(), ud_emulator::Error> {
    /// let rc: i32 = guest.call("DriverProc", (1u32, 0u32, 1u32, 0u32, 0u32))?;
    /// # let _ = rc;
    /// # Ok(())
    /// # }
    /// ```
    pub fn call<A, R>(&mut self, export: &str, args: A) -> Result<R, Error>
    where
        A: CallArgs,
        R: FromRet,
    {
        let dwords = args.into_dwords();
        let eax = self.sandbox.call_export(&self.image, export, &dwords)?;
        Ok(R::from_eax(eax))
    }

    /// True iff the module exports `name`.
    #[must_use]
    pub fn has_export(&self, name: &str) -> bool {
        self.image.export(name).is_some()
    }

    /// Resolve an export's guest virtual address, if present.
    #[must_use]
    pub fn export_addr(&self, name: &str) -> Option<u32> {
        self.image.export(name)
    }

    /// Allocate `bytes.len()` bytes of guest memory, copy
    /// `bytes` in, and return the guest pointer. The
    /// allocation lives in the sandbox heap arena for the rest
    /// of the `Guest`'s lifetime — there is no `free`; the
    /// arena is bump-allocated and reclaimed wholesale when the
    /// `Guest` drops.
    pub fn alloc(&mut self, bytes: &[u8]) -> Result<u32, Error> {
        let len = u32::try_from(bytes.len()).map_err(|_| {
            Error::Win32(crate::win32::Win32Error::InvalidArgument {
                stub: "Guest::alloc",
                reason: "allocation larger than 4 GiB".into(),
            })
        })?;
        let ptr = self
            .sandbox
            .host
            .arena_alloc(len.max(1))
            .map_err(Error::Win32)?;
        self.sandbox.mmu.write(ptr, bytes).map_err(Error::Trap)?;
        Ok(ptr)
    }

    /// Allocate and copy a NUL-terminated ASCII string into
    /// guest memory; return the guest pointer. The trailing
    /// `\0` is appended automatically.
    pub fn alloc_cstr(&mut self, s: &str) -> Result<u32, Error> {
        let mut buf = s.as_bytes().to_vec();
        buf.push(0);
        self.alloc(&buf)
    }

    /// Read `len` bytes of guest memory at `ptr`.
    pub fn read(&self, ptr: u32, len: usize) -> Result<Vec<u8>, Error> {
        self.sandbox.mmu.read(ptr, len).map_err(Error::Trap)
    }

    /// Write `data` into guest memory at `ptr`.
    pub fn write(&mut self, ptr: u32, data: &[u8]) -> Result<(), Error> {
        self.sandbox.mmu.write(ptr, data).map_err(Error::Trap)
    }

    /// Borrow the underlying [`Sandbox`] for lower-level
    /// access — the coverage map, the emulation context (VFS /
    /// registry), the VfW `IC*` helpers, the trace surface.
    #[must_use]
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    /// Mutable [`Sandbox`] accessor.
    pub fn sandbox_mut(&mut self) -> &mut Sandbox {
        &mut self.sandbox
    }

    /// The loaded module's parsed [`Image`].
    #[must_use]
    pub fn image(&self) -> &Image {
        &self.image
    }
}

// ============================================================
// Argument / return marshalling traits
// ============================================================

/// A value that lowers to one 32-bit stdcall argument slot.
pub trait Dword {
    /// Convert `self` to the raw dword pushed on the guest
    /// stack.
    fn to_dword(self) -> u32;
}

impl Dword for u32 {
    fn to_dword(self) -> u32 {
        self
    }
}
impl Dword for i32 {
    fn to_dword(self) -> u32 {
        self as u32
    }
}
impl Dword for u16 {
    fn to_dword(self) -> u32 {
        u32::from(self)
    }
}
impl Dword for u8 {
    fn to_dword(self) -> u32 {
        u32::from(self)
    }
}
impl Dword for bool {
    fn to_dword(self) -> u32 {
        u32::from(self)
    }
}

/// A tuple of [`Dword`] values that lowers to the stdcall
/// argument vector. Implemented for `()` through 8-arity.
pub trait CallArgs {
    /// Lower the tuple to the dword vector, in declaration
    /// order (the caller's `(a, b, c)` becomes `[a, b, c]`;
    /// the stdcall right-to-left push order is the run-loop's
    /// concern, not the caller's).
    fn into_dwords(self) -> Vec<u32>;
}

impl CallArgs for () {
    fn into_dwords(self) -> Vec<u32> {
        Vec::new()
    }
}

macro_rules! impl_call_args {
    ( $( $name:ident ),+ ) => {
        impl< $( $name: Dword ),+ > CallArgs for ( $( $name, )+ ) {
            #[allow(non_snake_case)]
            fn into_dwords(self) -> Vec<u32> {
                let ( $( $name, )+ ) = self;
                vec![ $( $name.to_dword() ),+ ]
            }
        }
    };
}

impl_call_args!(A);
impl_call_args!(A, B);
impl_call_args!(A, B, C);
impl_call_args!(A, B, C, D);
impl_call_args!(A, B, C, D, E);
impl_call_args!(A, B, C, D, E, F);
impl_call_args!(A, B, C, D, E, F, G);
impl_call_args!(A, B, C, D, E, F, G, H);

/// A type the call result (`eax`) can be reinterpreted as.
pub trait FromRet {
    /// Reinterpret the guest's `eax` return value.
    fn from_eax(eax: u32) -> Self;
}

impl FromRet for u32 {
    fn from_eax(eax: u32) -> Self {
        eax
    }
}
impl FromRet for i32 {
    fn from_eax(eax: u32) -> Self {
        eax as i32
    }
}
impl FromRet for bool {
    fn from_eax(eax: u32) -> Self {
        eax != 0
    }
}
impl FromRet for () {
    fn from_eax(_eax: u32) -> Self {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_args_lower_in_declaration_order() {
        assert_eq!(().into_dwords(), Vec::<u32>::new());
        assert_eq!((1u32,).into_dwords(), vec![1]);
        assert_eq!((1u32, 2u32, 3u32).into_dwords(), vec![1, 2, 3]);
    }

    #[test]
    fn dword_conversions() {
        assert_eq!((-1i32,).into_dwords(), vec![0xFFFF_FFFF]);
        assert_eq!((true, false).into_dwords(), vec![1, 0]);
        assert_eq!((0x1234u16, 0xABu8).into_dwords(), vec![0x1234, 0xAB]);
    }

    #[test]
    fn from_ret_reinterprets() {
        assert_eq!(u32::from_eax(0xFFFF_FFFF), 0xFFFF_FFFF);
        assert_eq!(i32::from_eax(0xFFFF_FFFF), -1);
        assert!(bool::from_eax(1));
        assert!(!bool::from_eax(0));
    }
}
