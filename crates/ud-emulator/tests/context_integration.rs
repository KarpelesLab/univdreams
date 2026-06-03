//! Sandbox-level integration of the [`ud_emulator::Context`]
//! layer. Round-1 surface: the context types are visible
//! through `Sandbox::with_vfs` / `with_registry` /
//! `context()` accessors and round-trip through them. The
//! Win32-stub wiring (`CreateFileA` / `RegOpenKeyExA`
//! consulting these surfaces) lands in follow-up commits;
//! this test pins the API shape so consumers can build
//! against it today.

use ud_emulator::{FileAccess, RegistryValue, Sandbox, VirtualFs, VirtualRegistry, HKLM};

#[test]
fn default_sandbox_has_empty_context() {
    let sandbox = Sandbox::new();
    assert!(sandbox.context().vfs.is_none());
    assert!(sandbox.context().registry.is_none());
}

#[test]
fn attached_vfs_round_trips_through_sandbox() {
    let mut vfs = VirtualFs::new();
    vfs.insert("C:\\codec\\settings.ini", b"[Settings]\nquality=5".to_vec());
    let sandbox = Sandbox::new().with_vfs(vfs);

    let vfs = sandbox.context().vfs.as_ref().expect("vfs attached");
    assert_eq!(
        vfs.read("c:/codec/SETTINGS.ini"),
        Some(&b"[Settings]\nquality=5"[..])
    );
}

#[test]
fn attached_registry_round_trips_through_sandbox() {
    let mut reg = VirtualRegistry::new();
    reg.set_value(
        "hkey_local_machine/software/codec",
        "Version",
        RegistryValue::Sz("3.11".into()),
    );
    let sandbox = Sandbox::new().with_registry(reg);
    let reg = sandbox
        .context()
        .registry
        .as_ref()
        .expect("registry attached");
    assert_eq!(
        reg.get_value("hkey_local_machine/software/codec", "version"),
        Some(&RegistryValue::Sz("3.11".into()))
    );
}

#[test]
fn context_mut_supports_post_creation_edits() {
    let mut sandbox = Sandbox::new().with_vfs(VirtualFs::new());

    // Codec staging: add a config file at runtime.
    let vfs = sandbox.context_mut().vfs.as_mut().expect("vfs attached");
    vfs.insert("foo.cfg", b"key=value".to_vec());
    // Then open it for read, simulating what `CreateFileA`
    // would do under the hood (next-commit work).
    let h = vfs.open("foo.cfg", FileAccess::Read).expect("opens");
    let mut buf = [0u8; 9];
    assert_eq!(vfs.read_handle(h, &mut buf), Some(9));
    assert_eq!(&buf, b"key=value");
    assert!(vfs.close(h));
}

#[test]
fn registry_can_open_preset_keys_via_hklm() {
    let mut reg = VirtualRegistry::new();
    reg.set_value(
        "hkey_local_machine/software/microsoft/windows",
        "CurrentBuild",
        RegistryValue::Sz("7600".into()),
    );
    let mut sandbox = Sandbox::new().with_registry(reg);

    let registry = sandbox
        .context_mut()
        .registry
        .as_mut()
        .expect("registry attached");
    let h = registry
        .open_key(HKLM, "Software\\Microsoft\\Windows")
        .expect("opens");
    assert!(registry.owns(h));
    assert_eq!(registry.path_of(h), Some("hklm/software/microsoft/windows"));
    assert!(registry.close_key(h));
}
