//! Module → arch-codec dispatch helpers.
//!
//! Each top-level compile entry point (`lower_to_elf`,
//! `lower_to_pe`, `lower_to_macho`, `lower_to_raw`) needs to pick
//! the right [`ud_arch_codec::ArchCodec`] for the input. That
//! decision is driven by the `arch: "…"` field in the parsed
//! `@module` block and (when more specificity is needed) the
//! numeric `build.e_machine`. This module centralises the
//! marshaling from a parsed `ud_ast::Module` to the
//! `(arch_name, e_machine)` pair `ud_arch_codec::for_arch` takes.

use std::sync::Once;

use ud_arch_codec::{ArchCodec, ArchError};
use ud_ast::{Module, Value};

static REGISTER_ALL: Once = Once::new();

/// Look up the arch codec for `module`. Triggers
/// [`crate::register_all_arches`] on first call (idempotent via
/// `Once`) so consumers that forget the explicit registration
/// step still get every workspace arch wired up before the first
/// compile / decompile call.
pub fn resolve_arch_codec(module: &Module) -> Result<Box<dyn ArchCodec>, ArchError> {
    REGISTER_ALL.call_once(crate::register_all_arches);
    let arch_name = module_arch_name(module);
    let e_machine = module_e_machine(module);
    ud_arch_codec::for_arch(arch_name.as_deref(), e_machine)
}

fn module_arch_name(module: &Module) -> Option<String> {
    module.fields.iter().find_map(|f| {
        if f.name != "arch" {
            return None;
        }
        match &f.value {
            Value::String(s) => Some(s.to_ascii_lowercase()),
            _ => None,
        }
    })
}

fn module_e_machine(module: &Module) -> Option<u64> {
    let build = module.fields.iter().find_map(|f| {
        if f.name != "build" {
            return None;
        }
        match &f.value {
            Value::Block(fields) => Some(fields),
            _ => None,
        }
    })?;
    build.iter().find_map(|f| {
        if f.name != "e_machine" {
            return None;
        }
        match &f.value {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    })
}
