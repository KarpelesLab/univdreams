//! BPF idiom recognition (decompile L6c, focused subset).
//!
//! v1 of L6c ships a Solana-syscall signature annotator:
//! when a `call <syscall_name>` is rendered (via L1's
//! relocation-derived name map), we add a `// <signature>`
//! comment underneath listing the expected argument names
//! and types from the Solana SDK. The values themselves
//! aren't computed (that needs the value-flow pass L6a
//! would provide); the annotation is a reading aid that
//! makes `call sol_log_` immediately legible as
//! `sol_log_(msg: *const u8, len: u64)`.
//!
//! Round-trip neutral: the annotation is a `Stmt::Comment`,
//! zero bytes at lower time.
//!
//! A full L6c with slice-index / option / struct-field idiom
//! recognition needs the SSA + expression-simplification
//! infrastructure that lives in `ssa.rs` and `expr.rs` —
//! currently x86-coupled. Generalising those (L6a) unlocks
//! the next tier of idiom matches.

/// Solana SDK / Anza syscalls and their argument signatures.
/// The list is intentionally small — only the syscalls we've
/// seen on-chain in practice. Adding new entries is purely
/// additive.
#[must_use]
pub fn solana_syscall_signature(name: &str) -> Option<&'static str> {
    match name {
        "sol_log_" => Some("sol_log_(msg: *const u8, len: u64)"),
        "sol_log_64_" => Some("sol_log_64_(a: u64, b: u64, c: u64, d: u64, e: u64)"),
        "sol_log_pubkey" => Some("sol_log_pubkey(pubkey: *const Pubkey)"),
        "sol_log_compute_units_" => Some("sol_log_compute_units_()"),
        "sol_log_data" => Some("sol_log_data(data: *const SliceArray, n: u64)"),
        "sol_memcpy_" => Some("sol_memcpy_(dst: *mut u8, src: *const u8, n: u64)"),
        "sol_memset_" => Some("sol_memset_(dst: *mut u8, value: u8, n: u64)"),
        "sol_memcmp_" => Some("sol_memcmp_(a: *const u8, b: *const u8, n: u64) -> i32"),
        "sol_memmove_" => Some("sol_memmove_(dst: *mut u8, src: *const u8, n: u64)"),
        "sol_invoke_signed_rust" => Some(
            "sol_invoke_signed_rust(insn: *const Instruction, account_infos: *const AccountInfo, \
             account_infos_len: u64, signers_seeds: *const SignerSeeds, signers_seeds_len: u64) -> u64",
        ),
        "sol_invoke_signed_c" => Some(
            "sol_invoke_signed_c(insn: *const Instruction, account_infos: *const AccountInfo, \
             account_infos_len: u64, signers_seeds: *const SignerSeeds, signers_seeds_len: u64) -> u64",
        ),
        "sol_try_find_program_address" => Some(
            "sol_try_find_program_address(seeds: *const Seed, seeds_len: u64, \
             program_id: *const Pubkey, address: *mut Pubkey, bump: *mut u8) -> u64",
        ),
        "sol_create_program_address" => Some(
            "sol_create_program_address(seeds: *const Seed, seeds_len: u64, \
             program_id: *const Pubkey, address: *mut Pubkey) -> u64",
        ),
        "sol_get_clock_sysvar" => Some("sol_get_clock_sysvar(buf: *mut Clock) -> u64"),
        "sol_get_rent_sysvar" => Some("sol_get_rent_sysvar(buf: *mut Rent) -> u64"),
        "sol_get_epoch_schedule_sysvar" => {
            Some("sol_get_epoch_schedule_sysvar(buf: *mut EpochSchedule) -> u64")
        }
        "sol_get_fees_sysvar" => Some("sol_get_fees_sysvar(buf: *mut Fees) -> u64"),
        "sol_get_stack_height" => Some("sol_get_stack_height() -> u64"),
        "sol_get_return_data" => {
            Some("sol_get_return_data(data: *mut u8, len: u64, program_id: *mut Pubkey) -> u64")
        }
        "sol_set_return_data" => Some("sol_set_return_data(data: *const u8, len: u64)"),
        "sol_sha256" => {
            Some("sol_sha256(slices: *const Slice, n: u64, result: *mut [u8; 32]) -> u64")
        }
        "sol_keccak256" => {
            Some("sol_keccak256(slices: *const Slice, n: u64, result: *mut [u8; 32]) -> u64")
        }
        "sol_secp256k1_recover" => Some(
            "sol_secp256k1_recover(hash: *const u8, recovery_id: u64, signature: *const u8, \
             result: *mut u8) -> u64",
        ),
        "sol_blake3" => {
            Some("sol_blake3(slices: *const Slice, n: u64, result: *mut [u8; 32]) -> u64")
        }
        "sol_curve_validate_point" => {
            Some("sol_curve_validate_point(curve: u64, point: *const u8) -> u64")
        }
        "sol_curve_group_op" => Some(
            "sol_curve_group_op(curve: u64, op: u64, a: *const u8, b: *const u8, \
             result: *mut u8) -> u64",
        ),
        "sol_alloc_free_" => Some("sol_alloc_free_(size: u64, freep: *mut u8) -> *mut u8"),
        "sol_panic_" => Some("sol_panic_(filename: *const u8, len: u64, line: u64, column: u64)"),
        "sol_remaining_compute_units" => Some("sol_remaining_compute_units() -> u64"),
        "abort" => Some("abort() -> !"),
        _ => None,
    }
}
