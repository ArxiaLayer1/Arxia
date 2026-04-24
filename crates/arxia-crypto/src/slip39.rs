//! SLIP39 Shamir Secret Sharing for seed backup and recovery.
//!
//! # Status — NOT IMPLEMENTED
//!
//! Reserved for milestones M12–M18 (portable key recovery: users
//! split their Ed25519 seed into 3 shares, any 2 of which can
//! reconstruct the original seed). The public `split_seed` and
//! `reconstruct_seed` functions currently return [`Unimplemented`]
//! and never touch their inputs.
//!
//! Pre-fix these functions were panic-on-call stubs (the standard
//! `todo` macro) — see CRIT-003 in `PHASE1_AUDIT_REPORT`. A caller
//! reaching the wallet-backup / key-recovery flow would panic the
//! process. Replacing the panic with an explicit `Err(Unimplemented)`
//! surfaces the unimplemented state to the type system.

use crate::Unimplemented;

/// Split a seed into `shares` shares with threshold `threshold`.
///
/// # Status
///
/// Always returns [`Err(Unimplemented)`] until a reviewed SLIP39
/// implementation is wired in. Do NOT deploy any wallet-backup flow
/// that depends on this path.
pub fn split_seed(
    _seed: &[u8; 32],
    _threshold: u8,
    _shares: u8,
) -> Result<Vec<Vec<u8>>, Unimplemented> {
    Err(Unimplemented)
}

/// Reconstruct a seed from `threshold` shares.
///
/// # Status
///
/// Always returns [`Err(Unimplemented)`] — see module docs and
/// [`split_seed`].
pub fn reconstruct_seed(_shares: &[Vec<u8>]) -> Result<[u8; 32], Unimplemented> {
    Err(Unimplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slip39_split_seed_returns_unimplemented_instead_of_panic() {
        let seed = [0u8; 32];
        assert_eq!(split_seed(&seed, 2, 3), Err(Unimplemented));
    }

    #[test]
    fn test_slip39_reconstruct_seed_returns_unimplemented_instead_of_panic() {
        let shares: Vec<Vec<u8>> = vec![vec![0u8; 16], vec![1u8; 16]];
        assert_eq!(reconstruct_seed(&shares), Err(Unimplemented));
    }

    /// Grep-guard regression test (CRIT-003): the current source of
    /// this file MUST NOT contain a panicking stub invocation of
    /// the `todo` macro. If you are seeing this test fail, someone
    /// re-added a panicking stub — use `Err(Unimplemented)` instead.
    #[test]
    fn test_slip39_source_has_no_todo_panic() {
        let src = include_str!("slip39.rs");
        let needle = concat!("todo", "!(");
        assert!(
            !src.contains(needle),
            "slip39.rs must not contain a panicking-stub invocation"
        );
    }
}
