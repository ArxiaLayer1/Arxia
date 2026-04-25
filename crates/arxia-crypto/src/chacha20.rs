//! ChaCha20-Poly1305 authenticated encryption for local data protection.
//!
//! # Status — NOT IMPLEMENTED
//!
//! Reserved for milestones M12–M18 (local-wallet-at-rest encryption
//! on mobile devices and ESP32 flash storage). The public `encrypt`
//! and `decrypt` functions currently return [`Unimplemented`] and
//! never touch their inputs.
//!
//! Pre-fix these functions were panic-on-call stubs (the standard
//! `todo` macro) — see CRIT-002 in `PHASE1_AUDIT_REPORT`. A caller
//! who force-routed a payload onto an encrypted path could crash the
//! process. Replacing the panic with an explicit `Err(Unimplemented)`
//! surfaces the unimplemented state to the type system, so downstream
//! callers are forced to handle it at compile time (via `?` or
//! `match`) rather than encountering it at runtime.

use crate::Unimplemented;

/// Encrypt data with ChaCha20-Poly1305.
///
/// # Status
///
/// Always returns `Err(Unimplemented)` until the ChaCha20-Poly1305
/// scheme is wired through `chacha20poly1305` or an equivalent
/// audited crate. Do NOT ship any caller that silently treats this
/// as best-effort.
pub fn encrypt(
    _key: &[u8; 32],
    _nonce: &[u8; 12],
    _plaintext: &[u8],
) -> Result<Vec<u8>, Unimplemented> {
    Err(Unimplemented)
}

/// Decrypt data with ChaCha20-Poly1305.
///
/// # Status
///
/// Always returns `Err(Unimplemented)` — see module docs and
/// [`encrypt`].
pub fn decrypt(
    _key: &[u8; 32],
    _nonce: &[u8; 12],
    _ciphertext: &[u8],
) -> Result<Vec<u8>, Unimplemented> {
    Err(Unimplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_encrypt_returns_unimplemented_instead_of_panic() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"anything";
        // Pre-CRIT-002-fix this panicked via the `todo` macro. Post-
        // fix it returns Err(Unimplemented) — a type-level signal the
        // caller must handle.
        assert_eq!(encrypt(&key, &nonce, plaintext), Err(Unimplemented));
    }

    #[test]
    fn test_chacha20_decrypt_returns_unimplemented_instead_of_panic() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let ciphertext = b"anything";
        assert_eq!(decrypt(&key, &nonce, ciphertext), Err(Unimplemented));
    }

    /// Grep-guard regression test (CRIT-002): the current source of
    /// this file MUST NOT contain a panicking stub invocation of
    /// the `todo` macro, because a future refactor could otherwise
    /// silently reintroduce the panic-path that the audit flagged.
    /// If you are seeing this test fail, someone re-added a
    /// panicking stub here — use `Err(Unimplemented)` instead.
    #[test]
    fn test_chacha20_source_has_no_todo_panic() {
        let src = include_str!("chacha20.rs");
        // Build the forbidden needle at runtime so this very file
        // does not self-match.
        let needle = concat!("todo", "!(");
        assert!(
            !src.contains(needle),
            "chacha20.rs must not contain a panicking-stub invocation"
        );
    }
}
