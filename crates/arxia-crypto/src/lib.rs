//! Cryptographic primitives for the Arxia protocol.
//!
//! Provides Ed25519 signatures, Blake3 hashing, ChaCha20-Poly1305
//! encryption, and SLIP39 seed backup.
//!
//! # Critical invariant
//!
//! Ed25519 signatures are computed over **raw Blake3 bytes** (32 bytes),
//! NOT over the hex-encoded string (64 bytes). This was a bug fixed in
//! PoC v0.3.0 and must never be reintroduced.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod blake3_hash;
pub mod chacha20;
pub mod ed25519;
pub mod slip39;

pub use blake3_hash::{hash_blake3, hash_blake3_bytes};
pub use ed25519::{generate_keypair, sign, validate_pubkey_strict, verify};

/// Marker error returned by crypto functions that are deliberately
/// left un-implemented until a future milestone.
///
/// This type exists to close CRIT-002 / CRIT-003: pre-fix,
/// [`chacha20::encrypt`], [`chacha20::decrypt`], [`slip39::split_seed`],
/// and [`slip39::reconstruct_seed`] were panic-on-call stubs, so a
/// caller that reached them crashed the process at runtime. Now
/// those functions return `Result<_, Unimplemented>` and callers
/// MUST handle the error case at compile time — either by `?`-
/// propagating it, gating the feature behind a capability check,
/// or refusing to ship the dependent flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unimplemented;

impl std::fmt::Display for Unimplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("feature not implemented; reserved for a future milestone")
    }
}

impl std::error::Error for Unimplemented {}
