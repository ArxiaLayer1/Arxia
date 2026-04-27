//! Decentralized Identity (DID) for Arxia.
//!
//! Format: `did:arxia:<base58(blake3(pubkey_bytes))>`
//!
//! # Strict pubkey validation (HIGH-018, commit 037)
//!
//! [`ArxiaDid::from_public_key`] validates the input bytes via
//! [`arxia_crypto::validate_pubkey_strict`] before constructing the
//! identifier. This rejects:
//!
//! - bytes that don't decompress to a Curve25519 point (off-curve,
//!   malformed encoding) → `InvalidKey("not a valid Ed25519 point: …")`
//! - low-order points (the identity + 7 small-subgroup points) →
//!   `InvalidKey("low-order Ed25519 public key (weak / small-
//!   subgroup point)")`
//!
//! Pre-fix the function accepted any 32-byte slice unconditionally.
//! A caller could mint a stable DID under a low-order pubkey for
//! which signature verification is mathematically impossible
//! ("anyone can sign as this DID" via small-subgroup tricks). The
//! audit (HIGH-018):
//!
//! > Pass 32 arbitrary bytes (including low-order points,
//! > torsion-group elements, or just garbage). DIDs can be
//! > constructed from unverifiable keys; anyone can claim an
//! > identity under that DID by signing with whatever private key
//! > they invented that matches no real curve point.
//!
//! Refs: PHASE1_AUDIT_REPORT.md HIGH-018.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use arxia_core::ArxiaError;
use serde::{Deserialize, Serialize};

/// An Arxia Decentralized Identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArxiaDid {
    /// The full DID string.
    pub did: String,
    /// The Ed25519 public key bytes.
    pub public_key: [u8; 32],
}

impl ArxiaDid {
    /// Create a new DID from an Ed25519 public key.
    ///
    /// The bytes are validated via
    /// [`arxia_crypto::validate_pubkey_strict`] before any DID
    /// material is built — see HIGH-018 in the module docstring.
    ///
    /// # Errors
    ///
    /// Returns `Err(ArxiaError::InvalidKey(reason))` for off-curve
    /// or low-order pubkey bytes.
    pub fn from_public_key(public_key: &[u8; 32]) -> Result<Self, ArxiaError> {
        arxia_crypto::validate_pubkey_strict(public_key)?;
        let hash = arxia_crypto::hash_blake3_bytes(public_key);
        let encoded = bs58::encode(&hash).into_string();
        Ok(Self {
            did: format!("did:arxia:{}", encoded),
            public_key: *public_key,
        })
    }

    /// Return the DID string.
    pub fn as_str(&self) -> &str {
        &self.did
    }

    /// Return the Base58-encoded identifier portion.
    pub fn identifier(&self) -> &str {
        self.did.strip_prefix("did:arxia:").unwrap_or(&self.did)
    }
}

impl std::fmt::Display for ArxiaDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::generate_keypair;

    #[test]
    fn test_did_from_public_key() {
        let (_, vk) = generate_keypair();
        let did = ArxiaDid::from_public_key(&vk.to_bytes()).unwrap();
        assert!(did.did.starts_with("did:arxia:"));
        assert!(!did.identifier().is_empty());
    }

    #[test]
    fn test_did_deterministic() {
        // Generate a keypair so we have valid Ed25519 bytes; reuse
        // the same bytes across two calls to pin determinism.
        let (_, vk) = generate_keypair();
        let pubkey = vk.to_bytes();
        let did1 = ArxiaDid::from_public_key(&pubkey).unwrap();
        let did2 = ArxiaDid::from_public_key(&pubkey).unwrap();
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_did_display() {
        let (_, vk) = generate_keypair();
        let did = ArxiaDid::from_public_key(&vk.to_bytes()).unwrap();
        let displayed = format!("{}", did);
        assert!(displayed.starts_with("did:arxia:"));
    }

    #[test]
    fn test_different_keys_different_dids() {
        let (_, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let did1 = ArxiaDid::from_public_key(&vk1.to_bytes()).unwrap();
        let did2 = ArxiaDid::from_public_key(&vk2.to_bytes()).unwrap();
        assert_ne!(did1, did2);
    }

    // ============================================================
    // HIGH-018 (commit 037) — from_public_key validates the curve
    // point before building the DID. Off-curve and low-order
    // pubkeys are rejected.
    // ============================================================

    #[test]
    fn test_did_from_public_key_rejects_zero_pubkey() {
        // PRIMARY HIGH-018 PIN: the all-zero point (identity
        // element) is a low-order point. Pre-fix this would build
        // a stable DID under an unverifiable key.
        let err = ArxiaDid::from_public_key(&[0u8; 32]).expect_err("zero pubkey must be rejected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_did_from_public_key_rejects_known_low_order_pubkey() {
        // Order-4 small-subgroup point. dalek's is_weak() catches
        // it via validate_pubkey_strict.
        let low_order_pk: [u8; 32] = [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ];
        let err = ArxiaDid::from_public_key(&low_order_pk)
            .expect_err("low-order pubkey must be rejected");
        assert!(matches!(err, ArxiaError::InvalidKey(_)));
    }

    #[test]
    fn test_did_from_public_key_accepts_many_freshly_generated_keys() {
        // Positive regression guard: every freshly-generated keypair
        // produces a valid DID. Pinned at 16 iterations to catch any
        // future regression that accidentally over-rejects valid
        // keys (e.g. a future is_weak() implementation flagging
        // legitimate dalek output).
        for _ in 0..16 {
            let (_, vk) = generate_keypair();
            assert!(ArxiaDid::from_public_key(&vk.to_bytes()).is_ok());
        }
    }
}
