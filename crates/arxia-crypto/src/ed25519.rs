//! Ed25519 signature operations.
//!
//! All signing is performed over **raw bytes** (typically 32-byte Blake3 hashes),
//! never over hex-encoded strings.
//!
//! # Strict verification (HIGH-001)
//!
//! [`verify`] uses `ed25519_dalek::VerifyingKey::verify_strict`, which
//! rejects:
//!
//! - **Non-canonical `S`** (RFC 8032 §5.1.7): the scalar component of
//!   the signature must satisfy `S < L`, where
//!   `L = 2^252 + 27742317777372353535851937790883648493` is the order
//!   of the prime subgroup. The lenient `verify` API accepts `S ≥ L`,
//!   which enables signature malleability — given a valid signature
//!   `(R, S)`, an attacker can produce `(R, S + L)` that also verifies
//!   under `verify` but represents a different bit pattern. Critical
//!   for any subsystem that hashes a signature into another protocol
//!   message (relay receipts, slashing proofs, gossip envelopes).
//! - **Low-order public keys**: points of order ≤ 8 on Curve25519
//!   (the identity, plus 7 small-subgroup points). These keys allow
//!   trivially-forgeable signatures and are excluded from the
//!   protocol surface at parse / verify time.
//!
//! Every Arxia subsystem that calls `arxia_crypto::verify` (lattice,
//! consensus, relay, gossip, finality, escrow, DID) inherits the
//! strict check transparently — no caller-side migration is needed
//! because `verify_strict` accepts every signature produced by
//! `arxia_crypto::sign` (which uses dalek's `Signer::sign`, which
//! always emits canonical signatures).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use arxia_core::{AccountId, ArxiaError, SignatureBytes};

/// Generate a new Ed25519 keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign raw bytes with an Ed25519 signing key.
///
/// The `data` parameter must be raw bytes (e.g., a 32-byte Blake3 hash),
/// NOT a hex string.
pub fn sign(signing_key: &SigningKey, data: &[u8]) -> SignatureBytes {
    signing_key.sign(data).to_bytes()
}

/// Verify an Ed25519 signature over raw bytes.
///
/// Uses dalek's `verify_strict` API, which enforces the canonicality
/// constraints from RFC 8032 §5.1.7 (`S < L`) and rejects low-order
/// public keys. See the module docstring for the full rationale.
///
/// # Errors
///
/// Returns `Err(ArxiaError::InvalidKey)` if `pubkey` is structurally
/// invalid as a `VerifyingKey` (which includes most low-order points
/// after dalek 2.x; the rest are caught by the strict-verify path).
/// Returns `Err(ArxiaError::SignatureInvalid)` if the signature does
/// not verify under the strict policy — including the case of a
/// canonical message + matching key + non-canonical `S`.
pub fn verify(
    pubkey: &AccountId,
    data: &[u8],
    signature: &SignatureBytes,
) -> Result<(), ArxiaError> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|e| ArxiaError::InvalidKey(e.to_string()))?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(data, &sig)
        .map_err(|e| ArxiaError::SignatureInvalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_raw_bytes() {
        let (sk, vk) = generate_keypair();
        let data = crate::hash_blake3_bytes(b"test message");
        let sig = sign(&sk, &data);
        assert!(verify(&vk.to_bytes(), &data, &sig).is_ok());
    }

    #[test]
    fn test_verify_rejects_tampered_data() {
        let (sk, vk) = generate_keypair();
        let data = crate::hash_blake3_bytes(b"original");
        let sig = sign(&sk, &data);
        let tampered = crate::hash_blake3_bytes(b"tampered");
        assert!(verify(&vk.to_bytes(), &tampered, &sig).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let (sk, _) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let data = [0u8; 32];
        let sig = sign(&sk, &data);
        assert!(verify(&vk2.to_bytes(), &data, &sig).is_err());
    }

    #[test]
    fn test_sign_over_blake3_bytes_not_hex() {
        let (sk, vk) = generate_keypair();
        let hash_hex = crate::hash_blake3(b"important");
        let hash_bytes = hex::decode(&hash_hex).unwrap();
        assert_eq!(hash_bytes.len(), 32);
        let sig = sign(&sk, &hash_bytes);
        assert!(verify(&vk.to_bytes(), &hash_bytes, &sig).is_ok());
        let wrong_sig = sign(&sk, hash_hex.as_bytes());
        assert!(verify(&vk.to_bytes(), &hash_bytes, &wrong_sig).is_err());
    }

    #[test]
    fn test_generate_keypair_unique() {
        let (_, vk1) = generate_keypair();
        let (_, vk2) = generate_keypair();
        assert_ne!(vk1.to_bytes(), vk2.to_bytes());
    }

    // ========================================================================
    // Adversarial tests for HIGH-001 (verify_strict)
    //
    // Pin the strict semantics: non-canonical S is rejected, low-order
    // pubkeys are rejected, and the existing canonical signatures from
    // `sign` continue to verify.
    // ========================================================================

    /// Order of the prime subgroup of Curve25519, little-endian.
    ///
    /// `L = 2^252 + 27742317777372353535851937790883648493`. Defined
    /// here purely for the malleability test; production code should
    /// not need to look at `L` directly.
    const ED25519_L_LE: [u8; 32] = [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    /// Add `L` to a 32-byte little-endian scalar with wrap-around at
    /// 2^256. Used to construct a non-canonical `S' = S + L` from a
    /// canonical `S`. Returns the new scalar bytes.
    fn add_l_to_scalar_le(s: [u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry: u16 = 0;
        for i in 0..32 {
            let sum = u16::from(s[i]) + u16::from(ED25519_L_LE[i]) + carry;
            out[i] = sum as u8;
            carry = sum >> 8;
        }
        out
    }

    #[test]
    fn test_verify_strict_rejects_non_canonical_s_via_s_plus_l() {
        // Build a valid signature, then add L to its S component to
        // produce a non-canonical (but still mathematically-valid
        // under the lenient API) signature. verify_strict must reject.
        let (sk, vk) = generate_keypair();
        let data = [0x42u8; 32];
        let sig_canonical = sign(&sk, &data);

        // Sanity check: the canonical signature verifies.
        assert!(
            verify(&vk.to_bytes(), &data, &sig_canonical).is_ok(),
            "canonical signature must pass verify_strict"
        );

        // Construct the malleable (non-canonical) version: S' = S + L.
        let s_canonical: [u8; 32] = sig_canonical[32..].try_into().unwrap();
        let s_malleable = add_l_to_scalar_le(s_canonical);
        // Sanity check: the new scalar bytes must differ from the
        // canonical ones (otherwise the test would be vacuous).
        assert_ne!(s_canonical, s_malleable);

        let mut sig_malleable: SignatureBytes = sig_canonical;
        sig_malleable[32..].copy_from_slice(&s_malleable);

        // verify_strict MUST reject the non-canonical S.
        let result = verify(&vk.to_bytes(), &data, &sig_malleable);
        assert!(
            result.is_err(),
            "verify_strict must reject non-canonical S (S + L = malleable form), got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_rejects_zero_pubkey() {
        // The all-zero compressed point is the identity element on
        // Curve25519 — a low-order point. dalek either rejects it at
        // VerifyingKey::from_bytes (preferred) or at verify_strict.
        // Either way, verify() returns Err.
        let zero_pubkey = [0u8; 32];
        let data = [0x42u8; 32];
        let dummy_sig = [0u8; 64];
        let result = verify(&zero_pubkey, &data, &dummy_sig);
        assert!(
            result.is_err(),
            "verify must reject the all-zero (identity / low-order) pubkey"
        );
    }

    #[test]
    fn test_verify_rejects_known_low_order_pubkey() {
        // A second known low-order point on Curve25519 in compressed
        // form. From RFC 7748 / Curve25519 small-subgroup attack
        // literature: this byte string represents a point of order 4.
        // dalek must reject either at parse time or at verify_strict.
        // Encoded form (32 bytes, little-endian compressed y):
        let low_order_pk: [u8; 32] = [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ];
        let data = [0x42u8; 32];
        let dummy_sig = [0u8; 64];
        let result = verify(&low_order_pk, &data, &dummy_sig);
        assert!(
            result.is_err(),
            "verify must reject the known low-order pubkey (order 4 small-subgroup point)"
        );
    }

    #[test]
    fn test_verify_strict_accepts_many_canonical_dalek_signatures() {
        // Defense-in-depth: dalek's `Signer::sign` always emits
        // canonical signatures (S < L). This test runs 32 fresh
        // sign/verify rounds to catch any future regression where a
        // change accidentally rejects canonical sigs from the same
        // dalek API.
        for i in 0..32u8 {
            let (sk, vk) = generate_keypair();
            let data = [i; 32];
            let sig = sign(&sk, &data);
            assert!(
                verify(&vk.to_bytes(), &data, &sig).is_ok(),
                "iteration {} canonical sig must verify",
                i
            );
        }
    }

    #[test]
    fn test_verify_strict_rejects_zero_signature_bytes() {
        // Construction-style attack: literal `[0u8; 64]` signature.
        // Not a valid Ed25519 signature under any (data, key) pair,
        // including under verify_strict.
        let (_, vk) = generate_keypair();
        let data = [0x42u8; 32];
        let zero_sig: SignatureBytes = [0u8; 64];
        assert!(
            verify(&vk.to_bytes(), &data, &zero_sig).is_err(),
            "verify must reject the all-zero signature"
        );
    }
}
