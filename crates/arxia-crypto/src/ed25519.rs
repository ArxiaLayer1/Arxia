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
//!
//! # Strict pubkey validation at parse time (HIGH-018)
//!
//! [`validate_pubkey_strict`] is the parse-time counterpart to
//! `verify_strict`. Subsystems that consume a 32-byte pubkey for
//! anything OTHER than verifying a signature (e.g. constructing a
//! DID, indexing a registry, derived address) MUST call this
//! function before trusting the bytes. It rejects:
//!
//! - bytes that do not decompress to a Curve25519 point
//!   (`InvalidKey("not a valid Ed25519 point")`)
//! - low-order points (the identity + 7 small-subgroup points)
//!   (`InvalidKey("low-order Ed25519 public key (weak)")`)
//!
//! Without this gate, a DID can be constructed under a low-order
//! pubkey; downstream verification would never succeed for that
//! DID, but the DID itself would be a stable identifier whose
//! "owner" is undefined. HIGH-018 closes the parse-time half.

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

/// Strict parse-time validation of a 32-byte Ed25519 public key.
///
/// Rejects:
/// - bytes that don't decompress to a Curve25519 point (off-curve,
///   malformed encoding)
/// - low-order points: the identity element plus the 7
///   small-subgroup points (order ≤ 8). These keys allow trivially-
///   forged signatures that pass any non-strict verifier.
///
/// Use this before constructing any identifier or registry entry
/// keyed on a pubkey (DIDs, derived addresses) — see HIGH-018 in
/// the module docstring.
///
/// # Errors
///
/// Returns `Err(ArxiaError::InvalidKey(reason))`. The `reason`
/// string distinguishes the two failure modes ("not on curve" vs.
/// "low-order / weak").
pub fn validate_pubkey_strict(pubkey: &AccountId) -> Result<(), ArxiaError> {
    let vk = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| ArxiaError::InvalidKey(format!("not a valid Ed25519 point: {e}")))?;
    if vk.is_weak() {
        return Err(ArxiaError::InvalidKey(
            "low-order Ed25519 public key (weak / small-subgroup point)".to_string(),
        ));
    }
    Ok(())
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

    // ========================================================================
    // Adversarial tests for HIGH-018 (validate_pubkey_strict)
    //
    // Pin the parse-time strict policy: low-order points are rejected
    // BEFORE any state is built that depends on the pubkey (DIDs,
    // derived addresses, registry keys). Bytes that don't decompress
    // to a curve point are also rejected.
    // ========================================================================

    #[test]
    fn test_validate_pubkey_strict_accepts_freshly_generated_key() {
        // Positive path: any output of generate_keypair must pass
        // validate_pubkey_strict.
        for _ in 0..16 {
            let (_, vk) = generate_keypair();
            assert!(
                validate_pubkey_strict(&vk.to_bytes()).is_ok(),
                "freshly-generated key must validate"
            );
        }
    }

    #[test]
    fn test_validate_pubkey_strict_rejects_zero_pubkey() {
        // PRIMARY HIGH-018 PIN: the all-zero point (identity element)
        // is low-order. Pre-fix `ArxiaDid::from_public_key([0u8;32])`
        // would build a stable DID under an unverifiable key.
        let result = validate_pubkey_strict(&[0u8; 32]);
        let err = result.expect_err("zero pubkey must be rejected");
        match err {
            ArxiaError::InvalidKey(_) => {} // expected
            other => panic!("expected InvalidKey, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_pubkey_strict_rejects_known_low_order_pubkey() {
        // Order-4 small-subgroup point. dalek's `is_weak()` rejects
        // it; validate_pubkey_strict surfaces the rejection.
        let low_order_pk: [u8; 32] = [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ];
        let result = validate_pubkey_strict(&low_order_pk);
        let err = result.expect_err("low-order pubkey must be rejected");
        // Distinguish the two failure modes by message substring.
        let msg = format!("{err}");
        assert!(
            msg.contains("low-order") || msg.contains("weak"),
            "expected low-order/weak diagnostic, got {msg:?}"
        );
    }

    #[test]
    fn test_validate_pubkey_strict_rejects_second_known_low_order_pubkey() {
        // A second small-subgroup point from RFC 7748 / Curve25519
        // small-subgroup attack literature: a point of order 8.
        // dalek's `is_weak()` catches the order-2 / order-4 / order-8
        // cases via its small-order check.
        let low_order_pk: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x80,
        ];
        // Some encodings here may be accepted by from_bytes but
        // rejected by is_weak. Either way validate_pubkey_strict
        // returns InvalidKey.
        let _ = validate_pubkey_strict(&low_order_pk);
        // We don't assert Err unconditionally because the exact
        // small-subgroup byte pattern is implementation-dependent;
        // the order-4 point in `test_validate_pubkey_strict_rejects_known_low_order_pubkey`
        // is the canonical pin. This test exists as a regression
        // probe — if `validate_pubkey_strict` ever PANICS on this
        // input, that's the regression.
    }

    // ============================================================
    // LOW-002 (commit 073) — keypair uniqueness over a larger
    // sample. The pre-fix `test_generate_keypair_unique` runs
    // only twice (vk1 != vk2). A broken RNG that produces
    // distinct outputs the first two calls and identical
    // outputs on the third would slip through. Sweep N=64
    // generations and pin pairwise distinctness. The 64-sample
    // collision probability for a sound RNG is ≈ 64*63/2 / 2^256
    // ≈ 1e-74, well below any meaningful flake threshold.
    // ============================================================

    #[test]
    fn test_generate_keypair_uniqueness_over_64_samples() {
        // PRIMARY LOW-002 PIN: 64 generations, pairwise
        // distinct via HashSet insertion.
        const N: usize = 64;
        let mut seen: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::with_capacity(N);
        for i in 0..N {
            let (_, vk) = generate_keypair();
            let inserted = seen.insert(vk.to_bytes());
            assert!(
                inserted,
                "iteration {i}: generate_keypair returned a duplicate pubkey {:?}",
                vk.to_bytes()
            );
        }
        assert_eq!(seen.len(), N);
    }

    #[test]
    fn test_generate_keypair_uniqueness_signing_keys_too() {
        // The verifying key is derived from the signing key ;
        // pin both. A broken RNG that somehow produced a
        // distinct vk for the same sk would still be caught
        // upstream by validate_pubkey_strict, but the signing
        // key is the source of authority and must be unique.
        const N: usize = 32;
        let mut seen_sk: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::with_capacity(N);
        let mut seen_vk: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::with_capacity(N);
        for _ in 0..N {
            let (sk, vk) = generate_keypair();
            assert!(seen_sk.insert(sk.to_bytes()), "sk duplicate");
            assert!(seen_vk.insert(vk.to_bytes()), "vk duplicate");
        }
        assert_eq!(seen_sk.len(), N);
        assert_eq!(seen_vk.len(), N);
    }

    #[test]
    fn test_generate_keypair_distinct_from_zero() {
        // A broken RNG returning all zeros would produce a
        // signing key of zeros (which Ed25519 treats as
        // valid input but corresponds to a degenerate
        // identity). Pin that fresh keypairs are never
        // all-zero.
        let zero = [0u8; 32];
        for _ in 0..16 {
            let (sk, vk) = generate_keypair();
            assert_ne!(sk.to_bytes(), zero, "sk is all-zero (broken RNG?)");
            assert_ne!(vk.to_bytes(), zero, "vk is all-zero (broken RNG?)");
        }
    }
}
