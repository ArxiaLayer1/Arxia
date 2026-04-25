//! Slashing proofs for relay-score penalties.
//!
//! A [`SlashingProof`] carries an Ed25519 signature by an observer
//! over a domain-separated claim that names a specific target relay.
//! [`crate::scoring::RelayScore::slash`] consumes a reference to a
//! proof, verifies it, and applies the penalty via `saturating_sub`
//! so no penalty value (even `i64::MAX`) can wrap the score past
//! `i64::MIN`.
//!
//! # Known limitation
//!
//! This commit (CRIT-006) does NOT validate that the observer's
//! public key is present in a trusted observer registry — there is
//! no such registry in the workspace yet. The gate here raises the
//! bar from "anyone can call `slash(i64::MAX)`" to "the caller must
//! name an observer and produce a valid signature by that observer's
//! private key over a claim targeting this relay". Once the
//! consensus layer defines the observer set, a follow-up commit
//! will add the `observer_pubkey ∈ registered_observers` check at
//! the `verify` boundary.

use serde::{Deserialize, Serialize};

use arxia_core::ArxiaError;

/// Domain-separation prefix for the Ed25519 signature on a
/// [`SlashingProof`].
///
/// Distinct from [`crate::receipt::RELAY_RECEIPT_DOMAIN`] so that a
/// signature minted for a receipt cannot be repackaged as a
/// slashing claim (cross-action replay). A future layout change MUST
/// bump the `-v1` suffix.
pub const SLASHING_PROOF_DOMAIN: &[u8] = b"arxia-relay-slash-v1";

/// Errors returned by [`SlashingProof::verify`] and
/// [`crate::scoring::RelayScore::slash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashingError {
    /// `target_relay_id` is not a 64-character lowercase-hex string
    /// of a 32-byte pubkey.
    InvalidTargetRelayId,
    /// `signature` is not a valid Ed25519 signature over the proof's
    /// canonical message under the declared observer pubkey. This is
    /// the exploit surface for CRIT-006.
    SignatureInvalid,
    /// The observer pubkey is structurally invalid (e.g. low-order).
    InvalidObserverPubkey,
    /// `signature` is not exactly 64 bytes.
    InvalidSignatureLength,
    /// The proof targets a different relay than the one being
    /// slashed.
    TargetMismatch,
    /// `penalty < 0`. Slashing cannot gift score — a negative
    /// penalty would be a reward, and the `saturating_sub(neg)`
    /// idiom adds rather than subtracts.
    NegativePenalty,
}

impl std::fmt::Display for SlashingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTargetRelayId => {
                f.write_str("target_relay_id is not a 64-char lowercase hex 32-byte pubkey")
            }
            Self::SignatureInvalid => {
                f.write_str("signature does not verify against the observer pubkey")
            }
            Self::InvalidObserverPubkey => {
                f.write_str("observer_pubkey is not a valid Ed25519 public key")
            }
            Self::InvalidSignatureLength => f.write_str("signature must be exactly 64 bytes"),
            Self::TargetMismatch => {
                f.write_str("proof's target_relay_id does not match the scored relay")
            }
            Self::NegativePenalty => f.write_str("penalty must be non-negative"),
        }
    }
}

impl std::error::Error for SlashingError {}

/// Signed attestation that a relay misbehaved, consumed by
/// [`crate::scoring::RelayScore::slash`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingProof {
    /// Public key of the observer making the claim, as 32 raw bytes.
    pub observer_pubkey: [u8; 32],
    /// The relay being accused, encoded as 64 lowercase hex chars
    /// (32 raw bytes).
    pub target_relay_id: String,
    /// Free-form human-readable reason for the slash (included in
    /// the signed payload so it cannot be tampered with post-sign).
    pub reason: String,
    /// Ed25519 signature over [`SlashingProof::canonical_message`]
    /// by the private key matching `observer_pubkey`. MUST be
    /// exactly 64 bytes when the proof is considered valid.
    pub signature: Vec<u8>,
}

impl SlashingProof {
    /// Build the canonical message bytes that the observer signs.
    ///
    /// Layout:
    ///
    /// - `SLASHING_PROOF_DOMAIN`           (20 bytes)
    /// - observer pubkey                   (32 bytes, raw)
    /// - target relay pubkey               (32 bytes, raw)
    /// - reason length                     (8 bytes, big-endian)
    /// - reason bytes                      (variable)
    pub fn canonical_message(&self) -> Result<Vec<u8>, SlashingError> {
        let target = decode_hex_32(&self.target_relay_id)
            .map_err(|_| SlashingError::InvalidTargetRelayId)?;
        let reason_bytes = self.reason.as_bytes();
        let mut buf =
            Vec::with_capacity(SLASHING_PROOF_DOMAIN.len() + 32 + 32 + 8 + reason_bytes.len());
        buf.extend_from_slice(SLASHING_PROOF_DOMAIN);
        buf.extend_from_slice(&self.observer_pubkey);
        buf.extend_from_slice(&target);
        buf.extend_from_slice(&(reason_bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(reason_bytes);
        Ok(buf)
    }

    /// Verify the observer's Ed25519 signature on the canonical
    /// message. Does NOT check that the observer is in any trusted
    /// registry — see module docs.
    pub fn verify(&self) -> Result<(), SlashingError> {
        let msg = self.canonical_message()?;
        if self.signature.len() != 64 {
            return Err(SlashingError::InvalidSignatureLength);
        }
        let sig: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SlashingError::InvalidSignatureLength)?;
        arxia_crypto::verify(&self.observer_pubkey, &msg, &sig).map_err(|e| match e {
            ArxiaError::InvalidKey(_) => SlashingError::InvalidObserverPubkey,
            _ => SlashingError::SignatureInvalid,
        })
    }
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], ()> {
    let v = hex::decode(s).map_err(|_| ())?;
    v.as_slice().try_into().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::{generate_keypair, sign};

    fn sign_proof(
        sk: &ed25519_dalek::SigningKey,
        observer_pk: [u8; 32],
        target: &str,
        reason: &str,
    ) -> SlashingProof {
        let mut p = SlashingProof {
            observer_pubkey: observer_pk,
            target_relay_id: target.to_string(),
            reason: reason.to_string(),
            signature: Vec::new(),
        };
        let msg = p.canonical_message().unwrap();
        p.signature = sign(sk, &msg).to_vec();
        p
    }

    #[test]
    fn test_verify_accepts_correctly_signed_proof() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let relay_hex = hex::encode([0x77u8; 32]);
        let p = sign_proof(&sk, pk, &relay_hex, "double-signed receipt");
        assert!(p.verify().is_ok());
    }

    #[test]
    fn test_verify_rejects_zero_signature() {
        let (_, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let p = SlashingProof {
            observer_pubkey: pk,
            target_relay_id: hex::encode([0x77u8; 32]),
            reason: "anything".to_string(),
            signature: vec![0u8; 64],
        };
        assert_eq!(p.verify(), Err(SlashingError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_wrong_length_signature() {
        let (_, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let p = SlashingProof {
            observer_pubkey: pk,
            target_relay_id: hex::encode([0x77u8; 32]),
            reason: "anything".to_string(),
            signature: vec![0u8; 32],
        };
        assert_eq!(p.verify(), Err(SlashingError::InvalidSignatureLength));
    }

    #[test]
    fn test_verify_rejects_tampered_reason() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let relay_hex = hex::encode([0x77u8; 32]);
        let mut p = sign_proof(&sk, pk, &relay_hex, "original reason");
        p.reason = "different reason".to_string();
        assert_eq!(p.verify(), Err(SlashingError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_tampered_target() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut p = sign_proof(&sk, pk, &hex::encode([0x77u8; 32]), "r");
        p.target_relay_id = hex::encode([0x88u8; 32]);
        assert_eq!(p.verify(), Err(SlashingError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_swapped_observer_pubkey() {
        let (sk_a, vk_a) = generate_keypair();
        let (_, vk_b) = generate_keypair();
        let mut p = sign_proof(&sk_a, vk_a.to_bytes(), &hex::encode([0x77u8; 32]), "r");
        p.observer_pubkey = vk_b.to_bytes();
        assert_eq!(p.verify(), Err(SlashingError::SignatureInvalid));
    }

    #[test]
    fn test_verify_rejects_non_hex_target() {
        // Can't go through sign_proof() because canonical_message
        // rejects the non-hex target BEFORE we get a chance to sign.
        let (_, vk) = generate_keypair();
        let p = SlashingProof {
            observer_pubkey: vk.to_bytes(),
            target_relay_id: "not-hex".to_string(),
            reason: "r".to_string(),
            signature: vec![0u8; 64],
        };
        assert_eq!(p.verify(), Err(SlashingError::InvalidTargetRelayId));
    }

    #[test]
    fn test_verify_rejects_wrong_length_target() {
        let (_, vk) = generate_keypair();
        let p = SlashingProof {
            observer_pubkey: vk.to_bytes(),
            target_relay_id: hex::encode([0u8; 16]), // 16 bytes, not 32
            reason: "r".to_string(),
            signature: vec![0u8; 64],
        };
        assert_eq!(p.verify(), Err(SlashingError::InvalidTargetRelayId));
    }

    #[test]
    fn test_domain_separation_vs_relay_receipt_domain() {
        // A signature minted with the relay-receipt domain prefix
        // (commit 013) MUST NOT verify as a slashing proof.
        use crate::receipt::RELAY_RECEIPT_DOMAIN;
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let target = [0x77u8; 32];
        // Fabricate bytes with RECEIPT domain instead of SLASHING.
        let mut raw = Vec::new();
        raw.extend_from_slice(RELAY_RECEIPT_DOMAIN);
        raw.extend_from_slice(&pk);
        raw.extend_from_slice(&target);
        raw.extend_from_slice(&(0u64).to_be_bytes());
        let receipt_domain_sig = sign(&sk, &raw);
        let p = SlashingProof {
            observer_pubkey: pk,
            target_relay_id: hex::encode(target),
            reason: String::new(),
            signature: receipt_domain_sig.to_vec(),
        };
        assert_eq!(p.verify(), Err(SlashingError::SignatureInvalid));
    }
}
