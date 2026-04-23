//! Escrow contract for Arxia.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Domain-separation prefix for the Ed25519 signature that authorizes
/// [`Escrow::release`]. Binding the prefix into the signed message
/// prevents a signature minted for a different protocol action from
/// being replayed as a release authorization.
pub const ESCROW_RELEASE_DOMAIN: &[u8] = b"arxia-escrow-release-v1";

/// Escrow state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowState {
    /// Funds are locked.
    Locked,
    /// Funds have been released to the recipient.
    Released,
    /// Funds have been refunded to the sender.
    Refunded,
}

/// An escrow contract.
#[derive(Debug, Clone)]
pub struct Escrow {
    /// Sender account, 32-byte hex-encoded Ed25519 public key.
    pub sender: String,
    /// Recipient account, 32-byte hex-encoded Ed25519 public key.
    pub recipient: String,
    /// Amount held (micro-ARX).
    pub amount: u64,
    /// Current state.
    pub state: EscrowState,
    /// Timeout timestamp (unix ms).
    pub timeout: u64,
}

impl Escrow {
    /// Create a new escrow.
    pub fn new(sender: String, recipient: String, amount: u64, timeout: u64) -> Self {
        Self {
            sender,
            recipient,
            amount,
            state: EscrowState::Locked,
            timeout,
        }
    }

    /// Build the canonical byte message whose Ed25519 signature
    /// authorizes a release. The recipient binds their consent to the
    /// specific escrow (sender, recipient, amount, timeout tuple) so a
    /// signature minted for one escrow cannot be reused for another.
    ///
    /// Layout (total = 23 + 32 + 32 + 8 + 8 = 103 bytes):
    ///
    /// - `ESCROW_RELEASE_DOMAIN` (23 bytes)
    /// - sender pubkey         (32 bytes, raw)
    /// - recipient pubkey      (32 bytes, raw)
    /// - amount                (8 bytes, big-endian)
    /// - timeout               (8 bytes, big-endian)
    pub fn release_message(&self) -> Result<Vec<u8>, &'static str> {
        let sender_bytes = hex::decode(&self.sender).map_err(|_| "sender is not valid hex")?;
        let recipient_bytes =
            hex::decode(&self.recipient).map_err(|_| "recipient is not valid hex")?;
        if sender_bytes.len() != 32 {
            return Err("sender must be a 32-byte pubkey");
        }
        if recipient_bytes.len() != 32 {
            return Err("recipient must be a 32-byte pubkey");
        }
        let mut msg = Vec::with_capacity(ESCROW_RELEASE_DOMAIN.len() + 80);
        msg.extend_from_slice(ESCROW_RELEASE_DOMAIN);
        msg.extend_from_slice(&sender_bytes);
        msg.extend_from_slice(&recipient_bytes);
        msg.extend_from_slice(&self.amount.to_be_bytes());
        msg.extend_from_slice(&self.timeout.to_be_bytes());
        Ok(msg)
    }

    /// Release funds to the recipient.
    ///
    /// Requires the caller to prove they are the recipient by supplying
    /// their Ed25519 public key and a valid signature over
    /// [`Self::release_message`].
    ///
    /// # Errors
    ///
    /// - `"escrow is not in locked state"` — already released / refunded.
    /// - `"recipient is not valid hex"` / `"recipient must be a 32-byte pubkey"`
    ///   — the escrow's recipient field is malformed.
    /// - `"caller is not the recipient"` — `caller_pubkey` does not match
    ///   the escrow's recipient.
    /// - `"invalid caller pubkey"` — the bytes do not form a valid
    ///   Ed25519 verifying key.
    /// - `"invalid signature"` — the signature does not verify against
    ///   the canonical message.
    pub fn release(
        &mut self,
        caller_pubkey: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), &'static str> {
        if self.state != EscrowState::Locked {
            return Err("escrow is not in locked state");
        }
        // Check caller identity matches recipient BEFORE crypto to keep
        // the cheap check ordered first.
        let recipient_bytes =
            hex::decode(&self.recipient).map_err(|_| "recipient is not valid hex")?;
        if recipient_bytes.len() != 32 {
            return Err("recipient must be a 32-byte pubkey");
        }
        if recipient_bytes.as_slice() != caller_pubkey.as_slice() {
            return Err("caller is not the recipient");
        }
        // Verify signature.
        let msg = self.release_message()?;
        let vk = VerifyingKey::from_bytes(caller_pubkey).map_err(|_| "invalid caller pubkey")?;
        let sig = Signature::from_bytes(signature);
        vk.verify(&msg, &sig).map_err(|_| "invalid signature")?;
        self.state = EscrowState::Released;
        Ok(())
    }

    /// Refund funds to the sender (only after timeout).
    ///
    /// **Note**: authentication for refund is introduced in the next
    /// commit (010) per the Wave 1 plan. This signature is intentionally
    /// preserved in commit 009 to isolate the release-auth change.
    pub fn refund(&mut self, current_time: u64) -> Result<(), &'static str> {
        if self.state != EscrowState::Locked {
            return Err("escrow is not in locked state");
        }
        if current_time < self.timeout {
            return Err("timeout has not elapsed");
        }
        self.state = EscrowState::Refunded;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn mk_keypair() -> (SigningKey, [u8; 32], String) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_bytes = sk.verifying_key().to_bytes();
        let pk_hex = hex::encode(pk_bytes);
        (sk, pk_bytes, pk_hex)
    }

    #[test]
    fn test_escrow_release_with_valid_signature() {
        let (sender_sk, _, sender_hex) = mk_keypair();
        let (recipient_sk, recipient_pk, recipient_hex) = mk_keypair();
        let _ = sender_sk;
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        assert_eq!(escrow.state, EscrowState::Locked);

        let msg = escrow.release_message().unwrap();
        let signature = recipient_sk.sign(&msg).to_bytes();

        escrow.release(&recipient_pk, &signature).unwrap();
        assert_eq!(escrow.state, EscrowState::Released);
    }

    #[test]
    fn test_escrow_refund_after_timeout() {
        let (_, _, sender_hex) = mk_keypair();
        let (_, _, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        assert!(escrow.refund(500).is_err());
        assert!(escrow.refund(1000).is_ok());
        assert_eq!(escrow.state, EscrowState::Refunded);
    }

    #[test]
    fn test_escrow_double_release_rejected() {
        let (_, _, sender_hex) = mk_keypair();
        let (recipient_sk, recipient_pk, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        let msg = escrow.release_message().unwrap();
        let signature = recipient_sk.sign(&msg).to_bytes();

        escrow.release(&recipient_pk, &signature).unwrap();
        // Second release must fail because state is no longer Locked.
        let err = escrow.release(&recipient_pk, &signature).unwrap_err();
        assert_eq!(err, "escrow is not in locked state");
    }

    // ========================================================================
    // Adversarial tests for CRIT-013 (escrow release has no authentication)
    // ========================================================================

    #[test]
    fn test_escrow_release_rejects_unauthorized_caller() {
        // Escrow: Alice → Bob. Eve tries to release using HER OWN key.
        // Must fail; escrow state must remain Locked.
        let (_, _, alice_hex) = mk_keypair();
        let (_, _, bob_hex) = mk_keypair();
        let (eve_sk, eve_pk, _) = mk_keypair();
        let mut escrow = Escrow::new(alice_hex, bob_hex, 1_000_000, 1000);

        let msg = escrow.release_message().unwrap();
        let eve_sig = eve_sk.sign(&msg).to_bytes();

        let err = escrow.release(&eve_pk, &eve_sig).unwrap_err();
        assert_eq!(err, "caller is not the recipient");
        assert_eq!(escrow.state, EscrowState::Locked);
    }

    #[test]
    fn test_escrow_release_rejects_recipient_key_with_wrong_signature() {
        // Caller IS the recipient, but signature is invalid (signed
        // different bytes). Must fail.
        let (_, _, alice_hex) = mk_keypair();
        let (bob_sk, bob_pk, bob_hex) = mk_keypair();
        let mut escrow = Escrow::new(alice_hex, bob_hex, 1_000_000, 1000);

        // Bob signs the wrong message
        let wrong_msg = b"not the canonical release message";
        let bad_sig = bob_sk.sign(wrong_msg).to_bytes();

        let err = escrow.release(&bob_pk, &bad_sig).unwrap_err();
        assert_eq!(err, "invalid signature");
        assert_eq!(escrow.state, EscrowState::Locked);
    }

    #[test]
    fn test_escrow_release_rejects_zero_signature() {
        let (_, _, alice_hex) = mk_keypair();
        let (_, bob_pk, bob_hex) = mk_keypair();
        let mut escrow = Escrow::new(alice_hex, bob_hex, 1_000_000, 1000);

        let err = escrow.release(&bob_pk, &[0u8; 64]).unwrap_err();
        assert_eq!(err, "invalid signature");
        assert_eq!(escrow.state, EscrowState::Locked);
    }

    #[test]
    fn test_escrow_release_signature_is_escrow_bound() {
        // A signature generated for escrow A cannot be reused to
        // release escrow B, even with the same recipient.
        let (_, _, alice_hex) = mk_keypair();
        let (bob_sk, bob_pk, bob_hex) = mk_keypair();

        let mut escrow_a = Escrow::new(alice_hex.clone(), bob_hex.clone(), 1_000_000, 1000);
        // Second escrow differs only by amount.
        let mut escrow_b = Escrow::new(alice_hex, bob_hex, 2_000_000, 1000);

        let msg_a = escrow_a.release_message().unwrap();
        let sig_for_a = bob_sk.sign(&msg_a).to_bytes();

        // Signature from A is rejected on B.
        let err = escrow_b.release(&bob_pk, &sig_for_a).unwrap_err();
        assert_eq!(err, "invalid signature");
        assert_eq!(escrow_b.state, EscrowState::Locked);

        // But still valid on A.
        escrow_a.release(&bob_pk, &sig_for_a).unwrap();
        assert_eq!(escrow_a.state, EscrowState::Released);
    }

    #[test]
    fn test_escrow_release_rejects_non_hex_recipient() {
        // Defensive: a malformed Escrow (recipient is not valid hex)
        // must not release, regardless of the signature provided.
        let (sender_sk, sender_pk, sender_hex) = mk_keypair();
        let _ = sender_sk;
        let mut escrow = Escrow::new(sender_hex, "not-hex-at-all".into(), 1_000_000, 1000);
        let err = escrow.release(&sender_pk, &[0u8; 64]).unwrap_err();
        assert_eq!(err, "recipient is not valid hex");
        assert_eq!(escrow.state, EscrowState::Locked);
    }
}
