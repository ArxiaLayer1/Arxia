//! Escrow contract for Arxia.
//!
//! # Reentrancy safety (LOW-012, commit 083)
//!
//! Both [`Escrow::release`] and [`Escrow::refund`] follow a
//! **check-effects-no-interaction** pattern:
//!
//! 1. **Check** — first line of each method tests
//!    `self.state != EscrowState::Locked` and returns an error
//!    if the escrow is no longer in the `Locked` state.
//! 2. **Effects** — only after all signature/timeout checks
//!    succeed does the state transition (`Released` /
//!    `Refunded`).
//! 3. **No interaction** — neither method calls into another
//!    contract or external function during the protected
//!    region. There is no callback surface and no
//!    cross-contract `transfer`-like primitive in the Arxia
//!    `escrow` model (settlement is performed by the runtime
//!    based on the resulting state, not by escrow itself).
//!
//! Consequence: a re-entrant call to `release` (or `refund`)
//! from any path — including a future contract that observes
//! the state transition — finds `self.state == Released` (or
//! `Refunded`) and rejects with the canonical
//! `"escrow is not in locked state"` error. The state-machine
//! transition is the reentrancy guard.
//!
//! Tests in this file include explicit reentrancy probes that
//! call `release` twice (and `refund` twice) on the same
//! escrow and verify the second call is rejected.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Domain-separation prefix for the Ed25519 signature that authorizes
/// [`Escrow::release`].
pub const ESCROW_RELEASE_DOMAIN: &[u8] = b"arxia-escrow-release-v1";

/// Domain-separation prefix for the Ed25519 signature that authorizes
/// [`Escrow::refund`]. Distinct from the release prefix so a signature
/// intended for one action cannot be replayed as the other.
pub const ESCROW_REFUND_DOMAIN: &[u8] = b"arxia-escrow-refund-v1";

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

    /// Internal helper: build the 80-byte identity suffix that both the
    /// release and refund canonical messages share (sender + recipient +
    /// amount + timeout).
    fn identity_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let sender_bytes = hex::decode(&self.sender).map_err(|_| "sender is not valid hex")?;
        let recipient_bytes =
            hex::decode(&self.recipient).map_err(|_| "recipient is not valid hex")?;
        if sender_bytes.len() != 32 {
            return Err("sender must be a 32-byte pubkey");
        }
        if recipient_bytes.len() != 32 {
            return Err("recipient must be a 32-byte pubkey");
        }
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(&sender_bytes);
        buf.extend_from_slice(&recipient_bytes);
        buf.extend_from_slice(&self.amount.to_be_bytes());
        buf.extend_from_slice(&self.timeout.to_be_bytes());
        Ok(buf)
    }

    /// Canonical release-authorization message. See commit 009 doc for
    /// full layout (23 + 80 = 103 bytes).
    pub fn release_message(&self) -> Result<Vec<u8>, &'static str> {
        let mut msg = Vec::with_capacity(ESCROW_RELEASE_DOMAIN.len() + 80);
        msg.extend_from_slice(ESCROW_RELEASE_DOMAIN);
        msg.extend_from_slice(&self.identity_bytes()?);
        Ok(msg)
    }

    /// Canonical refund-authorization message.
    ///
    /// Layout (total = 22 + 32 + 32 + 8 + 8 = 102 bytes):
    ///
    /// - `ESCROW_REFUND_DOMAIN` (22 bytes)
    /// - sender pubkey         (32 bytes, raw)
    /// - recipient pubkey      (32 bytes, raw)
    /// - amount                (8 bytes, big-endian)
    /// - timeout               (8 bytes, big-endian)
    pub fn refund_message(&self) -> Result<Vec<u8>, &'static str> {
        let mut msg = Vec::with_capacity(ESCROW_REFUND_DOMAIN.len() + 80);
        msg.extend_from_slice(ESCROW_REFUND_DOMAIN);
        msg.extend_from_slice(&self.identity_bytes()?);
        Ok(msg)
    }

    /// Release funds to the recipient (commit 009 contract).
    pub fn release(
        &mut self,
        caller_pubkey: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), &'static str> {
        if self.state != EscrowState::Locked {
            return Err("escrow is not in locked state");
        }
        let recipient_bytes =
            hex::decode(&self.recipient).map_err(|_| "recipient is not valid hex")?;
        if recipient_bytes.len() != 32 {
            return Err("recipient must be a 32-byte pubkey");
        }
        if recipient_bytes.as_slice() != caller_pubkey.as_slice() {
            return Err("caller is not the recipient");
        }
        let msg = self.release_message()?;
        let vk = VerifyingKey::from_bytes(caller_pubkey).map_err(|_| "invalid caller pubkey")?;
        let sig = Signature::from_bytes(signature);
        vk.verify(&msg, &sig).map_err(|_| "invalid signature")?;
        self.state = EscrowState::Released;
        Ok(())
    }

    /// Refund funds to the sender.
    ///
    /// Requires BOTH:
    /// 1. `current_time >= self.timeout` (the escrow's refund window is open).
    /// 2. `caller_pubkey` matches the sender AND a valid Ed25519
    ///    signature by that key over [`Self::refund_message`].
    ///
    /// # Errors
    ///
    /// - `"escrow is not in locked state"` — already released/refunded.
    /// - `"timeout has not elapsed"` — refund window still closed.
    /// - `"sender is not valid hex"` / `"sender must be a 32-byte pubkey"`
    /// - `"caller is not the sender"` — `caller_pubkey` does not match
    ///   the escrow's sender.
    /// - `"invalid caller pubkey"` — bytes are not a valid Ed25519 key.
    /// - `"invalid signature"` — signature does not verify.
    pub fn refund(
        &mut self,
        caller_pubkey: &[u8; 32],
        signature: &[u8; 64],
        current_time: u64,
    ) -> Result<(), &'static str> {
        if self.state != EscrowState::Locked {
            return Err("escrow is not in locked state");
        }
        if current_time < self.timeout {
            return Err("timeout has not elapsed");
        }
        let sender_bytes = hex::decode(&self.sender).map_err(|_| "sender is not valid hex")?;
        if sender_bytes.len() != 32 {
            return Err("sender must be a 32-byte pubkey");
        }
        if sender_bytes.as_slice() != caller_pubkey.as_slice() {
            return Err("caller is not the sender");
        }
        let msg = self.refund_message()?;
        let vk = VerifyingKey::from_bytes(caller_pubkey).map_err(|_| "invalid caller pubkey")?;
        let sig = Signature::from_bytes(signature);
        vk.verify(&msg, &sig).map_err(|_| "invalid signature")?;
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
        let (_, _, sender_hex) = mk_keypair();
        let (recipient_sk, recipient_pk, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        let msg = escrow.release_message().unwrap();
        let signature = recipient_sk.sign(&msg).to_bytes();
        escrow.release(&recipient_pk, &signature).unwrap();
        assert_eq!(escrow.state, EscrowState::Released);
    }

    #[test]
    fn test_escrow_refund_happy_path() {
        let (sender_sk, sender_pk, sender_hex) = mk_keypair();
        let (_, _, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        let msg = escrow.refund_message().unwrap();
        let signature = sender_sk.sign(&msg).to_bytes();

        // Before timeout: rejected
        assert_eq!(
            escrow.refund(&sender_pk, &signature, 500).unwrap_err(),
            "timeout has not elapsed"
        );
        assert_eq!(escrow.state, EscrowState::Locked);

        // At timeout: allowed
        escrow.refund(&sender_pk, &signature, 1000).unwrap();
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
        let err = escrow.release(&recipient_pk, &signature).unwrap_err();
        assert_eq!(err, "escrow is not in locked state");
    }

    #[test]
    fn test_escrow_release_rejects_unauthorized_caller() {
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
        let (_, _, alice_hex) = mk_keypair();
        let (bob_sk, bob_pk, bob_hex) = mk_keypair();
        let mut escrow = Escrow::new(alice_hex, bob_hex, 1_000_000, 1000);
        let bad_sig = bob_sk.sign(b"not the canonical release message").to_bytes();
        let err = escrow.release(&bob_pk, &bad_sig).unwrap_err();
        assert_eq!(err, "invalid signature");
    }

    #[test]
    fn test_escrow_release_rejects_zero_signature() {
        let (_, _, alice_hex) = mk_keypair();
        let (_, bob_pk, bob_hex) = mk_keypair();
        let mut escrow = Escrow::new(alice_hex, bob_hex, 1_000_000, 1000);
        let err = escrow.release(&bob_pk, &[0u8; 64]).unwrap_err();
        assert_eq!(err, "invalid signature");
    }

    #[test]
    fn test_escrow_release_signature_is_escrow_bound() {
        let (_, _, alice_hex) = mk_keypair();
        let (bob_sk, bob_pk, bob_hex) = mk_keypair();
        let mut escrow_a = Escrow::new(alice_hex.clone(), bob_hex.clone(), 1_000_000, 1000);
        let mut escrow_b = Escrow::new(alice_hex, bob_hex, 2_000_000, 1000);
        let sig_for_a = bob_sk.sign(&escrow_a.release_message().unwrap()).to_bytes();
        assert_eq!(
            escrow_b.release(&bob_pk, &sig_for_a).unwrap_err(),
            "invalid signature"
        );
        escrow_a.release(&bob_pk, &sig_for_a).unwrap();
    }

    #[test]
    fn test_escrow_release_rejects_non_hex_recipient() {
        let (sender_sk, sender_pk, sender_hex) = mk_keypair();
        let _ = sender_sk;
        let mut escrow = Escrow::new(sender_hex, "not-hex-at-all".into(), 1_000_000, 1000);
        let err = escrow.release(&sender_pk, &[0u8; 64]).unwrap_err();
        assert_eq!(err, "recipient is not valid hex");
    }

    // ========================================================================
    // Adversarial tests for CRIT-014 (escrow refund has no authentication)
    // ========================================================================

    #[test]
    fn test_escrow_refund_rejects_non_sender() {
        // Escrow: Alice (sender) → Bob (recipient). Carol tries to
        // refund with her own key after the timeout. Must fail; state
        // must remain Locked.
        let (_, _, alice_hex) = mk_keypair();
        let (_, _, bob_hex) = mk_keypair();
        let (carol_sk, carol_pk, _) = mk_keypair();
        let mut escrow = Escrow::new(alice_hex, bob_hex, 1_000_000, 1000);
        let msg = escrow.refund_message().unwrap();
        let carol_sig = carol_sk.sign(&msg).to_bytes();
        let err = escrow.refund(&carol_pk, &carol_sig, 1500).unwrap_err();
        assert_eq!(err, "caller is not the sender");
        assert_eq!(escrow.state, EscrowState::Locked);
    }

    #[test]
    fn test_escrow_refund_rejects_recipient_attempting_to_refund() {
        // Specifically test that the RECIPIENT cannot refund (Bob
        // cannot return his own expected funds to Alice to block the
        // release path). Refund is strictly sender's prerogative.
        let (_, _, alice_hex) = mk_keypair();
        let (bob_sk, bob_pk, bob_hex) = mk_keypair();
        let mut escrow = Escrow::new(alice_hex, bob_hex, 1_000_000, 1000);
        let msg = escrow.refund_message().unwrap();
        let bob_sig = bob_sk.sign(&msg).to_bytes();
        let err = escrow.refund(&bob_pk, &bob_sig, 1500).unwrap_err();
        assert_eq!(err, "caller is not the sender");
        assert_eq!(escrow.state, EscrowState::Locked);
    }

    #[test]
    fn test_escrow_refund_rejects_wrong_signature_even_from_sender() {
        let (sender_sk, sender_pk, sender_hex) = mk_keypair();
        let (_, _, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        // Sender signs the WRONG message.
        let bad_sig = sender_sk.sign(b"not the refund message").to_bytes();
        let err = escrow.refund(&sender_pk, &bad_sig, 1500).unwrap_err();
        assert_eq!(err, "invalid signature");
        assert_eq!(escrow.state, EscrowState::Locked);
    }

    #[test]
    fn test_escrow_refund_rejects_before_timeout_regardless_of_valid_signature() {
        // Timeout check runs BEFORE auth check; even a valid sender
        // signature cannot refund before timeout.
        let (sender_sk, sender_pk, sender_hex) = mk_keypair();
        let (_, _, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        let msg = escrow.refund_message().unwrap();
        let signature = sender_sk.sign(&msg).to_bytes();
        let err = escrow.refund(&sender_pk, &signature, 999).unwrap_err();
        assert_eq!(err, "timeout has not elapsed");
        assert_eq!(escrow.state, EscrowState::Locked);
    }

    #[test]
    fn test_escrow_refund_signature_is_escrow_bound() {
        // Sender's signature for escrow A cannot refund escrow B
        // (differing amount, same parties / timeout).
        let (alice_sk, alice_pk, alice_hex) = mk_keypair();
        let (_, _, bob_hex) = mk_keypair();
        let mut escrow_a = Escrow::new(alice_hex.clone(), bob_hex.clone(), 1_000_000, 1000);
        let mut escrow_b = Escrow::new(alice_hex, bob_hex, 2_000_000, 1000);
        let sig_for_a = alice_sk
            .sign(&escrow_a.refund_message().unwrap())
            .to_bytes();
        assert_eq!(
            escrow_b.refund(&alice_pk, &sig_for_a, 1500).unwrap_err(),
            "invalid signature"
        );
        escrow_a.refund(&alice_pk, &sig_for_a, 1500).unwrap();
    }

    #[test]
    fn test_escrow_refund_and_release_domains_do_not_cross() {
        // A signature valid on release_message must NOT be accepted by
        // refund (and vice versa). The distinct domain prefixes
        // (release-v1 vs refund-v1) enforce this.
        let (alice_sk, alice_pk, alice_hex) = mk_keypair();
        let (bob_sk, bob_pk, bob_hex) = mk_keypair();
        let mut escrow = Escrow::new(alice_hex, bob_hex, 1_000_000, 1000);

        // Alice signs her refund_message (she is the sender).
        let alice_refund_sig = alice_sk.sign(&escrow.refund_message().unwrap()).to_bytes();
        // Bob signs his release_message (he is the recipient).
        let bob_release_sig = bob_sk.sign(&escrow.release_message().unwrap()).to_bytes();

        // Alice's refund sig must NOT release.
        assert_eq!(
            escrow.release(&alice_pk, &alice_refund_sig).unwrap_err(),
            "caller is not the recipient"
        );
        // Bob's release sig must NOT refund.
        assert_eq!(
            escrow.refund(&bob_pk, &bob_release_sig, 1500).unwrap_err(),
            "caller is not the sender"
        );

        // Swap so caller matches the respective role but sig is for
        // the wrong action: release with a valid-looking refund-sig.
        // (Alice cannot refund AND cannot release; only Bob can release.)
        // Forge: Bob signs the refund message using his key. Since caller
        // must equal the sender for refund, bob != alice → "caller is
        // not the sender" still fires.
        let bob_refund_sig = bob_sk.sign(&escrow.refund_message().unwrap()).to_bytes();
        assert_eq!(
            escrow.refund(&bob_pk, &bob_refund_sig, 1500).unwrap_err(),
            "caller is not the sender"
        );

        // The valuable test: does the domain prefix actually matter?
        // Alice signs the RELEASE message (she has no business doing
        // so), then attempts to refund with it. Caller matches sender,
        // but signature is over release_message. Must fail on signature
        // verification (domain mismatch).
        let alice_release_sig = alice_sk.sign(&escrow.release_message().unwrap()).to_bytes();
        assert_eq!(
            escrow
                .refund(&alice_pk, &alice_release_sig, 1500)
                .unwrap_err(),
            "invalid signature"
        );
        assert_eq!(escrow.state, EscrowState::Locked);
    }

    // ============================================================
    // LOW-012 (commit 083) — reentrancy safety probes.
    //
    // The state-machine pattern (Locked → Released/Refunded) is
    // the reentrancy guard. A second call to release/refund on
    // the same escrow must be rejected with "escrow is not in
    // locked state".
    // ============================================================

    #[test]
    fn test_release_twice_rejects_second_call() {
        // PRIMARY LOW-012 PIN: a second `release` call returns
        // "escrow is not in locked state" because the first
        // call transitioned state to Released. State-machine
        // is the reentrancy guard.
        let (_, _, sender_hex) = mk_keypair();
        let (recipient_sk, recipient_pk, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        let msg = escrow.release_message().unwrap();
        let signature = recipient_sk.sign(&msg).to_bytes();
        escrow.release(&recipient_pk, &signature).unwrap();
        assert_eq!(escrow.state, EscrowState::Released);
        // Second call: must reject.
        let err = escrow
            .release(&recipient_pk, &signature)
            .expect_err("second release must be rejected");
        assert_eq!(err, "escrow is not in locked state");
        // State unchanged.
        assert_eq!(escrow.state, EscrowState::Released);
    }

    #[test]
    fn test_refund_twice_rejects_second_call() {
        let (sender_sk, sender_pk, sender_hex) = mk_keypair();
        let (_, _, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        let msg = escrow.refund_message().unwrap();
        let signature = sender_sk.sign(&msg).to_bytes();
        escrow.refund(&sender_pk, &signature, 1500).unwrap();
        assert_eq!(escrow.state, EscrowState::Refunded);
        // Second call: must reject.
        let err = escrow
            .refund(&sender_pk, &signature, 1500)
            .expect_err("second refund must be rejected");
        assert_eq!(err, "escrow is not in locked state");
        assert_eq!(escrow.state, EscrowState::Refunded);
    }

    #[test]
    fn test_release_after_refund_rejected() {
        // Once refunded, the escrow cannot be released either —
        // the Locked → terminal transition is one-shot.
        let (sender_sk, sender_pk, sender_hex) = mk_keypair();
        let (recipient_sk, recipient_pk, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        // Refund first.
        let refund_msg = escrow.refund_message().unwrap();
        let refund_sig = sender_sk.sign(&refund_msg).to_bytes();
        escrow.refund(&sender_pk, &refund_sig, 1500).unwrap();
        assert_eq!(escrow.state, EscrowState::Refunded);
        // Try to release.
        let release_msg = escrow.release_message().unwrap();
        let release_sig = recipient_sk.sign(&release_msg).to_bytes();
        let err = escrow
            .release(&recipient_pk, &release_sig)
            .expect_err("release after refund must be rejected");
        assert_eq!(err, "escrow is not in locked state");
    }

    #[test]
    fn test_refund_after_release_rejected() {
        // Symmetric: once released, refund is also blocked.
        let (sender_sk, sender_pk, sender_hex) = mk_keypair();
        let (recipient_sk, recipient_pk, recipient_hex) = mk_keypair();
        let mut escrow = Escrow::new(sender_hex, recipient_hex, 1_000_000, 1000);
        let release_msg = escrow.release_message().unwrap();
        let release_sig = recipient_sk.sign(&release_msg).to_bytes();
        escrow.release(&recipient_pk, &release_sig).unwrap();
        let refund_msg = escrow.refund_message().unwrap();
        let refund_sig = sender_sk.sign(&refund_msg).to_bytes();
        let err = escrow
            .refund(&sender_pk, &refund_sig, 1500)
            .expect_err("refund after release must be rejected");
        assert_eq!(err, "escrow is not in locked state");
    }
}
