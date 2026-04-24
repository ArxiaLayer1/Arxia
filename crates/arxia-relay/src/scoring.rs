//! Relay node reputation scoring.

use crate::receipt::{RelayReceipt, RelayReceiptError};

/// Reputation score for a relay node.
#[derive(Debug, Clone)]
pub struct RelayScore {
    /// Relay node public key (64 lowercase hex chars = 32 raw bytes).
    /// This MUST match the `relay_id` on every receipt credited here;
    /// see [`RelayScore::record_success`].
    pub relay_id: String,
    /// Current score (higher is better).
    pub score: i64,
    /// Total messages successfully relayed.
    pub messages_relayed: u64,
    /// Total messages that failed or were dropped.
    pub messages_failed: u64,
}

impl RelayScore {
    /// Create a new relay score with default values.
    pub fn new(relay_id: String) -> Self {
        Self {
            relay_id,
            score: 100,
            messages_relayed: 0,
            messages_failed: 0,
        }
    }

    /// Record a successful relay, backed by a signed [`RelayReceipt`].
    ///
    /// This is the only way to credit a successful relay: the receipt's
    /// Ed25519 signature is verified against the pubkey declared in
    /// its `relay_id`, and that pubkey must match the scored relay's
    /// `relay_id`. Either failure leaves the score unchanged and
    /// returns an error.
    ///
    /// This closes CRIT-004 (forged-receipt reputation inflation): a
    /// struct literal `RelayReceipt { signature: vec![0; 64], .. }`
    /// can no longer bump the score because its signature fails to
    /// verify under any pubkey.
    pub fn record_success(&mut self, receipt: &RelayReceipt) -> Result<(), RelayReceiptError> {
        if receipt.relay_id != self.relay_id {
            return Err(RelayReceiptError::WrongRelayId);
        }
        receipt.verify()?;
        self.messages_relayed += 1;
        self.score += 1;
        Ok(())
    }

    /// Record a failed relay attempt. Does not require a receipt —
    /// failures are observed locally (e.g. the message never reached
    /// the next hop) rather than proven by a counter-signature.
    pub fn record_failure(&mut self) {
        self.messages_failed += 1;
        self.score -= 5;
    }

    /// Apply slashing penalty for proven misbehavior.
    pub fn slash(&mut self, penalty: i64) {
        self.score -= penalty;
    }

    /// Whether this relay is in good standing.
    pub fn is_trusted(&self) -> bool {
        self.score > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::{generate_keypair, sign};

    /// Mint a correctly-signed receipt for `relay_pk`, plus the
    /// hex-encoded pubkey string for putting on a matching
    /// [`RelayScore`].
    fn signed_receipt_for(
        sk: &ed25519_dalek::SigningKey,
        relay_pk: &[u8; 32],
        timestamp: u64,
        hop_count: u8,
    ) -> (RelayReceipt, String) {
        let relay_id_hex = hex::encode(relay_pk);
        let mut r = RelayReceipt {
            relay_id: relay_id_hex.clone(),
            message_hash: hex::encode([0x22u8; 32]),
            timestamp,
            signature: Vec::new(),
            hop_count,
        };
        let msg = r.canonical_message().unwrap();
        r.signature = sign(sk, &msg).to_vec();
        (r, relay_id_hex)
    }

    #[test]
    fn test_relay_score_new_starts_at_100() {
        let score = RelayScore::new(hex::encode([0u8; 32]));
        assert_eq!(score.score, 100);
        assert!(score.is_trusted());
    }

    #[test]
    fn test_relay_score_success_with_valid_receipt_increments_score() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let (receipt, relay_id) = signed_receipt_for(&sk, &pk, 1, 3);
        let mut score = RelayScore::new(relay_id);
        score
            .record_success(&receipt)
            .expect("valid receipt must succeed");
        assert_eq!(score.score, 101);
        assert_eq!(score.messages_relayed, 1);
    }

    #[test]
    fn test_relay_score_failure() {
        let mut score = RelayScore::new(hex::encode([0u8; 32]));
        score.record_failure();
        assert_eq!(score.score, 95);
        assert_eq!(score.messages_failed, 1);
    }

    #[test]
    fn test_relay_score_slashing() {
        let mut score = RelayScore::new(hex::encode([0u8; 32]));
        score.slash(150);
        assert_eq!(score.score, -50);
        assert!(!score.is_trusted());
    }

    // ---- CRIT-004 adversarial regression guards ----

    #[test]
    fn test_relay_score_rejects_forged_receipt_zero_signature() {
        // The literal exploit from PHASE1 CRIT-004: build a
        // `RelayReceipt` with signature: vec![0; 64] and hand it to
        // record_success. The score MUST be unchanged and the call
        // MUST return Err.
        let (_sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let forged = RelayReceipt {
            relay_id: hex::encode(pk),
            message_hash: hex::encode([0xAAu8; 32]),
            timestamp: 42,
            signature: vec![0u8; 64],
            hop_count: 1,
        };
        let mut score = RelayScore::new(hex::encode(pk));
        let before = (score.score, score.messages_relayed);
        let res = score.record_success(&forged);
        assert_eq!(
            res,
            Err(RelayReceiptError::SignatureInvalid),
            "forged receipt MUST be rejected; CRIT-004 regression guard"
        );
        assert_eq!(
            (score.score, score.messages_relayed),
            before,
            "score state MUST be unchanged on rejection"
        );
    }

    #[test]
    fn test_relay_score_rejects_receipt_with_tampered_timestamp() {
        // Valid signature for (ts=100), but receipt says ts=200.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let (mut receipt, relay_id) = signed_receipt_for(&sk, &pk, 100, 1);
        receipt.timestamp = 200;
        let mut score = RelayScore::new(relay_id);
        assert_eq!(
            score.record_success(&receipt),
            Err(RelayReceiptError::SignatureInvalid)
        );
        assert_eq!(score.score, 100);
        assert_eq!(score.messages_relayed, 0);
    }

    #[test]
    fn test_relay_score_rejects_receipt_for_other_relay() {
        // Attacker mints a valid receipt for THEIR OWN relay
        // (attacker_pk) and tries to have it credited to
        // victim_pk's score. Identity mismatch must be caught even
        // before signature verification succeeds.
        let (sk_a, vk_a) = generate_keypair();
        let pk_a = vk_a.to_bytes();
        let (_, vk_v) = generate_keypair();
        let pk_v = vk_v.to_bytes();
        let (receipt, _) = signed_receipt_for(&sk_a, &pk_a, 1, 1);
        let mut victim_score = RelayScore::new(hex::encode(pk_v));
        assert_eq!(
            victim_score.record_success(&receipt),
            Err(RelayReceiptError::WrongRelayId)
        );
        assert_eq!(victim_score.score, 100);
    }

    #[test]
    fn test_relay_score_record_success_is_idempotent_in_failure_mode() {
        // Forged receipt submitted N times MUST still leave the score
        // untouched. This is adjacent to the separate CRIT-005
        // duplicate-dedup concern but also validates that a rejected
        // receipt never partially mutates state.
        let (_, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let forged = RelayReceipt {
            relay_id: hex::encode(pk),
            message_hash: hex::encode([0xAAu8; 32]),
            timestamp: 42,
            signature: vec![0u8; 64],
            hop_count: 1,
        };
        let mut score = RelayScore::new(hex::encode(pk));
        for _ in 0..100 {
            let _ = score.record_success(&forged);
        }
        assert_eq!(
            score.score, 100,
            "100 forged submissions must not bump score"
        );
        assert_eq!(score.messages_relayed, 0);
    }

    #[test]
    fn test_relay_score_rejects_malformed_signature_length() {
        let (_, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let forged = RelayReceipt {
            relay_id: hex::encode(pk),
            message_hash: hex::encode([0xAAu8; 32]),
            timestamp: 42,
            signature: vec![0u8; 32], // half the required length
            hop_count: 1,
        };
        let mut score = RelayScore::new(hex::encode(pk));
        assert_eq!(
            score.record_success(&forged),
            Err(RelayReceiptError::InvalidSignatureLength)
        );
    }
}
