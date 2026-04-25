//! Relay node reputation scoring.

use std::collections::HashSet;

use crate::receipt::{RelayReceipt, RelayReceiptError};
use crate::slashing::{SlashingError, SlashingProof};

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
    /// Set of 32-byte `message_hash` values that have already been
    /// credited to this score. Populated by
    /// [`RelayScore::record_success`]; closes CRIT-005
    /// (duplicate-receipt inflation).
    ///
    /// NOT `pub` — external code MUST NOT reach in and clear this
    /// set, because doing so would reopen the CRIT-005 hole.
    /// Storage grows monotonically with distinct relayed messages; a
    /// fixed upper bound / LRU eviction policy is a separate concern
    /// tracked as CRIT-011.
    credited_messages: HashSet<[u8; 32]>,
}

impl RelayScore {
    /// Create a new relay score with default values.
    pub fn new(relay_id: String) -> Self {
        Self {
            relay_id,
            score: 100,
            messages_relayed: 0,
            messages_failed: 0,
            credited_messages: HashSet::new(),
        }
    }

    /// Record a successful relay, backed by a signed [`RelayReceipt`].
    ///
    /// Gates applied, in order, before any state mutation:
    ///
    /// 1. **Identity gate** — `receipt.relay_id` must match this
    ///    score's `relay_id`, else [`RelayReceiptError::WrongRelayId`].
    /// 2. **Authenticity gate** — `receipt.verify()` must succeed,
    ///    else the variant it returns. Closes CRIT-004.
    /// 3. **Dedup gate** — the `message_hash` must not already have
    ///    been credited to this score, else
    ///    [`RelayReceiptError::DuplicateReceipt`]. Closes CRIT-005:
    ///    replaying the same authentic receipt (or a same-message
    ///    receipt with a different timestamp / hop_count) now fails.
    ///
    /// On any `Err`, the score fields (`score`, `messages_relayed`,
    /// `credited_messages`) are NOT mutated.
    pub fn record_success(&mut self, receipt: &RelayReceipt) -> Result<(), RelayReceiptError> {
        if receipt.relay_id != self.relay_id {
            return Err(RelayReceiptError::WrongRelayId);
        }
        receipt.verify()?;
        // Decode once (verify() has already validated the format), then
        // consult the dedup set. Using [u8; 32] as the key normalises
        // hex casing and lets us reject byte-identical replays even if
        // the attacker re-serialises the message_hash differently.
        let msg_hash_bytes: [u8; 32] = hex::decode(&receipt.message_hash)
            .map_err(|_| RelayReceiptError::InvalidMessageHash)?
            .as_slice()
            .try_into()
            .map_err(|_| RelayReceiptError::InvalidMessageHash)?;
        if !self.credited_messages.insert(msg_hash_bytes) {
            return Err(RelayReceiptError::DuplicateReceipt);
        }
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

    /// Apply a slashing penalty for proven misbehavior.
    ///
    /// Gates applied, in order:
    ///
    /// 1. `penalty >= 0` — slashing cannot gift score.
    /// 2. `proof.target_relay_id == self.relay_id` — the claim must
    ///    target this specific relay.
    /// 3. `proof.verify()` — the observer's Ed25519 signature must
    ///    authenticate the claim.
    ///
    /// On success the score decreases via `saturating_sub`, so no
    /// penalty value (even `i64::MAX`) can wrap past `i64::MIN`.
    /// This closes CRIT-006 in two places: no caller can slash
    /// without a valid observer signature, and the arithmetic is
    /// no longer underflow-prone.
    ///
    /// See `crate::slashing` for the observer-registry limitation.
    pub fn slash(&mut self, penalty: i64, proof: &SlashingProof) -> Result<(), SlashingError> {
        if penalty < 0 {
            return Err(SlashingError::NegativePenalty);
        }
        if proof.target_relay_id != self.relay_id {
            return Err(SlashingError::TargetMismatch);
        }
        proof.verify()?;
        self.score = self.score.saturating_sub(penalty);
        Ok(())
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

    fn signed_slashing_proof(
        observer_sk: &ed25519_dalek::SigningKey,
        observer_pk: [u8; 32],
        target_relay_id: &str,
        reason: &str,
    ) -> SlashingProof {
        let mut p = SlashingProof {
            observer_pubkey: observer_pk,
            target_relay_id: target_relay_id.to_string(),
            reason: reason.to_string(),
            signature: Vec::new(),
        };
        let msg = p.canonical_message().unwrap();
        p.signature = sign(observer_sk, &msg).to_vec();
        p
    }

    #[test]
    fn test_relay_score_slashing_with_valid_proof_reduces_score() {
        let (observer_sk, observer_vk) = generate_keypair();
        let relay_id = hex::encode([0x77u8; 32]);
        let mut score = RelayScore::new(relay_id.clone());
        let proof = signed_slashing_proof(
            &observer_sk,
            observer_vk.to_bytes(),
            &relay_id,
            "double-signed receipt",
        );
        assert!(score.slash(150, &proof).is_ok());
        assert_eq!(score.score, -50);
        assert!(!score.is_trusted());
    }

    // ---- CRIT-006 adversarial regression guards ----

    #[test]
    fn test_slash_rejects_unsigned_proof() {
        // Zero-signature proof: literal CRIT-006 attack.
        let (_, observer_vk) = generate_keypair();
        let relay_id = hex::encode([0x77u8; 32]);
        let mut score = RelayScore::new(relay_id.clone());
        let before = score.score;
        let proof = SlashingProof {
            observer_pubkey: observer_vk.to_bytes(),
            target_relay_id: relay_id,
            reason: "unauth".to_string(),
            signature: vec![0u8; 64],
        };
        assert_eq!(
            score.slash(100, &proof),
            Err(SlashingError::SignatureInvalid)
        );
        assert_eq!(score.score, before);
    }

    #[test]
    fn test_slash_rejects_proof_for_wrong_target() {
        // Observer A signs a proof targeting relay X; caller tries
        // to apply it to relay Y's score.
        let (observer_sk, observer_vk) = generate_keypair();
        let target_relay_id = hex::encode([0x11u8; 32]);
        let other_relay_id = hex::encode([0x22u8; 32]);
        let proof =
            signed_slashing_proof(&observer_sk, observer_vk.to_bytes(), &target_relay_id, "r");
        let mut other_score = RelayScore::new(other_relay_id);
        assert_eq!(
            other_score.slash(100, &proof),
            Err(SlashingError::TargetMismatch)
        );
        assert_eq!(other_score.score, 100);
    }

    #[test]
    fn test_slash_rejects_negative_penalty() {
        // A negative penalty would be `saturating_sub(neg)` which
        // adds score — a gift dressed as a slash.
        let (observer_sk, observer_vk) = generate_keypair();
        let relay_id = hex::encode([0x77u8; 32]);
        let proof = signed_slashing_proof(&observer_sk, observer_vk.to_bytes(), &relay_id, "r");
        let mut score = RelayScore::new(relay_id);
        assert_eq!(
            score.slash(-50, &proof),
            Err(SlashingError::NegativePenalty)
        );
        assert_eq!(score.score, 100, "score unchanged on negative penalty");
    }

    #[test]
    fn test_slash_i64_max_penalty_does_not_wrap_to_positive() {
        // Key CRIT-006 arithmetic: pre-fix `self.score -= penalty`
        // with penalty == i64::MAX can wrap a near-zero score past
        // i64::MIN to a positive value. `saturating_sub` clamps to
        // i64::MIN instead — a large-negative score is still bad
        // news, but it is not "trusted".
        let (observer_sk, observer_vk) = generate_keypair();
        let relay_id = hex::encode([0x77u8; 32]);
        let proof = signed_slashing_proof(&observer_sk, observer_vk.to_bytes(), &relay_id, "r");
        let mut score = RelayScore::new(relay_id);
        score
            .slash(i64::MAX, &proof)
            .expect("max penalty should succeed via saturation");
        assert!(
            score.score < 0,
            "score after i64::MAX slash must be negative, got {}",
            score.score
        );
        assert!(!score.is_trusted());
    }

    #[test]
    fn test_slash_saturates_exactly_at_i64_min() {
        // Drive the score pre-emptively to a value where `slash(i64::MAX)`
        // would underflow past i64::MIN without saturation. Verify
        // the actual floor is i64::MIN, not a wrapped positive.
        let (observer_sk, observer_vk) = generate_keypair();
        let relay_id = hex::encode([0x77u8; 32]);
        let proof = signed_slashing_proof(&observer_sk, observer_vk.to_bytes(), &relay_id, "r");
        let mut score = RelayScore::new(relay_id);
        score.score = -100; // set below zero so MIN underflows cleanly
        score.slash(i64::MAX, &proof).unwrap();
        assert_eq!(
            score.score,
            i64::MIN,
            "saturating_sub must clamp to i64::MIN"
        );
    }

    #[test]
    fn test_slash_rejects_proof_signed_by_other_observer() {
        // Observer A signs a proof for relay X; caller tries to
        // pass it off as signed by observer B. The pubkey→signature
        // mismatch must be caught.
        let (sk_a, vk_a) = generate_keypair();
        let (_, vk_b) = generate_keypair();
        let relay_id = hex::encode([0x77u8; 32]);
        let mut proof = signed_slashing_proof(&sk_a, vk_a.to_bytes(), &relay_id, "r");
        proof.observer_pubkey = vk_b.to_bytes();
        let mut score = RelayScore::new(relay_id);
        assert_eq!(
            score.slash(100, &proof),
            Err(SlashingError::SignatureInvalid)
        );
        assert_eq!(score.score, 100);
    }

    #[test]
    fn test_slash_gate_order_negative_penalty_before_signature_check() {
        // A negative penalty on an UNSIGNED proof must still return
        // NegativePenalty, not SignatureInvalid — the cheap check
        // runs first so a caller with zero evidence gets crisp
        // feedback on the primary mistake.
        let (_, observer_vk) = generate_keypair();
        let relay_id = hex::encode([0x77u8; 32]);
        let mut score = RelayScore::new(relay_id.clone());
        let proof = SlashingProof {
            observer_pubkey: observer_vk.to_bytes(),
            target_relay_id: relay_id,
            reason: String::new(),
            signature: Vec::new(),
        };
        assert_eq!(score.slash(-1, &proof), Err(SlashingError::NegativePenalty),);
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
        // untouched. Validates that a rejected receipt (CRIT-004 gate)
        // never partially mutates state — distinct from the CRIT-005
        // dedup property tested below, which governs *accepted*
        // receipts.
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

    // ---- CRIT-005 adversarial regression guards (duplicate-receipt dedup) ----

    #[test]
    fn test_relay_score_ignores_duplicate_receipts() {
        // The literal CRIT-005 attack: submit the SAME authentic
        // receipt 100 times. Score must increment exactly once; the
        // remaining 99 submissions must return Err(DuplicateReceipt)
        // without mutating any counter.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let (receipt, relay_id) = signed_receipt_for(&sk, &pk, 77, 3);
        let mut score = RelayScore::new(relay_id);

        // First submission succeeds.
        assert_eq!(score.record_success(&receipt), Ok(()));
        assert_eq!(score.score, 101);
        assert_eq!(score.messages_relayed, 1);

        // Replays MUST be refused, score MUST stay pinned.
        for _ in 0..99 {
            assert_eq!(
                score.record_success(&receipt),
                Err(RelayReceiptError::DuplicateReceipt),
            );
        }
        assert_eq!(
            score.score, 101,
            "100 submissions of same authentic receipt must credit exactly once"
        );
        assert_eq!(score.messages_relayed, 1);
    }

    #[test]
    fn test_relay_score_dedup_ignores_timestamp_variance() {
        // Attacker signs TWO authentic receipts for the same
        // message_hash with different timestamps. Dedup must bind to
        // the message, not the (message, timestamp) tuple — otherwise
        // CRIT-005 is still exploitable by re-signing.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let (r1, relay_id) = signed_receipt_for(&sk, &pk, 100, 1);
        let (r2, _) = signed_receipt_for(&sk, &pk, 200, 1);
        assert_eq!(r1.message_hash, r2.message_hash, "helper uses fixed msg");

        let mut score = RelayScore::new(relay_id);
        assert_eq!(score.record_success(&r1), Ok(()));
        assert_eq!(
            score.record_success(&r2),
            Err(RelayReceiptError::DuplicateReceipt),
            "same message_hash at a later timestamp MUST NOT double-credit"
        );
        assert_eq!(score.score, 101);
    }

    #[test]
    fn test_relay_score_dedup_ignores_hop_count_variance() {
        // Same attack shape as timestamp variance: attacker re-signs
        // with a different hop_count. Dedup must reject.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let (r1, relay_id) = signed_receipt_for(&sk, &pk, 5, 1);
        let (r2, _) = signed_receipt_for(&sk, &pk, 5, 7);

        let mut score = RelayScore::new(relay_id);
        assert_eq!(score.record_success(&r1), Ok(()));
        assert_eq!(
            score.record_success(&r2),
            Err(RelayReceiptError::DuplicateReceipt),
        );
        assert_eq!(score.score, 101);
    }

    #[test]
    fn test_relay_score_dedup_admits_distinct_messages() {
        // Baseline positive: three authentic receipts for three
        // DIFFERENT messages must all credit. This ensures the dedup
        // gate isn't a blanket "one credit per relay" cap.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let relay_id = hex::encode(pk);
        let mut score = RelayScore::new(relay_id.clone());

        for i in 0..3u8 {
            let mut r = RelayReceipt {
                relay_id: relay_id.clone(),
                message_hash: hex::encode([i; 32]),
                timestamp: 100 + u64::from(i),
                signature: Vec::new(),
                hop_count: 1,
            };
            r.signature = sign(&sk, &r.canonical_message().unwrap()).to_vec();
            assert_eq!(score.record_success(&r), Ok(()));
        }
        assert_eq!(score.score, 103);
        assert_eq!(score.messages_relayed, 3);
    }

    #[test]
    fn test_relay_score_dedup_is_per_score_instance() {
        // Two independent RelayScore instances for DIFFERENT relays
        // must each be able to credit their own receipt for the same
        // message_hash. Dedup state is per-instance, not global —
        // otherwise two relays forwarding the same broadcast message
        // would stomp on each other.
        let (sk_a, vk_a) = generate_keypair();
        let pk_a = vk_a.to_bytes();
        let (sk_b, vk_b) = generate_keypair();
        let pk_b = vk_b.to_bytes();
        let shared_hash = hex::encode([0xCDu8; 32]);

        let build = |sk: &ed25519_dalek::SigningKey, pk: &[u8; 32]| {
            let mut r = RelayReceipt {
                relay_id: hex::encode(pk),
                message_hash: shared_hash.clone(),
                timestamp: 1,
                signature: Vec::new(),
                hop_count: 1,
            };
            r.signature = sign(sk, &r.canonical_message().unwrap()).to_vec();
            r
        };

        let r_a = build(&sk_a, &pk_a);
        let r_b = build(&sk_b, &pk_b);

        let mut score_a = RelayScore::new(hex::encode(pk_a));
        let mut score_b = RelayScore::new(hex::encode(pk_b));
        assert_eq!(score_a.record_success(&r_a), Ok(()));
        assert_eq!(score_b.record_success(&r_b), Ok(()));
        assert_eq!(score_a.score, 101);
        assert_eq!(score_b.score, 101);
    }

    #[test]
    fn test_relay_score_dedup_state_unchanged_on_rejected_receipt() {
        // If a receipt is rejected (e.g. tampered signature), its
        // message_hash MUST NOT be marked as credited. Otherwise a
        // well-chosen forgery could lock a legitimate message out of
        // future crediting.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let (mut tampered, relay_id) = signed_receipt_for(&sk, &pk, 10, 1);
        let legit = tampered.clone();
        tampered.timestamp = 9999; // breaks the signature

        let mut score = RelayScore::new(relay_id);
        assert_eq!(
            score.record_success(&tampered),
            Err(RelayReceiptError::SignatureInvalid),
            "tampered receipt should be rejected on signature grounds"
        );
        // The same message_hash, on the ORIGINAL (untampered) receipt,
        // must still be creditable.
        assert_eq!(
            score.record_success(&legit),
            Ok(()),
            "rejected receipt must not poison the dedup set"
        );
        assert_eq!(score.score, 101);
    }
}
