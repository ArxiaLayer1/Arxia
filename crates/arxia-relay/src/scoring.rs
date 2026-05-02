//! Relay node reputation scoring.
//!
//! # Rolling-window score (HIGH-015, commit 048)
//!
//! Pre-fix [`RelayScore::score`] is lifetime-cumulative: a relay
//! that was legitimate for 29 days then turns hostile keeps its
//! accumulated trust indefinitely. The audit (HIGH-015):
//!
//! > Constant `RELAY_SCORING_WINDOW_DAYS = 30` exists in core,
//! > but `scoring.rs` has no timestamped entries and no
//! > pruning; score is lifetime-cumulative. A relay that was
//! > legitimate for 29 days and then goes hostile keeps its
//! > trust indefinitely; a new relay can never catch up.
//! > Suggested fix direction: replace counters with a ring
//! > buffer of timestamped receipts; compute score as a function
//! > of the last 30 days only.
//!
//! [`RelayScore::record_success_at`] /
//! [`RelayScore::record_failure_at`] are the timestamped
//! variants that append to a `VecDeque` of
//! `(timestamp_ms, delta)` events.
//! [`RelayScore::rolling_score`] returns the score considering
//! only events within the last
//! [`RelayScore::ROLLING_WINDOW_MS`] milliseconds
//! (= 30 days × 86_400_000). Older events can be dropped via
//! [`RelayScore::prune_rolling`].
//!
//! The pre-existing cumulative methods
//! ([`RelayScore::record_success`],
//! [`RelayScore::record_failure`]) are preserved unchanged.
//! Production callers that want rolling-window scoring opt in
//! via the `_at` variants; the cumulative `score: i64` field
//! remains for callers that prefer the lifetime view.
//!
//! # Per-target censorship detection (HIGH-016, commit 049)
//!
//! Aggregate scoring (lifetime or rolling) cannot detect a relay
//! that forwards 99% of messages globally but drops 100% of one
//! specific target's messages. The audit (HIGH-016):
//!
//! > A relay forwards 99% of messages but drops 100% of Alice's
//! > messages. Aggregate score stays at ~99% (trusted), but
//! > Alice is censored; the scoring design cannot see this.
//! > Suggested fix direction: track success rate per-sender
//! > (or per-destination) with a minimum sample size; flag
//! > relays whose per-target variance exceeds a threshold.
//!
//! [`RelayScore::record_success_for_target`] /
//! [`RelayScore::record_failure_for_target`] track per-target
//! event counts in addition to the cumulative / rolling state.
//! "Target" is a 32-byte identifier supplied by the caller —
//! typically the sender or destination pubkey decoded from the
//! gossiped payload. The caller decides what counts as a
//! target so the scoring layer stays decoupled from message
//! semantics.
//!
//! [`RelayScore::per_target_success_rate`] returns
//! `(successes, failures, rate)` for a target (or `None` if
//! the target has no events). [`RelayScore::flag_per_target_anomalies`]
//! returns the list of targets whose success rate is at or below
//! a caller-supplied threshold AND who have at least `min_sample`
//! events — matching the audit's "minimum sample size +
//! variance threshold" recommendation.

use std::collections::{HashMap, HashSet, VecDeque};

use arxia_core::constants::RELAY_SCORING_WINDOW_DAYS;

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
    /// Ring buffer of timestamped score events for HIGH-015
    /// rolling-window scoring. Each entry is
    /// `(timestamp_ms, delta_i32)`; `delta` is `+1` for success
    /// and `-5` for failure (matching the cumulative `score`
    /// math). NOT `pub` — callers interact via
    /// [`RelayScore::record_success_at`],
    /// [`RelayScore::record_failure_at`],
    /// [`RelayScore::rolling_score`], and
    /// [`RelayScore::prune_rolling`].
    rolling_events: VecDeque<(u64, i32)>,
    /// Per-target success/failure counts for HIGH-016
    /// per-target censorship detection. Keyed by a 32-byte
    /// caller-supplied identifier (typically a sender or
    /// destination pubkey). Each entry is
    /// `(successes, failures)`. NOT `pub` — callers interact
    /// via [`RelayScore::record_success_for_target`],
    /// [`RelayScore::record_failure_for_target`],
    /// [`RelayScore::per_target_success_rate`], and
    /// [`RelayScore::flag_per_target_anomalies`].
    per_target_counts: HashMap<[u8; 32], (u64, u64)>,
}

impl RelayScore {
    /// Width of the rolling-score window in milliseconds. Equals
    /// `RELAY_SCORING_WINDOW_DAYS × 86_400_000` (= 30 ×
    /// 86_400_000 = 2 592 000 000 ms). Events older than this
    /// relative to the supplied `now_ms` do not contribute to
    /// [`RelayScore::rolling_score`] and are dropped by
    /// [`RelayScore::prune_rolling`].
    pub const ROLLING_WINDOW_MS: u64 = RELAY_SCORING_WINDOW_DAYS * 86_400_000;

    /// Score contribution of a successful relay (+1, matches the
    /// cumulative `score` increment).
    pub const SUCCESS_DELTA: i32 = 1;

    /// Score contribution of a failed relay (-5, matches the
    /// cumulative `score` decrement).
    pub const FAILURE_DELTA: i32 = -5;

    /// Baseline score returned by `rolling_score` when no events
    /// fall within the window. Matches the construction default
    /// of `score: 100`.
    pub const ROLLING_BASELINE: i64 = 100;

    /// Create a new relay score with default values.
    pub fn new(relay_id: String) -> Self {
        Self {
            relay_id,
            score: 100,
            messages_relayed: 0,
            messages_failed: 0,
            credited_messages: HashSet::new(),
            rolling_events: VecDeque::new(),
            per_target_counts: HashMap::new(),
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

    /// Record a successful relay AND append a `+SUCCESS_DELTA`
    /// event to the rolling-window buffer at `now_ms`. See
    /// HIGH-015 in the module docstring.
    ///
    /// Behaviour: same checks and side effects as
    /// [`RelayScore::record_success`] (cumulative `score` and
    /// `messages_relayed` advance, dedup gate fires); on
    /// success the rolling buffer also gets a new entry, and
    /// stale entries (older than `now_ms - ROLLING_WINDOW_MS`)
    /// are pruned.
    ///
    /// Errors leave both the cumulative state AND the rolling
    /// buffer unchanged.
    pub fn record_success_at(
        &mut self,
        receipt: &RelayReceipt,
        now_ms: u64,
    ) -> Result<(), RelayReceiptError> {
        self.record_success(receipt)?;
        self.rolling_events.push_back((now_ms, Self::SUCCESS_DELTA));
        self.prune_rolling(now_ms);
        Ok(())
    }

    /// Record a failed relay AND append a `FAILURE_DELTA` event
    /// to the rolling-window buffer at `now_ms`. Same cumulative
    /// side effects as [`RelayScore::record_failure`], plus the
    /// buffer append + prune.
    pub fn record_failure_at(&mut self, now_ms: u64) {
        self.record_failure();
        self.rolling_events.push_back((now_ms, Self::FAILURE_DELTA));
        self.prune_rolling(now_ms);
    }

    /// Compute the rolling score considering only events whose
    /// timestamp is within `[now_ms - ROLLING_WINDOW_MS, now_ms]`.
    /// Returns `ROLLING_BASELINE` (100) plus the sum of
    /// in-window event deltas.
    ///
    /// This method is read-only; it does not prune the buffer.
    /// Call [`RelayScore::prune_rolling`] separately to bound memory.
    pub fn rolling_score(&self, now_ms: u64) -> i64 {
        let cutoff = now_ms.saturating_sub(Self::ROLLING_WINDOW_MS);
        let delta_sum: i64 = self
            .rolling_events
            .iter()
            .filter(|&&(t, _)| t >= cutoff)
            .map(|&(_, d)| d as i64)
            .sum();
        Self::ROLLING_BASELINE.saturating_add(delta_sum)
    }

    /// Drop rolling-buffer entries strictly older than
    /// `now_ms - ROLLING_WINDOW_MS`. The buffer is sorted by
    /// insertion order (which equals timestamp order under the
    /// monotonic-clock assumption); pop from the front until we
    /// see an in-window event.
    ///
    /// Idempotent: calling twice with the same `now_ms` is a
    /// no-op the second time. Storage is bounded by the rate of
    /// successful + failed relays in the window.
    pub fn prune_rolling(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(Self::ROLLING_WINDOW_MS);
        while let Some(&(t, _)) = self.rolling_events.front() {
            if t < cutoff {
                self.rolling_events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Number of events currently buffered in the rolling
    /// window (after the most recent prune). Useful for tests
    /// and observability.
    pub fn rolling_events_count(&self) -> usize {
        self.rolling_events.len()
    }

    /// Record a successful relay AND increment the per-target
    /// success count for `target`. See HIGH-016 in the module
    /// docstring.
    ///
    /// Behaviour: same checks and side effects as
    /// [`RelayScore::record_success`] (cumulative + dedup
    /// gates fire); on success the per-target counter for
    /// `target` is incremented.
    ///
    /// `target` is a caller-supplied 32-byte identifier; the
    /// scoring layer is decoupled from what it semantically
    /// means (sender, destination, message-class).
    ///
    /// Errors leave both the cumulative state AND the
    /// per-target counters unchanged.
    pub fn record_success_for_target(
        &mut self,
        receipt: &RelayReceipt,
        target: &[u8; 32],
    ) -> Result<(), RelayReceiptError> {
        self.record_success(receipt)?;
        let entry = self.per_target_counts.entry(*target).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        Ok(())
    }

    /// Record a failed relay AND increment the per-target
    /// failure count for `target`. Same cumulative side
    /// effects as [`RelayScore::record_failure`], plus the
    /// per-target counter increment.
    pub fn record_failure_for_target(&mut self, target: &[u8; 32]) {
        self.record_failure();
        let entry = self.per_target_counts.entry(*target).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);
    }

    /// Per-target observed event counts and computed success
    /// rate.
    ///
    /// Returns `Some((successes, failures, rate))` where `rate
    /// = successes as f64 / (successes + failures) as f64`,
    /// or `None` if the target has no recorded events.
    pub fn per_target_success_rate(&self, target: &[u8; 32]) -> Option<(u64, u64, f64)> {
        let (s, f) = self.per_target_counts.get(target).copied()?;
        let total = s.saturating_add(f);
        if total == 0 {
            return None;
        }
        let rate = s as f64 / total as f64;
        Some((s, f, rate))
    }

    /// Number of distinct targets currently tracked.
    pub fn per_target_count(&self) -> usize {
        self.per_target_counts.len()
    }

    /// Flag targets whose per-target success rate is at or
    /// below `threshold` AND who have at least `min_sample`
    /// events recorded. Returns the offending target IDs.
    ///
    /// HIGH-016 PRIMARY: detects relays that drop a specific
    /// target's messages while maintaining a high aggregate
    /// score. The audit's "minimum sample size + variance
    /// threshold" recommendation; we use absolute rate (not
    /// variance against the aggregate) for simplicity, but a
    /// future enhancement could swap in stddev-based
    /// detection.
    ///
    /// `min_sample`: minimum total events
    /// (successes + failures) before a target is eligible.
    /// Below this, the target is treated as not having
    /// statistical signal and is skipped.
    /// `threshold`: success rate at or below which a target
    /// is flagged. `0.5` means "≤ 50% success rate".
    ///
    /// Output ordering is unspecified (HashMap iteration is
    /// non-deterministic); callers that need a stable order
    /// must sort the result.
    pub fn flag_per_target_anomalies(&self, min_sample: u64, threshold: f64) -> Vec<[u8; 32]> {
        self.per_target_counts
            .iter()
            .filter_map(|(target, &(s, f))| {
                let total = s.saturating_add(f);
                if total < min_sample {
                    return None;
                }
                let rate = s as f64 / total as f64;
                if rate <= threshold {
                    Some(*target)
                } else {
                    None
                }
            })
            .collect()
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

    // ============================================================
    // HIGH-015 (commit 048) — rolling-window scoring.
    //
    // The audit's exact attack: a relay legitimate for 29 days,
    // hostile on day 30. Cumulative `score` reflects 29 days of
    // good behaviour; `rolling_score` reflects only the last 30
    // days' worth of events (which after enough time becomes
    // just the hostile activity).
    // ============================================================

    /// Build a fresh signed receipt with a unique message_hash so
    /// the dedup gate doesn't fire across multiple successes.
    fn unique_signed_receipt(
        sk: &ed25519_dalek::SigningKey,
        relay_pk: &[u8; 32],
        nonce: u64,
    ) -> RelayReceipt {
        let relay_id_hex = hex::encode(relay_pk);
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&nonce.to_be_bytes());
        let mut r = RelayReceipt {
            relay_id: relay_id_hex,
            message_hash: hex::encode(bytes),
            timestamp: nonce,
            signature: Vec::new(),
            hop_count: 1,
        };
        let msg = r.canonical_message().unwrap();
        r.signature = sign(sk, &msg).to_vec();
        r
    }

    const DAY_MS: u64 = 86_400_000;

    #[test]
    fn test_rolling_score_starts_at_baseline_with_no_events() {
        let score = RelayScore::new(hex::encode([0u8; 32]));
        assert_eq!(score.rolling_score(0), RelayScore::ROLLING_BASELINE);
        assert_eq!(score.rolling_score(u64::MAX), RelayScore::ROLLING_BASELINE);
    }

    #[test]
    fn test_rolling_window_constant_value() {
        // Pin: 30 days × 86_400_000 ms = 2_592_000_000 ms.
        assert_eq!(RelayScore::ROLLING_WINDOW_MS, 30 * 86_400_000);
        assert_eq!(RelayScore::ROLLING_WINDOW_MS, 2_592_000_000);
    }

    #[test]
    fn test_rolling_score_includes_recent_success() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let r = unique_signed_receipt(&sk, &pk, 1);
        let mut score = RelayScore::new(hex::encode(pk));
        // Record at t = 1_000_000.
        score.record_success_at(&r, 1_000_000).unwrap();
        // Score immediately afterwards = baseline + 1.
        assert_eq!(
            score.rolling_score(1_000_000),
            RelayScore::ROLLING_BASELINE + 1
        );
    }

    #[test]
    fn test_rolling_score_excludes_event_just_outside_window() {
        // PRIMARY HIGH-015 PIN.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let r = unique_signed_receipt(&sk, &pk, 1);
        let mut score = RelayScore::new(hex::encode(pk));
        // Record at t = 0.
        score.record_success_at(&r, 0).unwrap();
        // Query at t = ROLLING_WINDOW_MS + 1 (event is now
        // strictly older than the cutoff).
        let later = RelayScore::ROLLING_WINDOW_MS + 1;
        assert_eq!(score.rolling_score(later), RelayScore::ROLLING_BASELINE);
    }

    #[test]
    fn test_rolling_score_includes_event_at_exact_window_boundary() {
        // Boundary: event at t such that
        // now_ms - t == ROLLING_WINDOW_MS exactly is INCLUSIVE
        // (cutoff is `>= cutoff` in the filter).
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let r = unique_signed_receipt(&sk, &pk, 1);
        let mut score = RelayScore::new(hex::encode(pk));
        score.record_success_at(&r, 0).unwrap();
        // At t = ROLLING_WINDOW_MS, event timestamp is exactly
        // at the cutoff (cutoff = now - WINDOW = 0). So it IS
        // included.
        assert_eq!(
            score.rolling_score(RelayScore::ROLLING_WINDOW_MS),
            RelayScore::ROLLING_BASELINE + 1
        );
    }

    #[test]
    fn test_rolling_score_audit_attack_29_days_good_then_30th_bad() {
        // PRIMARY HIGH-015 PIN: the audit's exact scenario.
        // Day 1-29: 29 successful relays.
        // Day 30: 5 failures.
        // Day 31 (now), rolling score reflects only the 30th
        // day's failures + the day 1-29 successes that are still
        // within the window.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut score = RelayScore::new(hex::encode(pk));

        // Day 1: 29 successes spread across days 1-29.
        for d in 1..=29u64 {
            let r = unique_signed_receipt(&sk, &pk, d);
            let t = d * DAY_MS;
            score.record_success_at(&r, t).unwrap();
        }
        // Day 30: 5 failures.
        let day_30 = 30 * DAY_MS;
        for _ in 0..5 {
            score.record_failure_at(day_30);
        }

        // Cumulative score: 100 + 29 - 25 = 104.
        assert_eq!(score.score, 100 + 29 - 25);

        // Rolling score at end of day 30 = baseline + 29 - 25 = 104 also
        // (all events within 30-day window).
        assert_eq!(score.rolling_score(day_30), 100 + 29 - 25);

        // Now jump to day 60. All day-1-29 successes are
        // strictly older than the 30-day window (day 60 - 30 =
        // day 30 cutoff; events on day 1-29 are < day 30 →
        // pruned). Only the day-30 failures remain (since
        // day_30 == cutoff, they ARE within the window).
        let day_60 = 60 * DAY_MS;
        let rolling_d60 = score.rolling_score(day_60);
        assert_eq!(
            rolling_d60,
            RelayScore::ROLLING_BASELINE + 5 * (RelayScore::FAILURE_DELTA as i64)
        );
        assert_eq!(rolling_d60, 100 - 25);
        assert_eq!(rolling_d60, 75);
        // Cumulative is unchanged at 104 — the audit's exact
        // observation that lifetime score doesn't reflect
        // recent hostile behaviour.
        assert_eq!(score.score, 104);
    }

    #[test]
    fn test_prune_rolling_drops_old_events() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let r = unique_signed_receipt(&sk, &pk, 1);
        let mut score = RelayScore::new(hex::encode(pk));
        score.record_success_at(&r, 0).unwrap();
        assert_eq!(score.rolling_events_count(), 1);
        // Prune at t > WINDOW: event is dropped.
        score.prune_rolling(RelayScore::ROLLING_WINDOW_MS + 1);
        assert_eq!(score.rolling_events_count(), 0);
    }

    #[test]
    fn test_prune_rolling_keeps_recent_events() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let r = unique_signed_receipt(&sk, &pk, 1);
        let mut score = RelayScore::new(hex::encode(pk));
        score.record_success_at(&r, 1_000_000).unwrap();
        // Prune at t still within the window.
        score.prune_rolling(2_000_000);
        assert_eq!(score.rolling_events_count(), 1);
    }

    #[test]
    fn test_record_success_at_does_not_double_credit_on_dedup_failure() {
        // The cumulative dedup gate (CRIT-005) MUST still fire:
        // re-recording the same receipt returns
        // DuplicateReceipt and DOES NOT add a duplicate event
        // to the rolling buffer.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let r = unique_signed_receipt(&sk, &pk, 1);
        let mut score = RelayScore::new(hex::encode(pk));
        score.record_success_at(&r, 1_000_000).unwrap();
        let r2 = score.record_success_at(&r, 2_000_000);
        assert_eq!(r2, Err(RelayReceiptError::DuplicateReceipt));
        // Rolling buffer still has only the one event from the
        // first record.
        assert_eq!(score.rolling_events_count(), 1);
        // Rolling score still +1.
        assert_eq!(
            score.rolling_score(2_000_000),
            RelayScore::ROLLING_BASELINE + 1
        );
    }

    #[test]
    fn test_record_failure_at_appends_failure_event() {
        let mut score = RelayScore::new(hex::encode([0u8; 32]));
        score.record_failure_at(1_000_000);
        assert_eq!(score.rolling_events_count(), 1);
        assert_eq!(
            score.rolling_score(1_000_000),
            RelayScore::ROLLING_BASELINE + (RelayScore::FAILURE_DELTA as i64)
        );
        assert_eq!(score.rolling_score(1_000_000), 95);
    }

    #[test]
    fn test_rolling_score_combines_success_and_failure_within_window() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut score = RelayScore::new(hex::encode(pk));
        let r1 = unique_signed_receipt(&sk, &pk, 1);
        let r2 = unique_signed_receipt(&sk, &pk, 2);
        score.record_success_at(&r1, 100).unwrap();
        score.record_failure_at(200);
        score.record_success_at(&r2, 300).unwrap();
        // 100 + 1 - 5 + 1 = 97.
        assert_eq!(score.rolling_score(300), 97);
    }

    // ============================================================
    // HIGH-016 (commit 049) — per-target censorship detection.
    //
    // The audit's exact attack: a relay forwards 99% of
    // messages globally but drops 100% of Alice's messages.
    // Aggregate score stays high; `flag_per_target_anomalies`
    // surfaces Alice as a censored target.
    // ============================================================

    #[test]
    fn test_per_target_starts_empty() {
        let score = RelayScore::new(hex::encode([0u8; 32]));
        assert_eq!(score.per_target_count(), 0);
        assert_eq!(score.per_target_success_rate(&[1u8; 32]), None);
    }

    #[test]
    fn test_record_success_for_target_increments_count() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let r = unique_signed_receipt(&sk, &pk, 1);
        let mut score = RelayScore::new(hex::encode(pk));
        let target = [0xAAu8; 32];
        score.record_success_for_target(&r, &target).unwrap();
        let (s, f, rate) = score.per_target_success_rate(&target).unwrap();
        assert_eq!(s, 1);
        assert_eq!(f, 0);
        assert!((rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_record_failure_for_target_increments_count() {
        let target = [0xAAu8; 32];
        let mut score = RelayScore::new(hex::encode([0u8; 32]));
        score.record_failure_for_target(&target);
        let (s, f, rate) = score.per_target_success_rate(&target).unwrap();
        assert_eq!(s, 0);
        assert_eq!(f, 1);
        assert!((rate - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_per_target_independent_targets_tracked_separately() {
        // Pin: counts for one target don't leak into another.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut score = RelayScore::new(hex::encode(pk));
        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];
        let r1 = unique_signed_receipt(&sk, &pk, 1);
        let r2 = unique_signed_receipt(&sk, &pk, 2);
        score.record_success_for_target(&r1, &alice).unwrap();
        score.record_failure_for_target(&bob);
        score.record_success_for_target(&r2, &alice).unwrap();
        let (sa, fa, _) = score.per_target_success_rate(&alice).unwrap();
        let (sb, fb, _) = score.per_target_success_rate(&bob).unwrap();
        assert_eq!((sa, fa), (2, 0));
        assert_eq!((sb, fb), (0, 1));
        assert_eq!(score.per_target_count(), 2);
    }

    #[test]
    fn test_flag_per_target_anomalies_audit_attack() {
        // PRIMARY HIGH-016 PIN: the audit's exact scenario.
        // Relay forwards 99% globally (99 successes for "bob"
        // target, 1 failure scattered) but drops 100% of
        // Alice's messages (5 failures, 0 successes).
        //
        // Aggregate score (cumulative): 100 + 99 - 5*5 - 1*5 =
        // 100 + 99 - 30 = 169 — a "trusted" relay.
        //
        // flag_per_target_anomalies(min_sample=5, threshold=0.5)
        // returns Alice (rate 0%) and not Bob (rate 99%).
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut score = RelayScore::new(hex::encode(pk));
        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];

        // 99 successes for Bob.
        for n in 0..99u64 {
            let r = unique_signed_receipt(&sk, &pk, n);
            score.record_success_for_target(&r, &bob).unwrap();
        }
        // 5 failures for Alice (Alice's messages all dropped).
        for _ in 0..5 {
            score.record_failure_for_target(&alice);
        }
        // 1 failure attributed elsewhere (cumulative noise).
        score.record_failure();

        // Aggregate score is high — relay looks trusted.
        assert!(score.is_trusted());
        // Per-target detection surfaces Alice.
        let flagged = score.flag_per_target_anomalies(5, 0.5);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0], alice);
    }

    #[test]
    fn test_flag_per_target_anomalies_below_min_sample_skipped() {
        // Even with rate = 0%, a target with fewer than
        // min_sample events is skipped. Pin against false-
        // positives on small samples.
        let target = [0xCCu8; 32];
        let mut score = RelayScore::new(hex::encode([0u8; 32]));
        // 2 failures, no successes.
        score.record_failure_for_target(&target);
        score.record_failure_for_target(&target);
        let flagged = score.flag_per_target_anomalies(5, 0.5);
        assert!(flagged.is_empty(), "below min_sample must not be flagged");
    }

    #[test]
    fn test_flag_per_target_anomalies_above_threshold_not_flagged() {
        // Healthy target (100% success) is NOT flagged.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut score = RelayScore::new(hex::encode(pk));
        let target = [0xDDu8; 32];
        for n in 0..10u64 {
            let r = unique_signed_receipt(&sk, &pk, n);
            score.record_success_for_target(&r, &target).unwrap();
        }
        let flagged = score.flag_per_target_anomalies(5, 0.5);
        assert!(flagged.is_empty());
    }

    #[test]
    fn test_flag_per_target_anomalies_exactly_at_threshold_is_flagged() {
        // Boundary: rate exactly equal to threshold is flagged
        // (`<=` not `<`). Pins the inclusive boundary.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut score = RelayScore::new(hex::encode(pk));
        let target = [0xEEu8; 32];
        // 5 successes + 5 failures = 50% rate.
        for n in 0..5u64 {
            let r = unique_signed_receipt(&sk, &pk, n);
            score.record_success_for_target(&r, &target).unwrap();
        }
        for _ in 0..5 {
            score.record_failure_for_target(&target);
        }
        let flagged = score.flag_per_target_anomalies(5, 0.5);
        assert_eq!(flagged, vec![target]);
    }

    #[test]
    fn test_per_target_dedup_failure_does_not_count_target() {
        // CRIT-005 dedup gate fires even on
        // record_success_for_target. The per-target counter
        // must NOT advance for a duplicate receipt.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let r = unique_signed_receipt(&sk, &pk, 1);
        let mut score = RelayScore::new(hex::encode(pk));
        let target = [0xFFu8; 32];
        score.record_success_for_target(&r, &target).unwrap();
        // Replay same receipt → DuplicateReceipt error.
        let result = score.record_success_for_target(&r, &target);
        assert_eq!(result, Err(RelayReceiptError::DuplicateReceipt));
        // Per-target counter still 1, not 2.
        let (s, f, _) = score.per_target_success_rate(&target).unwrap();
        assert_eq!((s, f), (1, 0));
    }
}
