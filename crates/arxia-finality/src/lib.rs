//! Transaction finality assessment for Arxia.
//!
//! Arxia uses a 4-level finality model:
//! - PENDING: >10 ARX, no confirmations
//! - L0: <=10 ARX, signed confirmation from a registered node
//! - L1: Nonce registry sync (SyncResult::Success)
//! - L2: >=67% stake-weighted validator confirmation
//!
//! # CRIT-007 / CRIT-008 mitigation
//!
//! The pre-fix [`assess_finality`] took `validator_pct: f64` and
//! `local_confirmations: u32` directly from the caller. Any caller
//! that supplied `validator_pct = 1.0` got `FinalityLevel::L2`
//! instantly, with no validation; any caller that supplied
//! `local_confirmations = u32::MAX` got L0 / L1 promotion without
//! a single signed witness. The whole finality model trusted the
//! caller's numbers.
//!
//! This commit replaces those parameters with authenticated inputs:
//!
//! - `confirmations: &[SignedConfirmation]` — each entry carries an
//!   Ed25519 signature from a registered node bound to the block
//!   hash being assessed under [`FINALITY_CONFIRMATION_DOMAIN`].
//! - `votes: &[SignedValidatorVote]` — each entry carries an
//!   Ed25519 signature from a registered validator bound to the
//!   block hash under [`FINALITY_VALIDATOR_VOTE_DOMAIN`].
//! - `registry: &ValidatorRegistry` — the trusted set of validator
//!   pubkeys, with their stakes in micro-ARX. Validator pct is now
//!   computed inside the function as
//!   `sum(stake[v] for v in valid_votes) / registry.total_stake()`,
//!   never accepted as a free parameter.
//!
//! `assess_finality` now returns `Result<FinalityLevel, FinalityError>`
//! so signature / structural failures surface explicitly. Successful
//! assessment ignores votes / confirmations whose pubkey is not in
//! the registry (silent filter — they simply don't count) and
//! returns `Err(FinalityError::SignatureInvalid)` if a vote or
//! confirmation IS from a registered key but its signature does not
//! verify (loud failure — a registered key signing wrong is
//! actionable evidence of misbehavior).
//!
//! # Latched monotonic finality (HIGH-017, commit 042)
//!
//! Finality is supposed to be monotonic: once a block reaches L1,
//! subsequent reassessments must return L1 or higher — never L0,
//! never Pending. The pre-fix [`assess_finality`] is stateless;
//! a sync glitch that produces `SyncResult::Mismatch` on a block
//! that previously had `SyncResult::Success` would compute a
//! lower finality level for the same block. The audit (HIGH-017):
//!
//! > A block transitioned to L1; later, a sync glitch produces
//! > `SyncResult::Mismatch` and the finality reassesses to L0.
//! > Finality is supposed to be monotonic; regressing from L1 to
//! > L0 breaks every caller assumption (wallet UI, receipt
//! > issuance, reconciliation decisions).
//!
//! [`FinalityLatch`] wraps `assess_finality` with a per-block-hash
//! "highest seen" cache. Each call to
//! [`FinalityLatch::assess_monotonic`] computes the snapshot
//! finality, then returns `max(stored, snapshot)` and updates the
//! stored value. Once a block reaches L1, no subsequent
//! assessment can return less than L1 for that block; once it
//! reaches L2, never less than L2.
//!
//! Stateless [`assess_finality`] is preserved unchanged for
//! callers that explicitly want the snapshot semantics (e.g. unit
//! tests, instrumentation). Production callers that issue
//! receipts, render wallet UI, or commit reconciliation decisions
//! MUST use the latched variant.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use arxia_core::constants::L0_CAP_MICRO_ARX;
use arxia_core::ArxiaError;
use arxia_gossip::SyncResult;

/// Domain-separation prefix for the Ed25519 signature on a
/// [`SignedConfirmation`].
///
/// Distinct from [`FINALITY_VALIDATOR_VOTE_DOMAIN`] so a confirmation
/// signature cannot be replayed as a validator vote (and vice-versa).
/// 30 bytes.
pub const FINALITY_CONFIRMATION_DOMAIN: &[u8] = b"arxia-finality-confirmation-v1";

/// Domain-separation prefix for the Ed25519 signature on a
/// [`SignedValidatorVote`]. 31 bytes.
pub const FINALITY_VALIDATOR_VOTE_DOMAIN: &[u8] = b"arxia-finality-validator-vote-v1";

/// Stake threshold (fraction of total registered stake) for a block
/// to reach [`FinalityLevel::L2`].
///
/// Hard-coded at 0.67 (two-thirds) to match the documented finality
/// model. Bumping this constant is a protocol-level change.
pub const L2_QUORUM_FRACTION: f64 = 0.67;

/// Errors returned by the authenticated finality assessment path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalityError {
    /// A signature on a [`SignedConfirmation`] or
    /// [`SignedValidatorVote`] is not exactly 64 bytes.
    InvalidSignatureLength,
    /// A pubkey on a [`SignedConfirmation`] or
    /// [`SignedValidatorVote`] is structurally invalid as an
    /// Ed25519 public key.
    InvalidPublicKey,
    /// A signature does NOT verify against the canonical bytes
    /// under the carried pubkey, AND the pubkey is in the
    /// validator registry (so the signature failure is actionable
    /// evidence of misbehavior, not a stranger-signed payload that
    /// can be silently filtered).
    SignatureInvalid,
}

impl std::fmt::Display for FinalityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignatureLength => f.write_str("signature must be exactly 64 bytes"),
            Self::InvalidPublicKey => f.write_str("pubkey is not a valid Ed25519 public key"),
            Self::SignatureInvalid => {
                f.write_str("signature from a registered key does not verify")
            }
        }
    }
}

impl std::error::Error for FinalityError {}

/// Finality level for a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FinalityLevel {
    /// Transaction is pending confirmation (>10 ARX).
    Pending,
    /// Instant local confirmation via BLE / signed L0 witness (<=10 ARX).
    L0,
    /// Gossip-level finality (nonce sync confirmed).
    L1,
    /// Full validator consensus (>=67% stake confirmation).
    L2,
}

impl std::fmt::Display for FinalityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "PENDING"),
            Self::L0 => write!(f, "L0 (instant)"),
            Self::L1 => write!(f, "L1 (gossip)"),
            Self::L2 => write!(f, "L2 (full)"),
        }
    }
}

/// A signed confirmation from a registered node that it has seen and
/// accepts a specific block. Used to promote a transaction to
/// [`FinalityLevel::L0`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfirmation {
    /// 32-byte Ed25519 public key of the confirming node.
    pub confirmer_pubkey: [u8; 32],
    /// 32-byte hash of the block being confirmed.
    pub block_hash: [u8; 32],
    /// Ed25519 signature over [`Self::canonical_bytes`]. MUST be
    /// exactly 64 bytes.
    pub signature: Vec<u8>,
}

impl SignedConfirmation {
    /// Build the canonical bytes that the confirmer signs.
    ///
    /// Layout:
    /// - [`FINALITY_CONFIRMATION_DOMAIN`] (30 bytes)
    /// - confirmer_pubkey (32 bytes)
    /// - block_hash (32 bytes)
    ///
    /// Total: 94 bytes. Determinism guaranteed.
    pub fn canonical_bytes(confirmer_pubkey: &[u8; 32], block_hash: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FINALITY_CONFIRMATION_DOMAIN.len() + 32 + 32);
        buf.extend_from_slice(FINALITY_CONFIRMATION_DOMAIN);
        buf.extend_from_slice(confirmer_pubkey);
        buf.extend_from_slice(block_hash);
        buf
    }

    /// Verify the Ed25519 signature on this confirmation under
    /// [`Self::confirmer_pubkey`]. See module docs for how
    /// [`assess_finality`] interprets the result.
    pub fn verify(&self) -> Result<(), FinalityError> {
        verify_signature(
            &self.confirmer_pubkey,
            &Self::canonical_bytes(&self.confirmer_pubkey, &self.block_hash),
            &self.signature,
        )
    }
}

/// A signed validator vote on a specific block. Used to compute
/// stake-weighted finality for [`FinalityLevel::L2`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedValidatorVote {
    /// 32-byte Ed25519 public key of the voting validator.
    pub validator_pubkey: [u8; 32],
    /// 32-byte hash of the block being voted on.
    pub block_hash: [u8; 32],
    /// Ed25519 signature over [`Self::canonical_bytes`]. MUST be
    /// exactly 64 bytes.
    pub signature: Vec<u8>,
}

impl SignedValidatorVote {
    /// Build the canonical bytes that the validator signs.
    ///
    /// Layout:
    /// - [`FINALITY_VALIDATOR_VOTE_DOMAIN`] (32 bytes)
    /// - validator_pubkey (32 bytes)
    /// - block_hash (32 bytes)
    ///
    /// Total: 96 bytes.
    pub fn canonical_bytes(validator_pubkey: &[u8; 32], block_hash: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FINALITY_VALIDATOR_VOTE_DOMAIN.len() + 32 + 32);
        buf.extend_from_slice(FINALITY_VALIDATOR_VOTE_DOMAIN);
        buf.extend_from_slice(validator_pubkey);
        buf.extend_from_slice(block_hash);
        buf
    }

    /// Verify the Ed25519 signature on this vote under
    /// [`Self::validator_pubkey`].
    pub fn verify(&self) -> Result<(), FinalityError> {
        verify_signature(
            &self.validator_pubkey,
            &Self::canonical_bytes(&self.validator_pubkey, &self.block_hash),
            &self.signature,
        )
    }
}

/// Shared signature-check path for both [`SignedConfirmation`] and
/// [`SignedValidatorVote`].
fn verify_signature(
    pubkey: &[u8; 32],
    canonical: &[u8],
    signature: &[u8],
) -> Result<(), FinalityError> {
    if signature.len() != 64 {
        return Err(FinalityError::InvalidSignatureLength);
    }
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| FinalityError::InvalidSignatureLength)?;
    arxia_crypto::verify(pubkey, canonical, &sig).map_err(|e| match e {
        ArxiaError::InvalidKey(_) => FinalityError::InvalidPublicKey,
        _ => FinalityError::SignatureInvalid,
    })
}

/// A trusted set of validator public keys with their stakes
/// (in micro-ARX). Used by [`assess_finality`] to compute stake-
/// weighted L2 finality and to filter out votes / confirmations from
/// non-registered keys.
///
/// # Limitation
///
/// This is a flat in-memory map for now. A future commit will sync
/// the registry from the consensus layer (paralleling the observer-
/// registry follow-up of commit 018). For deployments today, the
/// caller is responsible for populating the registry from a
/// trusted source.
#[derive(Debug, Clone, Default)]
pub struct ValidatorRegistry {
    validators: BTreeMap<[u8; 32], u64>,
}

impl ValidatorRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `pubkey` with `stake_micro_arx`. If `pubkey` already
    /// exists, the stake is overwritten.
    pub fn insert(&mut self, pubkey: [u8; 32], stake_micro_arx: u64) {
        self.validators.insert(pubkey, stake_micro_arx);
    }

    /// Stake associated with `pubkey`, or `None` if unknown.
    pub fn stake_of(&self, pubkey: &[u8; 32]) -> Option<u64> {
        self.validators.get(pubkey).copied()
    }

    /// Whether `pubkey` is registered.
    pub fn contains(&self, pubkey: &[u8; 32]) -> bool {
        self.validators.contains_key(pubkey)
    }

    /// Number of registered validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Sum of all registered stakes, saturating at [`u64::MAX`].
    pub fn total_stake(&self) -> u64 {
        self.validators
            .values()
            .copied()
            .fold(0u64, u64::saturating_add)
    }
}

/// Assesses the finality level of a transaction over `block_hash`
/// using authenticated inputs.
///
/// # Arguments
///
/// - `amount_micro_arx` — transaction value, used to gate L0
///   ([`L0_CAP_MICRO_ARX`]).
/// - `block_hash` — the 32-byte hash of the block whose finality is
///   being assessed. Confirmations / votes whose `block_hash` does
///   NOT match are silently filtered (they belong to a different
///   transaction).
/// - `confirmations` — signed L0 confirmations from registered nodes.
///   Used only to upgrade Pending → L0 when the amount is small.
/// - `sync_result` — gossip-level L1 indicator, from
///   [`arxia_gossip::sync_nonces_before_l1`].
/// - `votes` — stake-weighted L2 votes from registered validators.
///   Used to compute the validator pct internally.
/// - `registry` — the trusted validator pubkey → stake map.
///
/// # Returns
///
/// `Ok(FinalityLevel)` on success. The decision tree is:
/// 1. Compute validator pct from votes whose `validator_pubkey` is
///    registered AND whose signature verifies. If pct ≥
///    [`L2_QUORUM_FRACTION`], return L2.
/// 2. If `*sync_result == SyncResult::Success`, return L1.
/// 3. If `amount_micro_arx <= L0_CAP_MICRO_ARX` AND there is at
///    least one valid `SignedConfirmation` from a registered node,
///    return L0.
/// 4. Otherwise return Pending.
///
/// # Errors
///
/// Returns `Err(FinalityError::SignatureInvalid)` if a vote or
/// confirmation IS from a registered key but its signature does not
/// verify — that is actionable evidence of misbehavior, not a
/// stranger-signed payload that can be silently filtered. Returns
/// `Err(FinalityError::InvalidSignatureLength)` or
/// `Err(FinalityError::InvalidPublicKey)` for structurally invalid
/// inputs from registered keys.
pub fn assess_finality(
    amount_micro_arx: u64,
    block_hash: [u8; 32],
    confirmations: &[SignedConfirmation],
    sync_result: &SyncResult,
    votes: &[SignedValidatorVote],
    registry: &ValidatorRegistry,
) -> Result<FinalityLevel, FinalityError> {
    // --- L2: stake-weighted validator quorum ---
    let total_stake = registry.total_stake();
    if total_stake > 0 {
        let mut counted_validators: HashSet<[u8; 32]> = HashSet::new();
        let mut accepted_stake: u64 = 0;
        for vote in votes {
            if vote.block_hash != block_hash {
                continue;
            }
            // Vote from a non-registered key: silently ignore. It
            // doesn't count, but it doesn't fail the whole call.
            if !registry.contains(&vote.validator_pubkey) {
                continue;
            }
            // Vote from a registered key: signature MUST verify.
            // A registered key signing wrong is misbehavior.
            vote.verify()?;
            // De-duplicate: a single validator can only contribute
            // its stake once, even if it submits multiple identical
            // votes.
            if counted_validators.insert(vote.validator_pubkey) {
                let stake = registry.stake_of(&vote.validator_pubkey).unwrap_or(0);
                accepted_stake = accepted_stake.saturating_add(stake);
            }
        }
        // Compute pct via integer-ratio comparison to avoid f64
        // rounding issues on large stakes:
        // accepted_stake / total_stake >= 0.67
        // ⇔ accepted_stake * 100 >= total_stake * 67
        // (saturating to prevent overflow on adversarial inputs).
        let lhs = accepted_stake.saturating_mul(100);
        let rhs = total_stake.saturating_mul(67);
        if lhs >= rhs {
            return Ok(FinalityLevel::L2);
        }
    }

    // --- L1: gossip-level sync ---
    if *sync_result == SyncResult::Success {
        return Ok(FinalityLevel::L1);
    }

    // --- L0: low-value + signed local confirmation ---
    if amount_micro_arx <= L0_CAP_MICRO_ARX {
        let mut seen_confirmer: HashSet<[u8; 32]> = HashSet::new();
        for conf in confirmations {
            if conf.block_hash != block_hash {
                continue;
            }
            if !registry.contains(&conf.confirmer_pubkey) {
                continue;
            }
            conf.verify()?;
            if seen_confirmer.insert(conf.confirmer_pubkey) {
                return Ok(FinalityLevel::L0);
            }
        }
    }

    Ok(FinalityLevel::Pending)
}

/// Per-block-hash "highest seen" finality cache that wraps
/// [`assess_finality`] with monotonic semantics.
///
/// Once a block reaches a given finality level, subsequent calls
/// to [`FinalityLatch::assess_monotonic`] for that block return
/// at least that level — never lower, regardless of transient
/// sync glitches or vote / confirmation churn.
///
/// See HIGH-017 in the module docstring for the rationale.
#[derive(Debug, Clone, Default)]
pub struct FinalityLatch {
    /// Per-block-hash highest finality observed so far.
    seen: HashMap<[u8; 32], FinalityLevel>,
}

impl FinalityLatch {
    /// Create an empty latch. No blocks tracked initially.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct block hashes the latch is tracking.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the latch is tracking zero blocks.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Read-only accessor: the highest finality the latch has
    /// observed for `block_hash`, or `None` if it has never been
    /// assessed.
    pub fn get(&self, block_hash: &[u8; 32]) -> Option<FinalityLevel> {
        self.seen.get(block_hash).copied()
    }

    /// Assess `block_hash` against the same inputs as
    /// [`assess_finality`], and return the higher of (current
    /// snapshot, previously-latched value).
    ///
    /// On every call, `self.seen[block_hash]` is updated to the
    /// returned value — so once a block reaches L1, no subsequent
    /// call can return less than L1 for that block.
    ///
    /// # Errors
    ///
    /// Propagates any [`FinalityError`] from the underlying
    /// `assess_finality` (signature verification failures,
    /// invalid lengths, etc.). On error, the latch is **not**
    /// updated — the previous latched value (if any) is left
    /// untouched.
    pub fn assess_monotonic(
        &mut self,
        amount_micro_arx: u64,
        block_hash: [u8; 32],
        confirmations: &[SignedConfirmation],
        sync_result: &SyncResult,
        votes: &[SignedValidatorVote],
        registry: &ValidatorRegistry,
    ) -> Result<FinalityLevel, FinalityError> {
        let snapshot = assess_finality(
            amount_micro_arx,
            block_hash,
            confirmations,
            sync_result,
            votes,
            registry,
        )?;
        let previous = self
            .seen
            .get(&block_hash)
            .copied()
            .unwrap_or(FinalityLevel::Pending);
        let latched = std::cmp::max(previous, snapshot);
        self.seen.insert(block_hash, latched);
        Ok(latched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::{generate_keypair, sign};

    /// Build a SignedConfirmation: returns the confirmation and the
    /// confirmer pubkey for registry insertion.
    fn make_confirmation(block_hash: [u8; 32]) -> (SignedConfirmation, [u8; 32]) {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let canonical = SignedConfirmation::canonical_bytes(&pk, &block_hash);
        let sig = sign(&sk, &canonical);
        (
            SignedConfirmation {
                confirmer_pubkey: pk,
                block_hash,
                signature: sig.to_vec(),
            },
            pk,
        )
    }

    /// Build a SignedValidatorVote.
    fn make_vote(block_hash: [u8; 32]) -> (SignedValidatorVote, [u8; 32]) {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let canonical = SignedValidatorVote::canonical_bytes(&pk, &block_hash);
        let sig = sign(&sk, &canonical);
        (
            SignedValidatorVote {
                validator_pubkey: pk,
                block_hash,
                signature: sig.to_vec(),
            },
            pk,
        )
    }

    fn block_hash_a() -> [u8; 32] {
        [0xAAu8; 32]
    }

    fn block_hash_b() -> [u8; 32] {
        [0xBBu8; 32]
    }

    // ========================================================================
    // SignedConfirmation: verify and tamper paths
    // ========================================================================

    #[test]
    fn test_confirmation_canonical_bytes_layout() {
        let pk = [0x11u8; 32];
        let h = block_hash_a();
        let c = SignedConfirmation::canonical_bytes(&pk, &h);
        assert!(c.starts_with(FINALITY_CONFIRMATION_DOMAIN));
        assert_eq!(
            &c[FINALITY_CONFIRMATION_DOMAIN.len()..FINALITY_CONFIRMATION_DOMAIN.len() + 32],
            &pk
        );
        assert_eq!(&c[FINALITY_CONFIRMATION_DOMAIN.len() + 32..], &h);
        assert_eq!(c.len(), FINALITY_CONFIRMATION_DOMAIN.len() + 64);
    }

    #[test]
    fn test_confirmation_verify_passes_on_correct_signature() {
        let (c, _) = make_confirmation(block_hash_a());
        assert!(c.verify().is_ok());
    }

    #[test]
    fn test_confirmation_verify_rejects_zero_signature() {
        let (mut c, _) = make_confirmation(block_hash_a());
        c.signature = vec![0u8; 64];
        assert_eq!(c.verify(), Err(FinalityError::SignatureInvalid));
    }

    #[test]
    fn test_confirmation_verify_rejects_tampered_block_hash() {
        let (mut c, _) = make_confirmation(block_hash_a());
        c.block_hash = block_hash_b();
        assert_eq!(c.verify(), Err(FinalityError::SignatureInvalid));
    }

    #[test]
    fn test_confirmation_verify_rejects_wrong_signature_length() {
        let (mut c, _) = make_confirmation(block_hash_a());
        c.signature = vec![0u8; 32];
        assert_eq!(c.verify(), Err(FinalityError::InvalidSignatureLength));
    }

    // ========================================================================
    // SignedValidatorVote: verify and tamper paths
    // ========================================================================

    #[test]
    fn test_vote_canonical_bytes_layout() {
        let pk = [0x22u8; 32];
        let h = block_hash_a();
        let c = SignedValidatorVote::canonical_bytes(&pk, &h);
        assert!(c.starts_with(FINALITY_VALIDATOR_VOTE_DOMAIN));
        assert_eq!(c.len(), FINALITY_VALIDATOR_VOTE_DOMAIN.len() + 64);
    }

    #[test]
    fn test_vote_verify_passes_on_correct_signature() {
        let (v, _) = make_vote(block_hash_a());
        assert!(v.verify().is_ok());
    }

    #[test]
    fn test_vote_verify_rejects_zero_signature() {
        let (mut v, _) = make_vote(block_hash_a());
        v.signature = vec![0u8; 64];
        assert_eq!(v.verify(), Err(FinalityError::SignatureInvalid));
    }

    #[test]
    fn test_vote_verify_rejects_tampered_block_hash() {
        let (mut v, _) = make_vote(block_hash_a());
        v.block_hash = block_hash_b();
        assert_eq!(v.verify(), Err(FinalityError::SignatureInvalid));
    }

    #[test]
    fn test_domain_separation_prevents_confirmation_replayed_as_vote() {
        // Build a SignedConfirmation; copy its signature into a
        // SignedValidatorVote. The vote must not verify because the
        // domain prefix differs.
        let (c, pk) = make_confirmation(block_hash_a());
        let v = SignedValidatorVote {
            validator_pubkey: pk,
            block_hash: c.block_hash,
            signature: c.signature.clone(),
        };
        assert_eq!(v.verify(), Err(FinalityError::SignatureInvalid));
    }

    // ========================================================================
    // ValidatorRegistry
    // ========================================================================

    #[test]
    fn test_registry_total_stake_sums() {
        let mut r = ValidatorRegistry::new();
        r.insert([1u8; 32], 100);
        r.insert([2u8; 32], 200);
        r.insert([3u8; 32], 300);
        assert_eq!(r.total_stake(), 600);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn test_registry_total_stake_saturates_at_u64_max() {
        let mut r = ValidatorRegistry::new();
        r.insert([1u8; 32], u64::MAX);
        r.insert([2u8; 32], 1);
        assert_eq!(r.total_stake(), u64::MAX);
    }

    #[test]
    fn test_registry_overwrite_replaces_stake() {
        let mut r = ValidatorRegistry::new();
        r.insert([1u8; 32], 100);
        r.insert([1u8; 32], 999);
        assert_eq!(r.stake_of(&[1u8; 32]), Some(999));
        assert_eq!(r.len(), 1);
    }

    // ========================================================================
    // assess_finality: positive paths
    // ========================================================================

    #[test]
    fn test_assess_pending_when_amount_high_and_no_inputs() {
        let level = assess_finality(
            100_000_000,
            block_hash_a(),
            &[],
            &SyncResult::NoNeighbors,
            &[],
            &ValidatorRegistry::new(),
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::Pending);
    }

    #[test]
    fn test_assess_l0_with_one_valid_confirmation() {
        let h = block_hash_a();
        let (c, pk) = make_confirmation(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1);
        let level =
            assess_finality(5_000_000, h, &[c], &SyncResult::Mismatch(0), &[], &registry).unwrap();
        assert_eq!(level, FinalityLevel::L0);
    }

    #[test]
    fn test_assess_l1_when_sync_success() {
        // Even with no confirmations / no votes, L1 is granted by
        // SyncResult::Success.
        let level = assess_finality(
            5_000_000,
            block_hash_a(),
            &[],
            &SyncResult::Success,
            &[],
            &ValidatorRegistry::new(),
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::L1);
    }

    #[test]
    fn test_assess_l2_when_quorum_stake_voted() {
        // Two validators with equal stakes; both vote. 2/2 = 100% > 67%.
        let h = block_hash_a();
        let (v1, pk1) = make_vote(h);
        let (v2, pk2) = make_vote(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk1, 50);
        registry.insert(pk2, 50);
        let level = assess_finality(
            100_000_000,
            h,
            &[],
            &SyncResult::NoNeighbors,
            &[v1, v2],
            &registry,
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::L2);
    }

    #[test]
    fn test_assess_l2_takes_priority_over_l1_and_l0() {
        let h = block_hash_a();
        let (c, pk_c) = make_confirmation(h);
        let (v1, pk1) = make_vote(h);
        let (v2, pk2) = make_vote(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk_c, 1);
        registry.insert(pk1, 100);
        registry.insert(pk2, 100);
        let level = assess_finality(
            5_000_000,
            h,
            &[c],
            &SyncResult::Success,
            &[v1, v2],
            &registry,
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::L2);
    }

    // ========================================================================
    // assess_finality: CRIT-007 and CRIT-008 attack surface
    // ========================================================================

    #[test]
    fn test_assess_l2_rejected_when_validator_not_in_registry() {
        // CRIT-007 core attack: caller wants L2 but their "validators"
        // are not in the trusted registry. Should fall back to
        // Pending (no L2 stake counted, no L1 sync, no L0 conf).
        let h = block_hash_a();
        let (v1, _pk1) = make_vote(h);
        let (v2, _pk2) = make_vote(h);
        let registry = ValidatorRegistry::new();
        let level = assess_finality(
            100_000_000,
            h,
            &[],
            &SyncResult::NoNeighbors,
            &[v1, v2],
            &registry,
        )
        .unwrap();
        assert_eq!(
            level,
            FinalityLevel::Pending,
            "phantom validators must not promote to L2"
        );
    }

    #[test]
    fn test_assess_l2_rejected_with_phantom_stake_via_unauthenticated_input() {
        // The pre-fix API took validator_pct: f64 directly. With the
        // new API there is no scalar to fake — the function ONLY
        // knows about votes that match the registry. Any unsigned
        // float passed by the caller has nowhere to land. This test
        // pins the absence of that surface: even with the registry
        // populated, votes carrying a different block_hash are
        // ignored.
        let h = block_hash_a();
        let (v_for_other_block, pk1) = make_vote(block_hash_b());
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk1, 1000);
        let level = assess_finality(
            100_000_000,
            h,
            &[],
            &SyncResult::NoNeighbors,
            &[v_for_other_block],
            &registry,
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::Pending);
    }

    #[test]
    fn test_assess_l2_rejected_with_zero_signature_from_registered_validator() {
        // A registered validator signs wrong. This is loud failure:
        // misbehavior from a known key is actionable.
        let h = block_hash_a();
        let (mut v1, pk1) = make_vote(h);
        v1.signature = vec![0u8; 64];
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk1, 100);
        let err = assess_finality(
            100_000_000,
            h,
            &[],
            &SyncResult::NoNeighbors,
            &[v1],
            &registry,
        )
        .unwrap_err();
        assert_eq!(err, FinalityError::SignatureInvalid);
    }

    #[test]
    fn test_assess_l0_rejected_when_confirmer_not_in_registry() {
        // CRIT-008 core attack: caller wants L0 but their "confirmers"
        // are not in the trusted registry. Should fall back to
        // Pending.
        let h = block_hash_a();
        let (c, _pk) = make_confirmation(h);
        let registry = ValidatorRegistry::new();
        let level =
            assess_finality(5_000_000, h, &[c], &SyncResult::Mismatch(0), &[], &registry).unwrap();
        assert_eq!(
            level,
            FinalityLevel::Pending,
            "phantom confirmer must not promote to L0"
        );
    }

    #[test]
    fn test_assess_l0_rejected_with_zero_signature_from_registered_confirmer() {
        let h = block_hash_a();
        let (mut c, pk) = make_confirmation(h);
        c.signature = vec![0u8; 64];
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1);
        let err = assess_finality(5_000_000, h, &[c], &SyncResult::Mismatch(0), &[], &registry)
            .unwrap_err();
        assert_eq!(err, FinalityError::SignatureInvalid);
    }

    #[test]
    fn test_assess_l0_rejected_when_amount_above_cap() {
        let h = block_hash_a();
        let (c, pk) = make_confirmation(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1);
        let level = assess_finality(
            L0_CAP_MICRO_ARX + 1,
            h,
            &[c],
            &SyncResult::Mismatch(0),
            &[],
            &registry,
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::Pending);
    }

    // ============================================================
    // MED-010 (commit 064) — L0 cap boundary explicit pins.
    //
    // The cap is `<=` (line in `assess_finality`):
    //     if amount_micro_arx <= L0_CAP_MICRO_ARX { ... }
    // Without explicit boundary tests, a future refactor changing
    // `<=` to `<` would silently break wallets that send exactly
    // L0_CAP_MICRO_ARX (the documented "≤ 10 ARX" promise).
    // The pre-064 suite covered `+1` (rejected) but not `==`,
    // not `−1`, not `0`. These five tests close the boundary.
    // ============================================================

    #[test]
    fn test_assess_l0_at_exact_cap_boundary_accepted() {
        // PRIMARY MED-010 PIN: amount == L0_CAP_MICRO_ARX (10
        // ARX) must reach L0 with one valid confirmation. The
        // documented contract is "≤ 10 ARX" (inclusive).
        let h = block_hash_a();
        let (c, pk) = make_confirmation(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1);
        let level = assess_finality(
            L0_CAP_MICRO_ARX,
            h,
            &[c],
            &SyncResult::Mismatch(0),
            &[],
            &registry,
        )
        .unwrap();
        assert_eq!(
            level,
            FinalityLevel::L0,
            "amount == L0_CAP_MICRO_ARX must reach L0 (`<=`)"
        );
    }

    #[test]
    fn test_assess_l0_just_below_cap_accepted() {
        // amount == L0_CAP_MICRO_ARX − 1 → L0.
        let h = block_hash_a();
        let (c, pk) = make_confirmation(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1);
        let level = assess_finality(
            L0_CAP_MICRO_ARX - 1,
            h,
            &[c],
            &SyncResult::Mismatch(0),
            &[],
            &registry,
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::L0);
    }

    #[test]
    fn test_assess_l0_zero_amount_accepted() {
        // Edge: amount == 0 (a zero-value tx, e.g. a no-op
        // sentinel). With a valid confirmation and the cap
        // contract `0 <= L0_CAP_MICRO_ARX`, must reach L0. No
        // panic, no off-by-one.
        let h = block_hash_a();
        let (c, pk) = make_confirmation(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1);
        let level = assess_finality(0, h, &[c], &SyncResult::Mismatch(0), &[], &registry).unwrap();
        assert_eq!(level, FinalityLevel::L0);
    }

    #[test]
    fn test_assess_l0_just_above_cap_rejected() {
        // Symmetric to the existing _above_cap test, but pins
        // the exact boundary: cap+1 must NOT reach L0. Pinned
        // alongside _at_exact_cap (==) and _just_below
        // (cap−1) so the three values around the threshold
        // are all asserted in one place.
        let h = block_hash_a();
        let (c, pk) = make_confirmation(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1);
        let level = assess_finality(
            L0_CAP_MICRO_ARX + 1,
            h,
            &[c],
            &SyncResult::Mismatch(0),
            &[],
            &registry,
        )
        .unwrap();
        assert_eq!(
            level,
            FinalityLevel::Pending,
            "amount > L0_CAP_MICRO_ARX must NOT reach L0"
        );
    }

    #[test]
    fn test_l0_cap_constant_value_pinned() {
        // The cap value itself is a protocol constant. Pin it
        // here so changes to `arxia_core::constants` show up
        // as a finality-test failure, not silently shift the
        // L0 boundary in the field.
        assert_eq!(
            L0_CAP_MICRO_ARX, 10_000_000,
            "L0 cap is 10 ARX in micro-ARX (10 * 1_000_000)"
        );
    }

    #[test]
    fn test_assess_dedup_double_voting_validator() {
        // A validator submits the same vote twice. Their stake counts
        // ONCE, not twice — preventing a validator with 50% stake
        // from inflating to 100% via duplicate submissions.
        let h = block_hash_a();
        let (v, pk) = make_vote(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 50); // 50% stake
        registry.insert([0xFFu8; 32], 50); // dummy 50% so total = 100
        let level = assess_finality(
            100_000_000,
            h,
            &[],
            &SyncResult::NoNeighbors,
            &[v.clone(), v.clone(), v],
            &registry,
        )
        .unwrap();
        // 50% < 67% threshold → no L2.
        assert_eq!(level, FinalityLevel::Pending);
    }

    #[test]
    fn test_assess_l2_below_quorum_does_not_promote() {
        // 1/3 stake is below 67% threshold.
        let h = block_hash_a();
        let (v, pk1) = make_vote(h);
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk1, 100);
        registry.insert([0xFFu8; 32], 200);
        let level = assess_finality(
            100_000_000,
            h,
            &[],
            &SyncResult::NoNeighbors,
            &[v],
            &registry,
        )
        .unwrap();
        // 100/300 ≈ 33% < 67% → not L2.
        assert_eq!(level, FinalityLevel::Pending);
    }

    #[test]
    fn test_assess_filters_votes_for_other_blocks_silently() {
        let h = block_hash_a();
        let (v_other, pk) = make_vote(block_hash_b());
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1000);
        let level = assess_finality(
            100_000_000,
            h,
            &[],
            &SyncResult::NoNeighbors,
            &[v_other],
            &registry,
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::Pending);
    }

    #[test]
    fn test_assess_filters_confirmations_for_other_blocks_silently() {
        let h = block_hash_a();
        let (c_other, pk) = make_confirmation(block_hash_b());
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 1);
        let level = assess_finality(
            5_000_000,
            h,
            &[c_other],
            &SyncResult::Mismatch(0),
            &[],
            &registry,
        )
        .unwrap();
        assert_eq!(level, FinalityLevel::Pending);
    }

    #[test]
    fn test_finality_ordering() {
        assert!(FinalityLevel::Pending < FinalityLevel::L0);
        assert!(FinalityLevel::L0 < FinalityLevel::L1);
        assert!(FinalityLevel::L1 < FinalityLevel::L2);
    }

    #[test]
    fn test_l2_quorum_fraction_constant_pinned() {
        assert!((L2_QUORUM_FRACTION - 0.67).abs() < 1e-9);
    }

    // ========================================================================
    // FinalityLatch — HIGH-017 monotonic finality (commit 042).
    //
    // Once a block reaches level L, subsequent assessments must
    // return ≥ L for that block. A sync glitch / vote churn /
    // confirmation drop must NOT regress the latched value.
    // ========================================================================

    #[test]
    fn test_latch_starts_empty() {
        let latch = FinalityLatch::new();
        assert!(latch.is_empty());
        assert_eq!(latch.len(), 0);
        assert_eq!(latch.get(&block_hash_a()), None);
    }

    #[test]
    fn test_latch_default_equals_new() {
        let l1 = FinalityLatch::default();
        let l2 = FinalityLatch::new();
        assert!(l1.is_empty());
        assert_eq!(l1.len(), l2.len());
    }

    #[test]
    fn test_latch_first_assessment_returns_snapshot_value() {
        // Positive baseline: first call to assess_monotonic on a
        // never-seen block returns the same level
        // assess_finality would.
        let h = block_hash_a();
        let mut latch = FinalityLatch::new();
        let level = latch
            .assess_monotonic(
                100_000_000,
                h,
                &[],
                &SyncResult::NoNeighbors,
                &[],
                &ValidatorRegistry::new(),
            )
            .unwrap();
        assert_eq!(level, FinalityLevel::Pending);
        assert_eq!(latch.get(&h), Some(FinalityLevel::Pending));
        assert_eq!(latch.len(), 1);
    }

    #[test]
    fn test_latch_l1_does_not_regress_to_l0() {
        // PRIMARY HIGH-017 PIN: the audit's exact attack scenario.
        //
        // Step 1: a block at the L0-cap with one valid local
        // confirmation, sync_result = Mismatch → L0.
        //
        // Wait, the audit specifies L1 → L0 regression. Let's set
        // up L1 first via SyncResult::Success, then trigger
        // SyncResult::Mismatch.
        let h = block_hash_a();
        let registry = ValidatorRegistry::new();
        let mut latch = FinalityLatch::new();

        // Phase 1: sync says Success → L1.
        let level = latch
            .assess_monotonic(100_000_000, h, &[], &SyncResult::Success, &[], &registry)
            .unwrap();
        assert_eq!(level, FinalityLevel::L1, "phase 1 must reach L1");
        assert_eq!(latch.get(&h), Some(FinalityLevel::L1));

        // Phase 2: sync glitches to Mismatch. assess_finality
        // alone would return Pending now (no confirmations, no
        // votes, large amount). The latch must keep L1.
        let level = latch
            .assess_monotonic(
                100_000_000,
                h,
                &[],
                &SyncResult::Mismatch(0),
                &[],
                &registry,
            )
            .unwrap();
        assert_eq!(
            level,
            FinalityLevel::L1,
            "HIGH-017: latch must not regress L1 → Pending after sync glitch"
        );
        assert_eq!(latch.get(&h), Some(FinalityLevel::L1));
    }

    #[test]
    fn test_latch_l2_does_not_regress_to_anything_lower() {
        // Stress: reach L2 via stake-weighted quorum, then hit it
        // with the worst possible glitch (no votes, no
        // confirmations, sync mismatch, large amount). Latch must
        // hold L2.
        let h = block_hash_a();
        let mut registry = ValidatorRegistry::new();

        // 5 validators, each with 25% stake = 125% total. Need 3
        // votes for ≥67%.
        let (v1, pk1) = make_vote(h);
        let (v2, pk2) = make_vote(h);
        let (v3, pk3) = make_vote(h);
        let (v4, pk4) = make_vote(h);
        let (_v5, pk5) = make_vote(h);
        registry.insert(pk1, 25);
        registry.insert(pk2, 25);
        registry.insert(pk3, 25);
        registry.insert(pk4, 25);
        registry.insert(pk5, 25);

        let mut latch = FinalityLatch::new();
        let level = latch
            .assess_monotonic(
                100_000_000,
                h,
                &[],
                &SyncResult::Mismatch(0),
                &[v1, v2, v3, v4],
                &registry,
            )
            .unwrap();
        assert_eq!(level, FinalityLevel::L2, "phase 1 must reach L2");

        // Worst-case glitch: no votes, no confirmations, sync
        // mismatch.
        let level = latch
            .assess_monotonic(
                100_000_000,
                h,
                &[],
                &SyncResult::Mismatch(0),
                &[],
                &registry,
            )
            .unwrap();
        assert_eq!(
            level,
            FinalityLevel::L2,
            "HIGH-017: latch must not regress L2 → Pending after total vote loss"
        );
    }

    #[test]
    fn test_latch_legitimate_upgrade_promotes() {
        // Latch must NOT block legitimate upward transitions.
        // Pending → L1 → L2 over three calls.
        let h = block_hash_a();
        let mut registry = ValidatorRegistry::new();
        let (vote, pk) = make_vote(h);
        registry.insert(pk, 100);

        let mut latch = FinalityLatch::new();

        // Phase 1: Pending.
        let level = latch
            .assess_monotonic(
                100_000_000,
                h,
                &[],
                &SyncResult::NoNeighbors,
                &[],
                &registry,
            )
            .unwrap();
        assert_eq!(level, FinalityLevel::Pending);

        // Phase 2: L1 (sync success).
        let level = latch
            .assess_monotonic(100_000_000, h, &[], &SyncResult::Success, &[], &registry)
            .unwrap();
        assert_eq!(level, FinalityLevel::L1);

        // Phase 3: L2 (single validator with 100% stake).
        let level = latch
            .assess_monotonic(
                100_000_000,
                h,
                &[],
                &SyncResult::Success,
                &[vote],
                &registry,
            )
            .unwrap();
        assert_eq!(level, FinalityLevel::L2);
    }

    #[test]
    fn test_latch_tracks_two_blocks_independently() {
        // The "highest seen" cache is per-block-hash. Promoting
        // block A to L1 must NOT promote block B.
        let ha = block_hash_a();
        let hb = block_hash_b();
        let registry = ValidatorRegistry::new();
        let mut latch = FinalityLatch::new();

        // Block A reaches L1.
        latch
            .assess_monotonic(100_000_000, ha, &[], &SyncResult::Success, &[], &registry)
            .unwrap();
        // Block B has no inputs → Pending.
        let level_b = latch
            .assess_monotonic(
                100_000_000,
                hb,
                &[],
                &SyncResult::Mismatch(0),
                &[],
                &registry,
            )
            .unwrap();
        assert_eq!(level_b, FinalityLevel::Pending);
        assert_eq!(latch.get(&ha), Some(FinalityLevel::L1));
        assert_eq!(latch.get(&hb), Some(FinalityLevel::Pending));
        assert_eq!(latch.len(), 2);
    }

    #[test]
    fn test_latch_propagates_signature_error_without_updating() {
        // If assess_finality returns Err (a registered validator's
        // signature is bad), the latch must propagate the error
        // AND leave the previously-latched value untouched. This
        // pins the "errors don't poison the cache" contract.
        let h = block_hash_a();
        let (mut bad_vote, pk) = make_vote(h);
        bad_vote.signature = vec![0u8; 64]; // invalid sig
        let mut registry = ValidatorRegistry::new();
        registry.insert(pk, 100);

        let mut latch = FinalityLatch::new();

        // Phase 1: legitimate L1.
        latch
            .assess_monotonic(100_000_000, h, &[], &SyncResult::Success, &[], &registry)
            .unwrap();
        assert_eq!(latch.get(&h), Some(FinalityLevel::L1));

        // Phase 2: bad vote triggers FinalityError. The latch must
        // not have been updated.
        let result = latch.assess_monotonic(
            100_000_000,
            h,
            &[],
            &SyncResult::Success,
            &[bad_vote],
            &registry,
        );
        assert!(result.is_err());
        // Latched value is still L1 from phase 1.
        assert_eq!(
            latch.get(&h),
            Some(FinalityLevel::L1),
            "errors must not corrupt the latch state"
        );
    }
}
