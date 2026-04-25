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

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, HashSet};

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
}
