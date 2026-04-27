//! Vote structure and cryptographic operations for ORV.
//!
//! # Ingress contract — votes must reference known blocks (HIGH-006, commit 034)
//!
//! [`cast_vote`] constructs and signs a vote locally. It does not
//! check that the target block is in any block store: the caller
//! is the validator itself, voting on a block it has just produced
//! or just verified, and a runtime cross-check would be redundant.
//!
//! Ingress is a different story. When a vote arrives over the wire
//! (gossip, sync, mailbox) the receiver MUST refuse votes that
//! reference a `block_hash` it has never seen. Without this check,
//! a representative with stake can sign a self-consistent vote whose
//! target is phantom — and `resolve_conflict_orv` will count that
//! stake against a competing block in the cascade. The audit calls
//! this HIGH-006: "votes for unknown blocks".
//!
//! [`verify_vote_known`] is the ingress entry point. It performs the
//! signature check (delegated to [`verify_vote`]) and then verifies
//! that `vote.block_hash` is in the supplied `known_blocks` set. The
//! `known_blocks` set is the receiver's local block store keyed by
//! Blake3 hash. Order of checks: signature first (cheap rejection of
//! malformed votes), inclusion second (defends valid-signature votes
//! whose target is phantom).
//!
//! Refs: PHASE1_AUDIT_REPORT.md HIGH-006.

use arxia_core::ArxiaError;
use ed25519_dalek::SigningKey;
use std::collections::HashSet;

/// A single ORV vote from a representative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteORV {
    /// The Blake3 hash of the block being voted on.
    pub block_hash: [u8; 32],
    /// The Ed25519 public key of the voting representative.
    pub voter_pubkey: [u8; 32],
    /// Amount of stake (in micro-ARX) delegated to this representative.
    pub delegated_stake: u64,
    /// Monotonic nonce to prevent vote replay attacks.
    pub nonce: u64,
    /// Ed25519 signature over the vote hash.
    pub signature: [u8; 64],
}

/// Computes the Blake3 hash of a vote content.
pub fn compute_vote_hash(
    block_hash: &[u8; 32],
    voter_pubkey: &[u8; 32],
    delegated_stake: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(block_hash);
    data.extend_from_slice(voter_pubkey);
    data.extend_from_slice(&delegated_stake.to_le_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    let hash = blake3::hash(&data);
    *hash.as_bytes()
}

/// Verifies the cryptographic signature on a vote.
///
/// This is *self-consistency only*: the signature is valid against
/// the voter's pubkey for the vote contents. It does NOT check that
/// the block referenced by the vote actually exists locally. For
/// ingress validation, use [`verify_vote_known`].
pub fn verify_vote(vote: &VoteORV) -> Result<(), ArxiaError> {
    let hash = compute_vote_hash(
        &vote.block_hash,
        &vote.voter_pubkey,
        vote.delegated_stake,
        vote.nonce,
    );
    arxia_crypto::verify(&vote.voter_pubkey, &hash, &vote.signature)
}

/// Ingress validation for a received vote: signature + inclusion.
///
/// Verifies (1) that the vote's signature is valid against the
/// voter's pubkey, and (2) that `vote.block_hash` is present in the
/// local `known_blocks` set. If either check fails, the vote is
/// rejected with a typed error:
///
/// - `Err(ArxiaError::SignatureInvalid(_))` — signature mismatch.
///   Returned first for cheap rejection.
/// - `Err(ArxiaError::UnknownVoteTarget { block_hash })` — signature
///   ok but the targeted block is not in `known_blocks`. This pins
///   HIGH-006: a representative cannot cast a vote whose target the
///   receiver has never seen.
///
/// Callers (gossip ingress, sync mailbox, RPC) must invoke this
/// instead of bare [`verify_vote`] for any vote received from
/// outside the local node.
pub fn verify_vote_known(
    vote: &VoteORV,
    known_blocks: &HashSet<[u8; 32]>,
) -> Result<(), ArxiaError> {
    verify_vote(vote)?;
    if !known_blocks.contains(&vote.block_hash) {
        return Err(ArxiaError::UnknownVoteTarget {
            block_hash: hex::encode(vote.block_hash),
        });
    }
    Ok(())
}

/// Creates and signs a new vote for a block.
///
/// **Local-only construction.** The caller is the validator
/// producing its own vote on a block it has just verified or
/// produced; this function performs no inclusion check. For
/// validation of *received* votes (gossip, sync), use
/// [`verify_vote_known`].
pub fn cast_vote(
    signing_key: &SigningKey,
    block_hash: [u8; 32],
    delegated_stake: u64,
    nonce: u64,
) -> VoteORV {
    let voter_pubkey = signing_key.verifying_key().to_bytes();
    let hash = compute_vote_hash(&block_hash, &voter_pubkey, delegated_stake, nonce);
    let signature = arxia_crypto::sign(signing_key, &hash);
    VoteORV {
        block_hash,
        voter_pubkey,
        delegated_stake,
        nonce,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::generate_keypair;

    #[test]
    fn test_compute_vote_hash_deterministic() {
        let h1 = compute_vote_hash(&[0xAB; 32], &[0xCD; 32], 1_000_000, 42);
        let h2 = compute_vote_hash(&[0xAB; 32], &[0xCD; 32], 1_000_000, 42);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_cast_and_verify_vote() {
        let (sk, vk) = generate_keypair();
        let vote = cast_vote(&sk, [0x12; 32], 5_000_000, 1);
        assert_eq!(vote.voter_pubkey, vk.to_bytes());
        assert!(verify_vote(&vote).is_ok());
    }

    #[test]
    fn test_verify_vote_rejects_tampered() {
        let (sk, _) = generate_keypair();
        let mut vote = cast_vote(&sk, [0x12; 32], 1_000_000, 1);
        vote.block_hash = [0xFF; 32];
        assert!(verify_vote(&vote).is_err());
    }

    // ============================================================
    // HIGH-006 (commit 034) — verify_vote_known rejects votes
    // whose block_hash is not in the local block store.
    // ============================================================

    #[test]
    fn test_verify_vote_known_accepts_valid_known_vote() {
        // Positive path: vote for a block the receiver knows about.
        let (sk, _) = generate_keypair();
        let bh = [0x12; 32];
        let vote = cast_vote(&sk, bh, 1_000_000, 1);
        let mut known = HashSet::new();
        known.insert(bh);
        assert!(verify_vote_known(&vote, &known).is_ok());
    }

    #[test]
    fn test_verify_vote_known_rejects_unknown_block() {
        // HIGH-006 PIN: signature is valid (vote is self-consistent)
        // but the target block hash is not in the local store. The
        // pre-fix code path (calling bare verify_vote) would accept
        // this. verify_vote_known must reject with
        // UnknownVoteTarget.
        let (sk, _) = generate_keypair();
        let phantom_hash = [0xDE; 32];
        let vote = cast_vote(&sk, phantom_hash, 1_000_000, 1);
        // Receiver's block store does NOT contain phantom_hash.
        let mut known = HashSet::new();
        known.insert([0xAA; 32]);
        known.insert([0xBB; 32]);
        let err = verify_vote_known(&vote, &known)
            .expect_err("HIGH-006: phantom-target vote must be rejected");
        match err {
            ArxiaError::UnknownVoteTarget { block_hash } => {
                assert_eq!(block_hash, hex::encode(phantom_hash));
            }
            other => panic!("expected UnknownVoteTarget, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_vote_known_rejects_invalid_signature_before_inclusion_check() {
        // Order matters: signature is checked first. A vote with a
        // tampered block_hash fails the signature check (cheap
        // rejection) and never reaches the inclusion check, even if
        // the (now-tampered) block_hash happens to be in
        // known_blocks.
        let (sk, _) = generate_keypair();
        let original = [0x12; 32];
        let mut vote = cast_vote(&sk, original, 1_000_000, 1);
        let tampered = [0xFF; 32];
        vote.block_hash = tampered;
        // Receiver knows the tampered hash (worst case for ordering).
        let mut known = HashSet::new();
        known.insert(tampered);
        let err = verify_vote_known(&vote, &known).expect_err("tampered signature must reject");
        match err {
            ArxiaError::SignatureInvalid(_) => {} // expected
            ArxiaError::UnknownVoteTarget { .. } => {
                panic!("inclusion check must not run before signature check");
            }
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_vote_known_rejects_when_known_set_is_empty() {
        // Edge case: empty block store rejects ALL votes regardless
        // of signature validity. This pins the contract that an
        // un-bootstrapped node cannot be tricked into counting any
        // received vote.
        let (sk, _) = generate_keypair();
        let bh = [0x12; 32];
        let vote = cast_vote(&sk, bh, 1_000_000, 1);
        let known: HashSet<[u8; 32]> = HashSet::new();
        let err = verify_vote_known(&vote, &known).expect_err("empty known_blocks must reject");
        assert!(matches!(err, ArxiaError::UnknownVoteTarget { .. }));
    }

    #[test]
    fn test_verify_vote_known_handles_multiple_votes_targeting_distinct_blocks() {
        // A receiver with 3 known blocks accepts votes for any of
        // them and rejects votes for any other block. Pins that the
        // inclusion check is membership-based (not first-element or
        // last-element).
        let (sk, _) = generate_keypair();
        let h1 = [0x11; 32];
        let h2 = [0x22; 32];
        let h3 = [0x33; 32];
        let phantom = [0x99; 32];
        let mut known = HashSet::new();
        known.insert(h1);
        known.insert(h2);
        known.insert(h3);
        let v1 = cast_vote(&sk, h1, 1_000_000, 1);
        let v2 = cast_vote(&sk, h2, 1_000_000, 2);
        let v3 = cast_vote(&sk, h3, 1_000_000, 3);
        let v_phantom = cast_vote(&sk, phantom, 1_000_000, 4);
        assert!(verify_vote_known(&v1, &known).is_ok());
        assert!(verify_vote_known(&v2, &known).is_ok());
        assert!(verify_vote_known(&v3, &known).is_ok());
        let err = verify_vote_known(&v_phantom, &known).expect_err("phantom must reject");
        assert!(matches!(err, ArxiaError::UnknownVoteTarget { .. }));
    }
}
