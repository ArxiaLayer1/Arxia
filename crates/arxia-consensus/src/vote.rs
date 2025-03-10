//! Vote structure and cryptographic operations for ORV.

use arxia_core::ArxiaError;
use ed25519_dalek::SigningKey;

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
pub fn verify_vote(vote: &VoteORV) -> Result<(), ArxiaError> {
    let hash = compute_vote_hash(
        &vote.block_hash,
        &vote.voter_pubkey,
        vote.delegated_stake,
        vote.nonce,
    );
    arxia_crypto::verify(&vote.voter_pubkey, &hash, &vote.signature)
}

/// Creates and signs a new vote for a block.
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
}
