//! Conflict resolution with 3-tier ORV cascade.

use crate::vote::VoteORV;
use arxia_lattice::block::Block;
use std::collections::HashMap;

/// A block candidate paired with its supporting votes.
#[derive(Debug)]
pub struct BlockCandidate<'a> {
    /// The candidate block.
    pub block: &'a Block,
    /// Votes supporting this block.
    pub votes: &'a [VoteORV],
}

/// Resolves a conflict between two competing blocks using 3-tier ORV cascade.
pub fn resolve_conflict_orv<'a>(
    block_a: &'a Block,
    block_b: &'a Block,
    votes_a: &[VoteORV],
    votes_b: &[VoteORV],
) -> (&'a Block, &'static str) {
    let stake_a: u64 = votes_a.iter().map(|v| v.delegated_stake).sum();
    let stake_b: u64 = votes_b.iter().map(|v| v.delegated_stake).sum();
    let total_stake = stake_a.saturating_add(stake_b);

    if total_stake > 0 {
        let gap = if stake_a > stake_b {
            stake_a - stake_b
        } else {
            stake_b - stake_a
        };
        if gap.saturating_mul(20) > total_stake {
            if stake_a > stake_b {
                return (block_a, "stake_weighted");
            } else {
                return (block_b, "stake_weighted");
            }
        }
    }

    if block_a.hash <= block_b.hash {
        (block_a, "hash_tiebreaker")
    } else {
        (block_b, "hash_tiebreaker")
    }
}

/// Detects double-spend conflicts among a set of blocks.
pub fn detect_double_spend(blocks: &[Block]) -> Vec<(Block, Block, &'static str)> {
    let mut nonce_map: HashMap<(String, u64), Vec<&Block>> = HashMap::new();
    let mut conflicts = Vec::new();
    for block in blocks {
        nonce_map
            .entry((block.account.clone(), block.nonce))
            .or_default()
            .push(block);
    }
    for group in nonce_map.values() {
        if group.len() > 1 {
            conflicts.push((group[0].clone(), group[1].clone(), "same_nonce"));
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cast_vote;
    use arxia_crypto::generate_keypair;
    use arxia_lattice::chain::{AccountChain, VectorClock};

    #[test]
    fn test_resolve_conflict_stake_weighted() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let ba = alice.send(bob.id(), 10_000, &mut vclock).unwrap();
        alice.chain.pop();
        alice.balance += 10_000;
        alice.nonce -= 1;
        let bb = alice.send(carol.id(), 10_000, &mut vclock).unwrap();
        let (sk1, _) = generate_keypair();
        let (sk2, _) = generate_keypair();
        let ha: [u8; 32] = hex::decode(&ba.hash).unwrap().try_into().unwrap();
        let hb: [u8; 32] = hex::decode(&bb.hash).unwrap().try_into().unwrap();
        let va = vec![
            cast_vote(&sk1, ha, 10_000_000, 1),
            cast_vote(&sk2, ha, 10_000_000, 1),
        ];
        let vb = vec![cast_vote(&sk1, hb, 1_000_000, 2)];
        let (w, m) = resolve_conflict_orv(&ba, &bb, &va, &vb);
        assert_eq!(m, "stake_weighted");
        assert_eq!(w.hash, ba.hash);
    }

    #[test]
    fn test_detect_double_spend() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let bob = AccountChain::new();
        let carol = AccountChain::new();
        let ba = alice.send(bob.id(), 10_000, &mut vclock).unwrap();
        alice.chain.pop();
        alice.balance += 10_000;
        alice.nonce -= 1;
        let bb = alice.send(carol.id(), 10_000, &mut vclock).unwrap();
        let conflicts = detect_double_spend(&[ba, bb]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].2, "same_nonce");
    }

    #[test]
    fn test_detect_no_double_spend() {
        let mut alice = AccountChain::new();
        let mut vclock = VectorClock::new();
        alice.open(100_000_000, &mut vclock).unwrap();
        let bob = AccountChain::new();
        let b1 = alice.send(bob.id(), 10_000, &mut vclock).unwrap();
        let b2 = alice.send(bob.id(), 20_000, &mut vclock).unwrap();
        assert!(detect_double_spend(&[b1, b2]).is_empty());
    }
}
