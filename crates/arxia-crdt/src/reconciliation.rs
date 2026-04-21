//! Partition reconciliation using CRDTs and Block Lattice data.

use crate::pn_counter::PNCounter;
use arxia_lattice::block::{Block, BlockType};
use std::collections::HashMap;

/// Reconcile two partitions into merged balances via PNCounter CRDT.
pub fn reconcile_partitions(partition_a: &[Block], partition_b: &[Block]) -> HashMap<String, i64> {
    let mut crdts: HashMap<String, PNCounter> = HashMap::new();
    let mut seen: Vec<String> = Vec::new();
    let all: Vec<&Block> = partition_a
        .iter()
        .chain(partition_b.iter())
        .filter(|b| {
            if seen.contains(&b.hash) {
                false
            } else {
                seen.push(b.hash.clone());
                true
            }
        })
        .collect();
    for block in &all {
        match &block.block_type {
            BlockType::Open { initial_balance } => {
                crdts
                    .entry(block.account.clone())
                    .or_default()
                    .increment(&block.account[..8], *initial_balance);
            }
            BlockType::Send { amount, .. } => {
                crdts
                    .entry(block.account.clone())
                    .or_default()
                    .decrement(&block.account[..8], *amount);
            }
            BlockType::Receive { .. } => {
                let recv = block.balance;
                let prev = partition_a
                    .iter()
                    .chain(partition_b.iter())
                    .filter(|b| b.account == block.account && b.nonce == block.nonce - 1)
                    .map(|b| b.balance)
                    .next()
                    .unwrap_or(0);
                if recv > prev {
                    crdts
                        .entry(block.account.clone())
                        .or_default()
                        .increment(&block.account[..8], recv - prev);
                }
            }
            BlockType::Revoke { .. } => {}
        }
    }
    crdts.iter().map(|(a, c)| (a.clone(), c.value())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_lattice::chain::{AccountChain, VectorClock};

    #[test]
    fn test_reconcile_identical_partitions() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        let result = reconcile_partitions(&alice.chain, &alice.chain);
        assert_eq!(result[alice.id()], 1_000_000);
    }

    #[test]
    fn test_reconcile_empty_partitions() {
        let result = reconcile_partitions(&[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_reconcile_disjoint_partitions() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc).unwrap();
        bob.open(500_000, &mut vc).unwrap();
        let result = reconcile_partitions(&alice.chain, &bob.chain);
        assert_eq!(result[alice.id()], 1_000_000);
        assert_eq!(result[bob.id()], 500_000);
    }
}
