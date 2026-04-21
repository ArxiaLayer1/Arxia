//! Compact binary serialization (193 bytes per block) for LoRa transport.
//!
//! Layout: [1B type][32B account][32B prev_hash][8B balance][8B nonce]
//! [8B timestamp][8B amount/initial][32B dest_or_source][64B signature]

use crate::block::{Block, BlockType};
use arxia_core::{ArxiaError, COMPACT_BLOCK_SIZE};

/// Serialize a block to compact binary format (193 bytes).
pub fn to_compact_bytes(block: &Block) -> Vec<u8> {
    let mut buf = Vec::with_capacity(COMPACT_BLOCK_SIZE);
    match &block.block_type {
        BlockType::Open { .. } => buf.push(0x00),
        BlockType::Send { .. } => buf.push(0x01),
        BlockType::Receive { .. } => buf.push(0x02),
        BlockType::Revoke { .. } => buf.push(0x03),
    }
    let account_bytes = hex::decode(&block.account).unwrap_or_else(|_| vec![0u8; 32]);
    buf.extend_from_slice(&account_bytes[..32]);
    if block.previous.is_empty() {
        buf.extend_from_slice(&[0u8; 32]);
    } else {
        let prev = hex::decode(&block.previous).unwrap_or_else(|_| vec![0u8; 32]);
        buf.extend_from_slice(&prev[..32]);
    }
    buf.extend_from_slice(&block.balance.to_be_bytes());
    buf.extend_from_slice(&block.nonce.to_be_bytes());
    buf.extend_from_slice(&block.timestamp.to_be_bytes());
    match &block.block_type {
        BlockType::Open { initial_balance } => {
            buf.extend_from_slice(&initial_balance.to_be_bytes())
        }
        BlockType::Send { amount, .. } => buf.extend_from_slice(&amount.to_be_bytes()),
        _ => buf.extend_from_slice(&0u64.to_be_bytes()),
    }
    match &block.block_type {
        BlockType::Send { destination, .. } => {
            let d = hex::decode(destination).unwrap_or_else(|_| vec![0u8; 32]);
            buf.extend_from_slice(&d[..32]);
        }
        BlockType::Receive { source_hash } => {
            let s = hex::decode(source_hash).unwrap_or_else(|_| vec![0u8; 32]);
            buf.extend_from_slice(&s[..32]);
        }
        BlockType::Revoke { credential_hash } => {
            let r = hex::decode(credential_hash).unwrap_or_else(|_| vec![0u8; 32]);
            buf.extend_from_slice(&r[..32]);
        }
        BlockType::Open { .. } => buf.extend_from_slice(&[0u8; 32]),
    }
    if block.signature.len() == 64 {
        buf.extend_from_slice(&block.signature);
    } else {
        buf.extend_from_slice(&[0u8; 64]);
    }
    buf
}

/// Deserialize a block from compact binary format (193 bytes).
pub fn from_compact_bytes(data: &[u8]) -> Result<Block, ArxiaError> {
    if data.len() < COMPACT_BLOCK_SIZE {
        return Err(ArxiaError::DataTooShort {
            got: data.len(),
            expected: COMPACT_BLOCK_SIZE,
        });
    }
    let tag = data[0];
    let account = hex::encode(&data[1..33]);
    let prev_raw = &data[33..65];
    let previous = if prev_raw.iter().all(|&b| b == 0) {
        String::new()
    } else {
        hex::encode(prev_raw)
    };
    let balance = u64::from_be_bytes(data[65..73].try_into().expect("8 bytes"));
    let nonce = u64::from_be_bytes(data[73..81].try_into().expect("8 bytes"));
    let timestamp = u64::from_be_bytes(data[81..89].try_into().expect("8 bytes"));
    let amount = u64::from_be_bytes(data[89..97].try_into().expect("8 bytes"));
    let dest_src = hex::encode(&data[97..129]);
    let signature = data[129..193].to_vec();
    let block_type = match tag {
        0x00 => BlockType::Open {
            initial_balance: amount,
        },
        0x01 => BlockType::Send {
            destination: dest_src,
            amount,
        },
        0x02 => BlockType::Receive {
            source_hash: dest_src,
        },
        0x03 => BlockType::Revoke {
            credential_hash: dest_src,
        },
        t => return Err(ArxiaError::InvalidBlockType(t)),
    };
    // CRITICAL: the hash is recomputed from the timestamp contained in the
    // data bytes, NOT from a fresh SystemTime::now(). This guarantees the
    // hash is a pure function of the serialized payload and is identical
    // across nodes with out-of-sync clocks. Regression tests below pin
    // this property.
    let hash = Block::compute_hash(&account, &previous, &block_type, balance, nonce, timestamp);
    Ok(Block {
        account,
        previous,
        block_type,
        balance,
        nonce,
        timestamp,
        hash,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{AccountChain, VectorClock};

    #[test]
    fn test_compact_round_trip_open() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let bytes = to_compact_bytes(&block);
        assert_eq!(bytes.len(), COMPACT_BLOCK_SIZE);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.balance, block.balance);
        assert_eq!(restored.nonce, block.nonce);
    }

    #[test]
    fn test_compact_round_trip_send() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        chain.open(1_000_000, &mut vc).unwrap();
        let send = chain.send(&"ab".repeat(32), 500_000, &mut vc).unwrap();
        let bytes = to_compact_bytes(&send);
        assert_eq!(bytes.len(), COMPACT_BLOCK_SIZE);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.balance, send.balance);
    }

    #[test]
    fn test_compact_size_193_bytes() {
        assert_eq!(COMPACT_BLOCK_SIZE, 193);
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(42, &mut vc).unwrap();
        assert_eq!(to_compact_bytes(&block).len(), 193);
    }

    #[test]
    fn test_from_compact_too_short() {
        let data = vec![0u8; 100];
        assert!(from_compact_bytes(&data).is_err());
    }

    // ========================================================================
    // Regression guards for Bug 6 — timestamp-in-hash concern
    //
    // stoneburner suggested that nodes with out-of-sync clocks would
    // compute different hashes for the same block. This was NOT true of
    // the code as written: compute_hash takes `timestamp` as a
    // parameter, and from_compact_bytes reads it from the serialized
    // payload. The hash is therefore a pure function of the bytes.
    //
    // The tests below pin that property so any future refactor that
    // replaces `timestamp` with a fresh `SystemTime::now()` call fails
    // loudly.
    // ========================================================================

    #[test]
    fn test_hash_is_deterministic_across_round_trip() {
        // Same bytes in, same hash out. Always.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let original_hash = block.hash.clone();
        let original_ts = block.timestamp;
        let bytes = to_compact_bytes(&block);
        let restored = from_compact_bytes(&bytes).unwrap();
        assert_eq!(restored.hash, original_hash);
        assert_eq!(restored.timestamp, original_ts);
    }

    #[test]
    fn test_hash_stable_across_delayed_deserialization() {
        // Simulates "same bytes received hours later on a different node":
        // we deserialize multiple times, possibly with a real delay between
        // calls. Every deserialization produces the identical hash.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let bytes = to_compact_bytes(&block);
        let h1 = from_compact_bytes(&bytes).unwrap().hash;
        std::thread::sleep(std::time::Duration::from_millis(10));
        let h2 = from_compact_bytes(&bytes).unwrap().hash;
        std::thread::sleep(std::time::Duration::from_millis(10));
        let h3 = from_compact_bytes(&bytes).unwrap().hash;
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
        assert_eq!(h1, block.hash);
    }

    #[test]
    fn test_hash_changes_when_timestamp_bytes_are_mutated() {
        // Adversarial: tamper with only the timestamp bytes in the
        // serialized form. The recomputed hash must differ, which means
        // verify_block (elsewhere) will reject the block on HashMismatch.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let mut bytes = to_compact_bytes(&block);
        // Bytes 81..89 are the timestamp. Flip the low-order byte.
        bytes[88] ^= 0xFF;
        let tampered = from_compact_bytes(&bytes).unwrap();
        assert_ne!(tampered.hash, block.hash);
        // The stored signature in tampered is still the original one;
        // verify_block would catch the mismatch on the very next check.
    }

    #[test]
    fn test_two_nodes_compute_same_hash_for_same_bytes() {
        // Explicit multi-"node" simulation: node A serializes, node B
        // deserializes on the same bytes. Hashes match regardless of
        // wall-clock drift between them.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block_a = chain.open(1_000_000, &mut vc).unwrap();
        let wire = to_compact_bytes(&block_a);
        // "Node B" deserializes fresh
        let block_b = from_compact_bytes(&wire).unwrap();
        assert_eq!(block_a.hash, block_b.hash);
        assert_eq!(block_a.account, block_b.account);
        assert_eq!(block_a.timestamp, block_b.timestamp);
    }

    #[test]
    fn test_explicit_timestamp_control_produces_stable_hash() {
        // Pin the property even more explicitly: computing the hash
        // directly via Block::compute_hash with a given timestamp yields
        // exactly the hash stored in the corresponding Block struct.
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc).unwrap();
        let recomputed = Block::compute_hash(
            &block.account,
            &block.previous,
            &block.block_type,
            block.balance,
            block.nonce,
            block.timestamp,
        );
        assert_eq!(recomputed, block.hash);
    }
}
