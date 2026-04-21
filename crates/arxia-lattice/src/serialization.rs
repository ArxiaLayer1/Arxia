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
}
