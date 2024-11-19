//! Block and chain validation.

use crate::block::{Block, BlockType};
use arxia_core::ArxiaError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify a single block hash and Ed25519 signature.
pub fn verify_block(block: &Block) -> Result<(), ArxiaError> {
    let expected_hash = Block::compute_hash(
        &block.account,
        &block.previous,
        &block.block_type,
        block.balance,
        block.nonce,
        block.timestamp,
    );
    if expected_hash != block.hash {
        return Err(ArxiaError::HashMismatch);
    }
    let pubkey_bytes: [u8; 32] = hex::decode(&block.account)
        .map_err(|e| ArxiaError::InvalidKey(e.to_string()))?
        .try_into()
        .map_err(|_| ArxiaError::InvalidKey("bad key length".into()))?;
    let vk = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| ArxiaError::InvalidKey(e.to_string()))?;
    let sig_bytes: [u8; 64] = block
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ArxiaError::SignatureInvalid("bad sig length".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    let hash_bytes =
        hex::decode(&block.hash).map_err(|e| ArxiaError::SignatureInvalid(e.to_string()))?;
    vk.verify(&hash_bytes, &signature)
        .map_err(|e| ArxiaError::SignatureInvalid(e.to_string()))?;
    Ok(())
}

/// Verify integrity of an entire account chain.
pub fn verify_chain_integrity(chain: &[Block]) -> Result<(), ArxiaError> {
    if chain.is_empty() {
        return Ok(());
    }
    if chain[0].nonce != 1 {
        return Err(ArxiaError::InvalidGenesis(format!(
            "nonce must be 1, got {}",
            chain[0].nonce
        )));
    }
    if !matches!(chain[0].block_type, BlockType::Open { .. }) {
        return Err(ArxiaError::InvalidGenesis(
            "first block must be OPEN".into(),
        ));
    }
    if !chain[0].previous.is_empty() {
        return Err(ArxiaError::InvalidGenesis(
            "genesis must have empty previous".into(),
        ));
    }
    verify_block(&chain[0])?;
    for i in 1..chain.len() {
        if chain[i].nonce != chain[i - 1].nonce + 1 {
            return Err(ArxiaError::NonceGap {
                index: i,
                expected: chain[i - 1].nonce + 1,
                got: chain[i].nonce,
            });
        }
        if chain[i].previous != chain[i - 1].hash {
            return Err(ArxiaError::HashChainBroken(i));
        }
        verify_block(&chain[i])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{AccountChain, VectorClock};

    #[test]
    fn test_verify_block_valid() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let block = chain.open(1_000_000, &mut vc);
        assert!(verify_block(&block).is_ok());
    }

    #[test]
    fn test_verify_chain_integrity_valid() {
        let mut vc = VectorClock::new();
        let mut alice = AccountChain::new();
        let mut bob = AccountChain::new();
        alice.open(1_000_000, &mut vc);
        bob.open(0, &mut vc);
        let send = alice.send(bob.id(), 100_000, &mut vc).unwrap();
        bob.receive(&send, &mut vc).unwrap();
        assert!(verify_chain_integrity(&alice.chain).is_ok());
        assert!(verify_chain_integrity(&bob.chain).is_ok());
    }

    #[test]
    fn test_verify_chain_empty_is_ok() {
        assert!(verify_chain_integrity(&[]).is_ok());
    }

    #[test]
    fn test_verify_block_rejects_tampered_hash() {
        let mut vc = VectorClock::new();
        let mut chain = AccountChain::new();
        let mut block = chain.open(1_000_000, &mut vc);
        block.hash = "0".repeat(64);
        assert!(verify_block(&block).is_err());
    }
}
