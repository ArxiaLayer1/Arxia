//! Block and BlockType definitions for the Arxia Block Lattice.
//!
//! # `compute_hash` returns Result (MED-001, commit 050)
//!
//! Pre-fix [`Block::compute_hash`] used
//! `serde_json::to_string(block_type).expect("BlockType serialization")`
//! to produce its content string. The audit (MED-001):
//!
//! > Custom `BlockType` variant added later with a failing
//! > `Serialize` impl panics in hash compute. DoS or hash mismatch.
//! > Suggested fix direction: return
//! > `Result<String, ArxiaError::Serialization>`.
//!
//! Today the four variants (`Open`, `Send`, `Receive`, `Revoke`)
//! all serialize successfully — they're flat structs of `String`
//! and `u64` fields. The panic is theoretical until a future
//! variant adds a custom `Serialize` impl that can fail. Returning
//! `Result` makes the failure case typed at the API boundary so
//! future code-touchers get a compile error instead of a runtime
//! panic.
//!
//! All 8 production callers (`AccountChain::{open, send, receive,
//! revoke_credential}`, `verify_block`, `verify_chain_integrity`
//! variants in `Ledger::add_block`, `from_compact_bytes`, and
//! `reconcile_partitions`) propagate via `?` — none of them is
//! in a context that can't return `ArxiaError`.

use serde::{Deserialize, Serialize};

use arxia_core::ArxiaError;

/// The type of operation a block represents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BlockType {
    /// Genesis block opening an account with an initial balance.
    Open {
        /// Initial balance in micro-ARX.
        initial_balance: u64,
    },
    /// Send funds to another account.
    Send {
        /// Destination account public key (hex-encoded).
        destination: String,
        /// Amount in micro-ARX.
        amount: u64,
    },
    /// Receive funds from a corresponding SEND block.
    Receive {
        /// Hash of the source SEND block.
        source_hash: String,
    },
    /// Revoke a DID credential.
    Revoke {
        /// Hash of the credential being revoked.
        credential_hash: String,
    },
}

/// A single block in an account chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Account public key (hex-encoded Ed25519).
    pub account: String,
    /// Hash of the previous block (empty for genesis).
    pub previous: String,
    /// The block operation type.
    pub block_type: BlockType,
    /// Account balance after this block.
    pub balance: u64,
    /// Monotonically increasing nonce (starts at 1).
    pub nonce: u64,
    /// Timestamp in milliseconds since UNIX epoch.
    pub timestamp: u64,
    /// Blake3 hash of the block contents (hex-encoded).
    pub hash: String,
    /// Ed25519 signature over raw Blake3 hash bytes.
    pub signature: Vec<u8>,
}

impl Block {
    /// Compute the Blake3 hash of block contents.
    ///
    /// # Errors
    ///
    /// Returns `Err(ArxiaError::Serialization)` if
    /// `serde_json::to_string(block_type)` fails. With the four
    /// canonical variants in `BlockType` this never happens
    /// today; the typed error exists so a future variant with a
    /// fallible `Serialize` impl produces a compile-time-handled
    /// error instead of a runtime panic. See MED-001 in the
    /// module docstring.
    pub fn compute_hash(
        account: &str,
        previous: &str,
        block_type: &BlockType,
        balance: u64,
        nonce: u64,
        timestamp: u64,
    ) -> Result<String, ArxiaError> {
        let bt_json = serde_json::to_string(block_type)
            .map_err(|e| ArxiaError::Serialization(format!("BlockType: {e}")))?;
        let content = format!(
            "{}:{}:{}:{}:{}:{}",
            account, previous, bt_json, balance, nonce, timestamp
        );
        Ok(blake3::hash(content.as_bytes()).to_hex().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MED-001 PRIMARY POSITIVE PIN: each canonical `BlockType`
    /// variant serializes successfully. A future regression
    /// (e.g. someone adds a non-Serialize field to one of these
    /// variants) trips this test before reaching CI.
    #[test]
    fn test_compute_hash_succeeds_on_open() {
        let h = Block::compute_hash(
            "abcd",
            "",
            &BlockType::Open {
                initial_balance: 100,
            },
            100,
            1,
            42,
        );
        assert!(h.is_ok());
        assert_eq!(h.unwrap().len(), 64); // blake3 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_compute_hash_succeeds_on_send() {
        let h = Block::compute_hash(
            "abcd",
            "prev",
            &BlockType::Send {
                destination: "dest".to_string(),
                amount: 50,
            },
            50,
            2,
            42,
        );
        assert!(h.is_ok());
        assert_eq!(h.unwrap().len(), 64);
    }

    #[test]
    fn test_compute_hash_succeeds_on_receive() {
        let h = Block::compute_hash(
            "abcd",
            "prev",
            &BlockType::Receive {
                source_hash: "src".to_string(),
            },
            150,
            3,
            42,
        );
        assert!(h.is_ok());
    }

    #[test]
    fn test_compute_hash_succeeds_on_revoke() {
        let h = Block::compute_hash(
            "abcd",
            "prev",
            &BlockType::Revoke {
                credential_hash: "cred".to_string(),
            },
            150,
            4,
            42,
        );
        assert!(h.is_ok());
    }

    #[test]
    fn test_compute_hash_returns_result_typed_signature() {
        // Compile-time pin: the function returns Result<String,
        // ArxiaError>. A future regression that reverts the
        // signature to bare String fails to type-check this
        // test (the `?` operator and Err pattern require
        // Result).
        fn assert_returns_result() -> Result<(), ArxiaError> {
            let _h =
                Block::compute_hash("x", "", &BlockType::Open { initial_balance: 0 }, 0, 1, 0)?;
            Ok(())
        }
        assert!(assert_returns_result().is_ok());
    }

    #[test]
    fn test_compute_hash_is_deterministic() {
        // Two calls with identical inputs produce identical
        // output — pin against any future change that
        // accidentally introduces nondeterminism.
        let h1 = Block::compute_hash("a", "p", &BlockType::Open { initial_balance: 1 }, 1, 1, 1)
            .unwrap();
        let h2 = Block::compute_hash("a", "p", &BlockType::Open { initial_balance: 1 }, 1, 1, 1)
            .unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_hash_distinct_for_distinct_block_types() {
        // Distinct BlockType variants produce distinct hashes
        // even when account/previous/balance/nonce/timestamp
        // are equal. Pin the BlockType-discriminator
        // contribution to the hash.
        let h_open = Block::compute_hash(
            "a",
            "",
            &BlockType::Open {
                initial_balance: 100,
            },
            100,
            1,
            0,
        )
        .unwrap();
        let h_send = Block::compute_hash(
            "a",
            "",
            &BlockType::Send {
                destination: "x".to_string(),
                amount: 100,
            },
            100,
            1,
            0,
        )
        .unwrap();
        assert_ne!(h_open, h_send);
    }
}
