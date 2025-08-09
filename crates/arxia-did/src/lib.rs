//! Decentralized Identity (DID) for Arxia.
//!
//! Format: `did:arxia:<base58(blake3(pubkey_bytes))>`

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// An Arxia Decentralized Identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArxiaDid {
    /// The full DID string.
    pub did: String,
    /// The Ed25519 public key bytes.
    pub public_key: [u8; 32],
}

impl ArxiaDid {
    /// Create a new DID from an Ed25519 public key.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        let hash = arxia_crypto::hash_blake3_bytes(public_key);
        let encoded = bs58::encode(&hash).into_string();
        Self {
            did: format!("did:arxia:{}", encoded),
            public_key: *public_key,
        }
    }

    /// Return the DID string.
    pub fn as_str(&self) -> &str {
        &self.did
    }

    /// Return the Base58-encoded identifier portion.
    pub fn identifier(&self) -> &str {
        self.did.strip_prefix("did:arxia:").unwrap_or(&self.did)
    }
}

impl std::fmt::Display for ArxiaDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::generate_keypair;

    #[test]
    fn test_did_from_public_key() {
        let (_, vk) = generate_keypair();
        let did = ArxiaDid::from_public_key(&vk.to_bytes());
        assert!(did.did.starts_with("did:arxia:"));
        assert!(!did.identifier().is_empty());
    }

    #[test]
    fn test_did_deterministic() {
        let pubkey = [0x42; 32];
        let did1 = ArxiaDid::from_public_key(&pubkey);
        let did2 = ArxiaDid::from_public_key(&pubkey);
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_did_display() {
        let pubkey = [0x01; 32];
        let did = ArxiaDid::from_public_key(&pubkey);
        let displayed = format!("{}", did);
        assert!(displayed.starts_with("did:arxia:"));
    }

    #[test]
    fn test_different_keys_different_dids() {
        let did1 = ArxiaDid::from_public_key(&[0x01; 32]);
        let did2 = ArxiaDid::from_public_key(&[0x02; 32]);
        assert_ne!(did1, did2);
    }
}
