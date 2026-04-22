# Decentralized Identity (DID) Specification

## Overview

Arxia implements W3C Decentralized Identifiers with offline-first resolution.
No network access is needed to generate or verify a DID.

## DID Format

```
did:arxia:<base58(blake3(ed25519_pubkey_bytes))>
```

Example: `did:arxia:2DrjgbN7P3qRmjaHp2x5tQNKv94NwQEJhzRUmKXz4rKe`

## Generation

1. Generate Ed25519 keypair
2. Take raw public key bytes (32 bytes)
3. Compute Blake3 hash of public key bytes (32 bytes)
4. Base58-encode the hash
5. Prefix with `did:arxia:`

## DID Document Structure

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:arxia:<identifier>",
  "verificationMethod": [{
    "id": "did:arxia:<identifier>#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:arxia:<identifier>",
    "publicKeyMultibase": "z<base58_pubkey>"
  }],
  "authentication": ["did:arxia:<identifier>#key-1"]
}
```

## Offline Resolution

DID resolution is O(1) - compute blake3(pubkey), base58-encode, compare.
No registry lookup needed. The DID is fully derived from the public key.

## Verifiable Credentials v2.0

Credentials are signed using the DID holder's Ed25519 key and can be
verified offline by any party that knows the issuer's public key.

## Revocation

REVOKE block type in the block lattice. Once a REVOKE block is published
for a credential hash, the credential is considered invalid. Revocation
propagates through gossip.
