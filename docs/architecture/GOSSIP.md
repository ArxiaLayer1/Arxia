# Gossip Protocol

## Overview

The gossip protocol propagates blocks and detects double-spends across
the mesh network. It uses a nonce registry for efficient synchronization.

## Nonce Registry

```rust
pub type NonceKey = ([u8; 32], u64);        // (account pubkey, nonce)
pub type NonceEntry = [u8; 32];             // block hash
pub type NonceRegistry = BTreeMap<NonceKey, NonceEntry>;
```

Keying on `(account, nonce)` — rather than on the block hash — is
what makes double-spends at the same nonce detectable. Two blocks
claiming the same `(account, nonce)` with different destinations produce
different hashes; a hash-keyed registry would store both as distinct
entries and miss the conflict. BTreeMap is mandatory for deterministic
iteration order across nodes.

## Merge Algorithm

```rust
pub fn merge_nonce_registries(
    local: &mut NonceRegistry,
    remote: &NonceRegistry,
) -> Vec<NonceConflict> {
    let mut conflicts = Vec::new();
    for (key, remote_hash) in remote {
        match local.get(key) {
            Some(local_hash) if local_hash == remote_hash => { /* no-op */ }
            Some(local_hash) => {
                conflicts.push(NonceConflict {
                    key: *key,
                    local_hash: *local_hash,
                    remote_hash: *remote_hash,
                });
            }
            None => { local.insert(*key, *remote_hash); }
        }
    }
    conflicts
}
```

Merge never silently overwrites: a divergent hash at the same
`(account, nonce)` is returned as a `NonceConflict`. Resolution is
delegated to the ORV stake-weighted vote
(`arxia-consensus::conflict::resolve_conflict_orv`).

## Double-Spend Detection

If two nodes know the same `(account, nonce)` but different block
hashes, a double-spend is detected at merge time:

```
local:  ((account_A, 5), hash=0xabc...)
remote: ((account_A, 5), hash=0xdef...)  // NonceConflict
```

`GossipNode::add_block` also rejects local insertions of a conflicting
hash at a known `(account, nonce)`, returning
`ArxiaError::DoubleSpend`.

## SyncResult

```rust
pub enum SyncResult {
    Success,          // All nonces match after merge
    Mismatch(usize),  // N conflicts detected
    NoNeighbors,      // No peers available to sync with
}
```

## GossipMessage

Messages are Ed25519-signed to prevent spoofing:

```rust
pub enum GossipMessage {
    BlockAnnounce { block_hash: [u8; 32], account: [u8; 32], nonce: u64 },
    SyncRequest { registry_subset: Vec<([u8; 32], u64)> },
    SyncResponse { updates: Vec<([u8; 32], u64, [u8; 32])> },
}
```
