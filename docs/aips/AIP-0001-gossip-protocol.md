# AIP-0001: Gossip Protocol

| Field       | Value                          |
|-------------|--------------------------------|
| **AIP**     | 0001                           |
| **Title**   | Gossip Protocol Specification  |
| **Status**  | Implemented (v0.5.0)           |
| **Created** | 2025-01-15                     |

## Motivation

Nodes in the Arxia mesh network need a protocol to propagate blocks and
detect double-spend attempts. Given intermittent connectivity, the protocol
must be efficient (minimal bandwidth), convergent (CRDT-based), and
resilient to partitions.

## Specification

### Nonce Registry

Each node maintains a nonce registry:

```rust
pub type NonceKey = ([u8; 32], u64);        // (account pubkey, nonce)
pub type NonceEntry = [u8; 32];             // block hash
pub type NonceRegistry = BTreeMap<NonceKey, NonceEntry>;
```

Key: `(account public key, nonce)` tuple.
Value: hash of the block that claimed this `(account, nonce)`.

Keying on `(account, nonce)` — rather than on the block hash itself —
is what allows the registry to detect double-spends at the same nonce:
two blocks with the same `(account, nonce)` but different destinations
produce different hashes and would collide on the registry key,
surfacing the conflict. BTreeMap is mandatory for deterministic
iteration order.

### Messages

```rust
enum GossipMessage {
    BlockAnnounce {
        block_hash: [u8; 32],
        account: [u8; 32],
        nonce: u64,
    },
    SyncRequest {
        registry_subset: Vec<([u8; 32], u64)>,
    },
    SyncResponse {
        updates: Vec<([u8; 32], u64, [u8; 32])>,
    },
}
```

### Sync Protocol

1. Node A sends `SyncRequest` with its registry entries
2. Node B compares with local registry
3. Node B sends `SyncResponse` with entries where B has higher nonces
4. Node A merges response into local registry
5. If any entry has same nonce but different hash: conflict detected

### Merge Algorithm

```
for each ((account, nonce), remote_hash) in response:
    match local.get((account, nonce)):
        Some(local_hash) if local_hash == remote_hash:
            no-op (identical)
        Some(local_hash):
            push NonceConflict { key: (account, nonce),
                                 local_hash, remote_hash }
        None:
            local.insert((account, nonce), remote_hash)
```

Merge never silently overwrites. Conflicts are returned as a
`Vec<NonceConflict>` for the caller to resolve (typically via
ORV stake-weighted vote; see `arxia-consensus::conflict`).

### SyncResult

```rust
enum SyncResult {
    Success,           // All entries consistent
    Mismatch(usize),   // N conflicts detected
    NoNeighbors,       // No peers to sync with
}
```

L1 finality requires `SyncResult::Success`.

## Rationale

- BTreeMap over HashMap: Deterministic ordering is critical for reproducible
  conflict detection and testing.
- Nonce-based: Compact representation (~40 bytes per account) fits LoRa MTU.
- Merge semantics: Higher nonce always wins (monotonically increasing).

## Test Results

Tested across 10 scenarios and 3 network topologies:

1. **Linear topology** (A-B-C): 2-hop propagation
2. **Star topology** (A-B, A-C, A-D): Hub propagation
3. **Mesh topology** (fully connected): Direct propagation

All scenarios achieved convergence within expected hop counts.

## Implementation

- Crate: `arxia-gossip`
- Entry point: `sync_nonces_before_l1()`
- Tests: 4 unit tests covering success, mismatch, merge, and no-neighbors cases
