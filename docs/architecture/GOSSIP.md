# Gossip Protocol

## Overview

The gossip protocol propagates blocks, synchronizes the per-`(account,
nonce)` registry, and detects double-spends across the mesh network.

Wave 3 introduced two structural hardenings that earlier versions of
this document did not reflect:

- **Bounded state on every `GossipNode`** (audit ID **CRIT-011**,
  closed by PR #45). `known_blocks` and `nonce_registry` are bounded
  to documented capacities with FIFO drop-oldest eviction and
  observable drop counters. A peer flooding valid signed blocks
  cannot OOM the node.
- **Authenticated message envelope** (`SignedGossipMessage`, audit
  ID **CRIT-010**, closed by PR #46). Every gossip message is
  wrapped in an Ed25519-signed envelope bound to the sender's
  public key under the domain prefix `arxia-gossip-msg-v1`. Forging
  a message at the gossip layer requires forging a signature.

Both surfaces are described in this document; the audit context and
attack vectors are summarized in `PHASE1_AUDIT_REPORT.md`.

---

## 1. Nonce Registry

```rust
pub type NonceKey = ([u8; 32], u64);        // (account pubkey, nonce)
pub type NonceEntry = [u8; 32];             // block hash
pub type NonceRegistry = BTreeMap<NonceKey, NonceEntry>;
```

Keying on `(account, nonce)` — rather than on the block hash — is
what makes double-spends at the same nonce detectable. Two blocks
claiming the same `(account, nonce)` with different destinations
produce different hashes; a hash-keyed registry would store both as
distinct entries and miss the conflict. `BTreeMap` is mandatory for
deterministic iteration order across nodes.

The registry stored on a `GossipNode` is bounded at the node level
(see §3 below). The `NonceRegistry` type alias itself is just a
`BTreeMap`; the cap is enforced by the `GossipNode` mutators.

---

## 2. Merge Algorithm

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

`merge_nonce_registries` operates on raw `BTreeMap`s. The bounded-
state machinery on `GossipNode::merge_registry` (§3) is what enforces
the per-node capacity by evicting the oldest entries after the merge.

### 2.1. Defense-in-depth: `pending_conflicts` (CRIT-009)

`GossipNode::merge_registry` returns the `Vec<NonceConflict>` to the
immediate caller AND mirrors every conflict into
`GossipNode::pending_conflicts` for future polling by the consensus
layer. A caller that drops the return value (the exact CRIT-009
pattern) still finds every conflict via
`GossipNode::drain_pending_conflicts`, so double-spend detection
cannot be silenced by an inattentive caller. Pinned by
`test_gossip_merge_registry_conflicts_survive_dropped_return`.

---

## 3. `GossipNode` and bounded state (CRIT-011, PR #45)

```rust
pub struct GossipNode {
    pub node_id: String,
    pub known_blocks: VecDeque<Block>,           // bounded, FIFO
    pub nonce_registry: NonceRegistry,            // bounded, FIFO
    pub peers: Vec<String>,
    pub pending_conflicts: Vec<NonceConflict>,    // CRIT-009 mirror
    // private: insertion-order tracker + drop counters + capacities
}
```

### 3.1. Capacities

| Constant                          | Default | Memory at default |
|-----------------------------------|---------|-------------------|
| `MAX_KNOWN_BLOCKS`                | `10_000` | ≈1.9 MB (193 B per compact block) |
| `MAX_NONCE_REGISTRY_ENTRIES`      | `10_000` | ≈720 KB (72 B per entry) |

Both constants are `pub const`. For deployments with tighter memory
budgets (ESP32-class hardware with ≈300 KB free DRAM after the
runtime), use `GossipNode::with_capacity(node_id, kb_cap, nr_cap)`.
Zero is silently clamped to 1 to keep "at least one block can be
held briefly" as a data-flow invariant.

### 3.2. Eviction policy

When either collection is at capacity, the OLDEST entry by insertion
order is evicted (FIFO drop-oldest). The eviction is silent — no
error is returned to the caller — but the cumulative count of
evicted entries is observable:

```rust
fn known_blocks_dropped(&self) -> u64;          // saturating at u64::MAX
fn nonce_registry_dropped(&self) -> u64;        // saturating at u64::MAX
```

Eviction is enforced inside the documented mutators
(`add_block` and `merge_registry`). Direct mutation of the public
fields bypasses the bound and re-introduces CRIT-011 — callers MUST
use the documented mutators.

The implementation uses a parallel `VecDeque<NonceKey>` order tracker
plus a self-healing pop loop in `evict_oldest_nonce_entry` that
skips stale entries (keys that were already removed from the registry
by some other path). This means external direct mutation of
`nonce_registry` is tolerated lazily — the next call to a documented
mutator cleans up.

### 3.3. Idempotent `add_block`

A block re-added with the same `(account, nonce)` AND the same hash
returns `Ok(())` WITHOUT growing either collection. This is the
CRIT-011 amplifier closure: pre-fix, `add_block` always pushed to
`known_blocks` after the registry check, doubling memory on every
redundant gossip arrival. Pinned by
`test_add_block_idempotent_does_not_grow_collections`.

A block at a known `(account, nonce)` with a DIFFERENT hash returns
`Err(ArxiaError::DoubleSpend { nonce })`.

---

## 4. Double-Spend Detection

The gossip layer detects double-spends in two places:

1. **Local insertion**: `GossipNode::add_block` rejects an attempted
   write of a divergent hash at a known `(account, nonce)` with
   `Err(ArxiaError::DoubleSpend { nonce })`. State is unchanged on
   rejection.
2. **Merge with a remote**: `GossipNode::merge_registry` returns
   every divergent-hash key as a `NonceConflict`, and mirrors each
   into `pending_conflicts` for asynchronous draining by the
   consensus layer.

```
local:  ((account_A, 5), hash=0xabc...)
remote: ((account_A, 5), hash=0xdef...)  // → NonceConflict
```

Resolution is the consensus layer's job (ORV vote, then hash
tiebreaker — see `FINALITY_MODEL.md` §6).

---

## 5. `SyncResult`

```rust
pub enum SyncResult {
    Success,          // All nonces match after merge
    Mismatch(usize),  // N conflicts detected
    NoNeighbors,      // No peers available to sync with
}
```

`Success` from `sync_nonces_before_l1` is the L1-finality predicate
(see `FINALITY_MODEL.md` §4.3). `Mismatch(n)` propagates the conflict
count to higher layers without revealing which keys diverged
(callers that need the per-key list use `merge_registry` directly).

---

## 6. `GossipMessage` and `SignedGossipMessage` envelope

### 6.1. Application-level message

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    BlockAnnounce {
        block_data: Vec<u8>,                                  // serialized compact block
        hops: u8,                                             // TTL counter
    },
    NonceSyncRequest {
        from: String,                                         // requester node ID
    },
    NonceSyncResponse {
        entries: Vec<([u8; 32], u64, [u8; 32])>,              // (block_hash, nonce, account)
    },
    Ping {
        node_id: String,
        timestamp: u64,
    },
}
```

This is the application-level payload — what one node wants to say
to another. It carries no signature and no sender identity in the
type itself. Authentication is added at the next layer (§6.2).

### 6.2. Authenticated envelope (CRIT-010, PR #46)

```rust
pub const GOSSIP_MESSAGE_DOMAIN: &[u8] = b"arxia-gossip-msg-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGossipMessage {
    pub message: GossipMessage,
    pub sender_pubkey: [u8; 32],
    pub signature: Vec<u8>,                                   // 64 bytes when valid
}

impl SignedGossipMessage {
    pub fn canonical_bytes(message: &GossipMessage,
                            sender_pubkey: &[u8; 32]) -> Vec<u8>;
    pub fn verify(&self) -> Result<(), SignedGossipMessageError>;
}
```

The bytes that the sender signs are
`GOSSIP_MESSAGE_DOMAIN || sender_pubkey || variant_tag || variant_fields`.
Each variant has a one-byte `variant_tag` (`0x01..=0x04`, pairwise
distinct) and a length-prefixed big-endian payload encoding (see
`SignedGossipMessage::canonical_bytes` doc-comment for the exact
byte layout per variant).

### 6.3. Domain separation

The 19-byte domain prefix `arxia-gossip-msg-v1` is **pairwise
distinct** from every other Arxia signed-envelope domain:

| Type                  | Domain prefix                          |
|-----------------------|----------------------------------------|
| `RelayReceipt`        | `arxia-relay-receipt-v1`               |
| `SlashingProof`       | `arxia-relay-slash-v1`                 |
| `SignedGossipMessage` | `arxia-gossip-msg-v1`                  |
| `SignedConfirmation`  | `arxia-finality-confirmation-v1`       |
| `SignedValidatorVote` | `arxia-finality-validator-vote-v1`     |

A signature minted in any one of these contexts cannot be replayed
as a signature in another. Pinned by
`test_domain_separation_rejects_signature_with_other_protocol_domain`.

### 6.4. `verify` error variants

```rust
pub enum SignedGossipMessageError {
    InvalidSignatureLength,       // signature.len() != 64
    InvalidPublicKey,              // sender_pubkey not a valid Ed25519 point
    SignatureInvalid,              // Ed25519 verify failed (most general)
    // (additional structural error variants are added in future commits;
    //  see `MessageInvalid(MessageError)` from the per-variant size-cap
    //  framework introduced post-Wave 3)
}
```

`verify` performs `signature.len() != 64` rejection up-front (cheap
structural check) before invoking `arxia_crypto::verify` on the
canonical bytes under the carried `sender_pubkey`.

`verify` does NOT check that `sender_pubkey` is in a known-good set
of registered peers — that gating belongs to a future peer-registry
commit. For Wave 3, the security property is "this message was
signed by the holder of `sender_pubkey`", not "this peer is
authorized to send".

---

## 7. End-to-end ingress contract

The intended ingress contract (once a transport-level dispatcher
lands) is:

```text
  bytes off the wire
       ↓
  serde::Deserialize → SignedGossipMessage
       ↓
  s.verify()       — rejects unsigned / wrong-key / wrong-domain
       ↓ Ok
  s.message        — now safely consumable
       ↓
  GossipNode::add_block / merge_registry / etc.
```

Every `Err` from `s.verify()` MUST be treated as a rejected packet.
No state mutation may occur on the path that produced an `Err`. The
strict ordering "verify before consume" is the structural mitigation
for CRIT-010.

### 7.1. Limitation: dispatcher not yet wired

As of Wave 3, no transport-level gossip dispatcher exists in the
workspace. `GossipNode` consumes `GossipMessage` only via direct
in-process Rust calls (the test suites and example code). The
`SignedGossipMessage` envelope is defined and verified, but the
bytes-on-the-wire path that wraps it is future work. This is
documented at the top of `crates/arxia-gossip/src/signed_message.rs`
in the §"Limitations" section.

### 7.2. Limitation: no peer registry

`verify` checks signature consistency with the carried
`sender_pubkey` but NOT membership in a trusted set. Until the
consensus layer exposes a validated peer registry (paralleling the
observer-registry follow-up from PR #42), an attacker can
self-issue a `SignedGossipMessage` with their own keypair and the
envelope verifies. Per-peer rate limiting, allow-listing, and
reputation logic all belong to that future layer.

---

## 8. Constants index

| Constant                       | Value                  | Defined in                                |
|--------------------------------|------------------------|-------------------------------------------|
| `MAX_KNOWN_BLOCKS`             | `10_000`               | `arxia-gossip::node`                      |
| `MAX_NONCE_REGISTRY_ENTRIES`   | `10_000`               | `arxia-gossip::node`                      |
| `GOSSIP_MESSAGE_DOMAIN`        | `b"arxia-gossip-msg-v1"` (19 B) | `arxia-gossip::signed_message`     |

---

## 9. Regression tests

| Property                                                        | Test                                                                                | Location |
|-----------------------------------------------------------------|-------------------------------------------------------------------------------------|----------|
| `MAX_KNOWN_BLOCKS = 10_000` pinned                              | `test_known_blocks_default_capacity_is_10000`                                       | `crates/arxia-gossip/src/node.rs` |
| `MAX_NONCE_REGISTRY_ENTRIES = 10_000` pinned                    | `test_nonce_registry_default_capacity_is_10000`                                     | `crates/arxia-gossip/src/node.rs` |
| `known_blocks` resists single-peer flood (FIFO eviction)         | `test_known_blocks_resistance_to_flooding_single_peer`                              | `crates/arxia-gossip/src/node.rs` |
| Idempotent `add_block` does NOT grow either collection           | `test_add_block_idempotent_does_not_grow_collections`                               | `crates/arxia-gossip/src/node.rs` |
| `merge_registry` respects the cap (drop-oldest)                  | `test_merge_registry_respects_nonce_registry_cap`                                   | `crates/arxia-gossip/src/node.rs` |
| Eviction is FIFO by insertion order                              | `test_eviction_drops_oldest_by_insertion_order`                                     | `crates/arxia-gossip/src/node.rs` |
| Conflicts collected before eviction survive in `pending_conflicts` | `test_eviction_preserves_pending_conflicts_history`                              | `crates/arxia-gossip/src/node.rs` |
| `merge_registry` returns conflicts (CRIT-009 surface)            | `test_gossip_merge_registry_returns_conflicts_to_caller`                            | `crates/arxia-gossip/src/node.rs` |
| Conflicts survive caller dropping the return value (CRIT-009)    | `test_gossip_merge_registry_conflicts_survive_dropped_return`                       | `crates/arxia-gossip/src/node.rs` |
| `add_block` detects double-spend on same `(account, nonce)`      | `test_gossip_add_block_detects_double_spend_on_same_account_nonce`                  | `crates/arxia-gossip/src/node.rs` |
| `SignedGossipMessage::verify` accepts canonical signatures        | `test_sign_then_verify_passes_for_{ping,block_announce,nonce_sync_request,nonce_sync_response}` | `crates/arxia-gossip/src/signed_message.rs` |
| `verify` rejects zero signature                                   | `test_verify_rejects_zero_signature`                                                | `crates/arxia-gossip/src/signed_message.rs` |
| `verify` rejects tampered fields (per variant)                    | `test_verify_rejects_tampered_*` (4 tests)                                          | `crates/arxia-gossip/src/signed_message.rs` |
| Sender pubkey swap rejected                                       | `test_verify_rejects_swap_to_different_signers_pubkey`                              | `crates/arxia-gossip/src/signed_message.rs` |
| Cross-domain replay rejected (envelope domain separation)         | `test_domain_separation_rejects_signature_with_other_protocol_domain`               | `crates/arxia-gossip/src/signed_message.rs` |
| Variant tags are pairwise distinct in canonical bytes             | `test_canonical_bytes_variant_tags_are_distinct`                                    | `crates/arxia-gossip/src/signed_message.rs` |
| `canonical_bytes` is deterministic                                | `test_canonical_bytes_is_deterministic`                                             | `crates/arxia-gossip/src/signed_message.rs` |
| Wire-format serde round-trip preserves verifiability              | `test_signed_gossip_message_serde_roundtrip_via_bincode_compatible_path`            | `crates/arxia-gossip/src/signed_message.rs` |

---

## 10. Change history

| Version | Change |
|---------|--------|
| `0.1.x` | Initial gossip protocol: nonce registry, double-spend detection at merge, SyncResult variants. |
| `0.2.0` (Wave 3, PR #45) | `GossipNode::known_blocks` and `nonce_registry` bounded with `MAX_KNOWN_BLOCKS` / `MAX_NONCE_REGISTRY_ENTRIES` defaults of 10 000 each. FIFO drop-oldest eviction; observable counters via `known_blocks_dropped()` / `nonce_registry_dropped()`. Idempotent `add_block` no longer grows the collections. Closes audit finding **CRIT-011**. |
| `0.2.0` (Wave 3, PR #46) | `SignedGossipMessage` envelope wrapping `GossipMessage` with Ed25519 sender authentication under domain prefix `arxia-gossip-msg-v1`. New `verify()` API; `canonical_bytes` layout with 1-byte variant tags + length-prefixed big-endian payloads. Closes audit finding **CRIT-010**. |
