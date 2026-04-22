# Finality Model

This document specifies Arxia's finality model: the four-tier assessment,
the predicates that promote a block from one tier to the next, the
conflict-resolution cascade, and the invariants that CRDT reconciliation
must preserve across partition healing.

> Status: **Normative** for protocol `v0.1.x`. The tier set, ordering,
> and thresholds documented here are stable. Extensions (transport-aware
> weighting, active delegation, full three-tier ORV cascade) are called
> out explicitly in §9 as non-normative future work.

---

## 1. Overview

Arxia is **offline-first**. A node may be fully partitioned from the
rest of the network for minutes, hours, or days. The finality model is
therefore not a single predicate ("this block is final") but a strictly
ordered set of tiers, each with a well-defined predicate and a clear
statement of what guarantees can be derived locally versus what requires
network participation.

```
                 pure local               +    network
 +---------+    +---------------+    +-----------------+    +------------+
 | Pending | -> | L0 (instant)  | -> | L1   (gossip)   | -> | L2 (full)  |
 +---------+    +---------------+    +-----------------+    +------------+
                 amount <= 10 ARX      nonce registry        >= 2/3 stake
                 + 1 local conf        synced vs peers        confirmation
```

Promotion is **monotone**: once assessed at tier `T`, a block cannot
regress to a lower tier. Transitions are driven by new information
(local confirmations, gossip sync, validator votes); absence of
information never demotes.

---

## 2. Tier definitions

Reference:
[`arxia-finality::FinalityLevel`](../../crates/arxia-finality/src/lib.rs).

| Tier      | Discriminant | Display form    | Meaning |
|-----------|:------------:|-----------------|---------|
| `Pending` | `0`          | `PENDING`       | Awaiting further confirmation. |
| `L0`      | `1`          | `L0 (instant)`  | Small-value, locally confirmed, offline-safe. |
| `L1`      | `2`          | `L1 (gossip)`   | Gossip layer reports no `(account, nonce)` conflict with any reachable peer. |
| `L2`      | `3`          | `L2 (full)`     | `>= 2/3` of the staked total supply has voted for this block. |

The enum derives `Ord` so that strict comparison holds:

```text
Pending < L0 < L1 < L2
```

This ordering is pinned by `test_finality_ordering`.

---

## 3. Assessment function

The canonical stateless assessment is
[`assess_finality`](../../crates/arxia-finality/src/lib.rs):

```rust
pub fn assess_finality(
    amount_micro_arx: u64,
    local_confirmations: u32,
    sync_result: &SyncResult,
    validator_pct: f64,
) -> FinalityLevel {
    if validator_pct >= 0.67 {
        return FinalityLevel::L2;
    }
    if *sync_result == SyncResult::Success {
        return FinalityLevel::L1;
    }
    if amount_micro_arx <= L0_CAP_MICRO_ARX && local_confirmations > 0 {
        return FinalityLevel::L0;
    }
    FinalityLevel::Pending
}
```

Evaluation is top-down and short-circuits at the first match. The order
is L2 → L1 → L0 → Pending, so validator consensus always dominates and
small-amount local confirmation is the weakest non-trivial tier.

### 3.1. Predicate table

| Predicate                                                          | Result       |
|--------------------------------------------------------------------|:------------:|
| `validator_pct >= 0.67`                                            | `L2`         |
| `sync_result == SyncResult::Success`                               | `L1`         |
| `amount <= L0_CAP_MICRO_ARX && local_confirmations > 0`            | `L0`         |
| otherwise                                                          | `Pending`    |

### 3.2. Inputs

| Input                 | Type          | Source |
|-----------------------|---------------|--------|
| `amount_micro_arx`    | `u64`         | Block payload (SEND `amount`, RECEIVE's referenced SEND, OPEN `initial_balance`, `0` for REVOKE). |
| `local_confirmations` | `u32`         | Count of distinct local confirmations (BLE / same-radio neighbors). |
| `sync_result`         | `&SyncResult` | Output of [`sync_nonces_before_l1`](../../crates/arxia-gossip/src/nonce_registry.rs). |
| `validator_pct`       | `f64`         | Fraction of total staked supply (in `[0.0, 1.0]`) whose ORV votes have been verified for this block. |

---

## 4. Tier predicates in detail

### 4.1. `Pending`

Default tier. The block exists locally but does not satisfy any of the
other predicates. A sender watching their own outgoing SEND will remain
at `Pending` until either (a) at least one local neighbor confirms, (b)
a gossip round synchronizes the nonce registry, or (c) validator votes
come in.

### 4.2. `L0` — instant local confirmation

Predicate:

```text
amount <= L0_CAP_MICRO_ARX  AND  local_confirmations > 0
```

- `L0_CAP_MICRO_ARX` is `10_000_000` micro-ARX, i.e. **10 ARX**
  ([`arxia-core::constants`](../../crates/arxia-core/src/constants.rs)).
- `L0` is reachable **fully offline**, so long as at least one local
  peer (typically a BLE neighbor) has observed and confirmed the block.
- `L0` is not safe against equivocation by the sender: a malicious
  sender may broadcast conflicting SENDs to two disjoint L0 audiences.
  That equivocation is detected at L1 when the audiences reconnect
  (see §5 and §6).

**Rationale**: `L0` is the tier that makes "coffee-shop payments over
LoRa" usable when no backbone is available. The 10-ARX cap is the
amount at which the protocol chooses to absorb the equivocation risk in
exchange for instant UX.

### 4.3. `L1` — gossip-level synchronization

Predicate:

```text
sync_result == SyncResult::Success
```

`SyncResult` comes from
[`sync_nonces_before_l1`](../../crates/arxia-gossip/src/nonce_registry.rs)
and has three variants:

| Variant                | Meaning |
|------------------------|---------|
| `Success`              | Local and remote nonce registries agree on every `(account, nonce)` key they share, and neither side holds an unknown key. |
| `Mismatch(n)`          | `n` entries differ or are absent on one side. |
| `NoNeighbors`          | No peer was reachable for gossip. |

`L1` is reached iff **every** `(account, nonce)` entry the node holds
for this block's account chain is identical across all peers consulted.
Any divergence keeps the block at `L0` or `Pending`.

**Bug 4 consequence**: the nonce registry is keyed on `(account, nonce)`
(see [`NonceKey`](../../crates/arxia-gossip/src/nonce_registry.rs)). A
sender that tries to equivocate by signing two different blocks with
the same `(account, nonce)` surfaces a registry conflict at the first
gossip round and the block cannot progress past `L0` until the conflict
is resolved by the higher tier.

### 4.4. `L2` — full validator consensus

Predicate:

```text
validator_pct >= 0.67
```

`validator_pct` is the cumulative fraction of **total staked supply**
whose ORV votes (§5) have been received, cryptographically verified,
and deduplicated for this specific block hash.

The `2/3` threshold is
[`QUORUM_FRACTION = 2.0/3.0`](../../crates/arxia-core/src/constants.rs)
and matches the classical Byzantine bound.

A block at `L2` is the strongest finality guarantee the protocol
offers: it is safe against any colluding minority holding less than
`1/3` of the total staked supply.

### 4.5. Priority

`L2` short-circuits the entire cascade. A block that satisfies
`validator_pct >= 0.67` reports `L2` regardless of amount or
confirmations. This is pinned by
`test_finality_l2_takes_priority`.

---

## 5. Open Representative Voting (ORV)

`L2` is produced by Open Representative Voting. A voter is a **staked
representative** whose votes are weighted by their **delegated stake**.

Reference:
[`arxia-consensus/src/vote.rs`](../../crates/arxia-consensus/src/vote.rs),
[`arxia-consensus/src/orv.rs`](../../crates/arxia-consensus/src/orv.rs),
[`arxia-consensus/src/quorum.rs`](../../crates/arxia-consensus/src/quorum.rs).

### 5.1. Vote structure

```rust
pub struct VoteORV {
    pub block_hash: [u8; 32],
    pub voter_pubkey: [u8; 32],
    pub delegated_stake: u64,
    pub nonce: u64,
    pub signature: [u8; 64],
}
```

The signature is an Ed25519 signature over
[`compute_vote_hash`](../../crates/arxia-consensus/src/vote.rs):

```text
preimage = block_hash(32) || voter_pubkey(32)
        || delegated_stake(u64, little-endian, 8)
        || nonce(u64, little-endian, 8)
hash     = blake3(preimage)                     // 32 bytes
```

Note the deliberate endianness choice: block hashing (§4 of
[`SERIALIZATION.md`](./SERIALIZATION.md)) is big-endian, but the
vote-hash preimage is little-endian. This asymmetry is frozen for
`v0.1.x`.

### 5.2. Representative eligibility

A public key is an ORV representative for a given epoch iff its
delegated stake is `>= MIN_DELEGATION_FRACTION * total_supply`, where
`MIN_DELEGATION_FRACTION = 0.001` (0.1% of total supply).
[`collect_votes`](../../crates/arxia-consensus/src/orv.rs) filters
ineligible voters out before quorum calculation.

### 5.3. Quorum

[`check_quorum`](../../crates/arxia-consensus/src/quorum.rs) requires
**both** of the following to hold:

| Component            | Predicate                              |
|----------------------|----------------------------------------|
| Representative count | `voted_reps * 3 >= total_reps * 2`     |
| Stake                | `voted_stake / total_supply >= 0.20`   |

`total_supply` here is the **total circulating supply** used as the
denominator for `MIN_STAKE_FRACTION`, distinct from the total
protocol supply cap.

When both components hold, quorum is reached and
`validator_pct = voted_stake / total_supply` is reported into
`assess_finality`, which then evaluates `>= 0.67` for the `L2`
predicate. In practice `L2` requires the strictly stronger
`validator_pct >= 0.67`.

---

## 6. Conflict resolution cascade

When two blocks collide on the same `(account, nonce)`, the protocol
uses a cascade of deterministic rules.

Reference:
[`arxia-consensus::conflict::resolve_conflict_orv`](../../crates/arxia-consensus/src/conflict.rs),
[`arxia-crdt::reconciliation::reconcile_partitions`](../../crates/arxia-crdt/src/reconciliation.rs).

### 6.1. Tier 1 — stake-weighted vote

If the absolute gap between `stake_a` (total stake voting for block A)
and `stake_b` (total stake voting for block B) exceeds **5%** of the
combined total, the stake majority wins:

```text
gap = |stake_a - stake_b|
if gap * 20 > stake_a + stake_b then
    winner = argmax(stake_a, stake_b)
```

### 6.2. Tier 2 — vector-clock causality (reserved)

The lattice maintains vector clocks
([`VectorClock`](../../crates/arxia-lattice/src/chain.rs)) that
establish the happened-before relation. In the current implementation
`resolve_conflict_orv` does **not** consult the vector clock — it jumps
directly from Tier 1 to Tier 3. Wiring causality into the cascade is
tracked as future work (§9).

### 6.3. Tier 3 — hash tiebreaker

If no tier above produced a winner, the block with the
**lexicographically smaller** Blake3 hash wins:

```rust
if block_a.hash <= block_b.hash { block_a } else { block_b }
```

This rule is deterministic across all nodes and requires no network
state. It is the same rule used by CRDT reconciliation (§7).

---

## 7. CRDT reconciliation

When two partitions rejoin, the reconciliation module
([`arxia-crdt`](../../crates/arxia-crdt/src/reconciliation.rs))
re-derives a consistent state. It enforces two hard invariants that
protect finality from regressing into an inconsistent ledger.

### 7.1. Invariant 1 — one block per `(account, nonce)`

For every `(account, nonce)` pair seen across the two partitions, at
most one block contributes to the reconciled state. When partitions
disagree, the hash tiebreaker (§6.3) selects the winner. The losers
are reported in `ReconciliationReport::conflicts`, never silently
discarded.

### 7.2. Invariant 2 — non-negative balances

After all winning blocks are applied, every account's materialized
balance must satisfy `balance >= 0`. If any account would end up
negative, the entire reconciliation fails with
`ArxiaError::NegativeBalance` and the caller must resolve the conflict
out-of-band.

### 7.3. Determinism

Reconciliation is a pure function of the two partition contents. Two
nodes running reconciliation on identical inputs produce identical
`ReconciliationReport`s, including identical `conflicts` lists.

### 7.4. Interaction with finality

A block that has been the **loser** of a reconciled conflict cannot
subsequently be promoted past `Pending`. From the perspective of
`assess_finality`, the block's account chain will surface
`SyncResult::Mismatch(n)` for that block, blocking `L1`, and no
well-behaved validator will sign an ORV vote for it, blocking `L2`.

---

## 8. Defense-in-depth against double-spend

The finality model is one of three layers that together prevent
double-spend. The other two sit below it in the lattice and gossip
layers.

| Layer             | Mechanism                                                                            | Bug fix reference |
|-------------------|--------------------------------------------------------------------------------------|-------------------|
| Lattice           | `consumed_sources: HashSet<hash>` prevents a SEND from being received twice.         | Bug 1 (PR #17)    |
| Lattice           | `AccountChain::open` is idempotent; a second OPEN returns `AccountAlreadyOpen`.      | Bug 3 (PR #13)    |
| Lattice           | `OPEN.initial_balance <= MAX_INITIAL_BALANCE_PER_ACCOUNT`.                           | Bug 6 (PR #14)    |
| Lattice           | Every insertion path calls `verify_block` (hash + Ed25519).                          | Bug 2 (PR #12)    |
| Lattice           | `timestamp` is part of the hash preimage — cannot be mutated in-flight.              | Bug 5 (PR #19)    |
| Gossip            | `NonceRegistry` keyed on `(account, nonce)`; registered conflicts surface at sync.   | Bug 4 (PR #18)    |
| CRDT reconciler   | One block per `(account, nonce)` + `balance >= 0` post-merge.                        | Bug 7 (PR #20)    |
| Finality (L2)     | `2/3` stake quorum on ORV votes for the specific block hash.                         | —                 |

---

## 9. Future work (non-normative)

The following are planned extensions and are explicitly **not** part of
the `v0.1.x` normative spec:

- **Vector-clock-aware conflict resolution.** Wire Tier 2 of the
  cascade so that a causally-later block loses to a causally-earlier
  one regardless of hash order.
- **Active delegation.** The
  [`Delegation`](../../crates/arxia-consensus/src/delegation.rs) struct
  and the delegation accumulator exist, but representative stake is
  currently passed into the vote directly rather than reconstructed
  from on-chain delegations.
- **Transport-aware weighting.** The assessor is transport-agnostic.
  Future versions may weight confirmations differently for BLE vs. LoRa
  vs. satellite based on reliability profiles.
- **Global supply accumulator.** The per-account cap is enforced but
  no global supply invariant is checked at OPEN time. Adding a
  cumulative-supply guard is a tracked follow-up.

---

## 10. Constants index

All values below are defined in
[`arxia-core::constants`](../../crates/arxia-core/src/constants.rs).

| Constant                          | Value                       | Used by |
|-----------------------------------|-----------------------------|---------|
| `L0_CAP_MICRO_ARX`                | `10_000_000` (10 ARX)       | `assess_finality` |
| `QUORUM_FRACTION`                 | `2.0 / 3.0` (`0.6666…`)     | `assess_finality`, `check_quorum` |
| `MIN_STAKE_FRACTION`              | `0.20` (20%)                | `check_quorum` |
| `MIN_DELEGATION_FRACTION`         | `0.001` (0.1%)              | `collect_votes` |
| `MAX_INITIAL_BALANCE_PER_ACCOUNT` | `100_000_000 * ONE_ARX`     | OPEN supply cap |
| `ONE_ARX`                         | `1_000_000` micro-ARX       | unit conversion |

---

## 11. Regression tests

The following tests pin the normative behavior in this document.

| Property                                               | Test                                                                | Location |
|--------------------------------------------------------|---------------------------------------------------------------------|----------|
| Tier ordering `Pending < L0 < L1 < L2`                 | `test_finality_ordering`                                            | `crates/arxia-finality/src/lib.rs` |
| `L2` when `validator_pct >= 0.67`                      | `test_finality_l2`                                                  | `crates/arxia-finality/src/lib.rs` |
| `L2` dominates the cascade                             | `test_finality_l2_takes_priority`                                   | `crates/arxia-finality/src/lib.rs` |
| `L1` when `sync_result == Success`                     | `test_finality_l1`                                                  | `crates/arxia-finality/src/lib.rs` |
| `L0` for small amount with ≥ 1 confirmation            | `test_finality_l0_small_amount`                                     | `crates/arxia-finality/src/lib.rs` |
| `Pending` for large amount                             | `test_finality_pending_large_amount`                                | `crates/arxia-finality/src/lib.rs` |
| `Pending` with zero confirmations                      | `test_finality_pending_no_confirmations`                            | `crates/arxia-finality/src/lib.rs` |
| NonceRegistry conflict on same `(account, nonce)`      | `test_merge_detects_conflict_same_account_same_nonce_different_hash`| `crates/arxia-gossip/src/nonce_registry.rs` |
| Gossip sync `Success` reporting                        | `test_sync_success`                                                 | `crates/arxia-gossip/src/nonce_registry.rs` |
| Gossip sync `Mismatch` counting                        | `test_sync_mismatch_counts_distinct_hashes`                         | `crates/arxia-gossip/src/nonce_registry.rs` |
| Partition-adversarial double-spend surfaces            | `test_adversarial_double_spend_two_partitions`                      | `crates/arxia-gossip/src/nonce_registry.rs` |
| Stake-weighted conflict resolution                     | `test_resolve_conflict_stake_weighted`                              | `crates/arxia-consensus/src/conflict.rs` |
| Reconciler preserves non-negative balance              | `test_reconcile_never_goes_negative_on_double_spend`                | `crates/arxia-crdt/src/reconciliation.rs` |
| Reconciler picks deterministic hash-tiebreaker winner  | `test_reconcile_deterministic_winner_by_hash`                       | `crates/arxia-crdt/src/reconciliation.rs` |
| Double-receive of the same SEND is rejected            | `test_receive_rejects_duplicate_send`                               | `crates/arxia-lattice/src/chain.rs` |
| RECEIVE replay cannot mint infinite balance            | `test_receive_replay_does_not_mint_infinite`                        | `crates/arxia-lattice/src/chain.rs` |

---

## 12. Change history

| Version | Change |
|---------|--------|
| `0.1.0` | Initial 4-tier model (Pending / L0 / L1 / L2); ORV quorum `2/3 stake AND 20% supply`; stake/hash conflict cascade; CRDT reconciliation with non-negative balance invariant. |
