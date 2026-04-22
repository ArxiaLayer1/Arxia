# CRDT Specification

## Overview

Arxia uses Conflict-free Replicated Data Types (CRDTs) to reconcile state
after network partitions. CRDTs guarantee eventual consistency without
coordination.

## Data Structures

### Vector Clock

```rust
pub struct CrdtVectorClock {
    pub clocks: BTreeMap<String, u64>,
}
```

Uses BTreeMap (not HashMap) for deterministic iteration order. Operations:
- `tick(node_id)`: Increment local clock
- `merge(other)`: Element-wise maximum
- `happened_before(other)`: Causal ordering check
- `is_concurrent(other)`: Neither happened-before the other

### PN-Counter

```rust
pub struct PNCounter {
    pub increments: BTreeMap<String, u64>,
    pub decrements: BTreeMap<String, u64>,
}
```

Supports increment and decrement by node. Value = sum(increments) - sum(decrements).
Merge: element-wise max of both maps.

### OR-Set (Observed-Remove Set)

```rust
pub struct ORSet<T> {
    pub entries: BTreeMap<T, BTreeSet<String>>,
}
```

Each element is tagged with unique IDs. Add creates a new tag. Remove deletes
all known tags. Concurrent add + remove results in the element being present
(add-wins semantics).

## Pruning

To bound memory on constrained devices:
- Entries older than 7 days are pruned
- Maximum 256 entries per structure
- Pruning is deterministic (oldest entries removed first)

## Partition Reconciliation

```
fn reconcile_partitions(partition_a, partition_b):
    // Merge all CRDTs element-wise
    partition_a.counter.merge(partition_b.counter)
    partition_a.vclock.merge(partition_b.vclock)
    partition_a.or_set.merge(partition_b.or_set)
    // Both partitions converge to identical state
```
