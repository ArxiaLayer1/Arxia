# Block Serialization

This document specifies the canonical on-wire and on-disk byte layout of
Arxia blocks, the Blake3 hash preimage used as the signing target, and the
Ed25519 signing rule.

> Status: **Normative** for protocol `v0.1.x`. Breaking changes to this
> layout are versioned protocol changes and **MUST** bump the protocol
> version number.

---

## 1. Overview

Every Arxia block, regardless of its type, is represented on the wire as
a fixed-width **193-byte** blob. This size is a hard constant defined in
[`arxia-core::constants::COMPACT_BLOCK_SIZE`](../../crates/arxia-core/src/constants.rs)
and is chosen so that a full block plus Meshtastic / LoRa framing
overhead fits comfortably under the 256-byte LoRa MTU at SF7/125 kHz.

```
+----+-----------+------------+---------+---------+------------+------------+------------------+-----------+
| kd |  account  |  previous  | balance |  nonce  | timestamp  | amt/init   | dest/src/cred    | signature |
|1 B |   32 B    |    32 B    |   8 B   |   8 B   |    8 B     |    8 B     |      32 B        |   64 B    |
+----+-----------+------------+---------+---------+------------+------------+------------------+-----------+
 0    1          33           65        73        81           89           97                 129       193
```

All integers are **big-endian** (network byte order). Byte offsets are
half-open: `[start, end)`.

---

## 2. Canonical layout

| Offset | Size | Field | Type | Notes |
|-------:|-----:|-------|------|-------|
| `0`   | `1`  | `kind`      | `u8`                | Block-type discriminant. See §3. |
| `1`   | `32` | `account`   | `[u8; 32]`          | Raw Ed25519 public key. |
| `33`  | `32` | `previous`  | `[u8; 32]`          | Blake3 hash of the prior block on this account chain. All-zero iff the block is an `OPEN`. |
| `65`  | `8`  | `balance`   | `u64` big-endian    | Account balance **after** applying this block, in micro-ARX (`1 ARX = 1_000_000` micro-ARX). |
| `73`  | `8`  | `nonce`     | `u64` big-endian    | Monotonic counter starting at `1` for the `OPEN`; must increase by exactly `1` per subsequent block. |
| `81`  | `8`  | `timestamp` | `u64` big-endian    | Unix epoch milliseconds. **Included in the hash preimage** (see §4). |
| `89`  | `8`  | `amount`    | `u64` big-endian    | Semantics depend on `kind`; see §3. Zero when unused. |
| `97`  | `32` | `dest_src`  | `[u8; 32]`          | Semantics depend on `kind`; see §3. All-zero when unused. |
| `129` | `64` | `signature` | `[u8; 64]`          | Ed25519 signature; see §5. |
| **`193`** | — | — | — | Total size. |

Reference implementation:
[`arxia-lattice::serialization::to_compact_bytes`](../../crates/arxia-lattice/src/serialization.rs),
[`arxia-lattice::serialization::from_compact_bytes`](../../crates/arxia-lattice/src/serialization.rs).

### 2.1. Round-trip invariant

```text
from_compact_bytes(to_compact_bytes(b)) == b     // for every valid block b
```

### 2.2. Deserialization errors

| Condition | Error |
|-----------|-------|
| Input shorter than 193 bytes | `ArxiaError::DataTooShort { got, expected: 193 }` |
| `kind` byte not in `{0x00, 0x01, 0x02, 0x03}` | `ArxiaError::InvalidBlockType(tag)` |

Deserializers **MUST NOT** trust the recomputed hash or the signature:
integrity verification is the responsibility of `verify_block` (§5).

---

## 3. Block kinds

`kind` at offset `0`:

| Value  | Variant   | `amount` semantics       | `dest_src` semantics                 |
|:------:|-----------|--------------------------|--------------------------------------|
| `0x00` | `OPEN`    | `initial_balance`        | `0u8 * 32`                           |
| `0x01` | `SEND`    | transfer amount          | recipient Ed25519 public key (32 B)  |
| `0x02` | `RECEIVE` | `0`                      | hash of the source `SEND` block      |
| `0x03` | `REVOKE`  | `0`                      | hash of the credential being revoked |

### 3.1. OPEN

- Genesis block of an account chain.
- `nonce == 1`.
- `previous` is all-zero.
- `balance == initial_balance`.
- `initial_balance` **MUST** be `<= MAX_INITIAL_BALANCE_PER_ACCOUNT`
  (see [`arxia-core::constants`](../../crates/arxia-core/src/constants.rs));
  violation is rejected with `ArxiaError::SupplyCapExceeded`. This is a
  hard protocol invariant enforced at block creation time.
- Opening an already-opened chain is rejected idempotently (no partial
  mutation, `ArxiaError::AccountAlreadyOpen`).

### 3.2. SEND

- Debits the sender. `balance == prev_balance - amount`.
- `dest_src` is the recipient's **raw** 32-byte Ed25519 public key.
- A SEND is *not* applied to the recipient until the recipient authors
  a matching RECEIVE block on their own chain.

### 3.3. RECEIVE

- Credits the receiver. `balance == prev_balance + amount` where
  `amount` is read from the referenced SEND.
- `dest_src` is the 32-byte Blake3 hash of the source SEND block.
- A given SEND hash may be received **at most once** per account: the
  ledger tracks a per-account `consumed_sources` set and rejects
  `ArxiaError::DuplicateReceive` on replay.

### 3.4. REVOKE

- Administrative block used by the `did:arxia:` method (see
  [`arxia-did`](../../crates/arxia-did/src/lib.rs)) to revoke a
  previously-issued verifiable credential.
- `balance` is unchanged relative to the prior block.
- `dest_src` is the 32-byte Blake3 hash of the credential being revoked.

---

## 4. Hash preimage

The block hash is a 32-byte Blake3 digest computed from a deterministic
ASCII preimage. It is **not** a hash of the 193-byte compact form; it is
a hash of a colon-separated string, defined in
[`arxia-lattice::block::Block::compute_hash`](../../crates/arxia-lattice/src/block.rs):

```text
preimage = hex(account) ":" hex(previous) ":" json(block_type) ":"
           dec(balance) ":" dec(nonce) ":" dec(timestamp)
```

where:

- `hex(account)` — 64 lowercase hex characters of the 32-byte pubkey.
- `hex(previous)` — 64 lowercase hex characters of the 32-byte prior
  block hash; **empty string** (zero characters) iff this is an OPEN.
- `json(block_type)` — `serde_json` serialization of the `BlockType`
  enum variant, adjacently tagged. The exact forms are:

  | Variant   | `json(block_type)` |
  |-----------|--------------------|
  | `OPEN`    | `{"Open":{"initial_balance":<u64>}}`                            |
  | `SEND`    | `{"Send":{"destination":"<64 hex>","amount":<u64>}}`            |
  | `RECEIVE` | `{"Receive":{"source_hash":"<64 hex>"}}`                        |
  | `REVOKE`  | `{"Revoke":{"credential_hash":"<64 hex>"}}`                     |

- `dec(x)` — base-10 decimal, no leading zeros, no sign, no separators.

```text
hash = blake3(preimage)          // 32 bytes
```

### 4.1. Timestamp determinism (informative)

Because `timestamp` is a *parameter* of `compute_hash` rather than a
call to `SystemTime::now()`, the hash is a pure function of the
serialized payload. Two nodes with out-of-sync wall clocks that receive
the same 193 bytes compute the same 32-byte hash. Regression tests in
[`arxia-lattice::serialization::tests`](../../crates/arxia-lattice/src/serialization.rs)
pin this property against future refactors.

### 4.2. Preimage uniqueness

The string formatting above is injective over well-formed blocks: every
unambiguous block maps to exactly one preimage, and decoding any of the
four variants from the JSON form is round-trip-exact. Implementations
**MUST NOT** introduce whitespace, reorder keys, or change the variant
tagging strategy.

---

## 5. Signatures

Arxia blocks are signed with **Ed25519** (`ed25519-dalek` v2) over the
raw 32-byte Blake3 hash:

```text
signature = Ed25519.sign(signing_key, hash)       // hash is 32 bytes
```

Reference sign sites:
[`AccountChain::open`](../../crates/arxia-lattice/src/chain.rs),
[`AccountChain::send`](../../crates/arxia-lattice/src/chain.rs),
[`AccountChain::receive`](../../crates/arxia-lattice/src/chain.rs).

Verification is performed by
[`arxia-lattice::validation::verify_block`](../../crates/arxia-lattice/src/validation.rs),
which:

1. Recomputes the hash from the block's declared payload (§4) and
   checks byte-equality with `block.hash` → `HashMismatch` on failure.
2. Parses `block.account` as an Ed25519 `VerifyingKey`.
3. Parses `block.signature` as an Ed25519 `Signature`.
4. Verifies the signature over the **raw hash bytes** (not the hex
   string) → `InvalidSignature` on failure.

Signatures are always performed over **raw bytes**, never over the hex
encoding. Implementations that sign the hex string will produce
signatures rejected by every compliant verifier.

### 5.1. Insertion-path verification

`verify_block` is called on **every** insertion path — local creation,
gossip ingress, and CRDT reconciliation — and is not optional. Any path
that bypasses it is a protocol violation.

---

## 6. Other hashes

For completeness, the following hashes are computed elsewhere in the
protocol and have independent preimage rules:

### 6.1. ORV consensus vote hash

Used by the Open Representative Voting layer; see
[`arxia-consensus::vote::compute_vote_hash`](../../crates/arxia-consensus/src/vote.rs).

```text
preimage = block_hash(32) || voter_pubkey(32) || delegated_stake(u64 LE, 8) || nonce(u64 LE, 8)
hash     = blake3(preimage)            // 32 bytes
```

Note that vote-hash integers are **little-endian**, in contrast with the
big-endian block layout in §2. This asymmetry is intentional and frozen;
reconciling it is a non-goal for `v0.1.x`.

### 6.2. DID identifier

The `did:arxia:` method derives its identifier from the account public
key as follows; see [`arxia-did`](../../crates/arxia-did/src/lib.rs).

```text
did = "did:arxia:" || base58(blake3(pubkey))
```

---

## 7. Protobuf wire format (informative)

Gossip and transport messages carry blocks inside protobuf envelopes
defined in
[`arxia-proto`](../../crates/arxia-proto/proto/arxia.proto). The
`CompactBlock` message is a field-by-field mirror of §2 and is **not**
canonical: two peers that disagree about a protobuf encoding (field
order, wire-format tags, repeated-field packing) will still agree about
the 193-byte compact form and the 32-byte hash, and that is what
consensus operates on.

---

## 8. Test vectors

Canonical vectors are generated from the reference implementation and
asserted by the regression suite. The primary pinning tests are:

| Property                                   | Location |
|--------------------------------------------|----------|
| Round-trip equality                        | `test_compact_round_trip_open`, `test_compact_round_trip_send` |
| Fixed size (193 bytes)                     | `test_compact_size_193_bytes` |
| Deserialization error on short input       | `test_from_compact_too_short` |
| Hash determinism across round-trip         | `test_hash_is_deterministic_across_round_trip` |
| Hash stability across delayed deserializ.  | `test_hash_stable_across_delayed_deserialization` |
| Tampering on the timestamp bytes flips hash| `test_hash_changes_when_timestamp_bytes_are_mutated` |
| Two nodes agree on the same bytes' hash    | `test_two_nodes_compute_same_hash_for_same_bytes` |
| Explicit `compute_hash` matches stored hash| `test_explicit_timestamp_control_produces_stable_hash` |

All located in
[`crates/arxia-lattice/src/serialization.rs`](../../crates/arxia-lattice/src/serialization.rs).

---

## 9. Change history

| Version | Change |
|---------|--------|
| `0.1.0` | Initial 193-byte layout, Blake3 preimage, Ed25519 over raw hash. |
