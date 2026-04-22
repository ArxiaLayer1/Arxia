# Block Lattice Specification

## Overview

Arxia uses a block-lattice structure inspired by Nano. Each account maintains
its own chain of blocks, forming a directed acyclic graph (DAG) when
cross-account references are considered.

## Block Types

| Type      | Purpose                                    |
|-----------|--------------------------------------------|
| `Open`    | Genesis block, sets initial balance         |
| `Send`    | Debit from sender, references destination   |
| `Receive` | Credit to receiver, references source hash  |
| `Revoke`  | Revoke a DID credential                     |

## Block Structure

Each block contains:
- `account`: Hex-encoded Ed25519 public key (64 hex chars)
- `previous`: Hash of the previous block in this account chain (empty for Open)
- `block_type`: One of Open/Send/Receive/Revoke
- `balance`: Account balance after this block
- `nonce`: Monotonically increasing counter (starts at 1)
- `timestamp`: Unix milliseconds
- `hash`: Blake3 hash of `"{account}:{previous}:{block_type_str}:{balance}:{nonce}:{timestamp}"`
- `signature`: Ed25519 signature over raw Blake3 hash bytes (32 bytes)

## Hash Computation

```rust
fn compute_hash(account, previous, block_type, balance, nonce, timestamp) -> String {
    let input = format!("{}:{}:{}:{}:{}:{}", account, previous, block_type, balance, nonce, timestamp);
    blake3::hash(input.as_bytes()).to_hex().to_string()
}
```

## Signature Invariant

**Ed25519 signatures are computed over raw Blake3 bytes (32 bytes), NOT over
the hex-encoded string (64 bytes).** This is a critical invariant.

```rust
let hash_bytes = hex::decode(&hash).expect("valid hex hash");
let signature = signing_key.sign(&hash_bytes);
```

## Chain Integrity

- Each block's `previous` field must equal the `hash` of the preceding block
- Nonces must be strictly monotonically increasing
- Balance must never go negative
- Send amount must be > 0

## Advantages Over Linear Chains

1. **No total ordering needed**: Blocks from different accounts are independent
2. **Parallel processing**: Each account chain can be validated independently
3. **Offline operation**: Users can create blocks without network access
4. **Conflict isolation**: Double-spends only affect the offending account
