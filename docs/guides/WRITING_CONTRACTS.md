# Writing Smart Contracts for Arxia

> **Status:** The ABI and compilation target described here are final. The
> on-chain deployment mechanism (DEPLOY block) is specified but not yet
> implemented. Target: M12-M18. You can write and test contracts locally today
> using the simulation environment.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Project Setup](#project-setup)
4. [The Arxia Host ABI](#the-arxia-host-abi)
5. [Writing Your First Contract](#writing-your-first-contract)
6. [Testing Locally](#testing-locally)
7. [Deployment](#deployment)
8. [Contract Patterns](#contract-patterns)
9. [Limitations and Constraints](#limitations-and-constraints)
10. [Example Contracts](#example-contracts)

---

## Overview

Arxia smart contracts are WebAssembly modules compiled from Rust. They run in
a sandboxed Wasmer runtime with access to five host functions that cover the
core protocol operations: balance queries, token transfers, block state access,
DID credential verification, and logging.

Contracts are:
- Written in Rust, compiled to `wasm32-unknown-unknown`
- Deployed via a signed `DEPLOY` block on the Block Lattice
- Addressed by `blake3(bytecode)` — immutable by default
- Executable offline at L0/L1 within the 100,000 instruction budget

---

## Prerequisites

```bash
# Rust with the WASM target
rustup target add wasm32-unknown-unknown

# wasm-opt for bytecode optimization (recommended)
cargo install wasm-opt --locked

# wasm-strip to minimize binary size
cargo install wasm-snip --locked
```

---

## Project Setup

Create a new contract project:

```bash
cargo new --lib my-contract
cd my-contract
```

Edit `Cargo.toml`:

```toml
[package]
name = "my-contract"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]  # Required for WASM compilation

[dependencies]
# No external dependencies — keep contracts minimal

[profile.release]
opt-level = "z"       # Optimize for size
lto = true
codegen-units = 1
panic = "abort"       # Required: no unwinding in WASM
strip = true
```

The `#![no_std]` attribute is required — the standard library is not available
in the Arxia WASM sandbox:

```rust
// src/lib.rs
#![no_std]

// Required panic handler for no_std + panic = "abort"
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

---

## The Arxia Host ABI

The runtime exposes five extern functions. Declare them in your contract:

```rust
extern "C" {
    /// Returns the ARX balance (in nanoARX) of the 32-byte public key at ptr.
    fn arxia_get_balance(pubkey_ptr: *const u8) -> u64;

    /// Sends `amount` nanoARX to the account at `to_ptr`.
    /// Returns 1 on success, 0 if balance insufficient.
    fn arxia_send(to_ptr: *const u8, amount_nanoarx: u64) -> u8;

    /// Returns the Blake3 hash (32 bytes) of the block at `nonce`
    /// in the calling account's chain. Returns all zeros if not found.
    fn arxia_get_block_hash(nonce: u64, out_ptr: *mut u8);

    /// Verifies a W3C Verifiable Credential (JSON, UTF-8).
    /// Returns 1 if valid, 0 if invalid or not locally resolvable.
    fn arxia_did_verify(json_ptr: *const u8, json_len: usize) -> u8;

    /// Emits a debug log message. No-op in production builds.
    fn arxia_log(msg_ptr: *const u8, msg_len: usize);
}
```

### Working with pointers

WASM linear memory is a flat byte array. All data exchange with the host uses
raw pointers. The safest pattern is to use fixed-size static arrays for keys
and hashes:

```rust
// Read a balance
let pubkey: [u8; 32] = [...]; // 32-byte Ed25519 public key
let balance = unsafe { arxia_get_balance(pubkey.as_ptr()) };

// Send tokens
let recipient: [u8; 32] = [...];
let success = unsafe { arxia_send(recipient.as_ptr(), 1_000_000) }; // 0.001 ARX

// Get block hash
let mut hash_out = [0u8; 32];
unsafe { arxia_get_block_hash(42, hash_out.as_mut_ptr()) };
```

---

## Writing Your First Contract

A minimal contract that checks a balance and sends a fixed amount:

```rust
#![no_std]

extern "C" {
    fn arxia_get_balance(pubkey_ptr: *const u8) -> u64;
    fn arxia_send(to_ptr: *const u8, amount_nanoarx: u64) -> u8;
    fn arxia_log(msg_ptr: *const u8, msg_len: usize);
}

// Recipient hardcoded at compile time
static RECIPIENT: [u8; 32] = [
    0x92, 0x89, 0x16, 0xc0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const TRANSFER_AMOUNT: u64 = 1_000_000_000; // 1 ARX in nanoARX

#[no_mangle]
pub extern "C" fn transfer() -> u8 {
    let log_msg = b"Initiating transfer";
    unsafe { arxia_log(log_msg.as_ptr(), log_msg.len()) };

    let balance = unsafe { arxia_get_balance(RECIPIENT.as_ptr()) };

    // Only send if recipient has less than 10 ARX
    if balance < 10_000_000_000 {
        unsafe { arxia_send(RECIPIENT.as_ptr(), TRANSFER_AMOUNT) }
    } else {
        0 // Recipient already has enough
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

Compile:

```bash
cargo build --target wasm32-unknown-unknown --release

# Optimize (recommended — reduces bytecode size significantly)
wasm-opt -Oz \
    target/wasm32-unknown-unknown/release/my_contract.wasm \
    -o my_contract_optimized.wasm

# Check size — must be ≤ 64KB for L0/L1 deployment
ls -lh my_contract_optimized.wasm
```

---

## Testing Locally

Until the on-chain deployment mechanism is implemented (M12-M18), test contracts
using the Arxia simulation environment:

```bash
# Run the contract simulation test suite
cargo test -p arxia-wasm

# Or test your contract directly using wasmtime for fast iteration
cargo install wasmtime-cli --locked
wasmtime my_contract_optimized.wasm --invoke transfer
```

Write unit tests that mock the host ABI:

```rust
#[cfg(test)]
mod tests {
    // Mock balances for testing
    static mut MOCK_BALANCE: u64 = 5_000_000_000; // 5 ARX

    // Override the extern functions with test implementations
    // (requires a test harness that links mock implementations)
    #[test]
    fn test_transfer_when_balance_low() {
        // Integration tests for WASM contracts are run via
        // the arxia-wasm crate's simulation environment
        // See: crates/arxia-wasm/tests/
        assert!(true); // placeholder until M12-M18
    }
}
```

---

## Deployment

> **[M12-M18] — On-chain deployment not yet implemented.**

When deployment is available, the process will be:

```bash
# Using the arxia-cli tool
./target/release/arxia-cli deploy \
    --wasm my_contract_optimized.wasm \
    --keypair ~/.arxia/wallet.json \
    --finality l1

# The CLI outputs the contract address (blake3 of bytecode)
# Contract address: 3a7f2c9d...
```

The deployment fee scales with bytecode size. For a typical 4KB contract:

```
deploy_fee = ceil(4096 / 100) × 0.001 ARX × 10 = 0.41 ARX
```

---

## Contract Patterns

### Pattern 1 — Time-locked release

Release funds after a specific block nonce is reached:

```rust
static RECIPIENT: [u8; 32] = [/* ... */0u8; 32];
static UNLOCK_NONCE: u64 = 1000;

#[no_mangle]
pub extern "C" fn release() -> u8 {
    let mut hash = [0u8; 32];
    unsafe { arxia_get_block_hash(UNLOCK_NONCE, hash.as_mut_ptr()) };

    if hash == [0u8; 32] {
        return 0; // Unlock nonce not reached yet
    }

    let balance = unsafe { arxia_get_balance(RECIPIENT.as_ptr()) };
    unsafe { arxia_send(RECIPIENT.as_ptr(), balance) }
}
```

### Pattern 2 — DID-gated transfer

Only transfer if the caller presents a valid Verifiable Credential:

```rust
#[no_mangle]
pub extern "C" fn verified_transfer(
    credential_ptr: *const u8,
    credential_len: usize,
    recipient_ptr: *const u8,
    amount: u64,
) -> u8 {
    // Verify the credential first
    let is_valid = unsafe { arxia_did_verify(credential_ptr, credential_len) };
    if is_valid == 0 {
        return 0; // Credential invalid or not locally resolvable
    }

    // Proceed with transfer
    unsafe { arxia_send(recipient_ptr, amount) }
}
```

This pattern is the foundation for humanitarian disbursement contracts where
funds are released only to wallets that have verified identity credentials
issued by a trusted ONG or government entity.

### Pattern 3 — Multi-party escrow

Hold funds until two parties both call `confirm()`:

```rust
static mut PARTY_A_CONFIRMED: bool = false;
static mut PARTY_B_CONFIRMED: bool = false;
static PARTY_A: [u8; 32] = [/* ... */0u8; 32];
static PARTY_B: [u8; 32] = [/* ... */0u8; 32];
static RECIPIENT: [u8; 32] = [/* ... */0u8; 32];

#[no_mangle]
pub extern "C" fn confirm_a() -> u8 {
    unsafe { PARTY_A_CONFIRMED = true };
    try_release()
}

#[no_mangle]
pub extern "C" fn confirm_b() -> u8 {
    unsafe { PARTY_B_CONFIRMED = true };
    try_release()
}

fn try_release() -> u8 {
    if unsafe { PARTY_A_CONFIRMED && PARTY_B_CONFIRMED } {
        let balance = unsafe { arxia_get_balance(RECIPIENT.as_ptr()) };
        unsafe { arxia_send(RECIPIENT.as_ptr(), balance) }
    } else {
        0
    }
}
```

> **Note:** Static mutable state in WASM is reset on each contract invocation.
> For persistent state across calls, use the block hash as a state anchor and
> encode state in the calldata.

---

## Limitations and Constraints

| Constraint             | Value           | Reason                                      |
|------------------------|-----------------|---------------------------------------------|
| Max bytecode size (L0/L1) | 64 KB        | ESP32 flash constraints                     |
| Max bytecode size (L2) | 1 MB            | Full node storage                            |
| Instruction limit (L0/L1) | 100,000      | Offline execution time budget               |
| Instruction limit (L2) | 10,000,000      | Full node compute budget                    |
| Memory limit           | 4 MB            | Wasmer linear memory cap                    |
| No floating point      | —               | Non-deterministic across platforms          |
| No cross-contract calls| —               | Eliminates reentrancy (planned M18-M24)     |
| No randomness          | —               | Determinism requirement                     |
| No network access      | —               | Offline-first sandbox isolation             |
| No dynamic allocation  | Discouraged     | Use fixed-size arrays where possible        |

### The no-reentrancy rule

Arxia contracts cannot call other contracts in the current specification. This
is a deliberate security decision that eliminates the entire class of reentrancy
vulnerabilities that have caused hundreds of millions in losses on EVM chains.

Cross-contract calls are planned for L2 execution in a future AIP, with a
mandatory reentrancy guard built into the ABI.

### State persistence

WASM linear memory is ephemeral — it does not persist between calls. Contracts
that need persistent state must encode it in calldata and verify it against
block hashes using `arxia_get_block_hash`. This is more complex than EVM storage
slots but eliminates an entire class of storage manipulation vulnerabilities.

---

## Example Contracts

Working example contracts are in the `contracts/` directory:

| Contract          | File                          | Description                     |
|-------------------|-------------------------------|---------------------------------|
| Escrow            | `contracts/escrow/src/lib.rs` | Time-locked fund release        |
| Token lock        | `contracts/token-lock/src/lib.rs` | Vesting schedule enforcement |

Build all examples:

```bash
cargo build --target wasm32-unknown-unknown --release \
    -p escrow \
    -p token-lock
```

---

*Last updated: 2026-03-19 — v29*
