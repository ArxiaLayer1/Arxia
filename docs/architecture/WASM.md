# Arxia WASM Runtime

> **Status:** Specified. Implementation target M12-M18. The ABI and execution
> model described here are final. The Wasmer integration is not yet coded.

---

## Table of Contents

1. [Overview](#overview)
2. [Design Goals](#design-goals)
3. [Execution Model](#execution-model)
4. [Finality Tiers and Instruction Limits](#finality-tiers-and-instruction-limits)
5. [Host ABI](#host-abi)
6. [Contract Deployment](#contract-deployment)
7. [Contract Addressing](#contract-addressing)
8. [Fee Model](#fee-model)
9. [Offline Execution](#offline-execution)
10. [Security Model](#security-model)
11. [Example Contract](#example-contract)
12. [Roadmap](#roadmap)

---

## Overview

Arxia supports WebAssembly (WASM) smart contracts executed in a sandboxed,
metered runtime powered by [Wasmer](https://wasmer.io/). Contracts are compiled
to `.wasm` bytecode and deployed via a `DEPLOY` block on the Arxia Block Lattice.

The runtime is designed for offline-first execution: contracts that fit within
the L0/L1 instruction budget can be evaluated locally on a T-Beam node or a
smartphone without any network connectivity.

---

## Design Goals

| Goal                  | Design Decision                                              |
|-----------------------|--------------------------------------------------------------|
| Offline execution     | Instruction-metered sandbox, no network calls from contracts |
| Determinism           | Pure function execution, no floating point, no randomness    |
| Resource constraints  | Hard limits on instructions, memory, and contract size       |
| Minimal attack surface| No dynamic linking, no syscalls, no filesystem access        |
| Rust-first            | Contracts written in Rust, compiled to WASM via `wasm32`     |

---

## Execution Model

Contract execution follows a strict call-response model:

```
Caller wallet
    │
    ▼
CALL transaction (signed, includes contract address + calldata)
    │
    ▼
Arxia WASM Runtime (Wasmer sandbox)
    │   ├── Instruction counter initialized
    │   ├── Memory limit enforced (4MB max)
    │   ├── Host functions injected (see ABI)
    │   └── Contract entry point invoked
    │
    ▼
Execution result (success / revert / out-of-gas)
    │
    ▼
State changes written to Block Lattice (on success only)
```

Execution is **atomic**: either all state changes from a contract call are
applied, or none are (revert). Partial state is never written.

If the instruction limit is exceeded, execution halts immediately with an
`OutOfGas` error. Fees are consumed regardless of revert status.

---

## Finality Tiers and Instruction Limits

Contract execution limits depend on the finality tier of the transaction:

| Finality Tier | Instruction Limit | Max Contract Size | Typical Use Case         |
|---------------|-------------------|-------------------|--------------------------|
| L0 (offline)  | 100,000           | 64 KB             | Simple token transfers   |
| L1 (mesh)     | 100,000           | 64 KB             | Escrow, multi-sig        |
| L2 (global)   | 10,000,000        | 1 MB              | Complex DeFi, governance |

L0 and L1 share the same limit because both execute without guaranteed access
to full network state. L2 execution has access to the complete global ledger
and can run significantly more complex logic.

Contracts that exceed the L0/L1 limit are rejected at submission time if they
target offline finality. A contract cannot dynamically escalate its finality tier.

---

## Host ABI

The WASM sandbox exposes five host functions to contracts. These are the only
external calls a contract can make. No other system calls are available.

### `arxia_get_balance`

```rust
fn arxia_get_balance(pubkey_ptr: *const u8) -> u64
```

Returns the current ARX balance (in nanoARX) of the account identified by the
32-byte Ed25519 public key at `pubkey_ptr`.

In offline execution (L0/L1), returns the last known local balance. May not
reflect the global state if the device is partitioned.

---

### `arxia_send`

```rust
fn arxia_send(to_ptr: *const u8, amount_nanoarx: u64) -> bool
```

Creates a `SEND` block from the contract's account to the account at `to_ptr`,
for `amount_nanoarx` nanoARX. Returns `true` on success, `false` if the balance
is insufficient.

The resulting SEND block is queued and broadcast after the contract call completes.
It is not finalized within the contract execution itself.

---

### `arxia_get_block_hash`

```rust
fn arxia_get_block_hash(nonce: u64) -> [u8; 32]
```

Returns the Blake3 hash of the block at the given nonce in the calling account's
chain. Returns `[0u8; 32]` if the nonce does not exist locally.

Useful for contracts that need to reference prior transaction state (e.g., escrow
contracts verifying a prior deposit block).

---

### `arxia_did_verify`

```rust
fn arxia_did_verify(credential_json_ptr: *const u8, len: usize) -> bool
```

Verifies a W3C Verifiable Credential against the local DID resolver. Returns
`true` if the credential is valid, not revoked, and issued by a known DID.

In offline operation, verification is performed against the locally cached DID
document DAG. A credential issued in a remote partition may not be verifiable
until the partition reconnects.

---

### `arxia_log`

```rust
fn arxia_log(msg_ptr: *const u8, len: usize)
```

Emits a log message visible in node debug output. Has no effect on contract
state and does not consume meaningful instruction budget. Stripped from
production builds.

---

## Contract Deployment

Contracts are deployed via a signed `DEPLOY` block on the Arxia Block Lattice:

```
DEPLOY block {
    account:    deployer_pubkey,
    prev_hash:  previous_block_hash,
    bytecode:   wasm_bytes,       // must be valid WASM, ≤ 64KB for L0/L1
    init_args:  calldata_bytes,   // passed to contract constructor
    nonce:      sequential_nonce,
    signature:  ed25519_sig,
}
```

The deployment fee scales with bytecode size:

```
deploy_fee = ceil(bytecode_bytes / 100) × BASE_FEE_ARX × DEPLOY_MULTIPLIER
```

Where `DEPLOY_MULTIPLIER = 10` (deploying costs 10× more per byte than a
standard transaction, to discourage bytecode bloat).

---

## Contract Addressing

A deployed contract's address is the Blake3 hash of its bytecode:

```
contract_address = blake3(wasm_bytecode)
```

This means:
- Identical bytecode deployed twice produces the same address (idempotent)
- The address is verifiable without trusting any registry
- Contract upgrades require deploying a new address (immutable by default)

Mutable proxy patterns are possible but must be implemented explicitly by the
contract author — the runtime does not provide built-in upgradeability.

---

## Fee Model

| Action              | Fee Formula                                              |
|---------------------|----------------------------------------------------------|
| Deploy              | `ceil(bytes/100) × BASE_FEE × 10`                       |
| Call (success)      | `ceil(calldata_bytes/100) × BASE_FEE + gas_used × RATE` |
| Call (revert)       | Same as success — fees are not refunded on revert        |
| Out-of-gas          | Full instruction budget consumed                         |

`BASE_FEE_ARX = 0.001 ARX`. The gas rate (`RATE`) is set by governance and
targets a fixed USD-equivalent cost per 1M instructions.

---

## Offline Execution

WASM contracts can execute in L0/L1 offline mode with the following constraints:

**Available in offline execution:**
- `arxia_get_balance` (local state only)
- `arxia_send` (queued, broadcast when connectivity returns)
- `arxia_get_block_hash` (local chain only)
- `arxia_log`

**Not available in offline execution:**
- `arxia_did_verify` requires the local DID cache to be populated. If the
  relevant DID document has not been synced, verification returns `false`.

**State consistency warning:**
Contracts that read balance or block state during L0/L1 execution operate on
local state that may diverge from global state. Contracts designed for offline
use should implement conservative logic (assume less state, not more) and
treat L0/L1 results as probabilistic rather than final.

---

## Security Model

### Sandbox isolation

Each contract execution runs in a Wasmer sandbox with:
- No access to the host filesystem
- No network calls (all external interaction via host ABI only)
- No dynamic library loading
- Separate linear memory per execution (zero shared state between calls)

### Reentrancy

The Arxia runtime does not support nested contract calls in the current
specification. A contract cannot call another contract. This eliminates the
reentrancy attack vector that has caused significant losses on EVM chains
(DAO hack, various DeFi exploits).

Cross-contract interaction is planned for L2 execution in a future AIP.

### Integer arithmetic

Contracts must use saturating or checked arithmetic. The runtime does not trap
on integer overflow — it wraps. Contract authors are responsible for overflow
safety. The Arxia Rust SDK (planned M12-M18) will provide safe arithmetic
primitives.

### No floating point

Floating point operations are determinism-breaking across platforms. The Wasmer
configuration used by Arxia rejects contracts that include floating point
instructions at deployment time.

---

## Example Contract

A minimal time-locked escrow contract in Rust, targeting the Arxia WASM ABI:

```rust
// escrow.rs — compile with: cargo build --target wasm32-unknown-unknown --release

#![no_std]

extern "C" {
    fn arxia_get_balance(pubkey_ptr: *const u8) -> u64;
    fn arxia_send(to_ptr: *const u8, amount: u64) -> bool;
    fn arxia_get_block_hash(nonce: u64) -> [u8; 32];
}

static RECIPIENT: [u8; 32] = [/* recipient pubkey bytes */0u8; 32];
static UNLOCK_NONCE: u64 = 100; // release after block nonce 100

#[no_mangle]
pub extern "C" fn release() -> bool {
    // Verify the unlock condition: block at nonce must exist
    let block_hash = unsafe { arxia_get_block_hash(UNLOCK_NONCE) };
    if block_hash == [0u8; 32] {
        return false; // unlock nonce not yet reached
    }

    // Send full balance to recipient
    let balance = unsafe { arxia_get_balance(RECIPIENT.as_ptr()) };
    unsafe { arxia_send(RECIPIENT.as_ptr(), balance) }
}
```

This contract compiles to approximately 2-4 KB of WASM bytecode — well within
the 64 KB L0/L1 limit.

---

## Roadmap

| Milestone | Deliverable                                                  |
|-----------|--------------------------------------------------------------|
| M12-M18   | Wasmer sandbox integration                                   |
| M12-M18   | Host ABI implementation (all 5 functions)                    |
| M12-M18   | Instruction metering (100k L0/L1, 10M L2)                   |
| M12-M18   | Contract deployment via DEPLOY block                         |
| M12-M18   | Arxia Rust SDK (safe arithmetic, ABI bindings)               |
| M18-M24   | Cross-contract calls (L2 only)                               |
| M18-M24   | Contract upgradeability patterns (proxy standard)            |
| M24+      | Formal verification tooling for critical contracts           |

The WASM runtime is not on the critical path for the seed round or testnet
launch. L0/L1 transactions (the core offline-first value proposition) do not
require smart contract execution. The runtime is an extension of the protocol,
not a prerequisite for it.

---

*Last updated: 2026-03-19 — v29*
