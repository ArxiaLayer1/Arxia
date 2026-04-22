# Offline Consensus: Why Block Lattice Over Linear Chain

## The Problem

Traditional blockchains require continuous network connectivity for
block production and validation. In environments with intermittent
connectivity (rural areas, disaster zones, developing regions), this
model fails.

## Linear Chain Limitations

In Bitcoin/Ethereum-style linear chains:
1. A single block producer must be elected per time slot
2. All validators must see the block to vote/attest
3. Transactions are ordered globally, creating bottlenecks
4. Forks require expensive reorganization
5. Offline nodes cannot participate at all

## Block Lattice Advantages

### Per-Account Parallelism

Each account maintains its own chain. Alice can create blocks while
completely disconnected from Bob. When they reconnect, their chains
are independent and don't conflict (unless Alice sent to Bob).

### No Total Ordering Needed

Send/Receive pairs create cross-account references, but there's no
requirement for a global ordering of all transactions. This eliminates
the need for a leader election protocol.

### CRDT Reconciliation

When partitioned networks reconnect:
1. Exchange nonce registries (compact: ~40 bytes per account)
2. Detect conflicts (same account, same nonce, different hash)
3. Resolve via ORV 3-tier cascade
4. Merge CRDT state (mathematically guaranteed convergence)

### Partition Tolerance

CAP theorem forces a choice between consistency and availability during
partitions. Arxia chooses availability (users can transact) with eventual
consistency (CRDTs converge after partition heals).

## Comparison with Nano

| Feature           | Nano                  | Arxia                      |
|-------------------|-----------------------|----------------------------|
| Transport         | TCP/IP only           | LoRa, BLE, SMS, Satellite  |
| Consensus         | ORV (online)          | ORV + CRDT (offline-first) |
| Conflict handling | Online resolution     | 3-tier cascade + offline   |
| Smart contracts   | None                  | WASM runtime               |
| Identity          | Account-based         | W3C DID                    |
| Target devices    | Servers               | ESP32, mobile phones       |

## Comparison with Bitcoin

| Feature           | Bitcoin               | Arxia                      |
|-------------------|-----------------------|----------------------------|
| Structure         | Linear chain          | Block lattice (DAG)        |
| Consensus         | Proof of Work         | ORV (stake-weighted)       |
| Finality          | Probabilistic (~60m)  | Progressive (L0-L2)        |
| Offline use       | Not possible          | Core design principle      |
| Energy            | High                  | Negligible                 |
| Block size        | 1-4 MB                | 193 bytes                  |
