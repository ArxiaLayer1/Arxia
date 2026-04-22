# Arxia Architecture Overview

Arxia is an offline-first Layer 1 blockchain built for environments with
intermittent or no internet connectivity. It operates over LoRa, BLE, SMS,
and satellite links using a block-lattice data structure and CRDT-based
state reconciliation.

## Layer Diagram

```
+------------------------------------------------------------------+
|                       Applications / DApps                        |
+------------------------------------------------------------------+
|                    DID / Verifiable Credentials                   |
+------------------------------------------------------------------+
|                     WASM Smart Contract Runtime                   |
+------------------------------------------------------------------+
|                      Finality Assessment (L0-L2)                  |
+------------------------------------------------------------------+
|        Gossip Protocol  |  ORV Consensus  |  Conflict Resolution  |
+------------------------------------------------------------------+
|                  CRDT Reconciliation (PN-Counter, OR-Set)         |
+------------------------------------------------------------------+
|              Block Lattice (per-account DAG chains)               |
+------------------------------------------------------------------+
|                  Cryptographic Primitives (Ed25519, Blake3)       |
+------------------------------------------------------------------+
|            Transport Layer (LoRa / BLE / SMS / Satellite)         |
+------------------------------------------------------------------+
```

## Crate Dependency Graph

```
arxia-core (types, errors, constants)
  +-- arxia-crypto (Ed25519, Blake3, ChaCha20, SLIP39)
       +-- arxia-lattice (Block, AccountChain, VectorClock)
       |    +-- arxia-crdt (PNCounter, ORSet, reconciliation)
       |    +-- arxia-consensus (ORV votes, conflict resolution, quorum)
       |    +-- arxia-gossip (nonce registry, sync protocol)
       +-- arxia-did (DID generation, W3C format)
       +-- arxia-transport (LoRa, BLE, SMS simulation)
            +-- arxia-relay (relay receipts, scoring, slashing)
  +-- arxia-finality (4-level assessment)
  +-- arxia-storage (pluggable backend)
  +-- arxia-wasm (contract runtime)
  +-- arxia-proto (protobuf definitions)
```

## Design Principles

1. **Offline-first**: Every operation must work without internet. Online
   connectivity improves finality but is never required for basic operation.

2. **Deterministic**: BTreeMap for ordered iteration, xorshift64 PRNG for
   reproducible transport simulation, stable hash ordering for conflict
   resolution.

3. **Minimal trust**: No oracles, no centralized coordinator. Consensus
   emerges from stake-weighted voting and CRDT convergence.

4. **Constrained-device friendly**: 193-byte compact blocks fit LoRa 256B
   MTU. Ed25519 and Blake3 are efficient on ESP32.

5. **Partition tolerant**: CRDTs guarantee eventual consistency after
   network partitions heal. No liveness dependency on quorum for local
   transactions.
