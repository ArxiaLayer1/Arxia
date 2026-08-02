# Running an Arxia Node

> **Status:** Testnet only. Mainnet node operation is not yet available.
> This guide covers running an Arxia relay node on the development testnet.
> Hardware deployment instructions are in [HARDWARE_SETUP.md](HARDWARE_SETUP.md).
>
> **Binary status:** the `arxia-node` binary at `bin/arxia-node` is
> currently a stub. The CLI surface documented below
> (`init`, `start`, `peer connect|list|disconnect`,
> `sync --from-snapshot`, `relay score|receipts`,
> `storage stats|prune`) describes the planned interface gated by
> `docs/SECURITY_INTERFACES.md` (HIGH-027). The stub binary emits
> a `STUB BINARY` warning at runtime and silently no-ops these
> subcommands. The node-runtime implementation is on the M6-M12
> roadmap ; this guide is the contract the implementation will
> honour.

---

## Table of Contents

1. [Node Types](#node-types)
2. [Requirements](#requirements)
3. [Quick Start (x86_64)](#quick-start-x86_64)
4. [Configuration](#configuration)
5. [Transport Configuration](#transport-configuration)
6. [Peer Discovery](#peer-discovery)
7. [Block Sync](#block-sync)
8. [Becoming a Relay Validator](#becoming-a-relay-validator)
9. [Storage](#storage)
10. [Metrics and Monitoring](#metrics-and-monitoring)
11. [ESP32 T-Beam Node](#esp32-t-beam-node)
12. [Troubleshooting](#troubleshooting)
13. [Roadmap](#roadmap)

---

## Node Types

Arxia has three node configurations:

| Type           | Hardware              | Role                               | Staking Required |
|----------------|-----------------------|------------------------------------|------------------|
| **Full node**  | Linux server / RPi    | Stores full DAG, validates L2      | Optional         |
| **Relay node** | T-Beam ESP32          | Relays transactions over LoRa mesh | 500 ARX          |
| **Light node** | Smartphone            | Wallet only, queries relay nodes   | No               |

This guide covers the **full node** (x86_64/ARM) and **relay node** (ESP32).
Light node setup is handled by the Arxia mobile app (planned M12-M18).

---

## Requirements

### Full Node (x86_64 / ARM64)

| Component | Minimum               | Recommended       |
|-----------|-----------------------|-------------------|
| OS        | Linux (Ubuntu 22.04+) | Ubuntu 24.04 LTS  |
| CPU       | 2 cores               | 4 cores           |
| RAM       | 2 GB                  | 4 GB              |
| Disk      | 20 GB SSD             | 100 GB SSD        |
| Network   | 10 Mbps               | 100 Mbps          |
| Rust      | 1.85.0+               | Latest stable     |

Disk usage grows at approximately 2 GB/year under normal load. Pruned snapshots
are taken every 100,000 blocks.

### Relay Node (ESP32 T-Beam)

See [HARDWARE_SETUP.md](HARDWARE_SETUP.md) for the complete hardware guide.
Minimum: TTGO T-Beam v1.1 (~$31), 18650 battery, LoRa antenna.

---

## Quick Start (x86_64)

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
```

### 2. Clone and build

```bash
git clone https://github.com/ArxiaLayer1/Arxia.git
cd Arxia
cargo build --release -p arxia-node
```

Build time: approximately 3-5 minutes on a modern machine.

### 3. Initialize node

```bash
./target/release/arxia-node init --data-dir ~/.arxia
```

This generates:
- Ed25519 keypair for the node identity
- Default configuration file at `~/.arxia/config.toml`
- An empty data directory at `~/.arxia/db/`

### 4. Start the node

```bash
./target/release/arxia-node start --config ~/.arxia/config.toml
```

On first start, the node will connect to bootstrap peers, begin syncing the
block DAG, and start listening for incoming LoRa/BLE relay connections.

---

## Configuration

The node configuration file is at `~/.arxia/config.toml`. Key sections:

```toml
[node]
keypair_path = "~/.arxia/node_keypair.bin"
name = "my-arxia-node"

[network]
bootstrap_peers = [
    "/ip4/testnet.arxia.one/tcp/9000/p2p/QmXxxxx",
]
listen_addr = "0.0.0.0:9000"

[storage]
data_dir = "~/.arxia/db"
snapshot_interval = 100000

[transport]
lora_enabled = false
ble_enabled = false
simulated_enabled = true   # testnet default, no hardware required

[consensus]
min_representative_stake = 1000000000  # 0.001 ARX in nanoARX

[metrics]
enabled = true
listen_addr = "127.0.0.1:9090"
```

---

## Transport Configuration

### Simulated Transport (testnet default)

No hardware required. Simulates LoRa latency and packet loss for development.
Configured automatically when `simulated_enabled = true`.

### LoRa / Meshtastic (production)

Requires a T-Beam with Meshtastic firmware connected over serial USB:

```toml
[transport.lora]
enabled = true
serial_port = "/dev/ttyUSB0"
baud_rate = 115200
spreading_factor = 9        # SF9 default — 15km range
frequency_mhz = 868.0       # EU 868MHz — use 915.0 for North America
duty_cycle_pct = 1.0        # EU regulatory limit
```

### BLE (proximity payments)

```toml
[transport.ble]
enabled = true
adv_interval_ms = 100
```

### SMS Gateway (fallback)

```toml
[transport.sms]
enabled = false
modem_port = "/dev/ttyUSB1"
```

---

## Peer Discovery

On startup, the node connects to the bootstrap peers in `config.toml`. These
peers share their own peer lists, expanding the node's view of the network.

```bash
# Connect to a specific peer manually
arxia-node peer connect /ip4/192.168.1.100/tcp/9000/p2p/QmYyyy

# List connected peers
arxia-node peer list
```

---

## Block Sync

On first start, the node downloads the full block DAG from peers. Progress is
visible in the logs:

```
[2026-03-19T12:00:00Z] INFO arxia_node: Syncing — 45,231 / 128,400 blocks (35%)
```

**Faster initial sync via snapshot:**

```bash
arxia-node sync --from-snapshot https://snapshots.arxia.one/latest
```

Snapshots are signed by the Arxia Foundation Ed25519 key and verified locally
before application.

---

## Becoming a Relay Validator

To earn ARX rewards, a node must:

1. Stake **500 ARX minimum** via a `STAKE` transaction (available post-TGE)
2. Maintain a **relay score ≥ 85%** over a 30-day rolling window
3. Accumulate `RelayReceipts` — Ed25519-signed proofs of relayed transactions

```
score = valid_relay_receipts / transactions_in_range (30d)
reward = (node_score / total_network_score) × monthly_emission
```

```bash
arxia-node relay score          # view your current score
arxia-node relay receipts       # view pending receipt batches
```

**Slashing conditions:**

| Condition                  | Penalty                           |
|----------------------------|-----------------------------------|
| Score < 85% over 30 days   | −10% stake                        |
| Score < 60% over 7 days    | −25% stake + 30-day exclusion     |

---

## Storage

> **Status: not yet implemented.** The node binary is a stub (see the
> banner at the top of this guide), and no persistent storage backend
> ships today. Everything in this section describes the intended
> design, not current behaviour. It is written down so the interface
> is agreed before it is built — treat it as a contract for future
> work, not as instructions you can follow now.

### What exists today

`arxia-storage` defines a `StorageBackend` trait — a byte-keyed
key/value interface (`put` / `get` / `delete` / `contains`) with a
transaction API (`begin_transaction` / `commit` / `rollback`) and
checksum-wrapping helpers for stored values.

The only implementations are in-memory: `MemoryStorage` and a
thread-safe `ConcurrentMemoryStorage`. They are used by the test
suite. A running node therefore holds all state in RAM and loses it
on restart.

### What is being built

A persistent backend behind that same trait. Two constraints shape
the work, and they do not admit a single engine:

- **Full nodes** (Linux x86_64 / ARM) need multi-key atomic commit:
  applying a block updates the chain, the send index, the consumed-
  source set and the supply accumulator, and a half-applied block
  must never be observable.
- **Light nodes** (ESP32 T-Beam) have roughly 520 KB of SRAM and a
  4 MB SPI flash. That rules out server-class embedded databases
  outright, so the device side needs a flash-aware, allocation-free
  design with wear levelling and power-loss recovery.

The trait also needs an ordered-iteration primitive before either
backend can be written: reading an account chain and verifying its
integrity both require prefix scans, which the current interface
does not offer.

Specific backend choices are not published here until they are
implemented and measured. Replacing one inaccurate description
with another would defeat the purpose of this correction.

### Capacity, measured

With state held in RAM, a light node saturates at roughly 336
transfers (~1.5 KB retained per transfer, no pruning). Moving to
flash is what lifts that ceiling; the figure will be restated here
once it is measured on hardware rather than derived.

---

## Metrics and Monitoring

Prometheus metrics are available at `http://127.0.0.1:9090/metrics`.

| Metric                       | Description                           |
|------------------------------|---------------------------------------|
| `arxia_blocks_total`         | Total blocks in local DAG             |
| `arxia_peers_connected`      | Active peer connections               |
| `arxia_relay_receipts_total` | Relay receipts issued (30d)           |
| `arxia_relay_score`          | Current relay score (0.0–1.0)         |
| `arxia_lora_tx_total`        | LoRa frames transmitted               |
| `arxia_lora_rx_total`        | LoRa frames received                  |
| `arxia_finality_l0_total`    | L0 finality events                    |
| `arxia_finality_l1_total`    | L1 finality events (gossip confirmed) |
| `arxia_finality_l2_total`    | L2 finality events (global consensus) |

A Grafana dashboard template is available at `scripts/grafana-dashboard.json`.

---

## ESP32 T-Beam Node

For field deployment, the Arxia relay firmware runs directly on a T-Beam ESP32
with no x86_64 host required.

### Flash the firmware

```bash
cargo install espflash
cd targets/esp32
cargo build --release --target xtensa-esp32-espidf
espflash flash --monitor target/xtensa-esp32-espidf/release/arxia-esp32
```

### ESP32 relay behavior

- Listens for Arxia transactions over LoRa radio
- Gossips nonce registries with neighboring nodes before confirming L1
- Signs and submits `RelayReceipts`
- Persists nonce registry to NVS flash (survives power cycles)
- Does not store the full block DAG (light relay mode only)

---

## Troubleshooting

**`keypair not found` on startup**
Run `arxia-node init --data-dir ~/.arxia` to generate the keypair.

**Sync stalls at a specific height**
A peer may be serving a forked chain. Disconnect and reconnect to bootstrap peers:
```bash
arxia-node peer disconnect --all
```

**LoRa transport not connecting**
Check that the T-Beam is powered and running Meshtastic firmware. Verify the
serial port path with `ls /dev/ttyUSB*` on Linux.

**High memory usage**
Expected: all state is currently held in RAM, and nothing is pruned.
A long-running node grows without bound. There is no cache setting to
reduce — persistent storage is the fix, and it is not shipped yet.

**Relay score dropping**
Check for sustained network interruptions. The 30-day window absorbs brief
outages — sustained downtime will eventually trigger slashing.

---

## Roadmap

| Milestone | Deliverable                                             |
|-----------|---------------------------------------------------------|
| M3-M6     | Testnet public — full node + simulated transport        |
| M6-M12    | LoRa physical transport (Meshtastic integration)        |
| M6-M12    | Staking and RelayReceipt on testnet                     |
| M6-M12    | Prometheus metrics + Grafana dashboard                  |
| M12-M18   | ESP32 firmware v1.0 (gossip ported to no_std)           |
| M12-M18   | BLE and SMS transport                                   |
| M18-M24   | Mainnet node operation                                  |

---

*Last updated: 2026-03-19 — v29*
