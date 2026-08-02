# Getting Started

## Prerequisites

- Rust 1.89.0 or later
- Git

## Clone and Build

```bash
git clone https://github.com/ArxiaLayer1/Arxia.git
cd Arxia
cargo build --workspace
```

> The first build of `arxia-proto` emits
> `warning: arxia-proto@0.1.0: protoc not found, using stub
> protobuf module (LOW-008: cfg=arxia_proto_stub set)` when the
> `protoc` binary is not on `PATH`. This is expected on hosts
> without a Protobuf toolchain ; the workspace falls back to a
> stub module gated by `cfg=arxia_proto_stub`.

## Run Tests

```bash
cargo test --workspace
```

## Run Examples

Each example under `examples/` is its own workspace member binary
(not a Cargo `[[example]]` target). Invoke with `-p`:

```bash
# Offline payment flow
cargo run -p offline_payment

# DID issuance
cargo run -p did_issuance

# Mesh relay simulation
cargo run -p mesh_relay

# Partition reconciliation
cargo run -p partition_reconciliation
```

## Run the Node (Development)

```bash
cargo run --bin arxia-node
```

## CLI Tools

```bash
# Generate a keypair (writes JSON {public_key, private_key} to a file).
# Default output path is ./arxia_keypair.json in the current directory.
# The private key is NEVER printed on stdout — only the public key and the
# output path are shown. The file is created with create_new (refuses to
# overwrite an existing keyfile) and on Unix is mode 0600.
cargo run --bin arxia-cli -- keygen

# Choose an explicit output path:
cargo run --bin arxia-cli -- keygen --out=/path/to/keypair.json
# (or:  cargo run --bin arxia-cli -- keygen --out /path/to/keypair.json)

# Generate a DID
cargo run --bin arxia-cli -- did
```

> **Backup the keypair file offline.** It contains the only copy of the
> Ed25519 secret seed. Never share it or commit it to version control.

## ESP32 Development

Install the ESP32 toolchain:

```bash
cargo install espup
espup install
. ~/export-esp.sh
```

Build for ESP32 (not in workspace):

```bash
cd targets/esp32
cargo build --target xtensa-esp32-none-elf
```

Testing with QEMU:

```bash
cargo install espflash
espflash run --monitor --target esp32
```

## Project Structure

```
Arxia/
  crates/          # Library crates (includes arxia-proto for
                   #   Protobuf definitions)
  bin/             # Binary targets
  tools/           # CLI tools
  examples/        # Example programs (each is its own workspace
                   #   member binary; invoke with `cargo run -p`)
  contracts/       # Smart contract examples
  targets/         # Hardware targets (ESP32)
  docs/            # Documentation
```
