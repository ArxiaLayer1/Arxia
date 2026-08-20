# arxia-esp32-bench

Power-loss bench firmware for the LilyGO T-Beam v1.1 (ESP32). The
protocol it executes — tagged batch traffic, the boot-time audit, the
failure criteria, the halt-on-failure rule — lives in
`crates/arxia-flash-bench` and is documented in
`docs/architecture/POWER_LOSS_PROTOCOL.md`; this binary hands that
crate a real flash chip and a serial line.

This is a standalone Cargo project, not a workspace member: it builds
with the Espressif Rust fork (the `esp` toolchain), which
`rust-toolchain.toml` selects automatically.

## Toolchain

```sh
cargo install espup --locked
espup install --targets esp32
```

On Unix, source `$HOME/export-esp.sh` before building; on Windows the
installer sets the environment variables (a copy lives in
`%USERPROFILE%\export-esp.ps1`).

## Build, commission, run

```sh
cargo build --release
```

First flash of a board (commissioning) — erase the whole chip so the
bench region starts from erased flash, not another firmware's
leftovers:

```sh
espflash erase-flash
```

Flash and watch the serial protocol:

```sh
espflash flash --monitor --chip esp32 target/xtensa-esp32-none-elf/release/arxia-esp32-bench
```

## Serial protocol

One line each, parseable off-device. Log everything: the off-device
log is what accumulates across power cuts.

- `AUDIT … verdict=PASS|FAIL:<criterion>` — once per boot, before any
  traffic.
- `BATCH seq=N ok|committed|uncertain|refused` — one per batch.
- `STATS seq=N reads=… writes=… erases=…` — every 32 batches;
  counters are per-boot.
- `HALT <reason>` — the run has stopped, as the protocol requires on
  any failure; the evidence stays on the medium.

The bench owns the last mebibyte of the 4 MiB part (`0x300000..
0x400000`), addressed absolutely; the application image at `0x10000`
is a few hundred kibibytes and never reaches it.
