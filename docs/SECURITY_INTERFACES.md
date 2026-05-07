# `bin/arxia-node` — Security Interfaces

**Status:** drafted (HIGH-027, commit 087). Gates the implementation
PR for the production node binary.

This document specifies the security contract every subsystem of
the production Arxia node MUST satisfy before the
`bin/arxia-node` stub can be replaced by a real implementation.
Each section describes one subsystem boundary, the threats at
that boundary, and the test surface that must exist before the
subsystem can be wired into the node.

A future implementation PR for `bin/arxia-node` SHALL be merged
only after every requirement below is either satisfied (with a
linked test) or explicitly deferred with a tracked exception in
the audit register.

---

## 1. Argument parsing & configuration loading

**Boundary:** untrusted input from `argv`, environment variables,
and a possible config file path.

**Requirements:**

- `argv` parsing MUST NOT panic on any byte sequence (including
  invalid UTF-8 encountered via `OsString`). Use a parser
  (`clap`, `argh`, or hand-rolled) that surfaces malformed input
  as a typed error.
- Secrets (signing keys, network passphrases) MUST NOT be
  accepted via `argv` — only via env or a permission-gated
  config file. Documented rationale: `argv` leaks to `ps` /
  `/proc/<pid>/cmdline` and into shell history.
- The config file path MUST be canonicalized BEFORE open, and
  the resolved path MUST be inside an explicit allow-list
  (typically `$HOME/.config/arxia/` or `/etc/arxia/`). Path
  traversal (`../../`) MUST be rejected loudly.
- A malformed config file MUST cause the node to refuse to
  start with a typed error — never silently fall back to a
  default profile.

**Tests required:**
- Argv fuzzing (e.g. `cargo fuzz` or `arbitrary`-driven property
  test) on the parser entry point. No panic, no UB.
- `test_argv_rejects_secret_in_command_line_flag`.
- `test_config_path_traversal_rejected`.
- `test_corrupt_config_refuses_startup`.

---

## 2. Signal handling & shutdown

**Boundary:** OS signals (SIGTERM / SIGINT / SIGHUP on Unix ;
Ctrl-C / Ctrl-Break on Windows).

**Requirements:**

- SIGTERM and SIGINT MUST trigger a graceful shutdown sequence:
  1. Stop accepting new transactions / gossip envelopes.
  2. Drain in-flight reconciliation tasks.
  3. Flush the storage backend (HIGH-020 transactionality
     guarantee MUST be respected — partial writes are
     unacceptable).
  4. Close all transports cleanly (drain outboxes).
  5. Exit with code 0.
- Shutdown MUST be idempotent: a second signal during shutdown
  triggers an immediate hard-exit (code 1) rather than re-entry.
- A 30-second timeout on the graceful sequence is the production
  default ; if it elapses, hard-exit with code 124 (SIGTERM
  convention) and emit a `tracing::error!` event with the stuck
  subsystem name.
- SIGHUP (Unix only) MUST trigger a config reload that
  re-validates against the same allow-list as section 1, NOT a
  graceful shutdown.

**Tests required:**
- `test_sigterm_flushes_storage_before_exit` (integration test
  spawning the binary, sending SIGTERM, verifying the storage
  backend's WAL is consistent).
- `test_double_signal_hard_exits` (not a test_panic).
- `test_shutdown_timeout_emits_diagnostic`.

---

## 3. Storage backend initialization

**Boundary:** persistent state on disk, possibly corrupted by a
prior unclean shutdown.

**Requirements:**

- The storage backend MUST refuse to open if the on-disk
  write-ahead log (or equivalent atomicity primitive) does not
  recover cleanly. Refuse to start ; never silently elide
  partial state. (Ties to HIGH-020.)
- The backend MUST reject database files whose checksum does
  not match the per-key checksum (LOW-011 from commit 082 ; the
  helper `wrap_with_checksum` is the building block).
- On first start (no on-disk state), the backend MUST create
  files with mode 0600 (Unix) or equivalent ACLs (Windows).
  World-readable storage of nonce registries leaks chain
  metadata.
- Migration from one storage version to the next MUST be
  explicit (versioned schema), and the node MUST refuse to
  open a newer-version DB with an older binary.

**Tests required:**
- `test_storage_init_refuses_corrupted_wal`.
- `test_storage_init_refuses_checksum_mismatch`.
- `test_storage_init_creates_files_with_mode_0600`.
- `test_storage_init_refuses_newer_schema_version`.

---

## 4. Network binding & transport listen

**Boundary:** the OS network stack, before any peer is admitted.

**Requirements:**

- The node MUST bind to `127.0.0.1` (or its configured BLE /
  LoRa local interface) by default. Binding to `0.0.0.0` (or
  routable ipv6) requires an explicit `--public` flag AND a
  non-default firewall rule documented in the deployment guide.
- Transport listen MUST happen AFTER storage init succeeds. A
  half-open node that accepts gossip but cannot persist it is
  a vector for HIGH-008 / HIGH-014 amplification.
- TLS / Noise handshake on TCP transports (when added) MUST be
  rejected if the peer does not present a key matching the
  registered relay set (HIGH-008 receipt registry from
  commit 029).
- Per-peer rate limits MUST be enabled before listen starts,
  not lazily on first message.

**Tests required:**
- `test_node_binds_localhost_by_default`.
- `test_node_refuses_public_bind_without_explicit_flag`.
- `test_listen_after_storage_init_only`.

---

## 5. Consensus & finality boot

**Boundary:** the node decides whether to trust the on-disk
state as the canonical chain.

**Requirements:**

- The genesis block hash MUST be a compile-time constant
  (already pinned in `arxia_core::constants`). The node MUST
  refuse to start if the on-disk genesis differs ; this is a
  hard fork detector.
- The node MUST reject any peer whose first announced
  finality-state genesis differs from the local genesis, with a
  loud log event (peer is on a different chain).
- The validator registry, if persisted, MUST be loaded with
  HIGH-018 strict pubkey validation on every entry. A
  malformed registry refuses node start.
- The `FinalityLatch` (HIGH-017, commit 042) MUST be persisted
  across restarts. Losing the latch causes the node to
  re-issue receipts at lower finality levels post-restart,
  which is the regression the latch closes.

**Tests required:**
- `test_node_refuses_start_on_genesis_mismatch`.
- `test_validator_registry_load_rejects_off_curve_pubkey`.
- `test_finality_latch_persists_across_restart`.

---

## 6. Logging, telemetry & secrets hygiene

**Boundary:** anything that leaves the process — stdout, stderr,
on-disk log files, future telemetry endpoint.

**Requirements:**

- Signing keys MUST NEVER appear in any log line, even at
  `tracing::Level::TRACE`. The `Display`/`Debug` impls on
  `SigningKey` (or any wrapper) MUST emit a redacted form
  (e.g. `Sk(****[8 hex chars of pubkey])`) to permit
  identification without exposure.
- Receipts and signatures MAY appear in DEBUG-level logs but
  MUST be hex-encoded and rate-limited (one log per 1000
  events at most).
- The node SHALL NOT phone home — no telemetry endpoint
  contacted by default. A future telemetry feature MUST be
  opt-in via `--telemetry-endpoint <URL>` AND the URL MUST be
  in an explicit allow-list (no DNS-rebinding to untrusted
  hosts).
- Crash dumps (panic backtraces) SHALL be redacted of any
  buffer that holds key material before being written to
  stderr.

**Tests required:**
- `test_signing_key_display_does_not_leak_bytes`.
- `test_signing_key_debug_does_not_leak_bytes`.
- `test_no_telemetry_endpoint_by_default`.

---

## 7. Privilege & runtime hardening

**Boundary:** the OS process credentials.

**Requirements:**

- The node MUST refuse to start as `root` / `Administrator`
  unless an explicit `--allow-privileged` flag is set.
- On Linux, the node SHOULD drop CAP_NET_ADMIN /
  CAP_NET_BIND_SERVICE after binding low-privilege ports (if
  any are needed in the future ; current default ports are
  >1024).
- On Windows, the node SHOULD run as a non-administrator
  service account via `sc.exe` configuration ; this is a
  deployment-doc requirement, not a code requirement, but the
  startup logic MUST detect and warn on running as
  Administrator.

**Tests required (some integration / doc only):**
- `test_node_warns_when_running_as_root` (OS-conditional).
- Deployment doc updated with non-admin service account
  instructions.

---

## Closing notes

This document is the audit-acknowledged baseline. It will be
revised when:
- A new subsystem is added to the node (new section).
- An audit fiche specifically targeting one of the above
  subsystems lands (the section is updated to reference the
  fiche ID).
- A test from the "Tests required" lists is implemented (the
  list entry is updated to link the test).

Until `bin/arxia-node` is implemented, the stub binary in
`bin/arxia-node/src/main.rs` MUST emit a startup log line that
references this document so an operator running the stub
understands the gating contract.
