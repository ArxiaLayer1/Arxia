# Dependency Risks — accepted residual risks in the dependency tree

This document records dependencies in the Arxia workspace whose
behaviour has known quirks that we have explicitly reviewed and
accepted rather than mitigated. Each entry is paired with an
explicit version pin in `deny.toml` so that an upstream bump
beyond the accepted-risk envelope is forced through a deliberate
review rather than landing silently.

The version pins in `deny.toml` are the mechanical floor ; this
document is the rationale. They cross-reference each other.

> **Scope.** This document covers behaviour quirks that affect
> the build chain, runtime initialisation, or transitive
> dependency tree. It does NOT cover RustSec advisories
> (handled by `[advisories]` in `deny.toml` with
> `vulnerability = "deny"`) or license issues (handled by
> `[licenses]`).

## zerocopy build-script PATH dependency

### Affected version

`zerocopy = 0.8.x` (current : 0.8.42).

### Behaviour

`zerocopy`'s `build.rs` forks the host's `rustc` binary by
invoking `Command::new("rustc")` directly instead of using the
`RUSTC` environment variable that Cargo sets for build scripts
per the build-script protocol. The fork relies on `rustc` being
on the host's `PATH`.

On hosts where the toolchain bin directory is not on `PATH`
(common on Windows where rustup defaults to a launcher script
that sets `RUSTUP_TOOLCHAIN` without prepending the toolchain to
`PATH`), the build fails at exit code 101 with :

```
could not invoke rustc: program not found
```

The error message does not point at PATH as the remediation, so
a developer hitting it spends time tracing the failure before
finding the workaround.

### Workaround

The toolchain bin directory MUST be on `PATH` before running
`cargo build` against this workspace. The standard `rustup`
installation prepends it ; users who manage their toolchain
manually need to do so themselves.

The README and `docs/guides/GETTING_STARTED.md` Quick Start
sections document the standard `rustup` install path, which
satisfies this requirement.

### Why we accept the residual risk

1. **Patching upstream is not in scope** for the protocol team.
   The zerocopy maintainers' build-script choice is theirs ; an
   upstream PR that uses `env::var("RUSTC")` is the proper fix
   but timeline is uncertain.
2. **Pinning to a pre-0.8 version** would lose security fixes
   and feature work landed in 0.8.x.
3. **The workaround is universal in standard installs** —
   essentially every developer who installs Rust via the
   official `rustup` installer has the toolchain on `PATH`
   already. The failure mode hits a narrow set of custom-managed
   environments (corporate launcher scripts, CI minimal-image
   setups) which can be configured explicitly.

The combination of (a) low blast radius on standard installs,
(b) clear and simple workaround, and (c) absence of a security
impact (the failure is a build error, not a runtime
vulnerability) puts this in the accepted-residual-risk class.

### Mechanical anchor

`deny.toml` `[bans]` section pins us to the 0.8.x line :

```toml
[[bans.deny]]
name = "zerocopy"
version = "<0.8.0"      # forbid pre-0.8

[[bans.deny]]
name = "zerocopy"
version = ">=0.9.0"     # forbid 0.9+ until reviewed
```

A future 0.9 release of zerocopy will trip the upper bound, so
the version bump cannot land without a deliberate review of
this document and an update to the version pin.

### Regression detection (manual procedure)

To verify that no other workspace dependency adopts the same
PATH-forking pattern, run the following on a host with the
toolchain bin **not** on PATH :

```bash
# Save and restrict PATH so toolchain is not auto-resolved.
ORIGINAL_PATH="$PATH"
export PATH="/usr/bin:/bin"   # minimal PATH

# Pass the cargo binary by absolute path so cargo itself is found.
/path/to/rustup/toolchains/stable-*/bin/cargo build --workspace
```

If the build fails with `could not invoke rustc` or similar
PATH-dependent diagnostics in a dependency other than zerocopy,
that's a new accepted-risk candidate that needs documentation
here AND a version pin in `deny.toml`.

CI does not currently run this restricted-PATH probe — adding
it as a CI step is tracked as a follow-up scope.

## redb crash windows during file growth (4.1.0)

### Affected version

`redb = 4.1.0` (the version this workspace pins).

### Behaviour

The upstream changelog for the **unreleased** 4.2.0 documents two
crash-window fixes that therefore exist in 4.1.0 :

1. A crash during a transaction that grows the database file can
   leave the database permanently unopenable afterward.
2. A crash during a commit that resizes the database file can
   leave the database permanently unopenable, reporting
   corruption on subsequent opens, even though every committed
   transaction was intact and fully recoverable.

Both are crash-timing windows around file growth : a process
death at the wrong instant does not lose a committed batch (the
atomicity and recovery contract holds) but can lose the ability
to *open* the file at all, which for a node is loss of the local
ledger replica.

### Workaround

`arxia-storage-redb`'s kill-nine test pre-grows the database
file in committed transactions *before* its kill window opens,
so the growth path is mostly kept out of the crash-timing test
(hammering a known-unfixed upstream window would only produce
unactionable flakes). Nothing else avoids the window at runtime ;
a node that dies mid-growth is exposed to it.

### Why we accept

Every redb release line still receiving fixes requires Rust
1.89 ; the alternative within the old MSRV was the 2.6.x line,
end-of-life since August 2025, which receives no fixes at all
and whose exposure to these same windows is unknown. A
maintained engine with two documented, soon-fixed windows was
judged a smaller risk than an unmaintained one with an unknown
set. RustSec lists no advisory for redb (checked 2026-08-02).

### Mechanical anchor

Two anchors. `deny.toml` pins the accepted envelope to exactly
the audited 4.1.x line as the conventional record. The enforced
one is `crates/arxia-storage-redb/tests/version_pin.rs`, which
reads the resolved version out of `Cargo.lock` and fails the
suite if redb drifts off 4.1.x — nothing in CI runs cargo-deny
today, so the test is what actually stops a silent bump.

### Regression detection

When redb 4.2.0 ships, it is validated, not adopted : point the
kill-nine harness at the exact paths the release claims to fix
(remove the pre-growth mitigation, add an aggressive-growth
round with large values), and only on green update the
version-pin test, this entry, and deny.toml together. The
kill-nine test itself is the regression net for the recovery
contract on every future bump.

## sequential-storage unstable in-flash format

### Affected version

`sequential-storage = 8.0.1` (the version this workspace pins),
used by `arxia-storage-flash` as the on-flash key-value log.

### Behaviour

The upstream README states the in-flash representation is not
(yet ?) stable, and the crate has shipped eight major versions
since 2023. A major bump is allowed to change the format of data
already written to flash : a device upgraded across such a bump
can find its existing store unreadable — for a node, loss of the
local ledger replica without any crash having occurred.

### Workaround

None at runtime. The store format a device is flashed with is
the format it lives with until a deliberate migration exists.

### Why we accept

The crate is the only maintained no_std key-value store over raw
NOR flash with per-item power-fail safety in the ecosystem ;
building an equivalent in-house was judged a larger risk than
pinning one version of a maintained one. RustSec lists no
advisory for sequential-storage (checked at adoption).

### Mechanical anchor

`deny.toml` pins the envelope to `>=8.0.1, <8.1.0` as the
conventional record. The enforced anchor is
`crates/arxia-storage-flash/tests/version_pin.rs`, which reads
the resolved version out of `Cargo.lock` and fails the suite on
any drift off 8.0.x — nothing in CI runs cargo-deny today, so
the test is what actually stops a silent bump.

### Regression detection

Any bump is validated, not adopted : mount a store written by
the pinned version under the candidate version and read every
key back, before anything else. A format break at that step
means the bump needs a migration plan, not a lockfile change.

## sequential-storage "latest stable" MSRV policy

### Affected version

`sequential-storage = 8.0.1` ; the risk is any future release.

### Behaviour

Upstream's stated MSRV policy is "latest stable Rust" : a Rust
version bump is not considered breaking and can arrive in any
release, including a patch. This workspace pins MSRV 1.89.0 in
lock-step across the toolchain file, manifests and CI ; any
sequential-storage release may silently require a newer
compiler and fail the whole workspace build.

### Workaround

The version pin (below) prevents any release from arriving
unreviewed, which subsumes the MSRV exposure.

### Why we accept

The policy is upstream's to set ; within a pinned version the
MSRV cannot move, so the exposure exists only at bump time,
which the pin already forces through review.

### Mechanical anchor

Same two anchors as the format entry : the `deny.toml` envelope
and `crates/arxia-storage-flash/tests/version_pin.rs`. The
workspace MSRV itself is enforced by the LOW-014 pin test in
`arxia-core`.

### Regression detection

At every bump review, `cargo +1.89.0 build -p
arxia-storage-flash` (or the then-current pinned toolchain) is
part of the gate before the pin moves.

## sequential-storage single-poll completion is not a contract

### Affected version

`sequential-storage = 8.0.1`.

### Behaviour

The crate's API is async, but in 8.0.1 its futures never pend of
their own accord : no `Poll::Pending`, `Waker` or `poll_fn`
appears anywhere in its source, and its futures await only the
flash driver. Over a synchronous driver — which is what an ESP32
SPI flash is — every future completes on the first poll,
measured by probe at adoption. `arxia-storage-flash` bridges to
the synchronous `StorageBackend` trait on exactly this property :
it polls once and never loops. Nothing upstream promises any of
this ; it is an implementation detail of the pinned version, and
a future release may lawfully introduce a genuine await point.

### Workaround

The bridge treats `Poll::Pending` as a typed fault
(`StorageFault::WouldBlock`) rather than spinning : if the
assumption ever breaks, every affected operation fails loudly
and immediately instead of hanging a node in silence. The guard
lives in the crate driver (`poll_once`) and its test suite.

### Why we accept

The alternative is carrying an async executor on a 520 KB
device to wait for a flash that never actually suspends. The
guard converts the residual risk from "silent hang" to "typed
error at the first affected operation", which the node can
surface.

### Mechanical anchor

The version pin (`deny.toml` +
`crates/arxia-storage-flash/tests/version_pin.rs`), plus the
`poll_once` guard and its deliberately-pending-future test
(`a_pending_future_is_a_typed_fault_never_a_second_poll` in
`crates/arxia-storage-flash/tests/single_poll.rs`).

### Regression detection

At every bump review, the single-poll probe is re-run against
the candidate version : grep its source for `Poll::Pending`,
`Waker` and `poll_fn`, and run every operation of the probe
suite counting polls. One poll each, or the bump does not land.

## sequential-storage iteration order is not a contract

### Affected version

`sequential-storage = 8.0.1`.

### Behaviour

`fetch_all_items` yields items in write order, not key order,
and an overwritten key is yielded once per surviving version,
oldest first ; removed keys are not yielded at all. All three
behaviours were established by probe at adoption — none of them
is documented as a promise. The `StorageBackend` trait requires
ascending lexicographic key order with one entry per live key,
so `arxia-storage-flash` builds its ordered scan (the bounded
sorted window with last-occurrence-wins resolution) on top of
these measured semantics. A future release may lawfully change
any of them — start yielding tombstones, change duplicate
handling, or reorder iteration entirely.

### Workaround

The ordering layer assumes nothing about the input order (it
sorts), resolves duplicates by taking the last occurrence, and
the conformance suite pins the externally visible result :
ascending order, one entry per live key, deleted keys absent.
A semantics change upstream surfaces as failing conformance
tests, not as wrong scan results in production.

### Why we accept

Compensating in one place (the windowed scan) against measured
semantics, with the suite as a tripwire, was judged sounder
than depending on an ordering guarantee upstream never made.

### Mechanical anchor

The version pin (`deny.toml` +
`crates/arxia-storage-flash/tests/version_pin.rs`), plus the
shared conformance checks and the overwrite/deleted-key
fixtures in `arxia-storage-flash`.

### Regression detection

At every bump review, the iteration probe is re-run against the
candidate version (insertion order vs iteration order, overwrite
yielding, removed-key behaviour), and the full
`arxia-storage-flash` suite — conformance, window mechanics and
power-cut sweeps — must be green before the pin moves.

## Adding a new entry to this document

When a new dependency is identified as having a build-script,
runtime-initialisation, or transitive-tree quirk worth
documenting :

1. Add a `## <Crate name> <quirk title>` section to this
   document with the same six-subsection structure (Affected
   version / Behaviour / Workaround / Why we accept / Mechanical
   anchor / Regression detection).
2. Add the corresponding `[[bans.deny]]` entries to `deny.toml`
   with the version range that defines the accepted-risk
   envelope.
3. Reference this document from the `[bans]` section comment in
   `deny.toml`.

The cross-reference between `deny.toml` and this document is
the audit trail. Both files must be updated in the same commit
when an entry is added or modified.
