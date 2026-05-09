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
