//! Pin sequential-storage to the probed 8.0.x line.
//!
//! Three properties this backend is built on are implementation
//! details of 8.0.1, established by probe and none of them promised
//! upstream: the in-flash format ("not (yet?) stable" in their own
//! README, eight major versions since 2023), the single-poll behaviour
//! (its futures never pend over a synchronous driver — the crate's
//! whole synchronous bridge stands on that), and the write-order
//! iteration semantics the windowed scan compensates for. A version
//! bump can silently change any of the three: a format change bricks
//! an existing store, a pend turns into `WouldBlock` faults at
//! runtime, an iteration change invalidates the ordering layer.
//!
//! So any bump must be *validated* — the pre-flight probes re-run
//! against the new version, the power-cut sweeps green, the endurance
//! numbers re-measured — not adopted because a changelog says so. This
//! test makes a silent drift (a lockfile bump, a Dependabot PR, a
//! `cargo update`) fail loudly until that review happens.
//!
//! Same mechanism as the redb and LOW-014 pins: the lockfile is the
//! resolved truth, so the assertion reads it rather than the manifest.
//! `deny.toml` carries the matching envelope (`>=8.0.1, <8.1.0`) as
//! the conventional anchor; nothing in CI runs cargo-deny today, so
//! this test is the enforcement — which is why it checks the exact
//! envelope, not a prefix (a prefix accepts 8.0.0, which deny.toml
//! bans), and every resolved copy, not the first (semver-incompatible
//! duplicates resolve as separate packages, and a second unvalidated
//! copy in the tree would otherwise pass unexamined).

#[test]
fn every_resolved_sequential_storage_lies_inside_the_probed_envelope() {
    let lock = include_str!("../../../Cargo.lock");

    let mut versions: Vec<String> = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"sequential-storage\"" {
            let v = lines
                .next()
                .expect("a [[package]] block has a version line after its name");
            versions.push(
                v.trim()
                    .strip_prefix("version = \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .expect("version line is well-formed")
                    .to_string(),
            );
        }
    }
    assert!(
        !versions.is_empty(),
        "sequential-storage must be present in Cargo.lock"
    );

    for version in &versions {
        let mut parts = version.split('.').map(|p| {
            p.parse::<u64>()
                .expect("version components are numeric in a lockfile")
        });
        let (major, minor, patch) = (
            parts.next().expect("major"),
            parts.next().expect("minor"),
            parts.next().expect("patch"),
        );
        assert!(
            major == 8 && minor == 0 && patch >= 1,
            "sequential-storage resolved to {version}, outside the probed \
             envelope >=8.0.1 <8.1.0. Before accepting any bump: re-run \
             the pre-flight probes (single-poll, iteration order, \
             overwrite and delete semantics), re-run the power-cut and \
             fault sweeps, check the in-flash format compatibility \
             against a store written by 8.0.x, update \
             docs/dependency-risks.md and deny.toml, and only then \
             update this pin. See dependency-risks.md, the four \
             sequential-storage entries."
        );
    }
}
