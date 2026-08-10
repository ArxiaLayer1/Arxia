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
//! this test is the enforcement.

#[test]
fn sequential_storage_stays_on_the_probed_8_0_line_until_a_bump_is_validated() {
    let lock = include_str!("../../../Cargo.lock");

    let mut lines = lock.lines();
    let version = loop {
        match lines.next() {
            Some(line) if line.trim() == "name = \"sequential-storage\"" => {
                let v = lines
                    .next()
                    .expect("a [[package]] block has a version line after its name");
                break v
                    .trim()
                    .strip_prefix("version = \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .expect("version line is well-formed")
                    .to_string();
            }
            Some(_) => continue,
            None => panic!("sequential-storage must be present in Cargo.lock"),
        }
    };

    assert!(
        version.starts_with("8.0."),
        "sequential-storage resolved to {version}, outside the probed \
         8.0.x line. Before accepting any bump: re-run the pre-flight \
         probes (single-poll, iteration order, overwrite and delete \
         semantics), re-run the power-cut sweeps, check the in-flash \
         format compatibility against a store written by 8.0.x, update \
         docs/dependency-risks.md and deny.toml, and only then update \
         this pin. See dependency-risks.md, the four sequential-storage \
         entries."
    );
}
