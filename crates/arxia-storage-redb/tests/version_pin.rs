//! Pin redb to the reviewed 4.1.x line.
//!
//! redb 4.1.0 carries two documented crash windows around file
//! growth/resize, accepted deliberately in `docs/dependency-risks.md`
//! with an exit plan. The exit plan is the point of this pin: when
//! 4.2.0 ships claiming to fix them, it must be *validated* — the
//! kill-nine harness pointed at the exact growth paths it says it
//! repaired, with the pre-growth mitigation removed — not adopted
//! because a changelog says so. This test makes a silent drift to
//! 4.2.0 (a lockfile bump, a Dependabot PR, a `cargo update`) fail
//! loudly until that review happens.
//!
//! Same mechanism as the LOW-014 pins in `arxia-core`: the lockfile is
//! the resolved truth, so the assertion reads it rather than the
//! manifest. `deny.toml` carries the matching envelope
//! (`>=4.1.0, <4.2.0`) as the conventional anchor; nothing in CI runs
//! cargo-deny today, so this test is the enforcement — which is why it
//! checks the exact envelope, not a prefix, and every resolved copy,
//! not the first: semver-incompatible duplicates resolve as separate
//! packages, and a second unvalidated copy in the tree would otherwise
//! pass unexamined. (The sequential-storage pin was hardened the same
//! way for the same reasons; the two anchors follow one pattern.)

#[test]
fn every_resolved_redb_lies_inside_the_reviewed_envelope() {
    let lock = include_str!("../../../Cargo.lock");

    let mut versions: Vec<String> = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"redb\"" {
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
    assert!(!versions.is_empty(), "redb must be present in Cargo.lock");

    for version in &versions {
        let mut parts = version.split('.').map(|p| {
            p.parse::<u64>()
                .expect("version components are numeric in a lockfile")
        });
        let (major, minor) = (parts.next().expect("major"), parts.next().expect("minor"));
        assert!(
            major == 4 && minor == 1,
            "redb resolved to {version}, outside the reviewed envelope \
             >=4.1.0 <4.2.0. If this is the move to 4.2.0: run the \
             kill-nine harness against the growth paths 4.2.0 claims to \
             fix (remove the pre-growth mitigation, add the \
             aggressive-growth round), update docs/dependency-risks.md \
             and deny.toml, and only then update this pin. See \
             dependency-risks.md, section \"redb crash windows during \
             file growth\"."
        );
    }
}
