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
//! cargo-deny today, so this test is the enforcement.

#[test]
fn redb_stays_on_the_reviewed_4_1_line_until_4_2_is_validated() {
    let lock = include_str!("../../../Cargo.lock");

    let mut lines = lock.lines();
    let version = loop {
        match lines.next() {
            Some(line) if line.trim() == "name = \"redb\"" => {
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
            None => panic!("redb must be present in Cargo.lock"),
        }
    };

    assert!(
        version.starts_with("4.1."),
        "redb resolved to {version}, outside the reviewed 4.1.x line. \
         If this is the move to 4.2.0: run the kill-nine harness \
         against the growth paths 4.2.0 claims to fix (remove the \
         pre-growth mitigation, add the aggressive-growth round), \
         update docs/dependency-risks.md and deny.toml, and only then \
         update this pin. See dependency-risks.md, section \"redb crash \
         windows during file growth\"."
    );
}
