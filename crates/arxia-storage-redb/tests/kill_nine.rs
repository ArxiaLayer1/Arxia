//! Crash-atomicity under a real process kill.
//!
//! A child process (this same test binary, re-invoked with
//! `ARXIA_KILL9_CHILD_DB` set) writes sealed batches in a tight loop:
//! eight payload keys plus a `last_seq` marker, all in one
//! `apply_batch`, so "the marker reads S" and "batch S committed in
//! full" are the same statement. The parent kills it mid-stream with
//! `TerminateProcess` — no signal handler, no destructor, no flush —
//! reopens the database, and checks the only acceptable outcome:
//!
//! - the database opens (a crashed writer must not brick the store),
//! - every batch `1..=last_seq` is present in full, bytes verified,
//! - nothing beyond `last_seq` exists, not one key.
//!
//! Three rounds run against the same file, so the sequence is
//! crash -> repair/reopen -> keep writing -> crash again, which is a
//! node's actual life on flaky power.
//!
//! # What this does and does not prove
//!
//! Proven here: crash-atomicity (no torn batch is ever visible), and
//! that commits survive the death of the process that made them — a
//! backend switched to `Durability::None` fails this test, verified
//! by mutation, because redb keeps non-durable commits process-local
//! and the kill takes them with it.
//!
//! Not proven: power-loss durability. `TerminateProcess` does not
//! drop the OS page cache or the drive's write cache, so this test
//! cannot see whether `Durability::Immediate`'s fsync truly reached
//! stable media. That needs hardware whose plug can be pulled; it is
//! planned for the T-Beam bench.
//!
//! The batch payload is kept modest and the file is pre-grown before
//! the first kill window: redb 4.1.0 has two upstream crash windows
//! during file growth/resize (fixed in the unreleased 4.2.0, see
//! docs/dependency-risks.md) that can leave a database unopenable.
//! Hammering growth during the kill window would make this test flake
//! on an upstream bug we cannot fix; once the pin moves to 4.2.0 an
//! aggressive-growth round should be added here.

use arxia_storage::{BatchOp, StorageBackend};
use arxia_storage_redb::RedbStorage;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

const CHILD_ENV: &str = "ARXIA_KILL9_CHILD_DB";
const PAYLOAD_KEYS_PER_BATCH: usize = 8;
const PAYLOAD_LEN: usize = 256;

fn payload_key(seq: u64, i: usize) -> Vec<u8> {
    format!("b:{seq:010}:{i}").into_bytes()
}

/// Deterministic per-(seq, i) payload so the verifier checks bytes,
/// not mere existence.
fn payload_value(seq: u64, i: usize) -> Vec<u8> {
    format!("payload-{seq}-{i}-")
        .into_bytes()
        .into_iter()
        .cycle()
        .take(PAYLOAD_LEN)
        .collect()
}

fn read_last_seq(store: &RedbStorage) -> u64 {
    match store.get(b"last_seq").expect("read last_seq") {
        Some(bytes) => String::from_utf8(bytes)
            .expect("last_seq utf8")
            .parse()
            .expect("last_seq number"),
        None => 0,
    }
}

/// The writer the parent kills. Never returns.
fn writer_child(db_path: &str) -> ! {
    let mut store = RedbStorage::open(db_path).expect("child: open db");
    let mut seq = read_last_seq(&store);

    // Pre-grow the file once, before the parent's kill window opens
    // (the parent only starts counting at the first COMMITTED line):
    // a few hundred KiB written and deleted in committed transactions,
    // so later batches mostly reuse pages instead of growing the file
    // inside the kill window. See the module docs for why.
    if seq == 0 {
        let big = vec![0xA5u8; 64 * 1024];
        for i in 0..8u8 {
            let key = format!("pregrow:{i}").into_bytes();
            store.put(&key, &big).expect("child: pregrow put");
            store.delete(&key).expect("child: pregrow delete");
        }
    }

    loop {
        seq += 1;
        let keys: Vec<Vec<u8>> = (0..PAYLOAD_KEYS_PER_BATCH)
            .map(|i| payload_key(seq, i))
            .collect();
        let values: Vec<Vec<u8>> = (0..PAYLOAD_KEYS_PER_BATCH)
            .map(|i| payload_value(seq, i))
            .collect();
        let marker = seq.to_string().into_bytes();

        let mut ops: Vec<BatchOp<'_>> = keys
            .iter()
            .zip(&values)
            .map(|(k, v)| BatchOp::Put { key: k, value: v })
            .collect();
        // The seal: committed in the same transaction as the payload,
        // so the marker cannot run ahead of or behind the data.
        ops.push(BatchOp::Put {
            key: b"last_seq",
            value: &marker,
        });

        store.apply_batch(&ops).expect("child: apply_batch");
        // Parent reads this to know a batch landed; flush is what
        // makes the line observable before a kill.
        println!("COMMITTED {seq}");
        use std::io::Write;
        std::io::stdout().flush().expect("child: flush");
    }
}

fn spawn_writer(db_path: &std::path::Path) -> Child {
    Command::new(std::env::current_exe().expect("current exe"))
        .args(["batches_survive_a_process_kill", "--exact", "--nocapture"])
        .env(CHILD_ENV, db_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn writer child")
}

/// Wait for `min_batches` commits, then kill without warning.
/// Returns the highest sequence the parent saw committed.
///
/// The pipe is drained by a dedicated thread for the whole lifetime of
/// the child. That detail is what gives the kill teeth: if the parent
/// simply stopped reading once its threshold was reached, the pipe
/// buffer would fill and the child would block on its stdout flush —
/// which sits *between* batches — so every kill would land at a batch
/// boundary and mid-commit kills would never be exercised. (The first
/// version of this harness had exactly that flaw, found because a
/// deliberately non-atomic backend survived it.) With the drain thread
/// running, the child spends its time inside `apply_batch`, and that
/// is where the kill lands.
fn kill_after(child: &mut Child, min_batches: u64, kill_fraction: f64) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let stdout = child.stdout.take().expect("child stdout");
    let highest = Arc::new(AtomicU64::new(0));
    let highest_for_reader = Arc::clone(&highest);

    let started = Instant::now();
    // Nanoseconds since `started` at which the latest line arrived —
    // one atomic, written only by the drain thread.
    let last_line_nanos = Arc::new(AtomicU64::new(0));
    let last_line_nanos_for_reader = Arc::clone(&last_line_nanos);

    let drain = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Some(rest) = line.strip_prefix("COMMITTED ") {
                if let Ok(seq) = rest.trim().parse::<u64>() {
                    let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                    last_line_nanos_for_reader.store(nanos, Ordering::Release);
                    highest_for_reader.store(seq, Ordering::Release);
                }
            }
        }
    });

    // Busy-wait on the child's progress; the child is doing fsyncs, so
    // yielding is plenty. Record when the first line arrives so batch
    // cadence can be measured over the observation window.
    let mut first_seen: Option<(u64, u64)> = None; // (seq, nanos)
    loop {
        let seq = highest.load(Ordering::Acquire);
        if seq > 0 && first_seen.is_none() {
            first_seen = Some((seq, last_line_nanos.load(Ordering::Acquire)));
        }
        if seq >= min_batches {
            break;
        }
        if child.try_wait().expect("try_wait").is_some() {
            panic!(
                "child exited on its own after {seq} batches — its \
                 writes failed before the kill; nothing was tested"
            );
        }
        std::thread::yield_now();
    }

    // The COMMITTED line that tripped the threshold was printed at a
    // batch boundary, and a kill issued immediately would land a few
    // microseconds later — right at the start of the next batch, before
    // any of its writes are durable. Killing there looks atomic even
    // for a backend that is not: the kill point must be decorrelated
    // from the boundary that triggered it. (Found because a
    // deliberately per-op-committing backend survived the naive
    // version of this harness three runs out of three.) So: measure
    // the child's real batch cadence over the observation window and
    // sleep a per-round fraction of one batch duration before killing,
    // placing the kill inside the write stream regardless of how fast
    // this machine commits.
    let (first_seq, first_nanos) = first_seen.expect("saw at least one line");
    let last_seq = highest.load(Ordering::Acquire);
    let last_nanos = last_line_nanos.load(Ordering::Acquire);
    if last_seq > first_seq && last_nanos > first_nanos {
        let per_batch = (last_nanos - first_nanos) / (last_seq - first_seq);
        let delay = (per_batch as f64 * kill_fraction) as u64;
        std::thread::sleep(Duration::from_nanos(delay));
    }

    child.kill().expect("kill child");
    child.wait().expect("reap child");
    drain.join().expect("join drain thread");
    highest.load(Ordering::Acquire)
}

/// Every batch `1..=last_seq` complete and byte-correct; nothing at
/// all beyond. `seen_by_parent` bounds where `last_seq` may legally
/// fall: no lower than the last line the parent read, no higher than
/// that plus the pipe's worth of in-flight batches.
fn verify_all_or_nothing(store: &RedbStorage, seen_by_parent: u64, probe_beyond: u64) {
    let last_seq = read_last_seq(store);
    assert!(
        last_seq >= seen_by_parent,
        "last_seq {last_seq} lost batches the parent saw committed ({seen_by_parent})"
    );

    for seq in 1..=last_seq {
        for i in 0..PAYLOAD_KEYS_PER_BATCH {
            let key = payload_key(seq, i);
            let got = store
                .get(&key)
                .expect("get")
                .unwrap_or_else(|| panic!("batch {seq} incomplete: key {i} missing"));
            assert_eq!(
                got,
                payload_value(seq, i),
                "batch {seq} key {i}: payload bytes corrupted"
            );
        }
    }

    for seq in (last_seq + 1)..=(last_seq + probe_beyond) {
        for i in 0..PAYLOAD_KEYS_PER_BATCH {
            assert!(
                store.get(&payload_key(seq, i)).expect("get").is_none(),
                "torn batch visible: key {i} of uncommitted batch {seq} exists"
            );
        }
    }
}

#[test]
fn batches_survive_a_process_kill() {
    // Child mode: this same test, re-invoked by `spawn_writer` with
    // the env var set, becomes the writer and never returns.
    if let Ok(db_path) = std::env::var(CHILD_ENV) {
        writer_child(&db_path);
    }

    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join("kill9.redb");

    // Rounds on one file: crash, reopen, keep writing, crash again.
    // The fractions sweep the kill point across the interior of a
    // batch — early, middle, late — so it cannot be systematically
    // synchronised with any phase of the commit.
    let mut cumulative = 0u64;
    for (min_batches, kill_fraction) in [
        (25u64, 0.15),
        (30, 0.35),
        (30, 0.55),
        (30, 0.75),
        (30, 0.95),
    ] {
        let mut child = spawn_writer(&db_path);
        let seen = kill_after(&mut child, cumulative + min_batches, kill_fraction);

        let store = RedbStorage::open(&db_path)
            .expect("a crashed writer must not leave the database unopenable");
        verify_all_or_nothing(&store, seen, 50);
        cumulative = read_last_seq(&store);
        // Drop the parent's handle before the next child opens the
        // file — only one process may hold the database at a time.
        drop(store);
    }

    assert!(
        cumulative >= 145,
        "five rounds should have accumulated at least the sum of the \
         thresholds, got {cumulative}"
    );
}
