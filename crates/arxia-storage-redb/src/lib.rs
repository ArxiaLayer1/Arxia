//! redb-backed persistent [`StorageBackend`] for Arxia nodes.
//!
//! This is the first backend written against the storage contract
//! rather than alongside it: the trait, its documentation and its
//! conformance suite predate this crate, and this crate's tests are
//! wrappers over that suite (see `tests/conformance.rs`). Nothing in
//! the node is wired to it yet — the ledger is still in-memory — so
//! this crate is the persistence layer arriving ahead of its caller,
//! the same order the trait itself arrived in.
//!
//! # How the contract is met
//!
//! **Ordering.** redb's B-tree stores `&[u8]` keys in lexicographic
//! byte order natively; [`StorageBackend::scan_prefix`] is a range walk
//! from the prefix, cut at the first key that no longer starts with it.
//!
//! **Atomicity.** [`StorageBackend::apply_batch`] is one redb
//! [`WriteTransaction`]: every operation lands inside it, in slice
//! order, and the transaction commits once. redb commits are
//! all-or-nothing — an error or a crash before the commit record is
//! durable leaves the previous root intact, so a torn batch is
//! unobservable on reopen. Readers run on MVCC snapshots and never see
//! a half-applied batch. This is exercised for real in
//! `tests/kill_nine.rs`, which kills a writer process mid-stream and
//! checks every batch is entirely present or entirely absent.
//!
//! **Durability.** Every write transaction explicitly sets
//! [`Durability::Immediate`], which redb documents as "guaranteed to be
//! persistent as soon as `commit` returns". It is set explicitly, not
//! inherited, so the guarantee does not silently follow an upstream
//! default change.
//!
//! # Known limits
//!
//! - A killed process proves crash-atomicity and process-death
//!   durability (a `Durability::None` mutant fails the kill-nine
//!   test — redb keeps non-durable commits process-local, so the kill
//!   takes them with it), but not power-loss durability:
//!   `TerminateProcess` drops neither the OS page cache nor the
//!   drive's write cache, so whether the fsync reached stable media is
//!   invisible to it. Power-loss behaviour is a hardware test (planned
//!   for the T-Beam bench, where the plug can actually be pulled).
//! - redb 4.1.0 has two upstream crash bugs fixed only in the
//!   unreleased 4.2.0, both able to leave a database unopenable after
//!   a file-growth or resize during commit. See
//!   `docs/dependency-risks.md`; the pin moves to 4.2.0 when it ships.
//! - `put` and `delete` each commit (and therefore fsync) their own
//!   transaction. Correct first; batching is what `apply_batch` is
//!   for.

use arxia_core::{ArxiaError, StorageFault};
use arxia_storage::{BatchOp, StorageBackend};
use redb::{Database, Durability, ReadableDatabase, TableDefinition, WriteTransaction};
use std::fmt::Display;
use std::path::Path;

/// The single key-value table backing the store.
///
/// One table, not one per keyspace: the `StorageBackend` contract is a
/// flat byte-keyed map, and keyspace separation is done by key prefix
/// (`c:acct:...`, `s:...`) exactly as the conformance suite exercises it.
const TABLE: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("arxia_kv");

/// Map any redb error into the storage fault variant, preserving its
/// message.
fn storage_err(e: impl Display) -> ArxiaError {
    ArxiaError::Storage {
        fault: StorageFault::Backend {
            detail: e.to_string(),
        },
    }
}

/// Persistent key-value store over a single redb database file.
pub struct RedbStorage {
    db: Database,
}

impl RedbStorage {
    /// Open the database at `path`, creating file and table if absent.
    ///
    /// The table is created eagerly so a read on a fresh database sees
    /// an empty table rather than `TableDoesNotExist`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArxiaError> {
        let db = Database::create(path).map_err(storage_err)?;
        // Table creation goes through the same explicit-durability
        // path as every other write: the crate's stance is that the
        // guarantee never rides on an upstream default, and the
        // table this transaction creates is state every reopen
        // depends on.
        let mut txn = db.begin_write().map_err(storage_err)?;
        txn.set_durability(Durability::Immediate)
            .map_err(storage_err)?;
        // Opening the table inside a committed write transaction is
        // what creates it.
        txn.open_table(TABLE).map_err(storage_err)?;
        txn.commit().map_err(storage_err)?;
        Ok(Self { db })
    }

    /// Begin a write transaction with the durability the contract
    /// requires, stated explicitly rather than inherited from redb's
    /// default.
    fn begin_durable_write(&self) -> Result<WriteTransaction, ArxiaError> {
        let mut txn = self.db.begin_write().map_err(storage_err)?;
        txn.set_durability(Durability::Immediate)
            .map_err(storage_err)?;
        Ok(txn)
    }
}

impl StorageBackend for RedbStorage {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        let txn = self.begin_durable_write()?;
        {
            let mut table = txn.open_table(TABLE).map_err(storage_err)?;
            table.insert(key, value).map_err(storage_err)?;
        }
        txn.commit().map_err(storage_err)
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        let txn = self.db.begin_read().map_err(storage_err)?;
        let table = txn.open_table(TABLE).map_err(storage_err)?;
        let guard = table.get(key).map_err(storage_err)?;
        Ok(guard.map(|g| g.value().to_vec()))
    }

    fn delete(&mut self, key: &[u8]) -> Result<bool, ArxiaError> {
        let txn = self.begin_durable_write()?;
        let existed = {
            let mut table = txn.open_table(TABLE).map_err(storage_err)?;
            // `remove` returns the previous value iff the key was
            // present — the existence signal HIGH-021 requires. Bound
            // to a local so the guard drops before the table does.
            let prev = table.remove(key).map_err(storage_err)?;
            prev.is_some()
        };
        txn.commit().map_err(storage_err)?;
        Ok(existed)
    }

    fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        let txn = self.db.begin_read().map_err(storage_err)?;
        let table = txn.open_table(TABLE).map_err(storage_err)?;
        Ok(table.get(key).map_err(storage_err)?.is_some())
    }

    fn scan_prefix(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<(), ArxiaError> {
        let txn = self.db.begin_read().map_err(storage_err)?;
        let table = txn.open_table(TABLE).map_err(storage_err)?;
        // redb iterates the B-tree in ascending byte order; starting at
        // the first key >= prefix and cutting at the first key that no
        // longer starts with it visits exactly the range, in order —
        // the same idiom the in-memory reference uses over BTreeMap.
        for entry in table.range(prefix..).map_err(storage_err)? {
            let (k, v) = entry.map_err(storage_err)?;
            if !k.value().starts_with(prefix) {
                break;
            }
            if !visit(k.value(), v.value()) {
                break;
            }
        }
        Ok(())
    }

    fn apply_batch(&mut self, ops: &[BatchOp<'_>]) -> Result<(), ArxiaError> {
        // One transaction for the whole batch is the entire atomicity
        // story: every operation lands inside it in slice order, and
        // either the commit record becomes durable — all of them
        // visible — or the transaction is dropped on the error path
        // and redb rolls back to the previous root, none of them
        // visible. There is no code path that commits a proper subset.
        let txn = self.begin_durable_write()?;
        {
            let mut table = txn.open_table(TABLE).map_err(storage_err)?;
            for op in ops {
                match op {
                    BatchOp::Put { key, value } => {
                        table.insert(*key, *value).map_err(storage_err)?;
                    }
                    BatchOp::Delete { key } => {
                        table.remove(*key).map_err(storage_err)?;
                    }
                }
            }
        }
        txn.commit().map_err(storage_err)
    }
}
