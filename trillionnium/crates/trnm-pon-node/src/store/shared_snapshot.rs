//! Local physical layout for the held native-IO AuthenticatedV1 owner.
//!
//! Consensus, complete State validation and the original caller do not change.
//! Retained account bytes already live in the authenticated COW graph. A local
//! snapshot refers to that actual native record and stores the complete working
//! partition; reads materialize ALL accounts before the original State checks.
use super::{bytes32, canonical, native_authenticated, StateBackend};
use crate::account_archive_prototype::native_store;
use crate::{ensure, Error, Result, Settings};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use trnm_mvcc_fee::{continuity_v1, pon_executor::State};
use trnm_protocol::pon_wire::{hash, Hash};
use trnm_sqlite_io_boundary::{NativeIoLease, FILE_BYTES};

const DDL: &str =
    "CREATE TABLE native_io_shared_snapshots(block BLOB PRIMARY KEY,data BLOB NOT NULL);";
const SCHEMA: &str = "native-io-shared-authenticated-snapshot-v1";
const MAX_BYTES: usize = FILE_BYTES as usize;
const RETAINED: usize = 64;

#[path = "shared_snapshot_binding.rs"]
mod binding;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Layout {
    CanonicalJson,
    SharedAccountsV1,
}
impl Layout {
    pub(super) fn for_opening(backend: StateBackend, io: Option<&NativeIoLease>) -> Self {
        if backend == StateBackend::AuthenticatedV1 && io.is_some() {
            Self::SharedAccountsV1
        } else {
            Self::CanonicalJson
        }
    }
    pub(super) fn is_shared(self) -> bool {
        self == Self::SharedAccountsV1
    }
    pub(super) fn ddl(self, base: String) -> String {
        match self {
            Self::CanonicalJson => base,
            Self::SharedAccountsV1 => format!("{base}{DDL}"),
        }
    }
    pub(super) fn schema_id(self, base: Hash) -> Hash {
        match self {
            Self::CanonicalJson => base,
            Self::SharedAccountsV1 => hash(
                b"native-io-shared-authenticated-branch-schema-v1",
                &[&base, DDL.as_bytes(), SCHEMA.as_bytes()],
            ),
        }
    }
}

/// Only main is authoritative. Keep unrelated TEMP workspace/spill objects,
/// but never let an unqualified legacy verifier resolve a shadow of main.
pub(super) fn check_authoritative_namespace(db: &Connection) -> Result<()> {
    let mut databases = db.prepare("PRAGMA database_list")?;
    let mut rows = databases.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        ensure(
            name == "main" || name == "temp",
            "NATIVE_SHARED_ATTACHED_SCHEMA",
        )
        .map_err(Error::local_integrity)?;
    }
    let shadow: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_master t JOIN main.sqlite_master m ON t.name=m.name COLLATE NOCASE)",
        [],
        |row| row.get(0),
    )?;
    ensure(!shadow, "NATIVE_SHARED_AUTHORITY_SHADOW").map_err(Error::local_integrity)
}

/// Examine metadata, never copy arbitrary row payloads. A lookup by BLOB must
/// not mistake an existing same-byte TEXT key for a legally absent index.
/// Normal reads allow 64 rows plus one rejecting sentinel. Only save's same
/// transaction may validate its one pending row before the original64 prune.
fn check_typed_rows(db: &Connection, limit: usize) -> Result<()> {
    let mut statement = db.prepare("SELECT typeof(s.block),CASE WHEN typeof(s.block)='blob' THEN length(s.block) ELSE -1 END,typeof(s.data),CASE WHEN typeof(s.data)='blob' THEN length(s.data) ELSE -1 END,EXISTS(SELECT 1 FROM main.blocks b JOIN main.metadata m ON m.key='genesis' WHERE b.id=s.block AND b.id!=m.value AND typeof(b.height)='integer' AND b.height>0 AND b.parent IS NOT NULL) FROM main.native_io_shared_snapshots s LIMIT ?")?;
    let mut rows = statement.query([limit + 1])?;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        count += 1;
        ensure(count <= limit, "SNAPSHOT_LIMIT").map_err(Error::local_integrity)?;
        ensure(
            row.get::<_, String>(0)? == "blob"
                && row.get::<_, i64>(1)? == 32
                && row.get::<_, String>(2)? == "blob"
                && (1..=MAX_BYTES as i64).contains(&row.get::<_, i64>(3)?),
            "NATIVE_SHARED_TYPED_RECORD",
        )
        .map_err(Error::local_integrity)?;
        // Membership is not validation of the unselected payload: the actual
        // record/State/COW checks still apply whenever that record is used.
        ensure(row.get::<_, bool>(4)?, "NATIVE_SHARED_KEY_DOMAIN")
            .map_err(Error::local_integrity)?;
    }
    Ok(())
}

pub(super) fn check_layout(db: &Connection, settings: &Settings) -> Result<()> {
    binding::check(db, settings, RETAINED)?;
    let (all, genesis): (u64, u64) = db.query_row(
        "SELECT (SELECT COUNT(*) FROM main.snapshots),(SELECT COUNT(*) FROM main.snapshots WHERE block=?)",
        [settings.genesis().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure(all == 1 && genesis == 1, "NATIVE_SHARED_MIXED_LAYOUT").map_err(Error::local_integrity)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    id: Hash,
    block: Hash,
    native_commitment: Hash,
    working: State,
}
impl Snapshot {
    fn digest(&self, settings: &Settings) -> Result<Hash> {
        Ok(hash(
            b"native-io-shared-authenticated-snapshot-v1",
            &[
                &settings.network(),
                &settings.parameters(),
                &settings.genesis(),
                &self.block,
                &self.native_commitment,
                &canonical(&self.working)?,
            ],
        ))
    }
}

/// Borrow an existing writer transaction or own one complete read snapshot.
/// A failed rollback is owner-fatal and never authorizes a successful State.
pub(super) fn in_read_snapshot<T>(db: &Connection, run: impl FnOnce() -> Result<T>) -> Result<T> {
    if !db.is_autocommit() {
        let result = run();
        if db.is_autocommit() {
            return Err(match result {
                Err(first) => {
                    Error::local_replay_source("NATIVE_SHARED_READ_TRANSACTION_LOST", first)
                }
                Ok(_) => Error::from("NATIVE_SHARED_READ_TRANSACTION_LOST").local_integrity(),
            });
        }
        return result;
    }
    let read = db.unchecked_transaction()?;
    let result = run();
    match (result, read.rollback()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(first), Ok(())) => Err(first),
        (Ok(_), Err(cleanup)) => Err(Error::local_replay_source(
            "NATIVE_SHARED_READ_ROLLBACK",
            cleanup,
        )),
        (Err(first), Err(cleanup)) => Err(Error::local_replay_source(
            "NATIVE_SHARED_READ_ROLLBACK",
            ReadCleanupFailure { first, cleanup },
        )),
    }
}
/// These observations cover same-connection side effects only, never foreign
/// data_version or a storage-health verdict. Actual full graph/State checks
/// still run. Take this fence AFTER the final caller callback so legitimate
/// earlier accounting is not mistaken for a write by this final read phase.
pub(super) fn final_read<T>(db: &Connection, run: impl FnOnce() -> Result<T>) -> Result<T> {
    check_authoritative_namespace(db)?;
    let before = (db.total_changes(), db.is_autocommit());
    let result = run()?;
    check_authoritative_namespace(db)?;
    ensure(
        (db.total_changes(), db.is_autocommit()) == before,
        "NATIVE_SHARED_FINAL_READ_MUTATION",
    )
    .map_err(Error::local_integrity)?;
    Ok(result)
}

#[derive(Debug)]
struct ReadCleanupFailure {
    first: Error,
    cleanup: rusqlite::Error,
}
impl std::fmt::Display for ReadCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "first error: {}; rollback: {}", self.first, self.cleanup)
    }
}
impl std::error::Error for ReadCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.first)
    }
}

pub(super) fn save(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: &native_authenticated::ArithmeticCache,
) -> Result<()> {
    binding::check(db, settings, RETAINED)?;
    ensure(block != settings.genesis(), "NATIVE_SHARED_GENESIS").map_err(Error::local_integrity)?;
    let native = native_authenticated::load(db, block)?;
    let mut snapshot = Snapshot {
        schema: SCHEMA.into(),
        id: [0; 32],
        block,
        native_commitment: native.id,
        working: state
            .iter()
            .filter(|(key, _)| !key.starts_with("account:"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    };
    snapshot.id = snapshot.digest(settings)?;
    let bytes = canonical(&snapshot)?;
    ensure(bytes.len() <= MAX_BYTES, "NATIVE_SHARED_SNAPSHOT_LIMIT")
        .map_err(Error::local_integrity)?;
    ensure(
        db.execute(
            "INSERT INTO native_io_shared_snapshots VALUES(?,?)",
            params![block.as_slice(), bytes],
        )? == 1,
        "NATIVE_SHARED_SNAPSHOT_WRITE",
    )
    .map_err(Error::local_integrity)?;
    // Verify the just-inserted row before pruning: a valid low-height fork
    // snapshot may itself fall outside the retained64 optional index window.
    ensure(
        load_with_limit(db, settings, block, progress, cache, RETAINED + 1)?.as_ref()
            == Some(state),
        "NATIVE_SHARED_SNAPSHOT_WRITE",
    )
    .map_err(Error::local_integrity)?;
    db.execute("DELETE FROM native_io_shared_snapshots WHERE block NOT IN (SELECT s.block FROM native_io_shared_snapshots s JOIN blocks b ON b.id=s.block ORDER BY b.height DESC,b.id LIMIT 64)", [])?;
    let count: u64 = db.query_row(
        "SELECT COUNT(*) FROM native_io_shared_snapshots",
        [],
        |row| row.get(0),
    )?;
    ensure(count <= RETAINED as u64, "SNAPSHOT_LIMIT").map_err(Error::local_integrity)?;
    binding::check(db, settings, RETAINED)
}

pub(super) fn load(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: &native_authenticated::ArithmeticCache,
) -> Result<Option<State>> {
    load_with_limit(db, settings, block, progress, cache, RETAINED)
}
fn load_with_limit(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: &native_authenticated::ArithmeticCache,
    limit: usize,
) -> Result<Option<State>> {
    let schema_version: u64 = db.query_row("PRAGMA main.schema_version", [], |row| row.get(0))?;
    let autocommit = db.is_autocommit();
    progress()?;
    binding::check(db, settings, limit)?;
    let bytes = encoded_with_limit(db, block, limit)?;
    let Some(bytes) = bytes else {
        // Absence is optional, but every PRESENT row must still be bound. In
        // particular, moving this row to a known pruned key is not absence.
        // No caller callback crosses this last check before returning None.
        binding::check(db, settings, limit)?;
        return Ok(None);
    };
    let (snapshot, native) = binding::decode(db, settings, block, &bytes)?;
    let accounts =
        native_store::materialize_accounts(db, &native.accounts, progress, Some(&cache.lifts))?;
    let mut state = snapshot.working;
    for (owner, account) in accounts {
        progress()?;
        ensure(
            state
                .insert(
                    format!("account:{}", hex::encode(owner)),
                    serde_json::to_value(account)?,
                )
                .is_none(),
            "NATIVE_SHARED_SNAPSHOT_PARTITION",
        )
        .map_err(Error::local_integrity)?;
    }
    continuity_v1::check_state(&state, native.height, &settings.app)
        .map_err(|error| Error::from(error).local_integrity())?;
    native_authenticated::verify_state_with_cache(
        db,
        settings,
        block,
        &state,
        progress,
        Some(cache),
    )?;
    native_authenticated::verify_history_with_cache(db, settings, block, progress, Some(cache))?;
    progress()?;
    final_read(db, || {
        // A caller callback can mutate this SAME SQLite connection even inside a
        // pinned read snapshot. Re-read the actual complete graph/State/history
        // after its last invocation; no caller callback crosses this final fence.
        native_authenticated::verify_state_with_cache(
            db,
            settings,
            block,
            &state,
            &mut || Ok(()),
            Some(cache),
        )?;
        native_authenticated::verify_history_with_cache(
            db,
            settings,
            block,
            &mut || Ok(()),
            Some(cache),
        )?;
        // Preserve current raw row identity after the last caller callback. A
        // malformed or replaced present record is never a pruned-index fallback.
        ensure(
            encoded_with_limit(db, block, limit)?.as_ref() == Some(&bytes)
                && native_authenticated::load(db, block)? == native
                && db.query_row::<u64, _, _>("PRAGMA main.schema_version", [], |row| row.get(0))?
                    == schema_version
                && db.is_autocommit() == autocommit,
            "NATIVE_SHARED_SNAPSHOT_CHANGED",
        )
        .map_err(Error::local_integrity)?;
        binding::check(db, settings, limit)?;
        Ok(Some(state))
    })
}

fn encoded(db: &Connection, block: Hash) -> Result<Option<Vec<u8>>> {
    encoded_with_limit(db, block, RETAINED)
}
fn encoded_with_limit(db: &Connection, block: Hash, limit: usize) -> Result<Option<Vec<u8>>> {
    check_authoritative_namespace(db)?;
    check_typed_rows(db, limit)?;
    Ok(db
        .prepare_cached("SELECT CASE WHEN typeof(data)='blob' AND length(data)>?1 THEN substr(data,1,?2) ELSE data END FROM main.native_io_shared_snapshots WHERE block=?3")?
        .query_row(params![MAX_BYTES, MAX_BYTES + 1, block.as_slice()], |row| row.get(0))
        .optional()?)
}

/// Only the one actual shared anchor used by this state_at operation is held.
/// Raw row identity is additional provenance, never a graph-verification result.
#[derive(Default)]
pub(super) struct ReadSet(Vec<(Hash, Vec<u8>)>);
impl ReadSet {
    pub(super) fn record(&mut self, db: &Connection, block: Hash) -> Result<()> {
        ensure(self.0.is_empty(), "NATIVE_SHARED_READ_SET_LIMIT")
            .map_err(Error::local_integrity)?;
        let bytes = encoded(db, block)?
            .ok_or_else(|| Error::from("NATIVE_SHARED_SNAPSHOT_CHANGED").local_integrity())?;
        ensure(bytes.len() <= MAX_BYTES, "NATIVE_SHARED_SNAPSHOT_LIMIT")
            .map_err(Error::local_integrity)?;
        self.0.push((block, bytes));
        Ok(())
    }
    pub(super) fn verify(
        &self,
        db: &Connection,
        settings: &Settings,
        cache: &native_authenticated::ArithmeticCache,
    ) -> Result<()> {
        for (block, bytes) in &self.0 {
            ensure(
                encoded(db, *block)?.as_ref() == Some(bytes),
                "NATIVE_SHARED_SNAPSHOT_CHANGED",
            )
            .map_err(Error::local_integrity)?;
            ensure(
                load(db, settings, *block, &mut || Ok(()), cache)?.is_some(),
                "NATIVE_SHARED_SNAPSHOT_CHANGED",
            )
            .map_err(Error::local_integrity)?;
            ensure(
                encoded(db, *block)?.as_ref() == Some(bytes),
                "NATIVE_SHARED_SNAPSHOT_CHANGED",
            )
            .map_err(Error::local_integrity)?;
        }
        Ok(())
    }
}

/// Last complete read fence for a returned State, including the ACTIVE fast path.
/// A missing optional index is permitted; a malformed present row is an error.
/// Every call hereafter is internal: no caller callback can alter the graph
/// between its final actual revalidation and returning this State.
pub(super) fn verify_returned_state(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    state: &State,
    cache: &native_authenticated::ArithmeticCache,
) -> Result<()> {
    if let Some(retained) = load(db, settings, block, &mut || Ok(()), cache)? {
        ensure(retained == *state, "NATIVE_SHARED_SNAPSHOT_STATE")
            .map_err(Error::local_integrity)?;
    }
    native_authenticated::verify_state_with_cache(
        db,
        settings,
        block,
        state,
        &mut || Ok(()),
        Some(cache),
    )?;
    native_authenticated::verify_history_with_cache(
        db,
        settings,
        block,
        &mut || Ok(()),
        Some(cache),
    )
}

pub(super) fn audit(
    db: &Connection,
    settings: &Settings,
    cache: &native_authenticated::ArithmeticCache,
) -> Result<()> {
    in_read_snapshot(db, || {
        check_layout(db, settings)?;
        let rows: Vec<Vec<u8>> = db
            .prepare("SELECT block FROM native_io_shared_snapshots ORDER BY block LIMIT 65")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        ensure(rows.len() <= RETAINED, "SNAPSHOT_LIMIT").map_err(Error::local_integrity)?;
        for raw in rows {
            let block = bytes32(raw).map_err(Error::local_integrity)?;
            ensure(
                load(db, settings, block, &mut || Ok(()), cache)?.is_some(),
                "NATIVE_SHARED_SNAPSHOT_MISSING",
            )
            .map_err(Error::local_integrity)?;
        }
        Ok(())
    })
}

#[cfg(test)]
#[path = "shared_snapshot_tests.rs"]
mod tests;
