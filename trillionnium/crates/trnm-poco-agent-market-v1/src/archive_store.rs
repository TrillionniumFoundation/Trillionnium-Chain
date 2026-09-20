//! Durable, proof-preserving TaskV1 archive ownership.
//!
//! The planner in [`crate::archive`] produces an authenticated batch, but a
//! planner alone must never be allowed to delete live state.  This adapter is
//! the local storage boundary: one immediate SQLite transaction verifies the
//! complete batch against the live inventory and the durable legal-hold set,
//! copies the records into an append-only archive, and only then removes the
//! live rows.  The seal and archive rows survive a restart, so a successful
//! deletion remains independently provable.
//!
//! This is a candidate storage owner.  It is not a consensus finality or
//! production activation authority; callers must bind it to the authenticated
//! terminal-task and legal-hold source before invoking the replacement APIs.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{
    archive::{TaskArchiveBatchV1, TaskArchivePolicyV1, TerminalTaskArchiveRecordV1},
    codec::{canonical_bytes, digest_value, strict_decode},
    error::{error, AgentMarketErrorCodeV1, AgentMarketResultV1},
    Hash32V1, TaskIdV1,
};

const STORE_APPLICATION_ID_V1: i64 = 0x5452_4e41;
const STORE_SCHEMA_VERSION_V1: u16 = 1;
const META_SQL: &str = "CREATE TABLE task_archive_metadata_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, policy_hash BLOB NOT NULL CHECK(length(policy_hash)=32), generation INTEGER NOT NULL CHECK(generation>=0), live_root BLOB NOT NULL CHECK(length(live_root)=32), last_batch_sequence INTEGER NOT NULL CHECK(last_batch_sequence>=0), last_seal_hash BLOB NOT NULL CHECK(length(last_seal_hash)=32)) STRICT";
const LIVE_SQL: &str = "CREATE TABLE task_archive_live_records_v1 (task_id BLOB PRIMARY KEY CHECK(length(task_id)=32), record BLOB NOT NULL, record_hash BLOB NOT NULL CHECK(length(record_hash)=32)) WITHOUT ROWID";
const HOLD_SQL: &str = "CREATE TABLE task_archive_legal_holds_v1 (task_id BLOB PRIMARY KEY CHECK(length(task_id)=32)) WITHOUT ROWID";
const SEAL_SQL: &str = "CREATE TABLE task_archive_seals_v1 (batch_sequence INTEGER PRIMARY KEY CHECK(batch_sequence>0), seal BLOB NOT NULL, seal_hash BLOB NOT NULL UNIQUE CHECK(length(seal_hash)=32), generation INTEGER NOT NULL CHECK(generation>=1), live_root_before BLOB NOT NULL CHECK(length(live_root_before)=32), live_root_after BLOB NOT NULL CHECK(length(live_root_after)=32)) WITHOUT ROWID";
const ARCHIVE_SQL: &str = "CREATE TABLE task_archive_records_v1 (batch_sequence INTEGER NOT NULL, task_id BLOB NOT NULL CHECK(length(task_id)=32), record BLOB NOT NULL, record_hash BLOB NOT NULL CHECK(length(record_hash)=32), PRIMARY KEY(batch_sequence,task_id), FOREIGN KEY(batch_sequence) REFERENCES task_archive_seals_v1(batch_sequence)) WITHOUT ROWID";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskArchiveDeletionReceiptV1 {
    pub generation: u64,
    pub batch_sequence: u64,
    pub seal_hash: Hash32V1,
    pub live_root_before: Hash32V1,
    pub live_root_after: Hash32V1,
    pub deleted_record_count: u32,
}

#[derive(Clone, Debug)]
pub struct TaskArchiveStoreV1 {
    path: PathBuf,
    policy: TaskArchivePolicyV1,
    policy_hash: Hash32V1,
}

impl TaskArchiveStoreV1 {
    /// Create a new archive owner with an empty live inventory.
    pub fn initialize(
        path: impl Into<PathBuf>,
        policy: TaskArchivePolicyV1,
    ) -> AgentMarketResultV1<Self> {
        policy.validate()?;
        let policy_hash = policy.policy_hash()?;
        let path = path.into();
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(error(
                    AgentMarketErrorCodeV1::Conflict,
                    "TaskV1 archive store path already exists",
                ));
            }
            Err(cause) if cause.kind() != std::io::ErrorKind::NotFound => {
                return Err(error(
                    AgentMarketErrorCodeV1::StoreFailure,
                    cause.to_string(),
                ));
            }
            Err(_) => {}
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|cause| error(AgentMarketErrorCodeV1::StoreFailure, cause.to_string()))?;
        }
        reject_path_ancestors(&path)?;
        reject_sidecars(&path)?;
        // Build the schema in a same-directory temporary inode first.  A
        // process crash during schema creation therefore leaves no final
        // database path that a later opener could mistake for an initialized
        // store.  hard_link() publishes the inode without replacing a path
        // created by a racing initializer.
        let temporary_path = initialization_temp_path(&path)?;
        // Acquire ownership before entering any cleanup path. A collided
        // temporary name belongs to another invocation and must be left alone.
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|cause| error(AgentMarketErrorCodeV1::StoreFailure, cause.to_string()))?;
        let initialized = (|| -> AgentMarketResultV1<()> {
            file.sync_all()
                .map_err(|cause| error(AgentMarketErrorCodeV1::StoreFailure, cause.to_string()))?;
            drop(file);

            let mut connection = open_connection(&temporary_path, true)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(&format!(
                "{META_SQL};{LIVE_SQL};{HOLD_SQL};{SEAL_SQL};{ARCHIVE_SQL};"
            ))?;
            let empty_live_root = live_root_v1(&[])?;
            transaction.execute(
                "INSERT INTO task_archive_metadata_v1(singleton,schema_version,policy_hash,generation,live_root,last_batch_sequence,last_seal_hash) VALUES(1,?1,?2,0,?3,0,?4)",
                params![
                    i64::from(STORE_SCHEMA_VERSION_V1),
                    &policy_hash.0[..],
                    &empty_live_root.0[..],
                    &[0_u8; 32][..],
                ],
            )?;
            transaction.commit()?;
            drop(connection);
            fs::File::open(&temporary_path)
                .and_then(|file| file.sync_all())
                .map_err(|cause| {
                    error(AgentMarketErrorCodeV1::CommitUncertain, cause.to_string())
                })?;
            Ok(())
        })();
        if let Err(cause) = initialized {
            let _ = fs::remove_file(&temporary_path);
            return Err(cause);
        }
        if let Err(cause) = fs::hard_link(&temporary_path, &path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(if cause.kind() == std::io::ErrorKind::AlreadyExists {
                error(
                    AgentMarketErrorCodeV1::Conflict,
                    "TaskV1 archive store path was created during initialization",
                )
            } else {
                error(AgentMarketErrorCodeV1::StoreFailure, cause.to_string())
            });
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent_sync = fs::File::open(parent)
            .and_then(|parent| parent.sync_all())
            .map_err(|cause| error(AgentMarketErrorCodeV1::CommitUncertain, cause.to_string()));
        if let Err(cause) = parent_sync {
            let _ = fs::remove_file(&temporary_path);
            return Err(cause);
        }
        fs::remove_file(&temporary_path)
            .map_err(|cause| error(AgentMarketErrorCodeV1::CommitUncertain, cause.to_string()))?;
        fs::File::open(parent)
            .and_then(|parent| parent.sync_all())
            .map_err(|cause| error(AgentMarketErrorCodeV1::CommitUncertain, cause.to_string()))?;
        Ok(Self {
            path,
            policy,
            policy_hash,
        })
    }

    /// Open and audit an existing archive owner without creating files.
    pub fn open_existing(
        path: impl Into<PathBuf>,
        policy: TaskArchivePolicyV1,
    ) -> AgentMarketResultV1<Self> {
        policy.validate()?;
        let policy_hash = policy.policy_hash()?;
        let path = path.into();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|cause| error(AgentMarketErrorCodeV1::StoreFailure, cause.to_string()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(error(
                AgentMarketErrorCodeV1::StoreFailure,
                "TaskV1 archive store path is not a regular file",
            ));
        }
        reject_sidecars(&path)?;
        let store = Self {
            path,
            policy,
            policy_hash,
        };
        let mut connection = store.open_connection(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        store.audit(&transaction)?;
        Ok(store)
    }

    /// Replace the complete durable hold snapshot.  The caller must obtain
    /// this set from the authenticated task/retention authority; the store
    /// persists it so a deletion cannot race a process-local hold map.
    pub fn replace_legal_hold_snapshot_v1(
        &self,
        holds: &BTreeSet<TaskIdV1>,
    ) -> AgentMarketResultV1<()> {
        let mut connection = self.open_connection(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.audit(&transaction)?;
        transaction.execute("DELETE FROM task_archive_legal_holds_v1", [])?;
        for task_id in holds {
            transaction.execute(
                "INSERT INTO task_archive_legal_holds_v1(task_id) VALUES(?1)",
                params![&task_id.0[..]],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Install the complete live terminal inventory into an empty store.
    /// An already populated inventory cannot be replaced by this API.
    pub fn install_live_records_v1(
        &self,
        records: &[TerminalTaskArchiveRecordV1],
        current_height: u64,
    ) -> AgentMarketResultV1<Hash32V1> {
        let rows = canonical_live_records(&self.policy, records, current_height)?;
        let root = live_root_v1(&rows)?;
        let mut connection = self.open_connection(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.audit(&transaction)?;
        let (generation, live_root) = read_meta(&transaction, self.policy_hash)?;
        if generation != 0 || live_root != live_root_v1(&[])? {
            return Err(error(
                AgentMarketErrorCodeV1::Conflict,
                "TaskV1 live inventory is already initialized",
            ));
        }
        for record in &rows {
            let encoded = canonical_bytes(record)?;
            transaction.execute(
                "INSERT INTO task_archive_live_records_v1(task_id,record,record_hash) VALUES(?1,?2,?3)",
                params![&record.task_id.0[..], encoded, &record.record_hash()?.0[..]],
            )?;
        }
        transaction.execute(
            "UPDATE task_archive_metadata_v1 SET live_root=?1 WHERE singleton=1",
            params![&root.0[..]],
        )?;
        transaction.commit()?;
        Ok(root)
    }

    /// Move one validated archive batch to durable archive rows and delete its
    /// live rows atomically.  A retry of the exact committed batch is
    /// idempotent; a changed batch sequence, seal, live root or record body is
    /// rejected before any mutation.
    pub fn archive_and_delete_v1(
        &self,
        batch: &TaskArchiveBatchV1,
    ) -> AgentMarketResultV1<TaskArchiveDeletionReceiptV1> {
        batch.validate(&self.policy)?;
        let sql_sequence = sql_integer(batch.seal.batch_sequence)?;
        let seal_hash = batch.seal.seal_hash()?;
        let mut connection = self.open_connection(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Revalidate history before both new deletion and exact retry. A
        // cached seal cannot acknowledge archive rows that disappeared.
        self.audit(&transaction)?;
        let (generation, live_root_before) = read_meta(&transaction, self.policy_hash)?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT seal FROM task_archive_seals_v1 WHERE batch_sequence=?1",
                params![sql_sequence],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let stored: TaskArchiveBatchV1 = strict_decode(&existing)?;
            if stored.seal.seal_hash()? != seal_hash || stored != *batch {
                return Err(error(
                    AgentMarketErrorCodeV1::Conflict,
                    "TaskV1 archive batch sequence is bound to another seal",
                ));
            }
            let stored_receipt = transaction.query_row(
                "SELECT generation,live_root_before,live_root_after FROM task_archive_seals_v1 WHERE batch_sequence=?1",
                params![sql_sequence],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?)),
            )?;
            return Ok(TaskArchiveDeletionReceiptV1 {
                generation: u64::try_from(stored_receipt.0).map_err(|_| {
                    error(
                        AgentMarketErrorCodeV1::SchemaMismatch,
                        "TaskV1 archive generation is negative",
                    )
                })?,
                batch_sequence: batch.seal.batch_sequence,
                seal_hash,
                live_root_before: digest32(&stored_receipt.1)?,
                live_root_after: digest32(&stored_receipt.2)?,
                deleted_record_count: batch.seal.record_count,
            });
        }
        let previous = read_last_seal_hash(&transaction)?;
        let last_sequence: i64 = transaction.query_row(
            "SELECT last_batch_sequence FROM task_archive_metadata_v1 WHERE singleton=1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let expected_sequence = u64::try_from(last_sequence)
            .map_err(|_| {
                error(
                    AgentMarketErrorCodeV1::SchemaMismatch,
                    "negative TaskV1 archive sequence",
                )
            })?
            .checked_add(1)
            .ok_or_else(|| {
                error(
                    AgentMarketErrorCodeV1::ArithmeticOverflow,
                    "TaskV1 archive batch sequence overflow",
                )
            })?;
        if batch.seal.batch_sequence != expected_sequence {
            return Err(error(
                AgentMarketErrorCodeV1::StaleVersion,
                "TaskV1 archive batch sequence is not the next durable sequence",
            ));
        }
        if previous != batch.seal.previous_seal_hash {
            return Err(error(
                AgentMarketErrorCodeV1::StaleVersion,
                "TaskV1 archive seal does not extend the durable seal chain",
            ));
        }
        let mut live_records = Vec::with_capacity(batch.records.len());
        for record in &batch.records {
            let bytes = transaction
                .query_row(
                    "SELECT record,record_hash FROM task_archive_live_records_v1 WHERE task_id=?1",
                    params![&record.task_id.0[..]],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?
                .ok_or_else(|| {
                    error(
                        AgentMarketErrorCodeV1::NotFound,
                        "TaskV1 live record is missing",
                    )
                })?;
            let stored: TerminalTaskArchiveRecordV1 = strict_decode(&bytes.0)?;
            if stored != *record || bytes.1.as_slice() != record.record_hash()?.0 {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "TaskV1 live record body or hash differs from archive batch",
                ));
            }
            let held = transaction
                .query_row(
                    "SELECT 1 FROM task_archive_legal_holds_v1 WHERE task_id=?1",
                    params![&record.task_id.0[..]],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if held {
                return Err(error(
                    AgentMarketErrorCodeV1::Conflict,
                    "TaskV1 archive batch contains a durable legal hold",
                ));
            }
            live_records.push(stored);
        }
        let mut remaining = read_live_records(&transaction)?;
        let expected_live_root = live_root_v1(&remaining)?;
        if expected_live_root != live_root_before {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "TaskV1 live inventory root differs from durable metadata",
            ));
        }
        let selected: BTreeSet<TaskIdV1> =
            live_records.iter().map(|record| record.task_id).collect();
        remaining.retain(|record| !selected.contains(&record.task_id));
        let live_root_after = live_root_v1(&remaining)?;
        let next_generation = generation.checked_add(1).ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::ArithmeticOverflow,
                "TaskV1 archive generation overflow",
            )
        })?;
        let sql_generation = sql_integer(next_generation)?;
        let encoded_batch = canonical_bytes(batch)?;
        transaction.execute(
            "INSERT INTO task_archive_seals_v1(batch_sequence,seal,seal_hash,generation,live_root_before,live_root_after) VALUES(?1,?2,?3,?4,?5,?6)",
            params![sql_sequence, encoded_batch, &seal_hash.0[..], sql_generation, &live_root_before.0[..], &live_root_after.0[..]],
        )?;
        for record in &live_records {
            let encoded = canonical_bytes(record)?;
            transaction.execute(
                "INSERT INTO task_archive_records_v1(batch_sequence,task_id,record,record_hash) VALUES(?1,?2,?3,?4)",
                params![sql_sequence, &record.task_id.0[..], encoded, &record.record_hash()?.0[..]],
            )?;
            let deleted = transaction.execute(
                "DELETE FROM task_archive_live_records_v1 WHERE task_id=?1",
                params![&record.task_id.0[..]],
            )?;
            if deleted != 1 {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "TaskV1 archive deletion did not remove exactly one live row",
                ));
            }
        }
        transaction.execute(
            "UPDATE task_archive_metadata_v1 SET generation=?1,live_root=?2,last_batch_sequence=?3,last_seal_hash=?4 WHERE singleton=1 AND generation=?5 AND live_root=?6",
            params![sql_generation, &live_root_after.0[..], sql_sequence, &seal_hash.0[..], sql_integer(generation)?, &live_root_before.0[..]],
        )?;
        if transaction.changes() != 1 {
            return Err(error(
                AgentMarketErrorCodeV1::StaleVersion,
                "TaskV1 live inventory changed during archive",
            ));
        }
        transaction.commit()?;
        Ok(TaskArchiveDeletionReceiptV1 {
            generation: next_generation,
            batch_sequence: batch.seal.batch_sequence,
            seal_hash,
            live_root_before,
            live_root_after,
            deleted_record_count: batch.seal.record_count,
        })
    }

    pub fn read_archive_batch_v1(
        &self,
        batch_sequence: u64,
    ) -> AgentMarketResultV1<TaskArchiveBatchV1> {
        let sql_sequence = sql_integer(batch_sequence)?;
        let mut connection = self.open_connection(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        self.audit(&transaction)?;
        read_archive_batch_from_connection_with_sql_sequence(
            &transaction,
            &self.policy,
            sql_sequence,
        )
    }

    pub fn live_root_v1(&self) -> AgentMarketResultV1<Hash32V1> {
        let mut connection = self.open_connection(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        self.audit(&transaction)?;
        Ok(read_meta(&transaction, self.policy_hash)?.1)
    }

    fn open_connection(&self, create: bool) -> AgentMarketResultV1<Connection> {
        if !create {
            reject_sidecars(&self.path)?;
        }
        open_connection(&self.path, create)
    }

    fn audit(&self, connection: &Connection) -> AgentMarketResultV1<()> {
        audit_schema(connection)?;
        let (generation, live_root) = read_meta(connection, self.policy_hash)?;
        if generation > i64::MAX as u64 {
            return Err(error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "TaskV1 archive generation overflow",
            ));
        }
        let live = read_live_records(connection)?;
        if live_root_v1(&live)? != live_root {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "TaskV1 live root audit failed",
            ));
        }
        let mut all_records = live.clone();
        let mut statement = connection.prepare(
            "SELECT batch_sequence,seal,seal_hash,generation,live_root_before,live_root_after FROM task_archive_seals_v1 ORDER BY batch_sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut previous_sequence = 0_u64;
        let mut previous_seal = Hash32V1([0; 32]);
        let mut previous_root = None;
        let mut archived_generation = 0_u64;
        let mut sealed_batches = Vec::new();
        let mut seen_task_ids: BTreeSet<TaskIdV1> =
            live.iter().map(|record| record.task_id).collect();
        for row in rows {
            let (sequence, encoded, encoded_hash, stored_generation, before, after) = row?;
            let sequence = u64::try_from(sequence).map_err(|_| {
                error(
                    AgentMarketErrorCodeV1::SchemaMismatch,
                    "TaskV1 archive batch sequence is negative",
                )
            })?;
            let stored_generation = u64::try_from(stored_generation).map_err(|_| {
                error(
                    AgentMarketErrorCodeV1::SchemaMismatch,
                    "TaskV1 archive generation is negative",
                )
            })?;
            let batch: TaskArchiveBatchV1 = strict_decode(&encoded)?;
            let seal_hash = batch.seal.seal_hash()?;
            if sequence == 0
                || sequence != previous_sequence.saturating_add(1)
                || stored_generation != archived_generation + 1
                || batch.seal.batch_sequence != sequence
                || batch.seal.previous_seal_hash != previous_seal
                || digest32(&encoded_hash)? != seal_hash
            {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "TaskV1 archive seal chain is invalid",
                ));
            }
            let before = digest32(&before)?;
            let after = digest32(&after)?;
            if before == Hash32V1([0; 32])
                || after == Hash32V1([0; 32])
                || previous_root.is_some_and(|root| root != before)
            {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "TaskV1 archive live-root chain is invalid",
                ));
            }
            let stored = read_archive_batch_from_connection(connection, &self.policy, sequence)?;
            if stored != batch {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "TaskV1 archived records differ from sealed batch",
                ));
            }
            for record in &stored.records {
                if !seen_task_ids.insert(record.task_id) {
                    return Err(error(
                        AgentMarketErrorCodeV1::TamperDetected,
                        "TaskV1 archive task identity is duplicated across live/archive rows",
                    ));
                }
            }
            all_records.extend(stored.records.iter().cloned());
            sealed_batches.push((stored, before, after));
            previous_sequence = sequence;
            previous_seal = seal_hash;
            previous_root = Some(after);
            archived_generation = stored_generation;
        }
        let metadata = connection.query_row(
            "SELECT last_batch_sequence,last_seal_hash FROM task_archive_metadata_v1 WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        let metadata_sequence = u64::try_from(metadata.0).map_err(|_| {
            error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "TaskV1 metadata batch sequence is negative",
            )
        })?;
        if previous_root.is_some_and(|root| live_root != root)
            || metadata_sequence != previous_sequence
            || digest32(&metadata.1)? != previous_seal
            || generation != archived_generation
        {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "TaskV1 archive metadata chain is invalid",
            ));
        }
        let mut reconstructed = all_records;
        for (batch, before, after) in sealed_batches {
            if live_root_v1(&reconstructed)? != before {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "TaskV1 archive predecessor root does not match the retained inventory",
                ));
            }
            let selected: BTreeSet<TaskIdV1> =
                batch.records.iter().map(|record| record.task_id).collect();
            let original_len = reconstructed.len();
            reconstructed.retain(|record| !selected.contains(&record.task_id));
            if reconstructed.len() + selected.len() != original_len
                || live_root_v1(&reconstructed)? != after
            {
                return Err(error(
                    AgentMarketErrorCodeV1::TamperDetected,
                    "TaskV1 archive successor root does not match the exact deletion",
                ));
            }
        }
        if live_root_v1(&reconstructed)? != live_root {
            return Err(error(
                AgentMarketErrorCodeV1::TamperDetected,
                "TaskV1 archive reconstruction does not reach the live root",
            ));
        }
        Ok(())
    }
}

fn audit_schema(connection: &Connection) -> AgentMarketResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    )?;
    let names = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = [
        ("table", "task_archive_legal_holds_v1", HOLD_SQL),
        ("table", "task_archive_live_records_v1", LIVE_SQL),
        ("table", "task_archive_metadata_v1", META_SQL),
        ("table", "task_archive_records_v1", ARCHIVE_SQL),
        ("table", "task_archive_seals_v1", SEAL_SQL),
    ];
    if names.len() != expected.len()
        || expected.iter().any(|(kind, name, sql)| {
            !names.iter().any(|(actual_kind, actual_name, actual_sql)| {
                actual_kind == kind
                    && actual_name == name
                    && actual_sql
                        .as_deref()
                        .is_some_and(|actual| normalize_sql(actual) == normalize_sql(sql))
            })
        })
    {
        return Err(error(
            AgentMarketErrorCodeV1::SchemaMismatch,
            "TaskV1 archive schema objects differ from the closed schema",
        ));
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn read_archive_batch_from_connection(
    connection: &Connection,
    policy: &TaskArchivePolicyV1,
    batch_sequence: u64,
) -> AgentMarketResultV1<TaskArchiveBatchV1> {
    read_archive_batch_from_connection_with_sql_sequence(
        connection,
        policy,
        sql_integer(batch_sequence)?,
    )
}

fn read_archive_batch_from_connection_with_sql_sequence(
    connection: &Connection,
    policy: &TaskArchivePolicyV1,
    sql_sequence: i64,
) -> AgentMarketResultV1<TaskArchiveBatchV1> {
    let encoded = connection
        .query_row(
            "SELECT seal FROM task_archive_seals_v1 WHERE batch_sequence=?1",
            params![sql_sequence],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| {
            error(
                AgentMarketErrorCodeV1::NotFound,
                "TaskV1 archive seal is missing",
            )
        })?;
    let mut batch: TaskArchiveBatchV1 = strict_decode(&encoded)?;
    let mut statement = connection.prepare(
        "SELECT task_id,record,record_hash FROM task_archive_records_v1 WHERE batch_sequence=?1",
    )?;
    let rows = statement.query_map(params![sql_sequence], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    batch.records = rows
        .map(|row| {
            row.map_err(Into::into)
                .and_then(|(task_id, bytes, record_hash)| {
                    let record: TerminalTaskArchiveRecordV1 = strict_decode(&bytes)?;
                    if task_id.as_slice() != record.task_id.0
                        || record_hash.as_slice() != record.record_hash()?.0
                    {
                        return Err(error(
                            AgentMarketErrorCodeV1::TamperDetected,
                            "TaskV1 archive row key or hash differs from record",
                        ));
                    }
                    Ok(record)
                })
        })
        .collect::<AgentMarketResultV1<Vec<_>>>()?;
    batch
        .records
        .sort_by_key(|record| (record.terminal_height, record.task_id));
    batch.validate(policy)?;
    Ok(batch)
}

fn open_connection(path: &Path, create: bool) -> AgentMarketResultV1<Connection> {
    let flags = if create {
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW
    };
    let connection = Connection::open_with_flags(path, flags)?;
    if create {
        connection.pragma_update(None, "application_id", STORE_APPLICATION_ID_V1)?;
        connection.pragma_update(None, "user_version", i64::from(STORE_SCHEMA_VERSION_V1))?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
    } else {
        let application_id =
            connection.pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))?;
        let user_version =
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?;
        let journal_mode =
            connection.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?;
        let synchronous =
            connection.pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))?;
        if application_id != STORE_APPLICATION_ID_V1
            || user_version != i64::from(STORE_SCHEMA_VERSION_V1)
            || !journal_mode.eq_ignore_ascii_case("delete")
            || synchronous != 2
        {
            return Err(error(
                AgentMarketErrorCodeV1::SchemaMismatch,
                "TaskV1 archive SQLite header differs from the closed schema",
            ));
        }
    }
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(connection)
}

fn sql_integer(value: u64) -> AgentMarketResultV1<i64> {
    i64::try_from(value).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::ArithmeticOverflow,
            "TaskV1 archive integer exceeds SQLite signed range",
        )
    })
}

fn reject_sidecars(path: &Path) -> AgentMarketResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if fs::symlink_metadata(&sidecar).is_ok() {
            return Err(error(
                AgentMarketErrorCodeV1::SidecarPresent,
                "TaskV1 archive sidecar is present",
            ));
        }
    }
    Ok(())
}

fn initialization_temp_path(path: &Path) -> AgentMarketResultV1<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|cause| error(AgentMarketErrorCodeV1::StoreFailure, cause.to_string()))?
        .as_nanos();
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(".init-{}-{}", std::process::id(), timestamp));
    Ok(PathBuf::from(temporary))
}

fn reject_path_ancestors(path: &Path) -> AgentMarketResultV1<()> {
    let mut current = Some(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    );
    while let Some(parent) = current {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(error(
                    AgentMarketErrorCodeV1::StoreFailure,
                    "TaskV1 archive parent path is a symlink",
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(error(
                    AgentMarketErrorCodeV1::StoreFailure,
                    "TaskV1 archive parent path is not a directory",
                ));
            }
            Ok(_) => {}
            Err(cause) => {
                return Err(error(
                    AgentMarketErrorCodeV1::StoreFailure,
                    cause.to_string(),
                ));
            }
        }
        current = parent
            .parent()
            .filter(|ancestor| !ancestor.as_os_str().is_empty());
    }
    Ok(())
}

fn read_meta(
    connection: &Connection,
    policy_hash: Hash32V1,
) -> AgentMarketResultV1<(u64, Hash32V1)> {
    let row = connection.query_row(
        "SELECT schema_version,policy_hash,generation,live_root FROM task_archive_metadata_v1 WHERE singleton=1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?)),
    )?;
    let schema = u16::try_from(row.0).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::SchemaMismatch,
            "TaskV1 archive schema overflow",
        )
    })?;
    let stored_policy = digest32(&row.1)?;
    let generation = u64::try_from(row.2).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::SchemaMismatch,
            "TaskV1 archive generation is negative",
        )
    })?;
    let live_root = digest32(&row.3)?;
    if schema != STORE_SCHEMA_VERSION_V1 || stored_policy != policy_hash {
        return Err(error(
            AgentMarketErrorCodeV1::SchemaMismatch,
            "TaskV1 archive metadata differs from policy",
        ));
    }
    Ok((generation, live_root))
}

fn read_last_seal_hash(connection: &Connection) -> AgentMarketResultV1<Hash32V1> {
    connection
        .query_row(
            "SELECT last_seal_hash FROM task_archive_metadata_v1 WHERE singleton=1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(Into::into)
        .and_then(|bytes| digest32(&bytes))
}

fn read_live_records(
    connection: &Connection,
) -> AgentMarketResultV1<Vec<TerminalTaskArchiveRecordV1>> {
    let mut statement = connection.prepare(
        "SELECT task_id,record,record_hash FROM task_archive_live_records_v1 ORDER BY task_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    rows.map(|row| {
        row.map_err(Into::into)
            .and_then(|(task_id, bytes, record_hash)| {
                let record: TerminalTaskArchiveRecordV1 = strict_decode(&bytes)?;
                if task_id.as_slice() != record.task_id.0
                    || record_hash.as_slice() != record.record_hash()?.0
                {
                    return Err(error(
                        AgentMarketErrorCodeV1::TamperDetected,
                        "TaskV1 live row key or hash differs from record",
                    ));
                }
                Ok(record)
            })
    })
    .collect()
}

fn canonical_live_records(
    policy: &TaskArchivePolicyV1,
    records: &[TerminalTaskArchiveRecordV1],
    current_height: u64,
) -> AgentMarketResultV1<Vec<TerminalTaskArchiveRecordV1>> {
    let mut rows = records.to_vec();
    rows.sort_by_key(|record| (record.terminal_height, record.task_id));
    let mut ids = BTreeSet::new();
    for record in &rows {
        record.validate_against(policy, current_height)?;
        if !ids.insert(record.task_id) {
            return Err(error(
                AgentMarketErrorCodeV1::NonCanonical,
                "duplicate TaskV1 live record",
            ));
        }
    }
    Ok(rows)
}

fn live_root_v1(records: &[TerminalTaskArchiveRecordV1]) -> AgentMarketResultV1<Hash32V1> {
    let mut hashes = records
        .iter()
        .map(TerminalTaskArchiveRecordV1::record_hash)
        .collect::<AgentMarketResultV1<Vec<_>>>()?;
    hashes.sort();
    digest_value("trnm.poco-ai.task-archive-live-root.candidate.v1", &hashes)
}

fn digest32(bytes: &[u8]) -> AgentMarketResultV1<Hash32V1> {
    <[u8; 32]>::try_from(bytes).map(Hash32V1).map_err(|_| {
        error(
            AgentMarketErrorCodeV1::SchemaMismatch,
            "TaskV1 archive digest length mismatch",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive::{plan_task_archive_pruning_v1, TASK_ARCHIVE_SCHEMA_VERSION_V1},
        ProtocolContextV1,
    };
    use tempfile::tempdir;

    fn context() -> ProtocolContextV1 {
        ProtocolContextV1 {
            genesis_hash: Hash32V1([1; 32]),
            chain_id: "trnm-archive-store-test".to_string(),
            protocol_version: 1,
            stack_profile_hash: Hash32V1([2; 32]),
        }
    }

    fn policy() -> TaskArchivePolicyV1 {
        TaskArchivePolicyV1 {
            schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
            context: context(),
            minimum_terminal_retention_blocks: 5,
            maximum_live_terminal_records: 1,
            maximum_live_terminal_bytes: 100,
            maximum_archive_batch_records: 8,
            maximum_archive_batch_bytes: 800,
            retention_charge_units_per_byte_block: 2,
        }
    }

    fn record(id: u8) -> TerminalTaskArchiveRecordV1 {
        TerminalTaskArchiveRecordV1 {
            schema_version: TASK_ARCHIVE_SCHEMA_VERSION_V1,
            context: context(),
            task_id: TaskIdV1([id; 32]),
            terminal_height: u64::from(id),
            task_revision: u64::from(id),
            terminal_state_digest: Hash32V1([id.wrapping_add(1); 32]),
            terminal_receipt_digest: Hash32V1([id.wrapping_add(2); 32]),
            evidence_root: Hash32V1([id.wrapping_add(3); 32]),
            encoded_bytes: 100,
            retention_paid_through_height: u64::from(id) + 4,
            retention_charge_paid: 1_000,
        }
    }

    #[test]
    fn archive_delete_moves_rows_and_reopen_preserves_proof() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("archive.sqlite");
        let policy = policy();
        let store = TaskArchiveStoreV1::initialize(&path, policy.clone()).unwrap();
        let records = vec![record(1), record(2), record(3)];
        store.install_live_records_v1(&records, 20).unwrap();
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &records,
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .unwrap();
        let batch = plan.archive_batch().unwrap().clone();
        let receipt = store.archive_and_delete_v1(&batch).unwrap();
        assert_eq!(receipt.deleted_record_count, 2);
        assert_eq!(
            store.live_root_v1().unwrap(),
            live_root_v1(plan.retained_records()).unwrap()
        );
        let archived = store.read_archive_batch_v1(1).unwrap();
        assert_eq!(archived, batch);
        let reopened = TaskArchiveStoreV1::open_existing(&path, policy).unwrap();
        assert_eq!(reopened.read_archive_batch_v1(1).unwrap(), batch);
        assert_eq!(reopened.archive_and_delete_v1(&batch).unwrap(), receipt);
    }

    #[test]
    fn durable_hold_blocks_delete_before_any_archive_mutation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("archive-hold.sqlite");
        let policy = policy();
        let store = TaskArchiveStoreV1::initialize(&path, policy.clone()).unwrap();
        let records = vec![record(1), record(2), record(3)];
        store.install_live_records_v1(&records, 20).unwrap();
        store
            .replace_legal_hold_snapshot_v1(&BTreeSet::from([TaskIdV1([1; 32])]))
            .unwrap();
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &records,
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .unwrap();
        let failure = store
            .archive_and_delete_v1(plan.archive_batch().unwrap())
            .unwrap_err();
        assert_eq!(failure.code(), AgentMarketErrorCodeV1::Conflict);
        assert_eq!(
            store.live_root_v1().unwrap(),
            live_root_v1(&records).unwrap()
        );
        assert!(store.read_archive_batch_v1(1).is_err());
    }

    #[test]
    fn archive_sequence_gap_is_rejected_before_mutation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("archive-sequence.sqlite");
        let policy = policy();
        let store = TaskArchiveStoreV1::initialize(&path, policy.clone()).unwrap();
        let records = vec![record(1), record(2), record(3)];
        store.install_live_records_v1(&records, 20).unwrap();
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &records,
            &BTreeSet::new(),
            20,
            2,
            Hash32V1([0; 32]),
        )
        .unwrap();
        let failure = store
            .archive_and_delete_v1(plan.archive_batch().unwrap())
            .unwrap_err();
        assert_eq!(failure.code(), AgentMarketErrorCodeV1::StaleVersion);
        assert_eq!(
            store.live_root_v1().unwrap(),
            live_root_v1(&records).unwrap()
        );
        assert!(store.read_archive_batch_v1(2).is_err());
    }

    #[test]
    fn schema_and_archive_row_tamper_fail_closed_before_reopen_or_retry() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("archive-schema.sqlite");
        let policy = policy();
        let store = TaskArchiveStoreV1::initialize(&path, policy.clone()).unwrap();
        let records = vec![record(1), record(2), record(3)];
        store.install_live_records_v1(&records, 20).unwrap();
        drop(store);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER archive_row_tamper_v1 AFTER INSERT ON task_archive_live_records_v1 BEGIN SELECT RAISE(IGNORE); END;",
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            TaskArchiveStoreV1::open_existing(&path, policy.clone())
                .unwrap_err()
                .code(),
            AgentMarketErrorCodeV1::SchemaMismatch
        );

        let path = directory.path().join("archive-row.sqlite");
        let store = TaskArchiveStoreV1::initialize(&path, policy.clone()).unwrap();
        store.install_live_records_v1(&records, 20).unwrap();
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &records,
            &BTreeSet::new(),
            20,
            1,
            Hash32V1([0; 32]),
        )
        .unwrap();
        let batch = plan.archive_batch().unwrap().clone();
        let receipt = store.archive_and_delete_v1(&batch).unwrap();
        drop(store);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE task_archive_seals_v1 SET live_root_before=?1 WHERE batch_sequence=1",
                params![&Hash32V1([88; 32]).0[..]],
            )
            .unwrap();
        drop(connection);
        assert!(TaskArchiveStoreV1::open_existing(&path, policy.clone()).is_err());
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE task_archive_seals_v1 SET live_root_before=?1 WHERE batch_sequence=1",
                params![&receipt.live_root_before.0[..]],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE task_archive_records_v1 SET task_id=?1 WHERE batch_sequence=1 AND task_id=(SELECT task_id FROM task_archive_records_v1 WHERE batch_sequence=1 ORDER BY task_id LIMIT 1)",
                params![&TaskIdV1([99; 32]).0[..]],
            )
            .unwrap();
        drop(connection);
        assert!(TaskArchiveStoreV1::open_existing(&path, policy).is_err());
    }
}
