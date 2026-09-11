//! Immutable local storage for the closed `EvidenceVerified` epoch phase.
//!
//! This namespace is separate from SafetyState schema 13 and the main safety
//! journal. A fresh read re-runs the complete strict epoch proof verification.
//! It attests neither native checkpoint application nor seal signing custody,
//! a live epoch anchor, or external-watermark freshness. Replacing an entire
//! self-consistent image cannot be detected without an independent expected
//! binding and a host-owned monotonic record.
//!
//! Like the main safety journal, this store requires Linux, a local filesystem
//! with reliable SQLite locks/flock/fsync, an owner-controlled private directory,
//! and one dedicated process owner. Untrusted same-EUID writers, raw secondary
//! SQLite connections, network filesystems and fork-after-open are unsupported.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    maximum_epoch_preparation_record_bytes_v1, recover_epoch_preparation_v1,
    EpochPreparationErrorV1, EpochPreparationV1, EPOCH_PREPARATION_RECORD_OVERHEAD_V1,
    MAX_EPOCH_PREPARATION_RECORD_BYTES_V1,
};
use trnm_consensus_types::{Cev0AdmissionBudgetV0, ConsensusParametersV0, ValidatorSet};

const STORE_SCHEMA_V1: i64 = 1;
const EVIDENCE_VERIFIED_PHASE_V1: i64 = 0;
const APPLICATION_ID_V1: i64 = 0x5452_4550;
const LOCK_MAGIC_V1: &[u8; 8] = b"TRNMEPL1";
const LOCK_BYTES_V1: u64 = 40;
const MAXIMUM_SHM_BYTES_V1: u64 = 65_536;
const SCHEMA_SQL_V1: &str = "CREATE TABLE epoch_preparation_v1 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    phase INTEGER NOT NULL CHECK (phase = 0),
    binding BLOB NOT NULL CHECK (length(binding) = 32),
    record BLOB NOT NULL CHECK (length(record) > 0),
    record_checksum BLOB NOT NULL CHECK (length(record_checksum) = 32)
) STRICT";

/// Real initialization cuts for process-crash qualification. Returning an error
/// before commit drops and rolls back the actual SQLite transaction; a process
/// exit at a cut leaves the real on-disk namespace for a later reopen test.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochPreparationCreateCutV1 {
    AfterSchemaBeforeRecord,
    AfterRecordBeforeCommit,
    AfterCommitBeforeSync,
    AfterSyncBeforeReadback,
}

#[derive(Debug)]
pub enum EpochPreparationStoreErrorV1 {
    Io {
        stage: &'static str,
        error: io::Error,
    },
    Sqlite {
        stage: &'static str,
        error: rusqlite::Error,
    },
    Preparation(EpochPreparationErrorV1),
    UnsupportedPlatform,
    InvalidNamespace(&'static str),
    AlreadyExists,
    Missing(&'static str),
    Locked,
    FileIdentityChanged,
    OwnerProcessChanged,
    SchemaMismatch,
    InvalidRecord(&'static str),
    RecordConflict,
    ResourceLimit,
}

impl std::fmt::Display for EpochPreparationStoreErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { stage, error } => write!(formatter, "epoch preparation {stage}: {error}"),
            Self::Sqlite { stage, error } => {
                write!(formatter, "epoch preparation {stage}: {error}")
            }
            Self::Preparation(error) => write!(formatter, "epoch preparation proof: {error}"),
            Self::UnsupportedPlatform => {
                formatter.write_str("epoch preparation store requires Linux")
            }
            Self::InvalidNamespace(reason) => {
                write!(formatter, "epoch preparation namespace: {reason}")
            }
            Self::AlreadyExists => {
                formatter.write_str("epoch preparation namespace already exists")
            }
            Self::Missing(part) => write!(formatter, "epoch preparation namespace lacks {part}"),
            Self::Locked => formatter.write_str("epoch preparation namespace is already owned"),
            Self::FileIdentityChanged => {
                formatter.write_str("epoch preparation pinned file or directory changed")
            }
            Self::OwnerProcessChanged => {
                formatter.write_str("epoch preparation store cannot be used after fork")
            }
            Self::SchemaMismatch => {
                formatter.write_str("epoch preparation SQLite schema is not exactly version 1")
            }
            Self::InvalidRecord(reason) => write!(formatter, "epoch preparation record: {reason}"),
            Self::RecordConflict => formatter
                .write_str("epoch preparation record conflicts with the immutable stored evidence"),
            Self::ResourceLimit => {
                formatter.write_str("epoch preparation storage resource bound exceeded")
            }
        }
    }
}

impl std::error::Error for EpochPreparationStoreErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::Sqlite { error, .. } => Some(error),
            Self::Preparation(error) => Some(error),
            _ => None,
        }
    }
}

type StoreResult<T> = Result<T, EpochPreparationStoreErrorV1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentityV1 {
    device: u64,
    inode: u64,
}

struct PinnedFileV1 {
    path: PathBuf,
    file: File,
    identity: FileIdentityV1,
    is_directory: bool,
    maximum_bytes: u64,
}

impl PinnedFileV1 {
    fn new(path: PathBuf, file: File, is_directory: bool, maximum_bytes: u64) -> StoreResult<Self> {
        let identity = checked_identity(
            &file
                .metadata()
                .map_err(|error| io_error("stat pinned handle", error))?,
            is_directory,
            maximum_bytes,
        )?;
        let pinned = Self {
            path,
            file,
            identity,
            is_directory,
            maximum_bytes,
        };
        pinned.require_unchanged()?;
        Ok(pinned)
    }

    fn require_unchanged(&self) -> StoreResult<()> {
        let named = fs::symlink_metadata(&self.path)
            .map_err(|error| io_error("stat pinned path", error))?;
        let opened = self
            .file
            .metadata()
            .map_err(|error| io_error("stat pinned handle", error))?;
        if checked_identity(&named, self.is_directory, self.maximum_bytes)? != self.identity
            || checked_identity(&opened, self.is_directory, self.maximum_bytes)? != self.identity
            || fs::canonicalize(&self.path)
                .map_err(|error| io_error("check canonical path", error))?
                != self.path
        {
            return Err(EpochPreparationStoreErrorV1::FileIdentityChanged);
        }
        Ok(())
    }
}

/// One immutable, strictly verified epoch preparation record.
///
/// The transitional SQLite connection is declared before pinned handles so it
/// closes before those descriptors on every error path. Successful public
/// operations retain no SQLite connection or page cache. Each fresh read opens
/// and explicitly closes its own read-only connection before returning evidence.
/// Every ordinary existing open is read-only; no missing record, sidecar, phase
/// or schema is initialized or repaired.
pub struct SqliteEpochPreparationStoreV1 {
    connection: Option<Connection>,
    database: PinnedFileV1,
    lock: PinnedFileV1,
    wal: Option<PinnedFileV1>,
    shm: Option<PinnedFileV1>,
    directory: PinnedFileV1,
    trusted_old_set: ValidatorSet,
    trusted_old_parameters: ConsensusParametersV0,
    expected_binding: [u8; 32],
    record_bytes: Vec<u8>,
    maximum_record_bytes: usize,
    owner_pid: u32,
}

impl std::fmt::Debug for SqliteEpochPreparationStoreV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteEpochPreparationStoreV1")
            .field("database_path", &self.database.path)
            .field("phase", &"EvidenceVerified")
            .field("expected_binding", &self.expected_binding)
            .finish_non_exhaustive()
    }
}

impl SqliteEpochPreparationStoreV1 {
    /// Creates an exclusive immutable store from a real strict preparation.
    ///
    /// The database parent must already exist with owner-only mode 0700. The
    /// proof, trusted old context and caller budget are checked before any
    /// namespace mutation. A failed creation leaves its partial namespace for
    /// inspection; it is never silently replaced or repaired on a later open.
    pub fn create_new(
        database_path: impl AsRef<Path>,
        preparation: EpochPreparationV1,
        trusted_old_set: &ValidatorSet,
        trusted_old_parameters: &ConsensusParametersV0,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> StoreResult<Self> {
        Self::create_new_with_observer_v1(
            database_path,
            preparation,
            trusted_old_set,
            trusted_old_parameters,
            budget,
            |_| Ok(()),
        )
    }

    /// Initialization-only qualification seam using actual transaction cuts.
    /// It cannot bypass evidence checks or create an additional supported phase.
    #[doc(hidden)]
    pub fn create_new_with_observer_v1(
        database_path: impl AsRef<Path>,
        preparation: EpochPreparationV1,
        trusted_old_set: &ValidatorSet,
        trusted_old_parameters: &ConsensusParametersV0,
        budget: &mut Cev0AdmissionBudgetV0,
        mut observer: impl FnMut(EpochPreparationCreateCutV1) -> StoreResult<()>,
    ) -> StoreResult<Self> {
        require_linux()?;
        let record_bytes = preparation
            .record_v1()
            .encode_v1()
            .map_err(EpochPreparationStoreErrorV1::Preparation)?;
        let expected_binding = preparation.record_v1().binding_ref_v1();
        let maximum_record_bytes = record_limit(trusted_old_parameters, budget)?;
        if record_bytes.len() > maximum_record_bytes {
            return Err(EpochPreparationStoreErrorV1::ResourceLimit);
        }
        let verified = recover_epoch_preparation_v1(
            &record_bytes,
            trusted_old_set,
            trusted_old_parameters,
            expected_binding,
            budget,
        )
        .map_err(EpochPreparationStoreErrorV1::Preparation)?;
        drop(verified);
        drop(preparation);

        let (database_path, directory) = pin_namespace(database_path.as_ref())?;
        let lock_path = auxiliary_path(&database_path, ".epoch.lock");
        for path in [
            &database_path,
            &lock_path,
            &auxiliary_path(&database_path, "-wal"),
            &auxiliary_path(&database_path, "-shm"),
            &auxiliary_path(&database_path, "-journal"),
        ] {
            require_absent(path)?;
        }
        let maximum_database_bytes = database_limit(maximum_record_bytes)?;
        let mut lock_file = private_file(&lock_path, true)?;
        lock_exclusive(&lock_file)?;
        lock_file
            .write_all(LOCK_MAGIC_V1)
            .and_then(|_| lock_file.write_all(&expected_binding))
            .map_err(|error| io_error("write preparation lock binding", error))?;
        lock_file
            .sync_all()
            .map_err(|error| io_error("sync preparation lock", error))?;
        let lock = PinnedFileV1::new(lock_path, lock_file, false, LOCK_BYTES_V1)?;
        let database_file = private_file(&database_path, true)?;
        lock_exclusive(&database_file)?;
        let database = PinnedFileV1::new(
            database_path.clone(),
            database_file,
            false,
            maximum_database_bytes,
        )?;
        directory
            .file
            .sync_all()
            .map_err(|error| io_error("sync created namespace", error))?;
        directory.require_unchanged()?;
        database.require_unchanged()?;

        let connection = open_connection(&database_path, false)?;
        configure_connection(
            &connection,
            true,
            maximum_record_bytes,
            maximum_database_bytes,
        )?;
        let mut store = Self {
            connection: Some(connection),
            database,
            lock,
            wal: None,
            shm: None,
            directory,
            trusted_old_set: trusted_old_set.clone(),
            trusted_old_parameters: *trusted_old_parameters,
            expected_binding,
            record_bytes,
            maximum_record_bytes,
            owner_pid: std::process::id(),
        };
        {
            let transaction = store
                .connection
                .as_mut()
                .expect("creation connection is present")
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| sql_error("begin immutable preparation", error))?;
            // BEGIN IMMEDIATE has materialized the real WAL/SHM. Pin them before
            // the first observer can alter their names, and retain them in the
            // same owner whose connection drops first on any transaction error.
            store.wal = Some(pin_existing(
                &auxiliary_path(&database_path, "-wal"),
                maximum_database_bytes,
            )?);
            store.shm = Some(pin_existing(
                &auxiliary_path(&database_path, "-shm"),
                MAXIMUM_SHM_BYTES_V1,
            )?);
            transaction
                .execute_batch(SCHEMA_SQL_V1)
                .map_err(|error| sql_error("create preparation schema", error))?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID_V1)
                .map_err(|error| sql_error("write preparation application ID", error))?;
            transaction
                .pragma_update(None, "user_version", STORE_SCHEMA_V1)
                .map_err(|error| sql_error("write preparation schema version", error))?;
            observer(EpochPreparationCreateCutV1::AfterSchemaBeforeRecord)?;
            let checksum = record_checksum(&store.record_bytes);
            transaction.execute(
                "INSERT INTO epoch_preparation_v1(singleton, schema_version, phase, binding, record, record_checksum)
                 VALUES(1, 1, 0, ?1, ?2, ?3)",
                params![expected_binding.as_slice(), store.record_bytes.as_slice(), checksum.as_slice()],
            ).map_err(|error| sql_error("insert immutable preparation", error))?;
            observer(EpochPreparationCreateCutV1::AfterRecordBeforeCommit)?;
            transaction
                .commit()
                .map_err(|error| sql_error("commit immutable preparation", error))?;
        }
        observer(EpochPreparationCreateCutV1::AfterCommitBeforeSync)?;
        store.require_namespace_unchanged()?;
        store.close_transitional_connection()?;
        store.require_namespace_unchanged()?;
        store
            .database
            .file
            .sync_all()
            .map_err(|error| io_error("sync preparation database", error))?;
        store
            .wal
            .as_ref()
            .expect("creation pinned WAL")
            .file
            .sync_all()
            .map_err(|error| io_error("sync preparation WAL", error))?;
        store
            .shm
            .as_ref()
            .expect("creation pinned SHM")
            .file
            .sync_all()
            .map_err(|error| io_error("sync preparation SHM", error))?;
        store
            .directory
            .file
            .sync_all()
            .map_err(|error| io_error("sync committed namespace", error))?;
        observer(EpochPreparationCreateCutV1::AfterSyncBeforeReadback)?;
        store.require_namespace_unchanged()?;
        // Reopen after the writer is closed and synced. A byte-identical fresh
        // disk read retains the strict verification done before creating files.
        store.read_exact_record()?;
        store.require_namespace_unchanged()?;
        Ok(store)
    }

    /// Opens only an existing complete namespace and strictly re-verifies it.
    /// The expected binding is supplied independently of the database image.
    pub fn open_existing(
        database_path: impl AsRef<Path>,
        trusted_old_set: &ValidatorSet,
        trusted_old_parameters: &ConsensusParametersV0,
        expected_binding: [u8; 32],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> StoreResult<Self> {
        require_linux()?;
        if expected_binding == [0; 32] {
            return Err(EpochPreparationStoreErrorV1::InvalidRecord(
                "zero expected binding",
            ));
        }
        let maximum_record_bytes = record_limit(trusted_old_parameters, budget)?;
        let maximum_database_bytes = database_limit(maximum_record_bytes)?;
        let (database_path, directory) = pin_namespace(database_path.as_ref())?;
        require_absent(&auxiliary_path(&database_path, "-journal"))?;
        let lock = pin_existing(
            &auxiliary_path(&database_path, ".epoch.lock"),
            LOCK_BYTES_V1,
        )?;
        lock_exclusive(&lock.file)?;
        require_lock_binding(&lock, expected_binding)?;
        let database = pin_existing(&database_path, maximum_database_bytes)?;
        lock_exclusive(&database.file)?;
        if database
            .file
            .metadata()
            .map_err(|error| io_error("stat database", error))?
            .len()
            == 0
        {
            return Err(EpochPreparationStoreErrorV1::Missing("committed database"));
        }
        // No CREATE flag and no sidecar materialization: incomplete creation
        // or a deleted persistent sidecar is a hard failure before SQLite opens.
        let wal = pin_existing(
            &auxiliary_path(&database_path, "-wal"),
            maximum_database_bytes,
        )?;
        let shm = pin_existing(
            &auxiliary_path(&database_path, "-shm"),
            MAXIMUM_SHM_BYTES_V1,
        )?;
        let mut store = Self {
            connection: None,
            database,
            lock,
            wal: Some(wal),
            shm: Some(shm),
            directory,
            trusted_old_set: trusted_old_set.clone(),
            trusted_old_parameters: *trusted_old_parameters,
            expected_binding,
            record_bytes: Vec::new(),
            maximum_record_bytes,
            owner_pid: std::process::id(),
        };
        let record_bytes = store.read_record_from_disk()?;
        let preparation = recover_epoch_preparation_v1(
            &record_bytes,
            trusted_old_set,
            trusted_old_parameters,
            expected_binding,
            budget,
        )
        .map_err(EpochPreparationStoreErrorV1::Preparation)?;
        drop(preparation);
        store.record_bytes = record_bytes;
        store.require_namespace_unchanged()?;
        Ok(store)
    }

    pub const fn binding_ref_v1(&self) -> [u8; 32] {
        self.expected_binding
    }

    /// Returns a real newly re-verified preparation owner from a fresh SQLite
    /// snapshot. No cached authority or unchecked record is returned.
    pub fn recover_fresh_v1(
        &mut self,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> StoreResult<EpochPreparationV1> {
        self.require_namespace_unchanged()?;
        let bytes = self.read_exact_record()?;
        let preparation = recover_epoch_preparation_v1(
            &bytes,
            &self.trusted_old_set,
            &self.trusted_old_parameters,
            self.expected_binding,
            budget,
        )
        .map_err(EpochPreparationStoreErrorV1::Preparation)?;
        self.require_namespace_unchanged()?;
        Ok(preparation)
    }

    /// Idempotently retains the same exact preparation. A different binding
    /// or record conflicts; this method never updates or overwrites the row.
    pub fn retain_exact_v1(
        &mut self,
        preparation: EpochPreparationV1,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> StoreResult<EpochPreparationV1> {
        self.require_namespace_unchanged()?;
        let bytes = preparation
            .record_v1()
            .encode_v1()
            .map_err(EpochPreparationStoreErrorV1::Preparation)?;
        if preparation.record_v1().binding_ref_v1() != self.expected_binding
            || bytes != self.record_bytes
        {
            return Err(EpochPreparationStoreErrorV1::RecordConflict);
        }
        drop(preparation);
        self.recover_fresh_v1(budget)
    }

    fn read_exact_record(&mut self) -> StoreResult<Vec<u8>> {
        let bytes = self.read_record_from_disk()?;
        if bytes != self.record_bytes {
            return Err(EpochPreparationStoreErrorV1::RecordConflict);
        }
        Ok(bytes)
    }

    fn read_record_from_disk(&mut self) -> StoreResult<Vec<u8>> {
        if self.connection.is_some() {
            return Err(EpochPreparationStoreErrorV1::InvalidRecord(
                "fresh disk read cannot reuse a live SQLite connection",
            ));
        }
        self.require_namespace_unchanged()?;
        let connection = open_connection(&self.database.path, true)?;
        self.connection = Some(connection);
        let result = (|| {
            let connection = self
                .connection
                .as_ref()
                .expect("fresh connection is present");
            configure_connection(
                connection,
                false,
                self.maximum_record_bytes,
                self.database.maximum_bytes,
            )?;
            read_record(connection, self.expected_binding, self.maximum_record_bytes)
        })();
        // Explicit close and post-close namespace checks are required even if
        // schema or record admission failed. No statement/transaction outlives
        // read_record, and no recovered authority exists yet at this boundary.
        let close_result = self.close_transitional_connection();
        let namespace_result = self.require_namespace_unchanged();
        close_result?;
        namespace_result?;
        result
    }

    fn close_transitional_connection(&mut self) -> StoreResult<()> {
        let Some(connection) = self.connection.take() else {
            return Ok(());
        };
        match connection.close() {
            Ok(()) => Ok(()),
            Err((connection, error)) => {
                // Retire the failed handle before any pinned file can close.
                // A close failure can never acknowledge a preparation.
                drop(connection);
                Err(sql_error(
                    "explicitly close preparation SQLite connection",
                    error,
                ))
            }
        }
    }

    fn require_namespace_unchanged(&self) -> StoreResult<()> {
        if std::process::id() != self.owner_pid {
            return Err(EpochPreparationStoreErrorV1::OwnerProcessChanged);
        }
        validate_ancestors(&self.directory.path)?;
        let wal = self
            .wal
            .as_ref()
            .ok_or(EpochPreparationStoreErrorV1::Missing("pinned WAL"))?;
        let shm = self
            .shm
            .as_ref()
            .ok_or(EpochPreparationStoreErrorV1::Missing("pinned SHM"))?;
        for pinned in [&self.directory, &self.database, &self.lock, wal, shm] {
            pinned.require_unchanged()?;
        }
        require_absent(&auxiliary_path(&self.database.path, "-journal"))?;
        require_lock_binding(&self.lock, self.expected_binding)
    }
}

fn read_record(
    connection: &Connection,
    expected_binding: [u8; 32],
    maximum_bytes: usize,
) -> StoreResult<Vec<u8>> {
    let transaction = connection
        .unchecked_transaction()
        .map_err(|error| sql_error("begin fresh preparation read", error))?;
    validate_schema(&transaction)?;
    let count: i64 = transaction
        .query_row("SELECT count(*) FROM epoch_preparation_v1", [], |row| {
            row.get(0)
        })
        .map_err(|error| sql_error("count preparation records", error))?;
    if count != 1 {
        return Err(EpochPreparationStoreErrorV1::InvalidRecord(
            "expected exactly one immutable row",
        ));
    }
    let shape: (i64, i64, i64, String, i64, String, i64, String, i64) = transaction
        .query_row(
            "SELECT singleton, schema_version, phase, typeof(binding), length(binding),
                typeof(record), length(record), typeof(record_checksum), length(record_checksum)
         FROM epoch_preparation_v1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .map_err(|error| sql_error("preflight preparation blob lengths", error))?;
    if shape.0 != 1
        || shape.1 != STORE_SCHEMA_V1
        || shape.2 != EVIDENCE_VERIFIED_PHASE_V1
        || shape.3 != "blob"
        || shape.4 != 32
        || shape.5 != "blob"
        || shape.6 <= 0
        || shape.6 as u128 > maximum_bytes as u128
        || shape.7 != "blob"
        || shape.8 != 32
    {
        return Err(EpochPreparationStoreErrorV1::InvalidRecord(
            "unsupported phase, schema, or bounded blob shape",
        ));
    }
    // The length/type check and allocation share one SQLite read transaction.
    let (binding, record, checksum): (Vec<u8>, Vec<u8>, Vec<u8>) = transaction
        .query_row(
            "SELECT binding, record, record_checksum FROM epoch_preparation_v1 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| sql_error("read bounded preparation record", error))?;
    if binding.as_slice() != expected_binding
        || record_checksum(&record).as_slice() != checksum.as_slice()
    {
        return Err(EpochPreparationStoreErrorV1::InvalidRecord(
            "binding or record checksum mismatch",
        ));
    }
    transaction
        .commit()
        .map_err(|error| sql_error("finish preparation read", error))?;
    Ok(record)
}

fn validate_schema(connection: &Connection) -> StoreResult<()> {
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|error| sql_error("read preparation application ID", error))?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| sql_error("read preparation schema version", error))?;
    if application_id != APPLICATION_ID_V1 || version != STORE_SCHEMA_V1 {
        return Err(EpochPreparationStoreErrorV1::SchemaMismatch);
    }
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name LIMIT 2")
        .map_err(|error| sql_error("inspect exact preparation schema", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| sql_error("read preparation schema", error))?;
    let row = rows
        .next()
        .map_err(|error| sql_error("read preparation schema row", error))?
        .ok_or(EpochPreparationStoreErrorV1::SchemaMismatch)?;
    let kind: String = row
        .get(0)
        .map_err(|error| sql_error("read schema kind", error))?;
    let name: String = row
        .get(1)
        .map_err(|error| sql_error("read schema name", error))?;
    let table: String = row
        .get(2)
        .map_err(|error| sql_error("read schema table", error))?;
    let sql: String = row
        .get(3)
        .map_err(|error| sql_error("read schema SQL", error))?;
    if kind != "table"
        || name != "epoch_preparation_v1"
        || table != name
        || sql != SCHEMA_SQL_V1
        || rows
            .next()
            .map_err(|error| sql_error("reject extra schema object", error))?
            .is_some()
    {
        return Err(EpochPreparationStoreErrorV1::SchemaMismatch);
    }
    Ok(())
}

fn record_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"trnm.local.epoch-preparation-record-checksum.v1");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn record_limit(
    parameters: &ConsensusParametersV0,
    budget: &Cev0AdmissionBudgetV0,
) -> StoreResult<usize> {
    let budget_limit = budget
        .maximum_root_bytes()
        .checked_add(EPOCH_PREPARATION_RECORD_OVERHEAD_V1)
        .ok_or(EpochPreparationStoreErrorV1::ResourceLimit)?;
    Ok(maximum_epoch_preparation_record_bytes_v1(parameters)
        .min(MAX_EPOCH_PREPARATION_RECORD_BYTES_V1)
        .min(budget_limit))
}

fn database_limit(record_limit: usize) -> StoreResult<u64> {
    // One immutable record, its WAL image and SQLite page/schema overhead.
    record_limit
        .checked_mul(4)
        .and_then(|value| value.checked_add(1_048_576))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(EpochPreparationStoreErrorV1::ResourceLimit)
}

fn open_connection(path: &Path, read_only: bool) -> StoreResult<Connection> {
    let access = if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    Connection::open_with_flags(
        path,
        access | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| sql_error("open existing SQLite file without create", error))
}

fn configure_connection(
    connection: &Connection,
    initialize: bool,
    maximum_record_bytes: usize,
    maximum_database_bytes: u64,
) -> StoreResult<()> {
    connection
        .busy_timeout(Duration::from_millis(100))
        .map_err(|error| sql_error("configure preparation busy timeout", error))?;
    let length_limit = maximum_record_bytes
        .checked_add(4096)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(EpochPreparationStoreErrorV1::ResourceLimit)?;
    // SAFETY: the live connection owns this SQLite handle; both limit operations
    // accept integer bounds and retain no caller pointers.
    unsafe {
        rusqlite::ffi::sqlite3_limit(
            connection.handle(),
            rusqlite::ffi::SQLITE_LIMIT_LENGTH,
            length_limit,
        );
        rusqlite::ffi::sqlite3_limit(
            connection.handle(),
            rusqlite::ffi::SQLITE_LIMIT_SQL_LENGTH,
            65_536,
        );
    }
    connection
        .execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA recursive_triggers=OFF;
        PRAGMA synchronous=FULL; PRAGMA mmap_size=0; PRAGMA cache_size=-512;
        PRAGMA temp_store=MEMORY;",
        )
        .map_err(|error| sql_error("configure bounded preparation connection", error))?;
    if initialize {
        connection
            .execute_batch(
                "PRAGMA page_size=4096; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;",
            )
            .map_err(|error| sql_error("enable preparation WAL", error))?;
        connection
            .pragma_update(None, "max_page_count", maximum_database_bytes / 4096)
            .map_err(|error| sql_error("bound preparation database pages", error))?;
        connection
            .pragma_update(None, "journal_size_limit", maximum_database_bytes)
            .map_err(|error| sql_error("bound preparation WAL", error))?;
    } else {
        connection
            .pragma_update(None, "query_only", true)
            .map_err(|error| sql_error("require read-only preparation queries", error))?;
    }
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| sql_error("verify preparation WAL mode", error))?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| sql_error("verify preparation synchronous mode", error))?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|error| sql_error("verify preparation trusted-schema mode", error))?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| sql_error("read preparation page size", error))?;
    let pages: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|error| sql_error("read preparation page count", error))?;
    if !mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || trusted_schema != 0
        || page_size != 4096
        || pages < 0
        || (pages as u128) * 4096 > maximum_database_bytes as u128
    {
        return Err(EpochPreparationStoreErrorV1::SchemaMismatch);
    }
    enable_persistent_wal(connection)
}

fn enable_persistent_wal(connection: &Connection) -> StoreResult<()> {
    let mut enabled = 1i32;
    // SAFETY: `main` is a static NUL-terminated name and this opcode expects
    // an int pointer valid for the duration of the call on the live handle.
    let code = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut enabled as *mut i32).cast(),
        )
    };
    if code != rusqlite::ffi::SQLITE_OK || enabled != 1 {
        return Err(EpochPreparationStoreErrorV1::InvalidRecord(
            "persistent WAL was not accepted",
        ));
    }
    Ok(())
}

fn pin_namespace(path: &Path) -> StoreResult<(PathBuf, PinnedFileV1)> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_error("read current directory", error))?
            .join(path)
    };
    if absolute
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(EpochPreparationStoreErrorV1::InvalidNamespace(
            "parent traversal is unsupported",
        ));
    }
    let name = absolute
        .file_name()
        .ok_or(EpochPreparationStoreErrorV1::InvalidNamespace(
            "missing database name",
        ))?;
    let lower = name.to_string_lossy().to_ascii_lowercase();
    if ["-wal", "-shm", "-journal", ".epoch.lock"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return Err(EpochPreparationStoreErrorV1::InvalidNamespace(
            "database name collides with a sidecar",
        ));
    }
    let parent = absolute
        .parent()
        .ok_or(EpochPreparationStoreErrorV1::InvalidNamespace(
            "missing database parent",
        ))?;
    validate_ancestors(parent)?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| io_error("canonicalize private directory", error))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC);
    }
    let file = options
        .open(&canonical_parent)
        .map_err(|error| io_error("pin private directory", error))?;
    let directory = PinnedFileV1::new(canonical_parent.clone(), file, true, 0)?;
    Ok((canonical_parent.join(name), directory))
}

fn validate_ancestors(parent: &Path) -> StoreResult<()> {
    for (index, ancestor) in parent.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| io_error("inspect private namespace ancestor", error))?;
        if !metadata.file_type().is_dir() {
            return Err(EpochPreparationStoreErrorV1::InvalidNamespace(
                "directory symlinks and non-directories are forbidden",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid takes no pointers and has no caller obligations.
            let uid = unsafe { libc::geteuid() };
            if index == 0 && (metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700) {
                return Err(EpochPreparationStoreErrorV1::InvalidNamespace(
                    "database parent must be owned by this user with mode 0700",
                ));
            }
            let trusted_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if metadata.mode() & 0o022 != 0 && !trusted_sticky {
                return Err(EpochPreparationStoreErrorV1::InvalidNamespace(
                    "an ancestor permits peer namespace replacement",
                ));
            }
        }
    }
    Ok(())
}

fn checked_identity(
    metadata: &fs::Metadata,
    is_directory: bool,
    maximum_bytes: u64,
) -> StoreResult<FileIdentityV1> {
    if (is_directory && !metadata.file_type().is_dir())
        || (!is_directory && !metadata.file_type().is_file())
    {
        return Err(EpochPreparationStoreErrorV1::FileIdentityChanged);
    }
    if !is_directory && metadata.len() > maximum_bytes {
        return Err(EpochPreparationStoreErrorV1::ResourceLimit);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid takes no pointers and has no caller obligations.
        let uid = unsafe { libc::geteuid() };
        let mode = if is_directory { 0o700 } else { 0o600 };
        if metadata.uid() != uid
            || metadata.mode() & 0o7777 != mode
            || (!is_directory && metadata.nlink() != 1)
        {
            return Err(EpochPreparationStoreErrorV1::InvalidNamespace(
                "private ownership, mode, or hard-link count differs",
            ));
        }
        Ok(FileIdentityV1 {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Err(EpochPreparationStoreErrorV1::UnsupportedPlatform)
    }
}

fn private_file(path: &Path, create_new: bool) -> StoreResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create_new).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            EpochPreparationStoreErrorV1::AlreadyExists
        } else if error.kind() == io::ErrorKind::NotFound {
            EpochPreparationStoreErrorV1::Missing("required private file")
        } else {
            io_error("open private preparation file", error)
        }
    })
}

fn pin_existing(path: &Path, maximum_bytes: u64) -> StoreResult<PinnedFileV1> {
    let file = private_file(path, false)?;
    PinnedFileV1::new(path.to_path_buf(), file, false, maximum_bytes)
}

fn lock_exclusive(file: &File) -> StoreResult<()> {
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            EpochPreparationStoreErrorV1::Locked
        } else {
            io_error("acquire lifetime preparation lock", error)
        }
    })
}

fn require_lock_binding(lock: &PinnedFileV1, binding: [u8; 32]) -> StoreResult<()> {
    if lock
        .file
        .metadata()
        .map_err(|error| io_error("stat preparation lock", error))?
        .len()
        != LOCK_BYTES_V1
    {
        return Err(EpochPreparationStoreErrorV1::InvalidRecord(
            "lock binding length differs",
        ));
    }
    let mut bytes = [0u8; LOCK_BYTES_V1 as usize];
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        lock.file
            .read_exact_at(&mut bytes, 0)
            .map_err(|error| io_error("read preparation lock binding", error))?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Read;
        let mut handle = &lock.file;
        handle
            .read_exact(&mut bytes)
            .map_err(|error| io_error("read preparation lock binding", error))?;
    }
    if &bytes[..8] != LOCK_MAGIC_V1 || bytes[8..] != binding {
        return Err(EpochPreparationStoreErrorV1::InvalidRecord(
            "lock names a different preparation",
        ));
    }
    Ok(())
}

fn auxiliary_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn require_absent(path: &Path) -> StoreResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(EpochPreparationStoreErrorV1::AlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect exclusive namespace", error)),
    }
}

fn require_linux() -> StoreResult<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(EpochPreparationStoreErrorV1::UnsupportedPlatform)
    }
}

fn io_error(stage: &'static str, error: io::Error) -> EpochPreparationStoreErrorV1 {
    EpochPreparationStoreErrorV1::Io { stage, error }
}

fn sql_error(stage: &'static str, error: rusqlite::Error) -> EpochPreparationStoreErrorV1 {
    EpochPreparationStoreErrorV1::Sqlite { stage, error }
}
