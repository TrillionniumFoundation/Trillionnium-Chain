use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, TryLockError,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Context, Result};
use jmt::{
    storage::{HasPreimage, LeafNode, NibblePath, Node, NodeKey, TreeReader},
    JellyfishMerkleIterator, KeyHash, RootHash, ValueHash, Version,
};
use rusqlite::{
    backup::Backup, limits::Limit, params, Connection, OpenFlags, OptionalExtension, Transaction,
    TransactionBehavior,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    auth_tree::{
        authenticated_key_hash, plan_put_value_set, prove_with_reader, stored_object_key,
        stored_object_key_preimage, validator_state_key, verify_ics23_membership,
        verify_ics23_non_membership, AuthProof, AuthWrite, AuthenticatedObjectRecord,
        InMemoryAuthTree, PlannedAuthUpdate, PruneStats,
    },
    persist_state_bytes, AppState, PendingBlock, StoredObject, ValidatorLifecycleStateV1,
    APP_VERSION, MAX_SNAPSHOT_CHUNKS, SNAPSHOT_CHUNK_SIZE, VALIDATOR_LIFECYCLE_SCHEMA_V1,
};

const STORE_SCHEMA_VERSION: &str = "4";
const PREVIOUS_STORE_SCHEMA_VERSION: &str = "3";
const STATUS_SCHEMA_V2: &str = "trnm_cometbft_app_status_v2";
const AUTH_QUERY_FLOOR_KEY: &str = "auth_query_floor";
const AUTH_PRUNE_TARGET_KEY: &str = "auth_prune_target";
const AUTH_PRUNE_BATCH_MAX_DURATION: Duration = Duration::from_millis(10);
const MAX_SNAPSHOT_AUTH_NODE_BYTES: u64 = 64 * 1024;
const MAX_SNAPSHOT_AUTH_VALUE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_KEY_PREIMAGE_BYTES: u64 = 1024 * 1024;
const MAX_SNAPSHOT_OBJECT_VALUE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_LIFECYCLE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SNAPSHOT_IDENTIFIER_BYTES: u64 = 4096;
const MAX_SNAPSHOT_SQLITE_VALUE_BYTES: i32 = 20 * 1024 * 1024;
const SNAPSHOT_SQLITE_PAGE_SIZE_BYTES: u64 = 4096;
const MAX_SNAPSHOT_DATABASE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_SNAPSHOT_DATABASE_PAGES: u64 =
    MAX_SNAPSHOT_DATABASE_BYTES / SNAPSHOT_SQLITE_PAGE_SIZE_BYTES;
const MAX_SNAPSHOT_SCRATCH_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SNAPSHOT_SCRATCH_PAGES: u64 =
    MAX_SNAPSHOT_SCRATCH_BYTES / SNAPSHOT_SQLITE_PAGE_SIZE_BYTES;
const MAX_SNAPSHOT_OBJECT_ROWS: u64 = 1_100_000;
const MAX_SNAPSHOT_AUTH_VALUE_ROWS: u64 = MAX_SNAPSHOT_OBJECT_ROWS + 1;
const MAX_SNAPSHOT_AUTH_NODE_ROWS: u64 = 2_000_000;
const MAX_SNAPSHOT_VALIDATION_COPY_BYTES: u64 =
    MAX_SNAPSHOT_CHUNKS as u64 * SNAPSHOT_CHUNK_SIZE as u64;
const JMT_PLACEHOLDER_HASH: [u8; 32] = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";
static SNAPSHOT_VALIDATION_NONCE: AtomicU64 = AtomicU64::new(0);
const STORE_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS objects (
        object_key_hex TEXT PRIMARY KEY NOT NULL,
        object_type TEXT NOT NULL,
        version TEXT NOT NULL,
        value_hash_hex TEXT NOT NULL,
        value_bytes BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS command_ids (
        command_id TEXT PRIMARY KEY NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS signer_nonces (
        signer_id TEXT NOT NULL,
        nonce BLOB NOT NULL CHECK(length(nonce)=8),
        PRIMARY KEY (signer_id, nonce)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS validator_lifecycle (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        state_json BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_nodes (
        node_key BLOB PRIMARY KEY NOT NULL,
        node BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_values (
        key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
        version_be BLOB NOT NULL CHECK(length(version_be)=8),
        value BLOB,
        is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0,1)),
        PRIMARY KEY (key_hash, version_be)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_preimages (
        key_hash BLOB PRIMARY KEY NOT NULL CHECK(length(key_hash)=32),
        key_preimage BLOB NOT NULL CHECK(length(key_preimage)>0)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_stale_nodes (
        stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
        node_key BLOB NOT NULL,
        PRIMARY KEY (stale_since_version_be, node_key)
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS auth_stale_nodes_by_node_key
        ON auth_stale_nodes(node_key);
    CREATE TABLE IF NOT EXISTS auth_stale_values (
        stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
        key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
        version_be BLOB NOT NULL CHECK(length(version_be)=8),
        PRIMARY KEY (stale_since_version_be, key_hash, version_be),
        UNIQUE (key_hash, version_be)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_roots (
        version_be BLOB PRIMARY KEY NOT NULL CHECK(length(version_be)=8),
        root_hash BLOB NOT NULL CHECK(length(root_hash)=32)
    ) STRICT;
";

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoreFailpoint {
    BeforeSqlCommit,
    AfterSqlCommitBeforeStatus,
}

#[derive(Debug, Clone)]
pub(super) struct ApplicationStore {
    status_path: PathBuf,
    database_path: PathBuf,
    chain_id: String,
    signer_policy_hash_hex: String,
    writer_gate: Arc<Mutex<()>>,
    writer_waiters: Arc<AtomicUsize>,
    maintenance_gate: Arc<Mutex<()>>,
    active_snapshot_pins: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "scale-gate"))]
    prune_writer_collision_hook: Arc<AtomicUsize>,
}

pub(super) struct PinnedSnapshot {
    source: Option<Connection>,
    active_snapshot_pins: Arc<AtomicUsize>,
}

struct SnapshotValidationScratch {
    connection: Option<Connection>,
    path: PathBuf,
}

#[derive(Debug)]
struct SnapshotValidationCopy {
    file: Option<fs::File>,
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SnapshotRowCounts {
    metadata: u64,
    objects: u64,
    command_ids: u64,
    signer_nonces: u64,
    validator_lifecycle: u64,
    auth_nodes: u64,
    auth_values: u64,
    auth_preimages: u64,
    auth_stale_nodes: u64,
    auth_stale_values: u64,
    auth_roots: u64,
}

#[derive(Debug)]
pub(super) struct ValidatedSnapshotDatabase {
    source: Connection,
    state: AppState,
    schema_version: String,
    _owned_copy: SnapshotValidationCopy,
}

impl ValidatedSnapshotDatabase {
    pub(super) fn state(&self) -> &AppState {
        &self.state
    }

    pub(super) fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn into_state(self) -> Result<AppState> {
        self.source.execute_batch("ROLLBACK")?;
        Ok(self.state)
    }
}

impl SnapshotValidationScratch {
    fn open(snapshot_path: &Path) -> Result<Self> {
        let parent = snapshot_path
            .parent()
            .context("SQLite snapshot validation path has no parent")?;
        let file_name = snapshot_path
            .file_name()
            .and_then(|value| value.to_str())
            .context("SQLite snapshot validation path is not UTF-8")?;
        let nonce = SNAPSHOT_VALIDATION_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".{file_name}.validate-{}-{nonce}.sqlite3",
            std::process::id()
        ));
        remove_file_if_exists(&path)?;
        remove_sqlite_sidecars(&path)?;
        let connection = Connection::open(&path).with_context(|| {
            format!("create SQLite snapshot validation index {}", path.display())
        })?;
        connection.pragma_update(None, "page_size", SNAPSHOT_SQLITE_PAGE_SIZE_BYTES)?;
        connection.pragma_update(None, "max_page_count", MAX_SNAPSHOT_SCRATCH_PAGES)?;
        connection.execute_batch(
            "
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            PRAGMA temp_store=FILE;
            PRAGMA cache_size=-8192;
            PRAGMA mmap_size=0;
            PRAGMA trusted_schema=OFF;
            CREATE TABLE node_checks (
                node_key BLOB PRIMARY KEY NOT NULL,
                actual_hash BLOB,
                actual_kind INTEGER,
                actual_leaf_count INTEGER,
                expected_hash BLOB,
                expected_kind INTEGER,
                expected_leaf_count INTEGER,
                reference_count INTEGER NOT NULL DEFAULT 0
            ) STRICT, WITHOUT ROWID;
            CREATE TABLE leaf_checks (
                key_hash BLOB PRIMARY KEY NOT NULL,
                node_version_be BLOB,
                node_hash BLOB,
                value_version_be BLOB,
                value_hash BLOB,
                domain_hash BLOB,
                preimage_seen INTEGER NOT NULL DEFAULT 0
            ) STRICT, WITHOUT ROWID;
            ",
        )?;
        Ok(Self {
            connection: Some(connection),
            path,
        })
    }

    fn connection_mut(&mut self) -> Result<&mut Connection> {
        self.connection
            .as_mut()
            .context("SQLite snapshot validation index is closed")
    }
}

impl SnapshotValidationCopy {
    fn file(&self) -> Result<&fs::File> {
        self.file
            .as_ref()
            .context("private SQLite snapshot validation copy is closed")
    }

    fn sqlite_path(&self) -> Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            Ok(PathBuf::from(format!(
                "/proc/self/fd/{}",
                self.file()?.as_raw_fd()
            )))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(self.path.clone())
        }
    }
}

impl SnapshotRowCounts {
    fn validate(self) -> Result<()> {
        ensure!(
            self.metadata <= 9,
            "SQLite snapshot metadata row count exceeds the resource limit"
        );
        ensure!(
            self.objects <= MAX_SNAPSHOT_OBJECT_ROWS,
            "SQLite snapshot object row count exceeds the resource limit"
        );
        ensure!(
            self.auth_nodes <= MAX_SNAPSHOT_AUTH_NODE_ROWS,
            "SQLite snapshot authenticated node row count exceeds the resource limit"
        );
        ensure!(
            self.auth_values <= MAX_SNAPSHOT_AUTH_VALUE_ROWS,
            "SQLite snapshot authenticated value row count exceeds the resource limit"
        );
        ensure!(
            self.auth_preimages <= MAX_SNAPSHOT_AUTH_VALUE_ROWS,
            "SQLite snapshot authenticated preimage row count exceeds the resource limit"
        );
        ensure!(
            self.validator_lifecycle == 1 && self.auth_roots == 1,
            "SQLite snapshot must contain exactly one lifecycle and authenticated root row"
        );
        ensure!(
            self.command_ids == 0
                && self.signer_nonces == 0
                && self.auth_stale_nodes == 0
                && self.auth_stale_values == 0,
            "SQLite snapshot contains replay-cache or stale-history rows"
        );
        Ok(())
    }
}

impl Drop for SnapshotValidationScratch {
    fn drop(&mut self) {
        drop(self.connection.take());
        let _ = remove_sqlite_sidecars(&self.path);
        let _ = remove_file_if_exists(&self.path);
    }
}

impl Drop for SnapshotValidationCopy {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = remove_sqlite_sidecars(&self.path);
        let _ = remove_file_if_exists(&sqlite_sidecar(&self.path, "-journal"));
        let _ = remove_file_if_exists(&self.path);
    }
}

impl PinnedSnapshot {
    fn source(&self) -> Result<&Connection> {
        self.source
            .as_ref()
            .context("pinned snapshot source was already released")
    }

    fn release(&mut self) -> Result<()> {
        let Some(source) = self.source.take() else {
            return Ok(());
        };
        let rollback = source.execute_batch("ROLLBACK");
        drop(source);
        self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        rollback?;
        Ok(())
    }
}

impl Drop for PinnedSnapshot {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            let _ = source.execute_batch("ROLLBACK");
            drop(source);
            self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PruneBatchOutcome {
    pub(super) stats: PruneStats,
    pub(super) query_floor: Version,
    pub(super) target: Version,
    pub(super) complete: bool,
    pub(super) rows_examined: usize,
    pub(super) logical_bytes_examined: u64,
    pub(super) elapsed: Duration,
    pub(super) yielded_to_writer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PruneSkipReason {
    MaintenanceBusy,
    SnapshotPinned,
    WriterWaiting,
    WriterBusy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PruneBatchAttempt {
    Skipped(PruneSkipReason),
    Completed(PruneBatchOutcome),
}

#[cfg(any(test, feature = "scale-gate"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AuthPruneStatus {
    pub(super) query_floor: Version,
    pub(super) target: Option<Version>,
}

#[derive(Serialize)]
struct PersistedStatusV2 {
    schema: &'static str,
    app_version: u64,
    height: u64,
    app_hash_hex: String,
}

struct SqliteAuthReader<'a> {
    connection: &'a Connection,
}

impl TreeReader for SqliteAuthReader<'_> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let encoded_key = borsh::to_vec(node_key).context("encode JMT node key")?;
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT node FROM auth_nodes WHERE node_key=?1",
                params![encoded_key],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|bytes| borsh::from_slice(&bytes).context("decode persisted JMT node"))
            .transpose()
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        let row: Option<(Option<Vec<u8>>, i64)> = self
            .connection
            .query_row(
                "SELECT value, is_deleted
                 FROM auth_values
                 WHERE key_hash=?1 AND version_be<=?2
                 ORDER BY version_be DESC
                 LIMIT 1",
                params![key_hash.0.as_slice(), max_version.to_be_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            None | Some((None, 1)) => Ok(None),
            Some((Some(value), 0)) => Ok(Some(value)),
            Some(_) => Err(anyhow!("persisted JMT value tombstone mismatch")),
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut statement = self
            .connection
            .prepare("SELECT node_key, node FROM auth_nodes")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut rightmost: Option<(NodeKey, LeafNode)> = None;
        for row in rows {
            let (node_key, node) = row?;
            let node_key: NodeKey =
                borsh::from_slice(&node_key).context("decode persisted JMT node key")?;
            let node: Node = borsh::from_slice(&node).context("decode persisted JMT node")?;
            let Node::Leaf(leaf) = node else {
                continue;
            };
            if rightmost.as_ref().is_none_or(|(best_key, best_leaf)| {
                (leaf.key_hash(), node_key.version()) > (best_leaf.key_hash(), best_key.version())
            }) {
                rightmost = Some((node_key, leaf));
            }
        }
        Ok(rightmost)
    }
}

impl HasPreimage for SqliteAuthReader<'_> {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .connection
            .query_row(
                "SELECT key_preimage FROM auth_preimages WHERE key_hash=?1",
                params![key_hash.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?)
    }
}

impl ApplicationStore {
    fn lock_writer(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.writer_waiters.fetch_add(1, Ordering::AcqRel);
        #[cfg(any(test, feature = "scale-gate"))]
        let _ = self.prune_writer_collision_hook.compare_exchange(
            2,
            3,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let locked = self.writer_gate.lock();
        self.writer_waiters.fetch_sub(1, Ordering::AcqRel);
        locked.map_err(|_| anyhow!("application store writer gate poisoned"))
    }

    pub(super) fn open(
        status_path: &Path,
        chain_id: &str,
        signer_policy_hash_hex: &str,
    ) -> Result<Self> {
        let extension = status_path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}.sqlite3"))
            .unwrap_or_else(|| "sqlite3".to_string());
        let store = Self {
            status_path: status_path.to_path_buf(),
            database_path: status_path.with_extension(extension),
            chain_id: chain_id.to_string(),
            signer_policy_hash_hex: signer_policy_hash_hex.to_string(),
            writer_gate: Arc::new(Mutex::new(())),
            writer_waiters: Arc::new(AtomicUsize::new(0)),
            maintenance_gate: Arc::new(Mutex::new(())),
            active_snapshot_pins: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "scale-gate"))]
            prune_writer_collision_hook: Arc::new(AtomicUsize::new(0)),
        };
        Ok(store)
    }

    pub(super) fn load_or_migrate(&self) -> Result<AppState> {
        if !self.database_path.exists() && self.status_path.exists() {
            return Err(anyhow!(
                "existing pre-v4 state requires the explicit export/new-genesis migration tool"
            ));
        }
        if self.database_path.exists() {
            self.probe_existing_database()?;
        }
        let connection = self.connect()?;
        if self.has_committed_state(&connection)? {
            let state = load_sqlite_state(&connection)?;
            self.refresh_status_best_effort(&state);
            return Ok(state);
        }
        drop(connection);

        if !self.status_path.exists() {
            return Ok(AppState::default());
        }
        Err(anyhow!(
            "existing pre-v4 state requires the explicit export/new-genesis migration tool"
        ))
    }

    pub(super) fn load_object(&self, object_key_hex: &str) -> Result<Option<StoredObject>> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let height = metadata(&connection, "height")?
            .parse::<u64>()
            .context("parse application store height")?;
        let root_hash = auth_root(&connection, height)?
            .with_context(|| format!("missing authenticated root at version {height}"))?;
        let object = load_object(&connection, object_key_hex)?;
        let key = stored_object_key(object_key_hex)?;
        let reader = SqliteAuthReader {
            connection: &connection,
        };
        let proof = prove_with_reader(&reader, height, root_hash, key)?;
        match &object {
            Some(object) => {
                let expected = AuthenticatedObjectRecord::new(
                    object.object_type.clone(),
                    object.version,
                    object.value_bytes.clone(),
                )?
                .encode()?;
                ensure!(
                    proof.value.as_deref() == Some(expected.as_slice())
                        && verify_ics23_membership(&proof, &expected),
                    "application store object differs from authenticated state"
                );
            }
            None => ensure!(
                proof.value.is_none() && verify_ics23_non_membership(&proof),
                "application store is missing an authenticated object"
            ),
        }
        connection.execute_batch("ROLLBACK")?;
        Ok(object)
    }

    #[cfg(test)]
    pub(super) fn contains_command_id(&self, command_id: &str) -> Result<bool> {
        let connection = self.connect_read()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM command_ids WHERE command_id=?1",
                params![command_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    #[cfg(test)]
    pub(super) fn contains_signer_nonce(&self, signer_id: &str, nonce: u64) -> Result<bool> {
        let connection = self.connect_read()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM signer_nonces WHERE signer_id=?1 AND nonce=?2",
                params![signer_id, nonce.to_be_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub(super) fn plan_auth_update(
        &self,
        version: Version,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> Result<PlannedAuthUpdate> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let expected_next_version = latest_auth_version(&connection)?.map_or(0, |value| value + 1);
        let reader = SqliteAuthReader {
            connection: &connection,
        };
        let update = plan_put_value_set(&reader, expected_next_version, version, writes)?;
        connection.execute_batch("ROLLBACK")?;
        Ok(update)
    }

    pub(super) fn prove(&self, version: Version, key: Vec<u8>) -> Result<AuthProof> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let query_floor = optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
            .or(oldest_auth_version(&connection)?)
            .unwrap_or(0);
        ensure!(
            version >= query_floor,
            "authenticated version {version} was pruned; retained query floor is {query_floor}"
        );
        let root_hash = auth_root(&connection, version)?
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let reader = SqliteAuthReader {
            connection: &connection,
        };
        let proof = prove_with_reader(&reader, version, root_hash, key)?;
        let valid = match proof.value.as_deref() {
            Some(value) => verify_ics23_membership(&proof, value),
            None => verify_ics23_non_membership(&proof),
        };
        ensure!(valid, "persisted authenticated proof failed verification");
        connection.execute_batch("ROLLBACK")?;
        Ok(proof)
    }

    /// Removes authenticated roots, stale nodes, and superseded values below
    /// the durable query floor using one writer-budgeted transaction.
    ///
    /// A `None` result means the consensus writer currently owns the shared
    /// gate. Callers must yield and retry; they must never wait in front of a
    /// Commit. Preimages remain one-per-distinct-key in the live database;
    /// latest-only snapshot compaction removes dead-key preimages.
    pub(super) fn try_prune_auth_batch(
        &self,
        max_rows: usize,
        max_logical_bytes: u64,
    ) -> Result<Option<PruneBatchOutcome>> {
        Ok(
            match self.try_prune_auth_batch_detailed(max_rows, max_logical_bytes)? {
                PruneBatchAttempt::Skipped(_) => None,
                PruneBatchAttempt::Completed(outcome) => Some(outcome),
            },
        )
    }

    pub(super) fn try_prune_auth_batch_detailed(
        &self,
        max_rows: usize,
        max_logical_bytes: u64,
    ) -> Result<PruneBatchAttempt> {
        ensure!(max_rows > 0, "authenticated prune batch must allow a row");
        ensure!(
            max_logical_bytes > 0,
            "authenticated prune batch must allow logical bytes"
        );
        let _maintenance = match self.maintenance_gate.try_lock() {
            Ok(maintenance) => maintenance,
            Err(TryLockError::WouldBlock) => {
                return Ok(PruneBatchAttempt::Skipped(PruneSkipReason::MaintenanceBusy));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store maintenance gate poisoned"));
            }
        };
        if self.active_snapshot_pins.load(Ordering::Acquire) > 0 {
            return Ok(PruneBatchAttempt::Skipped(PruneSkipReason::SnapshotPinned));
        }
        if self.writer_waiters.load(Ordering::Acquire) > 0 {
            return Ok(PruneBatchAttempt::Skipped(PruneSkipReason::WriterWaiting));
        }
        let _writer = match self.writer_gate.try_lock() {
            Ok(writer) => writer,
            Err(TryLockError::WouldBlock) => {
                return Ok(PruneBatchAttempt::Skipped(PruneSkipReason::WriterBusy));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store writer gate poisoned"));
            }
        };
        if self.writer_waiters.load(Ordering::Acquire) > 0 {
            return Ok(PruneBatchAttempt::Skipped(PruneSkipReason::WriterWaiting));
        }
        let started = Instant::now();
        let mut connection = self.connect_maintenance()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let query_floor = optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
            .context("application store is missing authenticated query floor")?;
        let Some(target) = optional_metadata_version(&transaction, AUTH_PRUNE_TARGET_KEY)? else {
            transaction.rollback()?;
            return Ok(PruneBatchAttempt::Completed(PruneBatchOutcome {
                stats: PruneStats::default(),
                query_floor,
                target: query_floor,
                complete: true,
                rows_examined: 0,
                logical_bytes_examined: 0,
                elapsed: started.elapsed(),
                yielded_to_writer: false,
            }));
        };
        let height = metadata(&transaction, "height")?
            .parse::<u64>()
            .context("parse application store height during authenticated pruning")?;
        let app_hash = trnm_finality_types::decode_hash32(
            "application store app_hash",
            &metadata(&transaction, "app_hash_hex")?,
        )?;
        ensure!(
            target <= query_floor && query_floor <= height,
            "authenticated prune control exceeds the committed head"
        );
        ensure!(
            auth_root(&transaction, target)?.is_some(),
            "authenticated prune boundary root is absent"
        );
        #[cfg(any(test, feature = "scale-gate"))]
        self.coordinate_prune_writer_collision()?;

        let target_be = target.to_be_bytes();
        let mut stats = PruneStats::default();
        let mut rows_examined = 0_usize;
        let mut logical_bytes_examined = 0_u64;
        let mut yielded_to_writer = false;

        // Row/byte/time budgets are progress-preserving soft limits: an
        // otherwise valid first row is processed even when it alone crosses a
        // configured threshold, and every later row is bounded normally.

        // Stale nodes are validated and removed before historical roots.  The
        // root at `stale_since_version` is therefore still available as a
        // witness that the candidate was actually retired by that version.
        // JMT node keys are immutable and retired nodes are never resurrected.
        let stale_rows = {
            let mut statement = transaction.prepare(
                "SELECT stale.stale_since_version_be,
                        stale.node_key,
                        nodes.node
                 FROM auth_stale_nodes AS stale
                 LEFT JOIN auth_nodes AS nodes ON nodes.node_key=stale.node_key
                 WHERE stale.stale_since_version_be<=?1
                 ORDER BY stale.stale_since_version_be, stale.node_key
                 LIMIT ?2",
            )?;
            let rows = statement.query_map(
                params![target_be.as_slice(), i64::try_from(max_rows)?],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (stale_since, encoded_key, encoded_node) in stale_rows {
            let Some(encoded_node) = encoded_node else {
                return Err(anyhow!(
                    "authenticated stale-node index points to an absent node"
                ));
            };
            let logical_bytes = u64::try_from(encoded_key.len())?
                .saturating_add(u64::try_from(encoded_node.len())?);
            if self.writer_waiters.load(Ordering::Acquire) > 0 {
                yielded_to_writer = true;
                break;
            }
            if rows_examined > 0
                && (logical_bytes_examined.saturating_add(logical_bytes) > max_logical_bytes
                    || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
            {
                break;
            }
            let stale_since_version = decode_version_be(&stale_since)?;
            let node_key: NodeKey = borsh::from_slice(&encoded_key)
                .context("decode authenticated stale JMT node key")?;
            let node: Node =
                borsh::from_slice(&encoded_node).context("decode authenticated stale JMT node")?;
            ensure!(
                borsh::to_vec(&node_key)? == encoded_key
                    && borsh::to_vec(&node)? == encoded_node
                    && node_key.version() < stale_since_version
                    && stale_since_version <= target,
                "authenticated stale-node index contains a non-canonical retirement"
            );
            ensure!(
                auth_root(&transaction, stale_since_version)?.is_some(),
                "authenticated stale-node retirement witness root is absent"
            );
            ensure!(
                !auth_node_reachable_at_version(&transaction, stale_since_version, &node_key,)?,
                "authenticated stale-node index points to a live retained node"
            );
            rows_examined = rows_examined.saturating_add(1);
            logical_bytes_examined = logical_bytes_examined.saturating_add(logical_bytes);
            let removed = transaction.execute(
                "DELETE FROM auth_nodes WHERE node_key=?1",
                params![encoded_key.as_slice()],
            )?;
            ensure!(
                removed == 1,
                "authenticated stale node disappeared during pruning"
            );
            stats.nodes_removed = stats.nodes_removed.saturating_add(removed);
            let index_removed = transaction.execute(
                "DELETE FROM auth_stale_nodes
                 WHERE stale_since_version_be=?1 AND node_key=?2",
                params![stale_since.as_slice(), encoded_key.as_slice()],
            )?;
            ensure!(
                index_removed == 1,
                "authenticated stale-node index disappeared during pruning"
            );
            stats.stale_indices_removed = stats.stale_indices_removed.saturating_add(index_removed);
        }

        let stale_nodes_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !stale_nodes_remain && rows_examined < max_rows {
            let remaining = max_rows.saturating_sub(rows_examined);
            let stale_values = {
                let mut statement = transaction.prepare(
                    "SELECT stale.stale_since_version_be,
                            stale.key_hash,
                            stale.version_be,
                            history.key_hash IS NOT NULL,
                            COALESCE(length(history.value), 0),
                            successor.key_hash IS NOT NULL,
                            NOT EXISTS (
                                SELECT 1
                                FROM auth_values AS intermediate
                                WHERE intermediate.key_hash=stale.key_hash
                                  AND intermediate.version_be>stale.version_be
                                  AND intermediate.version_be<stale.stale_since_version_be
                            )
                     FROM auth_stale_values AS stale
                     LEFT JOIN auth_values AS history
                       ON history.key_hash=stale.key_hash
                      AND history.version_be=stale.version_be
                     LEFT JOIN auth_values AS successor
                       ON successor.key_hash=stale.key_hash
                      AND successor.version_be=stale.stale_since_version_be
                     WHERE stale.stale_since_version_be<=?1
                     ORDER BY stale.stale_since_version_be,
                              stale.key_hash,
                              stale.version_be
                     LIMIT ?2",
                )?;
                let rows = statement.query_map(
                    params![target_be.as_slice(), i64::try_from(remaining)?],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, bool>(3)?,
                            row.get::<_, u64>(4)?,
                            row.get::<_, bool>(5)?,
                            row.get::<_, bool>(6)?,
                        ))
                    },
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (
                stale_since,
                key_hash,
                version_be,
                value_exists,
                value_length,
                successor_exists,
                successor_is_next,
            ) in stale_values
            {
                ensure!(
                    value_exists,
                    "authenticated stale-value index points to an absent value"
                );
                let stale_since_version = decode_version_be(&stale_since)?;
                let value_version = decode_version_be(&version_be)?;
                ensure!(
                    key_hash.len() == 32
                        && value_version < stale_since_version
                        && stale_since_version <= target
                        && successor_exists
                        && successor_is_next,
                    "authenticated stale-value index contains a non-canonical retirement"
                );
                let logical_bytes = value_length
                    .saturating_add(u64::try_from(key_hash.len())?)
                    .saturating_add(u64::try_from(version_be.len())?);
                if self.writer_waiters.load(Ordering::Acquire) > 0 {
                    yielded_to_writer = true;
                    break;
                }
                if rows_examined > 0
                    && (logical_bytes_examined.saturating_add(logical_bytes) > max_logical_bytes
                        || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
                {
                    break;
                }
                rows_examined = rows_examined.saturating_add(1);
                logical_bytes_examined = logical_bytes_examined.saturating_add(logical_bytes);
                let removed = transaction.execute(
                    "DELETE FROM auth_values
                     WHERE key_hash=?1 AND version_be=?2",
                    params![key_hash.as_slice(), version_be.as_slice()],
                )?;
                ensure!(
                    removed == 1,
                    "authenticated stale value disappeared during pruning"
                );
                stats.value_versions_removed = stats.value_versions_removed.saturating_add(removed);
                let index_removed = transaction.execute(
                    "DELETE FROM auth_stale_values
                     WHERE stale_since_version_be=?1
                       AND key_hash=?2
                       AND version_be=?3",
                    params![
                        stale_since.as_slice(),
                        key_hash.as_slice(),
                        version_be.as_slice(),
                    ],
                )?;
                ensure!(
                    index_removed == 1,
                    "authenticated stale-value index disappeared during pruning"
                );
                stats.stale_indices_removed =
                    stats.stale_indices_removed.saturating_add(index_removed);
            }
        }

        let stale_values_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_values
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !stale_nodes_remain
            && !stale_values_remain
            && rows_examined < max_rows
            && started.elapsed() < AUTH_PRUNE_BATCH_MAX_DURATION
        {
            let remaining = max_rows.saturating_sub(rows_examined);
            let root_versions = {
                let mut statement = transaction.prepare(
                    "SELECT version_be
                     FROM auth_roots
                     WHERE version_be<?1
                     ORDER BY version_be
                     LIMIT ?2",
                )?;
                let rows = statement.query_map(
                    params![target_be.as_slice(), i64::try_from(remaining)?],
                    |row| row.get::<_, Vec<u8>>(0),
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for encoded_version in root_versions {
                let version = decode_version_be(&encoded_version)?;
                let root_path: NibblePath = std::iter::empty().collect();
                let encoded_key = borsh::to_vec(&NodeKey::new(version, root_path))
                    .context("encode authenticated root node key during pruning")?;
                let node_bytes = transaction
                    .query_row(
                        "SELECT length(node) FROM auth_nodes WHERE node_key=?1",
                        params![encoded_key.as_slice()],
                        |row| row.get::<_, u64>(0),
                    )
                    .optional()?
                    .unwrap_or(0)
                    .saturating_add(u64::try_from(encoded_key.len())?);
                if self.writer_waiters.load(Ordering::Acquire) > 0 {
                    yielded_to_writer = true;
                    break;
                }
                if rows_examined > 0
                    && (logical_bytes_examined.saturating_add(node_bytes) > max_logical_bytes
                        || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
                {
                    break;
                }
                rows_examined = rows_examined.saturating_add(1);
                logical_bytes_examined = logical_bytes_examined.saturating_add(node_bytes);
                stats.nodes_removed = stats.nodes_removed.saturating_add(transaction.execute(
                    "DELETE FROM auth_nodes WHERE node_key=?1",
                    params![encoded_key.as_slice()],
                )?);
                stats.roots_removed = stats.roots_removed.saturating_add(transaction.execute(
                    "DELETE FROM auth_roots WHERE version_be=?1",
                    params![encoded_version],
                )?);
            }
        }

        let old_roots_remain = transaction
            .query_row(
                "SELECT 1 FROM auth_roots WHERE version_be<?1 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let stale_nodes_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let stale_values_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_values
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let complete = !old_roots_remain && !stale_nodes_remain && !stale_values_remain;
        if complete {
            verify_retained_lifecycle_proofs(&transaction, height, app_hash, target)?;
            transaction.execute(
                "DELETE FROM metadata WHERE key=?1",
                params![AUTH_PRUNE_TARGET_KEY],
            )?;
        }
        transaction.commit()?;
        Ok(PruneBatchAttempt::Completed(PruneBatchOutcome {
            stats,
            query_floor,
            target,
            complete,
            rows_examined,
            logical_bytes_examined,
            elapsed: started.elapsed(),
            yielded_to_writer,
        }))
    }

    #[cfg(any(test, feature = "scale-gate"))]
    pub(super) fn request_auth_prune(
        &self,
        retain_from_version: Version,
    ) -> Result<AuthPruneStatus> {
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let height = metadata(&transaction, "height")?
            .parse::<u64>()
            .context("parse application store height during prune request")?;
        ensure!(
            retain_from_version <= height,
            "cannot request a future authenticated query floor"
        );
        ensure!(
            auth_root(&transaction, retain_from_version)?.is_some(),
            "requested authenticated query floor has no root"
        );
        advance_auth_query_floor(&transaction, retain_from_version)?;
        let status = AuthPruneStatus {
            query_floor: optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
                .context("application store is missing authenticated query floor")?,
            target: optional_metadata_version(&transaction, AUTH_PRUNE_TARGET_KEY)?,
        };
        transaction.commit()?;
        Ok(status)
    }

    #[cfg(any(test, feature = "scale-gate"))]
    pub(super) fn auth_prune_status(&self) -> Result<AuthPruneStatus> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let status = AuthPruneStatus {
            query_floor: optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
                .context("application store is missing authenticated query floor")?,
            target: optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?,
        };
        connection.execute_batch("ROLLBACK")?;
        Ok(status)
    }

    #[cfg(any(test, feature = "scale-gate"))]
    pub(super) fn arm_prune_writer_collision(&self) -> Result<()> {
        self.prune_writer_collision_hook
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|state| anyhow!("prune writer collision hook is already in state {state}"))?;
        Ok(())
    }

    #[cfg(any(test, feature = "scale-gate"))]
    pub(super) fn wait_for_prune_writer_collision(&self) -> Result<()> {
        let started = Instant::now();
        loop {
            match self.prune_writer_collision_hook.load(Ordering::Acquire) {
                2 => return Ok(()),
                0 => {
                    return Err(anyhow!(
                        "prune writer collision hook disarmed before maintenance arrived"
                    ));
                }
                1 => {}
                state => return Err(anyhow!("invalid prune writer collision state {state}")),
            }
            ensure!(
                started.elapsed() < Duration::from_secs(5),
                "timed out waiting for maintenance to enter the prune writer collision hook"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[cfg(any(test, feature = "scale-gate"))]
    fn coordinate_prune_writer_collision(&self) -> Result<()> {
        if self
            .prune_writer_collision_hook
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        let started = Instant::now();
        while self.prune_writer_collision_hook.load(Ordering::Acquire) != 3
            || self.writer_waiters.load(Ordering::Acquire) == 0
        {
            if started.elapsed() >= Duration::from_secs(5) {
                self.prune_writer_collision_hook.store(0, Ordering::Release);
                return Err(anyhow!(
                    "timed out waiting for a designated consensus writer at the prune collision hook"
                ));
            }
            std::thread::yield_now();
        }
        self.prune_writer_collision_hook.store(0, Ordering::Release);
        Ok(())
    }

    pub(super) fn has_pending_auth_prune(&self) -> Result<bool> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let pending = optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?.is_some();
        connection.execute_batch("ROLLBACK")?;
        Ok(pending)
    }

    pub(super) fn prune_auth_versions_before(
        &self,
        state: &AppState,
        retain_from_version: Version,
    ) -> Result<PruneStats> {
        ensure!(
            state.pending.is_none(),
            "cannot prune authenticated history while a block is pending"
        );
        ensure!(
            retain_from_version <= state.height,
            "cannot retain a future authenticated version"
        );
        let _maintenance = self
            .maintenance_gate
            .lock()
            .map_err(|_| anyhow!("application store maintenance gate poisoned"))?;
        ensure!(
            self.active_snapshot_pins.load(Ordering::Acquire) == 0,
            "cannot run full authenticated pruning while a snapshot is pinned"
        );
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, state)?;
        ensure!(
            latest_auth_version(&transaction)? == Some(state.height),
            "authenticated tree head differs from application height"
        );
        let current_query_floor = optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
            .context("application store is missing authenticated query floor")?;
        ensure!(
            retain_from_version >= current_query_floor,
            "authenticated query floor cannot move backwards"
        );

        transaction.execute_batch(
            "
            CREATE TEMP TABLE trnm_prune_nodes (
                node_key BLOB PRIMARY KEY NOT NULL
            ) WITHOUT ROWID;
            CREATE TEMP TABLE trnm_live_preimages (
                key_hash BLOB PRIMARY KEY NOT NULL CHECK(length(key_hash)=32)
            ) WITHOUT ROWID;
            ",
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO trnm_prune_nodes(node_key)
             SELECT node_key
             FROM auth_stale_nodes
             WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;

        {
            let mut statement = transaction.prepare(
                "SELECT version_be
                 FROM auth_roots
                 WHERE version_be<?1
                 ORDER BY version_be",
            )?;
            let rows = statement.query_map(
                params![retain_from_version.to_be_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )?;
            for row in rows {
                let version = decode_version_be(&row?)?;
                let root_path: NibblePath = std::iter::empty().collect();
                let encoded_key = borsh::to_vec(&NodeKey::new(version, root_path))
                    .context("encode historical JMT root node key during pruning")?;
                transaction.execute(
                    "INSERT OR IGNORE INTO trnm_prune_nodes(node_key) VALUES (?1)",
                    params![encoded_key],
                )?;
            }
        }

        let nodes_removed = transaction.execute(
            "DELETE FROM auth_nodes
             WHERE node_key IN (SELECT node_key FROM trnm_prune_nodes)",
            [],
        )?;
        let stale_node_indices_removed = transaction.execute(
            "DELETE FROM auth_stale_nodes WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        let roots_removed = transaction.execute(
            "DELETE FROM auth_roots WHERE version_be<?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        {
            let mut statement = transaction.prepare("SELECT node FROM auth_nodes")?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                let node: Node =
                    borsh::from_slice(&row?).context("decode retained JMT node during pruning")?;
                if let Node::Leaf(leaf) = node {
                    transaction.execute(
                        "INSERT OR IGNORE INTO trnm_live_preimages(key_hash) VALUES (?1)",
                        params![leaf.key_hash().0.as_slice()],
                    )?;
                }
            }
        }
        let value_versions_removed = transaction.execute(
            "DELETE FROM auth_values AS candidate
             WHERE EXISTS (
                 SELECT 1
                 FROM auth_stale_values AS stale
                 WHERE stale.stale_since_version_be<=?1
                   AND stale.key_hash=candidate.key_hash
                   AND stale.version_be=candidate.version_be
             )",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        let stale_value_indices_removed = transaction.execute(
            "DELETE FROM auth_stale_values WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        ensure!(
            value_versions_removed == stale_value_indices_removed,
            "authenticated stale-value index differs from value history"
        );
        let dead_value_versions_removed = if retain_from_version == state.height {
            transaction.execute(
                "DELETE FROM auth_values
                 WHERE key_hash NOT IN (SELECT key_hash FROM trnm_live_preimages)",
                [],
            )?
        } else {
            0
        };
        let preimages_removed = transaction.execute(
            "DELETE FROM auth_preimages
             WHERE key_hash NOT IN (SELECT key_hash FROM trnm_live_preimages)",
            [],
        )?;
        write_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY, retain_from_version)?;
        transaction.execute(
            "DELETE FROM metadata WHERE key=?1",
            params![AUTH_PRUNE_TARGET_KEY],
        )?;

        let retained_root = auth_root(&transaction, state.height)?
            .context("pruning removed the committed authenticated root")?;
        ensure!(
            <[u8; 32]>::from(retained_root) == state.app_hash,
            "authenticated pruning changed the committed AppHash"
        );
        let lifecycle_bytes: Vec<u8> = transaction.query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let reader = SqliteAuthReader {
            connection: &transaction,
        };
        let latest_proof =
            prove_with_reader(&reader, state.height, retained_root, validator_state_key()?)?;
        let latest_value = latest_proof
            .value
            .as_deref()
            .context("latest validator lifecycle proof is absent")?;
        let lifecycle_record = AuthenticatedObjectRecord::decode(latest_value)?;
        ensure!(
            lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
                && lifecycle_record.object_version <= state.height
                && lifecycle_record.value == lifecycle_bytes
                && verify_ics23_membership(&latest_proof, latest_value),
            "authenticated pruning damaged the latest validator lifecycle proof"
        );
        if retain_from_version < state.height {
            let boundary_root = auth_root(&transaction, retain_from_version)?
                .context("pruning removed the retention-boundary root")?;
            let boundary_proof = prove_with_reader(
                &reader,
                retain_from_version,
                boundary_root,
                validator_state_key()?,
            )?;
            let boundary_value = boundary_proof
                .value
                .as_deref()
                .context("retention-boundary lifecycle proof is absent")?;
            ensure!(
                verify_ics23_membership(&boundary_proof, boundary_value),
                "authenticated pruning damaged the retention-boundary proof"
            );
        }
        transaction.commit()?;
        Ok(PruneStats {
            nodes_removed,
            value_versions_removed: value_versions_removed
                .saturating_add(dead_value_versions_removed),
            preimages_removed,
            stale_indices_removed: stale_node_indices_removed
                .saturating_add(stale_value_indices_removed),
            roots_removed,
        })
    }

    pub(super) fn build_snapshot_database(
        &self,
        state: &AppState,
        destination: &Path,
        mut pinned: PinnedSnapshot,
    ) -> Result<AppState> {
        ensure!(
            state.height > 0 && state.pending.is_none(),
            "snapshot database requires committed non-genesis state"
        );
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create snapshot directory {}", parent.display()))?;
        }
        let temporary = destination.with_extension("snapshot.tmp");
        remove_file_if_exists(&temporary)?;
        remove_sqlite_sidecars(&temporary)?;

        let mut target = Connection::open(&temporary)
            .with_context(|| format!("create SQLite snapshot {}", temporary.display()))?;
        {
            let backup = Backup::new(pinned.source()?, &mut target)?;
            backup.run_to_completion(256, Duration::from_millis(2), None)?;
        }
        drop(target);
        pinned.release()?;

        let snapshot_store = self.with_database_path(temporary.clone());
        snapshot_store.prune_auth_versions_before(state, state.height)?;
        {
            let connection = Connection::open(&temporary)?;
            connection.execute_batch(
                "
                -- These legacy replay-cache tables are not part of AppHash v4
                -- and release execution never populates them.  A public
                -- snapshot must not let an untrusted sender inject entries
                -- that make otherwise valid commands appear spent.
                DELETE FROM command_ids;
                DELETE FROM signer_nonces;
                PRAGMA wal_checkpoint(TRUNCATE);
                PRAGMA journal_mode=DELETE;
                PRAGMA page_size=4096;
                VACUUM;
                ",
            )?;
        }
        remove_sqlite_sidecars(&temporary)?;
        let validated =
            snapshot_store.validate_snapshot_database(&temporary, state.height, state.app_hash)?;
        let validated = validated.into_state()?;
        fs::File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, destination).with_context(|| {
            format!(
                "install completed snapshot {} from {}",
                destination.display(),
                temporary.display()
            )
        })?;
        sync_parent(destination)?;
        Ok(validated)
    }

    pub(super) fn pin_snapshot(&self, state: &AppState) -> Result<PinnedSnapshot> {
        ensure!(
            state.height > 0 && state.pending.is_none(),
            "snapshot pin requires committed non-genesis state"
        );
        let _maintenance = match self.maintenance_gate.try_lock() {
            Ok(maintenance) => maintenance,
            Err(TryLockError::WouldBlock) => {
                return Err(anyhow!(
                    "application store maintenance is busy; defer optional snapshot pin"
                ));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store maintenance gate poisoned"));
            }
        };
        let source = self.connect_read()?;
        source.execute_batch("BEGIN DEFERRED")?;
        let pinned_height = metadata(&source, "height")?
            .parse::<u64>()
            .context("parse pinned snapshot height")?;
        let pinned_hash = trnm_finality_types::decode_hash32(
            "pinned snapshot app_hash",
            &metadata(&source, "app_hash_hex")?,
        )?;
        ensure!(
            (pinned_height, pinned_hash) == (state.height, state.app_hash),
            "application store head differs from requested snapshot"
        );
        self.active_snapshot_pins.fetch_add(1, Ordering::AcqRel);
        Ok(PinnedSnapshot {
            source: Some(source),
            active_snapshot_pins: Arc::clone(&self.active_snapshot_pins),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn install_snapshot_database(
        &self,
        expected: &AppState,
        source_path: &Path,
        expected_height: u64,
        expected_app_hash: [u8; 32],
    ) -> Result<AppState> {
        let validated =
            self.validate_snapshot_database(source_path, expected_height, expected_app_hash)?;
        self.install_validated_snapshot_database(expected, validated)
    }

    pub(super) fn install_validated_snapshot_database(
        &self,
        expected: &AppState,
        validated: ValidatedSnapshotDatabase,
    ) -> Result<AppState> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "snapshot install requires empty application state"
        );
        let restored = validated.state().clone();
        ensure!(
            restored.height > 0 && restored.pending.is_none(),
            "validated snapshot is not committed state"
        );
        ensure!(
            validated.schema_version == STORE_SCHEMA_VERSION
                || validated.schema_version == PREVIOUS_STORE_SCHEMA_VERSION,
            "validated snapshot schema is unsupported"
        );

        let _maintenance = self
            .maintenance_gate
            .lock()
            .map_err(|_| anyhow!("application store maintenance gate poisoned"))?;
        ensure!(
            self.active_snapshot_pins.load(Ordering::Acquire) == 0,
            "cannot install a snapshot while a live snapshot read is pinned"
        );
        let _writer = self.lock_writer()?;
        let mut destination = self.connect()?;
        {
            let transaction =
                destination.transaction_with_behavior(TransactionBehavior::Immediate)?;
            verify_database_head(&transaction, expected)?;
            transaction.rollback()?;
        }
        {
            let backup = Backup::new(&validated.source, &mut destination)?;
            backup.run_to_completion(256, Duration::from_millis(2), None)?;
        }

        // A completed SQLite backup is the authoritative installation
        // boundary. Before this point an error is a normal retry; afterwards
        // every failure must stop the process so disk and memory cannot
        // diverge while CometBFT continues.
        let post_install = (|| -> Result<AppState> {
            let installed_schema = metadata(&destination, "schema_version")?;
            if installed_schema == PREVIOUS_STORE_SCHEMA_VERSION {
                migrate_store_schema_v3_to_v4(&mut destination)?;
            } else {
                ensure!(
                    installed_schema == STORE_SCHEMA_VERSION,
                    "installed snapshot store schema is unsupported"
                );
                validate_auth_prune_metadata(&destination)?;
            }
            let checkpoint =
                destination.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })?;
            ensure!(
                checkpoint.0 == 0,
                "installed snapshot WAL checkpoint was blocked by an active reader"
            );
            self.verify_installed_snapshot_copy(&destination, &restored)?;
            drop(destination);
            fs::File::open(&self.database_path)?.sync_all()?;
            let wal = sqlite_sidecar(&self.database_path, "-wal");
            if wal.exists() {
                fs::File::open(&wal)?.sync_all()?;
            }
            sync_parent(&self.database_path)?;

            let installed = self.connect_read()?;
            self.verify_installed_snapshot_copy(&installed, &restored)?;
            Ok(restored)
        })();
        match post_install {
            Ok(installed) => {
                self.refresh_status_best_effort(&installed);
                Ok(installed)
            }
            Err(error) => fail_stop_after_snapshot_install(error),
        }
    }

    fn verify_installed_snapshot_copy(
        &self,
        connection: &Connection,
        restored: &AppState,
    ) -> Result<()> {
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        ensure!(
            integrity == "ok",
            "installed SQLite snapshot quick_check failed"
        );
        validate_snapshot_schema(connection)?;
        self.verify_database_bindings(connection)?;
        ensure!(
            metadata(connection, "height")? == restored.height.to_string()
                && metadata(connection, "app_hash_hex")? == hex::encode(restored.app_hash)
                && latest_auth_version(connection)? == Some(restored.height),
            "installed SQLite snapshot head differs from its prevalidated source"
        );
        let root_hash = auth_root(connection, restored.height)?
            .context("installed SQLite snapshot is missing its committed root")?;
        ensure!(
            <[u8; 32]>::from(root_hash) == restored.app_hash,
            "installed SQLite snapshot root differs from its AppHash"
        );
        ensure!(
            connection.query_row("SELECT COUNT(*) FROM auth_roots", [], |row| {
                row.get::<_, u64>(0)
            })? == 1
                && connection.query_row("SELECT COUNT(*) FROM auth_stale_nodes", [], |row| {
                    row.get::<_, u64>(0)
                })? == 0
                && connection.query_row("SELECT COUNT(*) FROM auth_stale_values", [], |row| {
                    row.get::<_, u64>(0)
                })? == 0
                && optional_metadata_version(connection, AUTH_QUERY_FLOOR_KEY)?
                    == Some(restored.height)
                && optional_metadata_version(connection, AUTH_PRUNE_TARGET_KEY)?.is_none(),
            "installed SQLite snapshot is not normalized latest-only state"
        );

        let lifecycle_bytes: Vec<u8> = connection.query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let lifecycle: ValidatorLifecycleStateV1 = serde_json::from_slice(&lifecycle_bytes)?;
        ensure!(
            restored.validator_lifecycle.as_ref() == Some(&lifecycle),
            "installed SQLite snapshot lifecycle differs from its prevalidated source"
        );
        let reader = SqliteAuthReader { connection };
        let proof = prove_with_reader(&reader, restored.height, root_hash, validator_state_key()?)?;
        let value = proof
            .value
            .as_deref()
            .context("installed SQLite snapshot lifecycle proof is absent")?;
        let record = AuthenticatedObjectRecord::decode(value)?;
        ensure!(
            record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
                && record.object_version <= restored.height
                && record.value == lifecycle_bytes
                && verify_ics23_membership(&proof, value),
            "installed SQLite snapshot lifecycle proof failed"
        );
        Ok(())
    }

    pub(super) fn validate_snapshot_database(
        &self,
        path: &Path,
        expected_height: u64,
        expected_app_hash: [u8; 32],
    ) -> Result<ValidatedSnapshotDatabase> {
        let (copy, payload_hash) = prepare_snapshot_validation_copy(path)?;
        self.validate_snapshot_database_copy(copy, expected_height, expected_app_hash, payload_hash)
    }

    pub(super) fn validate_snapshot_database_with_payload_hash(
        &self,
        path: &Path,
        expected_height: u64,
        expected_app_hash: [u8; 32],
        expected_payload_hash: [u8; 32],
    ) -> Result<ValidatedSnapshotDatabase> {
        let (copy, observed_payload_hash) = prepare_snapshot_validation_copy(path)?;
        ensure!(
            observed_payload_hash == expected_payload_hash,
            "SQLite snapshot payload changed after manifest verification"
        );
        self.validate_snapshot_database_copy(
            copy,
            expected_height,
            expected_app_hash,
            expected_payload_hash,
        )
    }

    fn validate_snapshot_database_copy(
        &self,
        owned_copy: SnapshotValidationCopy,
        expected_height: u64,
        expected_app_hash: [u8; 32],
        expected_payload_hash: [u8; 32],
    ) -> Result<ValidatedSnapshotDatabase> {
        let path = owned_copy.path.as_path();
        for suffix in ["-wal", "-shm", "-journal"] {
            ensure!(
                !sqlite_sidecar(path, suffix).exists(),
                "SQLite snapshot must be a standalone database without {suffix}"
            );
        }
        let sqlite_path = owned_copy.sqlite_path()?;
        let connection = Connection::open_with_flags(
            &sqlite_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("open private SQLite snapshot copy {}", path.display()))?;
        connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_SNAPSHOT_SQLITE_VALUE_BYTES);
        connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024);
        connection.set_limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0);
        connection.execute_batch(
            "
            PRAGMA trusted_schema=OFF;
            PRAGMA query_only=ON;
            BEGIN DEFERRED;
            ",
        )?;
        validate_snapshot_file_layout(&connection, owned_copy.file()?.metadata()?.len())?;
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        ensure!(integrity == "ok", "SQLite snapshot quick_check failed");
        validate_snapshot_schema(&connection)?;
        validate_snapshot_row_counts(&connection)?;
        validate_storage_resource_bounds(&connection)?;
        let store_schema = self.verify_compatible_database_bindings(&connection)?;
        validate_snapshot_metadata_keys(&connection, &store_schema)?;
        ensure!(
            metadata(&connection, "height")? == expected_height.to_string()
                && metadata(&connection, "app_hash_hex")? == hex::encode(expected_app_hash),
            "SQLite snapshot trusted head mismatch"
        );
        let root_count = connection.query_row("SELECT COUNT(*) FROM auth_roots", [], |row| {
            row.get::<_, u64>(0)
        })?;
        let stale_count =
            connection.query_row("SELECT COUNT(*) FROM auth_stale_nodes", [], |row| {
                row.get::<_, u64>(0)
            })?;
        let stale_value_count = if store_schema == STORE_SCHEMA_VERSION {
            connection.query_row("SELECT COUNT(*) FROM auth_stale_values", [], |row| {
                row.get::<_, u64>(0)
            })?
        } else {
            0
        };
        ensure!(
            root_count == 1 && stale_count == 0 && stale_value_count == 0,
            "SQLite snapshot must contain latest-only authenticated history"
        );
        ensure!(
            connection.query_row("SELECT COUNT(*) FROM command_ids", [], |row| {
                row.get::<_, u64>(0)
            })? == 0
                && connection.query_row("SELECT COUNT(*) FROM signer_nonces", [], |row| {
                    row.get::<_, u64>(0)
                })? == 0,
            "SQLite snapshot contains unauthenticated replay-cache rows"
        );
        if store_schema == STORE_SCHEMA_VERSION {
            ensure!(
                optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
                    == Some(expected_height),
                "SQLite snapshot authenticated query floor is not latest-only"
            );
            ensure!(
                optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?.is_none(),
                "SQLite snapshot contains unfinished authenticated maintenance"
            );
        }
        let restored = Self::validate_latest_only_auth_storage(
            &connection,
            path,
            expected_height,
            expected_app_hash,
        )?;
        ensure!(
            (restored.height, restored.app_hash) == (expected_height, expected_app_hash),
            "validated SQLite snapshot state differs from trusted head"
        );
        for suffix in ["-wal", "-shm", "-journal"] {
            ensure!(
                !sqlite_sidecar(path, suffix).exists(),
                "SQLite snapshot sidecar {suffix} appeared during validation"
            );
        }
        ensure!(
            snapshot_payload_hash_open_file_v4(owned_copy.file()?)? == expected_payload_hash,
            "SQLite snapshot payload changed during validation"
        );
        Ok(ValidatedSnapshotDatabase {
            source: connection,
            state: restored,
            schema_version: store_schema,
            _owned_copy: owned_copy,
        })
    }

    fn validate_latest_only_auth_storage(
        connection: &Connection,
        snapshot_path: &Path,
        height: u64,
        expected_app_hash: [u8; 32],
    ) -> Result<AppState> {
        let root_hash = auth_root(connection, height)?
            .context("SQLite snapshot is missing its trusted root")?;
        ensure!(
            <[u8; 32]>::from(root_hash) == expected_app_hash,
            "SQLite snapshot root differs from its trusted AppHash"
        );

        let mut scratch = SnapshotValidationScratch::open(snapshot_path)?;
        let transaction = scratch
            .connection_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let root_path: NibblePath = std::iter::empty().collect();
        let root_key = borsh::to_vec(&NodeKey::new(height, root_path))
            .context("encode trusted snapshot root key")?;
        transaction.execute(
            "INSERT INTO node_checks(
                node_key, expected_hash, reference_count
             ) VALUES (?1, ?2, 1)",
            params![root_key, expected_app_hash.as_slice()],
        )?;

        let mut actual_node_statement = transaction.prepare(
            "INSERT INTO node_checks(
                node_key,
                actual_hash,
                actual_kind,
                actual_leaf_count
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(node_key) DO UPDATE SET
                actual_hash=excluded.actual_hash,
                actual_kind=excluded.actual_kind,
                actual_leaf_count=excluded.actual_leaf_count",
        )?;
        let mut expected_node_statement = transaction.prepare(
            "INSERT INTO node_checks(
                node_key,
                expected_hash,
                expected_kind,
                expected_leaf_count,
                reference_count
             ) VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT(node_key) DO UPDATE SET
                expected_hash=COALESCE(node_checks.expected_hash, excluded.expected_hash),
                expected_kind=COALESCE(node_checks.expected_kind, excluded.expected_kind),
                expected_leaf_count=COALESCE(
                    node_checks.expected_leaf_count,
                    excluded.expected_leaf_count
                ),
                reference_count=node_checks.reference_count + 1",
        )?;
        let mut node_leaf_statement = transaction.prepare(
            "INSERT INTO leaf_checks(
                key_hash, node_version_be, node_hash
             ) VALUES (?1, ?2, ?3)
             ON CONFLICT(key_hash) DO UPDATE SET
                node_version_be=excluded.node_version_be,
                node_hash=excluded.node_hash",
        )?;

        let mut stored_nodes = 0_u64;
        let mut reachable_leaves = 0_u64;
        let mut statement = connection.prepare("SELECT node_key, node FROM auth_nodes")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (encoded_key, encoded_node) = row?;
            let node_key: NodeKey =
                borsh::from_slice(&encoded_key).context("decode persisted JMT node key")?;
            ensure!(
                node_key.version() <= height && node_key.nibble_path().num_nibbles() <= 64,
                "SQLite snapshot contains an invalid or future-version JMT node key"
            );
            let canonical_path: NibblePath = node_key.nibble_path().nibbles().collect();
            ensure!(
                canonical_path == *node_key.nibble_path()
                    && borsh::to_vec(&node_key)? == encoded_key,
                "SQLite snapshot contains a non-canonical JMT node key"
            );
            let node: Node =
                borsh::from_slice(&encoded_node).context("decode persisted JMT node")?;
            ensure!(
                borsh::to_vec(&node)? == encoded_node,
                "SQLite snapshot contains a non-canonical JMT node"
            );
            stored_nodes = stored_nodes
                .checked_add(1)
                .context("SQLite snapshot JMT node count overflow")?;

            let (actual_hash, actual_kind, actual_leaf_count) = match &node {
                Node::Null => (JMT_PLACEHOLDER_HASH, 0_i64, 0_i64),
                Node::Leaf(leaf) => {
                    reachable_leaves = reachable_leaves
                        .checked_add(1)
                        .context("reachable JMT leaf count overflow")?;
                    for (index, nibble) in node_key.nibble_path().nibbles().enumerate() {
                        let byte = leaf.key_hash().0[index / 2];
                        let expected = if index.is_multiple_of(2) {
                            byte >> 4
                        } else {
                            byte & 0x0f
                        };
                        ensure!(
                            u8::from(nibble) == expected,
                            "SQLite snapshot leaf is stored outside its authenticated key path"
                        );
                    }
                    let leaf_hash = leaf.hash::<Sha256>();
                    node_leaf_statement.execute(params![
                        leaf.key_hash().0.as_slice(),
                        node_key.version().to_be_bytes().as_slice(),
                        leaf_hash.as_slice(),
                    ])?;
                    (leaf_hash, 1_i64, 1_i64)
                }
                Node::Internal(internal) => {
                    ensure!(
                        node_key.nibble_path().num_nibbles() < 64,
                        "SQLite snapshot contains a JMT internal node below maximum depth"
                    );
                    let mut child_count = 0_usize;
                    let mut child_leaf_count = 0_usize;
                    let mut only_child_is_leaf = false;
                    for (nibble, child) in internal.children_sorted() {
                        ensure!(
                            child.version <= height,
                            "SQLite snapshot contains a future-version JMT child"
                        );
                        child_count = child_count
                            .checked_add(1)
                            .context("JMT child count overflow")?;
                        child_leaf_count = child_leaf_count
                            .checked_add(child.leaf_count())
                            .context("JMT child leaf count overflow")?;
                        only_child_is_leaf = child.is_leaf();
                        let path = node_key
                            .nibble_path()
                            .nibbles()
                            .chain(std::iter::once(nibble))
                            .collect();
                        let child_key = borsh::to_vec(&NodeKey::new(child.version, path))
                            .context("encode expected snapshot child key")?;
                        expected_node_statement.execute(params![
                            child_key,
                            child.hash.as_slice(),
                            if child.is_leaf() { 1_i64 } else { 2_i64 },
                            i64::try_from(child.leaf_count())
                                .context("JMT child leaf count exceeds i64")?,
                        ])?;
                    }
                    ensure!(
                        child_count > 0
                            && !(child_count == 1 && only_child_is_leaf)
                            && internal.leaf_count() >= 2
                            && internal.leaf_count() == child_leaf_count,
                        "SQLite snapshot contains a structurally invalid JMT internal node"
                    );
                    (
                        internal.hash::<Sha256>(),
                        2_i64,
                        i64::try_from(internal.leaf_count())
                            .context("JMT internal leaf count exceeds i64")?,
                    )
                }
            };
            actual_node_statement.execute(params![
                encoded_key,
                actual_hash.as_slice(),
                actual_kind,
                actual_leaf_count,
            ])?;
        }
        drop(node_leaf_statement);
        drop(expected_node_statement);
        drop(actual_node_statement);
        drop(statement);

        let mut value_statement = transaction.prepare(
            "INSERT INTO leaf_checks(
                key_hash, value_version_be, value_hash
             ) VALUES (?1, ?2, ?3)
             ON CONFLICT(key_hash) DO UPDATE SET
                value_version_be=excluded.value_version_be,
                value_hash=excluded.value_hash",
        )?;
        let mut stored_values = 0_u64;
        let mut statement = connection
            .prepare("SELECT key_hash, version_be, value, is_deleted FROM auth_values")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (key_hash, version, value, is_deleted) = row?;
            let key_hash = KeyHash(
                <[u8; 32]>::try_from(key_hash.as_slice())
                    .map_err(|_| anyhow!("SQLite snapshot value key hash is not 32 bytes"))?,
            );
            let decoded_version = decode_version_be(&version)?;
            ensure!(
                decoded_version <= height && value.is_some() && is_deleted == 0,
                "SQLite snapshot contains a non-canonical latest value"
            );
            stored_values = stored_values
                .checked_add(1)
                .context("SQLite snapshot value count overflow")?;
            let value_hash = snapshot_leaf_hash(
                key_hash,
                value
                    .as_deref()
                    .expect("latest-only snapshot value was checked"),
            );
            value_statement.execute(params![
                key_hash.0.as_slice(),
                version,
                value_hash.as_slice(),
            ])?;
        }
        drop(value_statement);
        drop(statement);

        let mut preimage_statement = transaction.prepare(
            "INSERT INTO leaf_checks(key_hash, preimage_seen)
             VALUES (?1, 1)
             ON CONFLICT(key_hash) DO UPDATE SET
                preimage_seen=leaf_checks.preimage_seen + 1",
        )?;
        let mut stored_preimages = 0_u64;
        let mut statement =
            connection.prepare("SELECT key_hash, key_preimage FROM auth_preimages")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (key_hash, preimage) = row?;
            let key_hash = KeyHash(
                <[u8; 32]>::try_from(key_hash.as_slice())
                    .map_err(|_| anyhow!("SQLite snapshot preimage hash is not 32 bytes"))?,
            );
            ensure!(
                authenticated_key_hash(&preimage)? == key_hash,
                "SQLite snapshot authenticated key preimage hash mismatch"
            );
            stored_preimages = stored_preimages
                .checked_add(1)
                .context("SQLite snapshot preimage count overflow")?;
            preimage_statement.execute(params![key_hash.0.as_slice()])?;
        }
        drop(preimage_statement);
        drop(statement);

        let mut domain_statement = transaction.prepare(
            "INSERT INTO leaf_checks(key_hash, domain_hash)
             VALUES (?1, ?2)
             ON CONFLICT(key_hash) DO UPDATE SET
                domain_hash=excluded.domain_hash",
        )?;
        let mut object_count = 0_u64;
        let mut statement = connection.prepare(
            "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
             FROM objects",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        for row in rows {
            let (object_key_hex, object_type, version, value_hash_hex, value_bytes) = row?;
            let object = StoredObject {
                object_key_hex,
                object_type,
                version: version
                    .parse::<u64>()
                    .context("parse SQLite snapshot object version")?,
                value_hash_hex,
                value_bytes,
            };
            validate_object(&object)?;
            let key = stored_object_key(&object.object_key_hex)?;
            let key_hash = authenticated_key_hash(&key)?;
            let value = AuthenticatedObjectRecord::new(
                object.object_type,
                object.version,
                object.value_bytes,
            )?
            .encode()?;
            let domain_hash = snapshot_leaf_hash(key_hash, &value);
            domain_statement.execute(params![key_hash.0.as_slice(), domain_hash.as_slice(),])?;
            object_count = object_count
                .checked_add(1)
                .context("SQLite snapshot object count overflow")?;
        }
        drop(statement);

        let lifecycle_bytes: Vec<u8> = connection
            .query_row(
                "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .context("SQLite snapshot is missing committed validator lifecycle")?;
        let validator_lifecycle: ValidatorLifecycleStateV1 =
            serde_json::from_slice(&lifecycle_bytes)
                .context("decode SQLite snapshot validator lifecycle")?;
        validator_lifecycle.validate()?;
        let lifecycle_key = validator_state_key()?;
        let lifecycle_key_hash = authenticated_key_hash(&lifecycle_key)?;
        let lifecycle_value_version: Vec<u8> = connection
            .query_row(
                "SELECT version_be
                 FROM auth_values
                 WHERE key_hash=?1 AND is_deleted=0",
                params![lifecycle_key_hash.0.as_slice()],
                |row| row.get(0),
            )
            .context("SQLite snapshot is missing authenticated validator lifecycle value")?;
        let lifecycle_value = AuthenticatedObjectRecord::new(
            VALIDATOR_LIFECYCLE_SCHEMA_V1,
            decode_version_be(&lifecycle_value_version)?,
            lifecycle_bytes,
        )?
        .encode()?;
        let lifecycle_hash = snapshot_leaf_hash(lifecycle_key_hash, &lifecycle_value);
        domain_statement.execute(params![
            lifecycle_key_hash.0.as_slice(),
            lifecycle_hash.as_slice(),
        ])?;
        drop(domain_statement);

        let node_check_count =
            transaction.query_row("SELECT COUNT(*) FROM node_checks", [], |row| {
                row.get::<_, u64>(0)
            })?;
        let invalid_node_count = transaction.query_row(
            "SELECT COUNT(*)
             FROM node_checks
             WHERE actual_hash IS NULL
                OR expected_hash IS NULL
                OR reference_count<>1
                OR actual_hash<>expected_hash
                OR (
                    expected_kind IS NOT NULL
                    AND (
                        actual_kind<>expected_kind
                        OR actual_leaf_count<>expected_leaf_count
                    )
                )",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        ensure!(
            node_check_count == stored_nodes && invalid_node_count == 0,
            "SQLite snapshot contains missing, unreachable, multiply referenced, or hash-invalid JMT nodes"
        );

        let leaf_check_count =
            transaction.query_row("SELECT COUNT(*) FROM leaf_checks", [], |row| {
                row.get::<_, u64>(0)
            })?;
        let invalid_leaf_count = transaction.query_row(
            "SELECT COUNT(*)
             FROM leaf_checks
             WHERE node_version_be IS NULL
                OR node_hash IS NULL
                OR value_version_be IS NULL
                OR value_hash IS NULL
                OR domain_hash IS NULL
                OR preimage_seen<>1
                OR value_version_be>node_version_be
                OR node_hash<>value_hash
                OR node_hash<>domain_hash",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        let domain_rows = object_count
            .checked_add(1)
            .context("SQLite snapshot domain row count overflow")?;
        ensure!(
            leaf_check_count == reachable_leaves
                && reachable_leaves == stored_values
                && reachable_leaves == stored_preimages
                && reachable_leaves == domain_rows
                && invalid_leaf_count == 0,
            "SQLite snapshot authenticated leaves, values, preimages, and domain rows differ \
             (checks={leaf_check_count}, leaves={reachable_leaves}, values={stored_values}, \
             preimages={stored_preimages}, domain={domain_rows}, invalid={invalid_leaf_count})"
        );
        transaction.commit()?;

        Ok(AppState {
            height,
            app_hash: expected_app_hash,
            objects: std::collections::BTreeMap::new(),
            command_ids: std::collections::BTreeSet::new(),
            signer_nonces: std::collections::BTreeSet::new(),
            validator_lifecycle: Some(validator_lifecycle),
            pending: None,
        })
    }

    fn with_database_path(&self, database_path: PathBuf) -> Self {
        Self {
            status_path: database_path.with_extension("status-cache-unused"),
            database_path,
            chain_id: self.chain_id.clone(),
            signer_policy_hash_hex: self.signer_policy_hash_hex.clone(),
            writer_gate: Arc::new(Mutex::new(())),
            writer_waiters: Arc::new(AtomicUsize::new(0)),
            maintenance_gate: Arc::new(Mutex::new(())),
            active_snapshot_pins: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "scale-gate"))]
            prune_writer_collision_hook: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) fn persist_transition(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        query_floor: Version,
    ) -> Result<()> {
        self.persist_transition_inner(current, pending, query_floor, None)
    }

    #[cfg(test)]
    pub(super) fn persist_transition_with_failpoint(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        failpoint: StoreFailpoint,
    ) -> Result<()> {
        self.persist_transition_inner(current, pending, 0, Some(failpoint))
    }

    fn persist_transition_inner(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        query_floor: Version,
        #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<StoreFailpoint>,
    ) -> Result<()> {
        ensure!(
            pending.height == current.height.saturating_add(1),
            "application store height transition is not contiguous"
        );
        ensure!(
            pending.auth_update.version == pending.height,
            "authenticated update version differs from pending height"
        );
        ensure!(
            query_floor <= pending.height,
            "authenticated query floor exceeds pending height"
        );

        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, current)?;
        ensure!(
            latest_auth_version(&transaction)? == Some(current.height)
                && auth_root(&transaction, current.height)?.map(Into::<[u8; 32]>::into)
                    == Some(current.app_hash),
            "authenticated tree head differs from committed application head"
        );
        for object in pending.delta.objects.values() {
            upsert_object(&transaction, object)?;
        }
        for command_id in &pending.delta.command_ids {
            ensure!(
                !current.command_ids.contains(command_id),
                "pending command ID already exists in committed state"
            );
            transaction.execute(
                "INSERT INTO command_ids(command_id) VALUES (?1)",
                params![command_id],
            )?;
        }
        for (signer_id, nonce) in &pending.delta.signer_nonces {
            ensure!(
                !current.signer_nonces.contains(&(signer_id.clone(), *nonce)),
                "pending signer nonce already exists in committed state"
            );
            transaction.execute(
                "INSERT INTO signer_nonces(signer_id, nonce) VALUES (?1, ?2)",
                params![signer_id, nonce.to_be_bytes().as_slice()],
            )?;
        }
        let lifecycle = pending
            .delta
            .validator_lifecycle
            .as_ref()
            .or(current.validator_lifecycle.as_ref())
            .context("cannot persist state before validator lifecycle initialization")?;
        write_validator_lifecycle(&transaction, lifecycle)?;
        ensure!(
            <[u8; 32]>::from(pending.auth_update.root_hash) == pending.app_hash,
            "pending AppHash differs from authenticated tree root"
        );
        persist_auth_update(&transaction, &pending.auth_update)?;
        write_head_values(&transaction, pending.height, pending.app_hash)?;
        advance_auth_query_floor(&transaction, query_floor)?;
        #[cfg(test)]
        if failpoint == Some(StoreFailpoint::BeforeSqlCommit) {
            return Err(anyhow!("injected failure before SQLite COMMIT"));
        }
        transaction.commit()?;
        #[cfg(test)]
        if failpoint == Some(StoreFailpoint::AfterSqlCommitBeforeStatus) {
            return Err(anyhow!(
                "injected failure after SQLite COMMIT before status refresh"
            ));
        }
        self.refresh_status_values_best_effort(pending.height, pending.app_hash);
        Ok(())
    }

    pub(super) fn replace_empty_state(
        &self,
        expected: &AppState,
        state: &AppState,
        auth_update: &PlannedAuthUpdate,
    ) -> Result<()> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "replacement expected state must be empty"
        );
        ensure!(state.pending.is_none(), "cannot persist pending state");
        ensure!(
            auth_update.version == state.height
                && <[u8; 32]>::from(auth_update.root_hash) == state.app_hash,
            "replacement authenticated update does not match app head"
        );
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, expected)?;
        replace_domain_state(&transaction, state)?;
        clear_auth_tree(&transaction)?;
        persist_auth_update(&transaction, auth_update)?;
        write_head_values(&transaction, state.height, state.app_hash)?;
        transaction.commit()?;
        self.refresh_status_best_effort(state);
        Ok(())
    }

    pub(super) fn replace_empty_state_from_tree(
        &self,
        expected: &AppState,
        state: &AppState,
        auth_tree: &InMemoryAuthTree,
    ) -> Result<()> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "snapshot replacement expected state must be empty"
        );
        ensure!(state.pending.is_none(), "cannot persist pending state");
        ensure!(
            auth_tree.latest_version() == Some(state.height)
                && auth_tree
                    .root_hash(state.height)
                    .map(Into::<[u8; 32]>::into)
                    == Some(state.app_hash),
            "replacement authenticated state does not match app head"
        );
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, expected)?;
        replace_domain_state(&transaction, state)?;
        clear_auth_tree(&transaction)?;
        persist_full_auth_tree(&transaction, auth_tree)?;
        write_head_values(&transaction, state.height, state.app_hash)?;
        transaction.commit()?;
        self.refresh_status_best_effort(state);
        Ok(())
    }

    fn connect(&self) -> Result<Connection> {
        if let Some(parent) = self.database_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create application store directory {}", parent.display())
            })?;
        }
        let initialize = !self.database_path.exists();
        let mut connection = Connection::open(&self.database_path)
            .with_context(|| format!("open application store {}", self.database_path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        if initialize {
            connection.execute_batch("PRAGMA journal_mode=WAL;")?;
        }
        connection.execute_batch(
            "
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            ",
        )?;
        if initialize {
            connection.execute_batch(STORE_SCHEMA_SQL)?;
        }
        let schema: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match schema.as_deref() {
            Some(schema) => ensure!(
                schema == STORE_SCHEMA_VERSION || schema == PREVIOUS_STORE_SCHEMA_VERSION,
                "unsupported application store schema version"
            ),
            None => {
                ensure!(
                    initialize,
                    "existing application store is missing schema_version"
                );
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?1)",
                    params![STORE_SCHEMA_VERSION],
                )?;
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES (?1, '0')",
                    params![AUTH_QUERY_FLOOR_KEY],
                )?;
            }
        }
        if schema.as_deref() == Some(PREVIOUS_STORE_SCHEMA_VERSION) {
            migrate_store_schema_v3_to_v4(&mut connection)?;
        }
        if initialize {
            ensure_metadata_binding(&connection, "chain_id", &self.chain_id)?;
            ensure_metadata_binding(&connection, "app_version", &APP_VERSION.to_string())?;
            ensure_metadata_binding(
                &connection,
                "authorized_signers_hash_hex",
                &self.signer_policy_hash_hex,
            )?;
            ensure_metadata_binding(&connection, "auth_tree", "jmt-sha256-v0.12.0")?;
            ensure_metadata_binding(&connection, "auth_codec", "borsh-v1")?;
        } else {
            self.verify_database_bindings(&connection)?;
        }
        validate_auth_prune_metadata(&connection)?;
        Ok(connection)
    }

    fn connect_read(&self) -> Result<Connection> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| {
            format!(
                "open application store read-only {}",
                self.database_path.display()
            )
        })?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "
            PRAGMA trusted_schema=OFF;
            PRAGMA query_only=ON;
            ",
        )?;
        self.verify_database_bindings(&connection)?;
        Ok(connection)
    }

    fn connect_maintenance(&self) -> Result<Connection> {
        let connection = Connection::open(&self.database_path).with_context(|| {
            format!(
                "open application store maintenance connection {}",
                self.database_path.display()
            )
        })?;
        connection.busy_timeout(Duration::ZERO)?;
        connection.execute_batch(
            "
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            ",
        )?;
        self.verify_database_bindings(&connection)?;
        validate_auth_prune_metadata(&connection)?;
        Ok(connection)
    }

    fn probe_existing_database(&self) -> Result<()> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| {
            format!(
                "open existing application store read-only {}",
                self.database_path.display()
            )
        })?;
        validate_snapshot_schema(&connection)?;
        validate_storage_resource_bounds(&connection)?;
        self.verify_compatible_database_bindings(&connection)?;
        Ok(())
    }

    fn verify_database_bindings(&self, connection: &Connection) -> Result<()> {
        ensure!(
            self.verify_compatible_database_bindings(connection)? == STORE_SCHEMA_VERSION,
            "existing application store requires schema migration"
        );
        Ok(())
    }

    fn verify_compatible_database_bindings(&self, connection: &Connection) -> Result<String> {
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .context("existing application store is missing or cannot read schema_version")?;
        ensure!(
            schema_version == STORE_SCHEMA_VERSION
                || schema_version == PREVIOUS_STORE_SCHEMA_VERSION,
            "existing application store schema version is unsupported"
        );
        let app_version = APP_VERSION.to_string();
        let bindings = [
            ("chain_id", self.chain_id.as_str()),
            ("app_version", app_version.as_str()),
            (
                "authorized_signers_hash_hex",
                self.signer_policy_hash_hex.as_str(),
            ),
            ("auth_tree", "jmt-sha256-v0.12.0"),
            ("auth_codec", "borsh-v1"),
        ];
        for (key, expected) in bindings {
            let actual: String = connection
                .query_row(
                    "SELECT value FROM metadata WHERE key=?1",
                    params![key],
                    |row| row.get(0),
                )
                .with_context(|| {
                    format!("existing application store is missing or cannot read {key}")
                })?;
            ensure!(
                actual == expected,
                "existing application store {key} differs from configured value"
            );
        }
        Ok(schema_version)
    }

    fn has_committed_state(&self, connection: &Connection) -> Result<bool> {
        Ok(connection
            .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .is_some())
    }

    fn refresh_status_best_effort(&self, state: &AppState) {
        self.refresh_status_values_best_effort(state.height, state.app_hash);
    }

    fn refresh_status_values_best_effort(&self, height: u64, app_hash: [u8; 32]) {
        if let Err(error) = self.write_status_values(height, app_hash) {
            eprintln!(
                "[trnm-cometbft-app] SQLite commit is authoritative; failed to refresh status cache: {error:#}"
            );
        }
    }

    fn write_status_values(&self, height: u64, app_hash: [u8; 32]) -> Result<()> {
        let status = PersistedStatusV2 {
            schema: STATUS_SCHEMA_V2,
            app_version: APP_VERSION,
            height,
            app_hash_hex: hex::encode(app_hash),
        };
        persist_state_bytes(&self.status_path, &serde_json::to_vec(&status)?)
    }
}

fn verify_database_head(transaction: &Transaction<'_>, current: &AppState) -> Result<()> {
    let stored_height: Option<String> = transaction
        .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
            row.get(0)
        })
        .optional()?;
    if current.height == 0 && stored_height.is_none() {
        return Ok(());
    }
    let stored_height = stored_height
        .ok_or_else(|| anyhow!("application store is missing committed height"))?
        .parse::<u64>()
        .context("parse application store height")?;
    let stored_hash: String = transaction
        .query_row(
            "SELECT value FROM metadata WHERE key='app_hash_hex'",
            [],
            |row| row.get(0),
        )
        .context("application store is missing committed app hash")?;
    ensure!(
        stored_height == current.height && stored_hash == hex::encode(current.app_hash),
        "application store head differs from in-memory committed state"
    );
    Ok(())
}

fn write_head_values(transaction: &Transaction<'_>, height: u64, app_hash: [u8; 32]) -> Result<()> {
    for (key, value) in [
        ("height", height.to_string()),
        ("app_hash_hex", hex::encode(app_hash)),
    ] {
        transaction.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}

fn advance_auth_query_floor(transaction: &Transaction<'_>, requested: Version) -> Result<()> {
    let current = optional_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY)?
        .context("application store is missing authenticated query floor")?;
    if requested <= current {
        return Ok(());
    }
    write_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY, requested)?;
    write_metadata_version(transaction, AUTH_PRUNE_TARGET_KEY, requested)
}

fn clear_auth_tree(transaction: &Transaction<'_>) -> Result<()> {
    transaction.execute("DELETE FROM auth_nodes", [])?;
    transaction.execute("DELETE FROM auth_values", [])?;
    transaction.execute("DELETE FROM auth_preimages", [])?;
    transaction.execute("DELETE FROM auth_stale_nodes", [])?;
    transaction.execute("DELETE FROM auth_stale_values", [])?;
    transaction.execute("DELETE FROM auth_roots", [])?;
    write_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY, 0)?;
    transaction.execute(
        "DELETE FROM metadata WHERE key=?1",
        params![AUTH_PRUNE_TARGET_KEY],
    )?;
    Ok(())
}

fn replace_domain_state(transaction: &Transaction<'_>, state: &AppState) -> Result<()> {
    transaction.execute("DELETE FROM objects", [])?;
    transaction.execute("DELETE FROM command_ids", [])?;
    transaction.execute("DELETE FROM signer_nonces", [])?;
    transaction.execute("DELETE FROM validator_lifecycle", [])?;
    for object in state.objects.values() {
        upsert_object(transaction, object)?;
    }
    for command_id in &state.command_ids {
        transaction.execute(
            "INSERT INTO command_ids(command_id) VALUES (?1)",
            params![command_id],
        )?;
    }
    for (signer_id, nonce) in &state.signer_nonces {
        transaction.execute(
            "INSERT INTO signer_nonces(signer_id, nonce) VALUES (?1, ?2)",
            params![signer_id, nonce.to_be_bytes().as_slice()],
        )?;
    }
    if let Some(lifecycle) = &state.validator_lifecycle {
        write_validator_lifecycle(transaction, lifecycle)?;
    }
    Ok(())
}

fn persist_full_auth_tree(
    transaction: &Transaction<'_>,
    auth_tree: &InMemoryAuthTree,
) -> Result<()> {
    for (node_key, node) in auth_tree.nodes() {
        transaction.execute(
            "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
            params![
                borsh::to_vec(node_key).context("encode JMT node key")?,
                borsh::to_vec(node).context("encode JMT node")?,
            ],
        )?;
    }
    for ((key_hash, version), value) in auth_tree.values() {
        transaction.execute(
            "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key_hash.0.as_slice(),
                version.to_be_bytes().as_slice(),
                value.as_deref(),
                i64::from(value.is_none()),
            ],
        )?;
    }
    rebuild_auth_stale_values(transaction)?;
    for (key_hash, preimage) in auth_tree.preimages() {
        transaction.execute(
            "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (?1, ?2)",
            params![key_hash.0.as_slice(), preimage],
        )?;
    }
    for stale in auth_tree.stale_nodes() {
        transaction.execute(
            "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key)
             VALUES (?1, ?2)",
            params![
                stale.stale_since_version.to_be_bytes().as_slice(),
                borsh::to_vec(&stale.node_key).context("encode stale JMT node key")?,
            ],
        )?;
    }
    for (version, root) in auth_tree.roots() {
        transaction.execute(
            "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
            params![version.to_be_bytes().as_slice(), root.0.as_slice(),],
        )?;
    }
    Ok(())
}

fn persist_auth_update(transaction: &Transaction<'_>, update: &PlannedAuthUpdate) -> Result<()> {
    for (node_key, node) in update.tree_update_batch.node_batch.nodes() {
        transaction.execute(
            "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
            params![
                borsh::to_vec(node_key).context("encode JMT node key")?,
                borsh::to_vec(node).context("encode JMT node")?,
            ],
        )?;
    }
    for ((version, key_hash), value) in update.tree_update_batch.node_batch.values() {
        let previous_version: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT version_be
                 FROM auth_values
                 WHERE key_hash=?1 AND version_be<?2
                 ORDER BY version_be DESC
                 LIMIT 1",
                params![key_hash.0.as_slice(), version.to_be_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(previous_version) = previous_version {
            transaction.execute(
                "INSERT INTO auth_stale_values(
                    stale_since_version_be,
                    key_hash,
                    version_be
                 ) VALUES (?1, ?2, ?3)",
                params![
                    version.to_be_bytes().as_slice(),
                    key_hash.0.as_slice(),
                    previous_version,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key_hash.0.as_slice(),
                version.to_be_bytes().as_slice(),
                value.as_deref(),
                i64::from(value.is_none()),
            ],
        )?;
    }
    for (key_hash, preimage) in update.preimages() {
        transaction.execute(
            "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (?1, ?2)
             ON CONFLICT(key_hash) DO NOTHING",
            params![key_hash.0.as_slice(), preimage],
        )?;
        let stored: Vec<u8> = transaction.query_row(
            "SELECT key_preimage FROM auth_preimages WHERE key_hash=?1",
            params![key_hash.0.as_slice()],
            |row| row.get(0),
        )?;
        ensure!(
            stored == *preimage,
            "authenticated key hash collision in persistent preimage store"
        );
    }
    for stale in &update.tree_update_batch.stale_node_index_batch {
        transaction.execute(
            "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key)
             VALUES (?1, ?2)",
            params![
                stale.stale_since_version.to_be_bytes().as_slice(),
                borsh::to_vec(&stale.node_key).context("encode stale JMT node key")?,
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
        params![
            update.version.to_be_bytes().as_slice(),
            update.root_hash.0.as_slice(),
        ],
    )?;
    Ok(())
}

fn decode_version_be(bytes: &[u8]) -> Result<Version> {
    Ok(u64::from_be_bytes(<[u8; 8]>::try_from(bytes).map_err(
        |_| anyhow!("persisted JMT version is not 8 bytes"),
    )?))
}

fn rebuild_auth_stale_values(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM auth_stale_values", [])?;
    connection.execute(
        "INSERT INTO auth_stale_values(
            stale_since_version_be,
            key_hash,
            version_be
         )
         SELECT next_version_be, key_hash, version_be
         FROM (
             SELECT key_hash,
                    version_be,
                    LEAD(version_be) OVER (
                        PARTITION BY key_hash
                        ORDER BY version_be
                    ) AS next_version_be
             FROM auth_values
         )
         WHERE next_version_be IS NOT NULL",
        [],
    )?;
    Ok(())
}

fn upsert_object(transaction: &Transaction<'_>, object: &StoredObject) -> Result<()> {
    transaction.execute(
        "INSERT INTO objects(
            object_key_hex, object_type, version, value_hash_hex, value_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(object_key_hex) DO UPDATE SET
            object_type=excluded.object_type,
            version=excluded.version,
            value_hash_hex=excluded.value_hash_hex,
            value_bytes=excluded.value_bytes",
        params![
            object.object_key_hex,
            object.object_type,
            object.version.to_string(),
            object.value_hash_hex,
            object.value_bytes,
        ],
    )?;
    Ok(())
}

fn write_validator_lifecycle(
    transaction: &Transaction<'_>,
    lifecycle: &ValidatorLifecycleStateV1,
) -> Result<()> {
    lifecycle.validate()?;
    transaction.execute(
        "INSERT INTO validator_lifecycle(singleton, state_json) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET state_json=excluded.state_json",
        params![serde_json::to_vec(lifecycle)?],
    )?;
    Ok(())
}

fn verify_retained_lifecycle_proofs(
    connection: &Connection,
    height: Version,
    app_hash: [u8; 32],
    boundary: Version,
) -> Result<()> {
    ensure!(
        boundary <= height,
        "authenticated proof boundary exceeds the committed head"
    );
    let retained_root = auth_root(connection, height)?
        .context("authenticated maintenance removed the committed root")?;
    ensure!(
        <[u8; 32]>::from(retained_root) == app_hash,
        "authenticated maintenance changed the committed AppHash"
    );
    let lifecycle_bytes: Vec<u8> = connection.query_row(
        "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let reader = SqliteAuthReader { connection };
    let latest_proof = prove_with_reader(&reader, height, retained_root, validator_state_key()?)?;
    let latest_value = latest_proof
        .value
        .as_deref()
        .context("latest validator lifecycle proof is absent")?;
    let lifecycle_record = AuthenticatedObjectRecord::decode(latest_value)?;
    ensure!(
        lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
            && lifecycle_record.object_version <= height
            && lifecycle_record.value == lifecycle_bytes
            && verify_ics23_membership(&latest_proof, latest_value),
        "authenticated maintenance damaged the latest validator lifecycle proof"
    );
    if boundary < height {
        let boundary_root = auth_root(connection, boundary)?
            .context("authenticated maintenance removed the retention-boundary root")?;
        let boundary_proof =
            prove_with_reader(&reader, boundary, boundary_root, validator_state_key()?)?;
        let boundary_value = boundary_proof
            .value
            .as_deref()
            .context("retention-boundary lifecycle proof is absent")?;
        ensure!(
            verify_ics23_membership(&boundary_proof, boundary_value),
            "authenticated maintenance damaged the retention-boundary proof"
        );
    }
    Ok(())
}

fn load_sqlite_state(connection: &Connection) -> Result<AppState> {
    let height = metadata(connection, "height")?
        .parse::<u64>()
        .context("parse application store height")?;
    let app_hash = trnm_finality_types::decode_hash32(
        "application store app_hash",
        &metadata(connection, "app_hash_hex")?,
    )?;
    if let Some(query_floor) = optional_metadata_version(connection, AUTH_QUERY_FLOOR_KEY)? {
        ensure!(
            query_floor <= height && auth_root(connection, query_floor)?.is_some(),
            "application store authenticated query floor is invalid"
        );
        if let Some(target) = optional_metadata_version(connection, AUTH_PRUNE_TARGET_KEY)? {
            ensure!(
                target == query_floor,
                "application store authenticated prune target differs from its query floor"
            );
        }
    }
    validate_no_future_auth_rows(connection, height)?;
    if metadata(connection, "schema_version")? == STORE_SCHEMA_VERSION {
        validate_auth_stale_value_index(connection)?;
    }

    let lifecycle_bytes: Vec<u8> = connection
        .query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .context("application store is missing committed validator lifecycle")?;
    let validator_lifecycle: ValidatorLifecycleStateV1 =
        serde_json::from_slice(&lifecycle_bytes)
            .context("decode application store validator lifecycle")?;
    validator_lifecycle.validate()?;

    ensure!(
        latest_auth_version(connection)? == Some(height),
        "authenticated tree version differs from application height"
    );
    let root_hash = auth_root(connection, height)?
        .context("application store is missing authenticated root")?;
    ensure!(
        <[u8; 32]>::from(root_hash) == app_hash,
        "application store content does not match committed app hash"
    );

    let object_count = connection.query_row("SELECT COUNT(*) FROM objects", [], |row| {
        row.get::<_, u64>(0)
    })?;
    // JellyfishMerkleIterator's public API requires Arc even though this
    // connection-bound reader never leaves the current thread.
    #[allow(clippy::arc_with_non_send_sync)]
    let reader = Arc::new(SqliteAuthReader { connection });
    let iterator = JellyfishMerkleIterator::new(Arc::clone(&reader), height, KeyHash([0; 32]))
        .with_context(|| format!("open authenticated tree iterator at version {height}"))?;
    let lifecycle_key = validator_state_key()?;
    let mut object_leaves = 0_u64;
    let mut lifecycle_seen = false;
    for entry in iterator {
        let (hash, value) =
            entry.with_context(|| format!("iterate authenticated tree at version {height}"))?;
        let preimage = reader
            .preimage(hash)?
            .with_context(|| format!("missing authenticated key preimage {hash:?}"))?;
        ensure!(
            authenticated_key_hash(&preimage)? == hash,
            "authenticated key preimage hash mismatch"
        );
        let proof = prove_with_reader(reader.as_ref(), height, root_hash, preimage.clone())?;
        ensure!(
            proof.value.as_deref() == Some(value.as_slice())
                && verify_ics23_membership(&proof, &value),
            "authenticated tree leaf failed root verification"
        );
        if preimage == lifecycle_key {
            ensure!(
                !lifecycle_seen,
                "authenticated state contains duplicate validator lifecycle"
            );
            let lifecycle_record = AuthenticatedObjectRecord::decode(&value)?;
            ensure!(
                lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
                    && lifecycle_record.object_version <= height
                    && lifecycle_record.value == lifecycle_bytes,
                "application store validator lifecycle differs from authenticated state"
            );
            lifecycle_seen = true;
            continue;
        }

        let object_key_hex = stored_object_key_preimage(&preimage)?;
        let object = load_object(connection, &object_key_hex)?.with_context(|| {
            format!("authenticated object {object_key_hex} is absent from the application store")
        })?;
        validate_object(&object)?;
        let expected =
            AuthenticatedObjectRecord::new(object.object_type, object.version, object.value_bytes)?
                .encode()?;
        ensure!(
            value == expected,
            "application store object {object_key_hex} differs from authenticated state"
        );
        object_leaves = object_leaves.saturating_add(1);
    }
    ensure!(
        lifecycle_seen,
        "authenticated state is missing validator lifecycle"
    );
    ensure!(
        object_leaves == object_count,
        "application store contains objects absent from authenticated state"
    );

    Ok(AppState {
        height,
        app_hash,
        objects: std::collections::BTreeMap::new(),
        command_ids: std::collections::BTreeSet::new(),
        signer_nonces: std::collections::BTreeSet::new(),
        validator_lifecycle: Some(validator_lifecycle),
        pending: None,
    })
}

fn validate_no_future_auth_rows(connection: &Connection, height: u64) -> Result<()> {
    {
        let mut statement = connection.prepare("SELECT node_key FROM auth_nodes")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let node_key: NodeKey =
                borsh::from_slice(&row?).context("decode persisted JMT node key")?;
            ensure!(
                node_key.version() <= height,
                "application store contains a future-version JMT node"
            );
        }
    }
    let mut version_columns = vec![
        ("auth_values", "version_be"),
        ("auth_roots", "version_be"),
        ("auth_stale_nodes", "stale_since_version_be"),
    ];
    if metadata(connection, "schema_version")? == STORE_SCHEMA_VERSION {
        version_columns.extend([
            ("auth_stale_values", "stale_since_version_be"),
            ("auth_stale_values", "version_be"),
        ]);
    }
    for (table, column) in version_columns {
        let query = format!("SELECT {column} FROM {table}");
        let mut statement = connection.prepare(&query)?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            ensure!(
                decode_version_be(&row?)? <= height,
                "application store contains a future-version row in {table}"
            );
        }
    }
    Ok(())
}

fn validate_auth_stale_value_index(connection: &Connection) -> Result<()> {
    let missing_or_wrong = connection
        .query_row(
            "WITH ordered AS (
                 SELECT key_hash,
                        version_be,
                        LEAD(version_be) OVER (
                            PARTITION BY key_hash
                            ORDER BY version_be
                        ) AS next_version_be
                 FROM auth_values
             )
             SELECT 1
             FROM ordered
             LEFT JOIN auth_stale_values AS stale
               ON stale.key_hash=ordered.key_hash
              AND stale.version_be=ordered.version_be
             WHERE ordered.next_version_be IS NOT NULL
               AND (
                   stale.stale_since_version_be IS NULL
                   OR stale.stale_since_version_be<>ordered.next_version_be
               )
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    ensure!(
        !missing_or_wrong,
        "application store authenticated stale-value index is incomplete"
    );
    let unexpected = connection
        .query_row(
            "WITH ordered AS (
                 SELECT key_hash,
                        version_be,
                        LEAD(version_be) OVER (
                            PARTITION BY key_hash
                            ORDER BY version_be
                        ) AS next_version_be
                 FROM auth_values
             )
             SELECT 1
             FROM auth_stale_values AS stale
             LEFT JOIN ordered
               ON ordered.key_hash=stale.key_hash
              AND ordered.version_be=stale.version_be
             WHERE ordered.next_version_be IS NULL
                OR ordered.next_version_be<>stale.stale_since_version_be
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    ensure!(
        !unexpected,
        "application store authenticated stale-value index contains an invalid row"
    );
    Ok(())
}

fn load_object(connection: &Connection, object_key_hex: &str) -> Result<Option<StoredObject>> {
    let object = connection
        .query_row(
            "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
             FROM objects
             WHERE object_key_hex=?1",
            params![object_key_hex],
            |row| {
                Ok(StoredObject {
                    object_key_hex: row.get(0)?,
                    object_type: row.get(1)?,
                    version: row.get::<_, String>(2)?.parse::<u64>().map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    value_hash_hex: row.get(3)?,
                    value_bytes: row.get(4)?,
                })
            },
        )
        .optional()?;
    object
        .map(|object| validate_object(&object).map(|()| object))
        .transpose()
}

fn validate_object(object: &StoredObject) -> Result<()> {
    ensure!(
        object.value_hash_hex
            == hex::encode(trnm_finality_types::hash_domain(
                "trnm.state.object.value.v1",
                &[&object.value_bytes],
            )),
        "application store object value hash mismatch"
    );
    Ok(())
}

fn snapshot_leaf_hash(key_hash: KeyHash, value: &[u8]) -> [u8; 32] {
    LeafNode::new(key_hash, ValueHash::with::<Sha256>(value)).hash::<Sha256>()
}

fn latest_auth_version(connection: &Connection) -> Result<Option<Version>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    encoded.map(|bytes| decode_version_be(&bytes)).transpose()
}

fn oldest_auth_version(connection: &Connection) -> Result<Option<Version>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    encoded.map(|bytes| decode_version_be(&bytes)).transpose()
}

fn auth_root(connection: &Connection, version: Version) -> Result<Option<RootHash>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT root_hash FROM auth_roots WHERE version_be=?1",
            params![version.to_be_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    encoded
        .map(|bytes| {
            Ok(RootHash(<[u8; 32]>::try_from(bytes.as_slice()).map_err(
                |_| anyhow!("persisted JMT root hash is not 32 bytes"),
            )?))
        })
        .transpose()
}

fn auth_node_reachable_at_version(
    connection: &Connection,
    version: Version,
    candidate: &NodeKey,
) -> Result<bool> {
    let mut path: NibblePath = std::iter::empty().collect();
    let mut current = NodeKey::new(version, path.clone());
    if &current == candidate {
        return Ok(true);
    }
    for expected_nibble in candidate.nibble_path().nibbles() {
        let encoded = borsh::to_vec(&current).context("encode retained JMT traversal node key")?;
        let node_bytes: Vec<u8> = connection
            .query_row(
                "SELECT node FROM auth_nodes WHERE node_key=?1",
                params![encoded.as_slice()],
                |row| row.get(0),
            )
            .with_context(|| {
                format!(
                    "retained JMT traversal is missing node at version {}",
                    current.version()
                )
            })?;
        let node: Node =
            borsh::from_slice(&node_bytes).context("decode retained JMT traversal node")?;
        let Node::Internal(internal) = node else {
            return Ok(false);
        };
        let Some((nibble, child)) = internal
            .children_sorted()
            .find(|(nibble, _)| *nibble == expected_nibble)
        else {
            return Ok(false);
        };
        path = path.nibbles().chain(std::iter::once(nibble)).collect();
        current = NodeKey::new(child.version, path.clone());
        if &current == candidate {
            return Ok(true);
        }
    }
    Ok(false)
}

fn physical_prune_candidates_remain(connection: &Connection, target: Version) -> Result<bool> {
    let target_be = target.to_be_bytes();
    Ok(connection.query_row(
        "SELECT
             EXISTS(
                 SELECT 1 FROM auth_roots
                 WHERE version_be<?1
             )
             OR EXISTS(
                 SELECT 1 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
             )
             OR EXISTS(
                 SELECT 1 FROM auth_stale_values
                 WHERE stale_since_version_be<=?1
             )",
        params![target_be.as_slice()],
        |row| row.get::<_, bool>(0),
    )?)
}

fn metadata(connection: &Connection, key: &str) -> Result<String> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .with_context(|| format!("application store is missing {key}"))
}

fn optional_metadata_version(connection: &Connection, key: &str) -> Result<Option<Version>> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| {
            value
                .parse::<Version>()
                .with_context(|| format!("parse application store {key}"))
        })
        .transpose()
}

fn write_metadata_version(transaction: &Transaction<'_>, key: &str, value: Version) -> Result<()> {
    transaction.execute(
        "INSERT INTO metadata(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn validate_auth_prune_metadata(connection: &Connection) -> Result<()> {
    let floor = optional_metadata_version(connection, AUTH_QUERY_FLOOR_KEY)?
        .context("application store is missing authenticated query floor")?;
    let target = optional_metadata_version(connection, AUTH_PRUNE_TARGET_KEY)?;
    if let Some(target) = target {
        ensure!(
            target == floor,
            "authenticated prune target differs from the query floor"
        );
    }
    let height = connection
        .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()?
        .map(|value| {
            value
                .parse::<Version>()
                .context("parse application store height during prune metadata validation")
        })
        .transpose()?;
    match height {
        Some(height) => {
            ensure!(
                floor <= height && auth_root(connection, floor)?.is_some(),
                "application store authenticated query floor is invalid"
            );
            if target.is_none() {
                ensure!(
                    oldest_auth_version(connection)? == Some(floor),
                    "completed authenticated maintenance differs from its query floor"
                );
                ensure!(
                    !physical_prune_candidates_remain(connection, floor)?,
                    "completed authenticated maintenance still has prune candidates"
                );
            }
        }
        None => ensure!(
            floor == 0 && target.is_none(),
            "empty application store contains authenticated maintenance state"
        ),
    }
    Ok(())
}

fn migrate_store_schema_v3_to_v4(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        metadata(&transaction, "schema_version")? == PREVIOUS_STORE_SCHEMA_VERSION,
        "application store schema changed before v3 to v4 migration"
    );
    transaction.execute_batch(
        "
        CREATE UNIQUE INDEX IF NOT EXISTS auth_stale_nodes_by_node_key
            ON auth_stale_nodes(node_key);
        CREATE TABLE IF NOT EXISTS auth_stale_values (
            stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
            key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
            version_be BLOB NOT NULL CHECK(length(version_be)=8),
            PRIMARY KEY (stale_since_version_be, key_hash, version_be),
            UNIQUE (key_hash, version_be)
        ) STRICT;
        ",
    )?;
    let encoded: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let inferred_floor = encoded
        .map(|bytes| decode_version_be(&bytes))
        .transpose()?
        .unwrap_or(0);
    rebuild_auth_stale_values(&transaction)?;
    write_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY, inferred_floor)?;
    transaction.execute(
        "DELETE FROM metadata WHERE key=?1",
        params![AUTH_PRUNE_TARGET_KEY],
    )?;
    transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='schema_version'",
        params![STORE_SCHEMA_VERSION],
    )?;
    transaction.commit()?;
    Ok(())
}

fn ensure_metadata_binding(connection: &Connection, key: &str, expected: &str) -> Result<()> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    match actual {
        Some(actual) => ensure!(
            actual == expected,
            "application store {key} differs from configured value"
        ),
        None => {
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES (?1, ?2)",
                params![key, expected],
            )?;
        }
    }
    Ok(())
}

fn validate_snapshot_schema(connection: &Connection) -> Result<()> {
    let schema_version = metadata(connection, "schema_version")?;
    ensure!(
        schema_version == STORE_SCHEMA_VERSION || schema_version == PREVIOUS_STORE_SCHEMA_VERSION,
        "SQLite snapshot store schema is unsupported"
    );
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(STORE_SCHEMA_SQL)?;
    if schema_version == PREVIOUS_STORE_SCHEMA_VERSION {
        canonical.execute_batch(
            "
            DROP INDEX auth_stale_nodes_by_node_key;
            DROP TABLE auth_stale_values;
            ",
        )?;
    }
    let expected = schema_objects(&canonical)?;
    let actual = schema_objects(connection)?;
    ensure!(
        actual == expected,
        "SQLite snapshot schema differs from the canonical store schema"
    );
    Ok(())
}

fn validate_snapshot_metadata_keys(connection: &Connection, schema_version: &str) -> Result<()> {
    let mut expected = std::collections::BTreeSet::from([
        "app_hash_hex".to_string(),
        "app_version".to_string(),
        "auth_codec".to_string(),
        "auth_tree".to_string(),
        "authorized_signers_hash_hex".to_string(),
        "chain_id".to_string(),
        "height".to_string(),
        "schema_version".to_string(),
    ]);
    if schema_version == STORE_SCHEMA_VERSION {
        expected.insert(AUTH_QUERY_FLOOR_KEY.to_string());
    }
    let mut statement = connection.prepare("SELECT key FROM metadata ORDER BY key")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let actual = rows.collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        actual == expected,
        "SQLite snapshot metadata keys differ from the canonical allowlist"
    );
    Ok(())
}

fn prepare_snapshot_validation_copy(
    source_path: &Path,
) -> Result<(SnapshotValidationCopy, [u8; 32])> {
    for suffix in ["-wal", "-shm", "-journal"] {
        ensure!(
            !sqlite_sidecar(source_path, suffix).exists(),
            "SQLite snapshot must be a standalone database without {suffix}"
        );
    }
    let parent = source_path
        .parent()
        .context("SQLite snapshot validation path has no parent")?;
    let file_name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("SQLite snapshot validation path is not UTF-8")?;
    let nonce = SNAPSHOT_VALIDATION_NONCE.fetch_add(1, Ordering::Relaxed);
    let copy_path = parent.join(format!(
        ".{file_name}.validate-source-{}-{nonce}.sqlite3",
        std::process::id()
    ));
    let mut source = fs::File::open(source_path)
        .with_context(|| format!("open SQLite snapshot {}", source_path.display()))?;
    let mut destination = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&copy_path)
        .with_context(|| {
            format!(
                "create private SQLite snapshot validation copy {}",
                copy_path.display()
            )
        })?;
    let copied = (|| -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.cometbft.snapshot.payload.v4");
        hasher.update([0]);
        let mut total_bytes = 0_u64;
        let mut buffer = vec![0_u8; SNAPSHOT_CHUNK_SIZE];
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total_bytes = total_bytes
                .checked_add(u64::try_from(count)?)
                .context("SQLite snapshot validation copy length overflow")?;
            ensure!(
                total_bytes <= MAX_SNAPSHOT_VALIDATION_COPY_BYTES,
                "SQLite snapshot byte length exceeds validation limit"
            );
            destination.write_all(&buffer[..count])?;
            hasher.update(&buffer[..count]);
        }
        ensure!(total_bytes > 0, "SQLite snapshot payload is empty");
        destination.flush()?;
        destination.sync_all()?;
        destination.seek(SeekFrom::Start(0))?;
        Ok(hasher.finalize().into())
    })();
    let payload_hash = match copied {
        Ok(payload_hash) => payload_hash,
        Err(error) => {
            drop(destination);
            let _ = remove_file_if_exists(&copy_path);
            return Err(error);
        }
    };
    for suffix in ["-wal", "-shm", "-journal"] {
        if sqlite_sidecar(source_path, suffix).exists() {
            drop(destination);
            let _ = remove_file_if_exists(&copy_path);
            return Err(anyhow!(
                "SQLite snapshot sidecar {suffix} appeared while making the validation copy"
            ));
        }
    }
    Ok((
        SnapshotValidationCopy {
            file: Some(destination),
            path: copy_path,
        },
        payload_hash,
    ))
}

fn snapshot_payload_hash_open_file_v4(file: &fs::File) -> Result<[u8; 32]> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.cometbft.snapshot.payload.v4");
    hasher.update([0]);
    let mut buffer = vec![0_u8; SNAPSHOT_CHUNK_SIZE];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn validate_snapshot_file_layout(connection: &Connection, observed_bytes: u64) -> Result<()> {
    let page_size = connection.query_row("PRAGMA page_size", [], |row| row.get::<_, u64>(0))?;
    let page_count = connection.query_row("PRAGMA page_count", [], |row| row.get::<_, u64>(0))?;
    let freelist_count =
        connection.query_row("PRAGMA freelist_count", [], |row| row.get::<_, u64>(0))?;
    let journal_mode =
        connection.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;
    ensure!(
        page_size == SNAPSHOT_SQLITE_PAGE_SIZE_BYTES,
        "SQLite snapshot page size differs from the canonical 4096-byte layout"
    );
    ensure!(page_count > 0, "SQLite snapshot contains no database pages");
    ensure!(
        page_count <= MAX_SNAPSHOT_DATABASE_PAGES,
        "SQLite snapshot page count exceeds the resource limit"
    );
    ensure!(
        freelist_count == 0,
        "SQLite snapshot contains non-canonical freelist pages"
    );
    ensure!(
        journal_mode.eq_ignore_ascii_case("delete"),
        "SQLite snapshot journal mode differs from the canonical DELETE layout"
    );
    let canonical_bytes = page_size
        .checked_mul(page_count)
        .context("SQLite snapshot canonical file length overflow")?;
    ensure!(
        observed_bytes == canonical_bytes,
        "SQLite snapshot file length differs from its canonical page layout"
    );
    ensure!(
        observed_bytes <= MAX_SNAPSHOT_DATABASE_BYTES,
        "SQLite snapshot file length exceeds the resource limit"
    );
    Ok(())
}

fn validate_snapshot_row_counts(connection: &Connection) -> Result<()> {
    let mut counts = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM metadata),
            (SELECT COUNT(*) FROM objects),
            (SELECT COUNT(*) FROM command_ids),
            (SELECT COUNT(*) FROM signer_nonces),
            (SELECT COUNT(*) FROM validator_lifecycle),
            (SELECT COUNT(*) FROM auth_nodes),
            (SELECT COUNT(*) FROM auth_values),
            (SELECT COUNT(*) FROM auth_preimages),
            (SELECT COUNT(*) FROM auth_stale_nodes),
            (SELECT COUNT(*) FROM auth_roots)",
        [],
        |row| {
            Ok(SnapshotRowCounts {
                metadata: row.get(0)?,
                objects: row.get(1)?,
                command_ids: row.get(2)?,
                signer_nonces: row.get(3)?,
                validator_lifecycle: row.get(4)?,
                auth_nodes: row.get(5)?,
                auth_values: row.get(6)?,
                auth_preimages: row.get(7)?,
                auth_stale_nodes: row.get(8)?,
                auth_roots: row.get(9)?,
                ..SnapshotRowCounts::default()
            })
        },
    )?;
    if metadata(connection, "schema_version")? == STORE_SCHEMA_VERSION {
        counts.auth_stale_values =
            connection.query_row("SELECT COUNT(*) FROM auth_stale_values", [], |row| {
                row.get(0)
            })?;
    }
    counts.validate()
}

fn validate_storage_resource_bounds(connection: &Connection) -> Result<()> {
    let tables: &[(&str, &[(&str, u64)])] = &[
        (
            "metadata",
            &[
                ("key", MAX_SNAPSHOT_IDENTIFIER_BYTES),
                ("value", MAX_SNAPSHOT_IDENTIFIER_BYTES),
            ],
        ),
        (
            "objects",
            &[
                ("object_key_hex", MAX_SNAPSHOT_IDENTIFIER_BYTES),
                ("object_type", MAX_SNAPSHOT_IDENTIFIER_BYTES),
                ("version", MAX_SNAPSHOT_IDENTIFIER_BYTES),
                ("value_hash_hex", MAX_SNAPSHOT_IDENTIFIER_BYTES),
                ("value_bytes", MAX_SNAPSHOT_OBJECT_VALUE_BYTES),
            ],
        ),
        (
            "command_ids",
            &[("command_id", MAX_SNAPSHOT_IDENTIFIER_BYTES)],
        ),
        (
            "signer_nonces",
            &[("signer_id", MAX_SNAPSHOT_IDENTIFIER_BYTES)],
        ),
        (
            "validator_lifecycle",
            &[("state_json", MAX_SNAPSHOT_LIFECYCLE_BYTES)],
        ),
        (
            "auth_nodes",
            &[
                ("node_key", MAX_SNAPSHOT_IDENTIFIER_BYTES),
                ("node", MAX_SNAPSHOT_AUTH_NODE_BYTES),
            ],
        ),
        ("auth_values", &[("value", MAX_SNAPSHOT_AUTH_VALUE_BYTES)]),
        (
            "auth_preimages",
            &[("key_preimage", MAX_SNAPSHOT_KEY_PREIMAGE_BYTES)],
        ),
        (
            "auth_stale_nodes",
            &[("node_key", MAX_SNAPSHOT_IDENTIFIER_BYTES)],
        ),
    ];
    for (table, columns) in tables {
        let projections = columns
            .iter()
            .map(|(column, _)| format!("COALESCE(MAX(length(CAST({column} AS BLOB))), 0)"))
            .collect::<Vec<_>>()
            .join(", ");
        let query = format!("SELECT {projections} FROM {table}");
        let observed = connection.query_row(&query, [], |row| {
            (0..columns.len())
                .map(|index| row.get::<_, u64>(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        for ((column, maximum), observed) in columns.iter().zip(observed) {
            ensure!(
                observed <= *maximum,
                "SQLite store {table}.{column} exceeds the {maximum}-byte resource limit"
            );
        }
    }
    Ok(())
}

fn schema_objects(
    connection: &Connection,
) -> Result<std::collections::BTreeMap<(String, String), String>> {
    let mut objects = std::collections::BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT type, name, sql
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        let (kind, name, sql) = row?;
        let sql = sql
            .context("SQLite snapshot table is missing CREATE statement")?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        ensure!(
            objects.insert((kind, name), sql).is_none(),
            "SQLite snapshot contains duplicate schema object"
        );
    }
    Ok(objects)
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove stale temporary file {}", path.display()))
        }
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn remove_sqlite_sidecars(path: &Path) -> Result<()> {
    remove_file_if_exists(&sqlite_sidecar(path, "-wal"))?;
    remove_file_if_exists(&sqlite_sidecar(path, "-shm"))?;
    remove_file_if_exists(&sqlite_sidecar(path, "-journal"))
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cold]
fn fail_stop_after_snapshot_install(error: anyhow::Error) -> ! {
    eprintln!(
        "[trnm-cometbft-app] fatal error after authoritative snapshot installation; \
         restart is required before serving ABCI: {error:#}"
    );
    #[cfg(not(test))]
    std::process::abort();
    #[cfg(test)]
    panic!("fatal post-install snapshot error: {error:#}");
}

#[cfg(test)]
mod snapshot_resource_limit_tests {
    use super::*;

    #[test]
    fn formal_million_snapshot_counts_fit_bounded_validation() {
        assert_eq!(MAX_SNAPSHOT_SCRATCH_PAGES, 262_144);
        assert_eq!(MAX_SNAPSHOT_DATABASE_PAGES, 1_048_576);
        let measured_formal = SnapshotRowCounts {
            metadata: 9,
            objects: 1_000_001,
            validator_lifecycle: 1,
            auth_nodes: 1_359_787,
            auth_values: 1_000_002,
            auth_preimages: 1_000_002,
            auth_roots: 1,
            ..SnapshotRowCounts::default()
        };
        measured_formal.validate().unwrap();

        for invalid in [
            SnapshotRowCounts {
                metadata: 10,
                ..measured_formal
            },
            SnapshotRowCounts {
                objects: MAX_SNAPSHOT_OBJECT_ROWS + 1,
                ..measured_formal
            },
            SnapshotRowCounts {
                auth_nodes: MAX_SNAPSHOT_AUTH_NODE_ROWS + 1,
                ..measured_formal
            },
            SnapshotRowCounts {
                auth_values: MAX_SNAPSHOT_AUTH_VALUE_ROWS + 1,
                ..measured_formal
            },
            SnapshotRowCounts {
                auth_preimages: MAX_SNAPSHOT_AUTH_VALUE_ROWS + 1,
                ..measured_formal
            },
            SnapshotRowCounts {
                command_ids: 1,
                ..measured_formal
            },
            SnapshotRowCounts {
                validator_lifecycle: 0,
                ..measured_formal
            },
            SnapshotRowCounts {
                auth_roots: 2,
                ..measured_formal
            },
            SnapshotRowCounts {
                auth_stale_nodes: 1,
                ..measured_formal
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }
}
