//! PN6 source-preserving rehearsal only. This format is deliberately not a Node
//! storage schema: it cannot admit blocks or confer cross-context activation.
//! Old signed history and chain work remain exclusively in the source archive.
use super::*;
use crate::account_archive_execution::state_witness::GrowthStateCommitmentV2;
use crate::account_archive_prototype::{native_store, Context};
use crate::Settings;
use rusqlite::{params, OpenFlags};
use serde_json::json;
use std::cell::{Cell, RefCell};
use trnm_protocol::pon_wire::hash;

mod snapshot;

/// Local temporary-copy cap only, not a history-work bound or storage reservation.
pub const DEFAULT_GROWTH_REHEARSAL_SNAPSHOT_BYTE_LIMIT_V2: u64 = 8 * 1024 * 1024 * 1024;

const SCHEMA: &str = "native-growth-migration-rehearsal-v2";
const CHECKPOINT_DDL:&str="CREATE TABLE metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL);CREATE TABLE growth_checkpoint(singleton INTEGER PRIMARY KEY CHECK(singleton=1),data BLOB NOT NULL);";
const PENDING_REHEARSAL: &str = "growth-rehearsal.pending";
const REHEARSAL_RECEIPT: &str = "growth-rehearsal.json";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrowthRehearsalProgressV2 {
    SourceLocked,
    Source(AuthenticatedMigrationProgress),
    SourceCopied,
    CheckpointCommitted,
    BeforePublish,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrowthRehearsalReceiptV2 {
    pub schema: String,
    pub namespace: String,
    pub source_backend: String,
    pub source_network: Hash,
    pub source_parameters: Hash,
    pub source_genesis: Hash,
    pub source_tip: Hash,
    pub source_state_root: Hash,
    pub source_height: u64,
    pub source_generation: u64,
    pub source_schema: Hash,
    pub source_tables: Vec<RehearsalTableV2>,
    pub retained_blocks: u64,
    pub replayed_transactions: u64,
    pub profile_binding: GrowthProfileBindingV2,
    pub candidate_commitment: GrowthStateCommitmentV2,
    pub source_archive_sha256: Hash,
    pub checkpoint_sha256: Hash,
    pub source_receipt_sha256: Option<Hash>,
    pub candidate_materialized: bool,
    pub independent_cold_readback: bool,
    pub migration_executed: bool,
    pub old_work_promoted: bool,
    pub consensus_activation: bool,
    pub production_enabled: bool,
    pub external_journals_imported: bool,
    pub external_owner_operations_executed: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RehearsalTableV2 {
    pub table: String,
    pub rows: u64,
    pub digest: Hash,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRecord {
    source_tip: Hash,
    source_root: Hash,
    source_height: u64,
    source_generation: u64,
    binding: GrowthProfileBindingV2,
    commitment: GrowthStateCommitmentV2,
    accounts: native_store::Root,
    working: State,
}
fn archive_backend(name: &str) -> Result<StateBackend> {
    match name {
        "legacy" => Ok(StateBackend::Legacy),
        "authenticated-v1" => Ok(StateBackend::AuthenticatedV1),
        _ => Err("GROWTH_REHEARSAL_SOURCE_PROFILE".into()),
    }
}
fn backend_name(backend: StateBackend) -> Result<&'static str> {
    match backend {
        StateBackend::Legacy => Ok("legacy"),
        StateBackend::AuthenticatedV1 => Ok("authenticated-v1"),
        StateBackend::PermanentAccountGrowthV2 => Err("GROWTH_REHEARSAL_SOURCE_PROFILE".into()),
        StateBackend::PqNetworkV2 | StateBackend::PqContinuousV3 => {
            Err("GROWTH_REHEARSAL_SOURCE_PROFILE".into())
        }
    }
}
fn schema_id() -> Hash {
    hash(
        b"native-growth-rehearsal-schema-v2",
        &[CHECKPOINT_DDL.as_bytes()],
    )
}
fn stage_identity(
    parent: &File,
    parent_path: &Path,
    stage: &File,
    stage_path: &Path,
) -> Result<()> {
    growth_reservation_io::check_named_parent(parent, parent_path)?;
    let visible = fs::symlink_metadata(stage_path)?;
    let held = stage.metadata()?;
    ensure(
        visible.is_dir() && (visible.dev(), visible.ino()) == (held.dev(), held.ino()),
        "GROWTH_REHEARSAL_DIRECTORY",
    )
}
fn publish_directory(parent: &File, stage: &Path, destination: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        rustix::fs::renameat_with(
            parent,
            stage.file_name().ok_or("GROWTH_REHEARSAL_DIRECTORY")?,
            parent,
            destination
                .file_name()
                .ok_or("GROWTH_REHEARSAL_DIRECTORY")?,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|e| Error::from(std::io::Error::from(e)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, stage, destination);
        Err("GROWTH_REHEARSAL_PLATFORM".into())
    }
}
fn candidate_settings(source: &Settings, binding: &GrowthProfileBindingV2) -> Settings {
    let mut candidate = source.clone();
    candidate.app.network = hash(
        b"native-growth-rehearsal-network-v2",
        &[&binding.source_network, &binding.id],
    );
    candidate.app.parameters = binding.candidate_parameters;
    candidate.genesis = binding.candidate_genesis;
    candidate
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileReadProgress {
    BeforeOpen,
    Observed { bytes: u64 },
    Consumed { bytes: u64 },
}
fn file_hash(path: &Path) -> Result<Hash> {
    file_hash_with_progress(path, &mut |_| Ok(()))
}
// Private deterministic file-replacement/read boundary; production supplies no
// callback effects. Tests exercise this same path instead of a copy of the hash.
pub(super) fn file_hash_with_progress(
    path: &Path,
    progress: &mut impl FnMut(FileReadProgress) -> Result<()>,
) -> Result<Hash> {
    snapshot::file_hash_with_progress(path, progress)
}
fn optional_hash(path: &Path) -> Result<Option<Hash>> {
    match fs::symlink_metadata(path) {
        Ok(_) => file_hash(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn table_digests(db: &Connection) -> Result<Vec<RehearsalTableV2>> {
    let mut summaries = Vec::new();
    for table in table_names(db)? {
        let (select, columns) = ordered_select(db, &table)?;
        let mut statement = db.prepare(&select)?;
        let mut rows = statement.query([])?;
        let mut digest = Sha256::new();
        digest.update(b"native-growth-rehearsal-table-v2\0");
        digest.update((table.len() as u64).to_le_bytes());
        digest.update(table.as_bytes());
        let mut count = 0u64;
        while let Some(row) = rows.next()? {
            hash_values(&mut digest, &values(row, columns)?);
            count = count.checked_add(1).ok_or("GROWTH_REHEARSAL_COUNT")?;
        }
        digest.update(count.to_le_bytes());
        summaries.push(RehearsalTableV2 {
            table,
            rows: count,
            digest: digest.finalize().into(),
        });
    }
    Ok(summaries)
}
fn verify_source(
    node: &Node,
    progress: &(impl Fn(AuthenticatedMigrationProgress) -> Result<()> + Sync),
) -> Result<(u64, u64)> {
    ensure(
        !trnm_mvcc_fee::growth_profile_v2::enabled(&node.settings.app),
        "GROWTH_REFERENCE_MIGRATION_UNSUPPORTED",
    )?;
    node.namespace()?;
    node.storage_context()?;
    node.ready()?;
    check_schema(&node.db, node.state_backend)?;
    check_database(&node.db)?;
    ensure(
        node.owner_policy.is_none()
            && node.mining_owner.is_none()
            && node.continuous_owner.is_none()
            && node.public_service_cpu.is_none()
            && node.public_service_epoch_listeners == 0
            && !node.public_service_epoch_unknown
            && !super::super::owner_marker_present(&node.directory)?,
        "GROWTH_REHEARSAL_EXTERNAL_OWNER",
    )?;
    node.validate_authenticated_replay()?;
    node.validate_authenticated_outbox()?;
    // These source-local observations remain archive facts, never candidate
    // dispatch or payment authority. Check their set and real source history.
    node.validate_native_budget_records_v1()?;
    let pool: u64 = node
        .db
        .query_row("SELECT count(*) FROM local_pool_metadata", [], |r| r.get(0))?;
    if pool == 1 {
        node.pool_status_snapshot()?;
    } else {
        ensure(pool == 0, "GROWTH_REHEARSAL_POOL")?;
        for table in [
            "local_pool_groups",
            "local_pool_rows",
            "local_pool_removals",
        ] {
            let count: u64 =
                node.db
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
            ensure(count == 0, "GROWTH_REHEARSAL_POOL")?;
        }
    }
    ensure(
        !check_local_history(node)?,
        "GROWTH_REHEARSAL_DRAIN_REQUIRED",
    )?;
    let mut statement = node
        .db
        .prepare("SELECT id FROM blocks ORDER BY height,id")?;
    let mut rows = statement.query([])?;
    let mut blocks = 0u64;
    let mut transactions = 0u64;
    let mut genesis = 0u64;
    while let Some(row) = rows.next()? {
        let id = bytes32(row.get(0)?)?;
        let height = node.record(id)?.height;
        progress(AuthenticatedMigrationProgress::BeforeBlock { height })?;
        if id == node.settings.genesis() {
            check_genesis(node)?;
            genesis += 1;
        } else {
            let (_, _, _, count) = checked_successor(node, id, progress)?;
            transactions = transactions
                .checked_add(count)
                .ok_or("GROWTH_REHEARSAL_COUNT")?;
        }
        crate::ancestry_index::validate_tip(&node.db, node.ancestry_context()?, id)?;
        check_snapshot(node, id)?;
        blocks = blocks.checked_add(1).ok_or("GROWTH_REHEARSAL_COUNT")?;
        progress(AuthenticatedMigrationProgress::AfterBlock { height })?;
    }
    ensure(genesis == 1, "GROWTH_REHEARSAL_GENESIS")?;
    check_unreferenced_rows(&node.db)?;
    if node.state_backend == StateBackend::AuthenticatedV1 {
        let count: u64 =
            node.db
                .query_row("SELECT count(*) FROM native_state_commitments", [], |r| {
                    r.get(0)
                })?;
        ensure(count == blocks, "GROWTH_REHEARSAL_COMMITMENTS")?;
    }
    node.read_active()?;
    Ok((blocks, transactions))
}

fn lock_archive_owner(directory: &Path) -> Result<File> {
    plain(&directory.join("owner.lock"))?;
    let owner = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join("owner.lock"))?;
    FileExt::try_lock_shared(&owner).map_err(|_| Error::from("WRITER_BUSY"))?;
    check_archive_owner(directory, &owner)?;
    Ok(owner)
}
fn check_archive_owner(directory: &Path, owner: &File) -> Result<()> {
    plain(&directory.join("owner.lock"))?;
    let held = owner.metadata()?;
    let named = fs::symlink_metadata(directory.join("owner.lock"))?;
    ensure(
        held.is_file()
            && held.nlink() == 1
            && (held.dev(), held.ino()) == (named.dev(), named.ino()),
        "GROWTH_REHEARSAL_OWNER_CHANGED",
    )
}

/// Private verifier owner. Only a receipt-bound private copy reaches SQLite;
/// it never invokes native initialization, recovery, signing or external work.
fn read_only_archive(directory: &Path, settings: Settings, backend: StateBackend) -> Result<Node> {
    ensure(
        fs::symlink_metadata(directory)?.is_dir(),
        "GROWTH_REHEARSAL_DIRECTORY",
    )?;
    let directory = directory.canonicalize()?;
    let metadata = fs::symlink_metadata(&directory)?;
    ensure(metadata.is_dir(), "GROWTH_REHEARSAL_DIRECTORY")?;
    for name in ["native.sqlite", "owner.lock"] {
        plain(&directory.join(name))?;
    }
    let owner = lock_archive_owner(&directory)?;
    let db = Connection::open_with_flags(
        directory.join("native.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA query_only=ON;")?;
    let dm = fs::metadata(directory.join("native.sqlite"))?;
    #[cfg(test)]
    let expected_schema = schema(&db)?;
    Ok(Node {
        db,
        owner,
        growth_observer_snapshot: None,
        directory,
        directory_id: (metadata.dev(), metadata.ino()),
        database_id: (dm.dev(), dm.ino()),
        settings,
        workers: 1,
        state_backend: backend,
        growth_epoch: None,
        #[cfg(test)]
        expected_schema,
        #[cfg(test)]
        public_history_test_sql_limit: None,
        #[cfg(test)]
        public_history_test_snapshot: false,
        commitment_cache: RefCell::new(None),
        historical_commitment_cache: RefCell::default(),
        root_rejection_cache: RefCell::new(None),
        authenticated_arithmetic: native_authenticated::ArithmeticCache::default(),
        commitment_observation: RefCell::new(None),
        history_read_counters: Cell::new(super::super::HistoryReadCounters::default()),
        history_page_read_counters: Cell::new(super::super::HistoryPageReadCounters::default()),
        owner_policy: None,
        mining_owner: None,
        continuous_owner: None,
        public_service_cpu: None,
        public_service_epoch_listeners: 0,
        public_service_epoch_unknown: false,
        detached_execution: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        #[cfg(test)]
        cancel_next_activation_intent: false,
        pq_network_epoch: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
    })
}
fn read_receipt(directory: &Path) -> Result<GrowthRehearsalReceiptV2> {
    read_receipt_with_progress(directory, &mut |_| Ok(()))
}
pub(super) fn read_receipt_with_progress(
    directory: &Path,
    progress: &mut impl FnMut(FileReadProgress) -> Result<()>,
) -> Result<GrowthRehearsalReceiptV2> {
    let path = directory.join(REHEARSAL_RECEIPT);
    let bytes = snapshot::read_receipt_bytes_with_progress(&path, progress)?;
    let receipt: GrowthRehearsalReceiptV2 = serde_json::from_slice(&bytes)?;
    ensure(
        canonical(&receipt)? == bytes
            && receipt.schema == SCHEMA
            && receipt.candidate_materialized
            && receipt.independent_cold_readback
            && !receipt.migration_executed
            && !receipt.old_work_promoted
            && !receipt.consensus_activation
            && !receipt.production_enabled
            && !receipt.external_journals_imported
            && receipt.external_owner_operations_executed == 0,
        "GROWTH_REHEARSAL_AUTHORITY",
    )?;
    Ok(receipt)
}
fn verify_directory(
    directory: &Path,
    source_settings: Settings,
    allow_pending: bool,
    snapshot_byte_limit: u64,
    after_snapshot: impl FnOnce(&Path) -> Result<()>,
) -> Result<GrowthRehearsalReceiptV2> {
    let directory_meta = fs::symlink_metadata(directory)?;
    ensure(directory_meta.is_dir(), "GROWTH_REHEARSAL_DIRECTORY")?;
    let pending = directory.join(PENDING_REHEARSAL);
    let has_pending = match fs::symlink_metadata(&pending) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    ensure(allow_pending || !has_pending, "GROWTH_REHEARSAL_PENDING")?;
    let names: BTreeSet<_> = fs::read_dir(directory)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::result::Result<_, _>>()?;
    let mut expected: BTreeSet<_> = ["native.sqlite", "owner.lock", "source", REHEARSAL_RECEIPT]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect();
    if allow_pending {
        expected.insert(PENDING_REHEARSAL.into());
    }
    ensure(names == expected, "GROWTH_REHEARSAL_DIRECTORY")?;
    let receipt = read_receipt(directory)?;
    ensure(
        receipt.source_network == source_settings.network()
            && receipt.source_parameters == source_settings.parameters()
            && receipt.source_genesis == source_settings.genesis(),
        "GROWTH_REHEARSAL_CONTEXT",
    )?;
    let source_path = directory.join("source");
    let native_path = directory.join("native.sqlite");
    let source_meta = fs::symlink_metadata(&source_path)?;
    ensure(source_meta.is_dir(), "GROWTH_REHEARSAL_DIRECTORY")?;
    let source_names: BTreeSet<_> = fs::read_dir(&source_path)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::result::Result<_, _>>()?;
    let mut expected_source: BTreeSet<_> = ["native.sqlite", "owner.lock"]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect();
    if receipt.source_receipt_sha256.is_some() {
        expected_source.insert("authenticated-migration.json".into());
    }
    ensure(
        source_names == expected_source,
        "GROWTH_REHEARSAL_DIRECTORY",
    )?;
    let original_owner = lock_archive_owner(&source_path)?;
    ensure(
        optional_hash(&source_path.join("authenticated-migration.json"))?
            == receipt.source_receipt_sha256,
        "GROWTH_REHEARSAL_FILE_DIGEST",
    )?;
    snapshot::with_snapshot(
        directory,
        receipt.source_archive_sha256,
        receipt.checkpoint_sha256,
        snapshot_byte_limit,
        |private| {
            after_snapshot(private)?;
            verify_snapshot(private, source_settings, &receipt)?;
            ensure(
                file_hash(&source_path.join("native.sqlite"))? == receipt.source_archive_sha256
                    && file_hash(&native_path)? == receipt.checkpoint_sha256
                    && optional_hash(&source_path.join("authenticated-migration.json"))?
                        == receipt.source_receipt_sha256,
                "GROWTH_REHEARSAL_FILE_CHANGED",
            )?;
            let after = fs::symlink_metadata(directory)?;
            let source_after = fs::symlink_metadata(&source_path)?;
            let names: BTreeSet<_> = fs::read_dir(directory)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::result::Result<_, _>>()?;
            let source_names: BTreeSet<_> = fs::read_dir(&source_path)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::result::Result<_, _>>()?;
            ensure(
                after.is_dir()
                    && source_after.is_dir()
                    && (directory_meta.dev(), directory_meta.ino()) == (after.dev(), after.ino())
                    && (source_meta.dev(), source_meta.ino())
                        == (source_after.dev(), source_after.ino())
                    && names == expected
                    && source_names == expected_source,
                "GROWTH_REHEARSAL_DIRECTORY",
            )?;
            check_archive_owner(&source_path, &original_owner)?;
            Ok(receipt)
        },
    )
}

fn verify_snapshot(
    directory: &Path,
    source_settings: Settings,
    receipt: &GrowthRehearsalReceiptV2,
) -> Result<()> {
    let source_path = directory.join("source");
    let native_path = directory.join("native.sqlite");
    let source = read_only_archive(
        &source_path,
        source_settings.clone(),
        archive_backend(&receipt.source_backend)?,
    )?;
    ensure(
        source.state_backend.schema_id() == receipt.source_schema,
        "GROWTH_REHEARSAL_CONTEXT",
    )?;
    let snapshot = source.db.unchecked_transaction()?;
    let (blocks, transactions) = verify_source(&source, &|_| Ok(()))?;
    let (tip, generation, state) = source.read_active()?;
    let record = source.record(tip)?;
    ensure(
        tip == receipt.source_tip
            && generation == receipt.source_generation
            && record.root == receipt.source_state_root
            && record.height == receipt.source_height
            && blocks == receipt.retained_blocks
            && transactions == receipt.replayed_transactions
            && table_digests(&source.db)? == receipt.source_tables,
        "GROWTH_REHEARSAL_SOURCE_BINDING",
    )?;
    let source_commitment = growth_commitment_from_complete_state_v2(&source.settings, &state)
        .map_err(|e| Error::from(format!("GROWTH_REHEARSAL_STATE:{e:?}")))?;
    let binding =
        growth_profile_binding_v2(&source.settings, &source_commitment, &receipt.namespace)
            .map_err(|e| Error::from(format!("GROWTH_REHEARSAL_BINDING:{e:?}")))?;
    ensure(
        binding == receipt.profile_binding,
        "GROWTH_REHEARSAL_BINDING",
    )?;
    let settings = candidate_settings(&source.settings, &binding);
    let expected = growth_commitment_from_complete_state_v2(&settings, &state)
        .map_err(|e| Error::from(format!("GROWTH_REHEARSAL_STATE:{e:?}")))?;
    ensure(
        expected.observation() == &receipt.candidate_commitment,
        "GROWTH_REHEARSAL_COMMITMENT",
    )?;
    let db = Connection::open_with_flags(
        &native_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.execute_batch("PRAGMA trusted_schema=OFF;PRAGMA query_only=ON;")?;
    let checkpoint_read = db.unchecked_transaction()?;
    let exact = Connection::open_in_memory()?;
    exact.execute_batch(CHECKPOINT_DDL)?;
    ensure(schema(&db)? == schema(&exact)?, "GROWTH_REHEARSAL_SCHEMA")?;
    check_database(&db)?;
    let metadata: u64 = db.query_row("SELECT count(*) FROM metadata", [], |r| r.get(0))?;
    ensure(metadata == 3, "GROWTH_REHEARSAL_METADATA")?;
    for (key, value) in [
        ("schema", schema_id()),
        ("parameters", settings.parameters()),
        ("genesis", settings.genesis()),
    ] {
        let actual: Vec<u8> = db.query_row(
            "SELECT substr(value,1,33) FROM metadata WHERE key=?",
            [key],
            |r| r.get(0),
        )?;
        ensure(actual == value, "GROWTH_REHEARSAL_METADATA")?;
    }
    let bytes: Vec<u8> = db.query_row(
        "SELECT substr(data,1,524289) FROM growth_checkpoint WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    ensure(bytes.len() <= 524_288, "GROWTH_REHEARSAL_CHECKPOINT_LIMIT")?;
    let stored: CheckpointRecord = serde_json::from_slice(&bytes)?;
    ensure(
        canonical(&stored)? == bytes
            && stored.source_tip == tip
            && stored.source_root == record.root
            && stored.source_height == record.height
            && stored.source_generation == generation
            && stored.binding == binding
            && stored.commitment == receipt.candidate_commitment
            && stored.working
                == state
                    .iter()
                    .filter(|(k, _)| !k.starts_with("account:"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<State>()
            && stored.accounts.digest == expected.permanent_account_root
            && stored.accounts.count == expected.permanent_account_count
            && stored.accounts.balance == expected.permanent_account_balance,
        "GROWTH_REHEARSAL_CHECKPOINT",
    )?;
    native_store::audit_growth_roots(&db, std::slice::from_ref(&stored.accounts))?;
    let checkpoint = native_store::query_growth_checkpoint(
        &db,
        Context {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
        },
        settings.genesis(),
        record.height,
        expected.id,
        &stored.accounts,
    )?;
    ensure(
        checkpoint.height() == record.height,
        "GROWTH_REHEARSAL_HEIGHT",
    )?;
    checkpoint_read.rollback()?;
    snapshot.rollback()?;
    Ok(())
}

/// Independently reopen and replay the archived old-profile history, rebuild the
/// relation from its actual current State, then audit every COW checkpoint node.
/// No source Node, migration process, previous cache or caller amount is trusted.
pub fn verify_growth_rehearsal_v2(
    source_settings: Settings,
    directory: &Path,
) -> Result<GrowthRehearsalReceiptV2> {
    verify_growth_rehearsal_v2_with_snapshot_byte_limit(
        source_settings,
        directory,
        DEFAULT_GROWTH_REHEARSAL_SNAPSHOT_BYTE_LIMIT_V2,
    )
}

/// Choose a local cap for the combined source/checkpoint temporary copies.
/// This bounds copied bytes only, not retained history, SQL memory or replay CPU.
/// Input archives are never opened by SQLite and no WAL/journal is imported.
pub fn verify_growth_rehearsal_v2_with_snapshot_byte_limit(
    source_settings: Settings,
    directory: &Path,
    snapshot_byte_limit: u64,
) -> Result<GrowthRehearsalReceiptV2> {
    verify_directory(
        directory,
        source_settings,
        false,
        snapshot_byte_limit,
        |_| Ok(()),
    )
}

#[cfg(test)]
pub(super) fn verify_with_snapshot_hook(
    source_settings: Settings,
    directory: &Path,
    snapshot_byte_limit: u64,
    after_snapshot: impl FnOnce(&Path) -> Result<()>,
) -> Result<GrowthRehearsalReceiptV2> {
    verify_directory(
        directory,
        source_settings,
        false,
        snapshot_byte_limit,
        after_snapshot,
    )
}
impl Node {
    pub fn rehearse_growth_migration_v2(
        &self,
        destination: &Path,
        namespace: &str,
    ) -> Result<GrowthRehearsalReceiptV2> {
        self.rehearse_growth_migration_v2_with_progress(destination, namespace, &|_| Ok(()))
    }
    pub fn rehearse_growth_migration_v2_with_progress(
        &self,
        destination: &Path,
        namespace: &str,
        progress: &(impl Fn(GrowthRehearsalProgressV2) -> Result<()> + Sync),
    ) -> Result<GrowthRehearsalReceiptV2> {
        ensure(
            !trnm_mvcc_fee::growth_profile_v2::enabled(&self.settings.app),
            "GROWTH_REFERENCE_MIGRATION_UNSUPPORTED",
        )?;
        let backend = backend_name(self.state_backend)?;
        self.namespace()?;
        self.ready()?;
        ensure(
            self.settings.operator_bootstrap.is_none()
                && self.settings.operator_material.is_none()
                && self.settings.checkpoint_tile_paths.is_none(),
            "GROWTH_REHEARSAL_EXTERNAL_OWNER",
        )?;
        for entry in fs::read_dir(&self.directory)? {
            let name = entry?.file_name();
            ensure(
                [
                    "native.sqlite",
                    "native.sqlite-wal",
                    "native.sqlite-shm",
                    "owner.lock",
                    "authenticated-migration.json",
                ]
                .iter()
                .any(|s| name == *s),
                "GROWTH_REHEARSAL_SOURCE_FILES",
            )?;
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()?;
        ensure(
            !parent.starts_with(&self.directory),
            "GROWTH_REHEARSAL_SOURCE_DESTINATION",
        )?;
        let destination = parent.join(
            destination
                .file_name()
                .ok_or("GROWTH_REHEARSAL_DIRECTORY")?,
        );
        let parent_directory = growth_reservation_io::directory_components(&parent)?;
        growth_reservation_io::check_named_parent(&parent_directory, &parent)?;
        match fs::symlink_metadata(&destination) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err("GROWTH_REHEARSAL_DESTINATION_EXISTS".into()),
            Err(e) => return Err(e.into()),
        }
        let source =
            Transaction::new_unchecked(&self.db, rusqlite::TransactionBehavior::Immediate)?;
        let original = durable_fingerprint(&self.directory)?;
        let source_receipt = optional_hash(&self.directory.join("authenticated-migration.json"))?;
        progress(GrowthRehearsalProgressV2::SourceLocked)?;
        let relay = |point| progress(GrowthRehearsalProgressV2::Source(point));
        let (blocks, transactions) = verify_source(self, &relay)?;
        let (tip, generation, state) = self.read_active()?;
        let record = self.record(tip)?;
        let commitment = growth_commitment_from_complete_state_v2(&self.settings, &state)
            .map_err(|e| Error::from(format!("GROWTH_REHEARSAL_STATE:{e:?}")))?;
        let binding = growth_profile_binding_v2(&self.settings, &commitment, namespace)
            .map_err(|e| Error::from(format!("GROWTH_REHEARSAL_BINDING:{e:?}")))?;
        let settings = candidate_settings(&self.settings, &binding);
        let candidate = growth_commitment_from_complete_state_v2(&settings, &state)
            .map_err(|e| Error::from(format!("GROWTH_REHEARSAL_STATE:{e:?}")))?;
        let stage = tempfile::Builder::new()
            .prefix("native-growth-rehearsal-staging-")
            .tempdir_in(&parent)?
            .keep();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
        let stage_directory = File::from(
            rustix::fs::openat(
                &parent_directory,
                stage.file_name().ok_or("GROWTH_REHEARSAL_DIRECTORY")?,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| Error::from(std::io::Error::from(e)))?,
        );
        stage_identity(&parent_directory, &parent, &stage_directory, &stage)?;
        create_synced(
            &stage.join(PENDING_REHEARSAL),
            &canonical(
                &json!({"schema":SCHEMA,"source_tip":hex::encode(tip),"consensus_activation":false}),
            )?,
        )?;
        create_synced(&stage.join("owner.lock"), &[])?;
        let archived = stage.join("source");
        fs::create_dir(&archived)?;
        create_synced(&archived.join("owner.lock"), &[])?;
        if source_receipt.is_some() {
            create_synced(
                &archived.join("authenticated-migration.json"),
                &fs::read(self.directory.join("authenticated-migration.json"))?,
            )?;
        }
        create_synced(&archived.join("native.sqlite"), &[])?;
        let mut copy = Connection::open(archived.join("native.sqlite"))?;
        copy.execute_batch(
            "PRAGMA trusted_schema=OFF;PRAGMA foreign_keys=ON;PRAGMA synchronous=FULL;",
        )?;
        let tx = copy.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(&self.state_backend.ddl())?;
        tx.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
        for (index, table) in table_names(&source)?.iter().enumerate() {
            copy_table(&source, &tx, table, index, &relay)?;
        }
        let tables = table_digests(&source)?;
        ensure(table_digests(&tx)? == tables, "GROWTH_REHEARSAL_COPY")?;
        check_database(&tx)?;
        tx.commit()?;
        copy.close().map_err(|(_, e)| Error::from(e))?;
        File::open(archived.join("native.sqlite"))?.sync_all()?;
        sync_dir(&archived)?;
        progress(GrowthRehearsalProgressV2::SourceCopied)?;
        stage_identity(&parent_directory, &parent, &stage_directory, &stage)?;
        create_synced(&stage.join("native.sqlite"), &[])?;
        let mut db = Connection::open(stage.join("native.sqlite"))?;
        db.execute_batch("PRAGMA trusted_schema=OFF;PRAGMA synchronous=FULL;")?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(CHECKPOINT_DDL)?;
        for (key, value) in [
            ("schema", schema_id()),
            ("parameters", settings.parameters()),
            ("genesis", settings.genesis()),
        ] {
            tx.execute(
                "INSERT INTO metadata VALUES(?,?)",
                params![key, value.as_slice()],
            )?;
        }
        let accounts = native_store::seed_growth(&tx, &state)?;
        let stored = CheckpointRecord {
            source_tip: tip,
            source_root: record.root,
            source_height: record.height,
            source_generation: generation,
            binding: binding.clone(),
            commitment: candidate.observation().clone(),
            accounts,
            working: state
                .iter()
                .filter(|(k, _)| !k.starts_with("account:"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        let bytes = canonical(&stored)?;
        ensure(bytes.len() <= 524_288, "GROWTH_REHEARSAL_CHECKPOINT_LIMIT")?;
        tx.execute("INSERT INTO growth_checkpoint VALUES(1,?)", [bytes])?;
        check_database(&tx)?;
        tx.commit()?;
        db.close().map_err(|(_, e)| Error::from(e))?;
        File::open(stage.join("native.sqlite"))?.sync_all()?;
        progress(GrowthRehearsalProgressV2::CheckpointCommitted)?;
        stage_identity(&parent_directory, &parent, &stage_directory, &stage)?;
        let receipt = GrowthRehearsalReceiptV2 {
            schema: SCHEMA.into(),
            namespace: namespace.into(),
            source_backend: backend.into(),
            source_network: self.settings.network(),
            source_parameters: self.settings.parameters(),
            source_genesis: self.settings.genesis(),
            source_tip: tip,
            source_state_root: record.root,
            source_height: record.height,
            source_generation: generation,
            source_schema: self.state_backend.schema_id(),
            source_tables: tables,
            retained_blocks: blocks,
            replayed_transactions: transactions,
            profile_binding: binding,
            candidate_commitment: candidate.observation().clone(),
            source_archive_sha256: file_hash(&archived.join("native.sqlite"))?,
            checkpoint_sha256: file_hash(&stage.join("native.sqlite"))?,
            source_receipt_sha256: source_receipt,
            candidate_materialized: true,
            independent_cold_readback: true,
            migration_executed: false,
            old_work_promoted: false,
            consensus_activation: false,
            production_enabled: false,
            external_journals_imported: false,
            external_owner_operations_executed: 0,
        };
        create_synced(&stage.join(REHEARSAL_RECEIPT), &canonical(&receipt)?)?;
        sync_dir(&stage)?;
        progress(GrowthRehearsalProgressV2::BeforePublish)?;
        stage_identity(&parent_directory, &parent, &stage_directory, &stage)?;
        ensure(
            verify_directory(
                &stage,
                self.settings.clone(),
                true,
                DEFAULT_GROWTH_REHEARSAL_SNAPSHOT_BYTE_LIMIT_V2,
                |_| Ok(()),
            )? == receipt,
            "GROWTH_REHEARSAL_READBACK",
        )?;
        self.namespace()?;
        self.storage_context()?;
        ensure(
            self.active()? == (tip, generation)
                && durable_fingerprint(&self.directory)? == original
                && optional_hash(&self.directory.join("authenticated-migration.json"))?
                    == source_receipt,
            "GROWTH_REHEARSAL_SOURCE_CHANGED",
        )?;
        // No callback runs after this final source/readback fence. Failed stages
        // remain evidence; publication never replaces an existing destination.
        stage_identity(&parent_directory, &parent, &stage_directory, &stage)?;
        publish_directory(&parent_directory, &stage, &destination)?;
        parent_directory.sync_all()?;
        // A crash after publication but before this unlink leaves a visible
        // pending candidate; independent verification continues to refuse it.
        stage_identity(&parent_directory, &parent, &stage_directory, &destination)?;
        rustix::fs::unlinkat(
            &stage_directory,
            PENDING_REHEARSAL,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|e| Error::from(std::io::Error::from(e)))?;
        stage_directory.sync_all()?;
        source.rollback()?;
        Ok(receipt)
    }
}
