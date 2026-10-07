//! Explicit local-development migration from the legacy Node store. The source
//! writer and SQLite snapshot stay locked; no block admission, activation, replay
//! acknowledgement or external owner operation runs while copying historical facts.
use super::{
    bytes32, canonical, native_authenticated, plain, schema, sync_dir, Delta, Node, StateBackend,
};
use crate::account_archive_execution::state_witness::{
    growth_commitment_from_complete_state_v2, growth_profile_binding_v2,
    verify_growth_profile_binding_v2, GrowthProfileBindingV2,
};
use crate::{consensus, ensure, sequence_root, Error, Result};
use fs2::FileExt;
use rusqlite::{params_from_iter, types::Value as SqlValue, Connection, Transaction};
use rustix::fs::{fallocate, FallocateFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_commitment::ExecutionRequest;
use trnm_mvcc_fee::pon_executor::{root, ExecutionControl, State};
use trnm_protocol::pon_wire::Hash;

pub(crate) const PENDING: &str = "authenticated-migration.pending";
const RECEIPT: &str = "authenticated-migration.json";
const PROFILE: &str = "native-authenticated-local-migration-v1";
const GROWTH_RESERVATION_FILE: &str = "growth-storage-reservation.bin";
const GROWTH_RESERVATION_RECEIPT: &str = "growth-storage-reservation.json";
const MIN_GROWTH_RESERVATION_BYTES: u64 = 1024 * 1024;
const MAX_GROWTH_RESERVATION_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Cancellation is checked before any target publication and within proof,
/// execution, SQL-copy and authenticated-node work. No callback follows publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticatedMigrationProgress {
    SourceLocked,
    BeforeTargetVisible,
    TargetCreated,
    CopyRow { table: usize, row: u64 },
    BeforeBlock { height: u64 },
    Work { height: u64 },
    Execution { height: u64 },
    AuthenticatedState { height: u64 },
    AfterBlock { height: u64 },
    BeforeCommit,
    Committed,
    BeforePublish,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreservedTable {
    pub table: String,
    pub rows: u64,
    /// Ordered, typed SQLite values. The target schema metadata cell is mapped
    /// back to the source schema identity for this preserved-content digest.
    pub sha256: String,
}

/// A completed local copy, not activation permission, release qualification, a
/// new consensus state root or an instruction to discard the source directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedMigrationReceipt {
    pub profile: &'static str,
    pub source_schema: String,
    pub target_schema: String,
    pub genesis: String,
    pub parameters: String,
    pub retained_blocks: u64,
    pub replayed_blocks: u64,
    pub replayed_transactions: u64,
    pub active_tip: String,
    pub active_generation: u64,
    pub pending_reorganization: bool,
    pub preserved_tables: Vec<PreservedTable>,
    pub external_owner_operations_executed: u64,
}

/// Read-only handoff from an actual authenticated source Node into the already
/// defined candidate growth profile. It binds source state/tip/generation but
/// neither creates a target namespace nor reserves storage or activates consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrowthMigrationPlanV2 {
    pub schema: &'static str,
    pub source_tip: String,
    pub source_generation: u64,
    pub source_state_root: String,
    pub source_commitment: String,
    pub profile_binding: String,
    pub candidate_parameters: String,
    pub candidate_genesis: String,
    pub storage_namespace: String,
    pub complete_source_state_checked: bool,
    pub target_storage_reserved: bool,
    pub migration_executed: bool,
    pub consensus_activation: bool,
}

/// Physical local-development storage reservation for an already verified
/// growth candidate. This proves only that the requested bytes were allocated
/// for this exact binding at this instant; it is not a proof that the amount is
/// sufficient for the maximum profile, durable remote availability, migration,
/// or consensus activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrowthStorageReservationV2 {
    pub schema: String,
    pub profile_binding: String,
    pub storage_namespace: String,
    pub target: String,
    pub requested_bytes: u64,
    pub physically_reserved_bytes: u64,
    pub complete_source_state_checked: bool,
    pub target_storage_reserved: bool,
    pub capacity_sufficiency_qualified: bool,
    pub migration_executed: bool,
    pub consensus_activation: bool,
}

impl Node {
    /// Bind the current actual authenticated Node state to a retained candidate
    /// growth-profile identity. The full source-state scan is intentional here:
    /// migration must prove source equivalence before a future bounded profile
    /// can replace the complete-state hot path.
    pub fn prepare_growth_profile_migration_v2(
        &self,
        binding: &GrowthProfileBindingV2,
    ) -> Result<GrowthMigrationPlanV2> {
        ensure(
            matches!(self.state_backend, StateBackend::AuthenticatedV1),
            "GROWTH_MIGRATION_SOURCE_PROFILE",
        )?;
        self.namespace()?;
        self.ready()?;
        let (tip, generation, state) = self.read_active()?;
        let commitment = growth_commitment_from_complete_state_v2(&self.settings, &state)
            .map_err(|error| Error::from(format!("GROWTH_MIGRATION_RELATION:{error:?}")))?;
        verify_growth_profile_binding_v2(&self.settings, &commitment, binding)
            .map_err(|error| Error::from(format!("GROWTH_MIGRATION_BINDING:{error:?}")))?;
        let state_root = root(&state)?;
        ensure(
            self.record(tip)?.root == state_root && self.active()? == (tip, generation),
            "GROWTH_MIGRATION_STALE_SOURCE",
        )?;
        Ok(GrowthMigrationPlanV2 {
            schema: "pon-permanent-account-growth-migration-plan-v2",
            source_tip: hex::encode(tip),
            source_generation: generation,
            source_state_root: hex::encode(state_root),
            source_commitment: hex::encode(commitment.id),
            profile_binding: hex::encode(binding.id),
            candidate_parameters: hex::encode(binding.candidate_parameters),
            candidate_genesis: hex::encode(binding.candidate_genesis),
            storage_namespace: hex::encode(binding.storage_namespace),
            complete_source_state_checked: true,
            target_storage_reserved: false,
            migration_executed: false,
            consensus_activation: false,
        })
    }

    /// Reserve actual local filesystem blocks for the exact retained candidate.
    /// The target must be absent under an existing canonical parent. Any failure
    /// after target creation removes the new target rather than publishing a
    /// partial reservation.
    pub fn reserve_growth_profile_storage_v2(
        &self,
        binding: &GrowthProfileBindingV2,
        storage_namespace: &str,
        target: &Path,
        requested_bytes: u64,
    ) -> Result<GrowthStorageReservationV2> {
        ensure(
            (MIN_GROWTH_RESERVATION_BYTES..=MAX_GROWTH_RESERVATION_BYTES)
                .contains(&requested_bytes),
            "GROWTH_STORAGE_RESERVATION_BYTES",
        )?;
        let plan = self.prepare_growth_profile_migration_v2(binding)?;
        let (tip, generation, state) = self.read_active()?;
        ensure(
            plan.source_tip == hex::encode(tip) && plan.source_generation == generation,
            "GROWTH_STORAGE_STALE_SOURCE",
        )?;
        let commitment = growth_commitment_from_complete_state_v2(&self.settings, &state)
            .map_err(|error| Error::from(format!("GROWTH_STORAGE_RELATION:{error:?}")))?;
        let expected = growth_profile_binding_v2(&self.settings, &commitment, storage_namespace)
            .map_err(|error| Error::from(format!("GROWTH_STORAGE_NAMESPACE:{error:?}")))?;
        ensure(&expected == binding, "GROWTH_STORAGE_BINDING")?;
        ensure(target.is_absolute() && !target.exists(), "GROWTH_STORAGE_TARGET")?;
        let target_text = target.to_str().ok_or("GROWTH_STORAGE_TARGET")?.to_owned();
        let parent = target.parent().ok_or("GROWTH_STORAGE_TARGET")?;
        ensure(
            parent.canonicalize()? == parent && parent.is_dir(),
            "GROWTH_STORAGE_TARGET",
        )?;

        fs::create_dir(target)?;
        let result = (|| {
            fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
            let reservation_path = target.join(GROWTH_RESERVATION_FILE);
            let reservation = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&reservation_path)?;
            fallocate(
                reservation.as_fd(),
                FallocateFlags::empty(),
                0,
                requested_bytes,
            )
            .map_err(|error| Error::from(format!("GROWTH_STORAGE_FALLOCATE:{error}")))?;
            reservation.sync_all()?;
            let metadata = reservation.metadata()?;
            let physically_reserved_bytes = metadata
                .blocks()
                .checked_mul(512)
                .ok_or("GROWTH_STORAGE_RESERVATION_BYTES")?;
            ensure(
                metadata.len() == requested_bytes
                    && physically_reserved_bytes >= requested_bytes,
                "GROWTH_STORAGE_RESERVATION",
            )?;
            ensure(
                self.active()? == (tip, generation),
                "GROWTH_STORAGE_STALE_SOURCE",
            )?;
            let receipt = GrowthStorageReservationV2 {
                schema: "pon-permanent-account-growth-storage-reservation-v2".into(),
                profile_binding: plan.profile_binding.clone(),
                storage_namespace: plan.storage_namespace.clone(),
                target: target_text.clone(),
                requested_bytes,
                physically_reserved_bytes,
                complete_source_state_checked: plan.complete_source_state_checked,
                target_storage_reserved: true,
                capacity_sufficiency_qualified: false,
                migration_executed: false,
                consensus_activation: false,
            };
            let receipt_path = target.join(GROWTH_RESERVATION_RECEIPT);
            let mut receipt_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&receipt_path)?;
            receipt_file.write_all(&serde_json::to_vec_pretty(&receipt)?)?;
            receipt_file.sync_all()?;
            sync_dir(target)?;
            let retained: GrowthStorageReservationV2 =
                serde_json::from_slice(&fs::read(&receipt_path)?)?;
            ensure(retained == receipt, "GROWTH_STORAGE_RECEIPT")?;
            Ok(receipt)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(target);
            let _ = sync_dir(parent);
        }
        result
    }

    /// Copy a fully checked legacy local-development store into a fresh explicit
    /// authenticated namespace. Source files and irreversible journals remain.
    pub fn migrate_to_authenticated_state(
        &self,
        destination: &Path,
    ) -> Result<AuthenticatedMigrationReceipt> {
        self.migrate_to_authenticated_state_with_progress(destination, &|_| Ok(()))
    }

    pub fn migrate_to_authenticated_state_with_progress(
        &self,
        destination: &Path,
        progress: &(impl Fn(AuthenticatedMigrationProgress) -> Result<()> + Sync),
    ) -> Result<AuthenticatedMigrationReceipt> {
        ensure(
            matches!(self.state_backend, StateBackend::Legacy),
            "AUTHENTICATED_MIGRATION_SOURCE_PROFILE",
        )?;
        // A copied DB must never become an unrestricted route around an external
        // task/mining/continuous-owner journal. Such ownership requires its own
        // authorized migration relation; it is not implicitly downgraded here.
        ensure(
            self.owner_policy.is_none()
                && self.mining_owner.is_none()
                && self.continuous_owner.is_none()
                && !super::owner_marker_present(&self.directory)?,
            "AUTHENTICATED_MIGRATION_EXTERNAL_OWNER",
        )?;
        self.namespace()?;
        for entry in fs::read_dir(&self.directory)? {
            let name = entry?.file_name();
            ensure(
                [
                    "native.sqlite",
                    "native.sqlite-wal",
                    "native.sqlite-shm",
                    "owner.lock",
                ]
                .iter()
                .any(|expected| name == *expected),
                "AUTHENTICATED_MIGRATION_SOURCE_FILES",
            )?;
        }
        // IMMEDIATE also fences SQLite writers that do not honor owner.lock.
        // No SQL mutation is executed on this transaction; rollback ends it.
        let source =
            Transaction::new_unchecked(&self.db, rusqlite::TransactionBehavior::Immediate)?;
        let source_files = durable_fingerprint(&self.directory)?;
        progress(AuthenticatedMigrationProgress::SourceLocked)?;
        check_schema(&source, StateBackend::Legacy)?;
        check_database(&source)?;
        check_metadata(&source, self)?;
        self.validate_authenticated_replay()?;
        self.validate_authenticated_outbox()?;
        let pool: u64 =
            source.query_row("SELECT COUNT(*) FROM local_pool_metadata", [], |row| {
                row.get(0)
            })?;
        if pool == 1 {
            self.pool_status_snapshot()?;
        } else {
            ensure(pool == 0, "AUTHENTICATED_MIGRATION_POOL")?;
            for table in [
                "local_pool_groups",
                "local_pool_rows",
                "local_pool_removals",
            ] {
                let rows: u64 =
                    source.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
                ensure(rows == 0, "AUTHENTICATED_MIGRATION_POOL")?;
            }
        }
        let pending_reorganization = check_local_history(self)?;
        let (active_tip, active_generation, _) = self.read_active()?;
        let tables = table_names(&source)?;

        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()?;
        ensure(
            !parent.starts_with(&self.directory),
            "AUTHENTICATED_MIGRATION_SOURCE_DESTINATION",
        )?;
        let destination = parent.join(
            destination
                .file_name()
                .ok_or("AUTHENTICATED_MIGRATION_NAMESPACE")?,
        );

        // A visible destination must already carry its durable pending fence.
        // Keep private staging on failure; never overwrite even an empty target.
        let staging = tempfile::Builder::new()
            .prefix("native-authenticated-migration-staging-")
            .tempdir_in(&parent)?
            .keep();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
        let pending_bytes = canonical(&serde_json::json!({
            "profile": PROFILE,
            "source": self.directory,
            "destination": destination,
            "source_schema": hex::encode(StateBackend::Legacy.schema_id()),
            "target_schema": hex::encode(StateBackend::AuthenticatedV1.schema_id()),
            "parameters": hex::encode(self.settings.parameters()),
            "genesis": hex::encode(self.settings.genesis()),
        }))?;
        create_synced(&staging.join(PENDING), &pending_bytes)?;
        sync_dir(&staging)?;
        sync_dir(&parent)?;
        progress(AuthenticatedMigrationProgress::BeforeTargetVisible)?;
        rename_fresh(&staging, &destination)?;
        sync_dir(&parent)?;
        let directory = destination.canonicalize()?;
        let directory_meta = fs::symlink_metadata(&directory)?;
        ensure(directory_meta.is_dir(), "AUTHENTICATED_MIGRATION_NAMESPACE")?;
        let pending_path = directory.join(PENDING);
        let owner = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("owner.lock"))?;
        owner
            .try_lock_exclusive()
            .map_err(|_| Error::from("WRITER_BUSY"))?;
        progress(AuthenticatedMigrationProgress::TargetCreated)?;
        let path = directory.join("native.sqlite");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let database_meta = file.metadata()?;
        drop(file);
        let mut target = Connection::open(&path)?;
        // The standalone copy uses a rollback journal. A normal explicit opener
        // selects its usual WAL mode only after this complete namespace is sealed.
        target.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;",
        )?;
        let tx = target.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(&StateBackend::AuthenticatedV1.ddl())?;
        tx.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
        for (index, table) in tables.iter().enumerate() {
            copy_table(&source, &tx, table, index, progress)?;
        }
        let affected = tx.execute(
            "UPDATE metadata SET value=? WHERE key='schema'",
            [StateBackend::AuthenticatedV1.schema_id().as_slice()],
        )?;
        ensure(affected == 1, "AUTHENTICATED_MIGRATION_METADATA")?;
        native_authenticated::seed(&tx, &self.settings)?;
        let mut replayed_blocks = 0_u64;
        let mut replayed_transactions = 0_u64;
        let mut statement = source.prepare("SELECT id FROM blocks ORDER BY height,id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id = bytes32(row.get(0)?)?;
            let record = self.record(id)?;
            progress(AuthenticatedMigrationProgress::BeforeBlock {
                height: record.height,
            })?;
            if id == self.settings.genesis() {
                check_genesis(self)?;
                native_authenticated::verify_state(
                    &tx,
                    &self.settings,
                    id,
                    &self.settings.initial,
                    &mut || {
                        progress(AuthenticatedMigrationProgress::AuthenticatedState { height: 0 })
                    },
                )?;
            } else {
                let (parent, prior, after, transactions) = checked_successor(self, id, progress)?;
                native_authenticated::publish(
                    &tx,
                    &self.settings,
                    parent,
                    id,
                    &prior,
                    &after,
                    &mut || {
                        progress(AuthenticatedMigrationProgress::AuthenticatedState {
                            height: record.height,
                        })
                    },
                )?;
                replayed_blocks = replayed_blocks
                    .checked_add(1)
                    .ok_or("AUTHENTICATED_MIGRATION_COUNT")?;
                replayed_transactions = replayed_transactions
                    .checked_add(transactions)
                    .ok_or("AUTHENTICATED_MIGRATION_COUNT")?;
            }
            crate::ancestry_index::validate_tip(&source, self.ancestry_context(), id)?;
            check_snapshot(self, id)?;
            progress(AuthenticatedMigrationProgress::AfterBlock {
                height: record.height,
            })?;
        }
        drop(rows);
        drop(statement);
        check_unreferenced_rows(&source)?;
        check_database(&tx)?;
        check_schema(&tx, StateBackend::AuthenticatedV1)?;
        let preserved_tables = compare_preserved(&source, &tx, &tables, progress)?;
        let retained_blocks: u64 =
            source.query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))?;
        ensure(
            retained_blocks == replayed_blocks + 1,
            "AUTHENTICATED_MIGRATION_GENESIS",
        )?;
        let commitments: u64 =
            tx.query_row("SELECT COUNT(*) FROM native_state_commitments", [], |row| {
                row.get(0)
            })?;
        ensure(
            commitments == retained_blocks,
            "AUTHENTICATED_MIGRATION_COMMITMENTS",
        )?;
        let derived = derived_content(&tx)?;
        let receipt = AuthenticatedMigrationReceipt {
            profile: PROFILE,
            source_schema: hex::encode(StateBackend::Legacy.schema_id()),
            target_schema: hex::encode(StateBackend::AuthenticatedV1.schema_id()),
            genesis: hex::encode(self.settings.genesis()),
            parameters: hex::encode(self.settings.parameters()),
            retained_blocks,
            replayed_blocks,
            replayed_transactions,
            active_tip: hex::encode(active_tip),
            active_generation,
            pending_reorganization,
            preserved_tables,
            external_owner_operations_executed: 0,
        };
        progress(AuthenticatedMigrationProgress::BeforeCommit)?;
        tx.commit()?;
        target.close().map_err(|(_, error)| Error::from(error))?;
        let target_files = durable_fingerprint(&directory)?;
        progress(AuthenticatedMigrationProgress::Committed)?;
        // All caller code before the seal executes under both SQLite writer
        // locks except the explicit post-commit fault point; fingerprints reject
        // mutations there. A new connection reads committed disk bytes instead
        // of trusting the writer's cached pages after a same-inode file change.
        let target = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let sealed = Transaction::new_unchecked(&target, rusqlite::TransactionBehavior::Immediate)?;
        ensure(
            durable_fingerprint(&directory)? == target_files,
            "AUTHENTICATED_MIGRATION_DURABLE_BYTES",
        )?;
        check_schema(&sealed, StateBackend::AuthenticatedV1)?;
        check_database(&sealed)?;
        ensure(
            compare_preserved(&source, &sealed, &tables, progress)? == receipt.preserved_tables,
            "AUTHENTICATED_MIGRATION_COPY",
        )?;
        ensure(
            derived_content(&sealed)? == derived,
            "AUTHENTICATED_MIGRATION_COMMITMENTS",
        )?;
        let receipt_bytes = canonical(&receipt)?;
        create_synced(&directory.join(RECEIPT), &receipt_bytes)?;
        File::open(&path)?.sync_all()?;
        sync_dir(&directory)?;
        progress(AuthenticatedMigrationProgress::BeforePublish)?;
        // No caller callback follows this last full check. Locks fence SQL
        // mutation; direct reads catch raw-file changes hidden by page caches.
        ensure(
            durable_fingerprint(&self.directory)? == source_files,
            "AUTHENTICATED_MIGRATION_SOURCE_CHANGED",
        )?;
        ensure(
            durable_fingerprint(&directory)? == target_files,
            "AUTHENTICATED_MIGRATION_DURABLE_BYTES",
        )?;
        check_schema(&sealed, StateBackend::AuthenticatedV1)?;
        check_database(&sealed)?;
        ensure(
            compare_preserved(&source, &sealed, &tables, &|_| Ok(()))? == receipt.preserved_tables,
            "AUTHENTICATED_MIGRATION_COPY",
        )?;
        ensure(
            derived_content(&sealed)? == derived,
            "AUTHENTICATED_MIGRATION_COMMITMENTS",
        )?;
        let actual_names: BTreeSet<_> = fs::read_dir(&directory)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::result::Result<_, _>>()?;
        let expected_names: BTreeSet<_> = ["native.sqlite", "owner.lock", PENDING, RECEIPT]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect();
        ensure(
            actual_names == expected_names,
            "AUTHENTICATED_MIGRATION_NAMESPACE",
        )?;
        self.namespace()?;
        let actual_dir = fs::symlink_metadata(&directory)?;
        let actual_db = fs::symlink_metadata(&path)?;
        let actual_owner = fs::symlink_metadata(directory.join("owner.lock"))?;
        let held_owner = owner.metadata()?;
        ensure(
            (actual_dir.dev(), actual_dir.ino()) == (directory_meta.dev(), directory_meta.ino())
                && (actual_db.dev(), actual_db.ino()) == (database_meta.dev(), database_meta.ino())
                && (actual_owner.dev(), actual_owner.ino()) == (held_owner.dev(), held_owner.ino()),
            "AUTHENTICATED_MIGRATION_NAMESPACE",
        )?;
        for path in [
            &path,
            &pending_path,
            &directory.join(RECEIPT),
            &directory.join("owner.lock"),
        ] {
            plain(path)?;
        }
        ensure(
            fs::read(&pending_path)? == pending_bytes,
            "AUTHENTICATED_MIGRATION_MARKER",
        )?;
        ensure(
            fs::read(directory.join(RECEIPT))? == receipt_bytes,
            "AUTHENTICATED_MIGRATION_MARKER",
        )?;
        sealed.rollback()?;
        source.rollback()?;
        // Closing cannot silently conceal a failed SQLite cleanup. A complete
        // target can be published only after its connection is cleanly closed.
        target.close().map_err(|(_, error)| Error::from(error))?;
        fs::remove_file(pending_path)?;
        sync_dir(&directory)?;
        drop(owner);
        Ok(receipt)
    }
}

fn rename_fresh(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| std::io::Error::from(error).into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, destination);
        Err("AUTHENTICATED_MIGRATION_PLATFORM".into())
    }
}

fn durable_fingerprint(directory: &Path) -> Result<Vec<(String, Option<Hash>)>> {
    let mut out = Vec::new();
    for name in [
        "native.sqlite",
        "native.sqlite-wal",
        "native.sqlite-journal",
        "owner.lock",
    ] {
        let path = directory.join(name);
        plain(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path);
        let mut file = match file {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                out.push((name.into(), None));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let before = file.metadata()?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 65_536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        let after = file.metadata()?;
        let visible = fs::symlink_metadata(&path)?;
        ensure(
            before.len() == after.len()
                && (before.dev(), before.ino()) == (after.dev(), after.ino())
                && (visible.dev(), visible.ino()) == (before.dev(), before.ino())
                && visible.nlink() == 1,
            "AUTHENTICATED_MIGRATION_DURABLE_BYTES",
        )?;
        out.push((name.into(), Some(digest.finalize().into())));
    }
    Ok(out)
}

fn create_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn check_schema(db: &Connection, backend: StateBackend) -> Result<()> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(&backend.ddl())?;
    ensure(
        schema(db)? == schema(&expected)?,
        "AUTHENTICATED_MIGRATION_SCHEMA",
    )
}

fn check_database(db: &Connection) -> Result<()> {
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure(integrity == "ok", "AUTHENTICATED_MIGRATION_INTEGRITY")?;
    let violations: u64 =
        db.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    ensure(violations == 0, "AUTHENTICATED_MIGRATION_FOREIGN_KEY")
}

fn check_metadata(db: &Connection, node: &Node) -> Result<()> {
    let count: u64 = db.query_row("SELECT COUNT(*) FROM metadata", [], |row| row.get(0))?;
    ensure(count == 3, "AUTHENTICATED_MIGRATION_METADATA")?;
    for (key, expected) in [
        ("schema", StateBackend::Legacy.schema_id()),
        ("parameters", node.settings.parameters()),
        ("genesis", node.settings.genesis()),
    ] {
        let actual: Vec<u8> =
            db.query_row("SELECT value FROM metadata WHERE key=?", [key], |row| {
                row.get(0)
            })?;
        ensure(actual == expected, "AUTHENTICATED_MIGRATION_METADATA")?;
    }
    Ok(())
}

fn table_names(db: &Connection) -> Result<Vec<String>> {
    let mut statement =
        db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
    let names = statement
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<Vec<String>, _>>()?;
    ensure(
        names
            .iter()
            .all(|name| name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')),
        "AUTHENTICATED_MIGRATION_TABLE",
    )?;
    Ok(names)
}

fn ordered_select(db: &Connection, table: &str) -> Result<(String, usize)> {
    let statement = db.prepare(&format!("SELECT * FROM {table}"))?;
    let columns = statement.column_count();
    ensure(columns > 0, "AUTHENTICATED_MIGRATION_TABLE")?;
    let order = (1..=columns)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    Ok((format!("SELECT * FROM {table} ORDER BY {order}"), columns))
}

fn values(row: &rusqlite::Row<'_>, columns: usize) -> Result<Vec<SqlValue>> {
    (0..columns)
        .map(|column| row.get(column).map_err(Error::from))
        .collect()
}

fn copy_table(
    source: &Connection,
    target: &Connection,
    table: &str,
    index: usize,
    progress: &(impl Fn(AuthenticatedMigrationProgress) -> Result<()> + Sync),
) -> Result<()> {
    let (select, columns) = ordered_select(source, table)?;
    if table == "sqlite_sequence" {
        // Earlier inserts advanced target AUTOINCREMENT values. Restore the
        // retained source frontier exactly, including deleted maximum rows.
        target.execute("DELETE FROM sqlite_sequence", [])?;
    }
    let parameters = vec!["?"; columns].join(",");
    let mut write = target.prepare(&format!("INSERT INTO {table} VALUES({parameters})"))?;
    let mut read = source.prepare(&select)?;
    let mut rows = read.query([])?;
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        progress(AuthenticatedMigrationProgress::CopyRow {
            table: index,
            row: count,
        })?;
        ensure(
            write.execute(params_from_iter(values(row, columns)?))? == 1,
            "AUTHENTICATED_MIGRATION_COPY",
        )?;
        count = count
            .checked_add(1)
            .ok_or("AUTHENTICATED_MIGRATION_COUNT")?;
    }
    Ok(())
}

fn hash_values(digest: &mut Sha256, row: &[SqlValue]) {
    digest.update((row.len() as u64).to_le_bytes());
    for value in row {
        match value {
            SqlValue::Null => digest.update([0]),
            SqlValue::Integer(value) => {
                digest.update([1]);
                digest.update(value.to_le_bytes());
            }
            SqlValue::Real(value) => {
                digest.update([2]);
                digest.update(value.to_bits().to_le_bytes());
            }
            SqlValue::Text(value) => {
                digest.update([3]);
                digest.update((value.len() as u64).to_le_bytes());
                digest.update(value.as_bytes());
            }
            SqlValue::Blob(value) => {
                digest.update([4]);
                digest.update((value.len() as u64).to_le_bytes());
                digest.update(value);
            }
        }
    }
}

fn compare_preserved(
    source: &Connection,
    target: &Connection,
    tables: &[String],
    progress: &(impl Fn(AuthenticatedMigrationProgress) -> Result<()> + Sync),
) -> Result<Vec<PreservedTable>> {
    let mut summaries = Vec::new();
    for (index, table) in tables.iter().enumerate() {
        let (select, columns) = ordered_select(source, table)?;
        let mut left = source.prepare(&select)?;
        let mut right = target.prepare(&select)?;
        let mut original = left.query([])?;
        let mut copied = right.query([])?;
        let mut digest = Sha256::new();
        digest.update(b"native-authenticated-migration-table-v1\0");
        digest.update((table.len() as u64).to_le_bytes());
        digest.update(table.as_bytes());
        let mut count = 0_u64;
        loop {
            let (a, b) = (original.next()?, copied.next()?);
            match (a, b) {
                (None, None) => break,
                (Some(a), Some(b)) => {
                    progress(AuthenticatedMigrationProgress::CopyRow {
                        table: index,
                        row: count,
                    })?;
                    let a = values(a, columns)?;
                    let mut b = values(b, columns)?;
                    if table == "metadata" && a.first() == Some(&SqlValue::Text("schema".into())) {
                        ensure(
                            b == vec![
                                SqlValue::Text("schema".into()),
                                SqlValue::Blob(StateBackend::AuthenticatedV1.schema_id().to_vec()),
                            ],
                            "AUTHENTICATED_MIGRATION_METADATA",
                        )?;
                        b[1] = SqlValue::Blob(StateBackend::Legacy.schema_id().to_vec());
                    }
                    ensure(a == b, "AUTHENTICATED_MIGRATION_COPY")?;
                    hash_values(&mut digest, &a);
                    count = count
                        .checked_add(1)
                        .ok_or("AUTHENTICATED_MIGRATION_COUNT")?;
                }
                _ => return Err("AUTHENTICATED_MIGRATION_COPY".into()),
            }
        }
        digest.update(count.to_le_bytes());
        summaries.push(PreservedTable {
            table: table.clone(),
            rows: count,
            sha256: hex::encode(digest.finalize()),
        });
    }
    Ok(summaries)
}

fn derived_content(db: &Connection) -> Result<Vec<Hash>> {
    let mut results = Vec::new();
    for table in ["archive_nodes", "native_state_commitments"] {
        let (select, columns) = ordered_select(db, table)?;
        let mut statement = db.prepare(&select)?;
        let mut rows = statement.query([])?;
        let mut digest = Sha256::new();
        digest.update(table.as_bytes());
        let mut count = 0_u64;
        while let Some(row) = rows.next()? {
            hash_values(&mut digest, &values(row, columns)?);
            count = count
                .checked_add(1)
                .ok_or("AUTHENTICATED_MIGRATION_COUNT")?;
        }
        digest.update(count.to_le_bytes());
        results.push(digest.finalize().into());
    }
    Ok(results)
}

fn check_genesis(node: &Node) -> Result<()> {
    let genesis = node.settings.genesis();
    let record = node.record(genesis)?;
    let packet: Option<Vec<u8>> = node.db.query_row(
        "SELECT packet FROM blocks WHERE id=?",
        [genesis.as_slice()],
        |row| row.get(0),
    )?;
    ensure(
        record.parent.is_none()
            && record.height == 0
            && record.work.bytes() == [0; 64]
            && packet.is_none()
            && record.root == root(&node.settings.initial)?
            && node.state_at(genesis)? == node.settings.initial
            && node.delta_rows(genesis)?.is_empty(),
        "AUTHENTICATED_MIGRATION_GENESIS",
    )
}

fn checked_successor(
    node: &Node,
    id: Hash,
    progress: &(impl Fn(AuthenticatedMigrationProgress) -> Result<()> + Sync),
) -> Result<(Hash, State, State, u64)> {
    let packet = node.packet(id)?;
    let header = &packet.header;
    let record = node.record(id)?;
    let parent = node.record(header.parent)?;
    let raw: Vec<u8> = node.db.query_row(
        "SELECT packet FROM blocks WHERE id=?",
        [id.as_slice()],
        |row| row.get(0),
    )?;
    ensure(packet.encode()? == raw, "AUTHENTICATED_MIGRATION_PACKET")?;
    ensure(
        header.network == node.settings.network()
            && header.parameters == node.settings.parameters()
            && parent.height.checked_add(1) == Some(header.height)
            && header.height <= i64::MAX as u64
            && header.target == node.expected_target(header.parent)?
            && header.transactions == sequence_root("transactions", &packet.transactions),
        "AUTHENTICATED_MIGRATION_HEADER",
    )?;
    let times: Vec<_> = node
        .recent(header.parent)?
        .iter()
        .take(11)
        .map(|p| p.0)
        .collect();
    // Revalidate historical median time without manufacturing a current clock
    // observation. Ordinary live admission still supplies its own observed_now.
    consensus::check_time(
        header.timestamp,
        &times,
        u64::MAX,
        node.settings.limit("future_skew_seconds")?,
    )?;
    let prior = node.state_at(header.parent)?;
    let task = node.eligible_work_task_from_state(&prior, header.work_task, header.height)?;
    if let Some(manifest) = task.manifest() {
        let size = pon_work::CELLS * 4;
        ensure(
            packet.proof.get(..4) == Some(b"PNW1")
                && trnm_protocol::pon_wire::hash(b"artifact", &[&packet.proof[4..4 + size]])
                    == manifest.model
                && trnm_protocol::pon_wire::hash(
                    b"qualified-task-input-v1",
                    &[&packet.proof[4 + size..4 + 2 * size]],
                ) == manifest.input,
            "TASK_PROOF_MATERIAL",
        )?;
    }
    let work = pon_work::verify_with_progress(
        header.challenge(),
        header.work_task,
        header.target,
        &packet.proof,
        &mut |_| {
            progress(AuthenticatedMigrationProgress::Work {
                height: header.height,
            })
        },
    )
    .map_err(|error| match error {
        pon_work::VerificationError::Relation(error) => Error::from(format!("WORK:{error:?}")),
        pon_work::VerificationError::Cancelled(error) => error,
    })?;
    let execute_progress = |_| {
        progress(AuthenticatedMigrationProgress::Execution {
            height: header.height,
        })
    };
    let executed = node.execute_derived_core(
        &prior,
        ExecutionRequest {
            transactions: &packet.transactions,
            height: header.height,
            miner: header.miner,
            parent_id: header.parent,
            workers: node.workers,
        },
        &ExecutionControl::new(&execute_progress, &()),
        None,
    )?;
    let mut output = executed.output;
    if task.manifest().is_some() {
        let product: Vec<_> = work
            .product()
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        node.record_task_output(header.height, &mut output.state, &task, &product)?;
    }
    ensure(
        root(&output.state)? == header.state
            && sequence_root("receipts", &output.receipts) == header.receipts
            && record.work
                == parent
                    .work
                    .checked_add(consensus::required_work(header.target)?)?
            && node.state_at(id)? == output.state,
        "AUTHENTICATED_MIGRATION_EXECUTION",
    )?;
    let keys: BTreeSet<_> = prior.keys().chain(output.state.keys()).collect();
    let mut expected = Vec::<Delta>::new();
    for key in keys {
        let before = prior.get(key).map(canonical).transpose()?;
        let after = output.state.get(key).map(canonical).transpose()?;
        if before != after {
            expected.push((key.clone(), before, after));
        }
    }
    ensure(
        node.delta_rows(id)? == expected,
        "AUTHENTICATED_MIGRATION_DELTA",
    )?;
    Ok((
        header.parent,
        prior,
        output.state,
        packet.transactions.len() as u64,
    ))
}

fn check_snapshot(node: &Node, id: Hash) -> Result<()> {
    use rusqlite::OptionalExtension;
    let bytes: Option<Vec<u8>> = node
        .db
        .query_row(
            "SELECT state FROM snapshots WHERE block=?",
            [id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(bytes) = bytes {
        let state: State = serde_json::from_slice(&bytes)?;
        ensure(
            canonical(&state)? == bytes && state == node.state_at(id)?,
            "AUTHENTICATED_MIGRATION_SNAPSHOT",
        )?;
    }
    Ok(())
}

fn check_unreferenced_rows(db: &Connection) -> Result<()> {
    for table in ["deltas", "snapshots"] {
        let count: u64 = db.query_row(&format!("SELECT COUNT(*) FROM {table} t LEFT JOIN blocks b ON b.id=t.block WHERE b.id IS NULL"), [], |row| row.get(0))?;
        ensure(count == 0, "AUTHENTICATED_MIGRATION_ORPHAN")?;
    }
    Ok(())
}

fn check_local_history(node: &Node) -> Result<bool> {
    use rusqlite::OptionalExtension;
    let active_rows: u64 = node
        .db
        .query_row("SELECT COUNT(*) FROM active", [], |row| row.get(0))?;
    ensure(active_rows == 1, "AUTHENTICATED_MIGRATION_ACTIVE")?;
    let (tip, generation) = node.active()?;
    let slot = node.slot()?;
    ensure(slot <= generation, "AUTHENTICATED_MIGRATION_ACTIVE")?;
    let mut events = node
        .db
        .prepare("SELECT generation,ordinal,kind,block FROM events ORDER BY generation,ordinal")?;
    let mut rows = events.query([])?;
    let mut current = node.settings.genesis();
    let mut previous_tip = current;
    let mut g = 0_u64;
    let mut ordinal = 0_u64;
    let mut attaching = false;
    while let Some(row) = rows.next()? {
        let event_generation: u64 = row.get(0)?;
        let event_ordinal: u64 = row.get(1)?;
        let kind: u64 = row.get(2)?;
        let block = bytes32(row.get(3)?)?;
        if event_generation != g {
            if g > 0 {
                ensure(
                    node.record(current)?.work > node.record(previous_tip)?.work,
                    "AUTHENTICATED_MIGRATION_EVENTS",
                )?;
            }
            ensure(
                event_generation == g.checked_add(1).ok_or("AUTHENTICATED_MIGRATION_COUNT")?,
                "AUTHENTICATED_MIGRATION_EVENTS",
            )?;
            g = event_generation;
            ordinal = 0;
            attaching = false;
            previous_tip = current;
        }
        ensure(event_ordinal == ordinal, "AUTHENTICATED_MIGRATION_EVENTS")?;
        match kind {
            0 => {
                ensure(
                    !attaching && current == block,
                    "AUTHENTICATED_MIGRATION_EVENTS",
                )?;
                current = node.parent(block)?;
            }
            1 => {
                attaching = true;
                ensure(
                    node.parent(block)? == current,
                    "AUTHENTICATED_MIGRATION_EVENTS",
                )?;
                current = block;
            }
            _ => return Err("AUTHENTICATED_MIGRATION_EVENTS".into()),
        }
        ordinal = ordinal
            .checked_add(1)
            .ok_or("AUTHENTICATED_MIGRATION_COUNT")?;
    }
    if g > 0 {
        ensure(
            node.record(current)?.work > node.record(previous_tip)?.work,
            "AUTHENTICATED_MIGRATION_EVENTS",
        )?;
    }
    ensure(
        g == generation && current == tip,
        "AUTHENTICATED_MIGRATION_EVENTS",
    )?;
    let reorg_rows: u64 = node
        .db
        .query_row("SELECT COUNT(*) FROM reorg", [], |row| row.get(0))?;
    ensure(reorg_rows <= 1, "AUTHENTICATED_MIGRATION_REORG")?;
    type ReorgRow = (Vec<u8>, Vec<u8>, u64, u64, u64);
    let reorg: Option<ReorgRow> = node
        .db
        .query_row(
            "SELECT old_tip,new_tip,generation,cursor,done FROM reorg WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let mut allowed_slots = vec![slot];
    let mut pending = false;
    if let Some((old, target, next, cursor, done)) = reorg {
        let old = bytes32(old)?;
        let target = bytes32(target)?;
        let count = node.check_steps(old, target, cursor)?;
        ensure(
            count > 0 && next > 0 && done <= 1,
            "AUTHENTICATED_MIGRATION_REORG",
        )?;
        if done == 0 {
            ensure(
                tip == old && generation.checked_add(1) == Some(next),
                "AUTHENTICATED_MIGRATION_REORG",
            )?;
            let mut staged = node.state_at(old)?;
            let mut statement = node
                .db
                .prepare("SELECT kind,block FROM steps WHERE ordinal<? ORDER BY ordinal")?;
            let mut steps = statement.query([cursor])?;
            while let Some(row) = steps.next()? {
                let kind: u64 = row.get(0)?;
                for (key, before, after) in node.delta_rows(bytes32(row.get(1)?)?)? {
                    let (before, after) = if kind == 0 {
                        (after, before)
                    } else {
                        (before, after)
                    };
                    ensure(
                        staged.get(&key).map(canonical).transpose()? == before,
                        "AUTHENTICATED_MIGRATION_REORG",
                    )?;
                    if let Some(bytes) = after {
                        staged.insert(key, serde_json::from_slice(&bytes)?);
                    } else {
                        staged.remove(&key);
                    }
                }
            }
            ensure(
                node.slot_state(next)? == staged,
                "AUTHENTICATED_MIGRATION_REORG",
            )?;
            allowed_slots.push(next);
            pending = true;
        } else {
            ensure(
                next <= generation && cursor == count,
                "AUTHENTICATED_MIGRATION_REORG",
            )?;
            let mismatch: u64 = node.db.query_row(
                "SELECT COUNT(*) FROM (SELECT ordinal,kind,block FROM steps EXCEPT SELECT ordinal,kind,block FROM events WHERE generation=?)",
                [next], |row| row.get(0),
            )?;
            let recorded: u64 = node.db.query_row(
                "SELECT COUNT(*) FROM events WHERE generation=?",
                [next],
                |row| row.get(0),
            )?;
            ensure(
                mismatch == 0 && recorded == count,
                "AUTHENTICATED_MIGRATION_REORG",
            )?;
        }
    } else {
        let steps: u64 = node
            .db
            .query_row("SELECT COUNT(*) FROM steps", [], |row| row.get(0))?;
        ensure(steps == 0, "AUTHENTICATED_MIGRATION_REORG")?;
    }
    let mut slots = node.db.prepare("SELECT DISTINCT slot FROM kv")?;
    for value in slots.query_map([], |row| row.get::<_, u64>(0))? {
        ensure(
            allowed_slots.contains(&value?),
            "AUTHENTICATED_MIGRATION_ACTIVE",
        )?;
    }
    Ok(pending)
}

#[cfg(test)]
#[path = "authenticated_migration_tests.rs"]
mod tests;
