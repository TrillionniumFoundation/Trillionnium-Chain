use std::{
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    mem::ManuallyDrop,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use trnm_consensus_core::{
    decode_safety_state_record_v0_exact, encode_safety_state_record_v0,
    safety_state_record_config_ref_v0, BarrierId, Core, CoreConfig, SafetyState,
    SafetyStatePersistenceBindingV0, SafetyStatePersistenceV0, SafetyStateRecordContextV0,
    SafetyStateRecordLimitsV0, SAFETY_STATE_RECORD_CODEC_VERSION_V0,
    SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0,
};
use trnm_consensus_types::SignatureVerifier;

use crate::{
    decode_transition_context_v0_exact, encode_transition_context_v0,
    error::{SafetyStoreConflictV0, SafetyStoreErrorV0},
    hash::hash_domain,
    schema::{
        validate_canonical_schema, JOURNAL_SCHEMA_SQL_V1, JOURNAL_SCHEMA_VERSION_V1,
        MAXIMUM_SQL_STATE_RECORD_BYTES, MAXIMUM_TRANSITION_CONTEXT_BYTES_V0,
        TRANSITION_CONTEXT_CODEC_V0,
    },
    transition_context_checksum_v0, validate_transition_context_against_state_v0,
    SafetyTransitionContextV0,
};

const LOCK_MAGIC_V0: &[u8; 8] = b"TRNMSLK\0";
const LOCK_VERSION_V0: u16 = 0;
// Sequences alternate between two independently checksummed slots placed in
// separate 4 KiB regions. This prevents one region rewrite from directly
// overlapping both payloads; it is not a claim about every storage device's
// atomic-write geometry. A Stable
// slot names one exact database head. A HeadIntent names both the last Stable
// head and its one-revision successor, so recovery can distinguish a commit
// that did not apply from one that applied before the final Stable rewrite.
// A third disjoint 4 KiB region holds a terminal halt latch without ever
// overwriting either recoverable head payload.
const LOCK_SLOT_BYTES_V0: usize = 184;
const LOCK_SLOT_REGION_BYTES_V0: usize = 4096;
const LOCK_SLOT_COUNT_V0: usize = 2;
const LOCK_HALT_LATCH_REGION_V0: usize = LOCK_SLOT_COUNT_V0;
const LOCK_FILE_REGION_COUNT_V0: usize = LOCK_SLOT_COUNT_V0 + 1;
const LOCK_FILE_BYTES_V0: usize = LOCK_SLOT_REGION_BYTES_V0 * LOCK_FILE_REGION_COUNT_V0;
const LOCK_KIND_STABLE_V0: u8 = 0;
const LOCK_KIND_HEAD_INTENT_V0: u8 = 1;
const LOCK_SLOT_CHECKSUM_OFFSET_V0: usize = 152;
const HALT_LATCH_MAGIC_V0: &[u8; 8] = b"TRNMSHL\0";
const HALT_LATCH_VERSION_V0: u16 = 0;
const HALT_LATCH_BYTES_V0: usize = 224;
const HALT_LATCH_CHECKSUM_OFFSET_V0: usize = 192;
const LOCK_CHECKSUM_DOMAIN_V0: &str = "trnm.consensus-safety-store.lock.v0";
const METADATA_DOMAIN_V0: &str = "trnm.consensus-safety-store.metadata.v0";
const CHAIN_DOMAIN_V0: &str = "trnm.consensus-safety-store.record-chain.v0";
const HEAD_DOMAIN_V0: &str = "trnm.consensus-safety-store.head.v0";
const HALT_DOMAIN_V0: &str = "trnm.consensus-safety-store.halt.v0";
const DATABASE_OVERHEAD_BYTES_V0: usize = 16 * 1024 * 1024;
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Owned configuration and resource boundary for one safety-state journal.
#[derive(Debug, Clone)]
pub struct SafetyStateStoreProfileV0 {
    core_config: CoreConfig,
    verifier_profile_ref: [u8; 32],
    record_limits: SafetyStateRecordLimitsV0,
    maximum_database_bytes: usize,
}

impl SafetyStateStoreProfileV0 {
    pub fn new(
        core_config: CoreConfig,
        verifier_profile_ref: [u8; 32],
        record_limits: SafetyStateRecordLimitsV0,
        maximum_database_bytes: usize,
    ) -> Result<Self, SafetyStoreErrorV0> {
        SafetyStateRecordContextV0::new(&core_config, verifier_profile_ref, record_limits)
            .map_err(|error| SafetyStoreErrorV0::record("profile capacity preflight", error))?;
        if verifier_profile_ref == [0; 32]
            || record_limits.maximum_record_bytes() > MAXIMUM_SQL_STATE_RECORD_BYTES
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "verifier profile or SQL record bound",
            ));
        }
        let retained_bytes = record_limits
            .maximum_record_bytes()
            .checked_mul(2)
            .and_then(|value| value.checked_add(2 * MAXIMUM_TRANSITION_CONTEXT_BYTES_V0))
            .and_then(|value| value.checked_add(DATABASE_OVERHEAD_BYTES_V0))
            .ok_or(SafetyStoreErrorV0::InvalidProfile(
                "database budget overflow",
            ))?;
        if maximum_database_bytes < retained_bytes || maximum_database_bytes > i64::MAX as usize {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "database budget cannot retain two records and WAL overhead",
            ));
        }
        Ok(Self {
            core_config,
            verifier_profile_ref,
            record_limits,
            maximum_database_bytes,
        })
    }

    pub const fn core_config(&self) -> &CoreConfig {
        &self.core_config
    }

    pub const fn verifier_profile_ref(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }

    pub const fn record_limits(&self) -> SafetyStateRecordLimitsV0 {
        self.record_limits
    }

    pub const fn maximum_database_bytes(&self) -> usize {
        self.maximum_database_bytes
    }

    fn record_context(&self) -> Result<SafetyStateRecordContextV0<'_>, SafetyStoreErrorV0> {
        SafetyStateRecordContextV0::new(
            &self.core_config,
            self.verifier_profile_ref,
            self.record_limits,
        )
        .map_err(|error| SafetyStoreErrorV0::record("construct record context", error))
    }

    fn core_config_ref(&self) -> Result<[u8; 32], SafetyStoreErrorV0> {
        safety_state_record_config_ref_v0(&self.record_context()?)
            .map_err(|error| SafetyStoreErrorV0::record("derive Core config reference", error))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyPersistDispositionV0 {
    Inserted,
    Existing,
    ConfirmedAfterCommitError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactSafetyStateConfirmationV0 {
    Exact,
    Absent,
    Conflict,
}

/// A semantically checked but inert journal head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSafetyStateV0 {
    state: SafetyState,
    transition_context: SafetyTransitionContextV0,
    state_record_checksum: [u8; 32],
    chain_checksum: [u8; 32],
}

impl RecoveredSafetyStateV0 {
    pub const fn state(&self) -> &SafetyState {
        &self.state
    }

    pub const fn transition_context(&self) -> &SafetyTransitionContextV0 {
        &self.transition_context
    }

    pub const fn revision(&self) -> u64 {
        self.state.revision()
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.state_record_checksum
    }

    pub const fn chain_checksum(&self) -> [u8; 32] {
        self.chain_checksum
    }

    pub fn requires_authenticated_obligation_replay(&self) -> bool {
        !self.state.payload_validation_obligations().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    canonical_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredRecordV0 {
    revision: u64,
    predecessor_revision: Option<u64>,
    predecessor_chain_checksum: Option<[u8; 32]>,
    state_record_bytes: Vec<u8>,
    state_record_checksum: [u8; 32],
    transition_context_bytes: Vec<u8>,
    transition_context_checksum: [u8; 32],
    chain_checksum: [u8; 32],
}

struct PreparedRecordV0 {
    revision: u64,
    state_record_bytes: Vec<u8>,
    state_record_checksum: [u8; 32],
    transition_context_bytes: Vec<u8>,
    transition_context_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetainedRecordSummaryV0 {
    revision: u64,
    predecessor_revision: Option<u64>,
    predecessor_chain_checksum: Option<[u8; 32]>,
    chain_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurableHaltFactV0 {
    reason_code: i64,
    revision: Option<u64>,
    evidence_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockWatermarkV0 {
    Stable {
        sequence: u64,
        journal_id: [u8; 32],
        revision: u64,
        chain_checksum: [u8; 32],
    },
    HeadIntent {
        sequence: u64,
        journal_id: [u8; 32],
        source_revision: u64,
        source_chain_checksum: [u8; 32],
        target_revision: u64,
        target_chain_checksum: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurableHaltLatchV0 {
    head_watermark: LockWatermarkV0,
    halt: DurableHaltFactV0,
}

impl LockWatermarkV0 {
    const fn sequence(self) -> u64 {
        match self {
            Self::Stable { sequence, .. } | Self::HeadIntent { sequence, .. } => sequence,
        }
    }

    const fn journal_id(self) -> [u8; 32] {
        match self {
            Self::Stable { journal_id, .. } | Self::HeadIntent { journal_id, .. } => journal_id,
        }
    }
}

type StoredMetadataRowV0 = (
    i64,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
);
type StoredHaltRowV0 = (i64, Option<Vec<u8>>, Vec<u8>, Vec<u8>);

/// Non-cloneable authoritative handle for one node-local safety journal.
pub struct SqliteSafetyStateStoreV0<V> {
    database_path: PathBuf,
    lock_path: PathBuf,
    directory_path: PathBuf,
    database_identity: FileIdentityV0,
    lock_identity: FileIdentityV0,
    directory_identity: FileIdentityV0,
    wal_identity: FileIdentityV0,
    shm_identity: FileIdentityV0,
    connection: ManuallyDrop<Connection>,
    database_file: ManuallyDrop<File>,
    lock_file: ManuallyDrop<File>,
    wal_file: ManuallyDrop<File>,
    shm_file: ManuallyDrop<File>,
    directory_file: ManuallyDrop<File>,
    profile: SafetyStateStoreProfileV0,
    verifier: V,
    core_binding: Option<SafetyStatePersistenceBindingV0>,
    journal_id: [u8; 32],
    observed_lock_watermark: LockWatermarkV0,
    observed_halt_latch: Option<DurableHaltLatchV0>,
    observed_head_revision: u64,
    observed_head_chain_checksum: [u8; 32],
    owner_pid: u32,
    sticky_halt: AtomicBool,
}

impl<V: SignatureVerifier> SqliteSafetyStateStoreV0<V> {
    pub fn initialize_new(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
        genesis_state: &SafetyState,
    ) -> Result<Self, SafetyStoreErrorV0> {
        ensure_supported_file_identity()?;
        if genesis_state.revision() != 0 {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "initial SafetyState revision is not zero",
            ));
        }
        Core::validate_persisted_state_v0(profile.core_config(), genesis_state, &verifier)
            .map_err(|error| SafetyStoreErrorV0::core("validate initial state", error))?;
        Core::recover(
            profile.core_config().clone(),
            genesis_state.clone(),
            &verifier,
        )
        .map_err(|error| SafetyStoreErrorV0::core("prove initial state recoverable", error))?;

        let database_path = canonical_new_path(database_path.as_ref())?;
        let directory_path = database_path
            .parent()
            .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?
            .to_path_buf();
        let directory_file = File::open(&directory_path)
            .map_err(|error| SafetyStoreErrorV0::io("pin safety-store directory", error))?;
        let directory_identity = directory_handle_identity(&directory_file, &directory_path)?;
        ensure_sqlite_auxiliary_files_absent(&database_path)?;
        let lock_path = lock_path_for(&database_path)?;
        if fs::symlink_metadata(&database_path).is_ok() {
            return Err(SafetyStoreErrorV0::AlreadyExists("database"));
        }
        if fs::symlink_metadata(&lock_path).is_ok() {
            return Err(SafetyStoreErrorV0::AlreadyExists("lock sidecar"));
        }
        let journal_id = new_journal_id(&database_path)?;
        let mut lock_file = create_new_private_file(&lock_path, "create lock sidecar")?;
        acquire_lifetime_lock(&lock_file)?;
        initialize_lock_file(&mut lock_file)?;
        sync_directory_handle(&directory_file)?;
        let database_file = create_new_private_file(&database_path, "create database")?;
        acquire_lifetime_lock(&database_file)?;
        let database_identity = file_handle_identity(&database_file, &database_path)?;

        let mut connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("open new database", error))?;
        configure_connection(&connection, true, profile.maximum_database_bytes())?;
        validate_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        let prepared = prepare_record(
            &profile,
            &verifier,
            BarrierId::new(0),
            genesis_state,
            &SafetyTransitionContextV0::Ordinary,
        )?;
        initialize_schema(&mut connection, &profile, journal_id, &prepared)?;
        checkpoint_and_sync_initialization(&connection, &database_file, &directory_file)?;
        let (observed_head_revision, observed_head_chain_checksum, _) =
            read_head(&connection, journal_id)?;
        let observed_lock_watermark = LockWatermarkV0::Stable {
            sequence: 0,
            journal_id,
            revision: observed_head_revision,
            chain_checksum: observed_head_chain_checksum,
        };
        write_lock_watermark(&mut lock_file, observed_lock_watermark)?;
        sync_directory_handle(&directory_file)?;
        materialize_sqlite_auxiliary_files(&connection)?;
        let (wal_file, wal_identity, shm_file, shm_identity) =
            pin_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        // WAL/SHM creation is namespace state. Pinning proves which inodes we
        // opened; syncing the pinned parent makes their directory entries
        // durable before initialization is reported complete.
        sync_directory_handle(&directory_file)?;
        let lock_identity = file_handle_identity(&lock_file, &lock_path)?;
        if !canonical_path_is_stable(&database_path)?
            || !canonical_path_is_stable(&lock_path)?
            || file_identity(&database_path)? != database_identity
            || file_identity(&lock_path)? != lock_identity
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        let store = Self {
            database_identity,
            lock_identity,
            directory_identity,
            wal_identity,
            shm_identity,
            database_path,
            lock_path,
            directory_path,
            connection: ManuallyDrop::new(connection),
            database_file: ManuallyDrop::new(database_file),
            lock_file: ManuallyDrop::new(lock_file),
            wal_file: ManuallyDrop::new(wal_file),
            shm_file: ManuallyDrop::new(shm_file),
            directory_file: ManuallyDrop::new(directory_file),
            profile,
            verifier,
            core_binding: None,
            journal_id,
            observed_lock_watermark,
            observed_halt_latch: None,
            observed_head_revision,
            observed_head_chain_checksum,
            owner_pid: std::process::id(),
            sticky_halt: AtomicBool::new(false),
        };
        store.validate_database()?;
        Ok(store)
    }

    pub fn open_existing(
        database_path: impl AsRef<Path>,
        profile: SafetyStateStoreProfileV0,
        verifier: V,
    ) -> Result<Self, SafetyStoreErrorV0> {
        ensure_supported_file_identity()?;
        let database_path = canonical_existing_database_path(database_path.as_ref())?;
        let directory_path = database_path
            .parent()
            .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?
            .to_path_buf();
        let directory_file = File::open(&directory_path)
            .map_err(|error| SafetyStoreErrorV0::io("pin safety-store directory", error))?;
        let directory_identity = directory_handle_identity(&directory_file, &directory_path)?;
        validate_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        require_persistent_sqlite_auxiliary_files(&database_path)?;
        let lock_path = lock_path_for(&database_path)?;
        let lock_file = open_existing_private_file(&lock_path, "open lock sidecar")?;
        acquire_lifetime_lock(&lock_file)?;
        let lock_watermark = read_lock_watermark(&lock_file)?;
        let halt_latch = read_halt_latch(&lock_file)?;
        let journal_id = lock_watermark.journal_id();
        let lock_identity = file_handle_identity(&lock_file, &lock_path)?;
        if !canonical_path_is_stable(&lock_path)? || file_identity(&lock_path)? != lock_identity {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        let database_file = open_existing_private_file(&database_path, "pin existing database")?;
        acquire_lifetime_lock(&database_file)?;
        let database_identity = file_handle_identity(&database_file, &database_path)?;
        let (wal_file, wal_identity, shm_file, shm_identity) =
            pin_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("open existing database", error))?;
        configure_connection(&connection, false, profile.maximum_database_bytes())?;
        materialize_sqlite_auxiliary_files(&connection)?;
        validate_sqlite_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        if file_identity(&database_path)? != database_identity
            || file_identity(&lock_path)? != lock_identity
            || file_identity(&sqlite_auxiliary_path(&database_path, "-wal"))? != wal_identity
            || file_identity(&sqlite_auxiliary_path(&database_path, "-shm"))? != shm_identity
        {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        let (observed_head_revision, observed_head_chain_checksum) = match lock_watermark {
            LockWatermarkV0::Stable {
                revision,
                chain_checksum,
                ..
            }
            | LockWatermarkV0::HeadIntent {
                source_revision: revision,
                source_chain_checksum: chain_checksum,
                ..
            } => (revision, chain_checksum),
        };
        let mut store = Self {
            database_identity,
            lock_identity,
            directory_identity,
            wal_identity,
            shm_identity,
            database_path,
            lock_path,
            directory_path,
            connection: ManuallyDrop::new(connection),
            database_file: ManuallyDrop::new(database_file),
            lock_file: ManuallyDrop::new(lock_file),
            wal_file: ManuallyDrop::new(wal_file),
            shm_file: ManuallyDrop::new(shm_file),
            directory_file: ManuallyDrop::new(directory_file),
            profile,
            verifier,
            core_binding: None,
            journal_id,
            observed_lock_watermark: lock_watermark,
            observed_halt_latch: halt_latch,
            observed_head_revision,
            observed_head_chain_checksum,
            owner_pid: std::process::id(),
            sticky_halt: AtomicBool::new(false),
        };
        store.resolve_open_watermark()?;
        store.validate_database()?;
        if durable_halt_present(&store.connection)? {
            store.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::DurableHalt);
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        self.database_path.as_path()
    }

    /// Affines future writes to one host-designated Core instance.
    ///
    /// Opening and inspecting an inert obligation-bearing head does not require
    /// a live Core. Binding is therefore an explicit, one-way runtime step
    /// after the host has legitimately constructed or recovered its Core.
    pub fn bind_core_v0(
        &mut self,
        binding: SafetyStatePersistenceBindingV0,
    ) -> Result<(), SafetyStoreErrorV0> {
        if std::process::id() != self.owner_pid {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::ProcessChanged,
            ));
        }
        if self.core_binding.is_some() {
            return Err(SafetyStoreErrorV0::CoreAlreadyBound);
        }
        self.core_binding = Some(binding);
        Ok(())
    }

    pub fn head(&self) -> Result<RecoveredSafetyStateV0, SafetyStoreErrorV0> {
        self.ensure_file_identity()?;
        self.ensure_not_halted()?;
        validate_transaction_environment(&self.connection, &self.profile, self.journal_id)?;
        validate_storage_resource_bounds(&self.connection, &self.profile)?;
        validate_all_records(
            &self.connection,
            &self.profile,
            &self.verifier,
            self.journal_id,
        )?;
        let (active_revision, active_checksum, _) = read_head(&self.connection, self.journal_id)?;
        if active_revision != self.observed_head_revision
            || active_checksum != self.observed_head_chain_checksum
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "head differs from durable lock watermark",
            ));
        }
        let row = read_active_record(&self.connection)?;
        if row.chain_checksum != active_checksum {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "active head checksum does not identify active record",
            ));
        }
        let recovered = decode_and_validate_record(&row, &self.profile, &self.verifier)?;
        self.postcheck_primary_resources()?;
        Ok(recovered)
    }

    pub fn persist_exact_v0(
        &mut self,
        request: &SafetyStatePersistenceV0,
        transition_context: &SafetyTransitionContextV0,
    ) -> Result<SafetyPersistDispositionV0, SafetyStoreErrorV0> {
        let binding = self
            .core_binding
            .as_ref()
            .ok_or(SafetyStoreErrorV0::CoreNotBound)?;
        if !binding.accepts(request) {
            return Err(SafetyStoreErrorV0::CoreAffinityMismatch);
        }
        self.ensure_file_identity()?;
        self.ensure_not_halted()?;
        let barrier = request.barrier();
        let state = request.state();
        let prepared = prepare_record(
            &self.profile,
            &self.verifier,
            barrier,
            state,
            transition_context,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| SafetyStoreErrorV0::sqlite("begin persistence transaction", error))?;
        validate_transaction_environment(&transaction, &self.profile, self.journal_id)?;
        ensure_not_halted_connection(&transaction)?;
        validate_storage_resource_bounds(&transaction, &self.profile)?;
        validate_all_records(&transaction, &self.profile, &self.verifier, self.journal_id)?;
        let (active_revision, active_chain_checksum, retention_floor) =
            read_head(&transaction, self.journal_id)?;
        let stable_sequence = match self.observed_lock_watermark {
            LockWatermarkV0::Stable {
                sequence,
                journal_id,
                revision,
                chain_checksum,
            } if journal_id == self.journal_id
                && revision == active_revision
                && chain_checksum == active_chain_checksum =>
            {
                sequence
            }
            _ => {
                self.sticky_halt.store(true, Ordering::Release);
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "persistence began without an exact stable watermark",
                ));
            }
        };
        if active_revision != self.observed_head_revision
            || active_chain_checksum != self.observed_head_chain_checksum
        {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "live head differs from durable lock watermark",
            ));
        }
        let active = read_active_record(&transaction)?;
        if active.revision != active_revision || active.chain_checksum != active_chain_checksum {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "active head changed inside persistence transaction",
            ));
        }

        if prepared.revision == active_revision {
            if prepared_matches_stored(&prepared, &active) {
                transaction
                    .rollback()
                    .map_err(|error| SafetyStoreErrorV0::sqlite("finish exact retry", error))?;
                self.postcheck_primary_resources()?;
                return Ok(SafetyPersistDispositionV0::Existing);
            }
            return Err(commit_conflict(
                transaction,
                &self.sticky_halt,
                &mut self.lock_file,
                ObservedDurabilityStateV0 {
                    head_watermark: &mut self.observed_lock_watermark,
                    halt_latch: &mut self.observed_halt_latch,
                },
                ConflictStableHeadV0 {
                    sequence: stable_sequence,
                    journal_id: self.journal_id,
                    revision: active_revision,
                    chain_checksum: active_chain_checksum,
                },
                SafetyStoreConflictV0::SameRevisionDifferentRecord {
                    revision: prepared.revision,
                },
            ));
        }
        if prepared.revision < active_revision {
            return Err(commit_conflict(
                transaction,
                &self.sticky_halt,
                &mut self.lock_file,
                ObservedDurabilityStateV0 {
                    head_watermark: &mut self.observed_lock_watermark,
                    halt_latch: &mut self.observed_halt_latch,
                },
                ConflictStableHeadV0 {
                    sequence: stable_sequence,
                    journal_id: self.journal_id,
                    revision: active_revision,
                    chain_checksum: active_chain_checksum,
                },
                SafetyStoreConflictV0::RevisionRegression {
                    active: active_revision,
                    incoming: prepared.revision,
                },
            ));
        }
        if active_revision.checked_add(1) != Some(prepared.revision) {
            return Err(commit_conflict(
                transaction,
                &self.sticky_halt,
                &mut self.lock_file,
                ObservedDurabilityStateV0 {
                    head_watermark: &mut self.observed_lock_watermark,
                    halt_latch: &mut self.observed_halt_latch,
                },
                ConflictStableHeadV0 {
                    sequence: stable_sequence,
                    journal_id: self.journal_id,
                    revision: active_revision,
                    chain_checksum: active_chain_checksum,
                },
                SafetyStoreConflictV0::RevisionGap {
                    active: active_revision,
                    incoming: prepared.revision,
                },
            ));
        }
        let active_state =
            decode_and_validate_record(&active, &self.profile, &self.verifier)?.state;
        Core::validate_persisted_successor_v0(
            self.profile.core_config(),
            &active_state,
            state,
            &self.verifier,
        )
        .map_err(|error| SafetyStoreErrorV0::core("validate incoming successor", error))?;

        if retention_floor < active_revision {
            let deleted = transaction
                .execute(
                    "DELETE FROM safety_state_records_v0 WHERE revision_be=?1",
                    params![retention_floor.to_be_bytes().as_slice()],
                )
                .map_err(|error| {
                    SafetyStoreErrorV0::sqlite("release retained floor record", error)
                })?;
            if deleted != 1 {
                self.sticky_halt.store(true, Ordering::Release);
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "retention floor did not identify one record",
                ));
            }
        }

        let row = stored_record_from_prepared(
            &prepared,
            Some(active_revision),
            Some(active_chain_checksum),
            self.journal_id,
        );
        insert_record(&transaction, &row)?;
        let retention_floor = active_revision;
        let head_checksum = head_checksum(
            self.journal_id,
            row.revision,
            row.chain_checksum,
            retention_floor,
        );
        let updated = transaction
            .execute(
                "UPDATE safety_state_head_v0
                 SET active_revision_be=?1, active_chain_checksum=?2,
                     retention_floor_revision_be=?3, head_checksum=?4
                 WHERE singleton=1 AND active_revision_be=?5 AND active_chain_checksum=?6",
                params![
                    row.revision.to_be_bytes().as_slice(),
                    row.chain_checksum.as_slice(),
                    retention_floor.to_be_bytes().as_slice(),
                    head_checksum.as_slice(),
                    active_revision.to_be_bytes().as_slice(),
                    active_chain_checksum.as_slice(),
                ],
            )
            .map_err(|error| SafetyStoreErrorV0::sqlite("advance active head", error))?;
        if updated != 1 {
            return Err(commit_conflict(
                transaction,
                &self.sticky_halt,
                &mut self.lock_file,
                ObservedDurabilityStateV0 {
                    head_watermark: &mut self.observed_lock_watermark,
                    halt_latch: &mut self.observed_halt_latch,
                },
                ConflictStableHeadV0 {
                    sequence: stable_sequence,
                    journal_id: self.journal_id,
                    revision: active_revision,
                    chain_checksum: active_chain_checksum,
                },
                SafetyStoreConflictV0::HeadChanged,
            ));
        }
        transaction
            .execute(
                "DELETE FROM safety_state_records_v0 WHERE revision_be < ?1",
                params![retention_floor.to_be_bytes().as_slice()],
            )
            .map_err(|error| SafetyStoreErrorV0::sqlite("prune old safety records", error))?;
        rewrite_accounting(&transaction)?;
        validate_storage_resource_bounds(&transaction, &self.profile)?;
        validate_all_records(&transaction, &self.profile, &self.verifier, self.journal_id)?;

        let readback = read_active_record(&transaction)?;
        if readback != row {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "transactional record readback differs",
            ));
        }
        let decoded = decode_and_validate_record(&readback, &self.profile, &self.verifier)?;
        if decoded.state() != state || decoded.transition_context() != transition_context {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "transactional semantic readback differs",
            ));
        }

        let intent_sequence = preflight_intent_sequence(stable_sequence)?;
        let intent = LockWatermarkV0::HeadIntent {
            sequence: intent_sequence,
            journal_id: self.journal_id,
            source_revision: active_revision,
            source_chain_checksum: active_chain_checksum,
            target_revision: row.revision,
            target_chain_checksum: row.chain_checksum,
        };
        // The durable intent must precede SQLite's commit marker. Its write
        // targets the other slot, preserving the last Stable watermark.
        if let Err(source) = write_lock_watermark(&mut self.lock_file, intent) {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::HeadWatermarkUncertain {
                source: Box::new(source),
            });
        }
        self.observed_lock_watermark = intent;

        match transaction.commit() {
            Ok(()) => {
                if let Err(source) = self.sync_confirmed_sqlite_commit() {
                    self.sticky_halt.store(true, Ordering::Release);
                    return Err(SafetyStoreErrorV0::HeadWatermarkUncertain {
                        source: Box::new(source),
                    });
                }
                self.resolve_head_watermark(row.revision, row.chain_checksum)?;
                Ok(SafetyPersistDispositionV0::Inserted)
            }
            Err(commit_error) => match self.confirm_stored_exact(&row) {
                Ok(ExactSafetyStateConfirmationV0::Exact) => {
                    if let Err(confirmation) = self.sync_confirmed_sqlite_commit() {
                        self.sticky_halt.store(true, Ordering::Release);
                        return Err(SafetyStoreErrorV0::CommitUncertain {
                            commit: commit_error,
                            confirmation: Box::new(confirmation),
                        });
                    }
                    self.resolve_head_watermark(row.revision, row.chain_checksum)?;
                    Ok(SafetyPersistDispositionV0::ConfirmedAfterCommitError)
                }
                Ok(ExactSafetyStateConfirmationV0::Absent) => {
                    self.resolve_head_watermark(active_revision, active_chain_checksum)?;
                    Err(SafetyStoreErrorV0::CommitNotApplied {
                        commit: commit_error,
                    })
                }
                Ok(ExactSafetyStateConfirmationV0::Conflict) => {
                    self.sticky_halt.store(true, Ordering::Release);
                    let conflict = SafetyStoreConflictV0::CommitReadbackConflict;
                    self.terminalize_head_intent(conflict)?;
                    Err(SafetyStoreErrorV0::Conflict(conflict))
                }
                Err(confirmation) => {
                    self.sticky_halt.store(true, Ordering::Release);
                    Err(SafetyStoreErrorV0::CommitUncertain {
                        commit: commit_error,
                        confirmation: Box::new(confirmation),
                    })
                }
            },
        }
    }

    fn confirm_stored_exact(
        &self,
        expected: &StoredRecordV0,
    ) -> Result<ExactSafetyStateConfirmationV0, SafetyStoreErrorV0> {
        self.ensure_file_identity()?;
        self.ensure_not_halted()?;
        if !self.connection.is_autocommit() {
            self.sticky_halt.store(true, Ordering::Release);
            return Ok(ExactSafetyStateConfirmationV0::Conflict);
        }
        let connection = &*self.connection;
        validate_transaction_environment(connection, &self.profile, self.journal_id)?;
        validate_storage_resource_bounds(connection, &self.profile)?;
        if durable_halt_present(connection)? {
            self.ensure_file_identity()?;
            return Ok(ExactSafetyStateConfirmationV0::Conflict);
        }
        validate_all_records(connection, &self.profile, &self.verifier, self.journal_id)?;
        self.ensure_file_identity()?;
        let (active_revision, active_chain_checksum, _) = read_head(connection, self.journal_id)?;
        let active = read_active_record(connection)?;
        let outcome = if active_revision == expected.revision {
            if active.chain_checksum == active_chain_checksum && active == *expected {
                ExactSafetyStateConfirmationV0::Exact
            } else {
                ExactSafetyStateConfirmationV0::Conflict
            }
        } else if expected.predecessor_revision == Some(active_revision)
            && expected.predecessor_chain_checksum == Some(active_chain_checksum)
            && connection
                .query_row(
                    "SELECT 1 FROM safety_state_records_v0 WHERE revision_be=?1",
                    params![expected.revision.to_be_bytes().as_slice()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| {
                    SafetyStoreErrorV0::sqlite("confirm absent target revision", error)
                })?
                .is_none()
        {
            ExactSafetyStateConfirmationV0::Absent
        } else {
            ExactSafetyStateConfirmationV0::Conflict
        };
        validate_storage_resource_bounds(connection, &self.profile)?;
        self.ensure_file_identity()?;
        Ok(outcome)
    }

    fn ensure_file_identity(&self) -> Result<(), SafetyStoreErrorV0> {
        if std::process::id() != self.owner_pid {
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::ProcessChanged,
            ));
        }
        let matches = (|| {
            let wal_path = sqlite_auxiliary_path(&self.database_path, "-wal");
            let shm_path = sqlite_auxiliary_path(&self.database_path, "-shm");
            validate_sqlite_auxiliary_files(
                &self.database_path,
                self.profile.maximum_database_bytes(),
            )?;
            validate_private_directory(&self.directory_path)?;
            Ok::<_, SafetyStoreErrorV0>(
                canonical_path_is_stable(&self.database_path)?
                    && canonical_path_is_stable(&self.lock_path)?
                    && canonical_path_is_stable(&self.directory_path)?
                    && canonical_path_is_stable(&wal_path)?
                    && canonical_path_is_stable(&shm_path)?
                    && file_identity(&self.database_path)? == self.database_identity
                    && file_identity(&self.lock_path)? == self.lock_identity
                    && file_identity(&wal_path)? == self.wal_identity
                    && file_identity(&shm_path)? == self.shm_identity
                    && directory_identity(&self.directory_path)? == self.directory_identity
                    && file_handle_identity(&self.database_file, &self.database_path)?
                        == self.database_identity
                    && file_handle_identity(&self.lock_file, &self.lock_path)?
                        == self.lock_identity
                    && file_handle_identity(&self.wal_file, &wal_path)? == self.wal_identity
                    && file_handle_identity(&self.shm_file, &shm_path)? == self.shm_identity
                    && directory_handle_identity(&self.directory_file, &self.directory_path)?
                        == self.directory_identity
                    && read_lock_watermark(&self.lock_file)? == self.observed_lock_watermark
                    && read_halt_latch(&self.lock_file)? == self.observed_halt_latch,
            )
        })();
        if !matches.unwrap_or(false) {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::Conflict(
                SafetyStoreConflictV0::FileIdentityChanged,
            ));
        }
        Ok(())
    }

    fn postcheck_primary_resources(&self) -> Result<(), SafetyStoreErrorV0> {
        self.ensure_file_identity()?;
        validate_storage_resource_bounds(&self.connection, &self.profile)
    }

    fn resolve_head_watermark(
        &mut self,
        revision: u64,
        chain_checksum: [u8; 32],
    ) -> Result<(), SafetyStoreErrorV0> {
        let sequence = self
            .observed_lock_watermark
            .sequence()
            .checked_add(1)
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "lock watermark sequence overflow",
            ))?;
        let stable = LockWatermarkV0::Stable {
            sequence,
            journal_id: self.journal_id,
            revision,
            chain_checksum,
        };
        if let Err(source) = write_lock_watermark(&mut self.lock_file, stable) {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::HeadWatermarkUncertain {
                source: Box::new(source),
            });
        }
        self.observed_lock_watermark = stable;
        self.observed_head_revision = revision;
        self.observed_head_chain_checksum = chain_checksum;
        self.postcheck_primary_resources()
    }

    fn terminalize_head_intent(
        &mut self,
        conflict: SafetyStoreConflictV0,
    ) -> Result<(), SafetyStoreErrorV0> {
        if !matches!(
            self.observed_lock_watermark,
            LockWatermarkV0::HeadIntent { .. }
        ) {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "commit conflict did not retain its head intent",
            ));
        }
        let latch = DurableHaltLatchV0 {
            head_watermark: self.observed_lock_watermark,
            halt: halt_fact_for_conflict(self.journal_id, conflict),
        };
        write_halt_latch(&mut self.lock_file, latch)
            .map_err(|source| conflict_halt_uncertain(conflict, source))?;
        self.observed_halt_latch = Some(latch);
        Ok(())
    }

    fn sync_confirmed_sqlite_commit(&self) -> Result<(), SafetyStoreErrorV0> {
        self.database_file
            .sync_all()
            .map_err(|error| SafetyStoreErrorV0::io("sync confirmed SQLite database", error))?;
        self.wal_file
            .sync_all()
            .map_err(|error| SafetyStoreErrorV0::io("sync confirmed SQLite WAL", error))?;
        self.directory_file
            .sync_all()
            .map_err(|error| SafetyStoreErrorV0::io("sync confirmed SQLite namespace", error))?;
        self.ensure_file_identity()
    }

    fn ensure_not_halted(&self) -> Result<(), SafetyStoreErrorV0> {
        if self.observed_halt_latch.is_some()
            || self.sticky_halt.load(Ordering::Acquire)
            || durable_halt_present(&self.connection)?
        {
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::DurableHalt);
        }
        Ok(())
    }

    fn resolve_open_watermark(&mut self) -> Result<(), SafetyStoreErrorV0> {
        // No sidecar state, including a terminal halt, is trusted until the
        // SQLite schema, bindings, resource accounting, record chain, and
        // Core semantics have all passed deep validation.
        let (active_revision, active_chain_checksum, durable_halt) =
            self.validate_database_contents()?;
        let (resolved_revision, resolved_chain_checksum, needs_head_resolution) =
            match self.observed_lock_watermark {
                LockWatermarkV0::Stable {
                    journal_id,
                    revision,
                    chain_checksum,
                    ..
                } if journal_id == self.journal_id
                    && revision == active_revision
                    && chain_checksum == active_chain_checksum =>
                {
                    (revision, chain_checksum, false)
                }
                LockWatermarkV0::HeadIntent {
                    journal_id,
                    source_revision,
                    source_chain_checksum,
                    target_revision,
                    target_chain_checksum,
                    ..
                } if journal_id == self.journal_id => {
                    if active_revision == source_revision
                        && active_chain_checksum == source_chain_checksum
                    {
                        (source_revision, source_chain_checksum, true)
                    } else if active_revision == target_revision
                        && active_chain_checksum == target_chain_checksum
                    {
                        (target_revision, target_chain_checksum, true)
                    } else {
                        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                            "intent watermark matches neither exact source nor exact target",
                        ));
                    }
                }
                _ => {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "database head differs from durable lock watermark",
                    ));
                }
            };

        if let Some(latch) = self.observed_halt_latch {
            if latch.head_watermark != self.observed_lock_watermark {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "terminal halt latch differs from selected head watermark",
                ));
            }
            if durable_halt.is_some_and(|stored| stored != latch.halt) {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "durable halt row differs from terminal halt latch",
                ));
            }
            self.observed_head_revision = resolved_revision;
            self.observed_head_chain_checksum = resolved_chain_checksum;
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::DurableHalt);
        }
        if durable_halt.is_some() {
            self.observed_head_revision = resolved_revision;
            self.observed_head_chain_checksum = resolved_chain_checksum;
            self.sticky_halt.store(true, Ordering::Release);
            return Err(SafetyStoreErrorV0::DurableHalt);
        }
        if needs_head_resolution {
            self.sync_confirmed_sqlite_commit()?;
            self.resolve_head_watermark(resolved_revision, resolved_chain_checksum)
        } else {
            self.observed_head_revision = resolved_revision;
            self.observed_head_chain_checksum = resolved_chain_checksum;
            Ok(())
        }
    }

    fn validate_database_contents(
        &self,
    ) -> Result<(u64, [u8; 32], Option<DurableHaltFactV0>), SafetyStoreErrorV0> {
        self.ensure_file_identity()?;
        validate_canonical_schema(&self.connection)?;
        validate_metadata(&self.connection, &self.profile, self.journal_id)?;
        validate_storage_resource_bounds(&self.connection, &self.profile)?;
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|error| SafetyStoreErrorV0::sqlite("run integrity check", error))?;
        if integrity != "ok" {
            return Err(SafetyStoreErrorV0::IntegrityFailure);
        }
        let mut foreign_keys = self
            .connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| SafetyStoreErrorV0::sqlite("prepare foreign-key check", error))?;
        if foreign_keys
            .query([])
            .map_err(|error| SafetyStoreErrorV0::sqlite("run foreign-key check", error))?
            .next()
            .map_err(|error| SafetyStoreErrorV0::sqlite("read foreign-key check", error))?
            .is_some()
        {
            return Err(SafetyStoreErrorV0::ForeignKeyFailure);
        }
        drop(foreign_keys);
        validate_all_records(
            &self.connection,
            &self.profile,
            &self.verifier,
            self.journal_id,
        )?;
        let (active_revision, active_chain_checksum, _) =
            read_head(&self.connection, self.journal_id)?;
        let durable_halt = read_validated_durable_halt(&self.connection, self.journal_id)?;
        self.ensure_file_identity()?;
        Ok((active_revision, active_chain_checksum, durable_halt))
    }

    fn validate_database(&self) -> Result<(), SafetyStoreErrorV0> {
        let (active_revision, active_chain_checksum, _) = self.validate_database_contents()?;
        if !matches!(
            self.observed_lock_watermark,
            LockWatermarkV0::Stable {
                journal_id,
                revision,
                chain_checksum,
                ..
            } if journal_id == self.journal_id
                && revision == self.observed_head_revision
                && chain_checksum == self.observed_head_chain_checksum
        ) || active_revision != self.observed_head_revision
            || active_chain_checksum != self.observed_head_chain_checksum
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "database head differs from stable lock watermark",
            ));
        }
        Ok(())
    }
}

impl<V> Drop for SqliteSafetyStateStoreV0<V> {
    fn drop(&mut self) {
        if std::process::id() != self.owner_pid {
            // A post-fork child must not run SQLite cleanup or unlock inherited
            // open-file descriptions. The kernel reclaims these descriptors
            // when the unsupported child exits or execs.
            return;
        }
        // SAFETY: each field is initialized exactly once, wrapped immediately,
        // and dropped exactly here. SQLite must close before its pinned main,
        // WAL, SHM, and lock handles.
        unsafe {
            ManuallyDrop::drop(&mut self.connection);
            ManuallyDrop::drop(&mut self.shm_file);
            ManuallyDrop::drop(&mut self.wal_file);
            ManuallyDrop::drop(&mut self.database_file);
            ManuallyDrop::drop(&mut self.lock_file);
            ManuallyDrop::drop(&mut self.directory_file);
        }
    }
}

fn prepare_record<V: SignatureVerifier>(
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    barrier: BarrierId,
    state: &SafetyState,
    transition_context: &SafetyTransitionContextV0,
) -> Result<PreparedRecordV0, SafetyStoreErrorV0> {
    if barrier.get() != state.revision() {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "barrier does not equal SafetyState revision",
        ));
    }
    Core::validate_persisted_state_v0(profile.core_config(), state, verifier)
        .map_err(|error| SafetyStoreErrorV0::core("validate state before persistence", error))?;
    validate_transition_context_against_state_v0(transition_context, state)?;
    let context = profile.record_context()?;
    let state_record_bytes = encode_safety_state_record_v0(state, &context)
        .map_err(|error| SafetyStoreErrorV0::record("encode state for persistence", error))?;
    let decoded = decode_safety_state_record_v0_exact(&state_record_bytes, &context)
        .map_err(|error| SafetyStoreErrorV0::record("read back encoded state", error))?;
    let transition_context_bytes = encode_transition_context_v0(transition_context)?;
    let transition_context_checksum = transition_context_checksum_v0(&transition_context_bytes)?;
    Ok(PreparedRecordV0 {
        revision: state.revision(),
        state_record_checksum: decoded.record_checksum(),
        state_record_bytes,
        transition_context_bytes,
        transition_context_checksum,
    })
}

fn prepared_matches_stored(prepared: &PreparedRecordV0, stored: &StoredRecordV0) -> bool {
    prepared.revision == stored.revision
        && prepared.state_record_bytes == stored.state_record_bytes
        && prepared.state_record_checksum == stored.state_record_checksum
        && prepared.transition_context_bytes == stored.transition_context_bytes
        && prepared.transition_context_checksum == stored.transition_context_checksum
}

fn stored_record_from_prepared(
    prepared: &PreparedRecordV0,
    predecessor_revision: Option<u64>,
    predecessor_chain_checksum: Option<[u8; 32]>,
    journal_id: [u8; 32],
) -> StoredRecordV0 {
    let chain_checksum = chain_checksum(
        journal_id,
        prepared.revision,
        predecessor_revision,
        predecessor_chain_checksum,
        prepared.state_record_checksum,
        prepared.transition_context_checksum,
    );
    StoredRecordV0 {
        revision: prepared.revision,
        predecessor_revision,
        predecessor_chain_checksum,
        state_record_bytes: prepared.state_record_bytes.clone(),
        state_record_checksum: prepared.state_record_checksum,
        transition_context_bytes: prepared.transition_context_bytes.clone(),
        transition_context_checksum: prepared.transition_context_checksum,
        chain_checksum,
    }
}

fn initialize_schema(
    connection: &mut Connection,
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
    prepared: &PreparedRecordV0,
) -> Result<(), SafetyStoreErrorV0> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| SafetyStoreErrorV0::sqlite("begin initialization", error))?;
    transaction
        .execute_batch(JOURNAL_SCHEMA_SQL_V1)
        .map_err(|error| SafetyStoreErrorV0::sqlite("install safety-store schema", error))?;
    let metadata = metadata_values(profile, journal_id)?;
    if transaction
        .execute(
            "INSERT INTO safety_store_metadata_v0(
                singleton, journal_schema, journal_id, core_record_codec,
                safety_schema, core_config_ref, verifier_profile_ref,
                maximum_record_bytes_be, maximum_blob_bytes_be,
                maximum_database_bytes_be, transition_codec, metadata_checksum
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                i64::from(JOURNAL_SCHEMA_VERSION_V1),
                journal_id.as_slice(),
                i64::from(SAFETY_STATE_RECORD_CODEC_VERSION_V0),
                i64::from(SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0),
                metadata.core_config_ref.as_slice(),
                profile.verifier_profile_ref().as_slice(),
                usize_to_u64(
                    profile.record_limits().maximum_record_bytes(),
                    "record limit"
                )?
                .to_be_bytes()
                .as_slice(),
                usize_to_u64(profile.record_limits().maximum_blob_bytes(), "blob limit")?
                    .to_be_bytes()
                    .as_slice(),
                usize_to_u64(profile.maximum_database_bytes(), "database limit")?
                    .to_be_bytes()
                    .as_slice(),
                i64::from(TRANSITION_CONTEXT_CODEC_V0),
                metadata.checksum.as_slice(),
            ],
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("insert safety-store metadata", error))?
        != 1
    {
        return Err(SafetyStoreErrorV0::MetadataMismatch);
    }
    let row = stored_record_from_prepared(prepared, None, None, journal_id);
    insert_record(&transaction, &row)?;
    let head = head_checksum(journal_id, 0, row.chain_checksum, 0);
    transaction
        .execute(
            "INSERT INTO safety_state_head_v0(
                singleton, active_revision_be, active_chain_checksum,
                retention_floor_revision_be, head_checksum
             ) VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                0u64.to_be_bytes().as_slice(),
                row.chain_checksum.as_slice(),
                0u64.to_be_bytes().as_slice(),
                head.as_slice(),
            ],
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("insert initial head", error))?;
    rewrite_accounting(&transaction)?;
    validate_transaction_environment(&transaction, profile, journal_id)?;
    let readback = read_active_record(&transaction)?;
    if readback != row {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "initial record readback differs",
        ));
    }
    transaction
        .commit()
        .map_err(|error| SafetyStoreErrorV0::sqlite("commit initialization", error))
}

fn insert_record(connection: &Connection, row: &StoredRecordV0) -> Result<(), SafetyStoreErrorV0> {
    let inserted = connection
        .execute(
            "INSERT INTO safety_state_records_v0(
                revision_be, predecessor_revision_be, predecessor_chain_checksum,
                state_record_bytes, state_record_checksum,
                transition_context_bytes, transition_context_checksum, chain_checksum
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.revision.to_be_bytes().as_slice(),
                row.predecessor_revision
                    .map(u64::to_be_bytes)
                    .as_ref()
                    .map(<[u8; 8]>::as_slice),
                row.predecessor_chain_checksum
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                row.state_record_bytes,
                row.state_record_checksum.as_slice(),
                row.transition_context_bytes,
                row.transition_context_checksum.as_slice(),
                row.chain_checksum.as_slice(),
            ],
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("insert safety-state record", error))?;
    if inserted != 1 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "record insertion did not affect one row",
        ));
    }
    Ok(())
}

fn rewrite_accounting(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    let accounting: (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(state_record_bytes)),0),
                    COALESCE(SUM(length(transition_context_bytes)),0)
             FROM safety_state_records_v0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("derive safety-store accounting", error))?;
    if !(1..=2).contains(&accounting.0) || accounting.1 <= 0 || accounting.2 < 3 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "derived accounting is outside journal bounds",
        ));
    }
    let changed = connection
        .execute(
            "INSERT INTO safety_state_accounting_v0(
                singleton, record_count, state_bytes, transition_bytes
             ) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(singleton) DO UPDATE SET
                record_count=excluded.record_count,
                state_bytes=excluded.state_bytes,
                transition_bytes=excluded.transition_bytes",
            params![accounting.0, accounting.1, accounting.2],
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("write safety-store accounting", error))?;
    if changed != 1 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "accounting update did not affect one row",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct MetadataValuesV0 {
    core_config_ref: [u8; 32],
    checksum: [u8; 32],
}

fn metadata_values(
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
) -> Result<MetadataValuesV0, SafetyStoreErrorV0> {
    let core_config_ref = profile.core_config_ref()?;
    let journal_schema = JOURNAL_SCHEMA_VERSION_V1.to_be_bytes();
    let record_codec = SAFETY_STATE_RECORD_CODEC_VERSION_V0.to_be_bytes();
    let safety_schema = SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0.to_be_bytes();
    let record_limit = usize_to_u64(
        profile.record_limits().maximum_record_bytes(),
        "record limit",
    )?
    .to_be_bytes();
    let blob_limit =
        usize_to_u64(profile.record_limits().maximum_blob_bytes(), "blob limit")?.to_be_bytes();
    let database_limit =
        usize_to_u64(profile.maximum_database_bytes(), "database limit")?.to_be_bytes();
    let transition_codec = TRANSITION_CONTEXT_CODEC_V0.to_be_bytes();
    let checksum = hash_domain(
        METADATA_DOMAIN_V0,
        &[
            &journal_schema,
            &journal_id,
            &record_codec,
            &safety_schema,
            &core_config_ref,
            &profile.verifier_profile_ref,
            &record_limit,
            &blob_limit,
            &database_limit,
            &transition_codec,
        ],
    );
    Ok(MetadataValuesV0 {
        core_config_ref,
        checksum,
    })
}

fn validate_metadata(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
) -> Result<(), SafetyStoreErrorV0> {
    let row: StoredMetadataRowV0 = connection
        .query_row(
            "SELECT journal_schema, journal_id, core_record_codec, safety_schema,
                        core_config_ref, verifier_profile_ref, maximum_record_bytes_be,
                        maximum_blob_bytes_be, maximum_database_bytes_be,
                        transition_codec, metadata_checksum
                 FROM safety_store_metadata_v0 WHERE singleton=1",
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
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("read safety-store metadata", error))?;
    let expected = metadata_values(profile, journal_id)?;
    let metadata_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM safety_store_metadata_v0", [], |row| {
            row.get(0)
        })
        .map_err(|error| SafetyStoreErrorV0::sqlite("count safety-store metadata", error))?;
    if metadata_count != 1
        || row.0 != i64::from(JOURNAL_SCHEMA_VERSION_V1)
        || row.1.as_slice() != journal_id.as_slice()
        || row.2 != i64::from(SAFETY_STATE_RECORD_CODEC_VERSION_V0)
        || row.3 != i64::from(SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0)
        || row.4.as_slice() != expected.core_config_ref.as_slice()
        || row.5.as_slice() != profile.verifier_profile_ref.as_slice()
        || decode_u64_blob(&row.6, "record limit")?
            != usize_to_u64(profile.record_limits.maximum_record_bytes(), "record limit")?
        || decode_u64_blob(&row.7, "blob limit")?
            != usize_to_u64(profile.record_limits.maximum_blob_bytes(), "blob limit")?
        || decode_u64_blob(&row.8, "database limit")?
            != usize_to_u64(profile.maximum_database_bytes, "database limit")?
        || row.9 != i64::from(TRANSITION_CONTEXT_CODEC_V0)
        || row.10.as_slice() != expected.checksum.as_slice()
    {
        return Err(SafetyStoreErrorV0::MetadataMismatch);
    }
    Ok(())
}

fn read_active_record(connection: &Connection) -> Result<StoredRecordV0, SafetyStoreErrorV0> {
    connection
        .query_row(
            "SELECT r.revision_be, r.predecessor_revision_be,
                    r.predecessor_chain_checksum, r.state_record_bytes,
                    r.state_record_checksum, r.transition_context_bytes,
                    r.transition_context_checksum, r.chain_checksum
             FROM safety_state_head_v0 h
             JOIN safety_state_records_v0 r
               ON r.revision_be=h.active_revision_be
              AND r.chain_checksum=h.active_chain_checksum
             WHERE h.singleton=1",
            [],
            decode_stored_record_row,
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("read active safety record", error))
}

fn decode_stored_record_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRecordV0> {
    let revision: Vec<u8> = row.get(0)?;
    let predecessor_revision: Option<Vec<u8>> = row.get(1)?;
    let predecessor_chain_checksum: Option<Vec<u8>> = row.get(2)?;
    let state_record_checksum: Vec<u8> = row.get(4)?;
    let transition_context_checksum: Vec<u8> = row.get(6)?;
    let chain_checksum: Vec<u8> = row.get(7)?;
    Ok(StoredRecordV0 {
        revision: u64_from_slice_sql(&revision, 0)?,
        predecessor_revision: predecessor_revision
            .as_deref()
            .map(|bytes| u64_from_slice_sql(bytes, 1))
            .transpose()?,
        predecessor_chain_checksum: predecessor_chain_checksum
            .as_deref()
            .map(|bytes| array32_sql(bytes, 2))
            .transpose()?,
        state_record_bytes: row.get(3)?,
        state_record_checksum: array32_sql(&state_record_checksum, 4)?,
        transition_context_bytes: row.get(5)?,
        transition_context_checksum: array32_sql(&transition_context_checksum, 6)?,
        chain_checksum: array32_sql(&chain_checksum, 7)?,
    })
}

fn read_head(
    connection: &Connection,
    journal_id: [u8; 32],
) -> Result<(u64, [u8; 32], u64), SafetyStoreErrorV0> {
    let (revision, chain, floor, stored_head): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT active_revision_be, active_chain_checksum,
                    retention_floor_revision_be, head_checksum
             FROM safety_state_head_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("read safety-state head", error))?;
    let revision = decode_u64_blob(&revision, "head revision")?;
    let chain = decode_array32(&chain, "head chain checksum")?;
    let floor = decode_u64_blob(&floor, "retention floor")?;
    let stored_head = decode_array32(&stored_head, "head checksum")?;
    if floor > revision || stored_head != head_checksum(journal_id, revision, chain, floor) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "head checksum or retention floor",
        ));
    }
    Ok((revision, chain, floor))
}

fn decode_and_validate_record<V: SignatureVerifier>(
    row: &StoredRecordV0,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
) -> Result<RecoveredSafetyStateV0, SafetyStoreErrorV0> {
    let context = profile.record_context()?;
    let decoded = decode_safety_state_record_v0_exact(&row.state_record_bytes, &context)
        .map_err(|error| SafetyStoreErrorV0::record("decode stored state", error))?;
    if decoded.record_checksum() != row.state_record_checksum
        || decoded.state().revision() != row.revision
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "state record checksum or revision",
        ));
    }
    Core::validate_persisted_state_v0(profile.core_config(), decoded.state(), verifier)
        .map_err(|error| SafetyStoreErrorV0::core("validate stored state", error))?;
    let transition_context = decode_transition_context_v0_exact(&row.transition_context_bytes)?;
    if transition_context_checksum_v0(&row.transition_context_bytes)?
        != row.transition_context_checksum
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "transition-context checksum",
        ));
    }
    validate_transition_context_against_state_v0(&transition_context, decoded.state())?;
    Ok(RecoveredSafetyStateV0 {
        state: decoded.state().clone(),
        transition_context,
        state_record_checksum: row.state_record_checksum,
        chain_checksum: row.chain_checksum,
    })
}

fn validate_storage_resource_bounds(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
) -> Result<(), SafetyStoreErrorV0> {
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit SQLite page size", error))?;
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit SQLite page count", error))?;
    if page_size <= 0
        || page_count < 0
        || (page_size as u128) * (page_count as u128) > profile.maximum_database_bytes() as u128
    {
        return Err(SafetyStoreErrorV0::IntegrityFailure);
    }

    let (count, maximum_state, maximum_context, state_bytes, context_bytes): (
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(length(state_record_bytes)),0),
                    COALESCE(MAX(length(transition_context_bytes)),0),
                    COALESCE(SUM(length(state_record_bytes)),0),
                    COALESCE(SUM(length(transition_context_bytes)),0)
             FROM safety_state_records_v0",
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
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit stored resource bounds", error))?;
    let maximum_record_bytes = i64::try_from(profile.record_limits().maximum_record_bytes())
        .map_err(|_| SafetyStoreErrorV0::InvalidProfile("record limit"))?;
    let maximum_retained_state_bytes =
        maximum_record_bytes
            .checked_mul(2)
            .ok_or(SafetyStoreErrorV0::InvalidProfile(
                "retained record limit overflow",
            ))?;
    let maximum_context_bytes = i64::try_from(MAXIMUM_TRANSITION_CONTEXT_BYTES_V0)
        .map_err(|_| SafetyStoreErrorV0::InvalidProfile("transition-context limit"))?;
    if !(1..=2).contains(&count)
        || maximum_state <= 0
        || maximum_state > maximum_record_bytes
        || maximum_context < 3
        || maximum_context > maximum_context_bytes
        || state_bytes <= 0
        || state_bytes > maximum_retained_state_bytes
        || context_bytes < 3
        || context_bytes > maximum_context_bytes.saturating_mul(2)
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "stored resource bounds",
        ));
    }
    Ok(())
}

fn validate_all_records<V: SignatureVerifier>(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
    verifier: &V,
    journal_id: [u8; 32],
) -> Result<(), SafetyStoreErrorV0> {
    let mut statement = connection
        .prepare(
            "SELECT revision_be, predecessor_revision_be,
                    predecessor_chain_checksum, state_record_bytes,
                    state_record_checksum, transition_context_bytes,
                    transition_context_checksum, chain_checksum
             FROM safety_state_records_v0 ORDER BY revision_be",
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("prepare safety record scan", error))?;
    let rows = statement
        .query_map([], decode_stored_record_row)
        .map_err(|error| SafetyStoreErrorV0::sqlite("query safety record scan", error))?;
    let mut records = Vec::with_capacity(2);
    let mut states = Vec::new();
    for row in rows {
        let row =
            row.map_err(|error| SafetyStoreErrorV0::sqlite("read safety record scan", error))?;
        let expected_chain = chain_checksum(
            journal_id,
            row.revision,
            row.predecessor_revision,
            row.predecessor_chain_checksum,
            row.state_record_checksum,
            row.transition_context_checksum,
        );
        if expected_chain != row.chain_checksum {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "record-chain checksum",
            ));
        }
        let recovered = decode_and_validate_record(&row, profile, verifier)?;
        states.push(recovered.state);
        records.push(RetainedRecordSummaryV0 {
            revision: row.revision,
            predecessor_revision: row.predecessor_revision,
            predecessor_chain_checksum: row.predecessor_chain_checksum,
            chain_checksum: row.chain_checksum,
        });
    }
    if records.is_empty() || records.len() > 2 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "retained record count",
        ));
    }
    let (active_revision, active_chain, floor) = read_head(connection, journal_id)?;
    let first = records.first().expect("nonempty checked");
    let active = records.last().expect("nonempty checked");
    let floor_predecessor_is_canonical = if first.revision == 0 {
        first.predecessor_revision.is_none() && first.predecessor_chain_checksum.is_none()
    } else {
        first.predecessor_revision == first.revision.checked_sub(1)
            && first
                .predecessor_chain_checksum
                .is_some_and(|checksum| checksum != [0; 32])
    };
    if !floor_predecessor_is_canonical
        || first.revision != floor
        || active.revision != active_revision
        || active.chain_checksum != active_chain
        || (records.len() == 1 && active_revision != 0)
        || (records.len() == 2
            && (first.revision.checked_add(1) != Some(active.revision)
                || active.predecessor_revision != Some(first.revision)
                || active.predecessor_chain_checksum != Some(first.chain_checksum)))
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "retained predecessor chain",
        ));
    }
    if let [previous, current] = states.as_slice() {
        Core::validate_persisted_successor_v0(profile.core_config(), previous, current, verifier)
            .map_err(|error| SafetyStoreErrorV0::core("validate retained successor", error))?;
    }
    let actual: (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(state_record_bytes)),0),
                    COALESCE(SUM(length(transition_context_bytes)),0)
             FROM safety_state_records_v0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("audit record accounting", error))?;
    let stored: (i64, i64, i64) = connection
        .query_row(
            "SELECT record_count, state_bytes, transition_bytes
             FROM safety_state_accounting_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("read record accounting", error))?;
    if actual != stored || stored.0 != records.len() as i64 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "safety-store accounting mismatch",
        ));
    }
    Ok(())
}

fn chain_checksum(
    journal_id: [u8; 32],
    revision: u64,
    predecessor_revision: Option<u64>,
    predecessor_checksum: Option<[u8; 32]>,
    state_record_checksum: [u8; 32],
    transition_context_checksum: [u8; 32],
) -> [u8; 32] {
    let revision = revision.to_be_bytes();
    let predecessor_tag = [u8::from(predecessor_revision.is_some())];
    let predecessor_revision = predecessor_revision.unwrap_or(0).to_be_bytes();
    let predecessor_checksum = predecessor_checksum.unwrap_or([0; 32]);
    hash_domain(
        CHAIN_DOMAIN_V0,
        &[
            &journal_id,
            &revision,
            &predecessor_tag,
            &predecessor_revision,
            &predecessor_checksum,
            &state_record_checksum,
            &transition_context_checksum,
        ],
    )
}

fn head_checksum(
    journal_id: [u8; 32],
    revision: u64,
    chain_checksum: [u8; 32],
    floor: u64,
) -> [u8; 32] {
    hash_domain(
        HEAD_DOMAIN_V0,
        &[
            &journal_id,
            &revision.to_be_bytes(),
            &chain_checksum,
            &floor.to_be_bytes(),
        ],
    )
}

fn validate_transaction_environment(
    connection: &Connection,
    profile: &SafetyStateStoreProfileV0,
    journal_id: [u8; 32],
) -> Result<(), SafetyStoreErrorV0> {
    validate_canonical_schema(connection)?;
    validate_metadata(connection, profile, journal_id)
}

struct ObservedDurabilityStateV0<'a> {
    head_watermark: &'a mut LockWatermarkV0,
    halt_latch: &'a mut Option<DurableHaltLatchV0>,
}

#[derive(Clone, Copy)]
struct ConflictStableHeadV0 {
    sequence: u64,
    journal_id: [u8; 32],
    revision: u64,
    chain_checksum: [u8; 32],
}

fn commit_conflict(
    transaction: rusqlite::Transaction<'_>,
    sticky_halt: &AtomicBool,
    lock_file: &mut File,
    observed: ObservedDurabilityStateV0<'_>,
    stable_head: ConflictStableHeadV0,
    conflict: SafetyStoreConflictV0,
) -> SafetyStoreErrorV0 {
    sticky_halt.store(true, Ordering::Release);
    let halt = halt_fact_for_conflict(stable_head.journal_id, conflict);
    let stable = LockWatermarkV0::Stable {
        sequence: stable_head.sequence,
        journal_id: stable_head.journal_id,
        revision: stable_head.revision,
        chain_checksum: stable_head.chain_checksum,
    };
    if *observed.head_watermark != stable {
        return SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "conflict did not begin from its exact stable watermark",
        );
    }
    let halt_latch = DurableHaltLatchV0 {
        head_watermark: stable,
        halt,
    };
    // The terminal latch must reach stable storage before SQLite can commit
    // the redundant halt row. It occupies a third region and never overwrites
    // either recoverable head slot.
    if let Err(source) = write_halt_latch(lock_file, halt_latch) {
        return conflict_halt_uncertain(conflict, source);
    }
    let readback_latch = match read_halt_latch(lock_file) {
        Ok(Some(latch)) => latch,
        Ok(None) => {
            return conflict_halt_uncertain(
                conflict,
                SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "terminal halt latch disappeared after write",
                ),
            );
        }
        Err(source) => {
            return conflict_halt_uncertain(conflict, source);
        }
    };
    if readback_latch != halt_latch {
        return conflict_halt_uncertain(
            conflict,
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "terminal halt latch readback differs",
            ),
        );
    }
    *observed.halt_latch = Some(halt_latch);

    let _storage_result = if conflict == SafetyStoreConflictV0::HeadChanged {
        // This defensive CAS branch is reached only after candidate record
        // writes were staged. Keep the exact durable latch, but roll those
        // writes back so a reopen can validate the unchanged source database
        // before honoring the latch.
        transaction.rollback()
    } else {
        let revision_blob = halt.revision.map(u64::to_be_bytes);
        let halt_checksum = durable_halt_checksum(stable_head.journal_id, halt);
        transaction
            .execute(
                "INSERT OR IGNORE INTO safety_store_halt_v0(
                    singleton, reason_code, revision_be, evidence_checksum, halt_checksum
                 ) VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    halt.reason_code,
                    revision_blob.as_ref().map(<[u8; 8]>::as_slice),
                    halt.evidence_checksum.as_slice(),
                    halt_checksum.as_slice(),
                ],
            )
            .and_then(|_| transaction.commit())
    };
    // The sidecar is already a terminal, fsynced halt capability. The SQLite
    // row is only a redundant, deeply validated copy, so a SQLite error cannot
    // make this conflict retryable or uncertain.
    SafetyStoreErrorV0::Conflict(conflict)
}

fn conflict_halt_uncertain(
    conflict: SafetyStoreConflictV0,
    source: SafetyStoreErrorV0,
) -> SafetyStoreErrorV0 {
    SafetyStoreErrorV0::ConflictHaltUncertain {
        conflict,
        source: Box::new(source),
    }
}

fn halt_fact_for_conflict(
    journal_id: [u8; 32],
    conflict: SafetyStoreConflictV0,
) -> DurableHaltFactV0 {
    let (reason_code, revision) = match conflict {
        SafetyStoreConflictV0::RevisionRegression { incoming, .. } => (1i64, Some(incoming)),
        SafetyStoreConflictV0::RevisionGap { incoming, .. } => (2, Some(incoming)),
        SafetyStoreConflictV0::SameRevisionDifferentRecord { revision } => (3, Some(revision)),
        SafetyStoreConflictV0::HeadChanged => (4, None),
        SafetyStoreConflictV0::CommitReadbackConflict => (5, None),
        SafetyStoreConflictV0::FileIdentityChanged => (6, None),
        SafetyStoreConflictV0::ProcessChanged => (7, None),
    };
    let evidence = format!("{conflict:?}");
    let revision_bytes = revision.unwrap_or(0).to_be_bytes();
    let evidence_checksum = hash_domain(
        HALT_DOMAIN_V0,
        &[
            &journal_id,
            &reason_code.to_be_bytes(),
            &revision_bytes,
            evidence.as_bytes(),
        ],
    );
    DurableHaltFactV0 {
        reason_code,
        revision,
        evidence_checksum,
    }
}

fn durable_halt_checksum(journal_id: [u8; 32], halt: DurableHaltFactV0) -> [u8; 32] {
    hash_domain(
        HALT_DOMAIN_V0,
        &[
            &journal_id,
            &halt.reason_code.to_be_bytes(),
            &halt.revision.unwrap_or(0).to_be_bytes(),
            &halt.evidence_checksum,
        ],
    )
}

fn durable_halt_present(connection: &Connection) -> Result<bool, SafetyStoreErrorV0> {
    connection
        .query_row(
            "SELECT 1 FROM safety_store_halt_v0 WHERE singleton=1",
            [],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|error| SafetyStoreErrorV0::sqlite("read durable halt", error))
}

fn ensure_not_halted_connection(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    if durable_halt_present(connection)? {
        return Err(SafetyStoreErrorV0::DurableHalt);
    }
    Ok(())
}

fn read_validated_durable_halt(
    connection: &Connection,
    journal_id: [u8; 32],
) -> Result<Option<DurableHaltFactV0>, SafetyStoreErrorV0> {
    let row: Option<StoredHaltRowV0> = connection
        .query_row(
            "SELECT reason_code, revision_be, evidence_checksum, halt_checksum
             FROM safety_store_halt_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| SafetyStoreErrorV0::sqlite("validate durable halt", error))?;
    let Some((reason, revision, evidence, stored)) = row else {
        return Ok(None);
    };
    let revision = revision
        .as_deref()
        .map(|bytes| decode_u64_blob(bytes, "halt revision"))
        .transpose()?;
    let evidence = decode_array32(&evidence, "halt evidence checksum")?;
    let halt = DurableHaltFactV0 {
        reason_code: reason,
        revision,
        evidence_checksum: evidence,
    };
    if !durable_halt_fact_is_well_formed(halt) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "durable halt fields",
        ));
    }
    let expected = durable_halt_checksum(journal_id, halt);
    if stored.as_slice() != expected.as_slice() {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "durable halt checksum",
        ));
    }
    Ok(Some(halt))
}

fn configure_connection(
    connection: &Connection,
    initialize: bool,
    maximum_database_bytes: usize,
) -> Result<(), SafetyStoreErrorV0> {
    connection
        .busy_timeout(DEFAULT_BUSY_TIMEOUT)
        .map_err(|error| SafetyStoreErrorV0::sqlite("configure busy timeout", error))?;
    if initialize {
        connection
            .execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL;")
            .map_err(|error| SafetyStoreErrorV0::sqlite("enable SQLite WAL", error))?;
    }
    connection
        .execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA recursive_triggers=OFF;",
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("configure SQLite safety", error))?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read SQLite page size", error))?;
    if page_size <= 0 {
        return Err(SafetyStoreErrorV0::InvalidProfile("SQLite page size"));
    }
    let max_pages = (maximum_database_bytes as u64) / (page_size as u64);
    if max_pages == 0 || max_pages > i64::MAX as u64 {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "SQLite maximum page count",
        ));
    }
    connection
        .pragma_update(None, "max_page_count", max_pages as i64)
        .map_err(|error| SafetyStoreErrorV0::sqlite("set SQLite page bound", error))?;
    connection
        .pragma_update(None, "journal_size_limit", maximum_database_bytes as i64)
        .map_err(|error| SafetyStoreErrorV0::sqlite("set SQLite WAL bound", error))?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read journal mode", error))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "SQLite journal is not WAL",
        ));
    }
    enable_persistent_wal(connection)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read synchronous mode", error))?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read foreign-key mode", error))?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read trusted-schema mode", error))?;
    let configured_max_pages: i64 = connection
        .query_row("PRAGMA max_page_count", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read SQLite page bound", error))?;
    let current_pages: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|error| SafetyStoreErrorV0::sqlite("read SQLite page count", error))?;
    if synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || configured_max_pages <= 0
        || configured_max_pages > max_pages as i64
        || current_pages < 0
        || current_pages > configured_max_pages
    {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "SQLite durability PRAGMAs",
        ));
    }
    Ok(())
}

fn enable_persistent_wal(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    let mut enabled = 1i32;
    // SAFETY: the connection remains alive for the call, `main` is a static
    // NUL-terminated database name, and SQLite expects an `int *` for this
    // file-control opcode.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut enabled as *mut i32).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK || enabled != 1 {
        return Err(SafetyStoreErrorV0::sqlite(
            "enable persistent SQLite WAL",
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(result),
                Some("SQLITE_FCNTL_PERSIST_WAL was not accepted".to_owned()),
            ),
        ));
    }
    Ok(())
}

fn checkpoint_and_sync_initialization(
    connection: &Connection,
    database_file: &File,
    directory_file: &File,
) -> Result<(), SafetyStoreErrorV0> {
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|error| SafetyStoreErrorV0::sqlite("checkpoint initialized journal", error))?;
    database_file
        .sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync initialized database", error))?;
    sync_directory_handle(directory_file)
}

fn validate_private_directory(path: &Path) -> Result<(), SafetyStoreErrorV0> {
    let metadata = fs::metadata(path)
        .map_err(|error| SafetyStoreErrorV0::io("stat safety-store directory", error))?;
    if !metadata.is_dir() {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "safety-store parent is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no pointer arguments and no caller obligations.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "safety-store parent must be owner-controlled and non-writable by peers",
            ));
        }
        let mut ancestor = path.parent();
        while let Some(directory) = ancestor {
            let metadata = fs::metadata(directory).map_err(|error| {
                SafetyStoreErrorV0::io("stat safety-store ancestor directory", error)
            })?;
            if !metadata.is_dir() {
                return Err(SafetyStoreErrorV0::InvalidProfile(
                    "safety-store ancestor is not a directory",
                ));
            }
            let peer_writable = metadata.mode() & 0o022 != 0;
            let trusted_sticky_root = metadata.mode() & 0o1000 != 0 && metadata.uid() == 0;
            if peer_writable && !trusted_sticky_root {
                return Err(SafetyStoreErrorV0::InvalidProfile(
                    "safety-store ancestor namespace is peer-writable",
                ));
            }
            ancestor = directory.parent();
        }
    }
    Ok(())
}

fn sqlite_auxiliary_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut name = database_path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn ensure_sqlite_auxiliary_files_absent(database_path: &Path) -> Result<(), SafetyStoreErrorV0> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(SafetyStoreErrorV0::AlreadyExists("SQLite auxiliary file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SafetyStoreErrorV0::io(
                    "inspect SQLite auxiliary file",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn require_persistent_sqlite_auxiliary_files(
    database_path: &Path,
) -> Result<(), SafetyStoreErrorV0> {
    for (suffix, target) in [("-wal", "persistent WAL"), ("-shm", "persistent SHM")] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "persistent SQLite auxiliary path is not a regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(SafetyStoreErrorV0::Missing(target));
            }
            Err(error) => {
                return Err(SafetyStoreErrorV0::io(
                    "inspect persistent SQLite auxiliary file",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn materialize_sqlite_auxiliary_files(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    connection
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .map_err(|error| SafetyStoreErrorV0::sqlite("materialize SQLite WAL namespace", error))
}

fn pin_sqlite_auxiliary_files(
    database_path: &Path,
    maximum_database_bytes: usize,
) -> Result<(File, FileIdentityV0, File, FileIdentityV0), SafetyStoreErrorV0> {
    validate_sqlite_auxiliary_files(database_path, maximum_database_bytes)?;
    let wal_path = sqlite_auxiliary_path(database_path, "-wal");
    let shm_path = sqlite_auxiliary_path(database_path, "-shm");
    let wal_file = pin_sqlite_auxiliary_file(&wal_path, "pin SQLite WAL")?;
    let shm_file = pin_sqlite_auxiliary_file(&shm_path, "pin SQLite shared memory")?;
    let wal_identity = file_handle_identity(&wal_file, &wal_path)?;
    let shm_identity = file_handle_identity(&shm_file, &shm_path)?;
    if !canonical_path_is_stable(&wal_path)?
        || !canonical_path_is_stable(&shm_path)?
        || file_identity(&wal_path)? != wal_identity
        || file_identity(&shm_path)? != shm_identity
    {
        return Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::FileIdentityChanged,
        ));
    }
    Ok((wal_file, wal_identity, shm_file, shm_identity))
}

fn pin_sqlite_auxiliary_file(path: &Path, stage: &'static str) -> Result<File, SafetyStoreErrorV0> {
    let file = open_existing_private_file(path, stage)?;
    acquire_lifetime_lock(&file)?;
    Ok(file)
}

fn validate_sqlite_auxiliary_files(
    database_path: &Path,
    maximum_database_bytes: usize,
) -> Result<(), SafetyStoreErrorV0> {
    let rollback_journal = sqlite_auxiliary_path(database_path, "-journal");
    match fs::symlink_metadata(&rollback_journal) {
        Ok(_) => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "rollback journal is forbidden for WAL safety store",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(SafetyStoreErrorV0::io(
                "inspect SQLite rollback journal",
                error,
            ));
        }
    }
    for suffix in ["-wal", "-shm"] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(SafetyStoreErrorV0::io(
                    "inspect SQLite auxiliary file",
                    error,
                ));
            }
        };
        if !metadata.file_type().is_file()
            || u128::from(metadata.len()) > maximum_database_bytes as u128
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "SQLite auxiliary file shape or size",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: `geteuid` has no pointer arguments and no caller obligations.
            let effective_uid = unsafe { libc::geteuid() };
            if metadata.nlink() != 1
                || metadata.uid() != effective_uid
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "SQLite auxiliary file identity or permissions",
                ));
            }
        }
    }
    Ok(())
}

fn canonical_new_path(path: &Path) -> Result<PathBuf, SafetyStoreErrorV0> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| SafetyStoreErrorV0::io("resolve current directory", error))?
            .join(path)
    };
    let file_name = absolute
        .file_name()
        .ok_or(SafetyStoreErrorV0::InvalidProfile("database file name"))?;
    validate_database_file_name(file_name)?;
    let parent = absolute
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = match fs::canonicalize(parent) {
        Ok(parent) => parent,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(SafetyStoreErrorV0::Missing(
                "pre-existing safety-store parent directory",
            ));
        }
        Err(error) => {
            return Err(SafetyStoreErrorV0::io(
                "canonicalize safety-store directory",
                error,
            ));
        }
    };
    validate_private_directory(&parent)?;
    Ok(parent.join(file_name))
}

fn canonical_path_is_stable(path: &Path) -> Result<bool, SafetyStoreErrorV0> {
    fs::canonicalize(path)
        .map(|canonical| canonical == path)
        .map_err(|error| SafetyStoreErrorV0::io("verify canonical safety-store path", error))
}

fn ensure_supported_file_identity() -> Result<(), SafetyStoreErrorV0> {
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SafetyStoreErrorV0::UnsupportedPlatform)
    }
}

fn canonical_existing_database_path(path: &Path) -> Result<PathBuf, SafetyStoreErrorV0> {
    match fs::canonicalize(path) {
        Ok(path) => {
            let file_name = path
                .file_name()
                .ok_or(SafetyStoreErrorV0::InvalidProfile("database file name"))?;
            validate_database_file_name(file_name)?;
            let parent = path
                .parent()
                .ok_or(SafetyStoreErrorV0::InvalidProfile("database parent"))?;
            validate_private_directory(parent)?;
            file_identity(&path)?;
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SafetyStoreErrorV0::Missing("database"))
        }
        Err(error) => Err(SafetyStoreErrorV0::io(
            "canonicalize existing database",
            error,
        )),
    }
}

fn validate_database_file_name(file_name: &std::ffi::OsStr) -> Result<(), SafetyStoreErrorV0> {
    let name = file_name.to_string_lossy().to_ascii_lowercase();
    if ["-wal", "-shm", "-journal"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        return Err(SafetyStoreErrorV0::InvalidProfile(
            "database name collides with SQLite auxiliary namespace",
        ));
    }
    Ok(())
}

fn lock_path_for(database_path: &Path) -> Result<PathBuf, SafetyStoreErrorV0> {
    let file_name = database_path
        .file_name()
        .ok_or(SafetyStoreErrorV0::InvalidProfile("database file name"))?;
    let mut lock_name = OsString::from(file_name);
    lock_name.push(".safety.lock");
    Ok(database_path.with_file_name(lock_name))
}

fn create_new_private_file(path: &Path, stage: &'static str) -> Result<File, SafetyStoreErrorV0> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))
}

fn open_existing_private_file(
    path: &Path,
    stage: &'static str,
) -> Result<File, SafetyStoreErrorV0> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .map_err(|error| SafetyStoreErrorV0::io(stage, error))
}

fn acquire_lifetime_lock(file: &File) -> Result<(), SafetyStoreErrorV0> {
    match FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Err(SafetyStoreErrorV0::Locked)
        }
        Err(error) => Err(SafetyStoreErrorV0::io(
            "acquire safety-store lifetime lock",
            error,
        )),
    }
}

fn initialize_lock_file(file: &mut File) -> Result<(), SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat new lock sidecar", error))?
        .len()
        != 0
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "new lock sidecar is not empty",
        ));
    }
    file.set_len(LOCK_FILE_BYTES_V0 as u64)
        .map_err(|error| SafetyStoreErrorV0::io("allocate lock watermark slots", error))?;
    file.sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync empty lock watermark slots", error))
}

fn write_lock_watermark(
    file: &mut File,
    watermark: LockWatermarkV0,
) -> Result<(), SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat lock watermark slots", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark file size",
        ));
    }
    let bytes = encode_lock_slot(watermark)?;
    let slot = (watermark.sequence() & 1) as usize;
    file.seek(SeekFrom::Start((slot * LOCK_SLOT_REGION_BYTES_V0) as u64))
        .map_err(|error| SafetyStoreErrorV0::io("seek lock watermark slot", error))?;
    file.write_all(&bytes)
        .map_err(|error| SafetyStoreErrorV0::io("write lock watermark slot", error))?;
    file.sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync lock watermark slot", error))?;
    if read_lock_watermark(file)? != watermark {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark readback differs",
        ));
    }
    Ok(())
}

fn write_halt_latch(file: &mut File, latch: DurableHaltLatchV0) -> Result<(), SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat terminal halt latch", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark file size",
        ));
    }
    match read_halt_latch(file)? {
        Some(existing) if existing == latch => return Ok(()),
        Some(_) => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "terminal halt latch is already occupied",
            ));
        }
        None => {}
    }
    let bytes = encode_halt_latch(latch)?;
    file.seek(SeekFrom::Start(
        (LOCK_HALT_LATCH_REGION_V0 * LOCK_SLOT_REGION_BYTES_V0) as u64,
    ))
    .map_err(|error| SafetyStoreErrorV0::io("seek terminal halt latch", error))?;
    file.write_all(&bytes)
        .map_err(|error| SafetyStoreErrorV0::io("write terminal halt latch", error))?;
    file.sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync terminal halt latch", error))?;
    if read_halt_latch(file)? != Some(latch) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "terminal halt latch readback differs",
        ));
    }
    Ok(())
}

fn encode_halt_latch(
    latch: DurableHaltLatchV0,
) -> Result<[u8; HALT_LATCH_BYTES_V0], SafetyStoreErrorV0> {
    encode_lock_slot(latch.head_watermark)?;
    if !durable_halt_fact_is_well_formed(latch.halt) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "invalid terminal halt latch fields",
        ));
    }
    let mut bytes = [0u8; HALT_LATCH_BYTES_V0];
    bytes[..8].copy_from_slice(HALT_LATCH_MAGIC_V0);
    bytes[8..10].copy_from_slice(&HALT_LATCH_VERSION_V0.to_be_bytes());
    let (kind, sequence, journal_id, source_revision, source_chain, target_revision, target_chain) =
        match latch.head_watermark {
            LockWatermarkV0::Stable {
                sequence,
                journal_id,
                revision,
                chain_checksum,
            } => (
                LOCK_KIND_STABLE_V0,
                sequence,
                journal_id,
                revision,
                chain_checksum,
                revision,
                chain_checksum,
            ),
            LockWatermarkV0::HeadIntent {
                sequence,
                journal_id,
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
            } => (
                LOCK_KIND_HEAD_INTENT_V0,
                sequence,
                journal_id,
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
            ),
        };
    bytes[10] = kind;
    bytes[16..24].copy_from_slice(&sequence.to_be_bytes());
    bytes[24..56].copy_from_slice(&journal_id);
    bytes[56..64].copy_from_slice(&source_revision.to_be_bytes());
    bytes[64..96].copy_from_slice(&source_chain);
    bytes[96..104].copy_from_slice(&target_revision.to_be_bytes());
    bytes[104..136].copy_from_slice(&target_chain);
    bytes[136..144].copy_from_slice(&latch.halt.reason_code.to_be_bytes());
    if let Some(revision) = latch.halt.revision {
        bytes[144] = 1;
        bytes[152..160].copy_from_slice(&revision.to_be_bytes());
    }
    bytes[160..192].copy_from_slice(&latch.halt.evidence_checksum);
    let checksum = hash_domain(
        LOCK_CHECKSUM_DOMAIN_V0,
        &[&bytes[..HALT_LATCH_CHECKSUM_OFFSET_V0]],
    );
    bytes[HALT_LATCH_CHECKSUM_OFFSET_V0..].copy_from_slice(&checksum);
    Ok(bytes)
}

fn read_halt_latch(file: &File) -> Result<Option<DurableHaltLatchV0>, SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat terminal halt latch", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark file size",
        ));
    }
    let mut file = file;
    file.seek(SeekFrom::Start(
        (LOCK_HALT_LATCH_REGION_V0 * LOCK_SLOT_REGION_BYTES_V0) as u64,
    ))
    .map_err(|error| SafetyStoreErrorV0::io("seek terminal halt latch", error))?;
    let mut region = [0u8; LOCK_SLOT_REGION_BYTES_V0];
    file.read_exact(&mut region)
        .map_err(|error| SafetyStoreErrorV0::io("read terminal halt latch", error))?;
    if region.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if region[HALT_LATCH_BYTES_V0..].iter().any(|byte| *byte != 0) {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "terminal halt latch padding",
        ));
    }
    decode_halt_latch(&region[..HALT_LATCH_BYTES_V0])
        .map(Some)
        .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "terminal halt latch",
        ))
}

fn decode_halt_latch(bytes: &[u8]) -> Option<DurableHaltLatchV0> {
    if bytes.len() != HALT_LATCH_BYTES_V0
        || &bytes[..8] != HALT_LATCH_MAGIC_V0
        || u16::from_be_bytes(bytes[8..10].try_into().ok()?) != HALT_LATCH_VERSION_V0
        || !matches!(bytes[10], LOCK_KIND_STABLE_V0 | LOCK_KIND_HEAD_INTENT_V0)
        || bytes[11..16].iter().any(|byte| *byte != 0)
        || hash_domain(
            LOCK_CHECKSUM_DOMAIN_V0,
            &[&bytes[..HALT_LATCH_CHECKSUM_OFFSET_V0]],
        ) != bytes[HALT_LATCH_CHECKSUM_OFFSET_V0..]
    {
        return None;
    }
    let sequence = u64::from_be_bytes(bytes[16..24].try_into().ok()?);
    let journal_id: [u8; 32] = bytes[24..56].try_into().ok()?;
    let source_revision = u64::from_be_bytes(bytes[56..64].try_into().ok()?);
    let source_chain_checksum: [u8; 32] = bytes[64..96].try_into().ok()?;
    let target_revision = u64::from_be_bytes(bytes[96..104].try_into().ok()?);
    let target_chain_checksum: [u8; 32] = bytes[104..136].try_into().ok()?;
    let head_watermark = match bytes[10] {
        LOCK_KIND_STABLE_V0
            if source_revision == target_revision
                && source_chain_checksum == target_chain_checksum =>
        {
            LockWatermarkV0::Stable {
                sequence,
                journal_id,
                revision: source_revision,
                chain_checksum: source_chain_checksum,
            }
        }
        LOCK_KIND_HEAD_INTENT_V0 if source_revision.checked_add(1) == Some(target_revision) => {
            LockWatermarkV0::HeadIntent {
                sequence,
                journal_id,
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
            }
        }
        _ => return None,
    };
    encode_lock_slot(head_watermark).ok()?;
    let revision = match bytes[144] {
        0 if bytes[152..160].iter().all(|byte| *byte == 0) => None,
        1 => Some(u64::from_be_bytes(bytes[152..160].try_into().ok()?)),
        _ => return None,
    };
    if bytes[145..152].iter().any(|byte| *byte != 0) {
        return None;
    }
    let halt = DurableHaltFactV0 {
        reason_code: i64::from_be_bytes(bytes[136..144].try_into().ok()?),
        revision,
        evidence_checksum: bytes[160..192].try_into().ok()?,
    };
    if !durable_halt_fact_is_well_formed(halt) {
        return None;
    }
    Some(DurableHaltLatchV0 {
        head_watermark,
        halt,
    })
}

fn preflight_intent_sequence(stable_sequence: u64) -> Result<u64, SafetyStoreErrorV0> {
    // Both the intent and its potential Stable resolution must be representable
    // before the intent is written or the associated SQLite transaction can
    // commit. This rejects MAX-1 before it can strand a resolvable transition.
    stable_sequence
        .checked_add(2)
        .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark sequence overflow",
        ))?;
    Ok(stable_sequence + 1)
}

fn durable_halt_fact_is_well_formed(halt: DurableHaltFactV0) -> bool {
    let revision_shape_matches_reason = match halt.reason_code {
        1..=3 => halt.revision.is_some(),
        4..=7 => halt.revision.is_none(),
        _ => false,
    };
    revision_shape_matches_reason && halt.evidence_checksum != [0; 32]
}

fn encode_lock_slot(
    watermark: LockWatermarkV0,
) -> Result<[u8; LOCK_SLOT_BYTES_V0], SafetyStoreErrorV0> {
    let mut bytes = [0u8; LOCK_SLOT_BYTES_V0];
    bytes[..8].copy_from_slice(LOCK_MAGIC_V0);
    bytes[8..10].copy_from_slice(&LOCK_VERSION_V0.to_be_bytes());
    let (kind, sequence, journal_id) = match watermark {
        LockWatermarkV0::Stable {
            sequence,
            journal_id,
            revision,
            chain_checksum,
        } if journal_id != [0; 32] && chain_checksum != [0; 32] => {
            bytes[56..64].copy_from_slice(&revision.to_be_bytes());
            bytes[64..96].copy_from_slice(&chain_checksum);
            (LOCK_KIND_STABLE_V0, sequence, journal_id)
        }
        LockWatermarkV0::HeadIntent {
            sequence,
            journal_id,
            source_revision,
            source_chain_checksum,
            target_revision,
            target_chain_checksum,
        } if journal_id != [0; 32]
            && source_chain_checksum != [0; 32]
            && target_chain_checksum != [0; 32]
            && source_revision.checked_add(1) == Some(target_revision) =>
        {
            bytes[56..64].copy_from_slice(&source_revision.to_be_bytes());
            bytes[64..96].copy_from_slice(&source_chain_checksum);
            bytes[96..104].copy_from_slice(&target_revision.to_be_bytes());
            bytes[104..136].copy_from_slice(&target_chain_checksum);
            (LOCK_KIND_HEAD_INTENT_V0, sequence, journal_id)
        }
        _ => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "invalid lock watermark fields",
            ));
        }
    };
    bytes[10] = kind;
    bytes[16..24].copy_from_slice(&sequence.to_be_bytes());
    bytes[24..56].copy_from_slice(&journal_id);
    let checksum = hash_domain(
        LOCK_CHECKSUM_DOMAIN_V0,
        &[&bytes[..LOCK_SLOT_CHECKSUM_OFFSET_V0]],
    );
    bytes[LOCK_SLOT_CHECKSUM_OFFSET_V0..].copy_from_slice(&checksum);
    Ok(bytes)
}

fn read_lock_watermark(file: &File) -> Result<LockWatermarkV0, SafetyStoreErrorV0> {
    if file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat lock watermark slots", error))?
        .len()
        != LOCK_FILE_BYTES_V0 as u64
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "lock watermark file size",
        ));
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| SafetyStoreErrorV0::io("seek lock watermark slots", error))?;
    let mut bytes = [0u8; LOCK_FILE_BYTES_V0];
    file.read_exact(&mut bytes)
        .map_err(|error| SafetyStoreErrorV0::io("read lock watermark slots", error))?;

    let mut valid = [None, None];
    for (slot, target) in valid.iter_mut().enumerate() {
        let start = slot * LOCK_SLOT_REGION_BYTES_V0;
        let payload_end = start + LOCK_SLOT_BYTES_V0;
        let region_end = start + LOCK_SLOT_REGION_BYTES_V0;
        *target = if bytes[payload_end..region_end].iter().all(|byte| *byte == 0) {
            decode_lock_slot(&bytes[start..payload_end], slot)
        } else {
            None
        };
    }
    match (valid[0], valid[1]) {
        (None, None) => Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "no valid lock watermark slot",
        )),
        (Some(watermark), None) | (None, Some(watermark)) => Ok(watermark),
        (Some(left), Some(right)) => {
            let (older, newer) = if left.sequence() < right.sequence() {
                (left, right)
            } else {
                (right, left)
            };
            if older.journal_id() != newer.journal_id()
                || older.sequence().checked_add(1) != Some(newer.sequence())
                || !lock_watermarks_are_adjacent(older, newer)
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "lock watermark slot sequence or transition",
                ));
            }
            Ok(newer)
        }
    }
}

fn decode_lock_slot(bytes: &[u8], slot: usize) -> Option<LockWatermarkV0> {
    if bytes.len() != LOCK_SLOT_BYTES_V0 || bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    if &bytes[..8] != LOCK_MAGIC_V0
        || u16::from_be_bytes(bytes[8..10].try_into().ok()?) != LOCK_VERSION_V0
        || !matches!(bytes[10], LOCK_KIND_STABLE_V0 | LOCK_KIND_HEAD_INTENT_V0)
        || bytes[11..16].iter().any(|byte| *byte != 0)
        || hash_domain(
            LOCK_CHECKSUM_DOMAIN_V0,
            &[&bytes[..LOCK_SLOT_CHECKSUM_OFFSET_V0]],
        ) != bytes[LOCK_SLOT_CHECKSUM_OFFSET_V0..]
    {
        return None;
    }
    let sequence = u64::from_be_bytes(bytes[16..24].try_into().ok()?);
    if (sequence & 1) as usize != slot {
        return None;
    }
    let journal_id: [u8; 32] = bytes[24..56].try_into().ok()?;
    let source_revision = u64::from_be_bytes(bytes[56..64].try_into().ok()?);
    let source_chain_checksum: [u8; 32] = bytes[64..96].try_into().ok()?;
    if journal_id == [0; 32] || source_chain_checksum == [0; 32] {
        return None;
    }
    match bytes[10] {
        LOCK_KIND_STABLE_V0
            if bytes[96..LOCK_SLOT_CHECKSUM_OFFSET_V0]
                .iter()
                .all(|byte| *byte == 0) =>
        {
            Some(LockWatermarkV0::Stable {
                sequence,
                journal_id,
                revision: source_revision,
                chain_checksum: source_chain_checksum,
            })
        }
        LOCK_KIND_HEAD_INTENT_V0 => {
            let target_revision = u64::from_be_bytes(bytes[96..104].try_into().ok()?);
            let target_chain_checksum: [u8; 32] = bytes[104..136].try_into().ok()?;
            if source_revision.checked_add(1) != Some(target_revision)
                || target_chain_checksum == [0; 32]
                || bytes[136..LOCK_SLOT_CHECKSUM_OFFSET_V0]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return None;
            }
            Some(LockWatermarkV0::HeadIntent {
                sequence,
                journal_id,
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
            })
        }
        _ => None,
    }
}

fn lock_watermarks_are_adjacent(older: LockWatermarkV0, newer: LockWatermarkV0) -> bool {
    match (older, newer) {
        (
            LockWatermarkV0::Stable {
                revision,
                chain_checksum,
                ..
            },
            LockWatermarkV0::HeadIntent {
                source_revision,
                source_chain_checksum,
                ..
            },
        ) => revision == source_revision && chain_checksum == source_chain_checksum,
        (
            LockWatermarkV0::HeadIntent {
                source_revision,
                source_chain_checksum,
                target_revision,
                target_chain_checksum,
                ..
            },
            LockWatermarkV0::Stable {
                revision,
                chain_checksum,
                ..
            },
        ) => {
            (revision == source_revision && chain_checksum == source_chain_checksum)
                || (revision == target_revision && chain_checksum == target_chain_checksum)
        }
        _ => false,
    }
}

fn new_journal_id(_path: &Path) -> Result<[u8; 32], SafetyStoreErrorV0> {
    let mut id = [0u8; 32];
    getrandom::getrandom(&mut id).map_err(|error| {
        SafetyStoreErrorV0::io(
            "generate journal identity",
            std::io::Error::other(error.to_string()),
        )
    })?;
    if id == [0; 32] {
        return Err(SafetyStoreErrorV0::InvalidProfile("zero journal ID"));
    }
    Ok(id)
}

fn sync_directory_handle(directory_file: &File) -> Result<(), SafetyStoreErrorV0> {
    directory_file
        .sync_all()
        .map_err(|error| SafetyStoreErrorV0::io("sync safety-store parent directory", error))
}

fn file_identity(path: &Path) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    let metadata = fs::metadata(path)
        .map_err(|error| SafetyStoreErrorV0::io("stat safety-store file", error))?;
    file_identity_from_metadata(path, &metadata)
}

fn directory_identity(path: &Path) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    let metadata = fs::metadata(path)
        .map_err(|error| SafetyStoreErrorV0::io("stat pinned directory path", error))?;
    directory_identity_from_metadata(path, &metadata)
}

fn directory_handle_identity(
    file: &File,
    canonical_path: &Path,
) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    let metadata = file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat pinned directory handle", error))?;
    directory_identity_from_metadata(canonical_path, &metadata)
}

fn directory_identity_from_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    if !metadata.is_dir() {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "safety-store directory path is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        Ok(FileIdentityV0 {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentityV0 {
            canonical_path: fs::canonicalize(path)
                .map_err(|error| SafetyStoreErrorV0::io("canonicalize directory", error))?,
        })
    }
}

fn file_handle_identity(
    file: &File,
    canonical_path: &Path,
) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    let metadata = file
        .metadata()
        .map_err(|error| SafetyStoreErrorV0::io("stat pinned safety-store file", error))?;
    file_identity_from_metadata(canonical_path, &metadata)
}

fn file_identity_from_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<FileIdentityV0, SafetyStoreErrorV0> {
    if !metadata.is_file() {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "safety-store path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        // SAFETY: `geteuid` has no pointer arguments and no caller obligations.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.nlink() != 1
            || metadata.uid() != effective_uid
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "safety-store file identity or permissions",
            ));
        }
        Ok(FileIdentityV0 {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentityV0 {
            canonical_path: fs::canonicalize(path)
                .map_err(|error| SafetyStoreErrorV0::io("canonicalize file identity", error))?,
        })
    }
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, SafetyStoreErrorV0> {
    u64::try_from(value).map_err(|_| SafetyStoreErrorV0::InvalidProfile(field))
}

fn decode_u64_blob(bytes: &[u8], field: &'static str) -> Result<u64, SafetyStoreErrorV0> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| SafetyStoreErrorV0::PersistedRepresentationMalformed(field))?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_array32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], SafetyStoreErrorV0> {
    bytes
        .try_into()
        .map_err(|_| SafetyStoreErrorV0::PersistedRepresentationMalformed(field))
}

fn u64_from_slice_sql(bytes: &[u8], column: usize) -> rusqlite::Result<u64> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            "expected 8-byte big-endian integer".into(),
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn array32_sql(bytes: &[u8], column: usize) -> rusqlite::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            "expected 32-byte checksum".into(),
        )
    })
}

#[cfg(test)]
mod lock_watermark_tests {
    use super::*;

    const JOURNAL_ID: [u8; 32] = [0x11; 32];
    const SOURCE_CHAIN: [u8; 32] = [0x22; 32];
    const TARGET_CHAIN: [u8; 32] = [0x33; 32];
    const HALT_EVIDENCE: [u8; 32] = [0x44; 32];

    fn new_lock_file() -> File {
        let mut file = tempfile::tempfile().expect("create temporary lock sidecar");
        initialize_lock_file(&mut file).expect("initialize lock slots");
        file
    }

    fn stable(sequence: u64, revision: u64, chain_checksum: [u8; 32]) -> LockWatermarkV0 {
        LockWatermarkV0::Stable {
            sequence,
            journal_id: JOURNAL_ID,
            revision,
            chain_checksum,
        }
    }

    fn intent(sequence: u64) -> LockWatermarkV0 {
        LockWatermarkV0::HeadIntent {
            sequence,
            journal_id: JOURNAL_ID,
            source_revision: 7,
            source_chain_checksum: SOURCE_CHAIN,
            target_revision: 8,
            target_chain_checksum: TARGET_CHAIN,
        }
    }

    fn halt_latch(head_watermark: LockWatermarkV0) -> DurableHaltLatchV0 {
        DurableHaltLatchV0 {
            head_watermark,
            halt: DurableHaltFactV0 {
                reason_code: 2,
                revision: Some(9),
                evidence_checksum: HALT_EVIDENCE,
            },
        }
    }

    fn overwrite_slot(file: &mut File, slot: usize, bytes: &[u8; LOCK_SLOT_BYTES_V0]) {
        file.seek(SeekFrom::Start((slot * LOCK_SLOT_REGION_BYTES_V0) as u64))
            .expect("seek raw lock slot");
        file.write_all(bytes).expect("write raw lock slot");
        file.sync_all().expect("sync raw lock slot");
    }

    #[test]
    fn one_torn_slot_falls_back_to_the_other_valid_slot() {
        let mut file = new_lock_file();
        let source = stable(0, 7, SOURCE_CHAIN);
        write_lock_watermark(&mut file, source).expect("write source Stable");
        overwrite_slot(&mut file, 1, &[0xa5; LOCK_SLOT_BYTES_V0]);

        assert_eq!(read_lock_watermark(&file).expect("read valid slot"), source);
    }

    #[test]
    fn slot_payloads_occupy_disjoint_four_kib_regions() {
        let mut file = new_lock_file();
        write_lock_watermark(&mut file, stable(0, 7, SOURCE_CHAIN)).expect("write first region");
        write_lock_watermark(&mut file, intent(1)).expect("write second region");
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0)).expect("rewind lock file");
        file.read_to_end(&mut bytes).expect("read lock file");

        assert_eq!(bytes.len(), 3 * LOCK_SLOT_REGION_BYTES_V0);
        assert_eq!(&bytes[..8], LOCK_MAGIC_V0);
        assert_eq!(
            &bytes[LOCK_SLOT_REGION_BYTES_V0..LOCK_SLOT_REGION_BYTES_V0 + 8],
            LOCK_MAGIC_V0
        );
        assert!(bytes[LOCK_SLOT_BYTES_V0..LOCK_SLOT_REGION_BYTES_V0]
            .iter()
            .all(|byte| *byte == 0));
        assert!(bytes
            [LOCK_SLOT_REGION_BYTES_V0 + LOCK_SLOT_BYTES_V0..2 * LOCK_SLOT_REGION_BYTES_V0]
            .iter()
            .all(|byte| *byte == 0));
        assert!(bytes[2 * LOCK_SLOT_REGION_BYTES_V0..]
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn stable_to_intent_and_intent_to_either_stable_are_adjacent() {
        let mut target_file = new_lock_file();
        write_lock_watermark(&mut target_file, stable(0, 7, SOURCE_CHAIN))
            .expect("write source Stable");
        write_lock_watermark(&mut target_file, intent(1)).expect("write Intent");
        assert_eq!(
            read_lock_watermark(&target_file).expect("select Intent"),
            intent(1)
        );
        let target = stable(2, 8, TARGET_CHAIN);
        write_lock_watermark(&mut target_file, target).expect("resolve target Stable");
        assert_eq!(
            read_lock_watermark(&target_file).expect("select target Stable"),
            target
        );

        let mut source_file = new_lock_file();
        write_lock_watermark(&mut source_file, stable(0, 7, SOURCE_CHAIN))
            .expect("write source Stable");
        write_lock_watermark(&mut source_file, intent(1)).expect("write Intent");
        let source = stable(2, 7, SOURCE_CHAIN);
        write_lock_watermark(&mut source_file, source).expect("resolve source Stable");
        assert_eq!(
            read_lock_watermark(&source_file).expect("select source Stable"),
            source
        );
    }

    #[test]
    fn terminal_halt_latch_roundtrips_without_changing_stable_head() {
        let mut file = new_lock_file();
        let source = stable(0, 7, SOURCE_CHAIN);
        let latch = halt_latch(source);
        write_lock_watermark(&mut file, source).expect("write source Stable");
        write_halt_latch(&mut file, latch).expect("write terminal halt latch");

        assert_eq!(read_lock_watermark(&file).expect("retain Stable"), source);
        assert_eq!(read_halt_latch(&file).expect("read latch"), Some(latch));
        assert_eq!(
            decode_halt_latch(&encode_halt_latch(latch).expect("encode halt latch")),
            Some(latch)
        );
    }

    #[test]
    fn commit_readback_conflict_latch_binds_the_full_head_intent() {
        let mut file = new_lock_file();
        write_lock_watermark(&mut file, stable(0, 7, SOURCE_CHAIN)).expect("write source Stable");
        let head_intent = intent(1);
        write_lock_watermark(&mut file, head_intent).expect("write HeadIntent");
        let latch = DurableHaltLatchV0 {
            head_watermark: head_intent,
            halt: halt_fact_for_conflict(JOURNAL_ID, SafetyStoreConflictV0::CommitReadbackConflict),
        };
        write_halt_latch(&mut file, latch).expect("write terminal halt latch");

        assert_eq!(
            read_lock_watermark(&file).expect("retain HeadIntent"),
            head_intent
        );
        assert_eq!(read_halt_latch(&file).expect("read latch"), Some(latch));
    }

    #[test]
    fn torn_halt_latch_is_fail_closed_without_damaging_the_head_slots() {
        let mut file = new_lock_file();
        let source = stable(0, 7, SOURCE_CHAIN);
        write_lock_watermark(&mut file, source).expect("write source Stable");
        file.seek(SeekFrom::Start(
            (LOCK_HALT_LATCH_REGION_V0 * LOCK_SLOT_REGION_BYTES_V0) as u64,
        ))
        .expect("seek raw halt latch");
        file.write_all(&[0xa5; HALT_LATCH_BYTES_V0])
            .expect("write torn halt latch");
        file.sync_all().expect("sync torn halt latch");

        assert_eq!(
            read_lock_watermark(&file).expect("head remains readable"),
            source
        );
        assert!(matches!(
            read_halt_latch(&file),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "terminal halt latch"
            ))
        ));
        let conflict = SafetyStoreConflictV0::RevisionGap {
            active: 7,
            incoming: 9,
        };
        let failure = write_halt_latch(&mut file, halt_latch(source))
            .map_err(|source| conflict_halt_uncertain(conflict, source))
            .expect_err("a torn latch cannot be reported durable");
        assert!(matches!(
            failure,
            SafetyStoreErrorV0::ConflictHaltUncertain {
                conflict: SafetyStoreConflictV0::RevisionGap {
                    active: 7,
                    incoming: 9
                },
                ..
            }
        ));
    }

    #[test]
    fn intent_sequence_preflight_reserves_the_following_stable_sequence() {
        assert_eq!(
            preflight_intent_sequence(u64::MAX - 2)
                .expect("final intent sequence is representable"),
            u64::MAX - 1
        );
        assert!(matches!(
            preflight_intent_sequence(u64::MAX - 1),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "lock watermark sequence overflow"
            ))
        ));
    }

    #[test]
    fn two_valid_nonadjacent_slots_are_rejected() {
        let mut file = new_lock_file();
        overwrite_slot(
            &mut file,
            0,
            &encode_lock_slot(stable(0, 7, SOURCE_CHAIN)).expect("encode Stable"),
        );
        overwrite_slot(
            &mut file,
            1,
            &encode_lock_slot(intent(3)).expect("encode nonadjacent Intent"),
        );

        assert!(matches!(
            read_lock_watermark(&file),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "lock watermark slot sequence or transition"
            ))
        ));
    }

    #[test]
    fn torn_newest_rewrite_preserves_the_prior_intent_or_stable() {
        let mut after_intent = new_lock_file();
        write_lock_watermark(&mut after_intent, stable(0, 7, SOURCE_CHAIN))
            .expect("write source Stable");
        write_lock_watermark(&mut after_intent, intent(1)).expect("write Intent");
        overwrite_slot(&mut after_intent, 0, &[0x5a; LOCK_SLOT_BYTES_V0]);
        assert_eq!(
            read_lock_watermark(&after_intent).expect("recover prior Intent"),
            intent(1)
        );

        let mut after_stable = new_lock_file();
        write_lock_watermark(&mut after_stable, stable(0, 7, SOURCE_CHAIN))
            .expect("write source Stable");
        write_lock_watermark(&mut after_stable, intent(1)).expect("write Intent");
        let target = stable(2, 8, TARGET_CHAIN);
        write_lock_watermark(&mut after_stable, target).expect("write target Stable");
        overwrite_slot(&mut after_stable, 1, &[0x96; LOCK_SLOT_BYTES_V0]);
        assert_eq!(
            read_lock_watermark(&after_stable).expect("recover prior Stable"),
            target
        );
    }
}
