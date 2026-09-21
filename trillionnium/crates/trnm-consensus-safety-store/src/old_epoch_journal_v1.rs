//! Journal8's closed outgoing-epoch-zero profile. It persists real opaque Core
//! requests and returns fresh comparison evidence, never a signing/StorageAck
//! capability. Full epoch activation and external anti-rollback remain separate.
use crate::epoch_preparation_sqlite_v1 as fs_owner;
use crate::{
    decode_transition_context_v0_exact, encode_transition_context_v0,
    validate_transition_context_against_state_v0, SafetyStateStoreProfileV0, SafetyStoreErrorV0,
    SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use fs_owner::{EpochPreparationStoreErrorV1, PinnedFileV1};
use rusqlite::{params, Connection, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, sync::Arc};
use trnm_consensus_core::{
    decode_old_epoch_boundary_safety_record_v1_exact, decode_safety_state_record_v0_exact,
    encode_old_epoch_boundary_safety_record_v1, encode_safety_state_record_v0,
    old_epoch_boundary_record_context_ref_v1, safety_state_record_config_ref_v0, Core, CoreConfig,
    CoreError, OldEpochBoundaryCoreV1, SafetyState, SafetyStatePersistenceBindingV0,
    SafetyStatePersistenceV0, SafetyStateRecordContextV0, SafetyStateRecordErrorV0,
    SafetyStateRecordLimitsV0, UnverifiedSafetyStateRecordV0,
};
use trnm_consensus_crypto::{validate_validator_set_strict_ed25519_v0, StrictEd25519Verifier};

const APPLICATION_ID: i64 = 0x54524f38;
const LOCK_MAGIC: &[u8; 8] = b"TRNMJ8OL";
const MAX_RECORD: usize = 256 * 1024 * 1024;
const MAX_CONTEXT: usize = 1024 * 1024;
const SQL: &str = include_str!("old_epoch_journal_v1.sql");

#[derive(Debug)]
pub enum OldEpochJournalErrorV1 {
    Namespace(EpochPreparationStoreErrorV1),
    Sqlite(rusqlite::Error),
    Source(SafetyStoreErrorV0),
    Record(SafetyStateRecordErrorV0),
    Core(CoreError),
    Invalid(&'static str),
    Fenced,
}
impl std::fmt::Display for OldEpochJournalErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "outgoing journal8: {self:?}")
    }
}
impl std::error::Error for OldEpochJournalErrorV1 {}
impl From<EpochPreparationStoreErrorV1> for OldEpochJournalErrorV1 {
    fn from(e: EpochPreparationStoreErrorV1) -> Self {
        Self::Namespace(e)
    }
}
impl From<rusqlite::Error> for OldEpochJournalErrorV1 {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}
impl From<SafetyStoreErrorV0> for OldEpochJournalErrorV1 {
    fn from(e: SafetyStoreErrorV0) -> Self {
        Self::Source(e)
    }
}
impl From<SafetyStateRecordErrorV0> for OldEpochJournalErrorV1 {
    fn from(e: SafetyStateRecordErrorV0) -> Self {
        Self::Record(e)
    }
}
impl From<CoreError> for OldEpochJournalErrorV1 {
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}
type Result<T> = std::result::Result<T, OldEpochJournalErrorV1>;
fn invalid<T>(why: &'static str) -> Result<T> {
    Err(OldEpochJournalErrorV1::Invalid(why))
}
fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}
fn io(stage: &'static str, e: std::io::Error) -> OldEpochJournalErrorV1 {
    EpochPreparationStoreErrorV1::Io { stage, error: e }.into()
}
fn verifier_ref() -> [u8; 32] {
    digest(b"trnm.journal8.outgoing.strict-ed25519.v1", &[])
}

/// Closed profile: only the outgoing epoch-zero record codec, with fixed strict
/// Ed25519 validation. Capacity is checked before any destination file exists.
#[derive(Debug, Clone)]
pub struct OldEpochSafetyJournalProfileV1 {
    config: CoreConfig,
    limits: SafetyStateRecordLimitsV0,
    source_profile: SafetyStateStoreProfileV0,
    generation: u64,
    max_db: u64,
    max_row: usize,
    binding: [u8; 32],
}
impl OldEpochSafetyJournalProfileV1 {
    pub fn new(
        source_profile: SafetyStateStoreProfileV0,
        limits: SafetyStateRecordLimitsV0,
        generation: u64,
    ) -> Result<Self> {
        let config = source_profile.core_config().clone();
        validate_validator_set_strict_ed25519_v0(config.validator_set())
            .map_err(|_| OldEpochJournalErrorV1::Invalid("strict validator keys"))?;
        if generation == 0
            || limits.maximum_record_bytes() > MAX_RECORD
            || source_profile.record_limits().maximum_record_bytes() > MAX_RECORD
        {
            return invalid("generation or record capacity");
        }
        // SQLite LENGTH bounds the complete row, including the retained
        // source record and its transition, before any destination is created.
        let max_row = limits
            .maximum_record_bytes()
            .max(source_profile.record_limits().maximum_record_bytes())
            .checked_add(MAX_CONTEXT)
            .ok_or(OldEpochJournalErrorV1::Invalid("row capacity overflow"))?;
        max_row
            .checked_add(4096)
            .and_then(|n| i32::try_from(n).ok())
            .ok_or(OldEpochJournalErrorV1::Invalid("SQLite row capacity"))?;
        let context = SafetyStateRecordContextV0::new(&config, verifier_ref(), limits)?;
        let context_ref = old_epoch_boundary_record_context_ref_v1(&context)?;
        let source_context = SafetyStateRecordContextV0::new(
            &config,
            source_profile.verifier_profile_ref(),
            source_profile.record_limits(),
        )?;
        let source_ref = safety_state_record_config_ref_v0(&source_context)?;
        let max_db = (limits.maximum_record_bytes() as u64)
            .checked_mul(6)
            .and_then(|v| {
                v.checked_add(
                    source_profile.record_limits().maximum_record_bytes() as u64 * 2
                        + 16 * 1024 * 1024,
                )
            })
            .ok_or(OldEpochJournalErrorV1::Invalid("database capacity"))?;
        let binding = digest(
            b"trnm.journal8.outgoing.profile.v1",
            &[
                &context_ref,
                &source_ref,
                &generation.to_be_bytes(),
                &max_db.to_be_bytes(),
            ],
        );
        Ok(Self {
            config,
            limits,
            source_profile,
            generation,
            max_db,
            max_row,
            binding,
        })
    }
    pub(crate) fn context(&self) -> Result<SafetyStateRecordContextV0<'_>> {
        Ok(SafetyStateRecordContextV0::new(
            &self.config,
            verifier_ref(),
            self.limits,
        )?)
    }
    fn source_context(&self) -> Result<SafetyStateRecordContextV0<'_>> {
        Ok(SafetyStateRecordContextV0::new(
            &self.config,
            self.source_profile.verifier_profile_ref(),
            self.source_profile.record_limits(),
        )?)
    }
    pub const fn owner_generation_v1(&self) -> u64 {
        self.generation
    }
    pub const fn profile_ref_v1(&self) -> [u8; 32] {
        self.binding
    }
    pub fn context_ref_v1(&self) -> Result<[u8; 32]> {
        Ok(old_epoch_boundary_record_context_ref_v1(&self.context()?)?)
    }
    pub(crate) fn check_state(&self, state: &SafetyState) -> Result<()> {
        if state.schema_version() != 14
            || state.old_epoch_boundary_v1().map(|b| b.owner_generation()) != Some(self.generation)
        {
            return invalid("outgoing schema or owner generation");
        }
        Core::validate_persisted_state_v0(&self.config, state, &StrictEd25519Verifier)?;
        Ok(())
    }
}

/// Comparison-only expected head. A host obtains freshness by pinning this in
/// its independent monotonic service, never by reading it from the same image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OldEpochSafetyHeadPinV1 {
    pub journal_id: [u8; 32],
    pub revision: u64,
    pub chain_checksum: [u8; 32],
}

/// Real transaction/response-loss cuts, also usable by process-kill tests.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OldEpochJournalCutV1 {
    AfterWriteBeforeCommit,
    AfterCommitBeforeSync,
    AfterSyncBeforeReadback,
}

/// Immutable source facts obtained only while auditing the retained journal7
/// origin of a real journal8 head. These are comparison data, not an ACK or a
/// recovered Core owner. No caller can select another origin via these fields.
pub struct OldEpochMigrationSourceV1 {
    revision: u64,
    state_record_checksum: [u8; 32],
    journal_id: [u8; 32],
    chain_checksum: [u8; 32],
    verifier_profile_ref: [u8; 32],
    config_ref: [u8; 32],
}
impl OldEpochMigrationSourceV1 {
    pub const fn revision_v1(&self) -> u64 {
        self.revision
    }
    pub const fn state_record_checksum_v1(&self) -> [u8; 32] {
        self.state_record_checksum
    }
    pub const fn journal_id_v1(&self) -> [u8; 32] {
        self.journal_id
    }
    pub const fn chain_checksum_v1(&self) -> [u8; 32] {
        self.chain_checksum
    }
    pub const fn verifier_profile_ref_v1(&self) -> [u8; 32] {
        self.verifier_profile_ref
    }
    pub const fn config_ref_v1(&self) -> [u8; 32] {
        self.config_ref
    }
}

/// Fresh owner-affine facts. This is deliberately neither Clone nor signing or
/// Core recovery authority; M15 must still reconcile native and signer owners.
pub struct ConfirmedOldEpochSafetyHeadV1 {
    // A validated Safety record contains large closed protocol values. Keep
    // ownership on the heap instead of copying it through readback stack frames.
    record: Box<UnverifiedSafetyStateRecordV0>,
    transition: SafetyTransitionContextV0,
    pin: OldEpochSafetyHeadPinV1,
    context_ref: [u8; 32],
    generation: u64,
    origin: [u8; 32],
    source: OldEpochMigrationSourceV1,
    owner: Arc<()>,
}
impl ConfirmedOldEpochSafetyHeadV1 {
    pub const fn migration_source_v1(&self) -> &OldEpochMigrationSourceV1 {
        &self.source
    }
    pub fn state_v1(&self) -> &SafetyState {
        self.record.state()
    }
    pub const fn revision_v1(&self) -> u64 {
        self.pin.revision
    }
    pub fn state_record_checksum_v1(&self) -> [u8; 32] {
        self.record.record_checksum()
    }
    pub const fn chain_checksum_v1(&self) -> [u8; 32] {
        self.pin.chain_checksum
    }
    pub const fn journal_id_v1(&self) -> [u8; 32] {
        self.pin.journal_id
    }
    pub const fn context_ref_v1(&self) -> [u8; 32] {
        self.context_ref
    }
    pub const fn owner_generation_v1(&self) -> u64 {
        self.generation
    }
    pub const fn pin_v1(&self) -> OldEpochSafetyHeadPinV1 {
        self.pin
    }
    pub const fn transition_context_v1(&self) -> &SafetyTransitionContextV0 {
        &self.transition
    }
    pub fn into_unverified_record_v1(self) -> UnverifiedSafetyStateRecordV0 {
        *self.record
    }
    pub fn belongs_to_store_at_path_v1(
        &self,
        store: &SqliteOldEpochSafetyJournalV1,
        path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner, &store.owner)
            && store.database.path == path
            && store.require_namespace().is_ok()
    }
}

pub struct SqliteOldEpochSafetyJournalV1 {
    // Close connections before pin handles even on errors. Successful public
    // calls retain no SQLite connection/page cache across fresh readback.
    connection: Option<Connection>,
    database: PinnedFileV1,
    lock: PinnedFileV1,
    wal: Option<PinnedFileV1>,
    shm: Option<PinnedFileV1>,
    directory: PinnedFileV1,
    profile: OldEpochSafetyJournalProfileV1,
    journal_id: [u8; 32],
    owner: Arc<()>,
    pid: u32,
    binding: Option<SafetyStatePersistenceBindingV0>,
    fenced: bool,
}
impl SqliteOldEpochSafetyJournalV1 {
    pub(crate) fn immutable_profile_ref_v1(&self) -> [u8; 32] {
        self.profile.profile_ref_v1()
    }
    /// Explicitly migrate a fresh, independently pinned journal7 head. Original
    /// files stay untouched and owned; no custody retirement or external CAS is
    /// implied by creating the outgoing namespace.
    pub fn initialize_from_journal7_v1(
        path: impl AsRef<Path>,
        profile: OldEpochSafetyJournalProfileV1,
        source: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
        expected_source_chain: [u8; 32],
        owner: &OldEpochBoundaryCoreV1,
        request: &SafetyStatePersistenceV0,
    ) -> Result<(Self, ConfirmedOldEpochSafetyHeadV1)> {
        fs_owner::require_linux()?;
        let source_head = source.head()?;
        let source_facts = source.confirm_node_checkpoint_head_exact_v0(source_head.state())?;
        if source_head.chain_checksum() != expected_source_chain
            || source_facts.core_config_ref_v0()
                != safety_state_record_config_ref_v0(&profile.source_context()?)?
            || source.verifier_profile_ref_v0() != profile.source_profile.verifier_profile_ref()
        {
            return invalid("source head or context differs from independent pin");
        }
        let binding = owner.safety_state_persistence_binding_v0();
        if !binding.accepts(request)
            || owner.safety_state() != request.state()
            || owner.config() != &profile.config
        {
            return invalid("migration Core owner or request");
        }
        profile.check_state(request.state())?;
        Core::validate_persisted_successor_v0(
            &profile.config,
            source_head.state(),
            request.state(),
            &StrictEd25519Verifier,
        )?;
        let source_record =
            encode_safety_state_record_v0(source_head.state(), &profile.source_context()?)?;
        if decode_safety_state_record_v0_exact(&source_record, &profile.source_context()?)?
            .record_checksum()
            != source_head.state_record_checksum()
        {
            return invalid("source exact record");
        }
        let source_transition = encode_transition_context_v0(source_head.transition_context())?;
        let record =
            encode_old_epoch_boundary_safety_record_v1(request.state(), &profile.context()?)?;
        let context = SafetyTransitionContextV0::Ordinary;
        validate_transition_context_against_state_v0(&context, request.state())?;
        let transition = encode_transition_context_v0(&context)?;
        let (path, directory) = fs_owner::pin_namespace(path.as_ref())?;
        if path == source.path() || path.to_string_lossy().ends_with(".outgoing.lock") {
            return invalid("destination namespace collision");
        }
        let lock_path = fs_owner::auxiliary_path(&path, ".outgoing.lock");
        for p in [
            &path,
            &lock_path,
            &fs_owner::auxiliary_path(&path, "-wal"),
            &fs_owner::auxiliary_path(&path, "-shm"),
            &fs_owner::auxiliary_path(&path, "-journal"),
        ] {
            fs_owner::require_absent(p)?;
        }
        let mut journal_id = [0; 32];
        getrandom::getrandom(&mut journal_id)
            .map_err(|_| OldEpochJournalErrorV1::Invalid("journal identity entropy"))?;
        if journal_id == [0; 32] {
            return invalid("zero journal identity");
        }
        let mut lock_file = fs_owner::private_file(&lock_path, true)?;
        fs_owner::lock_exclusive(&lock_file)?;
        lock_file
            .write_all(LOCK_MAGIC)
            .and_then(|_| lock_file.write_all(&journal_id))
            .and_then(|_| lock_file.write_all(&profile.binding))
            .map_err(|e| io("write journal8 lock", e))?;
        lock_file
            .sync_all()
            .map_err(|e| io("sync journal8 lock", e))?;
        let lock = PinnedFileV1::new(lock_path, lock_file, false, 72)?;
        let database_file = fs_owner::private_file(&path, true)?;
        fs_owner::lock_exclusive(&database_file)?;
        let database = PinnedFileV1::new(path.clone(), database_file, false, profile.max_db)?;
        directory
            .file
            .sync_all()
            .map_err(|e| io("sync journal8 namespace", e))?;
        let connection = fs_owner::open_connection(&path, false)?;
        fs_owner::configure_connection(&connection, true, profile.max_row, profile.max_db)?;
        let mut store = Self {
            connection: Some(connection),
            database,
            lock,
            wal: None,
            shm: None,
            directory,
            profile,
            journal_id,
            owner: Arc::new(()),
            pid: std::process::id(),
            binding: Some(binding),
            fenced: false,
        };
        let revision = request.state().revision();
        let origin = origin_hash(
            &store.profile,
            journal_id,
            source.journal_id_v0(),
            expected_source_chain,
            &source_record,
            &source_transition,
        );
        let chain = chain_hash(origin, origin, revision, &record, &transition);
        {
            let tx = store
                .connection
                .as_mut()
                .expect("initialization connection")
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            store.wal = Some(fs_owner::pin_existing(
                &fs_owner::auxiliary_path(&path, "-wal"),
                store.profile.max_db * 2,
            )?);
            store.shm = Some(fs_owner::pin_existing(
                &fs_owner::auxiliary_path(&path, "-shm"),
                65_536,
            )?);
            tx.execute_batch(SQL)?;
            tx.pragma_update(None, "application_id", APPLICATION_ID)?;
            tx.pragma_update(None, "user_version", 8)?;
            tx.execute(
                "INSERT INTO outgoing_metadata VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    journal_id.as_slice(),
                    store.profile.binding.as_slice(),
                    source.journal_id_v0().as_slice(),
                    expected_source_chain.as_slice(),
                    source_record,
                    source_transition,
                    origin.as_slice(),
                    revision
                ],
            )?;
            tx.execute(
                "INSERT INTO outgoing_records VALUES(?1,?2,?3,?4,?5)",
                params![
                    revision,
                    origin.as_slice(),
                    chain.as_slice(),
                    record,
                    transition
                ],
            )?;
            tx.execute(
                "INSERT INTO outgoing_head VALUES(1,?1,?2)",
                params![revision, chain.as_slice()],
            )?;
            tx.commit()?;
        }
        store.close_and_sync()?;
        // Source must still name the same cut before initialization reports
        // success. Any uncertainty leaves a namespace which must be reconciled.
        if source.head()?.chain_checksum() != expected_source_chain {
            return invalid("source advanced during explicit migration");
        }
        let confirmed = store.fresh_read_v1(OldEpochSafetyHeadPinV1 {
            journal_id,
            revision,
            chain_checksum: chain,
        })?;
        Ok((store, confirmed))
    }

    /// Read-only existing open. Missing files, mismatched schema, unknown
    /// objects, and a stale independently expected head are fatal, never repaired.
    pub fn open_existing_v1(
        path: impl AsRef<Path>,
        profile: OldEpochSafetyJournalProfileV1,
        expected: OldEpochSafetyHeadPinV1,
    ) -> Result<Self> {
        fs_owner::require_linux()?;
        let (path, directory) = fs_owner::pin_namespace(path.as_ref())?;
        let lock = fs_owner::pin_existing(&fs_owner::auxiliary_path(&path, ".outgoing.lock"), 72)?;
        fs_owner::lock_exclusive(&lock.file)?;
        let database = fs_owner::pin_existing(&path, profile.max_db)?;
        fs_owner::lock_exclusive(&database.file)?;
        let wal = Some(fs_owner::pin_existing(
            &fs_owner::auxiliary_path(&path, "-wal"),
            profile.max_db * 2,
        )?);
        let shm = Some(fs_owner::pin_existing(
            &fs_owner::auxiliary_path(&path, "-shm"),
            65_536,
        )?);
        fs_owner::require_absent(&fs_owner::auxiliary_path(&path, "-journal"))?;
        let store = Self {
            connection: None,
            database,
            lock,
            wal,
            shm,
            directory,
            profile,
            journal_id: expected.journal_id,
            owner: Arc::new(()),
            pid: std::process::id(),
            binding: None,
            fenced: false,
        };
        store.fresh_read_v1(expected)?;
        Ok(store)
    }
    pub fn path_v1(&self) -> &Path {
        &self.database.path
    }

    /// Joins a fresh journal read to Core's strict terminal evidence validator
    /// using this owner's exact codec context. Both returned values remain
    /// inert; native application and shared signer custody are still required.
    pub fn prepare_terminal_recovery_v1(
        &self,
        expected: OldEpochSafetyHeadPinV1,
    ) -> Result<(
        ConfirmedOldEpochSafetyHeadV1,
        trnm_consensus_core::StrictOldEpochTerminalRecoveryV1,
    )> {
        let confirmed = self.fresh_read_v1(expected)?;
        let recovery = Core::prepare_old_epoch_terminal_recovery_v1(
            &confirmed.record,
            &self.profile.context()?,
            confirmed.state_record_checksum_v1(),
            self.profile.generation,
        )?;
        self.require_namespace()?;
        Ok((confirmed, recovery))
    }
    pub fn fresh_read_v1(
        &self,
        expected: OldEpochSafetyHeadPinV1,
    ) -> Result<ConfirmedOldEpochSafetyHeadV1> {
        self.require_namespace()?;
        let connection = fs_owner::open_connection(&self.database.path, true)?;
        fs_owner::configure_connection(
            &connection,
            false,
            self.profile.max_row,
            self.profile.max_db,
        )?;
        let result = self.read_head(&connection, expected);
        connection
            .close()
            .map_err(|(_, e)| OldEpochJournalErrorV1::Sqlite(e))?;
        self.require_namespace()?;
        result
    }
    /// A reopened journal cannot bind an arbitrary Core. It remains read-only
    /// until a concrete M15 recovery join is implemented. A live initialized
    /// journal accepts only requests from its originally bound strict owner.
    pub fn persist_exact_v1(
        &mut self,
        expected: OldEpochSafetyHeadPinV1,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> Result<ConfirmedOldEpochSafetyHeadV1> {
        self.persist_with_observer_v1(expected, request, transition, |_| Ok(()))
    }
    #[doc(hidden)]
    pub fn persist_with_observer_v1(
        &mut self,
        expected: OldEpochSafetyHeadPinV1,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        mut observer: impl FnMut(OldEpochJournalCutV1) -> Result<()>,
    ) -> Result<ConfirmedOldEpochSafetyHeadV1> {
        self.require_namespace()?;
        if !self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.accepts(request))
        {
            return invalid("journal is not bound to this live Core");
        }
        self.profile.check_state(request.state())?;
        validate_request_manifest(request, transition)?;
        validate_transition_context_against_state_v0(transition, request.state())?;
        let record =
            encode_old_epoch_boundary_safety_record_v1(request.state(), &self.profile.context()?)?;
        let transition_bytes = encode_transition_context_v0(transition)?;
        if transition_bytes.len() > MAX_CONTEXT {
            return invalid("transition capacity");
        }
        let result = self.persist_inner(
            expected,
            request,
            transition,
            &record,
            &transition_bytes,
            &mut observer,
        );
        if result.is_err() {
            self.fenced = true;
            let _ = self.close_connection();
        }
        result
    }
    fn persist_inner(
        &mut self,
        expected: OldEpochSafetyHeadPinV1,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        record: &[u8],
        transition_bytes: &[u8],
        observer: &mut impl FnMut(OldEpochJournalCutV1) -> Result<()>,
    ) -> Result<ConfirmedOldEpochSafetyHeadV1> {
        let head = self.fresh_read_v1(expected)?;
        if head.state_v1() == request.state() && head.transition_context_v1() == transition {
            return Ok(head);
        }
        Core::validate_persisted_successor_v0(
            &self.profile.config,
            head.state_v1(),
            request.state(),
            &StrictEd25519Verifier,
        )?;
        if (head.state_v1().application_applied() != request.state().application_applied())
            != request.native_finalization_applied_v0().is_some()
        {
            return invalid("application watermark requires exact Core manifest");
        }
        if let Some(manifest) = request.native_finalization_applied_v0() {
            crate::sqlite::validate_native_finalization_applied_predecessor_v0(
                request.state().revision(),
                manifest,
                head.state_v1(),
                request.state(),
            )?;
        }
        let revision = request.state().revision();
        let chain = chain_hash(
            head.origin,
            expected.chain_checksum,
            revision,
            record,
            transition_bytes,
        );
        let next = OldEpochSafetyHeadPinV1 {
            journal_id: self.journal_id,
            revision,
            chain_checksum: chain,
        };
        let connection = fs_owner::open_connection(&self.database.path, false)?;
        fs_owner::configure_connection(
            &connection,
            false,
            self.profile.max_row,
            self.profile.max_db,
        )?;
        connection.execute_batch("PRAGMA query_only=OFF; PRAGMA wal_autocheckpoint=0;")?;
        connection.pragma_update(None, "max_page_count", self.profile.max_db / 4096)?;
        self.connection = Some(connection);
        {
            let tx = self
                .connection
                .as_mut()
                .expect("writer opened")
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let active: (u64, Vec<u8>) = tx.query_row(
                "SELECT revision,chain FROM outgoing_head WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if active.0 != expected.revision || active.1.as_slice() != expected.chain_checksum {
                return invalid("head changed before transaction");
            }
            tx.execute(
                "INSERT INTO outgoing_records VALUES(?1,?2,?3,?4,?5)",
                params![
                    revision,
                    expected.chain_checksum.as_slice(),
                    chain.as_slice(),
                    record,
                    transition_bytes
                ],
            )?;
            if tx.execute("UPDATE outgoing_head SET revision=?1,chain=?2 WHERE singleton=1 AND revision=?3 AND chain=?4",params![revision,chain.as_slice(),expected.revision,expected.chain_checksum.as_slice()])?!=1 {return invalid("head CAS");}
            tx.execute(
                "DELETE FROM outgoing_records WHERE revision < ?1",
                [expected.revision],
            )?;
            observer(OldEpochJournalCutV1::AfterWriteBeforeCommit)?;
            tx.commit()?;
        }
        observer(OldEpochJournalCutV1::AfterCommitBeforeSync)?;
        self.close_and_sync()?;
        observer(OldEpochJournalCutV1::AfterSyncBeforeReadback)?;
        self.fresh_read_v1(next)
    }
    fn require_namespace(&self) -> Result<()> {
        if self.fenced {
            return Err(OldEpochJournalErrorV1::Fenced);
        }
        if std::process::id() != self.pid {
            return invalid("owner process changed");
        }
        for p in [&self.database, &self.lock, &self.directory] {
            p.require_unchanged()?;
        }
        if let Some(p) = &self.wal {
            p.require_unchanged()?;
        }
        if let Some(p) = &self.shm {
            p.require_unchanged()?;
        }
        if self
            .lock
            .file
            .metadata()
            .map_err(|e| io("stat lock", e))?
            .len()
            != 72
        {
            return invalid("lock size");
        }
        let mut bytes = [0; 72];
        let file = &self.lock.file;
        // Positional read avoids a mutable shared offset between fresh reads.
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            file.read_exact_at(&mut bytes, 0)
                .map_err(|e| io("read lock", e))?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Read;
            let mut file = file;
            file.read_exact(&mut bytes)
                .map_err(|e| io("read lock", e))?;
        }
        if &bytes[..8] != LOCK_MAGIC
            || bytes[8..40] != self.journal_id
            || bytes[40..] != self.profile.binding
        {
            return invalid("lock binding");
        }
        Ok(())
    }
    fn close_connection(&mut self) -> Result<()> {
        if let Some(c) = self.connection.take() {
            c.close()
                .map_err(|(_, e)| OldEpochJournalErrorV1::Sqlite(e))?;
        }
        Ok(())
    }
    fn close_and_sync(&mut self) -> Result<()> {
        self.require_namespace()?;
        self.close_connection()?;
        self.require_namespace()?;
        for file in [
            &self.database.file,
            &self.lock.file,
            &self
                .wal
                .as_ref()
                .ok_or(OldEpochJournalErrorV1::Invalid("missing WAL"))?
                .file,
            &self
                .shm
                .as_ref()
                .ok_or(OldEpochJournalErrorV1::Invalid("missing SHM"))?
                .file,
            &self.directory.file,
        ] {
            file.sync_all().map_err(|e| io("sync journal8", e))?;
        }
        self.require_namespace()
    }
    fn read_head(
        &self,
        c: &Connection,
        expected: OldEpochSafetyHeadPinV1,
    ) -> Result<ConfirmedOldEpochSafetyHeadV1> {
        check_schema(c)?;
        // Query scalar lengths before allocating untrusted persistent blobs.
        let sizes:(i64,i64)=c.query_row("SELECT length(source_record),length(source_transition) FROM outgoing_metadata WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if sizes.0 <= 0
            || sizes.0 as u64
                > self
                    .profile
                    .source_profile
                    .record_limits()
                    .maximum_record_bytes() as u64
            || sizes.1 <= 0
            || sizes.1 as usize > MAX_CONTEXT
        {
            return invalid("source blob bounds");
        }
        let m=c.query_row("SELECT journal,profile,source_journal,source_chain,source_record,source_transition,origin,first_revision FROM outgoing_metadata WHERE singleton=1",[],|r|Ok(Metadata{journal:r.get(0)?,profile:r.get(1)?,source_journal:r.get(2)?,source_chain:r.get(3)?,source_record:r.get(4)?,source_transition:r.get(5)?,origin:r.get(6)?,first_revision:r.get(7)?}))?;
        if m.journal != self.journal_id
            || m.profile != self.profile.binding
            || expected.journal_id != self.journal_id
            || m.origin
                != origin_hash(
                    &self.profile,
                    self.journal_id,
                    m.source_journal,
                    m.source_chain,
                    &m.source_record,
                    &m.source_transition,
                )
        {
            return invalid("metadata profile/source binding");
        }
        let source =
            decode_safety_state_record_v0_exact(&m.source_record, &self.profile.source_context()?)?;
        Core::validate_persisted_state_v0(
            &self.profile.config,
            source.state(),
            &StrictEd25519Verifier,
        )?;
        let source_transition = decode_transition_context_v0_exact(&m.source_transition)?;
        validate_transition_context_against_state_v0(&source_transition, source.state())?;
        if source.state().revision().checked_add(1) != Some(m.first_revision) {
            return invalid("migration origin revision");
        }
        let head: (u64, [u8; 32]) = c.query_row(
            "SELECT revision,chain FROM outgoing_head WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if head != (expected.revision, expected.chain_checksum) || head.0 < m.first_revision {
            return invalid("active head differs from independently expected cut");
        }
        let count: i64 = c.query_row("SELECT count(*) FROM outgoing_records", [], |r| r.get(0))?;
        if count != if head.0 == m.first_revision { 1 } else { 2 } {
            return invalid("retained record count");
        }
        let mut s=c.prepare("SELECT revision,predecessor,chain,length(record),length(transition) FROM outgoing_records ORDER BY revision")?;
        let coordinates = s
            .query_map([], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, [u8; 32]>(1)?,
                    r.get::<_, [u8; 32]>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut previous: Option<(UnverifiedSafetyStateRecordV0, [u8; 32])> = None;
        let mut result = None;
        for (index, (revision, predecessor, chain, record_len, context_len)) in
            coordinates.into_iter().enumerate()
        {
            if record_len <= 0
                || record_len as usize > self.profile.limits.maximum_record_bytes()
                || context_len <= 0
                || context_len as usize > MAX_CONTEXT
                || revision != head.0 - (count as u64 - 1) + index as u64
            {
                return invalid("retained record bounds or revision");
            }
            let (record_bytes, transition_bytes): (Vec<u8>, Vec<u8>) = c.query_row(
                "SELECT record,transition FROM outgoing_records WHERE revision=?1",
                [revision],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if chain
                != chain_hash(
                    m.origin,
                    predecessor,
                    revision,
                    &record_bytes,
                    &transition_bytes,
                )
            {
                return invalid("retained chain checksum");
            }
            let record = decode_old_epoch_boundary_safety_record_v1_exact(
                &record_bytes,
                &self.profile.context()?,
            )?;
            self.profile.check_state(record.state())?;
            if record.state().revision() != revision {
                return invalid("record revision");
            }
            let transition = decode_transition_context_v0_exact(&transition_bytes)?;
            validate_transition_context_against_state_v0(&transition, record.state())?;
            if revision == m.first_revision {
                if predecessor != m.origin {
                    return invalid("migration predecessor");
                }
                Core::validate_persisted_successor_v0(
                    &self.profile.config,
                    source.state(),
                    record.state(),
                    &StrictEd25519Verifier,
                )?;
            }
            if let Some((before, before_chain)) = &previous {
                if predecessor != *before_chain {
                    return invalid("retained predecessor link");
                }
                Core::validate_persisted_successor_v0(
                    &self.profile.config,
                    before.state(),
                    record.state(),
                    &StrictEd25519Verifier,
                )?;
                if (before.state().application_applied() != record.state().application_applied())
                    != transition
                        .native_finalization_applied_transition()
                        .is_some()
                {
                    return invalid("retained application watermark lacks context");
                }
                if let Some(facts) = transition.native_finalization_applied_transition() {
                    crate::sqlite::validate_persisted_native_finalization_applied_pair_v0(
                        facts,
                        before.state(),
                        record.state(),
                    )?;
                }
            }
            if revision == head.0 {
                if chain != head.1 {
                    return invalid("head chain differs from record");
                }
                result = Some(ConfirmedOldEpochSafetyHeadV1 {
                    record: Box::new(record.clone()),
                    transition,
                    pin: expected,
                    context_ref: self.profile.context_ref_v1()?,
                    generation: self.profile.generation,
                    origin: m.origin,
                    source: OldEpochMigrationSourceV1 {
                        revision: source.state().revision(),
                        state_record_checksum: source.record_checksum(),
                        journal_id: m.source_journal,
                        chain_checksum: m.source_chain,
                        verifier_profile_ref: self.profile.source_profile.verifier_profile_ref(),
                        config_ref: safety_state_record_config_ref_v0(
                            &self.profile.source_context()?,
                        )?,
                    },
                    owner: Arc::clone(&self.owner),
                });
            }
            previous = Some((record, chain));
        }
        result.ok_or(OldEpochJournalErrorV1::Invalid("missing head record"))
    }
}
struct Metadata {
    journal: [u8; 32],
    profile: [u8; 32],
    source_journal: [u8; 32],
    source_chain: [u8; 32],
    source_record: Vec<u8>,
    source_transition: Vec<u8>,
    origin: [u8; 32],
    first_revision: u64,
}
fn origin_hash(
    profile: &OldEpochSafetyJournalProfileV1,
    journal: [u8; 32],
    source_journal: [u8; 32],
    source_chain: [u8; 32],
    record: &[u8],
    context: &[u8],
) -> [u8; 32] {
    digest(
        b"trnm.journal8.outgoing.origin.v1",
        &[
            &profile.binding,
            &journal,
            &source_journal,
            &source_chain,
            record,
            context,
        ],
    )
}
fn chain_hash(
    origin: [u8; 32],
    previous: [u8; 32],
    revision: u64,
    record: &[u8],
    context: &[u8],
) -> [u8; 32] {
    digest(
        b"trnm.journal8.outgoing.chain.v1",
        &[&origin, &previous, &revision.to_be_bytes(), record, context],
    )
}
fn check_schema(c: &Connection) -> Result<()> {
    let app: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if app != APPLICATION_ID || version != 8 {
        return invalid("journal8 application ID/schema");
    }
    fn inventory(
        c: &Connection,
    ) -> std::result::Result<Vec<(String, String, String, String)>, rusqlite::Error> {
        let mut rows: Vec<_> = c
            .prepare("SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema LIMIT 4")?
            .query_map([], |r| {
                fn bounded(
                    r: &rusqlite::Row<'_>,
                    i: usize,
                    max: usize,
                ) -> rusqlite::Result<String> {
                    let text = r.get_ref(i)?.as_str()?;
                    if text.len() > max {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    Ok(text.to_owned())
                }
                Ok((
                    bounded(r, 0, 16)?,
                    bounded(r, 1, 64)?,
                    bounded(r, 2, 64)?,
                    bounded(r, 3, 4096)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        rows.sort();
        Ok(rows)
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SQL)?;
    if inventory(c)? != inventory(&reference)? {
        return invalid("journal8 closed schema inventory");
    }
    let metadata: i64 = c.query_row("SELECT count(*) FROM outgoing_metadata", [], |r| r.get(0))?;
    let heads: i64 = c.query_row("SELECT count(*) FROM outgoing_head", [], |r| r.get(0))?;
    if metadata != 1 || heads != 1 {
        return invalid("journal8 singleton inventory");
    }
    Ok(())
}

fn validate_request_manifest(
    request: &SafetyStatePersistenceV0,
    transition: &SafetyTransitionContextV0,
) -> Result<()> {
    if request.barrier().get() != request.state().revision()
        || request.state_sync_anchor_ordinary_promotion_v0().is_some()
        || transition
            .state_sync_anchor_ordinary_promotion_transition()
            .is_some()
    {
        return invalid("outgoing request barrier or unsupported state-sync route");
    }
    if request.native_valid_post_ack_action_v0().is_some()
        && request.native_finalization_applied_v0().is_some()
    {
        return invalid("multiple callback manifests");
    }
    crate::sqlite::validate_native_valid_post_ack_manifest_v0(
        request.state().revision(),
        request.native_valid_post_ack_action_v0().map(|a| a.code()),
        transition,
    )?;
    crate::sqlite::validate_native_finalization_applied_manifest_v0(
        request.state().revision(),
        request.native_finalization_applied_v0(),
        transition,
    )?;
    if let Some(manifest) = request.native_finalization_applied_v0() {
        crate::sqlite::validate_native_finalization_applied_successor_v0(
            request.state().revision(),
            manifest,
            request.state(),
        )?;
    }
    Ok(())
}
