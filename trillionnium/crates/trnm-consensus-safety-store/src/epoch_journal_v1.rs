//! Separate journal9 for exact full-context 14E records. Initial migration
//! consumes an opaque pending Core request plus the actual fresh journal8 cut.
//! The store returns inert comparison receipts, never an ACK or signer lease.
use crate::epoch_journal_physical_v2::{
    JournalBoundsV2, JournalLayoutV2, PhysicalJournalErrorV2, PhysicalJournalV2,
};
use crate::epoch_preparation_sqlite_v1 as fs_owner;
use crate::{
    decode_transition_context_v0_exact, encode_transition_context_v0,
    validate_transition_context_against_state_v0, OldEpochSafetyHeadPinV1,
    OldEpochSafetyJournalProfileV1, SafetyStoreErrorV0, SafetyTransitionContextV0,
    SqliteOldEpochSafetyJournalV1,
};
use fs_owner::EpochPreparationStoreErrorV1;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use trnm_consensus_core::{
    decode_epoch_safety_record_v1_exact, decode_old_epoch_boundary_safety_record_v1_exact,
    encode_epoch_safety_record_v1, encode_old_epoch_boundary_safety_record_v1,
    epoch_safety_record_context_ref_v1, Core, CoreConfig, CoreError, EpochCoreStateV1,
    EpochSafetyStateRecordContextV1, PreparedEpochCoreActivationV1, SafetyState,
    SafetyStatePersistenceBindingV0, SafetyStatePersistenceV0, SafetyStateRecordContextV0,
    SafetyStateRecordErrorV0, SafetyStateRecordLimitsV0, UnverifiedSafetyStateRecordV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;

const MAX_RECORD: usize = 256 * 1024 * 1024;
const MAX_CONTEXT: usize = 1024 * 1024;

#[derive(Debug)]
pub enum EpochJournalErrorV1 {
    Namespace(EpochPreparationStoreErrorV1),
    Sqlite(rusqlite::Error),
    Source(SafetyStoreErrorV0),
    OldJournal(crate::OldEpochJournalErrorV1),
    Record(SafetyStateRecordErrorV0),
    Core(CoreError),
    Invalid(&'static str),
    Fenced,
}
impl std::fmt::Display for EpochJournalErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch journal9: {self:?}")
    }
}
impl std::error::Error for EpochJournalErrorV1 {}
impl From<EpochPreparationStoreErrorV1> for EpochJournalErrorV1 {
    fn from(e: EpochPreparationStoreErrorV1) -> Self {
        Self::Namespace(e)
    }
}
impl From<rusqlite::Error> for EpochJournalErrorV1 {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}
impl From<SafetyStoreErrorV0> for EpochJournalErrorV1 {
    fn from(e: SafetyStoreErrorV0) -> Self {
        Self::Source(e)
    }
}
impl From<SafetyStateRecordErrorV0> for EpochJournalErrorV1 {
    fn from(e: SafetyStateRecordErrorV0) -> Self {
        Self::Record(e)
    }
}
impl From<crate::OldEpochJournalErrorV1> for EpochJournalErrorV1 {
    fn from(value: crate::OldEpochJournalErrorV1) -> Self {
        Self::OldJournal(value)
    }
}
impl From<CoreError> for EpochJournalErrorV1 {
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}
type Result<T> = std::result::Result<T, EpochJournalErrorV1>;
fn invalid<T>(why: &'static str) -> Result<T> {
    Err(EpochJournalErrorV1::Invalid(why))
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
impl From<PhysicalJournalErrorV2> for EpochJournalErrorV1 {
    fn from(error: PhysicalJournalErrorV2) -> Self {
        match error {
            PhysicalJournalErrorV2::Namespace(error) => Self::Namespace(error),
            PhysicalJournalErrorV2::Sqlite(error) => Self::Sqlite(error),
            PhysicalJournalErrorV2::Invalid(why) => Self::Invalid(why),
            PhysicalJournalErrorV2::Fenced => Self::Fenced,
        }
    }
}
/// Closed profile binds the exact full 14E context and immediate journal8
/// source context. No caller-selectable verifier or automatic codec upgrade.
#[derive(Debug, Clone)]
pub struct EpochSafetyJournalProfileV1 {
    config: CoreConfig,
    limits: SafetyStateRecordLimitsV0,
    source_profile: OldEpochSafetyJournalProfileV1,
    epoch: EpochCoreStateV1,
    generation: u64,
    max_db: u64,
    max_row: usize,
    binding: [u8; 32],
}
impl EpochSafetyJournalProfileV1 {
    pub fn new(
        source_profile: OldEpochSafetyJournalProfileV1,
        context: &EpochSafetyStateRecordContextV1<'_>,
    ) -> Result<Self> {
        let config = context.core_config().clone();
        let limits = context.limits();
        let epoch = context.epoch().clone();
        let source_context = source_profile.context()?;
        let old_config = source_context.core_config();
        if old_config.validator_set() != context.runtime().activation().old_validator_set()
            || old_config.consensus_parameters()
                != context.runtime().activation().old_consensus_parameters()
            || old_config.local_validator() != config.local_validator()
            || source_profile.owner_generation_v1().checked_add(1) != Some(epoch.owner_generation())
            || limits.maximum_record_bytes() > MAX_RECORD
            || source_context.limits().maximum_record_bytes() > MAX_RECORD
        {
            return invalid("source/target profile or capacity mismatch");
        }
        // SQLite LENGTH bounds an entire row, not just its largest BLOB.
        // Immutable metadata retains a source14O record beside its transition.
        let max_row = limits
            .maximum_record_bytes()
            .max(source_context.limits().maximum_record_bytes())
            .checked_add(MAX_CONTEXT)
            .ok_or(EpochJournalErrorV1::Invalid("row capacity overflow"))?;
        max_row
            .checked_add(4096)
            .and_then(|n| i32::try_from(n).ok())
            .ok_or(EpochJournalErrorV1::Invalid("SQLite row capacity"))?;
        let context_ref = epoch_safety_record_context_ref_v1(context)?;
        let max_db = (limits.maximum_record_bytes() as u64)
            .checked_mul(6)
            .and_then(|n| {
                n.checked_add(
                    source_context.limits().maximum_record_bytes() as u64 * 2 + 16 * 1024 * 1024,
                )
            })
            .ok_or(EpochJournalErrorV1::Invalid("database capacity"))?;
        let generation = epoch.owner_generation();
        let binding = digest(
            b"trnm.journal9.epoch.profile.v1",
            &[
                &context_ref,
                &source_profile.profile_ref_v1(),
                &source_profile.context_ref_v1()?,
                &generation.to_be_bytes(),
                &max_db.to_be_bytes(),
                &(max_row as u64).to_be_bytes(),
            ],
        );
        Ok(Self {
            config,
            limits,
            source_profile,
            epoch,
            generation,
            max_db,
            max_row,
            binding,
        })
    }
    pub(crate) fn context(&self) -> Result<EpochSafetyStateRecordContextV1<'_>> {
        Ok(EpochSafetyStateRecordContextV1::new(
            &self.config,
            self.epoch.strict_context()?,
            self.epoch.checkpoint_artifact(),
            self.generation,
            self.limits,
        )?)
    }
    fn source_context(&self) -> Result<SafetyStateRecordContextV0<'_>> {
        Ok(self.source_profile.context()?)
    }
    pub const fn owner_generation_v1(&self) -> u64 {
        self.generation
    }
    pub const fn profile_ref_v1(&self) -> [u8; 32] {
        self.binding
    }
    pub fn context_ref_v1(&self) -> Result<[u8; 32]> {
        Ok(epoch_safety_record_context_ref_v1(&self.context()?)?)
    }
    fn check_state(&self, state: &SafetyState) -> Result<()> {
        if state.epoch_state_v1() != Some(&self.epoch) {
            return invalid("epoch state context mismatch");
        }
        Core::validate_persisted_state_v0(&self.config, state, &StrictEd25519Verifier)?;
        Ok(())
    }
}

/// Comparison-only expected head. A host obtains freshness by pinning this in
/// its independent monotonic service, never by reading it from the same image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetyHeadPinV1 {
    pub journal_id: [u8; 32],
    pub revision: u64,
    pub chain_checksum: [u8; 32],
}

/// Real transaction/response-loss cuts, also usable by process-kill tests.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochJournalCutV1 {
    AfterWriteBeforeCommit,
    AfterCommitBeforeSync,
    AfterSyncBeforeReadback,
}

/// Immutable source facts audited from the retained, strictly decoded journal8
/// origin on every fresh read. These are comparison data, not source ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetyMigrationSourceV1 {
    pin: OldEpochSafetyHeadPinV1,
    record_checksum: [u8; 32],
    context_ref: [u8; 32],
    profile_ref: [u8; 32],
    initial_revision: u64,
}
impl EpochSafetyMigrationSourceV1 {
    pub const fn pin_v1(&self) -> OldEpochSafetyHeadPinV1 {
        self.pin
    }
    pub const fn state_record_checksum_v1(&self) -> [u8; 32] {
        self.record_checksum
    }
    pub const fn context_ref_v1(&self) -> [u8; 32] {
        self.context_ref
    }
    pub const fn profile_ref_v1(&self) -> [u8; 32] {
        self.profile_ref
    }
    pub const fn initial_revision_v1(&self) -> u64 {
        self.initial_revision
    }
}

/// Fresh owner-affine facts. This is deliberately neither Clone nor signing or
/// Core recovery authority; M15 must still reconcile native and signer owners.
pub struct ConfirmedEpochSafetyHeadV1 {
    record: Box<UnverifiedSafetyStateRecordV0>,
    transition: SafetyTransitionContextV0,
    pin: EpochSafetyHeadPinV1,
    context_ref: [u8; 32],
    generation: u64,
    origin: [u8; 32],
    source: EpochSafetyMigrationSourceV1,
    owner: Arc<()>,
}
impl ConfirmedEpochSafetyHeadV1 {
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
    pub const fn pin_v1(&self) -> EpochSafetyHeadPinV1 {
        self.pin
    }
    pub const fn transition_context_v1(&self) -> &SafetyTransitionContextV0 {
        &self.transition
    }
    pub const fn migration_source_v1(&self) -> &EpochSafetyMigrationSourceV1 {
        &self.source
    }
    pub fn into_unverified_record_v1(self) -> UnverifiedSafetyStateRecordV0 {
        *self.record
    }
    pub fn belongs_to_store_at_path_v1(
        &self,
        store: &SqliteEpochSafetyJournalV1,
        path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner, &store.owner)
            && store.path_v1() == path
            && store.fresh_read_v1(self.pin).is_ok_and(|fresh| {
                fresh.state_record_checksum_v1() == self.state_record_checksum_v1()
                    && fresh.transition_context_v1() == self.transition_context_v1()
            })
    }
}

pub struct SqliteEpochSafetyJournalV1 {
    physical: PhysicalJournalV2,
    profile: EpochSafetyJournalProfileV1,
    journal_id: [u8; 32],
    owner: Arc<()>,
    binding: Option<SafetyStatePersistenceBindingV0>,
}
impl SqliteEpochSafetyJournalV1 {
    /// Explicit source8-to-journal9 migration of the exact pending activation.
    /// The returned receipt is inert; this does not ACK Core or commission keys.
    pub fn initialize_from_journal8_v1(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV1,
        source: &SqliteOldEpochSafetyJournalV1,
        expected_source: OldEpochSafetyHeadPinV1,
        prepared: &PreparedEpochCoreActivationV1,
    ) -> Result<(Self, ConfirmedEpochSafetyHeadV1)> {
        Self::initialize_with_observer_v1(
            path,
            profile,
            source,
            expected_source,
            prepared,
            |_, _| Ok(()),
        )
    }
    /// Real initialization transaction cuts for process-death/reconciliation tests.
    /// The pin is inert comparison data; observing it acknowledges no Core work.
    #[doc(hidden)]
    pub fn initialize_with_observer_v1(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV1,
        source: &SqliteOldEpochSafetyJournalV1,
        expected_source: OldEpochSafetyHeadPinV1,
        prepared: &PreparedEpochCoreActivationV1,
        mut observer: impl FnMut(EpochJournalCutV1, EpochSafetyHeadPinV1) -> Result<()>,
    ) -> Result<(Self, ConfirmedEpochSafetyHeadV1)> {
        fs_owner::require_linux()?;
        let (source_head, source_recovery) =
            source.prepare_terminal_recovery_v1(expected_source)?;
        if source_head.context_ref_v1() != profile.source_profile.context_ref_v1()?
            || !source_head.belongs_to_store_at_path_v1(source, source.path_v1())
            || source_head.owner_generation_v1() != profile.source_profile.owner_generation_v1()
            || prepared.predecessor() != source_head.state_v1()
            || prepared.config() != &profile.config
        {
            return invalid("activation source owner/context/predecessor mismatch");
        }
        let expected_preparation =
            source_recovery.prepare_epoch_activation_v1(&profile.context()?)?;
        let request = prepared.initial_persistence_v1();
        let binding = prepared.persistence_binding_v1();
        if !binding.accepts(request)
            || request.state() != prepared.state()
            || prepared.state() != expected_preparation.state()
        {
            return invalid("activation request differs from exact terminal successor");
        }
        profile.check_state(request.state())?;
        let source_record = encode_old_epoch_boundary_safety_record_v1(
            source_head.state_v1(),
            &profile.source_context()?,
        )?;
        if decode_old_epoch_boundary_safety_record_v1_exact(
            &source_record,
            &profile.source_context()?,
        )?
        .record_checksum()
            != source_head.state_record_checksum_v1()
        {
            return invalid("source exact record");
        }
        let source_transition = encode_transition_context_v0(source_head.transition_context_v1())?;
        let record = encode_epoch_safety_record_v1(request.state(), &profile.context()?)?;
        let context = SafetyTransitionContextV0::Ordinary;
        validate_request_manifest(request, &context)?;
        validate_transition_context_against_state_v0(&context, request.state())?;
        let transition = encode_transition_context_v0(&context)?;
        let physical = PhysicalJournalV2::create_new(
            path.as_ref(),
            JournalLayoutV2::Codec1,
            profile.binding,
            JournalBoundsV2 {
                max_row: profile.max_row,
                max_db: profile.max_db,
            },
            Some(source.path_v1()),
        )?;
        let journal_id = physical.journal_id();
        let mut store = Self {
            physical,
            profile,
            journal_id,
            owner: Arc::new(()),
            binding: Some(binding),
        };
        let revision = request.state().revision();
        let origin = origin_hash(
            &store.profile,
            journal_id,
            expected_source.journal_id,
            expected_source.chain_checksum,
            &source_record,
            &source_transition,
        );
        let chain = chain_hash(origin, origin, revision, &record, &transition);
        let expected = EpochSafetyHeadPinV1 {
            journal_id,
            revision,
            chain_checksum: chain,
        };
        {
            let tx = store.physical.immediate_transaction()?;
            JournalLayoutV2::Codec1.initialize_schema(&tx)?;
            tx.execute(
                "INSERT INTO epoch_metadata VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    journal_id.as_slice(),
                    store.profile.binding.as_slice(),
                    expected_source.journal_id.as_slice(),
                    expected_source.chain_checksum.as_slice(),
                    source_record,
                    source_transition,
                    origin.as_slice(),
                    revision
                ],
            )?;
            tx.execute(
                "INSERT INTO epoch_records VALUES(?1,?2,?3,?4,?5)",
                params![
                    revision,
                    origin.as_slice(),
                    chain.as_slice(),
                    record,
                    transition
                ],
            )?;
            tx.execute(
                "INSERT INTO epoch_head VALUES(1,?1,?2)",
                params![revision, chain.as_slice()],
            )?;
            observer(EpochJournalCutV1::AfterWriteBeforeCommit, expected)?;
            tx.commit()?;
        }
        observer(EpochJournalCutV1::AfterCommitBeforeSync, expected)?;
        store.close_and_sync()?;
        observer(EpochJournalCutV1::AfterSyncBeforeReadback, expected)?;
        // Source must still name the same cut before initialization reports
        // success. Any uncertainty leaves a namespace which must be reconciled.
        if source.fresh_read_v1(expected_source)?.state_v1() != prepared.predecessor() {
            return invalid("source advanced during explicit migration");
        }
        let confirmed = store.fresh_read_v1(EpochSafetyHeadPinV1 {
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
        profile: EpochSafetyJournalProfileV1,
        expected: EpochSafetyHeadPinV1,
    ) -> Result<Self> {
        let physical = PhysicalJournalV2::open_existing(
            path.as_ref(),
            JournalLayoutV2::Codec1,
            profile.binding,
            JournalBoundsV2 {
                max_row: profile.max_row,
                max_db: profile.max_db,
            },
            expected.journal_id,
        )?;
        let store = Self {
            physical,
            profile,
            journal_id: expected.journal_id,
            owner: Arc::new(()),
            binding: None,
        };
        store.fresh_read_v1(expected)?;
        Ok(store)
    }
    pub fn path_v1(&self) -> &Path {
        self.physical.path()
    }
    pub(crate) fn immutable_profile_ref_v1(&self) -> [u8; 32] {
        self.profile.profile_ref_v1()
    }

    /// Joins a fresh journal read to Core's strict terminal evidence validator
    /// using this owner's exact codec context. Both returned values remain
    /// inert; native application and shared signer custody are still required.
    pub fn prepare_recovery_v1(
        &self,
        expected: EpochSafetyHeadPinV1,
    ) -> Result<(
        ConfirmedEpochSafetyHeadV1,
        trnm_consensus_core::StrictEpochCoreRecoveryV1,
    )> {
        let confirmed = self.fresh_read_v1(expected)?;
        let recovery = Core::prepare_epoch_recovery_v1(
            &confirmed.record,
            &self.profile.context()?,
            confirmed.state_record_checksum_v1(),
        )?;
        self.require_namespace()?;
        Ok((confirmed, recovery))
    }
    pub fn fresh_read_v1(
        &self,
        expected: EpochSafetyHeadPinV1,
    ) -> Result<ConfirmedEpochSafetyHeadV1> {
        let connection = self.physical.open_read_connection()?;
        let result = self.read_head(&connection, expected);
        self.physical.close_read_connection(connection)?;
        result
    }

    /// Fresh, exact confirmation for this journal's actual process-bound Core
    /// request. No writes, ACK, signing, or host activation are performed.
    pub fn confirm_exact_request_v1(
        &self,
        expected: EpochSafetyHeadPinV1,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> Result<ConfirmedEpochSafetyHeadV1> {
        if !self.binding.as_ref().is_some_and(|b| b.accepts(request)) {
            return invalid("exact confirmation requires this journal's bound Core request");
        }
        validate_request_manifest(request, transition)?;
        let confirmed = self.fresh_read_v1(expected)?;
        if confirmed.state_v1() != request.state()
            || confirmed.revision_v1() != request.barrier().get()
            || confirmed.transition_context_v1() != transition
        {
            return invalid("fresh journal cut differs from exact Core request/manifest");
        }
        Ok(confirmed)
    }

    /// Default-off trusted-host composition plumbing. Rebinds a read-only
    /// reopened owner only to the strictly reconstructed exact initial14E cut.
    /// The returned driver still rejects every input except its pending ACK.
    /// M15 must complete all physical native/custody/checkpoint joins before
    /// using that ACK. This method is not a lease or an external rollback check.
    #[cfg(feature = "candidate-epoch-host-v1")]
    pub fn prepare_candidate_host_initial_recovery_v1(
        &mut self,
        expected: EpochSafetyHeadPinV1,
    ) -> Result<(
        ConfirmedEpochSafetyHeadV1,
        trnm_consensus_core::PendingEpochHostDriverV1,
    )> {
        if self.binding.is_some() {
            return invalid("journal already bound; recovery cannot duplicate a live driver");
        }
        let (confirmed, recovery) = self.prepare_recovery_v1(expected)?;
        if confirmed.revision_v1() != confirmed.source.initial_revision
            || confirmed.transition_context_v1() != &SafetyTransitionContextV0::ordinary()
        {
            return invalid("candidate epoch recovery supports only the exact initial cut");
        }
        let driver = recovery.into_candidate_host_initial_pending_v1()?;
        if driver.state() != confirmed.state_v1()
            || driver.initial_persistence_v1().state() != confirmed.state_v1()
        {
            return invalid("strict initial driver differs from fresh journal cut");
        }
        // A second exact physical read precedes installation of the sole new
        // process affinity. Failure leaves the reopened journal unbound.
        let fresh = self.fresh_read_v1(expected)?;
        if fresh.state_record_checksum_v1() != confirmed.state_record_checksum_v1()
            || fresh.transition_context_v1() != confirmed.transition_context_v1()
        {
            return invalid("journal changed during initial recovery binding");
        }
        self.binding = Some(driver.persistence_binding_v1());
        Ok((fresh, driver))
    }

    /// Rebind a reopened journal to the exact progressed Core owner whose
    /// durable state contains one pending Vote.  Unlike initial recovery this
    /// does not synthesize an activation ACK; it only installs the fresh
    /// process affinity required for the already-recorded signature release.
    #[cfg(feature = "candidate-epoch-host-v1")]
    pub fn prepare_candidate_host_progressed_recovery_v1(
        &mut self,
        expected: EpochSafetyHeadPinV1,
    ) -> Result<(
        ConfirmedEpochSafetyHeadV1,
        trnm_consensus_core::PendingEpochHostDriverV1,
    )> {
        if self.binding.is_some() {
            return invalid("journal already bound; recovery cannot duplicate a live driver");
        }
        let (confirmed, recovery) = self.prepare_recovery_v1(expected)?;
        if !matches!(
            confirmed.state_v1().pending_sign(),
            Some(trnm_consensus_core::SignIntent::Vote { .. })
        ) || confirmed.state_v1().pending_finalize().is_some()
            || !confirmed
                .state_v1()
                .payload_validation_obligations()
                .is_empty()
        {
            return invalid("candidate progressed recovery requires one pending Vote");
        }
        let driver = recovery.into_candidate_host_progressed_v1()?;
        if driver.state() != confirmed.state_v1() {
            return invalid("strict progressed driver differs from fresh journal cut");
        }
        let fresh = self.fresh_read_v1(expected)?;
        if fresh.state_record_checksum_v1() != confirmed.state_record_checksum_v1()
            || fresh.transition_context_v1() != confirmed.transition_context_v1()
        {
            return invalid("journal changed during progressed recovery binding");
        }
        self.binding = Some(driver.persistence_binding_v1());
        Ok((fresh, driver))
    }
    /// A reopened journal cannot bind an arbitrary Core. It remains read-only
    /// until a concrete M15 recovery join is implemented. A live initialized
    /// journal accepts only requests from its originally bound strict owner.
    pub fn persist_exact_v1(
        &mut self,
        expected: EpochSafetyHeadPinV1,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> Result<ConfirmedEpochSafetyHeadV1> {
        self.persist_with_observer_v1(expected, request, transition, |_| Ok(()))
    }
    #[doc(hidden)]
    pub fn persist_with_observer_v1(
        &mut self,
        expected: EpochSafetyHeadPinV1,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        mut observer: impl FnMut(EpochJournalCutV1) -> Result<()>,
    ) -> Result<ConfirmedEpochSafetyHeadV1> {
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
        let record = encode_epoch_safety_record_v1(request.state(), &self.profile.context()?)?;
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
            self.physical.fence();
        }
        result
    }
    fn persist_inner(
        &mut self,
        expected: EpochSafetyHeadPinV1,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        record: &[u8],
        transition_bytes: &[u8],
        observer: &mut impl FnMut(EpochJournalCutV1) -> Result<()>,
    ) -> Result<ConfirmedEpochSafetyHeadV1> {
        let head = self.fresh_read_v1(expected)?;
        if head.state_v1() == request.state() && head.transition_context_v1() == transition {
            self.close_and_sync()?;
            return self.fresh_read_v1(expected);
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
        let next = EpochSafetyHeadPinV1 {
            journal_id: self.journal_id,
            revision,
            chain_checksum: chain,
        };
        self.physical.open_writer()?;
        {
            let tx = self.physical.immediate_transaction()?;
            let active: (u64, Vec<u8>) = tx.query_row(
                "SELECT revision,chain FROM epoch_head WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if active.0 != expected.revision || active.1.as_slice() != expected.chain_checksum {
                return invalid("head changed before transaction");
            }
            tx.execute(
                "INSERT INTO epoch_records VALUES(?1,?2,?3,?4,?5)",
                params![
                    revision,
                    expected.chain_checksum.as_slice(),
                    chain.as_slice(),
                    record,
                    transition_bytes
                ],
            )?;
            if tx.execute("UPDATE epoch_head SET revision=?1,chain=?2 WHERE singleton=1 AND revision=?3 AND chain=?4",params![revision,chain.as_slice(),expected.revision,expected.chain_checksum.as_slice()])?!=1 {return invalid("head CAS");}
            tx.execute(
                "DELETE FROM epoch_records WHERE revision < ?1",
                [expected.revision],
            )?;
            observer(EpochJournalCutV1::AfterWriteBeforeCommit)?;
            tx.commit()?;
        }
        observer(EpochJournalCutV1::AfterCommitBeforeSync)?;
        self.close_and_sync()?;
        observer(EpochJournalCutV1::AfterSyncBeforeReadback)?;
        self.fresh_read_v1(next)
    }
    fn require_namespace(&self) -> Result<()> {
        Ok(self.physical.require_namespace()?)
    }
    fn close_and_sync(&mut self) -> Result<()> {
        Ok(self.physical.close_and_sync()?)
    }
    fn read_head(
        &self,
        c: &Connection,
        expected: EpochSafetyHeadPinV1,
    ) -> Result<ConfirmedEpochSafetyHeadV1> {
        self.physical.check_schema(c)?;
        // Query scalar lengths before allocating untrusted persistent blobs.
        let sizes:(i64,i64)=c.query_row("SELECT length(source_record),length(source_transition) FROM epoch_metadata WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if sizes.0 <= 0
            || sizes.0 as u64
                > self
                    .profile
                    .source_context()?
                    .limits()
                    .maximum_record_bytes() as u64
            || sizes.1 <= 0
            || sizes.1 as usize > MAX_CONTEXT
        {
            return invalid("source blob bounds");
        }
        let m=c.query_row("SELECT journal,profile,source_journal,source_chain,source_record,source_transition,origin,first_revision FROM epoch_metadata WHERE singleton=1",[],|r|Ok(Metadata{journal:r.get(0)?,profile:r.get(1)?,source_journal:r.get(2)?,source_chain:r.get(3)?,source_record:r.get(4)?,source_transition:r.get(5)?,origin:r.get(6)?,first_revision:r.get(7)?}))?;
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
        let source = decode_old_epoch_boundary_safety_record_v1_exact(
            &m.source_record,
            &self.profile.source_context()?,
        )?;
        let source_recovery = Core::prepare_old_epoch_terminal_recovery_v1(
            &source,
            &self.profile.source_context()?,
            source.record_checksum(),
            self.profile.source_profile.owner_generation_v1(),
        )?;
        let expected_initial =
            source_recovery.prepare_epoch_activation_v1(&self.profile.context()?)?;
        let source_transition = decode_transition_context_v0_exact(&m.source_transition)?;
        validate_transition_context_against_state_v0(&source_transition, source.state())?;
        if source.state().revision().checked_add(1) != Some(m.first_revision) {
            return invalid("migration origin revision");
        }
        let head: (u64, [u8; 32]) = c.query_row(
            "SELECT revision,chain FROM epoch_head WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if head != (expected.revision, expected.chain_checksum) || head.0 < m.first_revision {
            return invalid("active head differs from independently expected cut");
        }
        let count: i64 = c.query_row("SELECT count(*) FROM epoch_records", [], |r| r.get(0))?;
        if count != if head.0 == m.first_revision { 1 } else { 2 } {
            return invalid("retained record count");
        }
        let mut s=c.prepare("SELECT revision,predecessor,chain,length(record),length(transition) FROM epoch_records ORDER BY revision")?;
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
                "SELECT record,transition FROM epoch_records WHERE revision=?1",
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
            let record =
                decode_epoch_safety_record_v1_exact(&record_bytes, &self.profile.context()?)?;
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
                if record.state() != expected_initial.state()
                    || transition != SafetyTransitionContextV0::Ordinary
                {
                    return invalid("initial epoch record differs from exact strict activation");
                }
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
                result = Some(ConfirmedEpochSafetyHeadV1 {
                    record: Box::new(record.clone()),
                    transition,
                    pin: expected,
                    context_ref: self.profile.context_ref_v1()?,
                    generation: self.profile.generation,
                    origin: m.origin,
                    source: EpochSafetyMigrationSourceV1 {
                        pin: OldEpochSafetyHeadPinV1 {
                            journal_id: m.source_journal,
                            revision: source.state().revision(),
                            chain_checksum: m.source_chain,
                        },
                        record_checksum: source.record_checksum(),
                        context_ref: self.profile.source_profile.context_ref_v1()?,
                        profile_ref: self.profile.source_profile.profile_ref_v1(),
                        initial_revision: m.first_revision,
                    },
                    owner: Arc::clone(&self.owner),
                });
            }
            previous = Some((record, chain));
        }
        result.ok_or(EpochJournalErrorV1::Invalid("missing head record"))
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
    profile: &EpochSafetyJournalProfileV1,
    journal: [u8; 32],
    source_journal: [u8; 32],
    source_chain: [u8; 32],
    record: &[u8],
    context: &[u8],
) -> [u8; 32] {
    digest(
        b"trnm.journal9.epoch.origin.v1",
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
        b"trnm.journal9.epoch.chain.v1",
        &[&origin, &previous, &revision.to_be_bytes(), record, context],
    )
}
pub(crate) fn validate_request_manifest(
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
