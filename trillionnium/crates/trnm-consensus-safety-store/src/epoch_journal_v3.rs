//! Journal11's explicit prefix-once owner. The private engine is shared with
//! Journal10; no public conversion exposes a Journal10 owner or profile.
use super::*;

#[path = "epoch_journal_source_capture_v3.rs"]
mod source_capture;
pub use source_capture::ConfirmedEpochSuccessorSourceV3;

#[derive(Debug)]
pub struct EpochJournalErrorV3(EpochJournalErrorV2);
impl std::fmt::Display for EpochJournalErrorV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch journal11: {:?}", self.0)
    }
}
impl std::error::Error for EpochJournalErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
impl From<EpochJournalErrorV2> for EpochJournalErrorV3 {
    fn from(error: EpochJournalErrorV2) -> Self {
        Self(error)
    }
}
type ResultV3<T> = std::result::Result<T, EpochJournalErrorV3>;
pub type EpochJournalCutV3 = EpochJournalCutV2;
/// Only actual Journal8/9/10 owners are admitted; Journal11 is not a source in
/// this version. This alias carries no target owner or target profile.
pub type EpochSafetySourceOwnerV3<'a> = EpochSafetySourceOwnerV2<'a>;

#[derive(Debug, Clone)]
pub struct EpochSafetyJournalProfileV3(EpochSafetyJournalProfileV2);
impl EpochSafetyJournalProfileV3 {
    fn prefix_once(
        mut inner: EpochSafetyJournalProfileV2,
        context: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV3<Self> {
        inner.storage = RecordStorageV3::PrefixOnce;
        inner.binding = digest(
            inner.storage.profile_domain(),
            &[
                &[inner.source.kind.tag()],
                &inner.source.profile_ref,
                &inner.source.context()?.context_ref()?,
                &epoch_safety_record_context_ref_v2(context).map_err(EpochJournalErrorV2::from)?,
                &inner.generation.to_be_bytes(),
                &(inner.max_row as u64).to_be_bytes(),
                &inner.max_db.to_be_bytes(),
            ],
        );
        Ok(Self(inner))
    }
    pub fn from_journal8_v3(
        source: &OldEpochSafetyJournalProfileV1,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV3<Self> {
        Self::prefix_once(
            EpochSafetyJournalProfileV2::from_journal8_v2(source, target)?,
            target,
        )
    }
    pub fn from_journal9_v3(
        source: &EpochSafetyJournalProfileV1,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV3<Self> {
        Self::prefix_once(
            EpochSafetyJournalProfileV2::from_journal9_v2(source, target)?,
            target,
        )
    }
    pub fn from_journal10_v3(
        source: &EpochSafetyJournalProfileV2,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV3<Self> {
        Self::prefix_once(
            EpochSafetyJournalProfileV2::from_journal10_v2(source, target)?,
            target,
        )
    }
    pub const fn owner_generation_v3(&self) -> u64 {
        self.0.owner_generation_v2()
    }
    pub const fn profile_ref_v3(&self) -> [u8; 32] {
        self.0.profile_ref_v2()
    }
    pub fn context_ref_v3(&self) -> ResultV3<[u8; 32]> {
        Ok(self.0.context_ref_v2()?)
    }
    pub const fn source_kind_v3(&self) -> EpochSafetySourceKindV2 {
        self.0.source_kind_v2()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetyHeadPinV3 {
    pub journal_id: [u8; 32],
    pub revision: u64,
    pub chain_checksum: [u8; 32],
}
impl EpochSafetyHeadPinV3 {
    fn inner(self) -> EpochSafetyHeadPinV2 {
        EpochSafetyHeadPinV2 {
            journal_id: self.journal_id,
            revision: self.revision,
            chain_checksum: self.chain_checksum,
        }
    }
    fn from_inner(pin: EpochSafetyHeadPinV2) -> Self {
        Self {
            journal_id: pin.journal_id,
            revision: pin.revision,
            chain_checksum: pin.chain_checksum,
        }
    }
}
/// Non-Clone comparison facts. This object cannot acknowledge or sign Core work.
pub struct ConfirmedEpochSafetyHeadV3(ConfirmedEpochSafetyHeadV2);
impl ConfirmedEpochSafetyHeadV3 {
    pub fn state_v3(&self) -> &SafetyState {
        self.0.state_v2()
    }
    pub fn pin_v3(&self) -> EpochSafetyHeadPinV3 {
        EpochSafetyHeadPinV3::from_inner(self.0.pin_v2())
    }
    pub const fn revision_v3(&self) -> u64 {
        self.0.revision_v2()
    }
    pub fn state_record_checksum_v3(&self) -> [u8; 32] {
        self.0.state_record_checksum_v2()
    }
    pub const fn chain_checksum_v3(&self) -> [u8; 32] {
        self.0.chain_checksum_v2()
    }
    pub const fn journal_id_v3(&self) -> [u8; 32] {
        self.0.journal_id_v2()
    }
    pub const fn context_ref_v3(&self) -> [u8; 32] {
        self.0.context_ref_v2()
    }
    pub const fn owner_generation_v3(&self) -> u64 {
        self.0.owner_generation_v2()
    }
    pub const fn transition_context_v3(&self) -> &SafetyTransitionContextV0 {
        self.0.transition_context_v2()
    }
    pub const fn migration_source_v3(&self) -> &EpochSafetyMigrationSourceV2 {
        self.0.migration_source_v2()
    }
    pub fn into_unverified_record_v3(self) -> UnverifiedSafetyStateRecordV0 {
        self.0.into_unverified_record_v2()
    }
    pub fn belongs_to_store_at_path_v3(
        &self,
        store: &SqliteEpochSafetyJournalV3,
        path: &Path,
    ) -> bool {
        self.0.belongs_to_store_at_path_v2(&store.0, path)
    }
}
/// Explicit Journal11 owner; old Journal10 APIs cannot consume this value.
///
/// ```compile_fail
/// use trnm_consensus_safety_store::SqliteEpochSafetyJournalV3;
/// fn clone_owner<T: Clone>() {}
/// clone_owner::<SqliteEpochSafetyJournalV3>();
/// ```
/// ```compile_fail
/// use trnm_consensus_safety_store::{SqliteEpochSafetyJournalV3, EpochSafetySourceOwnerV2, EpochSafetyHeadPinV2};
/// fn downgrade(owner: &SqliteEpochSafetyJournalV3, pin: EpochSafetyHeadPinV2) {
///     let _ = EpochSafetySourceOwnerV2::Journal10(owner, pin);
/// }
/// ```
pub struct SqliteEpochSafetyJournalV3(SqliteEpochSafetyJournalV2);
impl SqliteEpochSafetyJournalV3 {
    pub fn initialize_from_source_v3(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV3,
        source: EpochSafetySourceOwnerV3<'_>,
        prepared: &PreparedEpochCoreActivationV2,
    ) -> ResultV3<(Self, ConfirmedEpochSafetyHeadV3)> {
        Self::initialize_with_observer_v3(path, profile, source, prepared, |_, _| Ok(()))
    }
    #[doc(hidden)]
    pub fn initialize_with_observer_v3(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV3,
        source: EpochSafetySourceOwnerV3<'_>,
        prepared: &PreparedEpochCoreActivationV2,
        mut observer: impl FnMut(EpochJournalCutV3, EpochSafetyHeadPinV3) -> ResultV3<()>,
    ) -> ResultV3<(Self, ConfirmedEpochSafetyHeadV3)> {
        let (owner, head) = SqliteEpochSafetyJournalV2::initialize_with_observer_v2(
            path,
            profile.0,
            source,
            prepared,
            |cut, pin| {
                observer(cut, EpochSafetyHeadPinV3::from_inner(pin)).map_err(|error| error.0)
            },
        )?;
        Ok((Self(owner), ConfirmedEpochSafetyHeadV3(head)))
    }
    pub fn open_existing_v3(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV3,
        expected: EpochSafetyHeadPinV3,
    ) -> ResultV3<Self> {
        Ok(Self(SqliteEpochSafetyJournalV2::open_existing_v2(
            path,
            profile.0,
            expected.inner(),
        )?))
    }
    pub fn path_v3(&self) -> &Path {
        self.0.path_v2()
    }
    pub fn fresh_read_v3(
        &self,
        expected: EpochSafetyHeadPinV3,
    ) -> ResultV3<ConfirmedEpochSafetyHeadV3> {
        Ok(ConfirmedEpochSafetyHeadV3(
            self.0.fresh_read_v2(expected.inner())?,
        ))
    }
    pub fn prepare_recovery_v3(
        &self,
        expected: EpochSafetyHeadPinV3,
    ) -> ResultV3<(ConfirmedEpochSafetyHeadV3, StrictEpochCoreRecoveryV2)> {
        let (head, recovery) = self.0.prepare_recovery_v2(expected.inner())?;
        Ok((ConfirmedEpochSafetyHeadV3(head), recovery))
    }
    /// Default-off trusted-host initial-only rebind. The driver is still pending
    /// its ACK; native/custody/external joins remain the host's responsibility.
    #[cfg(feature = "candidate-epoch-host-v2")]
    pub fn prepare_candidate_host_initial_recovery_v3(
        &mut self,
        expected: EpochSafetyHeadPinV3,
    ) -> ResultV3<(
        ConfirmedEpochSafetyHeadV3,
        trnm_consensus_core::PendingEpochHostDriverV2,
    )> {
        let (head, driver) = self
            .0
            .prepare_candidate_host_initial_recovery_v2(expected.inner())?;
        Ok((ConfirmedEpochSafetyHeadV3(head), driver))
    }
    pub fn confirm_exact_request_v3(
        &self,
        expected: EpochSafetyHeadPinV3,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> ResultV3<ConfirmedEpochSafetyHeadV3> {
        Ok(ConfirmedEpochSafetyHeadV3(
            self.0
                .confirm_exact_request_v2(expected.inner(), request, transition)?,
        ))
    }
    pub fn persist_exact_v3(
        &mut self,
        expected: EpochSafetyHeadPinV3,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> ResultV3<ConfirmedEpochSafetyHeadV3> {
        Ok(ConfirmedEpochSafetyHeadV3(self.0.persist_exact_v2(
            expected.inner(),
            request,
            transition,
        )?))
    }
    #[doc(hidden)]
    pub fn persist_with_pin_observer_v3(
        &mut self,
        expected: EpochSafetyHeadPinV3,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        mut observer: impl FnMut(EpochJournalCutV3, EpochSafetyHeadPinV3) -> ResultV3<()>,
    ) -> ResultV3<ConfirmedEpochSafetyHeadV3> {
        Ok(ConfirmedEpochSafetyHeadV3(
            self.0.persist_with_pin_observer_v2(
                expected.inner(),
                request,
                transition,
                |cut, pin| {
                    observer(cut, EpochSafetyHeadPinV3::from_inner(pin)).map_err(|error| error.0)
                },
            )?,
        ))
    }
}
