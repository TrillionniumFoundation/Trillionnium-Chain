//! Journal12's explicit successor-capable prefix-once owner. The private engine is shared with
//! Journal10; no public conversion exposes a Journal10 owner or profile.
use super::*;

#[derive(Debug)]
pub struct EpochJournalErrorV4(EpochJournalErrorV2);
impl std::fmt::Display for EpochJournalErrorV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch journal12: {:?}", self.0)
    }
}
impl std::error::Error for EpochJournalErrorV4 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
impl From<EpochJournalErrorV2> for EpochJournalErrorV4 {
    fn from(error: EpochJournalErrorV2) -> Self {
        Self(error)
    }
}
type ResultV4<T> = std::result::Result<T, EpochJournalErrorV4>;
pub type EpochJournalCutV4 = EpochJournalCutV2;
#[path = "epoch_journal_v4_source.rs"]
mod source;
pub use source::{
    EpochSafetyMigrationSourceV4, EpochSafetySourceKindV4, EpochSafetySourceOwnerV4,
    EpochSafetySourcePinV4,
};

#[derive(Debug, Clone)]
pub struct EpochSafetyJournalProfileV4(EpochSafetyJournalProfileV2);
impl EpochSafetyJournalProfileV4 {
    fn prefix_once(
        mut inner: EpochSafetyJournalProfileV2,
        context: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV4<Self> {
        inner.storage = RecordStorageV3::SuccessorPrefixOnce;
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
    pub fn from_journal8_v4(
        source: &OldEpochSafetyJournalProfileV1,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV4<Self> {
        Self::prefix_once(
            EpochSafetyJournalProfileV2::from_journal8_v2(source, target)?,
            target,
        )
    }
    pub fn from_journal9_v4(
        source: &EpochSafetyJournalProfileV1,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV4<Self> {
        Self::prefix_once(
            EpochSafetyJournalProfileV2::from_journal9_v2(source, target)?,
            target,
        )
    }
    pub fn from_journal10_v4(
        source: &EpochSafetyJournalProfileV2,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV4<Self> {
        Self::prefix_once(
            EpochSafetyJournalProfileV2::from_journal10_v2(source, target)?,
            target,
        )
    }
    pub const fn owner_generation_v4(&self) -> u64 {
        self.0.owner_generation_v2()
    }
    pub const fn profile_ref_v4(&self) -> [u8; 32] {
        self.0.profile_ref_v2()
    }
    pub fn context_ref_v4(&self) -> ResultV4<[u8; 32]> {
        Ok(self.0.context_ref_v2()?)
    }
    pub const fn source_kind_v4(&self) -> EpochSafetySourceKindV4 {
        EpochSafetySourceKindV4::from_physical(self.0.source.kind)
    }
    pub fn from_journal11_v4(
        source: &v3::EpochSafetyJournalProfileV3,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV4<Self> {
        Self::from_prefix_source(&source.0, PhysicalSourceKindV4::Journal11, target)
    }
    pub fn from_journal12_v4(
        source: &Self,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV4<Self> {
        Self::from_prefix_source(&source.0, PhysicalSourceKindV4::Journal12, target)
    }
    fn from_prefix_source(
        source: &EpochSafetyJournalProfileV2,
        kind: PhysicalSourceKindV4,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> ResultV4<Self> {
        let expected = match kind {
            PhysicalSourceKindV4::Journal11 => RecordStorageV3::PrefixOnce,
            PhysicalSourceKindV4::Journal12 => RecordStorageV3::SuccessorPrefixOnce,
            _ => {
                return Err(
                    EpochJournalErrorV2::Invalid("expected prefix-once physical source").into(),
                )
            }
        };
        if source.storage != expected {
            return Err(EpochJournalErrorV2::Invalid("source physical profile differs").into());
        }
        Ok(Self(EpochSafetyJournalProfileV2::with_storage(
            SourceDescriptorV2 {
                kind,
                config: source.config.clone(),
                limits: source.limits,
                generation: source.generation,
                profile_ref: source.binding,
                verifier_ref: [0; 32],
                epoch: Some(source.epoch.clone()),
            },
            target,
            RecordStorageV3::SuccessorPrefixOnce,
        )?))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSafetyHeadPinV4 {
    pub journal_id: [u8; 32],
    pub revision: u64,
    pub chain_checksum: [u8; 32],
}
impl EpochSafetyHeadPinV4 {
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
pub struct ConfirmedEpochSafetyHeadV4(ConfirmedEpochSafetyHeadV2);
impl ConfirmedEpochSafetyHeadV4 {
    pub fn state_v4(&self) -> &SafetyState {
        self.0.state_v2()
    }
    pub fn pin_v4(&self) -> EpochSafetyHeadPinV4 {
        EpochSafetyHeadPinV4::from_inner(self.0.pin_v2())
    }
    pub const fn revision_v4(&self) -> u64 {
        self.0.revision_v2()
    }
    pub fn state_record_checksum_v4(&self) -> [u8; 32] {
        self.0.state_record_checksum_v2()
    }
    pub const fn chain_checksum_v4(&self) -> [u8; 32] {
        self.0.chain_checksum_v2()
    }
    pub const fn journal_id_v4(&self) -> [u8; 32] {
        self.0.journal_id_v2()
    }
    pub const fn context_ref_v4(&self) -> [u8; 32] {
        self.0.context_ref_v2()
    }
    pub const fn owner_generation_v4(&self) -> u64 {
        self.0.owner_generation_v2()
    }
    pub const fn transition_context_v4(&self) -> &SafetyTransitionContextV0 {
        self.0.transition_context_v2()
    }
    pub const fn migration_source_v4(&self) -> EpochSafetyMigrationSourceV4 {
        EpochSafetyMigrationSourceV4::from_facts(self.0.source)
    }
    pub fn into_unverified_record_v4(self) -> UnverifiedSafetyStateRecordV0 {
        self.0.into_unverified_record_v2()
    }
    pub fn belongs_to_store_at_path_v4(
        &self,
        store: &SqliteEpochSafetyJournalV4,
        path: &Path,
    ) -> bool {
        self.0.belongs_to_store_at_path_v2(&store.0, path)
    }
}
/// Explicit Journal12 owner; old Journal10 APIs cannot consume this value.
///
/// ```compile_fail
/// use trnm_consensus_safety_store::SqliteEpochSafetyJournalV4;
/// fn clone_owner<T: Clone>() {}
/// clone_owner::<SqliteEpochSafetyJournalV4>();
/// ```
/// ```compile_fail
/// use trnm_consensus_safety_store::{SqliteEpochSafetyJournalV4, EpochSafetySourceOwnerV2, EpochSafetyHeadPinV2};
/// fn downgrade(owner: &SqliteEpochSafetyJournalV4, pin: EpochSafetyHeadPinV2) {
///     let _ = EpochSafetySourceOwnerV2::Journal10(owner, pin);
/// }
/// ```
pub struct SqliteEpochSafetyJournalV4(SqliteEpochSafetyJournalV2);
impl SqliteEpochSafetyJournalV4 {
    pub fn initialize_from_source_v4(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV4,
        source: EpochSafetySourceOwnerV4<'_>,
        prepared: &PreparedEpochCoreActivationV2,
    ) -> ResultV4<(Self, ConfirmedEpochSafetyHeadV4)> {
        Self::initialize_with_observer_v4(path, profile, source, prepared, |_, _| Ok(()))
    }
    #[doc(hidden)]
    pub fn initialize_with_observer_v4(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV4,
        source: EpochSafetySourceOwnerV4<'_>,
        prepared: &PreparedEpochCoreActivationV2,
        mut observer: impl FnMut(EpochJournalCutV4, EpochSafetyHeadPinV4) -> ResultV4<()>,
    ) -> ResultV4<(Self, ConfirmedEpochSafetyHeadV4)> {
        let (owner, head) = SqliteEpochSafetyJournalV2::initialize_from_reader_v4(
            path,
            profile.0,
            SourceReaderV4::Successor(source),
            prepared,
            None,
            |cut, pin| {
                observer(cut, EpochSafetyHeadPinV4::from_inner(pin)).map_err(|error| error.0)
            },
        )?;
        Ok((Self(owner), ConfirmedEpochSafetyHeadV4(head)))
    }
    /// Retry only an independently selected, possibly committed initial target.
    /// This never adopts the database's own head or creates/replaces a namespace.
    /// The caller retains the original consuming Core preparation and target pin;
    /// all source/target joins and fsync/readback are repeated before binding it.
    pub fn reopen_initial_from_source_v4(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV4,
        expected: EpochSafetyHeadPinV4,
        source: EpochSafetySourceOwnerV4<'_>,
        prepared: &PreparedEpochCoreActivationV2,
    ) -> ResultV4<(Self, ConfirmedEpochSafetyHeadV4)> {
        let (owner, head) = SqliteEpochSafetyJournalV2::initialize_from_reader_v4(
            path,
            profile.0,
            SourceReaderV4::Successor(source),
            prepared,
            Some(expected.inner()),
            |_, _| Ok(()),
        )?;
        Ok((Self(owner), ConfirmedEpochSafetyHeadV4(head)))
    }
    pub fn open_existing_v4(
        path: impl AsRef<Path>,
        profile: EpochSafetyJournalProfileV4,
        expected: EpochSafetyHeadPinV4,
    ) -> ResultV4<Self> {
        Ok(Self(SqliteEpochSafetyJournalV2::open_existing_v2(
            path,
            profile.0,
            expected.inner(),
        )?))
    }
    pub fn path_v4(&self) -> &Path {
        self.0.path_v2()
    }
    pub fn fresh_read_v4(
        &self,
        expected: EpochSafetyHeadPinV4,
    ) -> ResultV4<ConfirmedEpochSafetyHeadV4> {
        Ok(ConfirmedEpochSafetyHeadV4(
            self.0.fresh_read_v2(expected.inner())?,
        ))
    }
    pub fn prepare_recovery_v4(
        &self,
        expected: EpochSafetyHeadPinV4,
    ) -> ResultV4<(ConfirmedEpochSafetyHeadV4, StrictEpochCoreRecoveryV2)> {
        let (head, recovery) = self.0.prepare_recovery_v2(expected.inner())?;
        Ok((ConfirmedEpochSafetyHeadV4(head), recovery))
    }
    /// Default-off trusted-host initial-only rebind. The driver is still pending
    /// its ACK; native/custody/external joins remain the host's responsibility.
    #[cfg(feature = "candidate-epoch-host-v2")]
    pub fn prepare_candidate_host_initial_recovery_v4(
        &mut self,
        expected: EpochSafetyHeadPinV4,
    ) -> ResultV4<(
        ConfirmedEpochSafetyHeadV4,
        trnm_consensus_core::PendingEpochHostDriverV2,
    )> {
        let (head, driver) = self
            .0
            .prepare_candidate_host_initial_recovery_v2(expected.inner())?;
        Ok((ConfirmedEpochSafetyHeadV4(head), driver))
    }
    pub fn confirm_exact_request_v4(
        &self,
        expected: EpochSafetyHeadPinV4,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> ResultV4<ConfirmedEpochSafetyHeadV4> {
        Ok(ConfirmedEpochSafetyHeadV4(
            self.0
                .confirm_exact_request_v2(expected.inner(), request, transition)?,
        ))
    }
    pub fn persist_exact_v4(
        &mut self,
        expected: EpochSafetyHeadPinV4,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
    ) -> ResultV4<ConfirmedEpochSafetyHeadV4> {
        Ok(ConfirmedEpochSafetyHeadV4(self.0.persist_exact_v2(
            expected.inner(),
            request,
            transition,
        )?))
    }
    #[doc(hidden)]
    pub fn persist_with_pin_observer_v4(
        &mut self,
        expected: EpochSafetyHeadPinV4,
        request: &SafetyStatePersistenceV0,
        transition: &SafetyTransitionContextV0,
        mut observer: impl FnMut(EpochJournalCutV4, EpochSafetyHeadPinV4) -> ResultV4<()>,
    ) -> ResultV4<ConfirmedEpochSafetyHeadV4> {
        Ok(ConfirmedEpochSafetyHeadV4(
            self.0.persist_with_pin_observer_v2(
                expected.inner(),
                request,
                transition,
                |cut, pin| {
                    observer(cut, EpochSafetyHeadPinV4::from_inner(pin)).map_err(|error| error.0)
                },
            )?,
        ))
    }
}
