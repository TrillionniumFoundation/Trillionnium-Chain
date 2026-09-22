//! Read-only Journal11 provenance capture. This is not settled-source authority.
use super::*;

/// Exact comparison facts from two strict reads of one physical Journal11 owner.
/// A pending Safety state is permitted for diagnostics. This carrier cannot
/// prepare a successor, restore a driver, acknowledge persistence, or sign.
/// Original codec2 bytes and their canonical physical split remain intact.
///
/// ```compile_fail
/// use trnm_consensus_safety_store::ConfirmedEpochSuccessorSourceV3;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedEpochSuccessorSourceV3>();
/// ```
/// ```compile_fail
/// use trnm_consensus_safety_store::ConfirmedEpochSuccessorSourceV3;
/// fn activate(source: ConfirmedEpochSuccessorSourceV3) {
///     source.into_candidate_host_pending_v2();
/// }
/// ```
#[must_use]
pub struct ConfirmedEpochSuccessorSourceV3 {
    head: ConfirmedEpochSafetyHeadV3,
    profile_ref: [u8; 32],
    path: PathBuf,
    parts: EpochSafetyRecordPartsV2,
    transition_bytes: Vec<u8>,
}

impl ConfirmedEpochSuccessorSourceV3 {
    pub const fn physical_schema_version_v3(&self) -> u64 {
        11
    }
    pub fn state_v3(&self) -> &SafetyState {
        self.head.state_v3()
    }
    pub fn pin_v3(&self) -> EpochSafetyHeadPinV3 {
        self.head.pin_v3()
    }
    pub const fn profile_ref_v3(&self) -> [u8; 32] {
        self.profile_ref
    }
    pub const fn context_ref_v3(&self) -> [u8; 32] {
        self.head.context_ref_v3()
    }
    pub const fn owner_generation_v3(&self) -> u64 {
        self.head.owner_generation_v3()
    }
    pub fn state_record_checksum_v3(&self) -> [u8; 32] {
        self.head.state_record_checksum_v3()
    }
    pub const fn origin_ref_v3(&self) -> [u8; 32] {
        self.head.0.origin
    }
    pub const fn migration_source_v3(&self) -> &EpochSafetyMigrationSourceV2 {
        self.head.migration_source_v3()
    }
    pub fn record_bytes_v3(&self) -> &[u8] {
        self.parts.record_bytes()
    }
    pub fn before_provenance_v3(&self) -> &[u8] {
        self.parts.before_provenance()
    }
    pub fn provenance_v3(&self) -> &[u8] {
        self.parts.provenance()
    }
    pub fn after_provenance_v3(&self) -> &[u8] {
        self.parts.after_provenance()
    }
    pub fn transition_bytes_v3(&self) -> &[u8] {
        &self.transition_bytes
    }
    pub const fn transition_context_v3(&self) -> &SafetyTransitionContextV0 {
        self.head.transition_context_v3()
    }
    /// Recheck the same live owner and exact namespace, including a new strict
    /// read. Equal database bytes under a different owner are insufficient.
    pub fn belongs_to_store_at_path_v3(
        &self,
        store: &SqliteEpochSafetyJournalV3,
        path: &Path,
    ) -> bool {
        self.path == path
            && store.path_v3() == path
            && store.0.profile.storage == RecordStorageV3::PrefixOnce
            && store.0.profile.profile_ref_v2() == self.profile_ref
            && Arc::ptr_eq(&self.head.0.owner, &store.0.owner)
            && store
                .fresh_read_v3(self.pin_v3())
                .is_ok_and(|fresh| same_head(&self.head, &fresh))
    }
}

impl SqliteEpochSafetyJournalV3 {
    /// Capture original source bytes without mutating or binding the owner.
    /// This does not establish a settled outgoing checkpoint; no Journal11
    /// successor writer or progressed driver recovery is enabled by capture.
    pub fn capture_successor_source_v3(
        &self,
        expected: EpochSafetyHeadPinV3,
    ) -> ResultV3<ConfirmedEpochSuccessorSourceV3> {
        self.capture_source_inner(expected, || {})
    }

    /// Deterministic mutation hook for the two-read regression only.
    #[cfg(feature = "test-fixtures")]
    #[doc(hidden)]
    pub fn capture_successor_source_with_observer_v3(
        &self,
        expected: EpochSafetyHeadPinV3,
        after_first_read: impl FnOnce(),
    ) -> ResultV3<ConfirmedEpochSuccessorSourceV3> {
        self.capture_source_inner(expected, after_first_read)
    }

    #[inline(never)]
    fn capture_source_inner(
        &self,
        expected: EpochSafetyHeadPinV3,
        after_first_read: impl FnOnce(),
    ) -> ResultV3<ConfirmedEpochSuccessorSourceV3> {
        if self.0.profile.storage != RecordStorageV3::PrefixOnce {
            return Err(EpochJournalErrorV2::Invalid("capture requires Journal11").into());
        }
        let (head, recovery) = self.prepare_recovery_v3(expected)?;
        if head.state_v3() != recovery.state() {
            return Err(EpochJournalErrorV2::Invalid("capture recovery state mismatch").into());
        }
        drop(recovery);
        let context = self.0.profile.context()?;
        let parts = encode_epoch_safety_record_parts_v2(head.state_v3(), &context)
            .map_err(EpochJournalErrorV2::from)?;
        // read_head already compared these canonical ranges with every actual
        // stored range. Encoding therefore preserves the original full bytes;
        // it cannot adopt a relocated physical boundary or alternate prefix.
        if parts.record_bytes().len() > context.limits().maximum_record_bytes()
            || parts.record_bytes().last_chunk::<32>() != Some(&head.state_record_checksum_v3())
            || epoch_safety_record_context_ref_v2(&context).map_err(EpochJournalErrorV2::from)?
                != head.context_ref_v3()
        {
            return Err(EpochJournalErrorV2::Invalid("capture original record mismatch").into());
        }
        drop(context);
        let transition_bytes = encode_transition_context_v0(head.transition_context_v3())
            .map_err(EpochJournalErrorV2::from)?;
        if transition_bytes.len() > MAX_CONTEXT {
            return Err(EpochJournalErrorV2::Invalid("capture transition bound").into());
        }
        after_first_read();
        let fresh = self.fresh_read_v3(expected)?;
        if !same_head(&head, &fresh) {
            return Err(
                EpochJournalErrorV2::Invalid("capture source changed between reads").into(),
            );
        }
        self.0
            .physical
            .require_namespace()
            .map_err(EpochJournalErrorV2::from)?;
        Ok(ConfirmedEpochSuccessorSourceV3 {
            head,
            profile_ref: self.0.profile.profile_ref_v2(),
            path: self.path_v3().to_path_buf(),
            parts,
            transition_bytes,
        })
    }
}

fn same_head(left: &ConfirmedEpochSafetyHeadV3, right: &ConfirmedEpochSafetyHeadV3) -> bool {
    left.pin_v3() == right.pin_v3()
        && left.state_v3() == right.state_v3()
        && left.state_record_checksum_v3() == right.state_record_checksum_v3()
        && left.transition_context_v3() == right.transition_context_v3()
        && left.context_ref_v3() == right.context_ref_v3()
        && left.owner_generation_v3() == right.owner_generation_v3()
        && left.0.origin == right.0.origin
        && left.0.source == right.0.source
        && Arc::ptr_eq(&left.0.owner, &right.0.owner)
}
