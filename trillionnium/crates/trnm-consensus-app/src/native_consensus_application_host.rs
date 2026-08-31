//! Opaque existing-only ApplicationStore owner for native consensus recovery.
//!
//! This module exposes the tag-3 exact-readback boundary, current application
//! watermark reconciliation, and one atomic dual-authority install. It does
//! not drive validation, apply a new queue front, remint Valid work, or make
//! the production node reachable.

use std::{fmt, path::Path, sync::Arc};

use trnm_consensus_core::{
    ApplicationFinalizationApplyReadbackV0, ApplicationFinalizationReceiptV0, Core, CoreConfig,
    CoreIssuedApplicationFinalizationApplyAuthorityV0, CoreIssuedApplicationFinalizationPermitV0,
    CoreIssuedApplicationSealAuthorityV0, Effect, NativeFinalizationAppliedRecoveryAttestationV0,
    NativeFinalizationAppliedRecoveryChallengeV0, NativeFinalizationAppliedRecoveryReconcilerV0,
    NativeFinalizationAppliedRecoveryTransitionV0, NativeValidCompletionRecoveryAttestationV0,
    NativeValidCompletionRecoveryChallengeV0, NativeValidCompletionRecoveryReconcilerV0,
    NativeValidPostAckActionV0, PayloadValidationRecoveryChallengeV0,
    PayloadValidationRecoveryDecisionV0, PayloadValidationRecoveryReconcilerV0, SafetyState,
    SafetyStatePersistenceV0, StateSyncAnchorRecoveryChallengeV0, StateSyncAnchorSuccessorPhaseV0,
    StateSyncAnchorSuccessorReplayV0,
};
use trnm_consensus_safety_store::{
    ConfirmedNativeDeterministicInvalidHeadV0, ConfirmedNativeFinalizationAppliedHeadV0,
    ConfirmedNativeValidHeadV0, ConfirmedSafetyNodeCheckpointFactsV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_types::{BlockId, SignatureVerifier};

use crate::{
    native_payload_validation::{
        prepare_empty_synced_state_sync_anchor_successor_valid_v0,
        prepare_ordinary_single_runtime_proposal_valid_v0, NativeValidationHostV0,
    },
    signer_policy_commitment,
    store::{
        native_validation_host_config_ref_from_application_v0,
        native_validation_recovery::{
            NativeValidationRecoveredAckedFactsV0, NativeValidationRecoveredInvalidCallbackFactsV0,
            NativeValidationRecoveredInvalidStateV0, NativeValidationRecoveryCoordinatorV0,
            NativeValidationRecoveryNamespacePinV0, NativeValidationRecoveryOpenFailureV0,
            NativeValidationRecoveryReconcileFailureV0,
            NativeValidationRecoveryTransitionFailureV0,
        },
        prepare_native_application_h1_projection_expectation_v0, ApplicationStore,
        NativeApplicationFinalizationApplyFailureCauseV0,
        NativeApplicationFinalizationApplyFailureCauseV0::*,
        NativeApplicationH1ProjectionExpectationV0,
        NativeCoreApplicationAuthoritiesInstallFailureV0,
        NativeCoreApplicationAuthoritiesInstallRejectionV0,
        NativeValidCompletionApplicationSourceV0, NativeValidationValidSealDecisionV0,
        ReconciledNativeApplicationAppliedKindV0, ReconciledNativeApplicationAppliedV0,
        ReconciledNativeApplicationNodeCheckpointFactsV0,
        ReconciledNativeApplicationStateSyncAnchorSuccessorsV0,
        ReconciledNativeApplicationStateSyncAnchorV0, ReconciledNativeApplicationValidCompletionV0,
    },
    ConsensusAppConfig,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeConsensusApplicationHostErrorV0 {
    InvalidConfig,
    StatePathRequired,
    StatePathNotAbsolute,
    InvalidSafetyProvenance,
    NamespaceUnavailable,
    DatabaseUnavailable,
    HostResourceUnavailable,
    AuthenticatedGenesisApplicationActivationUnavailable,
    PersistedStateMismatch,
    SafetyStateMismatch,
    CoreRecoveryMismatch,
    ForeignCapability,
    CoreAuthorityMismatch,
    CoreAuthorityUnavailable,
    CoreAuthoritiesAlreadyInstalled,
    StateSyncAnchorSuccessorUnavailable,
    NativeValidCompletionRecoveryUnavailable,
    OrdinarySingleRuntimeValidationUnavailable,
    OrdinarySingleRuntimeValidationInvariant,
}

impl fmt::Display for NativeConsensusApplicationHostErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "native consensus application configuration is invalid",
            Self::StatePathRequired => {
                "native consensus application recovery requires an existing state path"
            }
            Self::StatePathNotAbsolute => {
                "native consensus application recovery state path must be absolute"
            }
            Self::InvalidSafetyProvenance => {
                "native consensus application SafetyStore provenance is invalid or foreign"
            }
            Self::NamespaceUnavailable => {
                "native consensus application namespace is unavailable or not exclusive"
            }
            Self::DatabaseUnavailable => "native consensus application database is unavailable",
            Self::HostResourceUnavailable => {
                "native consensus application host resources are temporarily unavailable"
            }
            Self::AuthenticatedGenesisApplicationActivationUnavailable => {
                "authenticated-genesis application requires its dedicated inert bootstrap owner"
            }
            Self::PersistedStateMismatch => {
                "native consensus application persisted state is not exactly recoverable"
            }
            Self::SafetyStateMismatch => {
                "native consensus application facts differ from the authenticated SafetyStore head"
            }
            Self::CoreRecoveryMismatch => {
                "native consensus application facts differ from the Core recovery challenge"
            }
            Self::ForeignCapability => {
                "native consensus application capability belongs to another host lifetime"
            }
            Self::CoreAuthorityMismatch => {
                "native consensus application authorities do not belong to one exact Core"
            }
            Self::CoreAuthorityUnavailable => {
                "native consensus application authority slots are unavailable"
            }
            Self::CoreAuthoritiesAlreadyInstalled => {
                "native consensus application authorities are already installed"
            }
            Self::StateSyncAnchorSuccessorUnavailable => {
                "native consensus application anchored-successor validation is unavailable"
            }
            Self::NativeValidCompletionRecoveryUnavailable => {
                "native consensus application stable native-Valid completion is unavailable"
            }
            Self::OrdinarySingleRuntimeValidationUnavailable => {
                "ordinary single-runtime proposal validation is unavailable"
            }
            Self::OrdinarySingleRuntimeValidationInvariant => {
                "ordinary single-runtime proposal validation violated its closed effect contract"
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeConsensusApplicationAppliedKindV0 {
    TrustedBase,
    AppliedOverlay,
}

/// Copy-only facts confirming that one authenticated SafetyState application
/// watermark equals the complete current ApplicationStore closure.
///
/// This value deliberately carries no host/store handle and cannot recreate a
/// callback, finalization permit, receipt, or recovery attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedNativeApplicationAppliedFactsV0 {
    kind: NativeConsensusApplicationAppliedKindV0,
    block_id: BlockId,
    height: u64,
    state_root: [u8; 32],
    view: u64,
    timestamp_ms: u64,
    overlay_checksum: Option<[u8; 32]>,
    proof_id: Option<[u8; 32]>,
    receipt_count: u64,
    matched_valid_completion_count: u64,
}

impl ConfirmedNativeApplicationAppliedFactsV0 {
    pub const fn kind(self) -> NativeConsensusApplicationAppliedKindV0 {
        self.kind
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn height(self) -> u64 {
        self.height
    }

    pub const fn state_root(self) -> [u8; 32] {
        self.state_root
    }

    pub const fn view(self) -> u64 {
        self.view
    }

    pub const fn timestamp_ms(self) -> u64 {
        self.timestamp_ms
    }

    pub const fn overlay_checksum(self) -> Option<[u8; 32]> {
        self.overlay_checksum
    }

    pub const fn proof_id(self) -> Option<[u8; 32]> {
        self.proof_id
    }

    pub const fn receipt_count(self) -> u64 {
        self.receipt_count
    }

    pub const fn matched_valid_completion_count(self) -> u64 {
        self.matched_valid_completion_count
    }
}

impl From<ReconciledNativeApplicationAppliedV0> for ConfirmedNativeApplicationAppliedFactsV0 {
    fn from(value: ReconciledNativeApplicationAppliedV0) -> Self {
        Self {
            kind: match value.kind {
                ReconciledNativeApplicationAppliedKindV0::TrustedBase => {
                    NativeConsensusApplicationAppliedKindV0::TrustedBase
                }
                ReconciledNativeApplicationAppliedKindV0::AppliedOverlay => {
                    NativeConsensusApplicationAppliedKindV0::AppliedOverlay
                }
            },
            block_id: value.block_id,
            height: value.height,
            state_root: value.state_root,
            view: value.view,
            timestamp_ms: value.timestamp_ms,
            overlay_checksum: value.overlay_checksum,
            proof_id: value.proof_id,
            receipt_count: value.receipt_count,
            matched_valid_completion_count: value.matched_valid_completion_count,
        }
    }
}

/// One-shot, authority-free commitment to the complete fixed-snapshot
/// ApplicationStore recovery closure joined to one authenticated SafetyState.
///
/// Fields are private, the value has no raw constructor or serialization
/// surface, and it is deliberately neither `Clone` nor `Copy`.  It can be
/// inspected only as inert comparison material for a future independent node
/// checkpoint CAS; it cannot open the store or authorize application work.
///
/// ```compile_fail
/// use trnm_consensus_app::ConfirmedNativeApplicationNodeCheckpointFactsV0;
/// fn assert_clone<T: Clone>() {}
/// fn checkpoint_facts_are_linear() {
///     assert_clone::<ConfirmedNativeApplicationNodeCheckpointFactsV0>();
/// }
/// ```
///
/// ```compile_fail
/// use serde::Serialize;
/// use trnm_consensus_app::ConfirmedNativeApplicationNodeCheckpointFactsV0;
/// fn assert_serialize<T: Serialize>() {}
/// fn checkpoint_facts_are_not_durable() {
///     assert_serialize::<ConfirmedNativeApplicationNodeCheckpointFactsV0>();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the confirmed ApplicationStore closure must be joined to Safety and signer facts"]
pub struct ConfirmedNativeApplicationNodeCheckpointFactsV0 {
    applied: ConfirmedNativeApplicationAppliedFactsV0,
    host_config_ref: [u8; 32],
    projection_profile_ref: [u8; 32],
    safety_journal_id: [u8; 32],
    safety_verifier_profile_ref: [u8; 32],
    safety_revision: u64,
    safety_state_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    safety_binding_manifest_checksum: [u8; 32],
    committed_head_row_checksum: [u8; 32],
    recovery_closure_checksum: [u8; 32],
    host_affinity: Arc<()>,
}

impl ConfirmedNativeApplicationNodeCheckpointFactsV0 {
    pub const fn applied_facts_v0(&self) -> ConfirmedNativeApplicationAppliedFactsV0 {
        self.applied
    }

    pub const fn host_config_ref_v0(&self) -> [u8; 32] {
        self.host_config_ref
    }

    /// Exact comparison against the validated application configuration
    /// preimage used to open this store. This grants no host or persistence
    /// authority and does not trust the checkpoint capability's detached
    /// config reference by itself.
    pub fn matches_application_config_v0(&self, application: &ConsensusAppConfig) -> bool {
        application.validate().is_ok()
            && application.poco_authority.is_none()
            && self.host_config_ref
                == native_validation_host_config_ref_from_application_v0(application)
    }

    pub const fn projection_profile_ref_v0(&self) -> [u8; 32] {
        self.projection_profile_ref
    }

    pub const fn safety_journal_id_v0(&self) -> [u8; 32] {
        self.safety_journal_id
    }

    pub const fn safety_verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.safety_verifier_profile_ref
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_state_record_checksum_v0(&self) -> [u8; 32] {
        self.safety_state_record_checksum
    }

    pub const fn safety_chain_checksum_v0(&self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn safety_binding_manifest_checksum_v0(&self) -> [u8; 32] {
        self.safety_binding_manifest_checksum
    }

    pub const fn committed_head_row_checksum_v0(&self) -> [u8; 32] {
        self.committed_head_row_checksum
    }

    pub const fn recovery_closure_checksum_v0(&self) -> [u8; 32] {
        self.recovery_closure_checksum
    }

    pub const fn block_id_v0(&self) -> BlockId {
        self.applied.block_id
    }

    pub const fn height_v0(&self) -> u64 {
        self.applied.height
    }

    pub const fn state_root_v0(&self) -> [u8; 32] {
        self.applied.state_root
    }

    pub const fn view_v0(&self) -> u64 {
        self.applied.view
    }

    pub const fn timestamp_ms_v0(&self) -> u64 {
        self.applied.timestamp_ms
    }

    /// Confirms only process-lifetime affinity.  This does not consume the
    /// value or authorize checkpoint persistence.
    pub fn belongs_to_host_v0(&self, host: &NativeConsensusApplicationHostV0) -> bool {
        Arc::ptr_eq(&self.host_affinity, &host.affinity)
    }

    /// Confirms both process-local owner affinity and the exact canonical
    /// status path selected by the node process configuration.
    pub fn belongs_to_host_at_path_v0(
        &self,
        host: &NativeConsensusApplicationHostV0,
        expected_status_path: &Path,
    ) -> bool {
        self.belongs_to_host_v0(host)
            && host.store.status_path_v0() == expected_status_path
            && host.namespace_pin.validate_open_v0(&host.store).is_ok()
    }
}

/// Owner-preserving rejection from the facade's all-or-none Core authority
/// installation boundary.
#[must_use = "a rejected authority install retains both unique Core owners"]
pub struct NativeConsensusApplicationAuthoritiesInstallRejectionV0 {
    error: NativeConsensusApplicationHostErrorV0,
    seal: Box<CoreIssuedApplicationSealAuthorityV0>,
    finalization: Box<CoreIssuedApplicationFinalizationApplyAuthorityV0>,
}

impl fmt::Debug for NativeConsensusApplicationAuthoritiesInstallRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeConsensusApplicationAuthoritiesInstallRejectionV0")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl NativeConsensusApplicationAuthoritiesInstallRejectionV0 {
    fn new_v0(
        error: NativeConsensusApplicationHostErrorV0,
        seal: CoreIssuedApplicationSealAuthorityV0,
        finalization: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    ) -> Self {
        Self {
            error,
            seal: Box::new(seal),
            finalization: Box::new(finalization),
        }
    }

    pub const fn error(&self) -> NativeConsensusApplicationHostErrorV0 {
        self.error
    }

    pub fn into_parts(
        self,
    ) -> (
        NativeConsensusApplicationHostErrorV0,
        CoreIssuedApplicationSealAuthorityV0,
        CoreIssuedApplicationFinalizationApplyAuthorityV0,
    ) {
        (self.error, *self.seal, *self.finalization)
    }
}

/// Owner-preserving rejection from the candidate native application
/// finalization bridge.
///
/// The underlying `ApplicationStore` rejection is intentionally private to
/// this crate.  This facade carries its mapped host error together with the
/// exact, non-cloneable Core-issued queue-front permit so a trusted caller can
/// retry against the issuing Core or fail-stop without reminting/rebuilding a
/// permit from durable comparison data.
///
/// This is a candidate-only library boundary.  It does not wire the generic
/// node effect driver, process startup, or production consensus activation;
/// `production_candidate` and `production_consensus_activation` remain
/// `false`.
#[must_use = "a rejected finalization apply retains the sole Core-issued permit"]
pub struct NativeConsensusApplicationFinalizationApplyRejectionV0 {
    error: NativeConsensusApplicationHostErrorV0,
    permit: Box<CoreIssuedApplicationFinalizationPermitV0>,
}

impl fmt::Debug for NativeConsensusApplicationFinalizationApplyRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeConsensusApplicationFinalizationApplyRejectionV0")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl NativeConsensusApplicationFinalizationApplyRejectionV0 {
    fn new_v0(
        error: NativeConsensusApplicationHostErrorV0,
        permit: CoreIssuedApplicationFinalizationPermitV0,
    ) -> Self {
        Self {
            error,
            permit: Box::new(permit),
        }
    }

    /// Returns the mapped host-level cause without consuming the rejection or
    /// its linear permit.
    pub const fn error(&self) -> NativeConsensusApplicationHostErrorV0 {
        self.error
    }

    /// Consumes the rejection and returns the exact permit unchanged.
    pub fn into_permit(self) -> CoreIssuedApplicationFinalizationPermitV0 {
        *self.permit
    }

    /// Consumes the rejection and returns both the mapped cause and exact
    /// permit for explicit retry/fail-stop routing.
    pub fn into_parts(
        self,
    ) -> (
        NativeConsensusApplicationHostErrorV0,
        CoreIssuedApplicationFinalizationPermitV0,
    ) {
        (self.error, *self.permit)
    }
}

impl std::error::Error for NativeConsensusApplicationHostErrorV0 {}

/// Canonical, owned opening facts for the existing-only application host.
///
/// The full application configuration is retained as the signer-policy
/// preimage; callers cannot substitute only the detached hexadecimal database
/// binding. The SafetyStore journal/profile identities must match the pinned
/// application safety-binding manifest.
#[derive(Debug)]
pub struct NativeConsensusApplicationHostConfigV0 {
    application: ConsensusAppConfig,
    expected_safety_journal_id: [u8; 32],
    expected_safety_verifier_profile_ref: [u8; 32],
}

impl NativeConsensusApplicationHostConfigV0 {
    fn new(
        application: ConsensusAppConfig,
        expected_safety_journal_id: [u8; 32],
        expected_safety_verifier_profile_ref: [u8; 32],
    ) -> Result<Self, NativeConsensusApplicationHostErrorV0> {
        application
            .validate()
            .map_err(|_| NativeConsensusApplicationHostErrorV0::InvalidConfig)?;
        let state_path = application
            .state_path
            .as_deref()
            .ok_or(NativeConsensusApplicationHostErrorV0::StatePathRequired)?;
        if !state_path.is_absolute() {
            return Err(NativeConsensusApplicationHostErrorV0::StatePathNotAbsolute);
        }
        if expected_safety_journal_id == [0; 32] || expected_safety_verifier_profile_ref == [0; 32]
        {
            return Err(NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance);
        }
        Ok(Self {
            application,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        })
    }

    #[cfg(test)]
    pub(super) fn new_for_test_v0(
        application: ConsensusAppConfig,
        expected_safety_journal_id: [u8; 32],
        expected_safety_verifier_profile_ref: [u8; 32],
    ) -> Result<Self, NativeConsensusApplicationHostErrorV0> {
        Self::new(
            application,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        )
    }

    /// Constructs opening facts directly from the already-open authenticated
    /// SafetyStore owner, avoiding caller-selected detached provenance bytes.
    pub fn from_authenticated_safety_store_v0<V>(
        application: ConsensusAppConfig,
        safety_store: &trnm_consensus_safety_store::SqliteSafetyStateStoreV0<V>,
    ) -> Result<Self, NativeConsensusApplicationHostErrorV0>
    where
        V: trnm_consensus_types::SignatureVerifier,
    {
        Self::new(
            application,
            safety_store.journal_id_v0(),
            safety_store.verifier_profile_ref_v0(),
        )
    }
}

fn map_store_failure_v0(
    cause: NativeApplicationFinalizationApplyFailureCauseV0,
) -> NativeConsensusApplicationHostErrorV0 {
    match cause {
        NamespaceMismatch | AuthorityUnavailable | AuthorityMismatch | WriterUnavailable => {
            NativeConsensusApplicationHostErrorV0::NamespaceUnavailable
        }
        DatabaseUnavailable | CommitUncertain => {
            NativeConsensusApplicationHostErrorV0::DatabaseUnavailable
        }
        HostResourceUnavailable => NativeConsensusApplicationHostErrorV0::HostResourceUnavailable,
        PersistedStateMismatch => NativeConsensusApplicationHostErrorV0::PersistedStateMismatch,
        #[cfg(test)]
        Injected => NativeConsensusApplicationHostErrorV0::PersistedStateMismatch,
    }
}

/// Maps the store's apply-only failure taxonomy at the public host boundary.
///
/// The generic recovery mapper above intentionally keeps historical
/// readback failures coarse.  A live finalization apply has a stricter
/// authority distinction: a missing installed authority and a permit issued
/// by a different Core are different operator actions, while a writer lock
/// failure is a local resource failure.  Keep those distinctions visible to
/// callers without exposing the store-private cause type.
fn map_finalization_apply_failure_v0(
    cause: NativeApplicationFinalizationApplyFailureCauseV0,
) -> NativeConsensusApplicationHostErrorV0 {
    match cause {
        NamespaceMismatch => NativeConsensusApplicationHostErrorV0::NamespaceUnavailable,
        AuthorityUnavailable => NativeConsensusApplicationHostErrorV0::CoreAuthorityUnavailable,
        AuthorityMismatch => NativeConsensusApplicationHostErrorV0::CoreAuthorityMismatch,
        WriterUnavailable => NativeConsensusApplicationHostErrorV0::HostResourceUnavailable,
        DatabaseUnavailable | CommitUncertain => {
            NativeConsensusApplicationHostErrorV0::DatabaseUnavailable
        }
        HostResourceUnavailable => NativeConsensusApplicationHostErrorV0::HostResourceUnavailable,
        PersistedStateMismatch => NativeConsensusApplicationHostErrorV0::PersistedStateMismatch,
        #[cfg(test)]
        Injected => NativeConsensusApplicationHostErrorV0::PersistedStateMismatch,
    }
}

fn map_application_store_open_failure_v0(
    failure: crate::store::ApplicationStoreNamespaceOpenFailureV0,
) -> NativeConsensusApplicationHostErrorV0 {
    match failure {
        crate::store::ApplicationStoreNamespaceOpenFailureV0::
            AuthenticatedGenesisApplicationActivationUnavailable => {
                NativeConsensusApplicationHostErrorV0::
                    AuthenticatedGenesisApplicationActivationUnavailable
            }
        _ => NativeConsensusApplicationHostErrorV0::NamespaceUnavailable,
    }
}

fn map_recovery_open_failure_v0(
    cause: NativeValidationRecoveryOpenFailureV0,
) -> NativeConsensusApplicationHostErrorV0 {
    match cause {
        NativeValidationRecoveryOpenFailureV0::DatabaseUnavailable => {
            NativeConsensusApplicationHostErrorV0::DatabaseUnavailable
        }
        NativeValidationRecoveryOpenFailureV0::HostResourceUnavailable => {
            NativeConsensusApplicationHostErrorV0::HostResourceUnavailable
        }
        NativeValidationRecoveryOpenFailureV0::
            AuthenticatedGenesisApplicationActivationUnavailable => {
                NativeConsensusApplicationHostErrorV0::
                    AuthenticatedGenesisApplicationActivationUnavailable
            }
        NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding
        | NativeValidationRecoveryOpenFailureV0::MissingSafetyBinding
        | NativeValidationRecoveryOpenFailureV0::InvalidSafetyProvenance => {
            NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance
        }
        NativeValidationRecoveryOpenFailureV0::StatusPathNotAbsolute => {
            NativeConsensusApplicationHostErrorV0::StatePathNotAbsolute
        }
        NativeValidationRecoveryOpenFailureV0::ParentUnavailable
        | NativeValidationRecoveryOpenFailureV0::MissingDatabase
        | NativeValidationRecoveryOpenFailureV0::DatabaseIsNotRegularFile
        | NativeValidationRecoveryOpenFailureV0::Locked
        | NativeValidationRecoveryOpenFailureV0::UnsafeNamespace
        | NativeValidationRecoveryOpenFailureV0::NamespaceChanged
        | NativeValidationRecoveryOpenFailureV0::ProcessChanged => {
            NativeConsensusApplicationHostErrorV0::NamespaceUnavailable
        }
        NativeValidationRecoveryOpenFailureV0::UnsupportedSchema
        | NativeValidationRecoveryOpenFailureV0::UnsupportedJob(_)
        | NativeValidationRecoveryOpenFailureV0::DuplicateIdentity
        | NativeValidationRecoveryOpenFailureV0::Integrity => {
            NativeConsensusApplicationHostErrorV0::PersistedStateMismatch
        }
    }
}

fn map_authority_install_failure_v0(
    cause: NativeCoreApplicationAuthoritiesInstallFailureV0,
) -> NativeConsensusApplicationHostErrorV0 {
    match cause {
        NativeCoreApplicationAuthoritiesInstallFailureV0::NamespaceMismatch => {
            NativeConsensusApplicationHostErrorV0::NamespaceUnavailable
        }
        NativeCoreApplicationAuthoritiesInstallFailureV0::ChainMismatch
        | NativeCoreApplicationAuthoritiesInstallFailureV0::CoreAffinityMismatch => {
            NativeConsensusApplicationHostErrorV0::CoreAuthorityMismatch
        }
        NativeCoreApplicationAuthoritiesInstallFailureV0::SlotUnavailable => {
            NativeConsensusApplicationHostErrorV0::CoreAuthorityUnavailable
        }
        NativeCoreApplicationAuthoritiesInstallFailureV0::AlreadyInstalled => {
            NativeConsensusApplicationHostErrorV0::CoreAuthoritiesAlreadyInstalled
        }
    }
}

/// The only existing-only ApplicationStore lifetime exposed to a future
/// unified node host.
///
/// The value is non-cloneable and exposes neither its store nor an `into_parts`
/// escape hatch. Opening it acquires the exclusive namespace pin and performs
/// a read-only schema-v12 closure audit before any Core recovery attestation
/// can be minted.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeConsensusApplicationHostV0;
/// fn assert_clone<T: Clone>() {}
/// fn host_is_linear() { assert_clone::<NativeConsensusApplicationHostV0>(); }
/// ```
pub struct NativeConsensusApplicationHostV0 {
    application: ConsensusAppConfig,
    store: ApplicationStore,
    namespace_pin: NativeValidationRecoveryNamespacePinV0,
    invalid_recovery: NativeValidationRecoveryCoordinatorV0,
    affinity: Arc<()>,
}

/// Copy-only outcome of one fully closed anchored-successor empty-body
/// validation. Construction is private to the P/D/C/K facade below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeStateSyncAnchorSuccessorValidationFactsV0 {
    block_id: BlockId,
    accepted_core_revision: u64,
    job_acked: bool,
    effects_empty: bool,
    seal_authority_retired: bool,
}

impl NativeStateSyncAnchorSuccessorValidationFactsV0 {
    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn accepted_core_revision(self) -> u64 {
        self.accepted_core_revision
    }

    pub const fn job_acked(self) -> bool {
        self.job_acked
    }

    pub const fn effects_empty(self) -> bool {
        self.effects_empty
    }

    pub const fn seal_authority_retired(self) -> bool {
        self.seal_authority_retired
    }
}

/// Closed result of the first ordinary non-empty application slice.
///
/// The returned effect is inert: this facade never invokes a signer or a
/// network broadcaster. Its exact one-element shape is checked before this
/// owner can be constructed, and the authorizing Safety revision is copied
/// from the already-canonical sign intent after the matching StorageAck.
#[derive(Debug)]
#[must_use = "the released inert Vote signature request must be retained by the node host"]
pub struct NativeOrdinarySingleRuntimeValidationFactsV0 {
    block_id: BlockId,
    accepted_core_revision: u64,
    authorizing_safety_revision: u64,
    effects: Vec<Effect>,
}

impl NativeOrdinarySingleRuntimeValidationFactsV0 {
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn accepted_core_revision(&self) -> u64 {
        self.accepted_core_revision
    }

    pub const fn authorizing_safety_revision(&self) -> u64 {
        self.authorizing_safety_revision
    }

    pub fn effects_v0(&self) -> &[Effect] {
        &self.effects
    }

    pub fn into_effects_v0(self) -> Vec<Effect> {
        self.effects
    }
}

/// Non-cloneable proof that one fixed ApplicationStore snapshot is the exact
/// fresh h1 TrustedBase named by a Core state-sync recovery challenge.
///
/// It grants no Core, signer, callback, apply, or persistence authority and
/// has no public constructor or serialization surface.
#[derive(Debug)]
#[must_use = "the confirmed ApplicationStore state-sync base must be joined to virgin signer facts"]
pub struct ConfirmedNativeApplicationStateSyncAnchorV0 {
    challenge_state: Box<SafetyState>,
    facts: ReconciledNativeApplicationStateSyncAnchorV0,
    host_affinity: Arc<()>,
}

/// One-shot fixed-snapshot App confirmation for a stable anchored-successor
/// cut. Rev2 joins its current authenticated native-Valid Safety transition;
/// rev4 confirms the App-local h2+h3 K closure and retains the private h2
/// transition preimage. The facade must subsequently join that preimage to
/// SafetyStore's authenticated rev3 predecessor reconstruction before the
/// Node can activate; this capability alone never claims historical Safety
/// authentication.
#[derive(Debug)]
#[must_use = "the anchored-successor App confirmation must be joined by the node reconciler"]
pub struct ConfirmedNativeApplicationStateSyncAnchorSuccessorsV0 {
    challenge_state: Box<SafetyState>,
    facts: ReconciledNativeApplicationStateSyncAnchorSuccessorsV0,
    host_affinity: Arc<()>,
}

/// Stable App source observed when one ordinary NativeValid completion was
/// recovered. Both variants leave the durable database at exact K/Acked;
/// `Delivered` records that the recovery-only kernel performed D->K.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeConsensusApplicationValidCompletionSourceV0 {
    Delivered,
    Acked,
}

/// One-shot, host-affined confirmation that an authenticated ordinary
/// NativeValid Safety head and exactly one App D/K source were joined
/// field-for-field and that the App store now holds exact K.
///
/// This capability contains no Store, callback owner, Core persistence
/// barrier, StorageAck, signer, or effect authority. It is deliberately
/// non-cloneable and non-serializable.
///
/// ```compile_fail
/// use trnm_consensus_app::ConfirmedNativeApplicationValidCompletionRecoveryV0;
/// fn assert_clone<T: Clone>() {}
/// fn confirmation_is_linear() {
///     assert_clone::<ConfirmedNativeApplicationValidCompletionRecoveryV0>();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the stable native-Valid App confirmation must be consumed by Core attestation"]
pub struct ConfirmedNativeApplicationValidCompletionRecoveryV0 {
    challenge_state: Box<SafetyState>,
    safety: ConfirmedNativeValidHeadV0,
    facts: ReconciledNativeApplicationValidCompletionV0,
    host_affinity: Arc<()>,
}

impl ConfirmedNativeApplicationValidCompletionRecoveryV0 {
    pub const fn source_v0(&self) -> NativeConsensusApplicationValidCompletionSourceV0 {
        match self.facts.source {
            NativeValidCompletionApplicationSourceV0::Delivered => {
                NativeConsensusApplicationValidCompletionSourceV0::Delivered
            }
            NativeValidCompletionApplicationSourceV0::Acked => {
                NativeConsensusApplicationValidCompletionSourceV0::Acked
            }
        }
    }
}

struct ExactNativeValidCompletionRecoveryReconcilerV0<'a> {
    host: &'a NativeConsensusApplicationHostV0,
    confirmed_affinity: &'a Arc<()>,
    challenge_state: &'a SafetyState,
    facts: &'a ReconciledNativeApplicationValidCompletionV0,
}

impl NativeValidCompletionRecoveryReconcilerV0
    for ExactNativeValidCompletionRecoveryReconcilerV0<'_>
{
    fn reconcile_native_valid_completion_v0(
        &mut self,
        challenge: &NativeValidCompletionRecoveryChallengeV0,
        safety_state_record_checksum: [u8; 32],
        post_ack_action: NativeValidPostAckActionV0,
    ) -> bool {
        Arc::ptr_eq(&self.host.affinity, self.confirmed_affinity)
            && self
                .host
                .namespace_pin
                .validate_open_v0(&self.host.store)
                .is_ok()
            && challenge.safety_state() == self.challenge_state
            && challenge.route_v0() == self.facts.route
            && challenge.validation_id_v0() == self.facts.validation_id
            && challenge.safety_head_revision_v0() == self.facts.safety_revision
            && challenge.valid_result_checksum_v0() == self.facts.valid_result_checksum
            && safety_state_record_checksum == self.facts.safety_state_record_checksum
            && post_ack_action == self.facts.post_ack_action
    }
}

/// One-shot h1 projection expectation derived from the trusted Core validator
/// set and the validated application signer-policy preimage.
///
/// It is process-local, non-cloneable, non-serializable, and grants no store,
/// Core, signer, or persistence authority.  The database being audited cannot
/// construct this value or choose its expected lifecycle/root.
///
/// ```compile_fail
/// use trnm_consensus_app::PreparedNativeApplicationH1ProjectionExpectationV0;
/// fn assert_clone<T: Clone>() {}
/// fn expectation_is_linear() {
///     assert_clone::<PreparedNativeApplicationH1ProjectionExpectationV0>();
/// }
/// ```
///
/// ```compile_fail
/// use serde::Serialize;
/// use trnm_consensus_app::PreparedNativeApplicationH1ProjectionExpectationV0;
/// fn assert_serialize<T: Serialize>() {}
/// fn expectation_is_not_durable() {
///     assert_serialize::<PreparedNativeApplicationH1ProjectionExpectationV0>();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the pinned h1 projection expectation must be consumed by exact confirmation"]
pub struct PreparedNativeApplicationH1ProjectionExpectationV0 {
    inner: NativeApplicationH1ProjectionExpectationV0,
}

impl fmt::Debug for NativeConsensusApplicationHostV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeConsensusApplicationHostV0")
            .finish_non_exhaustive()
    }
}

/// Non-cloneable proof that one authenticated SafetyStore tag-3 head has an
/// exact current Applied receipt/head closure in this ApplicationStore.
///
/// It contains comparison material only. It cannot recreate a queue permit,
/// live receipt, `StorageAck`, or post-ack effect and has no public
/// constructor or field access.
///
/// ```compile_fail
/// use trnm_consensus_app::ConfirmedNativeApplicationFinalizationAppliedV0;
/// fn assert_clone<T: Clone>() {}
/// fn confirmation_is_linear() {
///     assert_clone::<ConfirmedNativeApplicationFinalizationAppliedV0>();
/// }
/// ```
///
/// ```compile_fail
/// use serde::Serialize;
/// use trnm_consensus_app::ConfirmedNativeApplicationFinalizationAppliedV0;
/// fn assert_serialize<T: Serialize>() {}
/// fn confirmation_is_not_durable() {
///     assert_serialize::<ConfirmedNativeApplicationFinalizationAppliedV0>();
/// }
/// ```
#[must_use = "the confirmed ApplicationStore tag-3 closure must be consumed by recovery attestation"]
pub struct ConfirmedNativeApplicationFinalizationAppliedV0 {
    safety: ConfirmedNativeFinalizationAppliedHeadV0,
    transition: NativeFinalizationAppliedRecoveryTransitionV0,
    readback: ApplicationFinalizationApplyReadbackV0,
    host_affinity: Arc<()>,
}

impl fmt::Debug for ConfirmedNativeApplicationFinalizationAppliedV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedNativeApplicationFinalizationAppliedV0")
            .field("revision", &self.transition.transition_revision())
            .field("ordinal", &self.transition.ordinal())
            .finish_non_exhaustive()
    }
}

struct ExactNativeFinalizationAppliedReconcilerV0<'a> {
    host_affinity: &'a Arc<()>,
    confirmed_affinity: &'a Arc<()>,
    transition: &'a NativeFinalizationAppliedRecoveryTransitionV0,
    readback: &'a ApplicationFinalizationApplyReadbackV0,
}

impl NativeFinalizationAppliedRecoveryReconcilerV0
    for ExactNativeFinalizationAppliedReconcilerV0<'_>
{
    fn reconcile_native_finalization_applied_v0(
        &mut self,
        _challenge: &NativeFinalizationAppliedRecoveryChallengeV0,
        transition: &NativeFinalizationAppliedRecoveryTransitionV0,
        application_readback: &ApplicationFinalizationApplyReadbackV0,
    ) -> bool {
        Arc::ptr_eq(self.host_affinity, self.confirmed_affinity)
            && transition == self.transition
            && application_readback == self.readback
    }
}

impl NativeConsensusApplicationHostV0 {
    /// Derives the only accepted h1 application projection from independent
    /// Core/application configuration. No ApplicationStore is opened and no
    /// database fact participates in this expectation.
    pub fn prepare_h1_projection_expectation_v0(
        core_config: &CoreConfig,
        application: &ConsensusAppConfig,
    ) -> Result<
        PreparedNativeApplicationH1ProjectionExpectationV0,
        NativeConsensusApplicationHostErrorV0,
    > {
        application
            .validate()
            .map_err(|_| NativeConsensusApplicationHostErrorV0::InvalidConfig)?;
        let inner =
            match prepare_native_application_h1_projection_expectation_v0(core_config, application)
            {
                Ok(inner) => inner,
                Err(NativeApplicationFinalizationApplyFailureCauseV0::HostResourceUnavailable) => {
                    return Err(NativeConsensusApplicationHostErrorV0::HostResourceUnavailable)
                }
                Err(_) => return Err(NativeConsensusApplicationHostErrorV0::InvalidConfig),
            };
        Ok(PreparedNativeApplicationH1ProjectionExpectationV0 { inner })
    }

    /// Opens only an already-existing, current schema-v12 store using the
    /// canonical chain and signer-policy preimage from the validated app
    /// configuration. No migration or writer transaction is performed.
    pub fn open_existing_v0(
        config: NativeConsensusApplicationHostConfigV0,
    ) -> Result<Self, NativeConsensusApplicationHostErrorV0> {
        let NativeConsensusApplicationHostConfigV0 {
            application,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        } = config;
        let state_path = application
            .state_path
            .as_deref()
            .expect("validated native consensus application config has a state path");
        let signer_policy_hash_hex = hex::encode(signer_policy_commitment(
            application.authorized_signers.as_slice(),
        ));
        let store = ApplicationStore::open_existing_recovery_v0(
            state_path,
            application.chain_id.as_str(),
            signer_policy_hash_hex.as_str(),
        )
        .map_err(map_application_store_open_failure_v0)?;
        let namespace_pin = NativeValidationRecoveryNamespacePinV0::capture(&store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        if !namespace_pin.matches_safety_provenance_v0(
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        ) {
            return Err(NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance);
        }
        namespace_pin
            .validate_open_v0(&store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let invalid_recovery = NativeValidationRecoveryCoordinatorV0::open_coexisting_existing_v0(
            &store,
            &namespace_pin,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        )
        .map_err(map_recovery_open_failure_v0)?;
        Ok(Self {
            application,
            store,
            namespace_pin,
            invalid_recovery,
            affinity: Arc::new(()),
        })
    }

    pub const fn last_invalid_reconcile_failure_v0(
        &self,
    ) -> Option<NativeValidationRecoveryReconcileFailureV0> {
        self.invalid_recovery.last_reconcile_failure_v0()
    }

    pub const fn supported_invalid_recovery_job_count_v0(&self) -> usize {
        self.invalid_recovery.supported_recovery_job_count_v0()
    }

    pub const fn active_invalid_recovery_job_count_v0(&self) -> usize {
        self.invalid_recovery.active_recovery_job_count_v0()
    }

    /// Returns the number of deeply audited active Valid P/D/K jobs in the
    /// pinned ApplicationStore namespace. The unified host uses this fact to
    /// fail closed until cross-crash Valid remint is implemented.
    pub fn active_valid_recovery_job_count_v0(
        &self,
    ) -> Result<usize, NativeConsensusApplicationHostErrorV0> {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let count = self
            .store
            .active_native_valid_recovery_job_count_v0()
            .map_err(map_store_failure_v0)?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(count)
    }

    /// Joins one exact authenticated ordinary NativeValid Safety head to the
    /// only matching stable App source. C+D is atomically retired to C+K by a
    /// recovery-only kernel; C+K is confirmed read-only and idempotently.
    ///
    /// The returned capability remains host-affined and owns the linear
    /// Safety confirmation. No Core attestation or recovered action is minted
    /// until [`Self::attest_native_valid_completion_recovery_v0`] consumes it
    /// after a fresh exact K readback.
    pub fn recover_native_valid_completion_v0<V: SignatureVerifier>(
        &self,
        challenge: &NativeValidCompletionRecoveryChallengeV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
        safety: ConfirmedNativeValidHeadV0,
    ) -> Result<
        ConfirmedNativeApplicationValidCompletionRecoveryV0,
        NativeConsensusApplicationHostErrorV0,
    > {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        if !safety.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
            || !self.namespace_pin.matches_safety_provenance_v0(
                safety.journal_id_v0(),
                safety.verifier_profile_ref_v0(),
            )
            || safety.state() != challenge.safety_state()
        {
            return Err(NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance);
        }
        let facts = self
            .store
            .recover_native_valid_completion_v0(challenge, &safety)
            .map_err(|cause| match cause {
                NativeApplicationFinalizationApplyFailureCauseV0::PersistedStateMismatch => {
                    NativeConsensusApplicationHostErrorV0::NativeValidCompletionRecoveryUnavailable
                }
                other => map_store_failure_v0(other),
            })?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(ConfirmedNativeApplicationValidCompletionRecoveryV0 {
            challenge_state: Box::new(challenge.safety_state().clone()),
            safety,
            facts,
            host_affinity: Arc::clone(&self.affinity),
        })
    }

    /// Model-only access to the detached App D->K kernel. This intentionally
    /// omits Core attestation and the production full-history closure so a
    /// fixture with unbacked historical completions cannot be mistaken for a
    /// genuine whole-store recovery proof.
    #[cfg(test)]
    pub(crate) fn exercise_native_valid_completion_stable_cut_kernel_for_test_v0<
        V: SignatureVerifier,
    >(
        &self,
        challenge: &NativeValidCompletionRecoveryChallengeV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
        safety: &ConfirmedNativeValidHeadV0,
    ) -> Result<
        NativeConsensusApplicationValidCompletionSourceV0,
        NativeConsensusApplicationHostErrorV0,
    > {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        if !safety.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
            || !self.namespace_pin.matches_safety_provenance_v0(
                safety.journal_id_v0(),
                safety.verifier_profile_ref_v0(),
            )
            || safety.state() != challenge.safety_state()
        {
            return Err(NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance);
        }
        let source = self
            .store
            .exercise_native_valid_completion_stable_cut_kernel_for_test_v0(challenge, safety)
            .map_err(|cause| match cause {
                NativeApplicationFinalizationApplyFailureCauseV0::PersistedStateMismatch => {
                    NativeConsensusApplicationHostErrorV0::NativeValidCompletionRecoveryUnavailable
                }
                other => map_store_failure_v0(other),
            })?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(match source {
            NativeValidCompletionApplicationSourceV0::Delivered => {
                NativeConsensusApplicationValidCompletionSourceV0::Delivered
            }
            NativeValidCompletionApplicationSourceV0::Acked => {
                NativeConsensusApplicationValidCompletionSourceV0::Acked
            }
        })
    }

    /// Consumes one host-affined App/Safety confirmation, freshly reopens the
    /// exact K poststate, and lets Core mint only its linear inert recovery
    /// attestation. No `Effect`, callback, StorageAck, signer, or generic Core
    /// input surface crosses this boundary.
    pub fn attest_native_valid_completion_recovery_v0<V: SignatureVerifier>(
        &self,
        challenge: &NativeValidCompletionRecoveryChallengeV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
        confirmed: ConfirmedNativeApplicationValidCompletionRecoveryV0,
    ) -> Result<NativeValidCompletionRecoveryAttestationV0, NativeConsensusApplicationHostErrorV0>
    {
        let ConfirmedNativeApplicationValidCompletionRecoveryV0 {
            challenge_state,
            safety,
            facts,
            host_affinity,
        } = confirmed;
        if !Arc::ptr_eq(&self.affinity, &host_affinity)
            || challenge_state.as_ref() != challenge.safety_state()
            || !safety.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
            || !self.namespace_pin.matches_safety_provenance_v0(
                safety.journal_id_v0(),
                safety.verifier_profile_ref_v0(),
            )
        {
            return Err(NativeConsensusApplicationHostErrorV0::ForeignCapability);
        }
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let fresh_safety = safety_store
            .confirmed_native_valid_head_exact_v0(safety.state(), safety.transition_context())
            .map_err(|_| NativeConsensusApplicationHostErrorV0::SafetyStateMismatch)?;
        if !fresh_safety.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
            || fresh_safety.journal_id_v0() != safety.journal_id_v0()
            || fresh_safety.verifier_profile_ref_v0() != safety.verifier_profile_ref_v0()
            || fresh_safety.state_record_checksum() != safety.state_record_checksum()
            || fresh_safety.chain_checksum() != safety.chain_checksum()
        {
            return Err(NativeConsensusApplicationHostErrorV0::ForeignCapability);
        }
        drop(safety);
        let fresh = self
            .store
            .recover_native_valid_completion_v0(challenge, &fresh_safety)
            .map_err(|cause| match cause {
                NativeApplicationFinalizationApplyFailureCauseV0::PersistedStateMismatch => {
                    NativeConsensusApplicationHostErrorV0::NativeValidCompletionRecoveryUnavailable
                }
                other => map_store_failure_v0(other),
            })?;
        if fresh.source != NativeValidCompletionApplicationSourceV0::Acked
            || !facts.same_exact_acked_cut_v0(&fresh)
        {
            return Err(
                NativeConsensusApplicationHostErrorV0::NativeValidCompletionRecoveryUnavailable,
            );
        }
        let mut reconciler = ExactNativeValidCompletionRecoveryReconcilerV0 {
            host: self,
            confirmed_affinity: &host_affinity,
            challenge_state: challenge_state.as_ref(),
            facts: &fresh,
        };
        let attestation = challenge
            .attest_authenticated_reconciliation_v0(
                fresh_safety.state(),
                fresh_safety.state_record_checksum(),
                fresh_safety.post_ack_action_v0(),
                &mut reconciler,
            )
            .map_err(|_| NativeConsensusApplicationHostErrorV0::CoreRecoveryMismatch)?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(attestation)
    }

    pub const fn acked_invalid_history_job_count_v0(&self) -> usize {
        self.invalid_recovery.acked_history_job_count_v0()
    }

    pub fn final_invalid_recovery_audit_v0(
        &self,
    ) -> Result<(), NativeValidationRecoveryTransitionFailureV0> {
        self.invalid_recovery
            .final_exact_audit_v0(&self.store, &self.namespace_pin)
    }

    pub fn recovered_invalid_obligation_state_v0(
        &self,
    ) -> Option<NativeValidationRecoveredInvalidStateV0> {
        self.invalid_recovery.recovered_obligation_state_v0()
    }

    pub fn recovered_invalid_obligation_callback_facts_v0(
        &self,
    ) -> Option<NativeValidationRecoveredInvalidCallbackFactsV0> {
        self.invalid_recovery
            .recovered_obligation_callback_facts_v0()
    }

    pub fn record_recovered_invalid_core_acceptance_v0(
        &mut self,
        persistence: &SafetyStatePersistenceV0,
    ) -> Result<
        NativeValidationRecoveredInvalidCallbackFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.invalid_recovery.record_recovered_core_acceptance_v0(
            &self.store,
            &self.namespace_pin,
            persistence,
        )
    }

    pub fn recover_confirmed_invalid_completion_v0(
        &mut self,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> Result<NativeValidationRecoveredInvalidStateV0, NativeValidationRecoveryTransitionFailureV0>
    {
        self.invalid_recovery
            .recover_confirmed_invalid_completion_v0(&self.store, &self.namespace_pin, confirmed)
    }

    pub fn acknowledge_recovered_invalid_completion_v0(
        &mut self,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> Result<NativeValidationRecoveredAckedFactsV0, NativeValidationRecoveryTransitionFailureV0>
    {
        self.invalid_recovery
            .acknowledge_recovered_invalid_completion_v0(
                &self.store,
                &self.namespace_pin,
                confirmed,
            )
    }

    /// Confirms the complete fixed-snapshot ApplicationStore recovery closure
    /// and joins its exact head and durable Valid ownership to one
    /// authenticated SafetyStore head capability.
    pub fn confirm_node_checkpoint_facts_v0(
        &self,
        safety: &ConfirmedSafetyNodeCheckpointFactsV0,
    ) -> Result<
        ConfirmedNativeApplicationNodeCheckpointFactsV0,
        NativeConsensusApplicationHostErrorV0,
    > {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        if !self
            .namespace_pin
            .matches_safety_provenance_v0(safety.journal_id_v0(), safety.verifier_profile_ref_v0())
        {
            return Err(NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance);
        }
        let ReconciledNativeApplicationNodeCheckpointFactsV0 {
            applied,
            host_config_ref,
            projection_profile_ref,
            committed_head_row_checksum,
            recovery_closure_checksum,
        } = self
            .store
            .reconcile_current_application_node_checkpoint_v0(safety.state_v0())
            .map_err(|cause| match cause {
                NativeApplicationFinalizationApplyFailureCauseV0::PersistedStateMismatch => {
                    NativeConsensusApplicationHostErrorV0::SafetyStateMismatch
                }
                other => map_store_failure_v0(other),
            })?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(ConfirmedNativeApplicationNodeCheckpointFactsV0 {
            applied: applied.into(),
            host_config_ref,
            projection_profile_ref,
            safety_journal_id: safety.journal_id_v0(),
            safety_verifier_profile_ref: safety.verifier_profile_ref_v0(),
            safety_revision: safety.revision_v0(),
            safety_state_record_checksum: safety.state_record_checksum_v0(),
            safety_chain_checksum: safety.chain_checksum_v0(),
            safety_binding_manifest_checksum: self
                .namespace_pin
                .safety_binding_manifest_checksum_v0(),
            committed_head_row_checksum,
            recovery_closure_checksum,
            host_affinity: Arc::clone(&self.affinity),
        })
    }

    /// Backwards-compatible copy-only diagnostic projection. This deliberately
    /// accepts a naked state only for legacy diagnostics and cannot mint the
    /// authenticated node-checkpoint capability.
    pub fn reconcile_current_application_applied_v0(
        &self,
        safety_state: &SafetyState,
    ) -> Result<ConfirmedNativeApplicationAppliedFactsV0, NativeConsensusApplicationHostErrorV0>
    {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let facts = self
            .store
            .reconcile_current_application_applied_v0(safety_state)
            .map_err(map_store_failure_v0)?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(facts.into())
    }

    /// Confirms the Core-authenticated h1 header against an exact, virgin
    /// schema-v12 ApplicationStore TrustedBase on one fixed read snapshot.
    pub fn confirm_state_sync_anchor_v0(
        &self,
        challenge: &StateSyncAnchorRecoveryChallengeV0,
        expectation: PreparedNativeApplicationH1ProjectionExpectationV0,
    ) -> Result<ConfirmedNativeApplicationStateSyncAnchorV0, NativeConsensusApplicationHostErrorV0>
    {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let PreparedNativeApplicationH1ProjectionExpectationV0 { inner } = expectation;
        let facts = self
            .store
            .reconcile_state_sync_anchor_v0(challenge, &inner)
            .map_err(map_store_failure_v0)?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(ConfirmedNativeApplicationStateSyncAnchorV0 {
            challenge_state: Box::new(challenge.safety_state().clone()),
            facts,
            host_affinity: Arc::clone(&self.affinity),
        })
    }

    /// Exact comparison hook for the unified node's private Core reconciler.
    /// The node must additionally join virgin signer facts before returning
    /// true from `StateSyncAnchorRecoveryReconcilerV0`.
    pub fn state_sync_anchor_confirmation_matches_v0(
        &self,
        challenge: &StateSyncAnchorRecoveryChallengeV0,
        confirmed: &ConfirmedNativeApplicationStateSyncAnchorV0,
    ) -> bool {
        let header = challenge.trusted_base_header();
        Arc::ptr_eq(&self.affinity, &confirmed.host_affinity)
            && self.namespace_pin.validate_open_v0(&self.store).is_ok()
            && confirmed.challenge_state.as_ref() == challenge.safety_state()
            && confirmed.facts.block_id == header.id()
            && confirmed.facts.height == header.height().get()
            && confirmed.facts.state_root == *header.state_root().as_bytes()
            && confirmed.facts.view == header.view().get()
            && confirmed.facts.timestamp_ms == header.timestamp_ms()
            && confirmed.facts.committed_head_checksum != [0; 32]
            && confirmed.facts.projection_profile_checksum != [0; 32]
            && confirmed.facts.validated_lifecycle_checksum != [0; 32]
            && confirmed.facts.physical_object_count == 0
            && confirmed.facts.active_poco_configuration_exact
    }

    /// Confirms one stable rev0/rev2/rev4 anchored-successor App cut on a
    /// fixed snapshot. Rev2/rev4 require the authenticated current
    /// native-Valid Safety head; rev0 requires its absence.
    pub fn confirm_state_sync_anchor_successors_v0(
        &self,
        challenge: &trnm_consensus_core::StateSyncAnchorSuccessorRecoveryChallengeV0,
        expectation: PreparedNativeApplicationH1ProjectionExpectationV0,
        confirmed: Option<&ConfirmedNativeValidHeadV0>,
    ) -> Result<
        ConfirmedNativeApplicationStateSyncAnchorSuccessorsV0,
        NativeConsensusApplicationHostErrorV0,
    > {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        if let Some(confirmed) = confirmed {
            if !self.namespace_pin.matches_safety_provenance_v0(
                confirmed.journal_id_v0(),
                confirmed.verifier_profile_ref_v0(),
            ) {
                return Err(NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance);
            }
        }
        let PreparedNativeApplicationH1ProjectionExpectationV0 { inner } = expectation;
        let facts = self
            .store
            .reconcile_state_sync_anchor_successors_v0(challenge, &inner, confirmed)
            .map_err(map_store_failure_v0)?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(ConfirmedNativeApplicationStateSyncAnchorSuccessorsV0 {
            challenge_state: Box::new(challenge.safety_state().clone()),
            facts,
            host_affinity: Arc::clone(&self.affinity),
        })
    }

    /// Opaque comparison hook for the Node's private Core+App+signer
    /// reconciler. It grants no Store, callback, signer, or Core authority.
    pub fn state_sync_anchor_successor_confirmation_matches_v0(
        &self,
        challenge: &trnm_consensus_core::StateSyncAnchorSuccessorRecoveryChallengeV0,
        confirmed: &ConfirmedNativeApplicationStateSyncAnchorSuccessorsV0,
    ) -> bool {
        let expected_jobs = match challenge.phase() {
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap => 0,
            StateSyncAnchorSuccessorPhaseV0::H2Valid => 1,
            StateSyncAnchorSuccessorPhaseV0::H3Valid => 2,
            StateSyncAnchorSuccessorPhaseV0::H2ValidationPending
            | StateSyncAnchorSuccessorPhaseV0::H3ValidationPending => return false,
        };
        Arc::ptr_eq(&self.affinity, &confirmed.host_affinity)
            && self.namespace_pin.validate_open_v0(&self.store).is_ok()
            && confirmed.challenge_state.as_ref() == challenge.safety_state()
            && confirmed.facts.phase == challenge.phase()
            && confirmed.facts.matched_acked_jobs == expected_jobs
            && confirmed.facts.current_transition_exact
    }

    /// Joins the h2 transition reconstructed from this host's rev4 fixed
    /// snapshot to the pruned SafetyStore prefix, then independently closes
    /// the App accepted-envelope checksum over Safety's reconstructed rev2
    /// state-record checksum. Both underlying comparison capabilities are
    /// consumed locally and no raw transition, callback, Core, signer, or
    /// persistence authority is returned.
    pub fn confirm_rev4_historical_h2_safety_v0<V: SignatureVerifier>(
        &self,
        challenge: &trnm_consensus_core::StateSyncAnchorSuccessorRecoveryChallengeV0,
        application: &ConfirmedNativeApplicationStateSyncAnchorSuccessorsV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
    ) -> Result<(), NativeConsensusApplicationHostErrorV0> {
        if challenge.phase() != StateSyncAnchorSuccessorPhaseV0::H3Valid
            || !Arc::ptr_eq(&self.affinity, &application.host_affinity)
            || application.challenge_state.as_ref() != challenge.safety_state()
            || application.facts.phase != StateSyncAnchorSuccessorPhaseV0::H3Valid
            || application.facts.matched_acked_jobs != 2
            || !application.facts.current_transition_exact
        {
            return Err(NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable);
        }
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let transition = application
            .facts
            .historical_h2_transition_v0()
            .ok_or(NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable)?;
        let confirmed = safety_store
            .confirm_anchored_successor_h2_transition_from_rev4_v0(challenge, transition)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::SafetyStateMismatch)?;
        if !self.namespace_pin.matches_safety_provenance_v0(
            confirmed.journal_id_v0(),
            confirmed.verifier_profile_ref_v0(),
        ) || confirmed.transition_v0() != transition
            || !application.facts.historical_current_safety_head_matches_v0(
                confirmed.current_state_record_checksum_v0(),
                confirmed.current_chain_checksum_v0(),
            )
            || !application
                .facts
                .historical_h2_accepted_envelope_matches_v0(
                    confirmed.reconstructed_state_record_checksum_v0(),
                )
        {
            return Err(NativeConsensusApplicationHostErrorV0::SafetyStateMismatch);
        }
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(())
    }

    /// Installs the exact live Core's seal and finalization authorities as one
    /// all-or-none operation.
    ///
    /// Namespace, chain, shared Core-instance affinity, and both empty slots
    /// are checked before either capability is moved into the store. Every
    /// rejection returns both unique owners unchanged.
    pub fn install_core_authorities_v0(
        &self,
        seal: CoreIssuedApplicationSealAuthorityV0,
        finalization: CoreIssuedApplicationFinalizationApplyAuthorityV0,
    ) -> Result<(), NativeConsensusApplicationAuthoritiesInstallRejectionV0> {
        if self.namespace_pin.validate_open_v0(&self.store).is_err() {
            return Err(
                NativeConsensusApplicationAuthoritiesInstallRejectionV0::new_v0(
                    NativeConsensusApplicationHostErrorV0::NamespaceUnavailable,
                    seal,
                    finalization,
                ),
            );
        }
        self.store
            .install_core_application_authorities_v0(seal, finalization)
            .map_err(
                |rejection: NativeCoreApplicationAuthoritiesInstallRejectionV0| {
                    let error = map_authority_install_failure_v0(rejection.cause());
                    let (seal, finalization) = rejection.into_authorities_v0();
                    NativeConsensusApplicationAuthoritiesInstallRejectionV0::new_v0(
                        error,
                        seal,
                        finalization,
                    )
                },
            )
    }

    /// Applies one exact Core-issued finalization queue front through the
    /// existing ApplicationStore owner and returns the Core-bound receipt.
    ///
    /// The store performs all authority, namespace, authenticated carrier,
    /// durable transaction, and fresh readback checks before this method can
    /// return `Ok`.  Any rejection preserves the sole non-cloneable permit in
    /// [`NativeConsensusApplicationFinalizationApplyRejectionV0`], allowing a
    /// trusted caller to retry with the issuing Core or fail-stop without
    /// reconstructing linear authority from persisted rows.
    ///
    /// This is deliberately a candidate-only library seam.  It is not called
    /// by generic process startup or the effect driver, and it does not alter
    /// `production_candidate=false` or
    /// `production_consensus_activation=false`.
    pub fn apply_native_application_finalization_v0(
        &self,
        permit: CoreIssuedApplicationFinalizationPermitV0,
    ) -> Result<
        ApplicationFinalizationReceiptV0,
        NativeConsensusApplicationFinalizationApplyRejectionV0,
    > {
        self.store
            .apply_native_application_finalization_v0(permit)
            .map_err(|rejection| {
                let error = map_finalization_apply_failure_v0(rejection.cause());
                NativeConsensusApplicationFinalizationApplyRejectionV0::new_v0(
                    error,
                    rejection.into_permit(),
                )
            })
    }

    /// Installs only the live anchored-successor Core's one-shot application
    /// seal capability. The ApplicationStore simultaneously proves that its
    /// finalization slot is empty; no apply authority is issued or accepted.
    pub fn install_state_sync_anchor_successor_seal_authority_v0(
        &self,
        replay: &StateSyncAnchorSuccessorReplayV0,
    ) -> Result<(), NativeConsensusApplicationHostErrorV0> {
        if !matches!(
            replay.phase().map_err(|_| {
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })?,
            StateSyncAnchorSuccessorPhaseV0::H1Bootstrap | StateSyncAnchorSuccessorPhaseV0::H2Valid
        ) {
            return Err(NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable);
        }
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let authority = replay
            .issue_application_seal_authority_v0()
            .map_err(|_| NativeConsensusApplicationHostErrorV0::CoreAuthorityUnavailable)?;
        self.store
            .install_core_application_seal_only_authority_v0(authority)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::CoreAuthorityMismatch)
    }

    /// Retires any process-local seal-only replay authority. An exact rev4
    /// reopen has no live slot and is accepted as already retired.
    pub fn retire_state_sync_anchor_successor_seal_authority_v0(
        &self,
        replay: &StateSyncAnchorSuccessorReplayV0,
    ) -> Result<(), NativeConsensusApplicationHostErrorV0> {
        if replay.phase().map_err(|_| {
            NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
        })? != StateSyncAnchorSuccessorPhaseV0::H3Valid
        {
            return Err(NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable);
        }
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        self.store
            .retire_core_application_seal_only_authority_v0()
            .map(|_| ())
            .map_err(|_| NativeConsensusApplicationHostErrorV0::CoreAuthorityUnavailable)
    }

    /// Completes the first ordinary non-empty production slice through the
    /// existing P→D→Safety-C→K→StorageAck typestate.
    ///
    /// Only a proposal-routed regular body with exactly one canonical runtime
    /// transaction is accepted. The App driver performs its unsupported-shape
    /// preflight before durable reservation. Success releases exactly one
    /// persisted Vote `RequestSignature`; this facade neither signs nor
    /// broadcasts it.
    pub fn complete_ordinary_single_runtime_proposal_validation_v0<V: SignatureVerifier>(
        &self,
        core: &mut Core,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
        effect: Effect,
        verifier: &V,
    ) -> Result<NativeOrdinarySingleRuntimeValidationFactsV0, NativeConsensusApplicationHostErrorV0>
    {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let block_id = match &effect {
            Effect::ValidatePayload(request) => request.id().block_id(),
            _ => return Err(
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable,
            ),
        };
        let host =
            NativeValidationHostV0::from_existing_consensus_host_v0(&self.store, &self.application);
        let prepared =
            prepare_ordinary_single_runtime_proposal_valid_v0(&host, effect).map_err(|_cause| {
                #[cfg(test)]
                eprintln!("ordinary single-runtime prepare failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable
            })?;
        let callback = match self
            .store
            .seal_durable_valid_and_enqueue_callback_v0(prepared)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("ordinary single-runtime seal failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable
            })? {
            NativeValidationValidSealDecisionV0::CallbackPending(callback) => *callback,
            NativeValidationValidSealDecisionV0::Existing(_) => return Err(
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable,
            ),
        };
        let accepted = callback
            .submit_to_core_v0(core, verifier)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("ordinary single-runtime callback submit failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable
            })?;
        let accepted_core_revision = accepted.completion_revision_v0();
        let preflighted = accepted
            .preflight_safety_store_v0(safety_store)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("ordinary single-runtime Safety preflight failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable
            })?;
        let delivered = preflighted
            .mark_application_delivered_v0(&self.store)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("ordinary single-runtime delivery failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable
            })?;
        let persisted = delivered
            .persist_and_confirm_safety_v0(safety_store)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("ordinary single-runtime Safety persist failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable
            })?;
        let acked = persisted
            .acknowledge_application_v0(&self.store)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("ordinary single-runtime acknowledge failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable
            })?;
        let released = acked
            .release_core_storage_ack_v0(core, verifier)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("ordinary single-runtime StorageAck release failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationUnavailable
            })?;
        let authorizing_safety_revision = match released.effects_v0() {
            [Effect::RequestSignature { intent }]
                if matches!(
                    intent.preimage(),
                    trnm_consensus_types::CanonicalSignPreimageV0::Vote(_)
                ) && intent.authorizing_safety_revision() == core.safety_state().revision() =>
            {
                intent.authorizing_safety_revision()
            }
            _ => {
                return Err(
                    NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationInvariant,
                )
            }
        };
        if released.app_facts_v0().validation_id().block_id() != block_id
            || accepted_core_revision != authorizing_safety_revision
        {
            return Err(
                NativeConsensusApplicationHostErrorV0::OrdinarySingleRuntimeValidationInvariant,
            );
        }
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(NativeOrdinarySingleRuntimeValidationFactsV0 {
            block_id,
            accepted_core_revision,
            authorizing_safety_revision,
            effects: released.effects_v0().to_vec(),
        })
    }

    /// Executes one exact empty `ValidateSyncedPayload` through the real
    /// ApplicationStore reservation/planner/seal journal and the complete
    /// P→D→Safety-C→K→StorageAck typestate against the dedicated replay owner.
    /// Any failed phase consumes or quarantines its unique owner; this facade
    /// never reconstructs a callback from durable rows.
    pub fn complete_state_sync_anchor_successor_empty_synced_validation_v0<V: SignatureVerifier>(
        &self,
        replay: &mut StateSyncAnchorSuccessorReplayV0,
        safety_store: &mut trnm_consensus_safety_store::SqliteSafetyStateStoreV0<V>,
        effect: Effect,
        verifier: &V,
    ) -> Result<
        NativeStateSyncAnchorSuccessorValidationFactsV0,
        NativeConsensusApplicationHostErrorV0,
    > {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        let block_id = match &effect {
            Effect::ValidateSyncedPayload(request) => request.id().block_id(),
            _ => {
                return Err(
                    NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable,
                )
            }
        };
        let host =
            NativeValidationHostV0::from_existing_consensus_host_v0(&self.store, &self.application);
        let prepared = prepare_empty_synced_state_sync_anchor_successor_valid_v0(&host, effect)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("anchor successor prepare failed: {_cause}");
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })?;
        let callback = match self
            .store
            .seal_durable_valid_and_enqueue_callback_v0(prepared)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("anchor successor seal failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })? {
            NativeValidationValidSealDecisionV0::CallbackPending(callback) => *callback,
            NativeValidationValidSealDecisionV0::Existing(_) => {
                return Err(
                    NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable,
                )
            }
        };
        let accepted = callback
            .submit_to_state_sync_anchor_successor_v0(replay, verifier)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("anchor successor callback submit failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })?;
        let accepted_core_revision = accepted.completion_revision_v0();
        let preflighted = accepted
            .preflight_safety_store_v0(safety_store)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("anchor successor Safety preflight failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })?;
        let delivered = preflighted
            .mark_application_delivered_v0(&self.store)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("anchor successor delivery failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })?;
        let persisted = delivered
            .persist_and_confirm_safety_v0(safety_store)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("anchor successor Safety persist failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })?;
        let acked = persisted
            .acknowledge_application_v0(&self.store)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("anchor successor acknowledge failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })?;
        let released = acked
            .release_state_sync_anchor_successor_storage_ack_v0(replay, verifier)
            .map_err(|_cause| {
                #[cfg(test)]
                eprintln!("anchor successor StorageAck release failed: {_cause:?}");
                NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
            })?;
        if !released.effects_v0().is_empty()
            || released.app_facts_v0().validation_id().block_id() != block_id
        {
            return Err(NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable);
        }
        let seal_authority_retired = replay.phase().map_err(|_| {
            NativeConsensusApplicationHostErrorV0::StateSyncAnchorSuccessorUnavailable
        })? == StateSyncAnchorSuccessorPhaseV0::H3Valid;
        if seal_authority_retired {
            self.retire_state_sync_anchor_successor_seal_authority_v0(replay)?;
        }
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(NativeStateSyncAnchorSuccessorValidationFactsV0 {
            block_id,
            accepted_core_revision,
            job_acked: true,
            effects_empty: true,
            seal_authority_retired,
        })
    }

    /// Consumes an authenticated SafetyStore tag-3 capability and confirms
    /// its exact current ApplicationStore receipt/head on one fixed read
    /// snapshot. The returned capability remains bound to this host lifetime.
    pub fn confirm_native_finalization_applied_v0(
        &self,
        challenge: &NativeFinalizationAppliedRecoveryChallengeV0,
        safety: ConfirmedNativeFinalizationAppliedHeadV0,
    ) -> Result<
        ConfirmedNativeApplicationFinalizationAppliedV0,
        NativeConsensusApplicationHostErrorV0,
    > {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        if !self
            .namespace_pin
            .matches_safety_provenance_v0(safety.journal_id_v0(), safety.verifier_profile_ref_v0())
        {
            return Err(NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance);
        }
        if challenge.safety_head_revision() != safety.revision()
            || challenge.application_applied() != safety.state().application_applied()
        {
            return Err(NativeConsensusApplicationHostErrorV0::SafetyStateMismatch);
        }
        let transition = safety.recovery_transition_v0();
        let readback = challenge
            .application_store_readback_for_recovery_v0(safety.state(), &transition)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::CoreRecoveryMismatch)?;
        self.store
            .confirm_native_application_finalization_applied_recovery_v0(
                safety.consumed_finalization_v0(),
                &readback,
            )
            .map_err(map_store_failure_v0)?;
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        Ok(ConfirmedNativeApplicationFinalizationAppliedV0 {
            safety,
            transition,
            readback,
            host_affinity: Arc::clone(&self.affinity),
        })
    }

    /// Consumes the exact App/Safety capability and asks Core's challenge to
    /// mint the sole recovery-session attestation. The raw App comparison
    /// projection never crosses this facade boundary.
    pub fn attest_native_finalization_applied_recovery_v0(
        &self,
        challenge: &NativeFinalizationAppliedRecoveryChallengeV0,
        confirmed: ConfirmedNativeApplicationFinalizationAppliedV0,
    ) -> Result<NativeFinalizationAppliedRecoveryAttestationV0, NativeConsensusApplicationHostErrorV0>
    {
        self.namespace_pin
            .validate_open_v0(&self.store)
            .map_err(|_| NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)?;
        if !Arc::ptr_eq(&self.affinity, &confirmed.host_affinity) {
            return Err(NativeConsensusApplicationHostErrorV0::ForeignCapability);
        }
        let ConfirmedNativeApplicationFinalizationAppliedV0 {
            safety,
            transition,
            readback,
            host_affinity,
        } = confirmed;
        let mut reconciler = ExactNativeFinalizationAppliedReconcilerV0 {
            host_affinity: &self.affinity,
            confirmed_affinity: &host_affinity,
            transition: &transition,
            readback: &readback,
        };
        challenge
            .attest_authenticated_reconciliation_v0(
                safety.state(),
                &transition,
                &readback,
                &mut reconciler,
            )
            .map_err(|_| NativeConsensusApplicationHostErrorV0::CoreRecoveryMismatch)
    }
}

impl PayloadValidationRecoveryReconcilerV0 for NativeConsensusApplicationHostV0 {
    fn reconcile_deterministically_invalid_obligation_v0(
        &mut self,
        challenge: &PayloadValidationRecoveryChallengeV0,
    ) -> PayloadValidationRecoveryDecisionV0 {
        self.invalid_recovery
            .reconcile_deterministically_invalid_obligation_v0(
                &self.store,
                &self.namespace_pin,
                challenge,
            )
    }
}

#[cfg(test)]
mod state_sync_projection_tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use ed25519_dalek::{Signer, SigningKey};
    use jmt::storage::{NibblePath, NodeKey};
    use rusqlite::Connection;
    use trnm_consensus_core::{
        leader_for, Core, CoreConfig, Effect, SafetyState,
        StateSyncAnchorSuccessorRecoveryChallengeV0, StateSyncAnchorSuccessorRecoveryReconcilerV0,
    };
    use trnm_consensus_crypto::StrictEd25519Verifier;
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockId, BlockKind,
        CertifiedHeaderV0, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
        ExecutionReceiptsV0, FinalityProofV0, GenesisHash, GenesisQcV0, Height, ProposalWitnessV0,
        ProtocolVersion, QcReferenceV0, QuorumCertificate, SignatureBytes, SignedProposalV0,
        SigningRoot, StateRoot, Validator, ValidatorId, ValidatorSet, View, Vote, VotingPower,
    };

    use crate::{
        poco_snapshot::{
            decode_poco_snapshot_physical_key_v0_exact, PocoSnapshotEntryKindV0,
            PocoSnapshotPhysicalKeyV0,
        },
        signer_policy_commitment,
        store::{
            application_store_database_path_v0,
            audit_native_application_h1_active_configuration_fixture_v0,
            native_application_h1_trusted_base_v0,
            native_application_h1_validator_lifecycle_expectation_v0,
            native_validation_recovery::{
                bootstrap_native_validation_safety_binding_manifest_v0,
                native_validation_safety_binding_manifest_path_v0,
            },
            ApplicationStore, ApplicationStoreNamespaceOpenFailureV0,
        },
        validator_lifecycle::ValidatorLifecycleStateV1,
        AuthorizedSignerV1, ConsensusAppConfig, CONFIG_SCHEMA_V1,
    };
    use trnm_consensus_core::SafetyStateRecordLimitsV0;
    use trnm_consensus_safety_store::{
        SafetyStateStoreProfileV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
    };

    #[test]
    fn native_host_preserves_authenticated_genesis_activation_refusal_taxonomy_v0() {
        assert_eq!(
            super::map_application_store_open_failure_v0(
                ApplicationStoreNamespaceOpenFailureV0::
                    AuthenticatedGenesisApplicationActivationUnavailable,
            ),
            super::NativeConsensusApplicationHostErrorV0::
                AuthenticatedGenesisApplicationActivationUnavailable,
        );
    }

    #[test]
    fn native_host_finalization_apply_maps_store_failures_and_keeps_fail_closed_taxonomy_v0() {
        use super::map_finalization_apply_failure_v0;
        use crate::store::NativeApplicationFinalizationApplyFailureCauseV0 as Cause;

        assert_eq!(
            map_finalization_apply_failure_v0(Cause::NamespaceMismatch),
            NativeConsensusApplicationHostErrorV0::NamespaceUnavailable,
        );
        assert_eq!(
            map_finalization_apply_failure_v0(Cause::AuthorityUnavailable),
            NativeConsensusApplicationHostErrorV0::CoreAuthorityUnavailable,
        );
        assert_eq!(
            map_finalization_apply_failure_v0(Cause::AuthorityMismatch),
            NativeConsensusApplicationHostErrorV0::CoreAuthorityMismatch,
        );
        assert_eq!(
            map_finalization_apply_failure_v0(Cause::WriterUnavailable),
            NativeConsensusApplicationHostErrorV0::HostResourceUnavailable,
        );
        for cause in [Cause::DatabaseUnavailable, Cause::CommitUncertain] {
            assert_eq!(
                map_finalization_apply_failure_v0(cause),
                NativeConsensusApplicationHostErrorV0::DatabaseUnavailable,
            );
        }
        assert_eq!(
            map_finalization_apply_failure_v0(Cause::HostResourceUnavailable),
            NativeConsensusApplicationHostErrorV0::HostResourceUnavailable,
        );
        for cause in [Cause::PersistedStateMismatch, Cause::Injected] {
            assert_eq!(
                map_finalization_apply_failure_v0(cause),
                NativeConsensusApplicationHostErrorV0::PersistedStateMismatch,
            );
        }
    }

    use super::{
        NativeConsensusApplicationHostConfigV0, NativeConsensusApplicationHostErrorV0,
        NativeConsensusApplicationHostV0, PreparedNativeApplicationH1ProjectionExpectationV0,
    };

    const TEST_CHAIN: ChainId = ChainId::from_static("trnm-app-h1-deep-audit-test");
    const SAFETY_PROFILE_REF: [u8; 32] = [0x82; 32];

    struct ProtectedTestRootV0(PathBuf);

    impl ProtectedTestRootV0 {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "trnm-app-h1-deep-audit-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create protected h1 App audit root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect h1 App audit root");
            Self(path)
        }

        fn path(&self) -> &Path {
            self.0.as_path()
        }
    }

    impl Drop for ProtectedTestRootV0 {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct StrictH1FixtureV0 {
        keys: Vec<(ValidatorId, SigningKey)>,
        parameters: ConsensusParametersV0,
        validator_set: ValidatorSet,
        core_config: CoreConfig,
    }

    impl StrictH1FixtureV0 {
        fn new() -> Self {
            let parameters = ConsensusParametersV0::reference_shadow_v0();
            let keys = (1_u8..=4)
                .map(|index| {
                    (
                        ValidatorId::new([index; 32]),
                        SigningKey::from_bytes(&[index.saturating_add(60); 32]),
                    )
                })
                .collect::<Vec<_>>();
            let validators = keys
                .iter()
                .map(|(id, key)| {
                    Validator::new(
                        *id,
                        ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                        VotingPower::new(1).expect("positive h1 test voting power"),
                    )
                    .expect("valid h1 test validator")
                })
                .collect();
            let validator_set = ValidatorSet::new(
                GenesisHash::new([0x91; 32]),
                TEST_CHAIN,
                ProtocolVersion::V0,
                Epoch::new(0),
                parameters.hash(),
                validators,
            )
            .expect("valid h1 test validator set");
            let core_config =
                CoreConfig::new(keys[0].0, validator_set.clone(), parameters, 0, 32, 64)
                    .expect("valid h1 test Core config");
            Self {
                keys,
                parameters,
                validator_set,
                core_config,
            }
        }

        fn sign(&self, author: ValidatorId, root: SigningRoot) -> SignatureBytes {
            let key = self
                .keys
                .iter()
                .find_map(|(id, key)| (*id == author).then_some(key))
                .expect("h1 author has a fixture key");
            SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes())
        }

        fn genesis_qc(&self) -> GenesisQcV0 {
            GenesisQcV0::new(
                self.validator_set.genesis_hash(),
                self.validator_set.chain_id(),
                &self.validator_set,
            )
            .expect("valid h1 genesis QC")
        }

        fn proposal(
            &self,
            justify: QcReferenceV0,
            view: u64,
            state_root: StateRoot,
        ) -> SignedProposalV0 {
            let parent = justify.qc_ref();
            let height = parent.height().get().checked_add(1).expect("h1 height");
            let proposer = leader_for(&self.validator_set, View::new(view));
            let application_payload =
                ApplicationPayloadV0::new(Vec::new()).expect("empty h1 application payload");
            let receipts = ExecutionReceiptsV0::new(&application_payload, Vec::new())
                .expect("empty h1 execution receipts");
            let body =
                BlockBodyV0::new(application_payload, Vec::new()).expect("empty h1 block body");
            let header = BlockHeader::new(
                self.validator_set.genesis_hash(),
                self.validator_set.chain_id(),
                self.validator_set.protocol_version(),
                self.validator_set.epoch(),
                View::new(view),
                Height::new(height),
                BlockKind::Regular,
                parent.block_id(),
                proposer,
                self.validator_set.id(),
                self.validator_set.consensus_parameters_hash(),
                body.payload_root().expect("h1 payload root"),
                state_root,
                receipts.receipts_root().expect("h1 receipts root"),
                body.evidence_root().expect("h1 evidence root"),
                height.saturating_mul(100),
                None,
            )
            .expect("valid h1 header");
            let block = Block::new(
                header,
                body.application_payload()
                    .try_cev0_bytes()
                    .expect("encode empty h1 application payload"),
                Vec::new(),
            )
            .expect("valid h1 block");
            let root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
                .expect("h1 proposal signing root");
            let witness = ProposalWitnessV0::new(
                block.header(),
                justify,
                None,
                None,
                self.sign(proposer, root),
                &self.validator_set,
                None,
                &self.parameters,
                parent.height().get().saturating_mul(100),
            )
            .expect("valid h1 proposal witness");
            SignedProposalV0::new(
                block,
                witness,
                &self.validator_set,
                None,
                &self.parameters,
                parent.height().get().saturating_mul(100),
            )
            .expect("valid h1 signed proposal")
        }

        fn parent_qc(&self, proposal: &SignedProposalV0) -> QuorumCertificate {
            let header = proposal.block().header();
            let votes = self
                .keys
                .iter()
                .take(3)
                .map(|(author, _)| {
                    let root = Vote::signing_root_for_set(
                        &self.validator_set,
                        header.view(),
                        header.height(),
                        proposal.block().id(),
                    )
                    .expect("h1 vote signing root");
                    Vote::new(
                        self.validator_set.chain_id(),
                        self.validator_set.protocol_version(),
                        self.validator_set.epoch(),
                        header.view(),
                        header.height(),
                        proposal.block().id(),
                        self.validator_set.id(),
                        *author,
                        self.sign(*author, root),
                        &self.validator_set,
                    )
                    .expect("valid h1 vote")
                })
                .collect();
            QuorumCertificate::new(
                self.validator_set.chain_id(),
                self.validator_set.protocol_version(),
                self.validator_set.epoch(),
                header.view(),
                header.height(),
                proposal.block().id(),
                self.validator_set.id(),
                votes,
                &self.validator_set,
            )
            .expect("valid h1 quorum certificate")
        }

        fn finality_proof_and_successors(
            &self,
            h1_root: [u8; 32],
            h2_root: [u8; 32],
            h3_root: [u8; 32],
        ) -> (FinalityProofV0, SignedProposalV0, SignedProposalV0) {
            let h1 = self.proposal(
                QcReferenceV0::genesis_anchor(self.genesis_qc()),
                1,
                StateRoot::new(h1_root),
            );
            let q1 = self.parent_qc(&h1);
            let h2 = self.proposal(
                QcReferenceV0::ordinary(q1.clone()),
                2,
                StateRoot::new(h2_root),
            );
            let q2 = self.parent_qc(&h2);
            let h3 = self.proposal(
                QcReferenceV0::ordinary(q2.clone()),
                3,
                StateRoot::new(h3_root),
            );
            let q3 = self.parent_qc(&h3);
            let certified_h1 = CertifiedHeaderV0::from_signed_proposal(
                h1,
                q1,
                &self.validator_set,
                None,
                &self.parameters,
                0,
            )
            .expect("certify h1");
            let certified_h2 = CertifiedHeaderV0::from_signed_proposal(
                h2.clone(),
                q2,
                &self.validator_set,
                None,
                &self.parameters,
                100,
            )
            .expect("certify h2");
            let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
                h3.clone(),
                q3,
                &self.validator_set,
                None,
                &self.parameters,
                200,
            )
            .expect("certify h3");
            let proof = FinalityProofV0::new(
                certified_h1,
                certified_h2,
                certified_h3,
                &self.validator_set,
                None,
                &self.parameters,
                0,
            )
            .expect("valid h1 finality proof");
            (proof, h2, h3)
        }
    }

    struct H1ApplicationProjectionFixtureV0 {
        _root: ProtectedTestRootV0,
        core_config: CoreConfig,
        safety_state: Box<SafetyState>,
        safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
        database_path: PathBuf,
        host: NativeConsensusApplicationHostV0,
        application: ConsensusAppConfig,
        child: SignedProposalV0,
        grandchild: SignedProposalV0,
        expectation: Option<PreparedNativeApplicationH1ProjectionExpectationV0>,
    }

    impl H1ApplicationProjectionFixtureV0 {
        fn new(mutate_lifecycle: impl FnOnce(&mut ValidatorLifecycleStateV1)) -> Self {
            let root = ProtectedTestRootV0::new();
            let status_path = root.path().join("application-state.json");
            let consensus = StrictH1FixtureV0::new();
            let application = ConsensusAppConfig {
                schema: CONFIG_SCHEMA_V1.to_string(),
                chain_id: TEST_CHAIN.as_str().to_string(),
                authorized_signers: vec![AuthorizedSignerV1 {
                    signer_id: "did:operator:h1-deep-audit-test".to_string(),
                    signer_role: "operator".to_string(),
                    public_key_hex: hex::encode(consensus.keys[0].1.verifying_key().to_bytes()),
                }],
                poco_authority: None,
                state_path: Some(status_path.clone()),
            };
            let expectation =
                NativeConsensusApplicationHostV0::prepare_h1_projection_expectation_v0(
                    &consensus.core_config,
                    &application,
                )
                .expect("prepare independent h1 App projection expectation");
            let mut actual_lifecycle = native_application_h1_validator_lifecycle_expectation_v0(
                &consensus.core_config,
                &application,
            )
            .expect("derive actual baseline h1 lifecycle");
            mutate_lifecycle(&mut actual_lifecycle);
            actual_lifecycle
                .validate()
                .expect("mutated h1 lifecycle remains internally valid");
            let (mut authenticated, actual_root) =
                native_application_h1_trusted_base_v0(1, &consensus.core_config, &actual_lifecycle)
                    .expect("derive actual lifecycle and active-configuration root");
            let h2_plan = authenticated
                .plan_put_value_set(2, Vec::new())
                .expect("plan exact empty h2 state root");
            let h2_root = h2_plan.root_hash.0;
            authenticated
                .apply(h2_plan)
                .expect("advance exact h2 speculative tree");
            let h3_root = authenticated
                .plan_put_value_set(3, Vec::new())
                .expect("plan exact empty h3 state root")
                .root_hash
                .0;
            let (proof, child, grandchild) =
                consensus.finality_proof_and_successors(actual_root.0, h2_root, h3_root);
            let prepared = Core::prepare_h1_state_sync_bootstrap_v0(
                consensus.core_config.clone(),
                proof,
                &StrictEd25519Verifier,
            )
            .expect("prepare authenticated h1 state");
            let safety_profile = SafetyStateStoreProfileV0::new(
                consensus.core_config.clone(),
                SAFETY_PROFILE_REF,
                SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
                    .expect("construct h1 Safety record limits"),
                192 * 1024 * 1024,
            )
            .expect("construct h1 Safety profile");
            let safety_store = SqliteSafetyStateStoreV0::initialize_h1_state_sync_v0(
                root.path().join("safety.sqlite3"),
                safety_profile,
                StrictEd25519Verifier,
                &prepared,
            )
            .expect("initialize authenticated h1 SafetyStore fixture");
            let h1_id = prepared
                .safety_state()
                .state_sync_anchor()
                .expect("prepared h1 has anchor")
                .proof()
                .finalized_block()
                .header()
                .id();
            let signer_policy = signer_policy_commitment(&application.authorized_signers);
            let store = ApplicationStore::open(
                &status_path,
                application.chain_id.as_str(),
                &hex::encode(signer_policy),
            )
            .expect("open fresh h1 App fixture");
            store
                .load_or_migrate()
                .expect("initialize current App schema");
            assert_eq!(
                store
                    .initialize_empty_native_trusted_base_for_recovery_test_v0(
                        h1_id,
                        1,
                        &consensus.core_config,
                        actual_lifecycle,
                    )
                    .expect("initialize h1 active-configuration TrustedBase"),
                actual_root.0,
            );
            bootstrap_native_validation_safety_binding_manifest_v0(
                &store,
                safety_store.journal_id_v0(),
                safety_store.verifier_profile_ref_v0(),
            )
            .expect("bind h1 App fixture to Safety provenance");
            drop(store);
            let database_path = application_store_database_path_v0(&status_path);
            let host = NativeConsensusApplicationHostV0::open_existing_v0(
                NativeConsensusApplicationHostConfigV0::new(
                    application.clone(),
                    safety_store.journal_id_v0(),
                    safety_store.verifier_profile_ref_v0(),
                )
                .expect("construct existing-only h1 App host config"),
            )
            .expect("open existing h1 App host before deep confirmation");
            Self {
                _root: root,
                core_config: consensus.core_config,
                safety_state: Box::new(prepared.into_safety_state()),
                safety_store,
                database_path,
                host,
                application,
                child,
                grandchild,
                expectation: Some(expectation),
            }
        }

        fn confirm(&mut self) -> Result<(), NativeConsensusApplicationHostErrorV0> {
            let session = Core::begin_state_sync_anchor_recovery_v0(
                self.core_config.clone(),
                self.safety_state.as_ref().clone(),
                &StrictEd25519Verifier,
            )
            .expect("begin exact h1 Core recovery session");
            let expectation = self
                .expectation
                .take()
                .expect("h1 projection expectation is consumed once");
            self.host
                .confirm_state_sync_anchor_v0(session.challenge(), expectation)
                .map(|confirmed| {
                    assert!(self.host.state_sync_anchor_confirmation_matches_v0(
                        session.challenge(),
                        &confirmed,
                    ));
                })
        }

        fn confirm_node_checkpoint(
            &self,
            safety_state: &SafetyState,
        ) -> Result<
            super::ConfirmedNativeApplicationNodeCheckpointFactsV0,
            NativeConsensusApplicationHostErrorV0,
        > {
            let safety = self
                .safety_store
                .confirm_node_checkpoint_head_exact_v0(safety_state)
                .map_err(|_| NativeConsensusApplicationHostErrorV0::SafetyStateMismatch)?;
            self.host.confirm_node_checkpoint_facts_v0(&safety)
        }

        fn safety_checkpoint_facts(
            &self,
        ) -> trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0 {
            self.safety_store
                .confirm_node_checkpoint_head_exact_v0(&self.safety_state)
                .expect("confirm exact fixture Safety head")
        }

        fn durable_namespace_bytes(&self) -> Vec<(PathBuf, Vec<u8>)> {
            vec![(
                native_validation_safety_binding_manifest_path_v0(&self.database_path)
                    .expect("derive h1 App Safety binding path"),
                fs::read(
                    native_validation_safety_binding_manifest_path_v0(&self.database_path)
                        .expect("derive h1 App Safety binding path"),
                )
                .expect("read h1 App Safety binding bytes"),
            )]
        }

        fn logical_database_snapshot(&self) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
            // SQLite READ_ONLY on a WAL database may still maintain SHM or
            // header bookkeeping, so this test does not overclaim byte-level
            // namespace immutability.  It snapshots every non-internal table,
            // including metadata, head, lifecycle, JMT, domain, replay,
            // validation, overlay, receipt, and accounting state.  The
            // separately pinned Safety-binding sidecar remains byte-exact.
            let connection = Connection::open(&self.database_path)
                .expect("open h1 App database for complete logical snapshot");
            let mut table_statement = connection
                .prepare(
                    "SELECT name FROM sqlite_master
                     WHERE type='table' AND name NOT LIKE 'sqlite_%'
                     ORDER BY name",
                )
                .expect("prepare h1 App logical table list");
            let tables = table_statement
                .query_map([], |row| row.get::<_, String>(0))
                .expect("query h1 App logical table list")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect h1 App logical table list");
            tables
                .into_iter()
                .map(|table| {
                    let quoted = table.replace('"', "\"\"");
                    let column_count = connection
                        .prepare(&format!("SELECT * FROM \"{quoted}\" LIMIT 0"))
                        .expect("prepare h1 App table projection")
                        .column_count();
                    let order = (1..=column_count)
                        .map(|index| index.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    let query = format!("SELECT * FROM \"{quoted}\" ORDER BY {order}");
                    let mut statement = connection
                        .prepare(&query)
                        .expect("prepare h1 App canonical table query");
                    let rows = statement
                        .query_map([], |row| {
                            (0..column_count)
                                .map(|index| row.get::<_, rusqlite::types::Value>(index))
                                .collect::<rusqlite::Result<Vec<_>>>()
                        })
                        .expect("query h1 App canonical table rows")
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .expect("collect h1 App canonical table rows");
                    (table, rows)
                })
                .collect()
        }
    }

    #[test]
    fn h1_confirmation_deeply_audits_exact_lifecycle_and_active_configuration_v0() {
        let mut fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        let (manifest, active_configuration) =
            audit_native_application_h1_active_configuration_fixture_v0(&fixture.core_config)
                .expect("audit canonical h1 active configuration authoring");
        let mut active_identity = vec![1];
        active_identity.extend_from_slice(&0_u64.to_be_bytes());
        assert_eq!(manifest.cutoff_height(), Height::new(0));
        assert_eq!(manifest.entry_count(), 2);
        assert_eq!(
            active_configuration,
            vec![
                (
                    PocoSnapshotEntryKindV0::ValidatorConfiguration,
                    1,
                    active_identity.clone(),
                ),
                (
                    PocoSnapshotEntryKindV0::ConsensusParameters,
                    1,
                    active_identity,
                ),
            ]
        );
        let connection = Connection::open(&fixture.database_path)
            .expect("open h1 active-configuration projection");
        let mut statement = connection
            .prepare("SELECT key_preimage FROM auth_preimages ORDER BY key_hash")
            .expect("prepare h1 authenticated preimage query");
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query h1 authenticated preimages")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect h1 authenticated preimages");
        let mut kinds = rows
            .iter()
            .filter_map(|preimage| {
                match decode_poco_snapshot_physical_key_v0_exact(preimage)
                    .expect("decode h1 PoCO physical key")
                {
                    Some(PocoSnapshotPhysicalKeyV0::Entry { kind, .. }) => Some(kind),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        kinds.sort_unstable();
        assert_eq!(
            kinds,
            vec![
                PocoSnapshotEntryKindV0::ValidatorConfiguration,
                PocoSnapshotEntryKindV0::ConsensusParameters,
            ]
        );
        assert!(!kinds.contains(&PocoSnapshotEntryKindV0::ApplicationAuthorityState));
        drop(statement);
        drop(connection);
        fixture
            .confirm()
            .expect("exact h1 lifecycle and active configuration confirm");
    }

    #[test]
    fn h1_node_checkpoint_facts_bind_exact_provenance_and_are_stable_v0() {
        let fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        let before_logical = fixture.logical_database_snapshot();
        let before_binding = fixture.durable_namespace_bytes();
        let first = fixture
            .confirm_node_checkpoint(&fixture.safety_state)
            .expect("confirm exact h1 node-checkpoint facts");
        let first_closure = first.recovery_closure_checksum_v0();
        assert!(first.belongs_to_host_v0(&fixture.host));
        assert_eq!(
            first.safety_journal_id_v0(),
            fixture.safety_store.journal_id_v0()
        );
        assert_eq!(first.safety_verifier_profile_ref_v0(), SAFETY_PROFILE_REF);
        assert_ne!(first.host_config_ref_v0(), [0; 32]);
        assert_ne!(first.projection_profile_ref_v0(), [0; 32]);
        assert_ne!(first.safety_binding_manifest_checksum_v0(), [0; 32]);
        assert_ne!(first.committed_head_row_checksum_v0(), [0; 32]);
        assert_ne!(first_closure, [0; 32]);
        assert_eq!(
            first.block_id_v0(),
            fixture.safety_state.application_applied().block_id()
        );
        assert_eq!(first.height_v0(), 1);
        assert_eq!(
            first.state_root_v0(),
            *fixture
                .safety_state
                .state_sync_anchor()
                .expect("h1 anchor")
                .proof()
                .finalized_block()
                .header()
                .state_root()
                .as_bytes()
        );
        assert_eq!(first.view_v0(), 1);
        assert_eq!(first.timestamp_ms_v0(), 100);
        drop(first);
        let second = fixture
            .confirm_node_checkpoint(&fixture.safety_state)
            .expect("repeat exact h1 node-checkpoint confirmation");
        assert_eq!(second.recovery_closure_checksum_v0(), first_closure);
        assert_eq!(fixture.logical_database_snapshot(), before_logical);
        assert_eq!(fixture.durable_namespace_bytes(), before_binding);
    }

    #[test]
    fn h1_node_checkpoint_rejects_foreign_same_revision_safety_v0() {
        let fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        let foreign = H1ApplicationProjectionFixtureV0::new(|lifecycle| {
            lifecycle.governance.signer_id = "did:operator:foreign-node-checkpoint".to_string();
        });
        assert_eq!(
            fixture.safety_state.revision(),
            foreign.safety_state.revision()
        );
        assert_ne!(
            fixture.safety_state.application_applied().block_id(),
            foreign.safety_state.application_applied().block_id()
        );
        let foreign_safety = foreign.safety_checkpoint_facts();
        assert!(matches!(
            fixture
                .host
                .confirm_node_checkpoint_facts_v0(&foreign_safety),
            Err(NativeConsensusApplicationHostErrorV0::InvalidSafetyProvenance)
        ));
    }

    #[test]
    fn h1_node_checkpoint_frozen_recovery_closure_vector_v0() {
        let fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        let confirmed = fixture
            .confirm_node_checkpoint(&fixture.safety_state)
            .expect("confirm frozen h1 node-checkpoint facts");
        assert_eq!(
            hex::encode(confirmed.recovery_closure_checksum_v0()),
            "ba226eab2adeeb0d8555cca76b0f75c32c52fb095189e77c404ffbf808e81e22"
        );
    }

    #[test]
    fn h1_node_checkpoint_rejects_extra_replay_rows_read_only_v0() {
        for sql in [
            "INSERT INTO command_ids(command_id) VALUES ('foreign-command')",
            "INSERT INTO signer_nonces(signer_id, nonce) VALUES ('foreign-signer', X'0000000000000001')",
        ] {
            let fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
            let connection = Connection::open(&fixture.database_path)
                .expect("open raw h1 App database for replay-index tamper");
            assert_eq!(connection.execute(sql, []).expect("insert replay tamper"), 1);
            drop(connection);
            let before_logical = fixture.logical_database_snapshot();
            let before_binding = fixture.durable_namespace_bytes();
            assert!(matches!(
                fixture.confirm_node_checkpoint(&fixture.safety_state),
                Err(NativeConsensusApplicationHostErrorV0::SafetyStateMismatch)
            ));
            assert_eq!(fixture.logical_database_snapshot(), before_logical);
            assert_eq!(fixture.durable_namespace_bytes(), before_binding);
        }
    }

    #[test]
    fn h1_node_checkpoint_rejects_representative_physical_carrier_tamper_v0() {
        for (label, sql) in [
            ("head", "UPDATE native_committed_head_v0 SET row_checksum=zeroblob(32)"),
            ("lifecycle", "UPDATE validator_lifecycle SET state_json=X'00' WHERE singleton=1"),
            ("preimage", "UPDATE auth_preimages SET key_preimage=X'00' WHERE rowid=(SELECT rowid FROM auth_preimages LIMIT 1)"),
            ("value", "UPDATE auth_values SET value=X'00' WHERE rowid=(SELECT rowid FROM auth_values WHERE is_deleted=0 LIMIT 1)"),
            ("node", "UPDATE auth_nodes SET node=X'00' WHERE rowid=(SELECT rowid FROM auth_nodes LIMIT 1)"),
        ] {
            let fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
            let connection = Connection::open(&fixture.database_path)
                .expect("open raw h1 App database for checkpoint carrier tamper");
            assert_eq!(connection.execute(sql, []).expect("tamper App carrier"), 1);
            drop(connection);
            let before_logical = fixture.logical_database_snapshot();
            let before_binding = fixture.durable_namespace_bytes();
            let result = fixture.confirm_node_checkpoint(&fixture.safety_state);
            assert!(
                matches!(
                result,
                Err(NativeConsensusApplicationHostErrorV0::SafetyStateMismatch)
                    | Err(NativeConsensusApplicationHostErrorV0::PersistedStateMismatch)
                    | Err(NativeConsensusApplicationHostErrorV0::DatabaseUnavailable)
                    | Err(NativeConsensusApplicationHostErrorV0::NamespaceUnavailable)
                ),
                "tampered {label} carrier unexpectedly returned {result:?}"
            );
            assert_eq!(fixture.logical_database_snapshot(), before_logical);
            assert_eq!(fixture.durable_namespace_bytes(), before_binding);
        }
    }

    #[test]
    fn h1_node_checkpoint_rejects_noncanonical_or_unreachable_jmt_rows_v0() {
        for (label, sql) in [
            (
                "historical root",
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (X'0000000000000000', zeroblob(32))",
            ),
            (
                "stale node index",
                "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key) SELECT X'0000000000000002', node_key FROM auth_nodes LIMIT 1",
            ),
            (
                "stale value index",
                "INSERT INTO auth_stale_values(stale_since_version_be, key_hash, version_be) SELECT X'0000000000000002', key_hash, version_be FROM auth_values LIMIT 1",
            ),
            (
                "unreachable value",
                "INSERT INTO auth_values(key_hash, version_be, value, is_deleted) VALUES (X'0101010101010101010101010101010101010101010101010101010101010101', X'0000000000000001', X'00', 0)",
            ),
            (
                "unreachable preimage",
                "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (X'0101010101010101010101010101010101010101010101010101010101010101', X'00')",
            ),
        ] {
            let fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
            let connection = Connection::open(&fixture.database_path)
                .expect("open raw h1 App database for canonical JMT tamper");
            assert_eq!(connection.execute(sql, []).expect("insert JMT tamper"), 1);
            drop(connection);
            let before_logical = fixture.logical_database_snapshot();
            let before_binding = fixture.durable_namespace_bytes();
            assert!(matches!(
                fixture.confirm_node_checkpoint(&fixture.safety_state),
                Err(NativeConsensusApplicationHostErrorV0::SafetyStateMismatch)
                    | Err(NativeConsensusApplicationHostErrorV0::PersistedStateMismatch)
            ), "noncanonical {label} unexpectedly minted checkpoint facts");
            assert_eq!(fixture.logical_database_snapshot(), before_logical);
            assert_eq!(fixture.durable_namespace_bytes(), before_binding);
        }

        let fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        let connection = Connection::open(&fixture.database_path)
            .expect("open raw h1 App database for unreachable-node tamper");
        let unreachable_node_key = (0_u8..=u8::MAX)
            .find_map(|byte| {
                let path: NibblePath = [byte >> 4, byte & 0x0f]
                    .into_iter()
                    .map(Into::into)
                    .collect();
                let key = borsh::to_vec(&NodeKey::new(1, path))
                    .expect("encode candidate unreachable h1 NodeKey");
                let count = connection
                    .query_row(
                        "SELECT COUNT(*) FROM auth_nodes WHERE node_key=?1",
                        [key.as_slice()],
                        |row| row.get::<_, u64>(0),
                    )
                    .expect("check candidate unreachable h1 NodeKey");
                (count == 0).then_some(key)
            })
            .expect("h1 tree leaves one nonconflicting child NodeKey");
        let valid_node: Vec<u8> = connection
            .query_row(
                "SELECT node FROM auth_nodes ORDER BY node_key LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("read one valid h1 JMT node encoding");
        assert_eq!(
            connection
                .execute(
                    "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
                    rusqlite::params![unreachable_node_key, valid_node],
                )
                .expect("insert validly encoded unreachable h1 JMT node"),
            1
        );
        drop(connection);
        let before_logical = fixture.logical_database_snapshot();
        let before_binding = fixture.durable_namespace_bytes();
        assert!(
            matches!(
                fixture.confirm_node_checkpoint(&fixture.safety_state),
                Err(NativeConsensusApplicationHostErrorV0::SafetyStateMismatch)
                    | Err(NativeConsensusApplicationHostErrorV0::PersistedStateMismatch)
            ),
            "validly encoded unreachable node unexpectedly minted checkpoint facts"
        );
        assert_eq!(fixture.logical_database_snapshot(), before_logical);
        assert_eq!(fixture.durable_namespace_bytes(), before_binding);
    }

    #[test]
    fn h1_confirmation_rejects_physical_lifecycle_tamper_read_only_v0() {
        let mut fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        let connection = Connection::open(&fixture.database_path)
            .expect("open raw h1 App database for lifecycle tamper");
        let lifecycle_bytes: Vec<u8> = connection
            .query_row(
                "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("read physical h1 lifecycle");
        let mut lifecycle: ValidatorLifecycleStateV1 =
            serde_json::from_slice(&lifecycle_bytes).expect("decode physical h1 lifecycle");
        lifecycle.governance_sequence = 1;
        connection
            .execute(
                "UPDATE validator_lifecycle SET state_json=?1 WHERE singleton=1",
                [serde_json::to_vec(&lifecycle).expect("encode tampered h1 lifecycle")],
            )
            .expect("tamper physical h1 lifecycle only");
        drop(connection);
        let before_logical = fixture.logical_database_snapshot();
        let before_binding = fixture.durable_namespace_bytes();
        assert_eq!(
            fixture.confirm(),
            Err(NativeConsensusApplicationHostErrorV0::PersistedStateMismatch)
        );
        assert_eq!(
            fixture.logical_database_snapshot(),
            before_logical,
            "failed physical-lifecycle audit mutated logical App state"
        );
        assert_eq!(
            fixture.durable_namespace_bytes(),
            before_binding,
            "failed physical-lifecycle audit mutated the pinned Safety binding"
        );
    }

    fn assert_jmt_tamper_is_rejected_read_only_v0(sql: &str, expected_rows: usize) {
        let mut fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        let connection = Connection::open(&fixture.database_path)
            .expect("open raw h1 App database for JMT tamper");
        assert_eq!(
            connection.execute(sql, []).expect("tamper one h1 JMT cut"),
            expected_rows
        );
        drop(connection);
        let before_logical = fixture.logical_database_snapshot();
        let before_binding = fixture.durable_namespace_bytes();
        assert_eq!(
            fixture.confirm(),
            Err(NativeConsensusApplicationHostErrorV0::PersistedStateMismatch)
        );
        assert_eq!(
            fixture.logical_database_snapshot(),
            before_logical,
            "failed h1 deep audit mutated logical App state"
        );
        assert_eq!(
            fixture.durable_namespace_bytes(),
            before_binding,
            "failed h1 deep audit mutated the pinned Safety binding"
        );
    }

    #[test]
    fn h1_confirmation_rejects_jmt_preimage_value_and_node_tamper_read_only_v0() {
        for (sql, expected_rows) in [
            (
                "UPDATE auth_preimages SET key_preimage=X'00' WHERE rowid=(SELECT rowid FROM auth_preimages LIMIT 1)",
                1,
            ),
            (
                "UPDATE auth_values SET value=X'00' WHERE rowid=(SELECT rowid FROM auth_values WHERE is_deleted=0 LIMIT 1)",
                1,
            ),
            (
                "UPDATE auth_nodes SET node=X'00' WHERE rowid=(SELECT rowid FROM auth_nodes LIMIT 1)",
                1,
            ),
        ] {
            assert_jmt_tamper_is_rejected_read_only_v0(sql, expected_rows);
        }
    }

    fn assert_internally_consistent_profile_drift_rejected_v0(
        mutate: impl FnOnce(&mut ValidatorLifecycleStateV1),
    ) {
        let mut fixture = H1ApplicationProjectionFixtureV0::new(mutate);
        let before_logical = fixture.logical_database_snapshot();
        let before_binding = fixture.durable_namespace_bytes();
        assert_eq!(
            fixture.confirm(),
            Err(NativeConsensusApplicationHostErrorV0::PersistedStateMismatch)
        );
        assert_eq!(
            fixture.logical_database_snapshot(),
            before_logical,
            "failed profile audit mutated logical App state"
        );
        assert_eq!(
            fixture.durable_namespace_bytes(),
            before_binding,
            "failed profile audit mutated the pinned Safety binding"
        );
    }

    #[test]
    fn h1_confirmation_rejects_internally_consistent_pinned_profile_drift_v0() {
        assert_internally_consistent_profile_drift_rejected_v0(|lifecycle| {
            for validator in &mut lifecycle.active_validators {
                validator.voting_power = 2;
            }
        });
        assert_internally_consistent_profile_drift_rejected_v0(|lifecycle| {
            lifecycle.governance.signer_id = "did:operator:foreign-h1-governance".to_string();
        });
        assert_internally_consistent_profile_drift_rejected_v0(|lifecycle| {
            lifecycle.authorized_signers_hash_hex = "ab".repeat(32);
        });
    }

    struct ExactAnchorSuccessorAppReconcilerV0<'a> {
        host: &'a NativeConsensusApplicationHostV0,
        confirmed: &'a super::ConfirmedNativeApplicationStateSyncAnchorSuccessorsV0,
    }

    impl StateSyncAnchorSuccessorRecoveryReconcilerV0 for ExactAnchorSuccessorAppReconcilerV0<'_> {
        fn reconcile_state_sync_anchor_successors_v0(
            &mut self,
            challenge: &StateSyncAnchorSuccessorRecoveryChallengeV0,
        ) -> bool {
            self.host
                .state_sync_anchor_successor_confirmation_matches_v0(challenge, self.confirmed)
        }
    }

    fn persist_anchor_successor_obligation_and_take_validation_v0(
        replay: &mut trnm_consensus_core::StateSyncAnchorSuccessorReplayV0,
        safety_store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    ) -> Effect {
        let mut effects = replay
            .step_next_proposal_v0(&StrictEd25519Verifier)
            .expect("register exact anchored successor proposal");
        assert_eq!(effects.len(), 1);
        let Effect::PersistSafetyState(persistence) = effects.pop().expect("one persistence")
        else {
            panic!("anchored successor proposal did not emit exact persistence")
        };
        safety_store
            .persist_exact_v0(&persistence, &SafetyTransitionContextV0::ordinary())
            .expect("persist anchored successor obligation");
        let mut validation = replay
            .step_storage_ack_v0(persistence.barrier(), &StrictEd25519Verifier)
            .expect("release exact anchored successor validation");
        assert_eq!(validation.len(), 1);
        validation.pop().expect("one exact validation effect")
    }

    #[test]
    fn anchor_successor_real_h2_h3_pipeline_uses_exact_speculative_parent_and_k_cuts_v0() {
        let mut fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        assert_eq!(
            *fixture.child.block().header().state_root().as_bytes(),
            *fixture.grandchild.block().header().state_root().as_bytes(),
            "the no-op h3 planner must preserve the exact h2 speculative root"
        );
        let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &fixture.core_config,
            &fixture.safety_state,
            fixture.child.clone(),
            fixture.grandchild.clone(),
            &StrictEd25519Verifier,
        )
        .expect("authenticate exact h2/h3 bodies");
        let session = Core::begin_state_sync_anchor_successor_recovery_v0(
            fixture.core_config.clone(),
            fixture.safety_state.as_ref().clone(),
            bundle,
            &StrictEd25519Verifier,
        )
        .expect("begin stable revision-zero successor recovery");
        let initial = fixture
            .host
            .confirm_state_sync_anchor_successors_v0(
                session.challenge(),
                fixture
                    .expectation
                    .take()
                    .expect("consume exact h1 projection expectation"),
                None,
            )
            .expect("confirm exact empty revision-zero App cut");
        let mut reconciler = ExactAnchorSuccessorAppReconcilerV0 {
            host: &fixture.host,
            confirmed: &initial,
        };
        let mut replay = session
            .reconcile_and_activate_v0(&mut reconciler)
            .expect("activate exact anchored successor replay owner");
        fixture
            .safety_store
            .bind_core_v0(replay.safety_state_persistence_binding_v0())
            .expect("bind SafetyStore to successor replay owner");
        fixture
            .host
            .install_state_sync_anchor_successor_seal_authority_v0(&replay)
            .expect("install seal-only authority at h1");

        let h2_effect = persist_anchor_successor_obligation_and_take_validation_v0(
            &mut replay,
            &mut fixture.safety_store,
        );
        let h2 = fixture
            .host
            .complete_state_sync_anchor_successor_empty_synced_validation_v0(
                &mut replay,
                &mut fixture.safety_store,
                h2_effect,
                &StrictEd25519Verifier,
            )
            .expect("close real h2 P/D/C/K/StorageAck");
        assert_eq!(h2.block_id(), fixture.child.block().id());
        assert_eq!(h2.accepted_core_revision(), 2);
        assert!(h2.job_acked() && h2.effects_empty() && !h2.seal_authority_retired());

        let h2_head = fixture
            .safety_store
            .confirmed_native_valid_head_v0()
            .expect("authenticate revision-two native Valid head");
        let h2_bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &fixture.core_config,
            h2_head.state(),
            fixture.child.clone(),
            fixture.grandchild.clone(),
            &StrictEd25519Verifier,
        )
        .expect("authenticate successor bodies at revision two");
        let h2_session = Core::begin_state_sync_anchor_successor_recovery_v0(
            fixture.core_config.clone(),
            h2_head.state().clone(),
            h2_bundle,
            &StrictEd25519Verifier,
        )
        .expect("begin stable revision-two confirmation session");
        let h2_confirmation = fixture
            .host
            .confirm_state_sync_anchor_successors_v0(
                h2_session.challenge(),
                NativeConsensusApplicationHostV0::prepare_h1_projection_expectation_v0(
                    &fixture.core_config,
                    &fixture.application,
                )
                .expect("prepare fresh h1 expectation for revision-two audit"),
                Some(&h2_head),
            )
            .expect("K-only revision-two App cut reconciles exactly");
        assert!(fixture
            .host
            .state_sync_anchor_successor_confirmation_matches_v0(
                h2_session.challenge(),
                &h2_confirmation,
            ));

        let h3_effect = persist_anchor_successor_obligation_and_take_validation_v0(
            &mut replay,
            &mut fixture.safety_store,
        );
        let h3 = fixture
            .host
            .complete_state_sync_anchor_successor_empty_synced_validation_v0(
                &mut replay,
                &mut fixture.safety_store,
                h3_effect,
                &StrictEd25519Verifier,
            )
            .expect("close real h3 from the exact h2 speculative parent");
        assert_eq!(h3.block_id(), fixture.grandchild.block().id());
        assert_eq!(h3.accepted_core_revision(), 4);
        assert!(h3.job_acked() && h3.effects_empty() && h3.seal_authority_retired());
        assert_eq!(replay.safety_state().revision(), 4);

        let rev4_head = fixture
            .safety_store
            .confirmed_native_valid_head_v0()
            .expect("authenticate revision-four native Valid head");
        let rev4_bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &fixture.core_config,
            rev4_head.state(),
            fixture.child.clone(),
            fixture.grandchild.clone(),
            &StrictEd25519Verifier,
        )
        .expect("authenticate successor bodies at revision four");
        let rev4_session = Core::begin_state_sync_anchor_successor_recovery_v0(
            fixture.core_config.clone(),
            rev4_head.state().clone(),
            rev4_bundle,
            &StrictEd25519Verifier,
        )
        .expect("begin stable revision-four confirmation session");
        let rev4_confirmation = fixture
            .host
            .confirm_state_sync_anchor_successors_v0(
                rev4_session.challenge(),
                NativeConsensusApplicationHostV0::prepare_h1_projection_expectation_v0(
                    &fixture.core_config,
                    &fixture.application,
                )
                .expect("prepare fresh h1 expectation for revision-four audit"),
                Some(&rev4_head),
            )
            .expect("two-K revision-four App cut reconciles exactly");
        fixture
            .host
            .confirm_rev4_historical_h2_safety_v0(
                rev4_session.challenge(),
                &rev4_confirmation,
                &fixture.safety_store,
            )
            .expect("join fixed-snapshot h2 preimage to reconstructed Safety prefix");
    }

    #[test]
    fn anchor_successor_rev0_rejects_same_height_root_foreign_block_id_v0() {
        let mut fixture = H1ApplicationProjectionFixtureV0::new(|_| {});
        let foreign = BlockId::new([0xf1; 32]);
        assert_ne!(
            foreign,
            fixture.safety_state.application_applied().block_id()
        );
        let connection = Connection::open(&fixture.database_path)
            .expect("open h1 head for foreign BlockId tamper");
        let height: Vec<u8> = connection
            .query_row(
                "SELECT height_be FROM native_committed_head_v0 WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("read exact h1 head height");
        let root: Vec<u8> = connection
            .query_row(
                "SELECT state_root FROM native_committed_head_v0 WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("read exact h1 head root");
        let row_checksum = trnm_finality_types::hash_domain(
            "trnm.consensus-app.native-committed-head-row.v0",
            &[
                &0_u16.to_be_bytes(),
                &[0],
                foreign.as_bytes(),
                &height,
                &root,
                &0_u64.to_be_bytes(),
                &0_u64.to_be_bytes(),
                &[0; 32],
                &[0; 32],
                &[0; 32],
            ],
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE native_committed_head_v0 SET block_id=?1, row_checksum=?2 WHERE singleton=1",
                    rusqlite::params![foreign.as_bytes().as_slice(), row_checksum.as_slice()],
                )
                .expect("install internally checksummed foreign h1 BlockId"),
            1,
        );
        drop(connection);
        let bundle = Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &fixture.core_config,
            &fixture.safety_state,
            fixture.child.clone(),
            fixture.grandchild.clone(),
            &StrictEd25519Verifier,
        )
        .expect("authenticate exact successor bodies");
        let session = Core::begin_state_sync_anchor_successor_recovery_v0(
            fixture.core_config.clone(),
            fixture.safety_state.as_ref().clone(),
            bundle,
            &StrictEd25519Verifier,
        )
        .expect("begin exact rev0 successor session");
        assert!(matches!(
            fixture.host.confirm_state_sync_anchor_successors_v0(
                session.challenge(),
                fixture
                    .expectation
                    .take()
                    .expect("consume exact h1 projection expectation"),
                None,
            ),
            Err(NativeConsensusApplicationHostErrorV0::PersistedStateMismatch)
                | Err(NativeConsensusApplicationHostErrorV0::SafetyStateMismatch)
        ));
    }

    // TODO(h1-state-projection-v1): add a production bootstrap/import fixture
    // that can build an internally consistent non-empty object and PoCO JMT.
    // The deep audit already rejects both for this fresh-only expectation;
    // this TODO is test-carrier coverage, not an unguarded production branch.
}
