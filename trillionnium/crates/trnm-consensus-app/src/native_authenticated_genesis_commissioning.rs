//! Dedicated inert owner for authenticated-genesis application commissioning.
//!
//! This module deliberately does not expose `ApplicationStore`, the ordinary
//! consensus application host, Core, application authorities, or a raw-parts
//! conversion. Its only successful result is a non-cloneable comparison
//! capability for one exact live schema-v14 namespace.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use trnm_consensus_core::{
    AuthenticatedGenesisApplicationH1CompletedV0,
    AuthenticatedGenesisApplicationH1OfflineActivationBundleV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0,
    AuthenticatedGenesisApplicationH1OfflineContextFactsV0,
    AuthenticatedGenesisApplicationH1OfflinePhaseV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReconcilerV0,
    AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
    AuthenticatedGenesisApplicationH1ValidationRequestV0, AuthenticatedGenesisApplicationParentV0,
    CoreConfig, PreparedAuthenticatedGenesisApplicationBootstrapV0,
};
use trnm_consensus_safety_store::{
    ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
    ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0, SafetyStoreErrorV0,
    SqliteSafetyStateStoreV0,
};
use trnm_consensus_types::{SignatureVerifier, SignedProposalV0};

use super::{
    native_validation_host_config_ref_from_application_v0,
    prepare_native_authenticated_genesis_h1_inactive_expectation_v0,
    validate_authenticated_genesis_h1_obligation_request_shape_v0, ApplicationStore,
    ApplicationStoreFileIdentityV0, ApplicationStoreNamespaceOpenFailureV0,
    NativeApplicationFinalizationApplyFailureCauseV0,
    NativeAuthenticatedGenesisCommissioningBindingV0,
    NativeAuthenticatedGenesisCommissioningDecisionV0,
    NativeAuthenticatedGenesisH1InactiveExpectationV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
    NativeAuthenticatedGenesisH1StableApplicationCutV0, NativeValidationReservationFailureCauseV0,
    NativeValidationValidJournalTransitionFailureCauseV0,
};
use crate::ConsensusAppConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthenticatedGenesisApplicationCommissioningDispositionV0 {
    Commissioned,
    Existing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthenticatedGenesisApplicationCommissioningErrorV0 {
    InvalidConfig,
    StatePathRequired,
    StatePathNotAbsolute,
    NamespaceUnavailable,
    CleanCheckpointRequired,
    PersistedStateMismatch,
    SafetyCapabilityMismatch,
    HostResourceUnavailable,
    DatabaseUnavailable,
}

impl fmt::Display for NativeAuthenticatedGenesisApplicationCommissioningErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => {
                "authenticated-genesis application commissioning config is invalid"
            }
            Self::StatePathRequired => {
                "authenticated-genesis application commissioning requires a state path"
            }
            Self::StatePathNotAbsolute => {
                "authenticated-genesis application state path must be absolute"
            }
            Self::NamespaceUnavailable => {
                "authenticated-genesis application namespace is unavailable"
            }
            Self::CleanCheckpointRequired => {
                "authenticated-genesis application commissioning requires a clean checkpoint with absent-or-zero SQLite sidecars"
            }
            Self::PersistedStateMismatch => {
                "authenticated-genesis application persisted state differs"
            }
            Self::SafetyCapabilityMismatch => {
                "authenticated-genesis Safety capability is foreign or stale"
            }
            Self::HostResourceUnavailable => {
                "authenticated-genesis application host resources are unavailable"
            }
            Self::DatabaseUnavailable => {
                "authenticated-genesis application database is unavailable"
            }
        })
    }
}

impl std::error::Error for NativeAuthenticatedGenesisApplicationCommissioningErrorV0 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthenticatedGenesisH1OfflineValidationErrorV0 {
    CommissioningCapabilityMismatch,
    NamespaceUnavailable,
    PersistedStateMismatch,
    CoreAuthorityMismatch,
    CoreObligationRejected,
    SafetyBindingMismatch,
    ObligationPersistenceUnavailable,
    ValidationRequestMismatch,
    CoreRejectedCallback,
    SafetyPreflightMismatch,
    ApplicationDeliveryUnavailable,
    CoreDeliverySealMismatch,
    SafetyPersistenceUnavailable,
    ApplicationAcknowledgementUnavailable,
    CoreCompletionAcknowledgementMismatch,
    ReservationUnavailable,
    AuthenticatedOpenBodySourceUnavailable,
    AuthenticatedOpenParentStateMissing,
    AuthenticatedOpenParentStateUnauthenticated,
    AuthenticatedOpenDatabaseUnavailable,
    AuthenticatedOpenStorageUnavailable,
    AuthenticatedOpenHostResourceUnavailable,
    AuthenticatedOpenReservationCapacityUnavailable,
    AuthenticatedOpenDeterministicallyInvalid,
    AuthenticatedOpenInvariant,
    PlanningUnavailable,
    DurablePreparationUnavailable,
    DurableSealUnavailable,
    UnsupportedRecoveryState,
}

impl fmt::Display for NativeAuthenticatedGenesisH1OfflineValidationErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CommissioningCapabilityMismatch => {
                "authenticated-genesis h1 commissioning capability is foreign or stale"
            }
            Self::NamespaceUnavailable => {
                "authenticated-genesis h1 application namespace is unavailable"
            }
            Self::PersistedStateMismatch => "authenticated-genesis h1 application closure differs",
            Self::CoreAuthorityMismatch => "authenticated-genesis h1 Core seal authority differs",
            Self::CoreObligationRejected => "authenticated-genesis h1 Core obligation was rejected",
            Self::SafetyBindingMismatch => "authenticated-genesis h1 Safety binding differs",
            Self::ObligationPersistenceUnavailable => {
                "authenticated-genesis h1 obligation persistence is unavailable"
            }
            Self::ValidationRequestMismatch => {
                "authenticated-genesis h1 validation request differs"
            }
            Self::CoreRejectedCallback => {
                "authenticated-genesis h1 Core rejected the App-sealed callback"
            }
            Self::SafetyPreflightMismatch => "authenticated-genesis h1 Safety preflight differs",
            Self::ApplicationDeliveryUnavailable => {
                "authenticated-genesis h1 application delivery is unavailable"
            }
            Self::CoreDeliverySealMismatch => {
                "authenticated-genesis h1 App Delivered facts failed the Core seal join"
            }
            Self::SafetyPersistenceUnavailable => {
                "authenticated-genesis h1 Safety persistence is unavailable"
            }
            Self::ApplicationAcknowledgementUnavailable => {
                "authenticated-genesis h1 application acknowledgement is unavailable"
            }
            Self::CoreCompletionAcknowledgementMismatch => {
                "authenticated-genesis h1 Core completion acknowledgement differs"
            }
            Self::ReservationUnavailable => {
                "authenticated-genesis h1 durable reservation is unavailable"
            }
            Self::AuthenticatedOpenBodySourceUnavailable => {
                "authenticated-genesis h1 canonical body source is unavailable"
            }
            Self::AuthenticatedOpenParentStateMissing => {
                "authenticated-genesis h1 parent state is unavailable"
            }
            Self::AuthenticatedOpenParentStateUnauthenticated => {
                "authenticated-genesis h1 parent state is unauthenticated"
            }
            Self::AuthenticatedOpenDatabaseUnavailable => {
                "authenticated-genesis h1 application database is unavailable"
            }
            Self::AuthenticatedOpenStorageUnavailable => {
                "authenticated-genesis h1 application storage is unavailable"
            }
            Self::AuthenticatedOpenHostResourceUnavailable => {
                "authenticated-genesis h1 host resources are unavailable"
            }
            Self::AuthenticatedOpenReservationCapacityUnavailable => {
                "authenticated-genesis h1 reservation capacity is unavailable"
            }
            Self::AuthenticatedOpenDeterministicallyInvalid => {
                "authenticated-genesis h1 open classified a deterministic invalidity"
            }
            Self::AuthenticatedOpenInvariant => {
                "authenticated-genesis h1 open violated an authenticated invariant"
            }
            Self::PlanningUnavailable => {
                "authenticated-genesis h1 exact execution planning is unavailable"
            }
            Self::DurablePreparationUnavailable => {
                "authenticated-genesis h1 durable Valid preparation is unavailable"
            }
            Self::DurableSealUnavailable => {
                "authenticated-genesis h1 durable Valid seal is unavailable"
            }
            Self::UnsupportedRecoveryState => {
                "authenticated-genesis h1 Valid recovery state is unsupported"
            }
        })
    }
}

impl std::error::Error for NativeAuthenticatedGenesisH1OfflineValidationErrorV0 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    InvalidConfig,
    NamespaceUnavailable,
    SafetyCapabilityMismatch,
    PersistedStateMismatch,
    UnsupportedRecoveryState,
    HostResourceUnavailable,
    DatabaseUnavailable,
    CommitUncertain,
}

impl fmt::Display for NativeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "authenticated-genesis h1 stable recovery config is invalid",
            Self::NamespaceUnavailable => {
                "authenticated-genesis h1 stable application namespace is unavailable"
            }
            Self::SafetyCapabilityMismatch => {
                "authenticated-genesis h1 stable Safety capability is foreign or stale"
            }
            Self::PersistedStateMismatch => {
                "authenticated-genesis h1 stable application closure differs"
            }
            Self::UnsupportedRecoveryState => {
                "authenticated-genesis h1 recovery admits only stable Delivered or Acked"
            }
            Self::HostResourceUnavailable => {
                "authenticated-genesis h1 stable recovery host resources are unavailable"
            }
            Self::DatabaseUnavailable => {
                "authenticated-genesis h1 stable recovery database is unavailable"
            }
            Self::CommitUncertain => "authenticated-genesis h1 stable D-to-K commit is uncertain",
        })
    }
}

impl std::error::Error for NativeAuthenticatedGenesisH1StableRecoveryErrorV0 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthenticatedGenesisH1StableApplicationSourceV0 {
    Delivered,
    Acked,
}

/// Exact App cut visible while the durable Core still owns the h1 validation
/// obligation. No discriminant grants callback delivery or execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0 {
    Absent,
    Reserved,
    CallbackPending,
    Delivered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {
    InvalidConfig,
    NamespaceUnavailable,
    RequestMismatch,
    PersistedStateMismatch,
    CoreActivationMismatch,
    ReexecutionUnavailable,
    DurableSealUnavailable,
    CoreRejectedCallback,
    DeliveredCutUnsupported,
    StorageUnavailable,
    HostResourceUnavailable,
    DatabaseUnavailable,
}

impl fmt::Display for NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "authenticated-genesis h1 takeover config is invalid",
            Self::NamespaceUnavailable => {
                "authenticated-genesis h1 takeover namespace is unavailable"
            }
            Self::RequestMismatch => {
                "authenticated-genesis h1 takeover request differs from the exact empty h1"
            }
            Self::PersistedStateMismatch => "authenticated-genesis h1 takeover App closure differs",
            Self::CoreActivationMismatch => {
                "authenticated-genesis h1 takeover Core owner and request differ"
            }
            Self::ReexecutionUnavailable => {
                "authenticated-genesis h1 takeover reexecution is unavailable"
            }
            Self::DurableSealUnavailable => {
                "authenticated-genesis h1 takeover durable Valid seal is unavailable"
            }
            Self::CoreRejectedCallback => {
                "authenticated-genesis h1 takeover Core rejected the sealed callback"
            }
            Self::DeliveredCutUnsupported => {
                "authenticated-genesis h1 Delivered cut requires the unified read-only takeover completion path"
            }
            Self::StorageUnavailable => "authenticated-genesis h1 takeover storage is unavailable",
            Self::HostResourceUnavailable => {
                "authenticated-genesis h1 takeover host resources are unavailable"
            }
            Self::DatabaseUnavailable => {
                "authenticated-genesis h1 takeover database is unavailable"
            }
        })
    }
}

impl std::error::Error for NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {}

/// Linear, process-local expectation for the inactive authenticated-genesis
/// h1 context. It is derived from the exact Core configuration, Core-prepared
/// revision-zero Safety facts and App configuration before any h1 authority is
/// registered. It contains no Core, input/effect, store or persistence
/// authority.
///
/// ```compile_fail
/// use trnm_consensus_app::PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0;
/// fn require_clone<T: Clone>() {}
/// fn probe() {
///     require_clone::<PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0>();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the inactive h1 expectation must be consumed by the exact Core/App registration"]
pub struct PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0 {
    inner: NativeAuthenticatedGenesisH1InactiveExpectationV0,
}

impl PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0 {
    pub fn new_v0(
        core_config: &CoreConfig,
        prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
        application: &ConsensusAppConfig,
    ) -> Result<Self, NativeAuthenticatedGenesisH1OfflineValidationErrorV0> {
        prepare_native_authenticated_genesis_h1_inactive_expectation_v0(
            core_config,
            prepared,
            application,
        )
        .map(|inner| Self { inner })
        .map_err(|_| {
            NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CommissioningCapabilityMismatch
        })
    }
}

/// Existing-only configuration for the stable authenticated-genesis empty-h1
/// application recovery owner.  It consumes the independently derived
/// inactive expectation, but never receives a Core owner, callback permit, or
/// application authority.
#[derive(Debug)]
pub struct NativeAuthenticatedGenesisH1StableRecoveryConfigV0 {
    application: ConsensusAppConfig,
    inactive_expectation: NativeAuthenticatedGenesisH1InactiveExpectationV0,
}

impl NativeAuthenticatedGenesisH1StableRecoveryConfigV0 {
    pub fn new(
        application: ConsensusAppConfig,
        inactive_expectation: PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
    ) -> Result<Self, NativeAuthenticatedGenesisH1StableRecoveryErrorV0> {
        application
            .validate()
            .map_err(|_| NativeAuthenticatedGenesisH1StableRecoveryErrorV0::InvalidConfig)?;
        if application.poco_authority.is_some()
            || application
                .state_path
                .as_deref()
                .is_none_or(|path| !path.is_absolute())
            || inactive_expectation.inner.application_host_config_ref
                != native_validation_host_config_ref_from_application_v0(&application)
        {
            return Err(NativeAuthenticatedGenesisH1StableRecoveryErrorV0::InvalidConfig);
        }
        Ok(Self {
            application,
            inactive_expectation: inactive_expectation.inner,
        })
    }
}

/// Existing-only configuration for inspecting one exact schema-v14 App cut
/// while Core still owns the authenticated-genesis empty-h1 obligation.  The
/// configuration carries no Core owner and cannot install application
/// authorities.
#[derive(Debug)]
pub struct NativeAuthenticatedGenesisH1ObligationTakeoverConfigV0 {
    application: ConsensusAppConfig,
    inactive_expectation: NativeAuthenticatedGenesisH1InactiveExpectationV0,
}

impl NativeAuthenticatedGenesisH1ObligationTakeoverConfigV0 {
    pub fn new(
        application: ConsensusAppConfig,
        inactive_expectation: PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
    ) -> Result<Self, NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0> {
        application
            .validate()
            .map_err(|_| NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::InvalidConfig)?;
        if application.poco_authority.is_some()
            || application
                .state_path
                .as_deref()
                .is_none_or(|path| !path.is_absolute())
            || inactive_expectation.inner.application_host_config_ref
                != native_validation_host_config_ref_from_application_v0(&application)
        {
            return Err(NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::InvalidConfig);
        }
        Ok(Self {
            application,
            inactive_expectation: inactive_expectation.inner,
        })
    }
}

/// Dedicated RecoveryExclusive owner for fixed-snapshot obligation takeover
/// classification. It exposes no store, Core, generic step, callback,
/// application authority, finalization, or raw-parts surface.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1ObligationTakeoverHostV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<NativeAuthenticatedGenesisH1ObligationTakeoverHostV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1ObligationTakeoverHostV0;
/// fn leak(host: &mut NativeAuthenticatedGenesisH1ObligationTakeoverHostV0) {
///     let _ = host.store();
///     let _ = host.core();
///     let _ = host.step();
///     let _ = host.callback();
///     let _ = host.authority();
///     let _ = host.into_parts();
/// }
/// ```
pub struct NativeAuthenticatedGenesisH1ObligationTakeoverHostV0 {
    store: ApplicationStore,
    application: ConsensusAppConfig,
    database_identity: ApplicationStoreFileIdentityV0,
    owner_affinity: Arc<()>,
    commissioning: NativeAuthenticatedGenesisCommissioningBindingV0,
    inactive_expectation: NativeAuthenticatedGenesisH1InactiveExpectationV0,
}

impl fmt::Debug for NativeAuthenticatedGenesisH1ObligationTakeoverHostV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeAuthenticatedGenesisH1ObligationTakeoverHostV0")
            .field("status_path", &self.store.status_path)
            .field("database_path", &self.store.database_path)
            .finish_non_exhaustive()
    }
}

/// One-shot proof that an exact live schema-v14 namespace was observed at one
/// fixed App cut.  It is comparison material only; in particular P and D do
/// not recreate callback or execution authority.
///
/// ```compile_fail
/// use trnm_consensus_app::ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0>();
/// ```
#[derive(Debug)]
#[must_use = "the takeover cut must be freshly joined to its issuing live owner"]
pub struct ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0 {
    status_path: PathBuf,
    database_path: PathBuf,
    database_identity: ApplicationStoreFileIdentityV0,
    owner_affinity: Arc<()>,
    cut: NativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
}

/// App-owned CoreAccepted endpoint of one exact authenticated-genesis h1
/// takeover reexecution.  The private takeover host, Core owner, and App P
/// callback remain joined for a later dedicated Safety/App transition.  This
/// value exposes no callback, Core, store, authority, or raw-parts surface.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0;
/// fn leak(owner: NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0) {
///     let _ = owner.core();
///     let _ = owner.callback();
///     let _ = owner.store();
///     let _ = owner.into_parts();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the CoreAccepted takeover must remain joined for its dedicated next transition"]
pub struct NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0 {
    host: NativeAuthenticatedGenesisH1ObligationTakeoverHostV0,
    _owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    accepted: crate::NativeAuthenticatedGenesisH1CoreAcceptedValidV0,
    source: NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0,
    cut: NativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
}

impl NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0 {
    pub const fn source_before_reexecution_v0(
        &self,
    ) -> NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0 {
        self.source
    }

    pub const fn validation_id_v0(&self) -> trnm_consensus_core::ValidationId {
        self.accepted.validation_id_v0()
    }

    pub fn status_path_v0(&self) -> &Path {
        self.host.store.status_path.as_path()
    }

    fn complete_takeover_v0<V: SignatureVerifier>(
        self,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
        verifier: &V,
    ) -> Result<
        NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0,
        NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0,
    > {
        let Self {
            host,
            _owner: mut owner,
            accepted,
            source,
            cut,
        } = self;
        if safety_store.path() != expected_safety_path {
            return Err(
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch,
            );
        }
        host.require_live_database_v0()?;
        let delivered = match source {
            NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Delivered => accepted
                .preflight_and_confirm_existing_application_delivered_v0(
                    &host.store,
                    &owner,
                    safety_store,
                    &cut,
                ),
            NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Absent
            | NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Reserved
            | NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::CallbackPending => accepted
                .preflight_and_mark_application_delivered_v0(
                    &host.store,
                    &owner,
                    safety_store,
                ),
        }
        .map_err(|cause| match cause {
                crate::native_validation_valid_delivery::NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Safety(error) => {
                    map_takeover_safety_failure_v0(error)
                }
                crate::native_validation_valid_delivery::NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Application(error) => {
                    map_takeover_app_transition_failure_v0(error)
                }
                crate::native_validation_valid_delivery::NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Core(_) => {
                    NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::CoreRejectedCallback
                }
            })?;
        let persisted = delivered
            .persist_and_confirm_safety_v0(safety_store)
            .map_err(map_takeover_safety_failure_v0)?;
        let acked = persisted
            .acknowledge_application_v0(&host.store)
            .map_err(map_takeover_app_transition_failure_v0)?;
        let app_facts = acked.app_facts_v0();
        let delivery_facts = acked.sealed_transition_v0().delivery_facts_v0();
        let valid_result_checksum = acked.valid_result_checksum_v0();
        let acked_job_row_checksum = acked.acked_job_row_checksum_v0();
        let completion_carrier_checksum = acked.sealed_transition_v0().carrier_checksum_v0();
        let barrier = acked.completion_persistence_v0().barrier_v0();
        let completed = owner
            .acknowledge_completion_persisted_v0(acked.sealed_transition_v0(), barrier, verifier)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::CoreRejectedCallback
            })?;
        let application = acked
            .confirm_completed_application_v0(&host.store, &completed)
            .map_err(map_takeover_store_error_v0)?;
        Ok(
            NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0 {
                host,
                completed: NativeAuthenticatedGenesisH1OfflineCompletedV0 {
                    core: completed,
                    application,
                },
                app_facts,
                delivery_facts,
                valid_result_checksum,
                acked_job_row_checksum,
                completion_carrier_checksum,
            },
        )
    }
}

struct NativeAuthenticatedGenesisH1ObligationTakeoverExecutionRegistrarV0<'a, V> {
    host: NativeAuthenticatedGenesisH1ObligationTakeoverHostV0,
    cut: NativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
    request: AuthenticatedGenesisApplicationH1ValidationRequestV0,
    verifier: &'a V,
}

impl ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0 {
    pub fn belongs_to_host_at_path_v0(
        &self,
        host: &NativeAuthenticatedGenesisH1ObligationTakeoverHostV0,
        expected_status_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &host.owner_affinity)
            && self.status_path.as_path() == expected_status_path
            && host.store.status_path.as_path() == expected_status_path
            && self.database_path == host.store.database_path
            && current_database_identity_v0(&host.store).ok() == Some(self.database_identity)
            && host.store.require_namespace_owner_v0().is_ok()
    }

    pub const fn source_v0(&self) -> NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0 {
        self.cut.source
    }

    pub const fn validation_id_v0(&self) -> trnm_consensus_core::ValidationId {
        self.cut.validation_id
    }

    pub const fn request_fingerprint_v0(&self) -> [u8; 32] {
        self.cut.request_fingerprint
    }

    pub const fn immutable_checksum_v0(&self) -> Option<[u8; 32]> {
        self.cut.immutable_checksum
    }

    pub const fn job_row_checksum_v0(&self) -> Option<[u8; 32]> {
        self.cut.job_row_checksum
    }

    pub const fn artifact_checksum_v0(&self) -> Option<[u8; 32]> {
        self.cut.artifact_checksum
    }

    pub const fn outbox_checksum_v0(&self) -> Option<[u8; 32]> {
        self.cut.outbox_checksum
    }

    pub const fn overlay_checksum_v0(&self) -> Option<[u8; 32]> {
        self.cut.overlay_checksum
    }

    pub const fn accounting_checksum_v0(&self) -> [u8; 32] {
        self.cut.accounting_checksum
    }

    pub const fn recovery_closure_checksum_v0(&self) -> [u8; 32] {
        self.cut.recovery_closure_checksum
    }

    pub const fn application_host_config_ref_v0(&self) -> [u8; 32] {
        self.cut.application_host_config_ref
    }

    pub const fn carrier_binding_ref_v0(&self) -> [u8; 32] {
        self.cut.carrier_binding_ref
    }

    pub const fn commissioning_row_checksum_v0(&self) -> [u8; 32] {
        self.cut.commissioning_row_checksum
    }

    pub const fn cut_checksum_v0(&self) -> [u8; 32] {
        self.cut.cut_checksum
    }

    pub fn status_path_v0(&self) -> &Path {
        self.status_path.as_path()
    }

    pub fn database_path_v0(&self) -> &Path {
        self.database_path.as_path()
    }
}

/// Dedicated existing-only owner for stable `C+D`/`C+K`.  It has no raw
/// store, callback, Core, input/effect, application authority, finalization,
/// or parts escape surface.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1StableApplicationHostV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<NativeAuthenticatedGenesisH1StableApplicationHostV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1StableApplicationHostV0;
/// fn leak(host: &mut NativeAuthenticatedGenesisH1StableApplicationHostV0) {
///     let _ = host.store();
///     let _ = host.core();
///     let _ = host.step();
///     let _ = host.finalize();
///     let _ = host.into_parts();
/// }
/// ```
#[derive(Debug)]
pub struct NativeAuthenticatedGenesisH1StableApplicationHostV0 {
    store: ApplicationStore,
    application: ConsensusAppConfig,
    database_identity: ApplicationStoreFileIdentityV0,
    owner_affinity: Arc<()>,
    commissioning: NativeAuthenticatedGenesisCommissioningBindingV0,
    inactive_expectation: NativeAuthenticatedGenesisH1InactiveExpectationV0,
}

/// One-shot proof of an exact live v14 App `K` poststate. `source` records
/// whether this call observed `C+D` and performed the sole recovery write, or
/// observed the already-stable `C+K` cut.  The remaining fields are inert
/// fixed-snapshot comparison facts.
///
/// ```compile_fail
/// use trnm_consensus_app::ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0>();
/// ```
#[derive(Debug)]
#[must_use = "the stable App capability must be consumed by the exact Core recovery session"]
pub struct ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0 {
    status_path: PathBuf,
    database_path: PathBuf,
    database_identity: ApplicationStoreFileIdentityV0,
    owner_affinity: Arc<()>,
    source: NativeAuthenticatedGenesisH1StableApplicationSourceV0,
    validation_id: trnm_consensus_core::ValidationId,
    valid_result_checksum: [u8; 32],
    delivered_job_row_checksum: [u8; 32],
    acked_job_row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
    artifact_checksum: [u8; 32],
    overlay_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    carrier_binding_ref: [u8; 32],
    commissioning_row_checksum: [u8; 32],
    completion_carrier_checksum: [u8; 32],
    recovery_closure_checksum: [u8; 32],
    safety_head_facts: AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
}

impl ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0 {
    pub fn belongs_to_host_at_path_v0(
        &self,
        host: &NativeAuthenticatedGenesisH1StableApplicationHostV0,
        expected_status_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &host.owner_affinity)
            && self.status_path.as_path() == expected_status_path
            && host.store.status_path.as_path() == expected_status_path
            && self.database_path == host.store.database_path
            && current_database_identity_v0(&host.store).ok() == Some(self.database_identity)
            && host.store.require_namespace_owner_v0().is_ok()
    }

    pub const fn source_v0(&self) -> NativeAuthenticatedGenesisH1StableApplicationSourceV0 {
        self.source
    }

    pub const fn validation_id_v0(&self) -> trnm_consensus_core::ValidationId {
        self.validation_id
    }

    pub const fn valid_result_checksum_v0(&self) -> [u8; 32] {
        self.valid_result_checksum
    }

    pub const fn delivered_job_row_checksum_v0(&self) -> [u8; 32] {
        self.delivered_job_row_checksum
    }

    pub const fn acked_job_row_checksum_v0(&self) -> [u8; 32] {
        self.acked_job_row_checksum
    }

    pub const fn outbox_checksum_v0(&self) -> [u8; 32] {
        self.outbox_checksum
    }

    pub const fn artifact_checksum_v0(&self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub const fn overlay_checksum_v0(&self) -> [u8; 32] {
        self.overlay_checksum
    }

    pub const fn application_host_config_ref_v0(&self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn carrier_binding_ref_v0(&self) -> [u8; 32] {
        self.carrier_binding_ref
    }

    pub const fn commissioning_row_checksum_v0(&self) -> [u8; 32] {
        self.commissioning_row_checksum
    }

    pub const fn completion_carrier_checksum_v0(&self) -> [u8; 32] {
        self.completion_carrier_checksum
    }

    pub const fn recovery_closure_checksum_v0(&self) -> [u8; 32] {
        self.recovery_closure_checksum
    }

    pub fn status_path_v0(&self) -> &Path {
        self.status_path.as_path()
    }

    pub fn database_path_v0(&self) -> &Path {
        self.database_path.as_path()
    }

    pub const fn safety_head_facts_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0 {
        &self.safety_head_facts
    }
}

impl AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReconcilerV0
    for ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0
{
    fn reconcile_authenticated_genesis_application_h1_stable_native_valid_v0(
        &mut self,
        challenge: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
        safety_head_facts: &AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
    ) -> bool {
        self.validation_id == challenge.validation_id_v0()
            && self.valid_result_checksum == challenge.valid_result_checksum_v0()
            && self.completion_carrier_checksum == challenge.completion_carrier_checksum_v0()
            && self.safety_head_facts == *safety_head_facts
    }
}

/// Point-in-time comparison facts for the one dedicated offline h1 owner.
/// These values are inert and do not remain fresh after they are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeAuthenticatedGenesisH1OfflineValidationFactsV0 {
    carrier_binding_ref: [u8; 32],
    application_host_config_ref: [u8; 32],
    descriptor_ref: [u8; 32],
    projection_profile_ref: [u8; 32],
    safety_journal_id: [u8; 32],
    safety_head_checksum: [u8; 32],
    commissioning_row_checksum: [u8; 32],
    commissioning_recovery_closure_checksum: [u8; 32],
}

/// Terminal output of the bounded h1 owner after Core rev2 completion and a
/// fresh fixed-snapshot App `K` confirmation. Neither field can recreate the
/// Core owner, App callback, Safety transition, or application authority.
#[derive(Debug)]
pub struct NativeAuthenticatedGenesisH1OfflineCompletedV0 {
    core: AuthenticatedGenesisApplicationH1CompletedV0,
    application: crate::NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
}

/// Lifetime owner retained after an exact obligation takeover reaches C+K.
/// It keeps the RecoveryExclusive App namespace pinned for the final
/// whole-node freshness join, while exposing only inert completion facts.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0;
/// fn leak(host: NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0) {
///     let _ = host.core();
///     let _ = host.store();
///     let _ = host.step();
///     let _ = host.activate();
///     let _ = host.into_parts();
/// }
/// ```
#[must_use = "the completed takeover owner must remain live through the final freshness join"]
pub struct NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0 {
    host: NativeAuthenticatedGenesisH1ObligationTakeoverHostV0,
    completed: NativeAuthenticatedGenesisH1OfflineCompletedV0,
    app_facts: crate::NativeValidationValidAppFactsV0,
    delivery_facts: trnm_consensus_core::ApplicationNativeValidDeliveryFactsV0,
    valid_result_checksum: [u8; 32],
    acked_job_row_checksum: [u8; 32],
    completion_carrier_checksum: [u8; 32],
}

/// One-shot fresh K confirmation affined to the completed live takeover
/// owner.  The copyable App facts are getters on this non-cloneable
/// capability; they are not themselves freshness authority.
///
/// ```compile_fail
/// use trnm_consensus_app::ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0>();
/// ```
#[must_use = "the fresh completed capability must be consumed by the final owner join"]
pub struct ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0 {
    status_path: PathBuf,
    database_path: PathBuf,
    database_identity: ApplicationStoreFileIdentityV0,
    owner_affinity: Arc<()>,
    validation_id: trnm_consensus_core::ValidationId,
    authenticated_parent_binding_ref: [u8; 32],
    application: crate::NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
}

impl fmt::Debug for ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0")
            .field("status_path", &self.status_path)
            .field("database_path", &self.database_path)
            .field("validation_id", &self.validation_id)
            .finish_non_exhaustive()
    }
}

impl ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0 {
    pub fn belongs_to_host_at_path_v0(
        &self,
        host: &NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0,
        expected_status_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &host.host.owner_affinity)
            && self.status_path.as_path() == expected_status_path
            && host.host.store.status_path.as_path() == expected_status_path
            && self.database_path == host.host.store.database_path
            && current_database_identity_v0(&host.host.store).ok() == Some(self.database_identity)
            && host.host.store.require_namespace_owner_v0().is_ok()
    }

    pub const fn validation_id_v0(&self) -> trnm_consensus_core::ValidationId {
        self.validation_id
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        2
    }

    pub const fn authenticated_parent_binding_ref_v0(&self) -> [u8; 32] {
        self.authenticated_parent_binding_ref
    }

    pub const fn application_facts_v0(
        &self,
    ) -> crate::NativeAuthenticatedGenesisH1CompletedAppConfirmationV0 {
        self.application
    }
}

impl fmt::Debug for NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0")
            .field("status_path", &self.host.store.status_path)
            .field("database_path", &self.host.store.database_path)
            .finish_non_exhaustive()
    }
}

impl NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0 {
    pub fn status_path_v0(&self) -> &Path {
        self.host.store.status_path.as_path()
    }

    pub fn belongs_to_host_at_path_v0(&self, expected_status_path: &Path) -> bool {
        self.host.store.status_path.as_path() == expected_status_path
            && current_database_identity_v0(&self.host.store).ok()
                == Some(self.host.database_identity)
            && self.host.store.require_namespace_owner_v0().is_ok()
    }

    pub const fn core_facts_v0(&self) -> &AuthenticatedGenesisApplicationH1CompletedV0 {
        &self.completed.core
    }

    pub const fn application_facts_v0(
        &self,
    ) -> crate::NativeAuthenticatedGenesisH1CompletedAppConfirmationV0 {
        self.completed.application
    }

    /// Revalidates the exact K closure against the retained live owner.  The
    /// returned value is inert comparison material; no callback, Core owner,
    /// store, or transition can be reconstructed from it.
    pub fn fresh_confirm_capability_exact_v0(
        &self,
    ) -> Result<
        ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0,
        NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0,
    > {
        self.host.require_live_database_v0()?;
        // `confirm_completed_application_v0` is a fixed-snapshot, exact K
        // audit and is the same final gate used by the fresh straight line.
        let application = self
            .host
            .store
            .confirm_authenticated_genesis_h1_completed_exact_v0(
                self.app_facts,
                self.delivery_facts,
                self.valid_result_checksum,
                self.acked_job_row_checksum,
                self.completion_carrier_checksum,
                &self.completed.core,
            )
            .map_err(map_takeover_store_error_v0)?;
        Ok(
            ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0 {
                status_path: self.host.store.status_path.clone(),
                database_path: self.host.store.database_path.clone(),
                database_identity: self.host.database_identity,
                owner_affinity: Arc::clone(&self.host.owner_affinity),
                validation_id: self.completed.core.validation_id_v0(),
                authenticated_parent_binding_ref: self
                    .completed
                    .core
                    .authenticated_parent_binding_ref_v0(),
                application,
            },
        )
    }
}

impl NativeAuthenticatedGenesisH1OfflineCompletedV0 {
    pub const fn core_v0(&self) -> &AuthenticatedGenesisApplicationH1CompletedV0 {
        &self.core
    }

    pub const fn application_v0(
        &self,
    ) -> crate::NativeAuthenticatedGenesisH1CompletedAppConfirmationV0 {
        self.application
    }
}

impl NativeAuthenticatedGenesisH1OfflineValidationFactsV0 {
    pub const fn carrier_binding_ref_v0(self) -> [u8; 32] {
        self.carrier_binding_ref
    }

    pub const fn application_host_config_ref_v0(self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn descriptor_ref_v0(self) -> [u8; 32] {
        self.descriptor_ref
    }

    pub const fn projection_profile_ref_v0(self) -> [u8; 32] {
        self.projection_profile_ref
    }

    pub const fn safety_journal_id_v0(self) -> [u8; 32] {
        self.safety_journal_id
    }

    pub const fn safety_head_checksum_v0(self) -> [u8; 32] {
        self.safety_head_checksum
    }

    pub const fn commissioning_row_checksum_v0(self) -> [u8; 32] {
        self.commissioning_row_checksum
    }

    pub const fn commissioning_recovery_closure_checksum_v0(self) -> [u8; 32] {
        self.commissioning_recovery_closure_checksum
    }
}

/// Configuration for the dedicated inert commissioning owner. Descriptor and
/// projection-profile references are deliberately absent: the store derives
/// both inside the fixed App snapshot and compares them to the Core carrier.
#[derive(Debug)]
pub struct NativeAuthenticatedGenesisApplicationCommissioningConfigV0 {
    application: ConsensusAppConfig,
}

impl NativeAuthenticatedGenesisApplicationCommissioningConfigV0 {
    pub fn new(
        application: ConsensusAppConfig,
    ) -> Result<Self, NativeAuthenticatedGenesisApplicationCommissioningErrorV0> {
        application.validate().map_err(|_| {
            NativeAuthenticatedGenesisApplicationCommissioningErrorV0::InvalidConfig
        })?;
        let state_path = application
            .state_path
            .as_deref()
            .ok_or(NativeAuthenticatedGenesisApplicationCommissioningErrorV0::StatePathRequired)?;
        if !state_path.is_absolute() {
            return Err(
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::StatePathNotAbsolute,
            );
        }
        if application.poco_authority.is_some() {
            return Err(NativeAuthenticatedGenesisApplicationCommissioningErrorV0::InvalidConfig);
        }
        Ok(Self { application })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SafetyBindingFactsV0 {
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    core_config_ref: [u8; 32],
    revision: u64,
    state_record_checksum: [u8; 32],
    transition_context_checksum: [u8; 32],
    chain_checksum: [u8; 32],
    head_checksum: [u8; 32],
}

/// Inert, non-cloneable proof of one exact App+Safety commissioning closure.
/// The private affinity token and database identity keep detached facts bound
/// to the live owner which minted them; comparison getters grant no runtime or
/// persistence authority.
///
/// ```compile_fail
/// use trnm_consensus_app::ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0;
///
/// fn require_clone<T: Clone>() {}
///
/// fn probe() {
///     require_clone::<ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0>();
/// }
/// ```
#[derive(Debug)]
#[must_use = "the commissioned application capability must be joined to the remaining live owners"]
pub struct ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0 {
    status_path: PathBuf,
    database_path: PathBuf,
    database_identity: ApplicationStoreFileIdentityV0,
    owner_affinity: Arc<()>,
    carrier: AuthenticatedGenesisApplicationParentV0,
    carrier_binding_ref: [u8; 32],
    application_host_config_ref: [u8; 32],
    descriptor_ref: [u8; 32],
    projection_profile_ref: [u8; 32],
    safety: SafetyBindingFactsV0,
    recovery_closure_checksum: [u8; 32],
    row_checksum: [u8; 32],
}

impl ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0 {
    /// Confirms live-owner affinity, canonical status/database paths, current
    /// database inode, and the still-held exclusive namespace owner.
    pub fn belongs_to_host_at_path_v0(
        &self,
        host: &NativeAuthenticatedGenesisApplicationCommissioningHostV0,
        expected_status_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &host.owner_affinity)
            && self.status_path.as_path() == expected_status_path
            && host.store.status_path.as_path() == expected_status_path
            && self.database_path == host.store.database_path
            && current_database_identity_v0(&host.store).ok() == Some(self.database_identity)
            && host.store.require_namespace_owner_v0().is_ok()
    }

    pub fn status_path_v0(&self) -> &Path {
        self.status_path.as_path()
    }

    pub fn database_path_v0(&self) -> &Path {
        self.database_path.as_path()
    }

    pub const fn carrier_binding_ref_v0(&self) -> [u8; 32] {
        self.carrier_binding_ref
    }

    pub const fn carrier_v0(&self) -> AuthenticatedGenesisApplicationParentV0 {
        self.carrier
    }

    pub const fn application_host_config_ref_v0(&self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn descriptor_ref_v0(&self) -> [u8; 32] {
        self.descriptor_ref
    }

    pub const fn projection_profile_ref_v0(&self) -> [u8; 32] {
        self.projection_profile_ref
    }

    pub const fn safety_journal_id_v0(&self) -> [u8; 32] {
        self.safety.journal_id
    }

    pub const fn safety_verifier_profile_ref_v0(&self) -> [u8; 32] {
        self.safety.verifier_profile_ref
    }

    pub const fn safety_core_config_ref_v0(&self) -> [u8; 32] {
        self.safety.core_config_ref
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        self.safety.revision
    }

    pub const fn safety_state_record_checksum_v0(&self) -> [u8; 32] {
        self.safety.state_record_checksum
    }

    pub const fn safety_transition_context_checksum_v0(&self) -> [u8; 32] {
        self.safety.transition_context_checksum
    }

    pub const fn safety_chain_checksum_v0(&self) -> [u8; 32] {
        self.safety.chain_checksum
    }

    pub const fn safety_head_checksum_v0(&self) -> [u8; 32] {
        self.safety.head_checksum
    }

    pub const fn recovery_closure_checksum_v0(&self) -> [u8; 32] {
        self.recovery_closure_checksum
    }

    pub const fn row_checksum_v0(&self) -> [u8; 32] {
        self.row_checksum
    }
}

/// Dedicated non-cloneable owner for the authenticated-genesis application
/// commissioning namespace.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisApplicationCommissioningHostV0;
///
/// fn require_clone<T: Clone>() {}
///
/// fn probe() {
///     require_clone::<NativeAuthenticatedGenesisApplicationCommissioningHostV0>();
/// }
/// ```
///
/// The owner deliberately has no raw store, parts, or authority escape getter.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisApplicationCommissioningHostV0;
///
/// fn leak(host: &NativeAuthenticatedGenesisApplicationCommissioningHostV0) {
///     let _ = host.store();
///     let _ = host.parts();
///     let _ = host.authority();
/// }
/// ```
#[derive(Debug)]
pub struct NativeAuthenticatedGenesisApplicationCommissioningHostV0 {
    store: ApplicationStore,
    application: ConsensusAppConfig,
    database_identity: ApplicationStoreFileIdentityV0,
    owner_affinity: Arc<()>,
    application_host_config_ref: [u8; 32],
}

/// Dedicated non-cloneable owner for the first exact offline h1 validation.
/// It contains no raw Core, generic Core step surface, finalization authority,
/// network, timer, signer, or raw-parts escape hatch.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1OfflineValidationHostV0;
///
/// fn require_clone<T: Clone>() {}
/// fn probe() {
///     require_clone::<NativeAuthenticatedGenesisH1OfflineValidationHostV0>();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_app::NativeAuthenticatedGenesisH1OfflineValidationHostV0;
///
/// fn leak(host: &mut NativeAuthenticatedGenesisH1OfflineValidationHostV0) {
///     let _ = host.core();
///     let _ = host.step();
///     let _ = host.store();
///     let _ = host.into_parts();
/// }
/// ```
#[derive(Debug)]
pub struct NativeAuthenticatedGenesisH1OfflineValidationHostV0 {
    store: ApplicationStore,
    application: ConsensusAppConfig,
    database_identity: ApplicationStoreFileIdentityV0,
    facts: NativeAuthenticatedGenesisH1OfflineValidationFactsV0,
    owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    completed_closure: Option<NativeAuthenticatedGenesisH1CompletedClosureV0>,
}

#[derive(Debug, Clone, Copy)]
struct NativeAuthenticatedGenesisH1CompletedClosureV0 {
    app_facts: crate::NativeValidationValidAppFactsV0,
    delivery_facts: trnm_consensus_core::ApplicationNativeValidDeliveryFactsV0,
    valid_result_checksum: [u8; 32],
    acked_job_row_checksum: [u8; 32],
    completion_carrier_checksum: [u8; 32],
}

/// Linear registrar consumed only by Core's opaque h1 activation bundle. It
/// carries the exact commissioning owner and fresh capability into the single
/// application registration call without exposing Core's seal authority.
#[must_use = "the h1 registrar must be consumed by Core's activation bundle"]
pub struct NativeAuthenticatedGenesisH1OfflineApplicationRegistrarV0 {
    commissioning_host: NativeAuthenticatedGenesisApplicationCommissioningHostV0,
    commissioning: ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
    inactive_expectation: PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
}

impl fmt::Debug for NativeAuthenticatedGenesisH1OfflineApplicationRegistrarV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeAuthenticatedGenesisH1OfflineApplicationRegistrarV0")
            .field("contains_linear_commissioning_owner", &true)
            .field("contains_linear_commissioning_capability", &true)
            .field("contains_linear_inactive_expectation", &true)
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
#[must_use = "failed h1 activation quarantines every linear commissioning and Core owner"]
pub struct NativeAuthenticatedGenesisH1OfflineValidationActivationRejectionV0 {
    cause: NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    commissioning_host: NativeAuthenticatedGenesisApplicationCommissioningHostV0,
    commissioning: ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
    inactive_expectation: PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
    owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
}

impl fmt::Debug for NativeAuthenticatedGenesisH1OfflineValidationActivationRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeAuthenticatedGenesisH1OfflineValidationActivationRejectionV0")
            .field("cause", &self.cause)
            .field("retains_commissioning_owner", &true)
            .field("retains_commissioning_capability", &true)
            .field("retains_inactive_expectation", &true)
            .field("retains_combined_core_application_owner", &true)
            .finish()
    }
}

impl NativeAuthenticatedGenesisH1OfflineValidationActivationRejectionV0 {
    pub const fn cause(&self) -> NativeAuthenticatedGenesisH1OfflineValidationErrorV0 {
        self.cause
    }
}

impl NativeAuthenticatedGenesisApplicationCommissioningHostV0 {
    pub fn open_existing_commissionable_v0(
        config: NativeAuthenticatedGenesisApplicationCommissioningConfigV0,
    ) -> Result<Self, NativeAuthenticatedGenesisApplicationCommissioningErrorV0> {
        let state_path = config
            .application
            .state_path
            .as_deref()
            .expect("validated commissioning config has a state path");
        let signer_policy_hash_hex = hex::encode(crate::signer_policy_commitment(
            config.application.authorized_signers.as_slice(),
        ));
        let store = ApplicationStore::open_with_namespace_owner_v0(
            state_path,
            config.application.chain_id.as_str(),
            signer_policy_hash_hex.as_str(),
            super::ApplicationStoreOwnerModeV0::RecoveryExclusive,
        )
        .map_err(map_namespace_failure_v0)?;
        let database_identity = current_database_identity_v0(&store)?;
        store
            .preflight_existing_authenticated_genesis_commissioning_clean_v0()
            .map_err(map_store_failure_v0)?;
        let application_host_config_ref =
            native_validation_host_config_ref_from_application_v0(&config.application);
        Ok(Self {
            store,
            application: config.application,
            database_identity,
            owner_affinity: Arc::new(()),
            application_host_config_ref,
        })
    }

    /// Joins the inert commissioning owner and its fresh capability into the
    /// sole registrar accepted by Core's opaque activation bundle. This does
    /// not receive or reveal Core's seal authority.
    pub fn into_h1_offline_application_registrar_v0(
        self,
        commissioning: ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
        inactive_expectation: PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
    ) -> NativeAuthenticatedGenesisH1OfflineApplicationRegistrarV0 {
        NativeAuthenticatedGenesisH1OfflineApplicationRegistrarV0 {
            commissioning_host: self,
            commissioning,
            inactive_expectation,
        }
    }

    #[allow(clippy::result_large_err)]
    fn register_h1_offline_validation_v0(
        self,
        commissioning: ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
        inactive_expectation: PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
        owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    ) -> Result<
        NativeAuthenticatedGenesisH1OfflineValidationHostV0,
        NativeAuthenticatedGenesisH1OfflineValidationActivationRejectionV0,
    > {
        let reject = |cause, commissioning_host, commissioning, inactive_expectation, owner| {
            NativeAuthenticatedGenesisH1OfflineValidationActivationRejectionV0 {
                cause,
                commissioning_host,
                commissioning,
                inactive_expectation,
                owner,
            }
        };
        let core_context = match owner.h1_context_facts_v0() {
            Ok(context) => context,
            Err(_) => {
                return Err(reject(
                    NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreAuthorityMismatch,
                    self,
                    commissioning,
                    inactive_expectation,
                    owner,
                ));
            }
        };
        if !commissioning.belongs_to_host_at_path_v0(&self, self.store.status_path.as_path())
            || commissioning.application_host_config_ref_v0() != self.application_host_config_ref
            || commissioning.carrier_binding_ref_v0() != commissioning.carrier_v0().binding_ref_v0()
            || commissioning.carrier_v0() != inactive_expectation.inner.carrier
            || commissioning.safety_core_config_ref_v0()
                != inactive_expectation.inner.safety_state_record_config_ref
            || commissioning.application_host_config_ref_v0()
                != inactive_expectation.inner.application_host_config_ref
            || !inactive_expectation_matches_core_context_v0(
                &inactive_expectation.inner,
                &core_context,
            )
        {
            return Err(reject(
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CommissioningCapabilityMismatch,
                self,
                commissioning,
                inactive_expectation,
                owner,
            ));
        }
        let carrier = commissioning.carrier_v0();
        let expected_binding = commissioning_store_binding_v0(&commissioning);
        if expected_binding.row_checksum_v0() != commissioning.row_checksum_v0() {
            return Err(reject(
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CommissioningCapabilityMismatch,
                self,
                commissioning,
                inactive_expectation,
                owner,
            ));
        }
        let access = match self.store.prepare_authenticated_genesis_h1_store_access_v0(
            &self.application,
            self.database_identity,
            carrier,
            expected_binding,
            commissioning.recovery_closure_checksum_v0(),
            inactive_expectation.inner.clone(),
        ) {
            Ok(access) => access,
            Err(error) => {
                let cause = match map_store_failure_v0(error) {
                    NativeAuthenticatedGenesisApplicationCommissioningErrorV0::NamespaceUnavailable
                    | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::DatabaseUnavailable
                    | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::HostResourceUnavailable
                    | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::CleanCheckpointRequired => {
                        NativeAuthenticatedGenesisH1OfflineValidationErrorV0::NamespaceUnavailable
                    }
                    NativeAuthenticatedGenesisApplicationCommissioningErrorV0::InvalidConfig
                    | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::StatePathRequired
                    | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::StatePathNotAbsolute
                    | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::PersistedStateMismatch
                    | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch => {
                        NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch
                    }
                };
                return Err(reject(
                    cause,
                    self,
                    commissioning,
                    inactive_expectation,
                    owner,
                ));
            }
        };
        let facts = NativeAuthenticatedGenesisH1OfflineValidationFactsV0 {
            carrier_binding_ref: commissioning.carrier_binding_ref_v0(),
            application_host_config_ref: commissioning.application_host_config_ref_v0(),
            descriptor_ref: commissioning.descriptor_ref_v0(),
            projection_profile_ref: commissioning.projection_profile_ref_v0(),
            safety_journal_id: commissioning.safety_journal_id_v0(),
            safety_head_checksum: commissioning.safety_head_checksum_v0(),
            commissioning_row_checksum: commissioning.row_checksum_v0(),
            commissioning_recovery_closure_checksum: commissioning.recovery_closure_checksum_v0(),
        };
        if let Err(_access) = self
            .store
            .install_authenticated_genesis_h1_store_access_v0(access)
        {
            return Err(reject(
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreAuthorityMismatch,
                self,
                commissioning,
                inactive_expectation,
                owner,
            ));
        }
        Ok(NativeAuthenticatedGenesisH1OfflineValidationHostV0 {
            store: self.store,
            application: self.application,
            database_identity: self.database_identity,
            facts,
            owner,
            completed_closure: None,
        })
    }

    /// Atomically commissions strict virgin schema v13, or confirms an exact
    /// existing v14 namespace.  The caller-provided Safety capability is
    /// consumed by value; fresh exact Safety capabilities are minted before
    /// and after the App transaction.
    pub fn commission_or_confirm_exact_v0<V: SignatureVerifier>(
        &mut self,
        prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
        safety: ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
    ) -> Result<
        (
            ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
            NativeAuthenticatedGenesisApplicationCommissioningDispositionV0,
        ),
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0,
    > {
        self.require_live_database_v0()?;
        let pinned_safety =
            validate_safety_capability_v0(prepared, safety_store, expected_safety_path, &safety)?;
        let fresh_before = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(prepared)
            .map_err(|_| {
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch
            })?;
        let fresh_before_facts = validate_safety_capability_v0(
            prepared,
            safety_store,
            expected_safety_path,
            &fresh_before,
        )?;
        if fresh_before_facts != pinned_safety {
            return Err(
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch,
            );
        }

        let carrier = prepared.authenticated_genesis_application_parent_v0();
        let (decision, derived_binding, recovery_closure_checksum) = self
            .store
            .commission_or_confirm_authenticated_genesis_application_v14_v0(
                &self.application,
                self.database_identity,
                carrier,
                fresh_before_facts.into_store_binding_facts_v0(),
            )
            .map_err(map_store_failure_v0)?;

        let fresh_after = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(prepared)
            .map_err(|_| {
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch
            })?;
        let fresh_after_facts = validate_safety_capability_v0(
            prepared,
            safety_store,
            expected_safety_path,
            &fresh_after,
        )?;
        if fresh_after_facts != pinned_safety {
            return Err(
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch,
            );
        }

        let (confirmed_binding, confirmed_recovery_closure_checksum) = self
            .store
            .confirm_authenticated_genesis_application_v14_v0(
                &self.application,
                self.database_identity,
                carrier,
                fresh_before_facts.into_store_binding_facts_v0(),
            )
            .map_err(map_store_failure_v0)?;
        if (confirmed_binding, confirmed_recovery_closure_checksum)
            != (derived_binding, recovery_closure_checksum)
        {
            return Err(
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::PersistedStateMismatch,
            );
        }

        // Final Safety read occurs after the final fixed-snapshot App confirm,
        // closing the return boundary against a post-commit head substitution.
        let final_safety = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(prepared)
            .map_err(|_| {
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch
            })?;
        if validate_safety_capability_v0(
            prepared,
            safety_store,
            expected_safety_path,
            &final_safety,
        )? != pinned_safety
        {
            return Err(
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch,
            );
        }
        self.require_live_database_v0()?;

        let capability = self.capability_v0(
            carrier,
            derived_binding,
            pinned_safety,
            confirmed_recovery_closure_checksum,
        );
        let disposition = match decision {
            NativeAuthenticatedGenesisCommissioningDecisionV0::Commissioned => {
                NativeAuthenticatedGenesisApplicationCommissioningDispositionV0::Commissioned
            }
            NativeAuthenticatedGenesisCommissioningDecisionV0::Existing => {
                NativeAuthenticatedGenesisApplicationCommissioningDispositionV0::Existing
            }
        };
        Ok((capability, disposition))
    }

    /// Freshly confirms an existing v14 App closure together with a newly
    /// minted exact Safety tag-5 capability. This method never commissions or
    /// upgrades a schema-v13 namespace.
    pub fn fresh_confirm_exact_v0<V: SignatureVerifier>(
        &self,
        prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
    ) -> Result<
        ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0,
    > {
        self.require_live_database_v0()?;
        let safety = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(prepared)
            .map_err(|_| {
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch
            })?;
        let safety_facts =
            validate_safety_capability_v0(prepared, safety_store, expected_safety_path, &safety)?;
        let carrier = prepared.authenticated_genesis_application_parent_v0();
        let (binding, recovery_closure_checksum) = self
            .store
            .confirm_authenticated_genesis_application_v14_v0(
                &self.application,
                self.database_identity,
                carrier,
                safety_facts.into_store_binding_facts_v0(),
            )
            .map_err(map_store_failure_v0)?;
        let final_safety = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(prepared)
            .map_err(|_| {
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch
            })?;
        if validate_safety_capability_v0(
            prepared,
            safety_store,
            expected_safety_path,
            &final_safety,
        )? != safety_facts
        {
            return Err(
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch,
            );
        }
        self.require_live_database_v0()?;
        Ok(self.capability_v0(carrier, binding, safety_facts, recovery_closure_checksum))
    }

    fn capability_v0(
        &self,
        carrier: AuthenticatedGenesisApplicationParentV0,
        binding: NativeAuthenticatedGenesisCommissioningBindingV0,
        safety: SafetyBindingFactsV0,
        recovery_closure_checksum: [u8; 32],
    ) -> ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0 {
        ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0 {
            status_path: self.store.status_path.clone(),
            database_path: self.store.database_path.clone(),
            database_identity: self.database_identity,
            owner_affinity: Arc::clone(&self.owner_affinity),
            carrier,
            carrier_binding_ref: binding.carrier_binding_ref,
            application_host_config_ref: self.application_host_config_ref,
            descriptor_ref: binding.descriptor_ref,
            projection_profile_ref: binding.projection_profile_ref,
            safety,
            recovery_closure_checksum,
            row_checksum: binding.row_checksum_v0(),
        }
    }

    fn require_live_database_v0(
        &self,
    ) -> Result<(), NativeAuthenticatedGenesisApplicationCommissioningErrorV0> {
        self.store.require_namespace_owner_v0().map_err(|_| {
            NativeAuthenticatedGenesisApplicationCommissioningErrorV0::NamespaceUnavailable
        })?;
        if current_database_identity_v0(&self.store)? != self.database_identity {
            return Err(
                NativeAuthenticatedGenesisApplicationCommissioningErrorV0::NamespaceUnavailable,
            );
        }
        Ok(())
    }
}

impl NativeAuthenticatedGenesisH1StableApplicationHostV0 {
    pub fn open_existing_v0(
        config: NativeAuthenticatedGenesisH1StableRecoveryConfigV0,
    ) -> Result<Self, NativeAuthenticatedGenesisH1StableRecoveryErrorV0> {
        let state_path = config
            .application
            .state_path
            .as_deref()
            .expect("validated stable recovery config has a state path");
        let signer_policy_hash_hex = hex::encode(crate::signer_policy_commitment(
            config.application.authorized_signers.as_slice(),
        ));
        let store = ApplicationStore::open_with_namespace_owner_v0(
            state_path,
            config.application.chain_id.as_str(),
            signer_policy_hash_hex.as_str(),
            super::ApplicationStoreOwnerModeV0::RecoveryExclusive,
        )
        .map_err(map_stable_namespace_failure_v0)?;
        let database_identity =
            current_database_identity_v0(&store).map_err(map_commissioning_to_stable_error_v0)?;
        let (access, commissioning, _admission_closure) = store
            .prepare_authenticated_genesis_h1_stable_store_access_v0(
                &config.application,
                database_identity,
                config.inactive_expectation.clone(),
            )
            .map_err(map_stable_store_error_v0)?;
        store
            .install_authenticated_genesis_h1_store_access_v0(access)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1StableRecoveryErrorV0::PersistedStateMismatch
            })?;
        Ok(Self {
            store,
            application: config.application,
            database_identity,
            owner_affinity: Arc::new(()),
            commissioning,
            inactive_expectation: config.inactive_expectation,
        })
    }

    pub fn recover_or_confirm_exact_v0<V: SignatureVerifier>(
        &mut self,
        challenge: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
        safety: ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0,
    ) -> Result<
        ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
        NativeAuthenticatedGenesisH1StableRecoveryErrorV0,
    > {
        self.require_live_database_v0()?;
        let pinned = validate_stable_safety_capability_v0(
            challenge,
            safety_store,
            expected_safety_path,
            &safety,
        )?;
        let fresh_before = safety_store
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                challenge,
            )
            .map_err(|_| {
                NativeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch
            })?;
        if validate_stable_safety_capability_v0(
            challenge,
            safety_store,
            expected_safety_path,
            &fresh_before,
        )? != pinned
        {
            return Err(
                NativeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch,
            );
        }
        let cut = self
            .store
            .recover_authenticated_genesis_h1_stable_application_v0(challenge, &pinned)
            .map_err(map_stable_cut_failure_v0)?;
        let fresh_after = safety_store
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                challenge,
            )
            .map_err(|_| {
                NativeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch
            })?;
        if validate_stable_safety_capability_v0(
            challenge,
            safety_store,
            expected_safety_path,
            &fresh_after,
        )? != pinned
        {
            return Err(
                NativeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch,
            );
        }
        let stable = self
            .store
            .confirm_authenticated_genesis_h1_stable_application_acked_v0(challenge, &pinned)
            .map_err(map_stable_cut_failure_v0)?;
        if !cut.same_exact_acked_cut_v0(&stable) {
            return Err(NativeAuthenticatedGenesisH1StableRecoveryErrorV0::PersistedStateMismatch);
        }
        self.capability_v0(cut, pinned)
    }

    /// Fresh `C+K` confirmation. This never performs D-to-K and therefore
    /// remains a fixed-snapshot logical read of the App journal.
    pub fn fresh_confirm_exact_v0<V: SignatureVerifier>(
        &self,
        challenge: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
    ) -> Result<
        ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
        NativeAuthenticatedGenesisH1StableRecoveryErrorV0,
    > {
        self.require_live_database_v0()?;
        let safety_before = safety_store
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                challenge,
            )
            .map_err(|_| {
                NativeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch
            })?;
        let facts = validate_stable_safety_capability_v0(
            challenge,
            safety_store,
            expected_safety_path,
            &safety_before,
        )?;
        let cut = self
            .store
            .confirm_authenticated_genesis_h1_stable_application_acked_v0(challenge, &facts)
            .map_err(map_stable_cut_failure_v0)?;
        let safety_after = safety_store
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                challenge,
            )
            .map_err(|_| {
                NativeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch
            })?;
        if validate_stable_safety_capability_v0(
            challenge,
            safety_store,
            expected_safety_path,
            &safety_after,
        )? != facts
        {
            return Err(
                NativeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch,
            );
        }
        self.capability_v0(cut, facts)
    }

    fn capability_v0(
        &self,
        cut: NativeAuthenticatedGenesisH1StableApplicationCutV0,
        safety_head_facts: AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
    ) -> Result<
        ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
        NativeAuthenticatedGenesisH1StableRecoveryErrorV0,
    > {
        self.require_live_database_v0()?;
        if cut.commissioning_row_checksum != self.commissioning.row_checksum_v0()
            || cut.carrier_binding_ref != self.inactive_expectation.carrier.binding_ref_v0()
            || cut.application_host_config_ref
                != native_validation_host_config_ref_from_application_v0(&self.application)
            || cut.completion_carrier_checksum != safety_head_facts.completion_carrier_checksum_v0()
        {
            return Err(NativeAuthenticatedGenesisH1StableRecoveryErrorV0::PersistedStateMismatch);
        }
        Ok(ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0 {
            status_path: self.store.status_path.clone(),
            database_path: self.store.database_path.clone(),
            database_identity: self.database_identity,
            owner_affinity: Arc::clone(&self.owner_affinity),
            source: cut.source,
            validation_id: cut.validation_id,
            valid_result_checksum: cut.valid_result_checksum,
            delivered_job_row_checksum: cut.delivered_job_row_checksum,
            acked_job_row_checksum: cut.acked_job_row_checksum,
            outbox_checksum: cut.outbox_checksum,
            artifact_checksum: cut.artifact_checksum,
            overlay_checksum: cut.overlay_checksum,
            application_host_config_ref: cut.application_host_config_ref,
            carrier_binding_ref: cut.carrier_binding_ref,
            commissioning_row_checksum: cut.commissioning_row_checksum,
            completion_carrier_checksum: cut.completion_carrier_checksum,
            recovery_closure_checksum: cut.recovery_closure_checksum,
            safety_head_facts,
        })
    }

    fn require_live_database_v0(
        &self,
    ) -> Result<(), NativeAuthenticatedGenesisH1StableRecoveryErrorV0> {
        self.store
            .require_namespace_owner_v0()
            .map_err(|_| NativeAuthenticatedGenesisH1StableRecoveryErrorV0::NamespaceUnavailable)?;
        if current_database_identity_v0(&self.store)
            .map_err(map_commissioning_to_stable_error_v0)?
            != self.database_identity
        {
            return Err(NativeAuthenticatedGenesisH1StableRecoveryErrorV0::NamespaceUnavailable);
        }
        Ok(())
    }
}

impl NativeAuthenticatedGenesisH1ObligationTakeoverHostV0 {
    pub fn open_existing_v0(
        config: NativeAuthenticatedGenesisH1ObligationTakeoverConfigV0,
    ) -> Result<Self, NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0> {
        let state_path = config
            .application
            .state_path
            .as_deref()
            .expect("validated obligation takeover config has a state path");
        let signer_policy_hash_hex = hex::encode(crate::signer_policy_commitment(
            config.application.authorized_signers.as_slice(),
        ));
        let store = ApplicationStore::open_with_namespace_owner_v0(
            state_path,
            config.application.chain_id.as_str(),
            signer_policy_hash_hex.as_str(),
            super::ApplicationStoreOwnerModeV0::RecoveryExclusive,
        )
        .map_err(map_takeover_namespace_failure_v0)?;
        let database_identity =
            current_database_identity_v0(&store).map_err(map_commissioning_to_takeover_error_v0)?;
        let (access, commissioning, _admission_closure) = store
            .prepare_authenticated_genesis_h1_stable_store_access_v0(
                &config.application,
                database_identity,
                config.inactive_expectation.clone(),
            )
            .map_err(map_takeover_store_error_v0)?;
        store
            .install_authenticated_genesis_h1_store_access_v0(access)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch
            })?;
        Ok(Self {
            store,
            application: config.application,
            database_identity,
            owner_affinity: Arc::new(()),
            commissioning,
            inactive_expectation: config.inactive_expectation,
        })
    }

    /// Deeply classifies Absent, Reserved, CallbackPending, or Delivered on a
    /// single deferred SQLite snapshot.  No classification performs an App
    /// write and no P/D result recreates callback authority.
    pub fn inspect_exact_cut_v0(
        &self,
        request: &AuthenticatedGenesisApplicationH1ValidationRequestV0,
    ) -> Result<
        ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
        NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0,
    > {
        self.require_live_database_v0()?;
        let request_fingerprint = validate_authenticated_genesis_h1_obligation_request_shape_v0(
            request,
            &self.inactive_expectation,
        )
        .map_err(|_| NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch)?;
        let cut = self
            .store
            .read_authenticated_genesis_h1_obligation_takeover_cut_v0(request)
            .map_err(map_takeover_cut_failure_v0)?;
        if cut.request_fingerprint != request_fingerprint
            || cut.application_host_config_ref
                != native_validation_host_config_ref_from_application_v0(&self.application)
            || cut.carrier_binding_ref != self.inactive_expectation.carrier.binding_ref_v0()
            || cut.commissioning_row_checksum != self.commissioning.row_checksum_v0()
        {
            return Err(
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch,
            );
        }
        self.capability_v0(cut)
    }

    /// Consumes this exact live App owner, one non-cloneable fixed-snapshot
    /// cut, Core's fresh takeover activation bundle, and Core's fresh request
    /// in a single registration call.  No standalone reservation permit or
    /// callback authority is returned.  Absent creates the sole R row;
    /// Reserved reuses that exact row; CallbackPending requires the seal
    /// transaction to return exact Existing. Delivered is intentionally
    /// unavailable through this A/R/P-only CoreAccepted primitive and must use
    /// the unified consuming completion method, which confirms D read-only.
    pub fn reexecute_exact_cut_to_core_accepted_v0<V: SignatureVerifier>(
        self,
        cut: ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
        activation: AuthenticatedGenesisApplicationH1OfflineActivationBundleV0,
        request: AuthenticatedGenesisApplicationH1ValidationRequestV0,
        verifier: &V,
    ) -> Result<
        NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0,
        NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0,
    > {
        self.require_live_database_v0()?;
        if !cut.belongs_to_host_at_path_v0(&self, self.store.status_path.as_path()) {
            return Err(
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch,
            );
        }
        let source = cut.source_v0();
        if source == NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Delivered {
            return Err(
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::DeliveredCutUnsupported,
            );
        }
        let request_fingerprint = validate_authenticated_genesis_h1_obligation_request_shape_v0(
            &request,
            &self.inactive_expectation,
        )
        .map_err(|_| NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch)?;
        if request.validation_id_v0() != cut.validation_id_v0()
            || request_fingerprint != cut.request_fingerprint_v0()
        {
            return Err(NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch);
        }
        let ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0 { cut, .. } = cut;
        activation.activate_application_v0(
            NativeAuthenticatedGenesisH1ObligationTakeoverExecutionRegistrarV0 {
                host: self,
                cut,
                request,
                verifier,
            },
        )
    }

    /// Consumes one exact A/R/P/D App cut through fresh reexecution and Core
    /// rev2. A/R/P use the sole P-to-D writer; D reconstructs the private
    /// attempt-zero callback and confirms the existing attempt-one row
    /// read-only. Both paths continue through Safety C, App K, and Core
    /// completion without releasing CoreAccepted, callback, transition, or
    /// persistence authority to the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn take_over_and_complete_v0<V: SignatureVerifier>(
        self,
        cut: ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
        activation: AuthenticatedGenesisApplicationH1OfflineActivationBundleV0,
        request: AuthenticatedGenesisApplicationH1ValidationRequestV0,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
        verifier: &V,
    ) -> Result<
        NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0,
        NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0,
    > {
        self.require_live_database_v0()?;
        if !cut.belongs_to_host_at_path_v0(&self, self.store.status_path.as_path())
            || safety_store.path() != expected_safety_path
            || safety_store.journal_id_v0() != self.commissioning.safety_journal_id_v0()
            || safety_store.verifier_profile_ref_v0()
                != self.commissioning.safety_verifier_profile_ref_v0()
        {
            return Err(
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch,
            );
        }
        let request_fingerprint = validate_authenticated_genesis_h1_obligation_request_shape_v0(
            &request,
            &self.inactive_expectation,
        )
        .map_err(|_| NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch)?;
        if request.validation_id_v0() != cut.validation_id_v0()
            || request_fingerprint != cut.request_fingerprint_v0()
        {
            return Err(NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch);
        }
        let ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0 { cut, .. } = cut;
        let accepted = activation.activate_application_v0(
            NativeAuthenticatedGenesisH1ObligationTakeoverExecutionRegistrarV0 {
                host: self,
                cut,
                request,
                verifier,
            },
        )?;
        accepted.complete_takeover_v0(safety_store, expected_safety_path, verifier)
    }

    #[cfg(test)]
    pub(super) fn drive_exact_request_to_reserved_for_test_v0(
        &self,
        request: AuthenticatedGenesisApplicationH1ValidationRequestV0,
    ) -> Result<(), NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0> {
        self.require_live_database_v0()?;
        let host = crate::native_payload_validation::NativeValidationHostV0::from_existing_consensus_host_v0(
            &self.store,
            &self.application,
        );
        let prepared =
            crate::native_payload_validation::prepare_empty_synced_authenticated_genesis_h1_valid_v0(
                &host,
                request,
            )
            .map_err(|_| NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch)?;
        drop(prepared);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn drive_exact_request_to_callback_pending_for_test_v0(
        &self,
        request: AuthenticatedGenesisApplicationH1ValidationRequestV0,
        owner: &AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    ) -> Result<(), NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0> {
        self.require_live_database_v0()?;
        let host = crate::native_payload_validation::NativeValidationHostV0::from_existing_consensus_host_v0(
            &self.store,
            &self.application,
        );
        let prepared =
            crate::native_payload_validation::prepare_empty_synced_authenticated_genesis_h1_valid_v0(
                &host,
                request,
            )
            .map_err(|_| NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch)?;
        let callback = match self
            .store
            .seal_authenticated_genesis_h1_durable_valid_and_enqueue_callback_v0(prepared, owner)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::NamespaceUnavailable
            })? {
            super::NativeValidationValidSealDecisionV0::CallbackPending(callback) => callback,
            super::NativeValidationValidSealDecisionV0::Existing(_) => {
                return Err(
                    NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch,
                );
            }
        };
        drop(callback);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn drive_exact_request_to_delivered_for_test_v0<V: SignatureVerifier>(
        &self,
        request: AuthenticatedGenesisApplicationH1ValidationRequestV0,
        owner: &mut AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        verifier: &V,
    ) -> Result<(), NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0> {
        self.require_live_database_v0()?;
        let host = crate::native_payload_validation::NativeValidationHostV0::from_existing_consensus_host_v0(
            &self.store,
            &self.application,
        );
        let prepared =
            crate::native_payload_validation::prepare_empty_synced_authenticated_genesis_h1_valid_v0(
                &host,
                request,
            )
            .map_err(|_| NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch)?;
        let callback = match self
            .store
            .seal_authenticated_genesis_h1_durable_valid_and_enqueue_callback_v0(prepared, owner)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::NamespaceUnavailable
            })? {
            super::NativeValidationValidSealDecisionV0::CallbackPending(callback) => *callback,
            super::NativeValidationValidSealDecisionV0::Existing(_) => {
                return Err(
                    NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch,
                );
            }
        };
        let accepted = callback
            .submit_to_authenticated_genesis_h1_v0(owner, verifier)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::DatabaseUnavailable
            })?;
        let delivered = accepted
            .preflight_and_mark_application_delivered_v0(&self.store, owner, safety_store)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch
            })?;
        drop(delivered);
        Ok(())
    }

    fn capability_v0(
        &self,
        cut: NativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
    ) -> Result<
        ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
        NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0,
    > {
        self.require_live_database_v0()?;
        Ok(
            ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0 {
                status_path: self.store.status_path.clone(),
                database_path: self.store.database_path.clone(),
                database_identity: self.database_identity,
                owner_affinity: Arc::clone(&self.owner_affinity),
                cut,
            },
        )
    }

    fn require_live_database_v0(
        &self,
    ) -> Result<(), NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0> {
        self.store.require_namespace_owner_v0().map_err(|_| {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::NamespaceUnavailable
        })?;
        if current_database_identity_v0(&self.store)
            .map_err(map_commissioning_to_takeover_error_v0)?
            != self.database_identity
        {
            return Err(
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::NamespaceUnavailable,
            );
        }
        Ok(())
    }
}

impl<V: SignatureVerifier> AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0
    for NativeAuthenticatedGenesisH1ObligationTakeoverExecutionRegistrarV0<'_, V>
{
    type Output = NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0;
    type Error = NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0;

    fn register_authenticated_genesis_application_h1_offline_v0(
        self,
        mut owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    ) -> Result<Self::Output, Self::Error> {
        if !owner.accepts_validation_request_v0(&self.request) {
            return Err(
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::CoreActivationMismatch,
            );
        }
        self.host.require_live_database_v0()?;
        let fresh = self
            .host
            .store
            .read_authenticated_genesis_h1_obligation_takeover_cut_v0(&self.request)
            .map_err(map_takeover_cut_failure_v0)?;
        if fresh != self.cut {
            return Err(
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch,
            );
        }
        let source = fresh.source;
        let validation_host =
            crate::native_payload_validation::NativeValidationHostV0::from_existing_consensus_host_v0(
                &self.host.store,
                &self.host.application,
            );
        let prepared = crate::native_payload_validation::reexecute_empty_synced_authenticated_genesis_h1_valid_v0(
            &validation_host,
            self.request,
            &fresh,
        )
        .map_err(|cause| match cause {
            crate::native_payload_validation::PrepareEmptyAuthenticatedGenesisH1ValidFailureV0::DeliveredCutUnsupported => {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::DeliveredCutUnsupported
            }
            crate::native_payload_validation::PrepareEmptyAuthenticatedGenesisH1ValidFailureV0::RequestShape
            | crate::native_payload_validation::PrepareEmptyAuthenticatedGenesisH1ValidFailureV0::TakeoverCutMismatch
            | crate::native_payload_validation::PrepareEmptyAuthenticatedGenesisH1ValidFailureV0::DuplicateRequest => {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::RequestMismatch
            }
            _ => NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::ReexecutionUnavailable,
        })?;
        let callback = match source {
            NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Delivered => self
                .host
                .store
                .reconstruct_authenticated_genesis_h1_delivered_callback_v0(
                    prepared,
                    &owner,
                    &fresh,
                )
                .map_err(map_takeover_cut_failure_v0)?,
            _ => match self
                .host
                .store
                .seal_authenticated_genesis_h1_durable_valid_and_enqueue_callback_v0(
                    prepared, &owner,
                )
            {
            Ok(super::NativeValidationValidSealDecisionV0::CallbackPending(callback))
                if source == NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Absent
                    || source
                        == NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::Reserved =>
            {
                *callback
            }
            Ok(super::NativeValidationValidSealDecisionV0::Existing(callback))
                if source
                    == NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0::CallbackPending =>
            {
                *callback
            }
            Ok(_) | Err(_) => {
                return Err(
                    NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::DurableSealUnavailable,
                )
            }
            },
        };
        let accepted = callback
            .submit_to_authenticated_genesis_h1_v0(&mut owner, self.verifier)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::CoreRejectedCallback
            })?;
        Ok(
            NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0 {
                host: self.host,
                _owner: owner,
                accepted,
                source,
                cut: fresh,
            },
        )
    }
}

fn validate_stable_safety_capability_v0<V: SignatureVerifier>(
    challenge: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
    safety_store: &SqliteSafetyStateStoreV0<V>,
    expected_safety_path: &Path,
    safety: &ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0,
) -> Result<
    AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
    NativeAuthenticatedGenesisH1StableRecoveryErrorV0,
> {
    if !safety.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
        || safety.state_v0() != challenge.revision_two_state_v0()
        || safety.core_config_ref_v0() != challenge.safety_state_record_config_ref_v0()
        || safety.state_record_checksum_v0()
            != safety
                .safety_head_facts_v0()
                .revision_two_state_record_checksum_v0()
        || safety.chain_checksum_v0()
            != safety
                .safety_head_facts_v0()
                .revision_two_chain_checksum_v0()
        || safety.application_delivery_facts_v0().validation_id() != challenge.validation_id_v0()
        || safety
            .application_delivery_facts_v0()
            .valid_result_checksum()
            != challenge.valid_result_checksum_v0()
        || safety
            .safety_head_facts_v0()
            .completion_carrier_checksum_v0()
            != challenge.completion_carrier_checksum_v0()
    {
        return Err(NativeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch);
    }
    Ok(safety.safety_head_facts_v0().clone())
}

fn map_stable_namespace_failure_v0(
    failure: ApplicationStoreNamespaceOpenFailureV0,
) -> NativeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    map_commissioning_to_stable_error_v0(map_namespace_failure_v0(failure))
}

fn map_takeover_namespace_failure_v0(
    failure: ApplicationStoreNamespaceOpenFailureV0,
) -> NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {
    map_commissioning_to_takeover_error_v0(map_namespace_failure_v0(failure))
}

fn map_commissioning_to_takeover_error_v0(
    error: NativeAuthenticatedGenesisApplicationCommissioningErrorV0,
) -> NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {
    match error {
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::HostResourceUnavailable => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::HostResourceUnavailable
        }
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::DatabaseUnavailable => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::DatabaseUnavailable
        }
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::NamespaceUnavailable
        | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::CleanCheckpointRequired => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::NamespaceUnavailable
        }
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::InvalidConfig
        | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::StatePathRequired
        | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::StatePathNotAbsolute => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::InvalidConfig
        }
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::PersistedStateMismatch
        | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch
        }
    }
}

fn map_takeover_store_error_v0(
    error: anyhow::Error,
) -> NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {
    if error
        .chain()
        .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
    {
        NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::StorageUnavailable
    } else {
        map_commissioning_to_takeover_error_v0(map_store_failure_v0(error))
    }
}

fn map_takeover_cut_failure_v0(
    failure: NativeApplicationFinalizationApplyFailureCauseV0,
) -> NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {
    match failure {
        NativeApplicationFinalizationApplyFailureCauseV0::NamespaceMismatch => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::NamespaceUnavailable
        }
        NativeApplicationFinalizationApplyFailureCauseV0::WriterUnavailable
        | NativeApplicationFinalizationApplyFailureCauseV0::HostResourceUnavailable => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::HostResourceUnavailable
        }
        NativeApplicationFinalizationApplyFailureCauseV0::DatabaseUnavailable
        | NativeApplicationFinalizationApplyFailureCauseV0::CommitUncertain => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::DatabaseUnavailable
        }
        NativeApplicationFinalizationApplyFailureCauseV0::AuthorityUnavailable
        | NativeApplicationFinalizationApplyFailureCauseV0::AuthorityMismatch
        | NativeApplicationFinalizationApplyFailureCauseV0::PersistedStateMismatch => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch
        }
        #[cfg(test)]
        NativeApplicationFinalizationApplyFailureCauseV0::Injected => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch
        }
    }
}

fn map_takeover_app_transition_failure_v0(
    failure: NativeValidationValidJournalTransitionFailureCauseV0,
) -> NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {
    match failure {
        NativeValidationValidJournalTransitionFailureCauseV0::Storage(storage) => match storage {
            NativeValidationReservationFailureCauseV0::DatabaseUnavailable { .. } => {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::DatabaseUnavailable
            }
            NativeValidationReservationFailureCauseV0::StorageUnavailable { .. } => {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::StorageUnavailable
            }
            NativeValidationReservationFailureCauseV0::HostResourceUnavailable { .. }
            | NativeValidationReservationFailureCauseV0::Capacity { .. }
            | NativeValidationReservationFailureCauseV0::ByteCapacity { .. } => {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::HostResourceUnavailable
            }
            NativeValidationReservationFailureCauseV0::Invariant { .. }
            | NativeValidationReservationFailureCauseV0::HostInvariant { .. } => {
                NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch
            }
        },
        NativeValidationValidJournalTransitionFailureCauseV0::HostInvariant { .. } => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::HostResourceUnavailable
        }
        NativeValidationValidJournalTransitionFailureCauseV0::DeliveryAttemptOverflow
        | NativeValidationValidJournalTransitionFailureCauseV0::AccountingUnderflow
        | NativeValidationValidJournalTransitionFailureCauseV0::Invariant(_) => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch
        }
    }
}

fn map_takeover_safety_failure_v0(
    failure: SafetyStoreErrorV0,
) -> NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0 {
    match failure {
        SafetyStoreErrorV0::Io { .. } => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::StorageUnavailable
        }
        SafetyStoreErrorV0::Sqlite { .. }
        | SafetyStoreErrorV0::CommitNotApplied { .. }
        | SafetyStoreErrorV0::CommitUncertain { .. }
        | SafetyStoreErrorV0::ConflictHaltUncertain { .. }
        | SafetyStoreErrorV0::HeadWatermarkUncertain { .. } => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::DatabaseUnavailable
        }
        SafetyStoreErrorV0::Missing(_)
        | SafetyStoreErrorV0::Locked
        | SafetyStoreErrorV0::CoreNotBound => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::NamespaceUnavailable
        }
        SafetyStoreErrorV0::UnsupportedPlatform => {
            NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::HostResourceUnavailable
        }
        _ => NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0::PersistedStateMismatch,
    }
}

fn map_commissioning_to_stable_error_v0(
    error: NativeAuthenticatedGenesisApplicationCommissioningErrorV0,
) -> NativeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    match error {
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::HostResourceUnavailable => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::HostResourceUnavailable
        }
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::DatabaseUnavailable => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::DatabaseUnavailable
        }
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::NamespaceUnavailable
        | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::CleanCheckpointRequired => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::NamespaceUnavailable
        }
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::InvalidConfig
        | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::StatePathRequired
        | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::StatePathNotAbsolute => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::InvalidConfig
        }
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::PersistedStateMismatch
        | NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::PersistedStateMismatch
        }
    }
}

fn map_stable_store_error_v0(
    error: anyhow::Error,
) -> NativeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    map_commissioning_to_stable_error_v0(map_store_failure_v0(error))
}

fn map_stable_cut_failure_v0(
    failure: NativeApplicationFinalizationApplyFailureCauseV0,
) -> NativeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    match failure {
        NativeApplicationFinalizationApplyFailureCauseV0::NamespaceMismatch => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::NamespaceUnavailable
        }
        NativeApplicationFinalizationApplyFailureCauseV0::WriterUnavailable
        | NativeApplicationFinalizationApplyFailureCauseV0::HostResourceUnavailable => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::HostResourceUnavailable
        }
        NativeApplicationFinalizationApplyFailureCauseV0::DatabaseUnavailable => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::DatabaseUnavailable
        }
        NativeApplicationFinalizationApplyFailureCauseV0::CommitUncertain => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::CommitUncertain
        }
        NativeApplicationFinalizationApplyFailureCauseV0::AuthorityUnavailable
        | NativeApplicationFinalizationApplyFailureCauseV0::AuthorityMismatch
        | NativeApplicationFinalizationApplyFailureCauseV0::PersistedStateMismatch => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::PersistedStateMismatch
        }
        #[cfg(test)]
        NativeApplicationFinalizationApplyFailureCauseV0::Injected => {
            NativeAuthenticatedGenesisH1StableRecoveryErrorV0::PersistedStateMismatch
        }
    }
}

fn inactive_expectation_matches_core_context_v0(
    expectation: &NativeAuthenticatedGenesisH1InactiveExpectationV0,
    core: &AuthenticatedGenesisApplicationH1OfflineContextFactsV0,
) -> bool {
    expectation.carrier == core.authenticated_genesis_application_parent_v0()
        && expectation.safety_state_record_config_ref == core.safety_state_record_config_ref_v0()
        && expectation.validator_set == *core.validator_set_v0()
        && expectation.parameters == *core.consensus_parameters_v0()
        && expectation.carrier.timestamp_ms() == core.trusted_genesis_timestamp_ms_v0()
}

impl AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0
    for NativeAuthenticatedGenesisH1OfflineApplicationRegistrarV0
{
    type Output = NativeAuthenticatedGenesisH1OfflineValidationHostV0;
    type Error = NativeAuthenticatedGenesisH1OfflineValidationActivationRejectionV0;

    #[allow(clippy::result_large_err)]
    fn register_authenticated_genesis_application_h1_offline_v0(
        self,
        owner: AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    ) -> Result<Self::Output, Self::Error> {
        self.commissioning_host.register_h1_offline_validation_v0(
            self.commissioning,
            self.inactive_expectation,
            owner,
        )
    }
}

impl NativeAuthenticatedGenesisH1OfflineValidationHostV0 {
    fn require_live_database_v0(
        &self,
    ) -> Result<(), NativeAuthenticatedGenesisH1OfflineValidationErrorV0> {
        self.store.require_namespace_owner_v0().map_err(|_| {
            NativeAuthenticatedGenesisH1OfflineValidationErrorV0::NamespaceUnavailable
        })?;
        self.store
            .require_database_identity_v0(self.database_identity)
            .map_err(|_| NativeAuthenticatedGenesisH1OfflineValidationErrorV0::NamespaceUnavailable)
    }

    /// Returns inert point-in-time facts. The live owner performs fresh
    /// namespace and commissioning checks again at every later store access.
    pub const fn facts(&self) -> NativeAuthenticatedGenesisH1OfflineValidationFactsV0 {
        self.facts
    }

    pub fn phase_v0(
        &self,
    ) -> Result<
        AuthenticatedGenesisApplicationH1OfflinePhaseV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;
        self.owner.phase_v0().map_err(|_| {
            NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreObligationRejected
        })
    }

    /// Admits exactly one canonical h1, binds the already-commissioned tag-5
    /// Safety owner, persists the exact rev1 obligation, and returns only the
    /// resulting typed validation request. Neither the Core binding nor the
    /// obligation persistence carrier is exposed to Node.
    pub fn admit_h1_and_release_validation_request_v0<V: SignatureVerifier>(
        &mut self,
        proposal: SignedProposalV0,
        confirmed_tag5: ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
        verifier: &V,
    ) -> Result<
        AuthenticatedGenesisApplicationH1ValidationRequestV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;
        let obligation = self
            .owner
            .submit_exact_h1_synced_proposal_v0(proposal, verifier)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreObligationRejected
            })?;
        let binding = self
            .owner
            .issue_safety_persistence_binding_v0()
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::SafetyBindingMismatch
            })?;
        safety_store
            .bind_authenticated_genesis_application_h1_offline_v0(confirmed_tag5, binding)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::SafetyBindingMismatch
            })?;
        safety_store
            .persist_authenticated_genesis_application_h1_obligation_exact_v0(&obligation)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::ObligationPersistenceUnavailable
            })?;
        self.owner
            .acknowledge_obligation_persisted_v0(&obligation, obligation.barrier_v0(), verifier)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreObligationRejected
            })
    }

    /// Consumes the Core wrapper's sole fresh synced h1 request, prepares and
    /// seals the real empty-body application Valid, and submits its opaque
    /// callback directly to the dedicated Core owner. Neither the callback nor
    /// its application proof crosses this boundary. The successful result is
    /// only an App-owned typestate retaining Core's typed rev2 carrier.
    ///
    /// Any pre-existing durable row is an explicit fail-closed recovery cut.
    /// This first slice does not remint Valid permits for O, O+P, or O+D.
    pub fn prepare_seal_and_submit_empty_synced_valid_v0<V: SignatureVerifier>(
        &mut self,
        request: AuthenticatedGenesisApplicationH1ValidationRequestV0,
        verifier: &V,
    ) -> Result<
        crate::NativeAuthenticatedGenesisH1CoreAcceptedValidV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;

        let host = crate::native_payload_validation::NativeValidationHostV0::from_existing_consensus_host_v0(
            &self.store,
            &self.application,
        );
        let prepared = crate::native_payload_validation::prepare_empty_synced_authenticated_genesis_h1_valid_v0(
            &host,
            request,
        )
        .map_err(map_prepare_empty_authenticated_genesis_h1_valid_failure_v0)?;
        let callback = match self
            .store
            .seal_authenticated_genesis_h1_durable_valid_and_enqueue_callback_v0(
                prepared,
                &self.owner,
            ) {
            Ok(super::NativeValidationValidSealDecisionV0::CallbackPending(callback)) => *callback,
            Ok(super::NativeValidationValidSealDecisionV0::Existing(_)) => {
                return Err(
                    NativeAuthenticatedGenesisH1OfflineValidationErrorV0::UnsupportedRecoveryState,
                );
            }
            Err(_) => {
                return Err(
                    NativeAuthenticatedGenesisH1OfflineValidationErrorV0::DurableSealUnavailable,
                );
            }
        };
        callback
            .submit_to_authenticated_genesis_h1_v0(&mut self.owner, verifier)
            .map_err(|_| NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreRejectedCallback)
    }

    /// Authors only the exact durable `Reserved` cut for the recovery matrix.
    ///
    /// This feature-gated helper consumes the fresh Core request through the
    /// production reservation path, then destroys every process-local permit
    /// without sealing a callback. It exposes no store, token, callback, Core,
    /// or transition and is unavailable from a default production build.
    #[cfg(feature = "recovery-test-support")]
    #[doc(hidden)]
    pub fn stop_after_exact_reserved_for_recovery_test_v0(
        &mut self,
        request: AuthenticatedGenesisApplicationH1ValidationRequestV0,
    ) -> Result<(), NativeAuthenticatedGenesisH1OfflineValidationErrorV0> {
        self.require_live_database_v0()?;
        let host = crate::native_payload_validation::NativeValidationHostV0::from_existing_consensus_host_v0(
            &self.store,
            &self.application,
        );
        let prepared = crate::native_payload_validation::prepare_empty_synced_authenticated_genesis_h1_valid_v0(
            &host,
            request,
        )
        .map_err(map_prepare_empty_authenticated_genesis_h1_valid_failure_v0)?;
        drop(prepared);
        Ok(())
    }

    /// Consumes the opaque Core-accepted App owner into the durable App D
    /// stage after the dedicated SafetyStore preflight. Callback, proof,
    /// transition, and generic persistence facts remain private.
    pub fn mark_h1_valid_delivered_v0<V: SignatureVerifier>(
        &self,
        accepted: crate::NativeAuthenticatedGenesisH1CoreAcceptedValidV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
    ) -> Result<
        crate::NativeAuthenticatedGenesisH1DeliveredValidV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;
        accepted
            .preflight_and_mark_application_delivered_v0(
                &self.store,
                &self.owner,
                safety_store,
            )
            .map_err(|cause| match cause {
                crate::native_validation_valid_delivery::NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Safety(_error) => {
                    NativeAuthenticatedGenesisH1OfflineValidationErrorV0::SafetyPreflightMismatch
                }
                crate::native_validation_valid_delivery::NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Application(_error) => {
                    NativeAuthenticatedGenesisH1OfflineValidationErrorV0::ApplicationDeliveryUnavailable
                }
                crate::native_validation_valid_delivery::NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Core(_error) => {
                    NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreDeliverySealMismatch
                }
            })
    }

    /// Advances only the opaque App D owner through dedicated Safety C and
    /// exact readback. The private tag-2 transition is never returned.
    pub fn persist_and_confirm_h1_valid_safety_v0<V: SignatureVerifier>(
        &self,
        delivered: crate::NativeAuthenticatedGenesisH1DeliveredValidV0,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
    ) -> Result<
        crate::NativeAuthenticatedGenesisH1SafetyPersistedValidV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;
        delivered
            .persist_and_confirm_safety_v0(safety_store)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::SafetyPersistenceUnavailable
            })
    }

    /// Retires the exact D outbox into App K only after the affined Safety C
    /// readback. The live callback is destroyed inside the returned K owner.
    pub fn acknowledge_h1_valid_application_v0(
        &self,
        persisted: crate::NativeAuthenticatedGenesisH1SafetyPersistedValidV0,
    ) -> Result<
        crate::NativeAuthenticatedGenesisH1AckedValidV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;
        persisted
            .acknowledge_application_v0(&self.store)
            .map_err(|_| NativeAuthenticatedGenesisH1OfflineValidationErrorV0::ApplicationAcknowledgementUnavailable)
    }

    /// Closes the bounded Core owner only after App K. Core's typed terminal
    /// facts contain no callback, proof, effect, App authority, or raw Core.
    pub fn complete_h1_valid_v0<V: SignatureVerifier>(
        &mut self,
        acked: crate::NativeAuthenticatedGenesisH1AckedValidV0,
        verifier: &V,
    ) -> Result<
        NativeAuthenticatedGenesisH1OfflineCompletedV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;
        let closure = NativeAuthenticatedGenesisH1CompletedClosureV0 {
            app_facts: acked.app_facts_v0(),
            delivery_facts: acked.sealed_transition_v0().delivery_facts_v0(),
            valid_result_checksum: acked.valid_result_checksum_v0(),
            acked_job_row_checksum: acked.acked_job_row_checksum_v0(),
            completion_carrier_checksum: acked.sealed_transition_v0().carrier_checksum_v0(),
        };
        let barrier = acked.completion_persistence_v0().barrier_v0();
        let completed = self
            .owner
            .acknowledge_completion_persisted_v0(
                acked.sealed_transition_v0(),
                barrier,
                verifier,
            )
            .map_err(|_| NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreCompletionAcknowledgementMismatch)?;
        let application = acked
            .confirm_completed_application_v0(&self.store, &completed)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch
            })?;
        self.completed_closure = Some(closure);
        Ok(NativeAuthenticatedGenesisH1OfflineCompletedV0 {
            core: completed,
            application,
        })
    }

    /// Permanently retires the exact completed h1 owner into Core's
    /// proof-carrying state-sync promotion candidate.
    ///
    /// The application namespace remains pinned by `self` until this
    /// consuming call.  The call first requires the exact completed phase and
    /// then destroys the combined App/Core owner regardless of whether proof
    /// verification succeeds.  No application store, callback, seal permit,
    /// or legacy application authority crosses the boundary.
    pub fn retire_completed_into_h1_state_sync_promotion_v0<V: SignatureVerifier>(
        self,
        completed: NativeAuthenticatedGenesisH1OfflineCompletedV0,
        proof: trnm_consensus_types::FinalityProofV0,
        verifier: &V,
    ) -> Result<
        trnm_consensus_core::AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;
        if self.phase_v0()?
            != trnm_consensus_core::AuthenticatedGenesisApplicationH1OfflinePhaseV0::CompletedRev2
        {
            return Err(
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch,
            );
        }
        let NativeAuthenticatedGenesisH1OfflineCompletedV0 { core, application } = completed;
        if core.proposal_v0()
            != self.owner.exact_completed_h1_proposal_v0().ok_or(
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch,
            )?
            || application.validation_id_v0() != core.validation_id_v0()
        {
            return Err(
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch,
            );
        }
        let _ = application;
        self.owner
            .retire_completed_into_h1_state_sync_promotion_v0(proof, verifier)
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::CoreCompletionAcknowledgementMismatch
            })
    }

    /// Reconstructs the exact inert terminal wrapper from the still-live K
    /// owner immediately before proof-carrying retirement.
    ///
    /// The complete fixed-snapshot App confirmation is regenerated from the
    /// retained completed Core facts; neither component can be used to resume
    /// the completed bounded owner.  This entry exists only for Node's
    /// consuming retirement join.
    pub fn fresh_terminal_completion_v0(
        &self,
    ) -> Result<
        NativeAuthenticatedGenesisH1OfflineCompletedV0,
        NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    > {
        self.require_live_database_v0()?;
        let completion = self
            .owner
            .exact_completed_facts_v0()
            .ok_or(NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch)?;
        let closure = self
            .completed_closure
            .ok_or(NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch)?;
        let application = self
            .store
            .confirm_authenticated_genesis_h1_completed_exact_v0(
                closure.app_facts,
                closure.delivery_facts,
                closure.valid_result_checksum,
                closure.acked_job_row_checksum,
                closure.completion_carrier_checksum,
                &completion,
            )
            .map_err(|_| {
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch
            })?;
        if application.validation_id_v0() != completion.validation_id_v0() {
            return Err(
                NativeAuthenticatedGenesisH1OfflineValidationErrorV0::PersistedStateMismatch,
            );
        }
        Ok(NativeAuthenticatedGenesisH1OfflineCompletedV0 {
            core: completion,
            application,
        })
    }
}

fn map_prepare_empty_authenticated_genesis_h1_valid_failure_v0(
    cause: crate::native_payload_validation::PrepareEmptyAuthenticatedGenesisH1ValidFailureV0,
) -> NativeAuthenticatedGenesisH1OfflineValidationErrorV0 {
    use crate::native_payload_validation::{
        CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0 as OpenFacts,
        CoreAuthorizedRegularPreExecutionUnavailableKindV0 as Unavailable,
        PrepareEmptyAuthenticatedGenesisH1ValidFailureV0 as PrepareFailure,
    };
    use NativeAuthenticatedGenesisH1OfflineValidationErrorV0 as Error;

    match cause {
        PrepareFailure::DuplicateRequest
        | PrepareFailure::ExistingDurableJob
        | PrepareFailure::TakeoverCutMismatch
        | PrepareFailure::DeliveredCutUnsupported => Error::UnsupportedRecoveryState,
        PrepareFailure::RequestShape
        | PrepareFailure::NonEmptyBody
        | PrepareFailure::CommitmentMismatch => Error::ValidationRequestMismatch,
        PrepareFailure::ReservationUnavailable => Error::ReservationUnavailable,
        PrepareFailure::AuthenticatedOpen(facts) => match facts {
            OpenFacts::Unavailable { kind, .. } => match kind {
                Unavailable::BodySource => Error::AuthenticatedOpenBodySourceUnavailable,
                Unavailable::ParentStateMissing => Error::AuthenticatedOpenParentStateMissing,
                Unavailable::ParentStateUnauthenticated => {
                    Error::AuthenticatedOpenParentStateUnauthenticated
                }
                Unavailable::Database => Error::AuthenticatedOpenDatabaseUnavailable,
                Unavailable::StorageIo => Error::AuthenticatedOpenStorageUnavailable,
                Unavailable::HostResource => Error::AuthenticatedOpenHostResourceUnavailable,
                Unavailable::ReservationCapacity => {
                    Error::AuthenticatedOpenReservationCapacityUnavailable
                }
            },
            OpenFacts::DeterministicallyInvalid { .. } => {
                Error::AuthenticatedOpenDeterministicallyInvalid
            }
            OpenFacts::Invariant { .. } => Error::AuthenticatedOpenInvariant,
        },
        PrepareFailure::Planning => Error::PlanningUnavailable,
        PrepareFailure::DurablePreparation => Error::DurablePreparationUnavailable,
    }
}

impl SafetyBindingFactsV0 {
    fn into_store_binding_facts_v0(self) -> super::NativeAuthenticatedGenesisSafetyBindingFactsV0 {
        super::NativeAuthenticatedGenesisSafetyBindingFactsV0 {
            journal_id: self.journal_id,
            verifier_profile_ref: self.verifier_profile_ref,
            core_config_ref: self.core_config_ref,
            revision: self.revision,
            state_record_checksum: self.state_record_checksum,
            transition_context_checksum: self.transition_context_checksum,
            chain_checksum: self.chain_checksum,
            head_checksum: self.head_checksum,
        }
    }
}

fn commissioning_store_binding_v0(
    commissioning: &ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
) -> NativeAuthenticatedGenesisCommissioningBindingV0 {
    NativeAuthenticatedGenesisCommissioningBindingV0 {
        carrier_binding_ref: commissioning.carrier_binding_ref_v0(),
        application_host_config_ref: commissioning.application_host_config_ref_v0(),
        descriptor_ref: commissioning.descriptor_ref_v0(),
        projection_profile_ref: commissioning.projection_profile_ref_v0(),
        safety_journal_id: commissioning.safety_journal_id_v0(),
        safety_verifier_profile_ref: commissioning.safety_verifier_profile_ref_v0(),
        safety_core_config_ref: commissioning.safety_core_config_ref_v0(),
        safety_revision: commissioning.safety_revision_v0(),
        safety_state_record_checksum: commissioning.safety_state_record_checksum_v0(),
        safety_transition_context_checksum: commissioning.safety_transition_context_checksum_v0(),
        safety_chain_checksum: commissioning.safety_chain_checksum_v0(),
        safety_head_checksum: commissioning.safety_head_checksum_v0(),
        committed_head_row_checksum:
            super::native_authenticated_genesis_application_head_row_checksum_v0(
                commissioning.carrier_v0(),
            ),
    }
}

fn validate_safety_capability_v0<V: SignatureVerifier>(
    prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
    safety_store: &SqliteSafetyStateStoreV0<V>,
    expected_safety_path: &Path,
    safety: &ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
) -> Result<SafetyBindingFactsV0, NativeAuthenticatedGenesisApplicationCommissioningErrorV0> {
    let carrier = prepared.authenticated_genesis_application_parent_v0();
    let transition = safety.transition_v0();
    if !safety.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
        || safety.state_v0() != prepared.safety_state()
        || safety.core_config_ref_v0() != prepared.safety_state_record_config_ref_v0()
        || safety.revision_v0() != 0
        || transition.carrier() != carrier
        || transition.carrier_binding_ref() != carrier.binding_ref_v0()
        || transition.state_record_checksum() != safety.state_record_checksum_v0()
        || transition.transition_revision() != safety.revision_v0()
    {
        return Err(
            NativeAuthenticatedGenesisApplicationCommissioningErrorV0::SafetyCapabilityMismatch,
        );
    }
    Ok(SafetyBindingFactsV0 {
        journal_id: safety.journal_id_v0(),
        verifier_profile_ref: safety.verifier_profile_ref_v0(),
        core_config_ref: safety.core_config_ref_v0(),
        revision: safety.revision_v0(),
        state_record_checksum: safety.state_record_checksum_v0(),
        transition_context_checksum: safety.transition_context_checksum_v0(),
        chain_checksum: safety.chain_checksum_v0(),
        head_checksum: safety.head_checksum_v0(),
    })
}

fn current_database_identity_v0(
    store: &ApplicationStore,
) -> Result<ApplicationStoreFileIdentityV0, NativeAuthenticatedGenesisApplicationCommissioningErrorV0>
{
    let metadata = fs::symlink_metadata(&store.database_path).map_err(|_| {
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::DatabaseUnavailable
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(
            NativeAuthenticatedGenesisApplicationCommissioningErrorV0::NamespaceUnavailable,
        );
    }
    Ok(ApplicationStoreFileIdentityV0::from_metadata(&metadata))
}

fn map_store_failure_v0(
    error: anyhow::Error,
) -> NativeAuthenticatedGenesisApplicationCommissioningErrorV0 {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<super::NativeAuthenticatedGenesisCleanCheckpointRequiredV0>()
            .is_some()
    }) {
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::CleanCheckpointRequired
    } else if error.chain().any(|cause| {
        cause
            .downcast_ref::<rusqlite::Error>()
            .is_some_and(|sqlite| {
                let text = sqlite.to_string();
                text.contains("database is locked") || text.contains("database is busy")
            })
    }) {
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::HostResourceUnavailable
    } else if error
        .chain()
        .any(|cause| cause.downcast_ref::<rusqlite::Error>().is_some())
    {
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::DatabaseUnavailable
    } else {
        NativeAuthenticatedGenesisApplicationCommissioningErrorV0::PersistedStateMismatch
    }
}

fn map_namespace_failure_v0(
    failure: ApplicationStoreNamespaceOpenFailureV0,
) -> NativeAuthenticatedGenesisApplicationCommissioningErrorV0 {
    match failure {
        ApplicationStoreNamespaceOpenFailureV0::Locked => {
            NativeAuthenticatedGenesisApplicationCommissioningErrorV0::HostResourceUnavailable
        }
        ApplicationStoreNamespaceOpenFailureV0::ParentUnavailable
        | ApplicationStoreNamespaceOpenFailureV0::MissingDatabase
        | ApplicationStoreNamespaceOpenFailureV0::DatabaseIsNotRegularFile
        | ApplicationStoreNamespaceOpenFailureV0::UnsafeNamespace
        | ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged
        | ApplicationStoreNamespaceOpenFailureV0::ProcessChanged
        | ApplicationStoreNamespaceOpenFailureV0::AuthenticatedGenesisApplicationActivationUnavailable => {
            NativeAuthenticatedGenesisApplicationCommissioningErrorV0::NamespaceUnavailable
        }
        ApplicationStoreNamespaceOpenFailureV0::InvalidPath => {
            NativeAuthenticatedGenesisApplicationCommissioningErrorV0::InvalidConfig
        }
        ApplicationStoreNamespaceOpenFailureV0::Io => {
            NativeAuthenticatedGenesisApplicationCommissioningErrorV0::DatabaseUnavailable
        }
    }
}
