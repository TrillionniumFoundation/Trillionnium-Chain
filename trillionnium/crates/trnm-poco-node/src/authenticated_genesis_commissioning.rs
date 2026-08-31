//! Dedicated, inert whole-node owner for authenticated-genesis commissioning.
//!
//! This module is intentionally disjoint from [`crate::PocoNodeProcessHostV0`]
//! and its bootstrap-mode enum.  A successful commissioning owns the exact
//! Safety, application, and pinned signer namespaces, but exposes only copied
//! comparison facts.  It never constructs a live Core, activates the signer,
//! installs application authority, produces effects, or starts a timer,
//! network, pacemaker, finalization, or production runtime.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use trnm_consensus_app::{
    ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
    ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0, ConsensusAppConfig,
    NativeAuthenticatedGenesisApplicationCommissioningConfigV0,
    NativeAuthenticatedGenesisApplicationCommissioningDispositionV0,
    NativeAuthenticatedGenesisApplicationCommissioningErrorV0,
    NativeAuthenticatedGenesisApplicationCommissioningHostV0,
    NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
    NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    NativeAuthenticatedGenesisH1OfflineValidationHostV0,
    NativeAuthenticatedGenesisH1StableApplicationHostV0,
    NativeAuthenticatedGenesisH1StableApplicationSourceV0,
    NativeAuthenticatedGenesisH1StableRecoveryConfigV0,
    NativeAuthenticatedGenesisH1StableRecoveryErrorV0, NativeValidationValidAppFactsV0,
    PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
};
use trnm_consensus_core::{
    safety_state_record_config_ref_v0, AuthenticatedGenesisApplicationH1CompletedV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0, Core, CoreConfig,
    CoreError, PreparedAuthenticatedGenesisApplicationBootstrapV0, SafetyStateRecordContextV0,
    SafetyStateRecordLimitsV0, ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    AuthenticatedGenesisApplicationInitializationDispositionV0,
    ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
    ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0, SafetyStateStoreProfileV0,
    SafetyStoreErrorV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ConfirmedSignerNodeCheckpointFactsV0, ExternalMonotonicWatermarkV0,
    PinnedSqliteSignerJournalV0, SignerExternalWatermarkRelationV0, SignerJournalErrorV0,
    SignerJournalProfileV0, SignerJournalReconciliationFactsV0, SignerWatermarkV0,
};
use trnm_consensus_types::{BlockId, RolloutPhase, SignedProposalV0};

use crate::{
    derive_signer_watermark_scope_v0,
    process_host::{
        canonical_process_store_path_v0, revalidate_process_store_paths_v0,
        validate_distinct_store_parent_identities_v0, validate_distinct_store_parents_v0,
        ProcessStoreParentIdentitiesV0,
    },
    SIGNER_JOURNAL_PROFILE_REF_V0, STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
};

/// Fixed inert mode returned by the dedicated commissioning owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeAuthenticatedGenesisCommissioningModeV0 {
    AuthenticatedGenesisApplicationCommissionedInert,
}

/// Fixed terminal mode returned after the sole externally signed empty h1 has
/// traversed Core rev1, App P/D/K, Safety rev2 C, and the empty Core ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeAuthenticatedGenesisH1CompletedModeV0 {
    AuthenticatedGenesisApplicationEmptyH1ValidCompletedInert,
}

/// Fixed terminal mode returned after reopening an already-stable
/// authenticated-genesis empty-h1 NativeValid completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeAuthenticatedGenesisH1StableRecoveryModeV0 {
    AuthenticatedGenesisApplicationEmptyH1StableNativeValidRecoveredInert,
}

/// The exact stable App cut observed by one recovery call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0 {
    DeliveredToAcked,
    Acked,
}

/// Typed commissioning failure.  The variants deliberately do not return a
/// partially opened owner or a capability which could be reused elsewhere.
#[derive(Debug)]
pub enum PocoNodeAuthenticatedGenesisCommissioningErrorV0 {
    InvalidCoreConfig,
    AuthenticatedGenesisApplicationParentRequired,
    PreparedBootstrapMismatch,
    ProductionActivationRequested,
    NonShadowRolloutRequested,
    UnsupportedEpoch { epoch: u64 },
    InvalidStorePath,
    StoreParentUnavailable,
    OverlappingStoreNamespaces,
    StoreParentIdentityChanged,
    InvalidApplicationConfig,
    ApplicationChainMismatch,
    ApplicationAuthorityConfigured,
    SignerJournal(SignerJournalErrorV0),
    SignerNotVirgin,
    SignerCapabilityMismatch,
    SafetyStore(SafetyStoreErrorV0),
    SafetyCapabilityMismatch,
    Application(NativeAuthenticatedGenesisApplicationCommissioningErrorV0),
    ApplicationCapabilityMismatch,
}

impl fmt::Display for PocoNodeAuthenticatedGenesisCommissioningErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCoreConfig => formatter.write_str(
                "authenticated-genesis commissioning Core configuration is invalid",
            ),
            Self::AuthenticatedGenesisApplicationParentRequired => formatter.write_str(
                "authenticated-genesis commissioning requires an operator-pinned application parent",
            ),
            Self::PreparedBootstrapMismatch => formatter.write_str(
                "authenticated-genesis prepared bootstrap differs from node configuration",
            ),
            Self::ProductionActivationRequested => formatter.write_str(
                "authenticated-genesis commissioning cannot enable production activation",
            ),
            Self::NonShadowRolloutRequested => formatter.write_str(
                "authenticated-genesis commissioning requires shadow rollout",
            ),
            Self::UnsupportedEpoch { epoch } => write!(
                formatter,
                "authenticated-genesis commissioning does not support epoch {epoch}"
            ),
            Self::InvalidStorePath => {
                formatter.write_str("authenticated-genesis commissioning store path is invalid")
            }
            Self::StoreParentUnavailable => formatter.write_str(
                "authenticated-genesis commissioning store parent is unavailable",
            ),
            Self::OverlappingStoreNamespaces => formatter.write_str(
                "authenticated-genesis commissioning store parents overlap",
            ),
            Self::StoreParentIdentityChanged => formatter.write_str(
                "authenticated-genesis commissioning store parent identity changed",
            ),
            Self::InvalidApplicationConfig => formatter.write_str(
                "authenticated-genesis commissioning application configuration is invalid",
            ),
            Self::ApplicationChainMismatch => formatter.write_str(
                "authenticated-genesis commissioning application chain differs from Core",
            ),
            Self::ApplicationAuthorityConfigured => formatter.write_str(
                "authenticated-genesis commissioning application authority must be absent",
            ),
            Self::SignerJournal(error) => write!(formatter, "signer journal: {error}"),
            Self::SignerNotVirgin => formatter.write_str(
                "authenticated-genesis commissioning requires an exact virgin signer journal",
            ),
            Self::SignerCapabilityMismatch => formatter.write_str(
                "authenticated-genesis commissioning signer capability is foreign or stale",
            ),
            Self::SafetyStore(error) => write!(formatter, "safety store: {error}"),
            Self::SafetyCapabilityMismatch => formatter.write_str(
                "authenticated-genesis commissioning Safety capability is foreign or stale",
            ),
            Self::Application(error) => write!(formatter, "application store: {error}"),
            Self::ApplicationCapabilityMismatch => formatter.write_str(
                "authenticated-genesis commissioning App capability is foreign or stale",
            ),
        }
    }
}

impl std::error::Error for PocoNodeAuthenticatedGenesisCommissioningErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SignerJournal(error) => Some(error),
            Self::SafetyStore(error) => Some(error),
            Self::Application(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SignerJournalErrorV0> for PocoNodeAuthenticatedGenesisCommissioningErrorV0 {
    fn from(error: SignerJournalErrorV0) -> Self {
        Self::SignerJournal(error)
    }
}

impl From<SafetyStoreErrorV0> for PocoNodeAuthenticatedGenesisCommissioningErrorV0 {
    fn from(error: SafetyStoreErrorV0) -> Self {
        Self::SafetyStore(error)
    }
}

impl From<NativeAuthenticatedGenesisApplicationCommissioningErrorV0>
    for PocoNodeAuthenticatedGenesisCommissioningErrorV0
{
    fn from(error: NativeAuthenticatedGenesisApplicationCommissioningErrorV0) -> Self {
        Self::Application(error)
    }
}

/// Failure of the consuming h1 driver. The commissioning owner is consumed on
/// entry, so no error variant returns a partially active Core, application
/// callback, Safety binding, persistence carrier, or signer owner.
#[derive(Debug)]
pub enum PocoNodeAuthenticatedGenesisH1RunErrorV0 {
    SignerJournal(SignerJournalErrorV0),
    SignerCapabilityMismatch,
    SafetyStore(SafetyStoreErrorV0),
    SafetyCapabilityMismatch,
    ApplicationCommissioning(NativeAuthenticatedGenesisApplicationCommissioningErrorV0),
    Application(NativeAuthenticatedGenesisH1OfflineValidationErrorV0),
    Core(CoreError),
    ApplicationCapabilityMismatch,
    CompletedClosureMismatch,
    StoreParentIdentityChanged,
}

impl fmt::Display for PocoNodeAuthenticatedGenesisH1RunErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignerJournal(error) => write!(formatter, "signer journal: {error}"),
            Self::SignerCapabilityMismatch => formatter
                .write_str("authenticated-genesis h1 signer capability is foreign or stale"),
            Self::SafetyStore(error) => write!(formatter, "safety store: {error}"),
            Self::SafetyCapabilityMismatch => formatter
                .write_str("authenticated-genesis h1 Safety capability is foreign or stale"),
            Self::ApplicationCommissioning(error) => {
                write!(formatter, "application commissioning: {error}")
            }
            Self::Application(error) => write!(formatter, "application h1 driver: {error}"),
            Self::Core(error) => write!(formatter, "Core h1 driver: {error}"),
            Self::ApplicationCapabilityMismatch => formatter
                .write_str("authenticated-genesis h1 application capability is foreign or stale"),
            Self::CompletedClosureMismatch => formatter
                .write_str("authenticated-genesis h1 completed cross-store closure differs"),
            Self::StoreParentIdentityChanged => {
                formatter.write_str("authenticated-genesis h1 store parent identity changed")
            }
        }
    }
}

impl std::error::Error for PocoNodeAuthenticatedGenesisH1RunErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SignerJournal(error) => Some(error),
            Self::SafetyStore(error) => Some(error),
            Self::ApplicationCommissioning(error) => Some(error),
            Self::Application(error) => Some(error),
            Self::Core(_) => None,
            Self::SignerCapabilityMismatch
            | Self::SafetyCapabilityMismatch
            | Self::ApplicationCapabilityMismatch
            | Self::CompletedClosureMismatch
            | Self::StoreParentIdentityChanged => None,
        }
    }
}

impl From<SignerJournalErrorV0> for PocoNodeAuthenticatedGenesisH1RunErrorV0 {
    fn from(error: SignerJournalErrorV0) -> Self {
        Self::SignerJournal(error)
    }
}

impl From<SafetyStoreErrorV0> for PocoNodeAuthenticatedGenesisH1RunErrorV0 {
    fn from(error: SafetyStoreErrorV0) -> Self {
        Self::SafetyStore(error)
    }
}

impl From<NativeAuthenticatedGenesisApplicationCommissioningErrorV0>
    for PocoNodeAuthenticatedGenesisH1RunErrorV0
{
    fn from(error: NativeAuthenticatedGenesisApplicationCommissioningErrorV0) -> Self {
        Self::ApplicationCommissioning(error)
    }
}

impl From<NativeAuthenticatedGenesisH1OfflineValidationErrorV0>
    for PocoNodeAuthenticatedGenesisH1RunErrorV0
{
    fn from(error: NativeAuthenticatedGenesisH1OfflineValidationErrorV0) -> Self {
        Self::Application(error)
    }
}

impl From<CoreError> for PocoNodeAuthenticatedGenesisH1RunErrorV0 {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

/// Typed failure from the dedicated existing-only stable `C+D`/`C+K`
/// recovery owner. No variant returns a partially opened store, Core session,
/// App capability, or signer owner.
#[derive(Debug)]
pub enum PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    InvalidConfiguration,
    PreparedBootstrapMismatch,
    SignerJournal(SignerJournalErrorV0),
    SignerCapabilityMismatch,
    SafetyStore(SafetyStoreErrorV0),
    SafetyCapabilityMismatch,
    Application(NativeAuthenticatedGenesisH1StableRecoveryErrorV0),
    ApplicationCapabilityMismatch,
    Core(CoreError),
    RecoveredClosureMismatch,
    StoreParentIdentityChanged,
}

impl fmt::Display for PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => formatter
                .write_str("authenticated-genesis h1 stable recovery configuration is invalid"),
            Self::PreparedBootstrapMismatch => formatter
                .write_str("authenticated-genesis h1 stable recovery prepared bootstrap differs"),
            Self::SignerJournal(error) => write!(formatter, "signer journal: {error}"),
            Self::SignerCapabilityMismatch => formatter.write_str(
                "authenticated-genesis h1 stable recovery signer capability is foreign or stale",
            ),
            Self::SafetyStore(error) => write!(formatter, "safety store: {error}"),
            Self::SafetyCapabilityMismatch => formatter.write_str(
                "authenticated-genesis h1 stable recovery Safety capability is foreign or stale",
            ),
            Self::Application(error) => write!(formatter, "application stable recovery: {error}"),
            Self::ApplicationCapabilityMismatch => formatter.write_str(
                "authenticated-genesis h1 stable recovery App capability is foreign or stale",
            ),
            Self::Core(error) => write!(formatter, "Core stable recovery: {error}"),
            Self::RecoveredClosureMismatch => formatter.write_str(
                "authenticated-genesis h1 stable recovered closure differs across owners",
            ),
            Self::StoreParentIdentityChanged => formatter.write_str(
                "authenticated-genesis h1 stable recovery store parent identity changed",
            ),
        }
    }
}

impl std::error::Error for PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SignerJournal(error) => Some(error),
            Self::SafetyStore(error) => Some(error),
            Self::Application(error) => Some(error),
            Self::Core(_) => None,
            Self::InvalidConfiguration
            | Self::PreparedBootstrapMismatch
            | Self::SignerCapabilityMismatch
            | Self::SafetyCapabilityMismatch
            | Self::ApplicationCapabilityMismatch
            | Self::RecoveredClosureMismatch
            | Self::StoreParentIdentityChanged => None,
        }
    }
}

impl From<SignerJournalErrorV0> for PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    fn from(error: SignerJournalErrorV0) -> Self {
        Self::SignerJournal(error)
    }
}

impl From<SafetyStoreErrorV0> for PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    fn from(error: SafetyStoreErrorV0) -> Self {
        Self::SafetyStore(error)
    }
}

impl From<NativeAuthenticatedGenesisH1StableRecoveryErrorV0>
    for PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0
{
    fn from(error: NativeAuthenticatedGenesisH1StableRecoveryErrorV0) -> Self {
        Self::Application(error)
    }
}

impl From<CoreError> for PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

/// Dedicated commissioning configuration.  It recreates the exact Safety and
/// signer profiles directly from Core configuration, because the ordinary
/// [`crate::PocoNodeStartConfigV0`] is intentionally fenced against this mode.
#[derive(Debug)]
pub struct PocoNodeAuthenticatedGenesisCommissioningConfigV0 {
    pub(crate) safety_store_path: PathBuf,
    pub(crate) safety_store_profile: SafetyStateStoreProfileV0,
    pub(crate) signer_journal_path: PathBuf,
    pub(crate) signer_journal_profile: SignerJournalProfileV0,
    pub(crate) application: ConsensusAppConfig,
    pub(crate) store_parents: ProcessStoreParentIdentitiesV0,
}

/// Existing-only configuration for stable authenticated-genesis empty-h1
/// NativeValid recovery. The same static profiles and three disjoint parent
/// identities used by commissioning are revalidated, but this owner never
/// initializes a missing namespace.
#[derive(Debug)]
pub struct PocoNodeAuthenticatedGenesisH1StableRecoveryConfigV0 {
    inner: PocoNodeAuthenticatedGenesisCommissioningConfigV0,
}

impl PocoNodeAuthenticatedGenesisH1StableRecoveryConfigV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        safety_store_path: impl AsRef<Path>,
        signer_journal_path: impl AsRef<Path>,
        core_config: CoreConfig,
        record_limits: SafetyStateRecordLimitsV0,
        maximum_safety_database_bytes: usize,
        maximum_signer_intents: u64,
        maximum_signer_intent_bytes: usize,
        maximum_signer_database_bytes: usize,
        application: ConsensusAppConfig,
    ) -> Result<Self, PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0> {
        let inner = PocoNodeAuthenticatedGenesisCommissioningConfigV0::new(
            safety_store_path,
            signer_journal_path,
            core_config,
            record_limits,
            maximum_safety_database_bytes,
            maximum_signer_intents,
            maximum_signer_intent_bytes,
            maximum_signer_database_bytes,
            application,
        )
        .map_err(|_| PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::InvalidConfiguration)?;
        Ok(Self { inner })
    }
}

impl PocoNodeAuthenticatedGenesisCommissioningConfigV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        safety_store_path: impl AsRef<Path>,
        signer_journal_path: impl AsRef<Path>,
        core_config: CoreConfig,
        record_limits: SafetyStateRecordLimitsV0,
        maximum_safety_database_bytes: usize,
        maximum_signer_intents: u64,
        maximum_signer_intent_bytes: usize,
        maximum_signer_database_bytes: usize,
        mut application: ConsensusAppConfig,
    ) -> Result<Self, PocoNodeAuthenticatedGenesisCommissioningErrorV0> {
        if core_config
            .authenticated_genesis_application_parent_v0()
            .is_none()
        {
            return Err(PocoNodeAuthenticatedGenesisCommissioningErrorV0::AuthenticatedGenesisApplicationParentRequired);
        }
        if core_config.consensus_parameters().production_activation() {
            return Err(
                PocoNodeAuthenticatedGenesisCommissioningErrorV0::ProductionActivationRequested,
            );
        }
        if core_config.consensus_parameters().rollout_phase() != RolloutPhase::Shadow {
            return Err(
                PocoNodeAuthenticatedGenesisCommissioningErrorV0::NonShadowRolloutRequested,
            );
        }
        let epoch = core_config.validator_set().epoch().get();
        if epoch != 0 {
            return Err(
                PocoNodeAuthenticatedGenesisCommissioningErrorV0::UnsupportedEpoch { epoch },
            );
        }
        application.validate().map_err(|_| {
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidApplicationConfig
        })?;
        if application.poco_authority.is_some() {
            return Err(
                PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationAuthorityConfigured,
            );
        }
        if application.chain_id != core_config.validator_set().chain_id().as_str() {
            return Err(PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationChainMismatch);
        }

        let safety_store_path = safety_store_path.as_ref();
        let signer_journal_path = signer_journal_path.as_ref();
        let application_path = application
            .state_path
            .as_deref()
            .ok_or(PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidApplicationConfig)?;
        if !safety_store_path.is_absolute()
            || !signer_journal_path.is_absolute()
            || !application_path.is_absolute()
        {
            return Err(PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidStorePath);
        }
        let (safety_store_path, safety_parent) =
            canonical_process_store_path_v0(safety_store_path).map_err(map_store_path_error_v0)?;
        let (signer_journal_path, signer_parent) =
            canonical_process_store_path_v0(signer_journal_path)
                .map_err(map_store_path_error_v0)?;
        let (application_path, application_parent) =
            canonical_process_store_path_v0(application_path).map_err(map_store_path_error_v0)?;
        validate_distinct_store_parents_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
        )
        .map_err(map_store_path_error_v0)?;
        let store_parents = ProcessStoreParentIdentitiesV0 {
            safety: safety_parent,
            signer: signer_parent,
            application: application_parent,
        };
        validate_distinct_store_parent_identities_v0(store_parents)
            .map_err(map_store_path_error_v0)?;
        application.state_path = Some(application_path);

        let signer_journal_profile = SignerJournalProfileV0::new(
            core_config.validator_set().clone(),
            core_config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&core_config),
            maximum_signer_intents,
            maximum_signer_intent_bytes,
            maximum_signer_database_bytes,
        )?;
        let safety_store_profile = SafetyStateStoreProfileV0::new(
            core_config,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits,
            maximum_safety_database_bytes,
        )?;
        Ok(Self {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
            application,
            store_parents,
        })
    }
}

/// Copy-only point-in-time commissioning evidence minted at the final fresh
/// join. These fields are comparison facts, not a continuously fresh runtime
/// lease, and grant no store, signer, Core, application, timer, network, or
/// finalization authority.
///
/// ```
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisCommissioningFactsV0;
///
/// fn inspect(facts: PocoNodeAuthenticatedGenesisCommissioningFactsV0) {
///     let _ = (
///         facts.mode(),
///         facts.safety_journal_id(),
///         facts.application_recovery_closure_checksum(),
///         facts.signer_exact_watermark(),
///         facts.signer_activated(),
///         facts.application_authorities_installed(),
///         facts.production_activation_enabled(),
///     );
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeAuthenticatedGenesisCommissioningFactsV0 {
    mode: PocoNodeAuthenticatedGenesisCommissioningModeV0,
    safety_disposition: AuthenticatedGenesisApplicationInitializationDispositionV0,
    application_disposition: NativeAuthenticatedGenesisApplicationCommissioningDispositionV0,
    carrier_binding_ref: [u8; 32],
    safety_journal_id: [u8; 32],
    safety_core_config_ref: [u8; 32],
    safety_state_record_checksum: [u8; 32],
    safety_transition_context_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    safety_head_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    application_descriptor_ref: [u8; 32],
    application_projection_profile_ref: [u8; 32],
    application_recovery_closure_checksum: [u8; 32],
    application_row_checksum: [u8; 32],
    signer_journal_id: [u8; 32],
    signer_profile_checksum: [u8; 32],
    signer_exact_watermark: SignerWatermarkV0,
}

impl PocoNodeAuthenticatedGenesisCommissioningFactsV0 {
    pub const fn mode(self) -> PocoNodeAuthenticatedGenesisCommissioningModeV0 {
        self.mode
    }

    pub const fn safety_disposition(
        self,
    ) -> AuthenticatedGenesisApplicationInitializationDispositionV0 {
        self.safety_disposition
    }

    pub const fn application_disposition(
        self,
    ) -> NativeAuthenticatedGenesisApplicationCommissioningDispositionV0 {
        self.application_disposition
    }

    pub const fn carrier_binding_ref(self) -> [u8; 32] {
        self.carrier_binding_ref
    }

    pub const fn safety_journal_id(self) -> [u8; 32] {
        self.safety_journal_id
    }

    pub const fn safety_core_config_ref(self) -> [u8; 32] {
        self.safety_core_config_ref
    }

    pub const fn safety_state_record_checksum(self) -> [u8; 32] {
        self.safety_state_record_checksum
    }

    pub const fn safety_transition_context_checksum(self) -> [u8; 32] {
        self.safety_transition_context_checksum
    }

    pub const fn safety_chain_checksum(self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn safety_head_checksum(self) -> [u8; 32] {
        self.safety_head_checksum
    }

    pub const fn application_host_config_ref(self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn application_descriptor_ref(self) -> [u8; 32] {
        self.application_descriptor_ref
    }

    pub const fn application_projection_profile_ref(self) -> [u8; 32] {
        self.application_projection_profile_ref
    }

    pub const fn application_recovery_closure_checksum(self) -> [u8; 32] {
        self.application_recovery_closure_checksum
    }

    pub const fn application_row_checksum(self) -> [u8; 32] {
        self.application_row_checksum
    }

    pub const fn signer_journal_id(self) -> [u8; 32] {
        self.signer_journal_id
    }

    pub const fn signer_profile_checksum(self) -> [u8; 32] {
        self.signer_profile_checksum
    }

    pub const fn signer_exact_watermark(self) -> SignerWatermarkV0 {
        self.signer_exact_watermark
    }

    pub const fn signer_activated(self) -> bool {
        false
    }

    pub const fn application_authorities_installed(self) -> bool {
        false
    }

    pub const fn production_activation_enabled(self) -> bool {
        false
    }
}

/// Copy-only point-in-time facts for one fully closed empty-h1 validation.
/// They are not a continuously fresh checkpoint. These values are inert
/// comparison evidence only and cannot recreate Core, App, SafetyStore,
/// signer, callback, persistence, timer, network, or finalization authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeAuthenticatedGenesisH1CompletedFactsV0 {
    mode: PocoNodeAuthenticatedGenesisH1CompletedModeV0,
    carrier_binding_ref: [u8; 32],
    block_id: BlockId,
    validation_id: ValidationId,
    safety_revision: u64,
    safety_journal_id: [u8; 32],
    safety_state_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    application_facts: NativeValidationValidAppFactsV0,
    valid_result_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    application_delivered_job_row_checksum: [u8; 32],
    application_outbox_checksum: [u8; 32],
    application_acked_job_row_checksum: [u8; 32],
    application_artifact_checksum: [u8; 32],
    application_overlay_checksum: [u8; 32],
    application_completion_carrier_checksum: [u8; 32],
    signer_journal_id: [u8; 32],
    signer_profile_checksum: [u8; 32],
    signer_exact_watermark: SignerWatermarkV0,
}

impl PocoNodeAuthenticatedGenesisH1CompletedFactsV0 {
    pub const fn mode(self) -> PocoNodeAuthenticatedGenesisH1CompletedModeV0 {
        self.mode
    }

    pub const fn carrier_binding_ref(self) -> [u8; 32] {
        self.carrier_binding_ref
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn validation_id(self) -> ValidationId {
        self.validation_id
    }

    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_journal_id(self) -> [u8; 32] {
        self.safety_journal_id
    }

    pub const fn safety_state_record_checksum(self) -> [u8; 32] {
        self.safety_state_record_checksum
    }

    pub const fn safety_chain_checksum(self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn application_facts(self) -> NativeValidationValidAppFactsV0 {
        self.application_facts
    }

    pub const fn valid_result_checksum(self) -> [u8; 32] {
        self.valid_result_checksum
    }

    pub const fn application_host_config_ref(self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn application_delivered_job_row_checksum(self) -> [u8; 32] {
        self.application_delivered_job_row_checksum
    }

    pub const fn application_outbox_checksum(self) -> [u8; 32] {
        self.application_outbox_checksum
    }

    pub const fn application_acked_job_row_checksum(self) -> [u8; 32] {
        self.application_acked_job_row_checksum
    }

    pub const fn application_artifact_checksum(self) -> [u8; 32] {
        self.application_artifact_checksum
    }

    pub const fn application_overlay_checksum(self) -> [u8; 32] {
        self.application_overlay_checksum
    }

    pub const fn application_completion_carrier_checksum(self) -> [u8; 32] {
        self.application_completion_carrier_checksum
    }

    pub const fn signer_journal_id(self) -> [u8; 32] {
        self.signer_journal_id
    }

    pub const fn signer_profile_checksum(self) -> [u8; 32] {
        self.signer_profile_checksum
    }

    pub const fn signer_exact_watermark(self) -> SignerWatermarkV0 {
        self.signer_exact_watermark
    }

    pub const fn signer_activated(self) -> bool {
        false
    }

    pub const fn network_started(self) -> bool {
        false
    }

    pub const fn timer_started(self) -> bool {
        false
    }

    pub const fn finalization_started(self) -> bool {
        false
    }

    pub const fn production_activation_enabled(self) -> bool {
        false
    }
}

/// Completed inert owner retaining the exact live Safety/App/signer namespaces
/// after the bounded h1 flow. It exposes facts only: there is no raw Core,
/// callback, persistence transition, authority, signer activation, or parts
/// conversion.
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1CompletedHostV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PocoNodeAuthenticatedGenesisH1CompletedHostV0<()>>();
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1CompletedHostV0;
/// fn leak_core<W>(host: &PocoNodeAuthenticatedGenesisH1CompletedHostV0<W>) {
///     let _ = host.core();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1CompletedHostV0;
/// fn leak_parts<W>(host: PocoNodeAuthenticatedGenesisH1CompletedHostV0<W>) {
///     let _ = host.into_parts();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1CompletedHostV0;
/// fn reactivate<W>(host: &mut PocoNodeAuthenticatedGenesisH1CompletedHostV0<W>) {
///     host.step();
///     host.activate_v0();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1CompletedHostV0;
/// fn escape_runtime<W>(host: &mut PocoNodeAuthenticatedGenesisH1CompletedHostV0<W>) {
///     host.sign();
///     host.finalize();
/// }
/// ```
#[must_use = "the completed inert h1 owner must remain alive while its facts are trusted"]
pub struct PocoNodeAuthenticatedGenesisH1CompletedHostV0<W> {
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application_owner: NativeAuthenticatedGenesisH1OfflineValidationHostV0,
    pinned_signer: PinnedSqliteSignerJournalV0<W>,
    facts: PocoNodeAuthenticatedGenesisH1CompletedFactsV0,
}

impl<W> PocoNodeAuthenticatedGenesisH1CompletedHostV0<W> {
    pub const fn facts(&self) -> PocoNodeAuthenticatedGenesisH1CompletedFactsV0 {
        self.facts
    }
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeAuthenticatedGenesisH1CompletedHostV0<W> {
    /// Consumes the completed legacy application owner into Core's
    /// proof-carrying h1 promotion candidate while retaining the live source
    /// Safety and virgin signer owners for the subsequent native join.
    ///
    /// This is a one-way retirement boundary: failure returns no legacy
    /// application/Core authority.  The result remains inert and cannot
    /// activate Core, mutate Safety, activate the signer, or construct a whole
    /// node checkpoint.
    pub fn retire_into_native_h1_state_sync_source_v0(
        self,
        proof: trnm_consensus_types::FinalityProofV0,
    ) -> Result<
        crate::PocoNodeNativeH1StateSyncPromotionSourceV0<W>,
        PocoNodeAuthenticatedGenesisH1RunErrorV0,
    > {
        let Self {
            safety_store,
            application_owner,
            pinned_signer,
            facts,
        } = self;
        let source_state = safety_store.head()?.state().clone();
        let completed = application_owner
            .fresh_terminal_completion_v0()
            .map_err(PocoNodeAuthenticatedGenesisH1RunErrorV0::Application)?;
        let candidate = application_owner.retire_completed_into_h1_state_sync_promotion_v0(
            completed,
            proof,
            &StrictEd25519Verifier,
        )?;
        if candidate.source_validation_id_v0() != facts.validation_id
            || candidate.source_safety_state_v0() != &source_state
            || candidate.source_valid_result_checksum_v0() != facts.valid_result_checksum
        {
            return Err(PocoNodeAuthenticatedGenesisH1RunErrorV0::CompletedClosureMismatch);
        }
        Ok(
            crate::PocoNodeNativeH1StateSyncPromotionSourceV0::from_completed_authorities_v0(
                candidate,
                safety_store,
                pinned_signer,
            ),
        )
    }
}

impl<W> fmt::Debug for PocoNodeAuthenticatedGenesisH1CompletedHostV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.safety_store,
            &self.application_owner,
            &self.pinned_signer,
        );
        formatter
            .debug_struct("PocoNodeAuthenticatedGenesisH1CompletedHostV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// Copy-only point-in-time comparison facts for one exact stable h1 recovery.
/// They are not a continuously fresh lease and grant no Core, App, Safety,
/// signer, callback, persistence, network, timer, or finalization authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeAuthenticatedGenesisH1StableRecoveryFactsV0 {
    mode: PocoNodeAuthenticatedGenesisH1StableRecoveryModeV0,
    source: PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0,
    carrier_binding_ref: [u8; 32],
    block_id: BlockId,
    validation_id: ValidationId,
    valid_result_checksum: [u8; 32],
    safety_revision: u64,
    safety_journal_id: [u8; 32],
    safety_core_config_ref: [u8; 32],
    safety_state_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    safety_head_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    application_delivered_job_row_checksum: [u8; 32],
    application_acked_job_row_checksum: [u8; 32],
    application_outbox_checksum: [u8; 32],
    application_artifact_checksum: [u8; 32],
    application_overlay_checksum: [u8; 32],
    application_commissioning_row_checksum: [u8; 32],
    application_completion_carrier_checksum: [u8; 32],
    application_recovery_closure_checksum: [u8; 32],
    signer_journal_id: [u8; 32],
    signer_profile_checksum: [u8; 32],
    signer_exact_watermark: SignerWatermarkV0,
}

impl PocoNodeAuthenticatedGenesisH1StableRecoveryFactsV0 {
    pub const fn mode(self) -> PocoNodeAuthenticatedGenesisH1StableRecoveryModeV0 {
        self.mode
    }
    pub const fn source(self) -> PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0 {
        self.source
    }
    pub const fn carrier_binding_ref(self) -> [u8; 32] {
        self.carrier_binding_ref
    }
    pub const fn block_id(self) -> BlockId {
        self.block_id
    }
    pub const fn validation_id(self) -> ValidationId {
        self.validation_id
    }
    pub const fn valid_result_checksum(self) -> [u8; 32] {
        self.valid_result_checksum
    }
    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }
    pub const fn safety_journal_id(self) -> [u8; 32] {
        self.safety_journal_id
    }
    pub const fn safety_core_config_ref(self) -> [u8; 32] {
        self.safety_core_config_ref
    }
    pub const fn safety_state_record_checksum(self) -> [u8; 32] {
        self.safety_state_record_checksum
    }
    pub const fn safety_chain_checksum(self) -> [u8; 32] {
        self.safety_chain_checksum
    }
    pub const fn safety_head_checksum(self) -> [u8; 32] {
        self.safety_head_checksum
    }
    pub const fn application_host_config_ref(self) -> [u8; 32] {
        self.application_host_config_ref
    }
    pub const fn application_delivered_job_row_checksum(self) -> [u8; 32] {
        self.application_delivered_job_row_checksum
    }
    pub const fn application_acked_job_row_checksum(self) -> [u8; 32] {
        self.application_acked_job_row_checksum
    }
    pub const fn application_outbox_checksum(self) -> [u8; 32] {
        self.application_outbox_checksum
    }
    pub const fn application_artifact_checksum(self) -> [u8; 32] {
        self.application_artifact_checksum
    }
    pub const fn application_overlay_checksum(self) -> [u8; 32] {
        self.application_overlay_checksum
    }
    pub const fn application_commissioning_row_checksum(self) -> [u8; 32] {
        self.application_commissioning_row_checksum
    }
    pub const fn application_completion_carrier_checksum(self) -> [u8; 32] {
        self.application_completion_carrier_checksum
    }
    pub const fn application_recovery_closure_checksum(self) -> [u8; 32] {
        self.application_recovery_closure_checksum
    }
    pub const fn signer_journal_id(self) -> [u8; 32] {
        self.signer_journal_id
    }
    pub const fn signer_profile_checksum(self) -> [u8; 32] {
        self.signer_profile_checksum
    }
    pub const fn signer_exact_watermark(self) -> SignerWatermarkV0 {
        self.signer_exact_watermark
    }
    pub const fn signer_activated(self) -> bool {
        false
    }
    pub const fn callback_reminted(self) -> bool {
        false
    }
    pub const fn storage_ack_emitted(self) -> bool {
        false
    }
    pub const fn application_authorities_installed(self) -> bool {
        false
    }
    pub const fn network_started(self) -> bool {
        false
    }
    pub const fn timer_started(self) -> bool {
        false
    }
    pub const fn finalization_started(self) -> bool {
        false
    }
    pub const fn production_activation_enabled(self) -> bool {
        false
    }
}

/// Dedicated inert owner retaining the exact stable Safety/App/signer
/// namespaces. It deliberately has no raw Core, generic input/effect,
/// callback, signer activation, application authority, or parts escape.
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0<()>>();
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0;
/// fn escape<W>(host: &mut PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0<W>) {
///     let _ = host.core();
///     let _ = host.step();
///     let _ = host.activate_v0();
///     let _ = host.sign();
///     let _ = host.finalize();
///     let _ = host.into_parts();
/// }
/// ```
#[must_use = "the stable inert h1 recovery owner must remain alive while its facts are trusted"]
pub struct PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0<W> {
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application_owner: NativeAuthenticatedGenesisH1StableApplicationHostV0,
    pinned_signer: PinnedSqliteSignerJournalV0<W>,
    facts: PocoNodeAuthenticatedGenesisH1StableRecoveryFactsV0,
}

impl<W> PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0<W> {
    pub const fn facts(&self) -> PocoNodeAuthenticatedGenesisH1StableRecoveryFactsV0 {
        self.facts
    }
}

impl<W> fmt::Debug for PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.safety_store,
            &self.application_owner,
            &self.pinned_signer,
        );
        formatter
            .debug_struct("PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// Whole-node inert commissioning owner.
///
/// It intentionally has no `Clone`, raw-parts conversion, Core/effect/input
/// getter, step/resume/timeout method, application-authority method, signer
/// activation method, or conversion to any ordinary node/application owner.
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisCommissioningHostV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PocoNodeAuthenticatedGenesisCommissioningHostV0<()>>();
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisCommissioningHostV0;
/// fn requires_copy<T: Copy>() {}
/// requires_copy::<PocoNodeAuthenticatedGenesisCommissioningHostV0<()>>();
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisCommissioningHostV0;
/// fn leak_core<W>(host: &PocoNodeAuthenticatedGenesisCommissioningHostV0<W>) {
///     let _ = host.core();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeAuthenticatedGenesisCommissioningHostV0;
/// fn activate_signer<W>(host: PocoNodeAuthenticatedGenesisCommissioningHostV0<W>) {
///     let _ = host.activate_v0();
/// }
/// ```
#[must_use = "the commissioned inert owner must remain alive while its facts are trusted"]
pub struct PocoNodeAuthenticatedGenesisCommissioningHostV0<W> {
    core_config: CoreConfig,
    prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
    inactive_h1_expectation: PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
    safety_store_path: PathBuf,
    signer_journal_path: PathBuf,
    application_path: PathBuf,
    store_parents: ProcessStoreParentIdentitiesV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application_owner: NativeAuthenticatedGenesisApplicationCommissioningHostV0,
    pinned_signer: PinnedSqliteSignerJournalV0<W>,
    facts: PocoNodeAuthenticatedGenesisCommissioningFactsV0,
}

#[cfg(all(test, feature = "recovery-test-support", target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatedGenesisH1ObligationAppCutForTestV0 {
    Absent,
    Reserved,
    CallbackPending,
    Delivered,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeAuthenticatedGenesisCommissioningHostV0<W> {
    /// Pins an existing virgin signer without CAS, initializes/resumes exact
    /// tag-5 Safety, commissions/confirms App, then freshly reconfirms all
    /// three live owners and their canonical parent identities.  Success never
    /// creates a Core or runtime authority.
    pub fn commission_or_open_exact_v0(
        config: PocoNodeAuthenticatedGenesisCommissioningConfigV0,
        prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeAuthenticatedGenesisCommissioningErrorV0> {
        let PocoNodeAuthenticatedGenesisCommissioningConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
            application,
            store_parents,
        } = config;
        let core_config = safety_store_profile.core_config().clone();
        validate_prepared_bootstrap_v0(
            &core_config,
            safety_store_profile.record_limits(),
            &prepared,
        )?;
        let application_path = application
            .state_path
            .as_deref()
            .expect("commissioning config validates an application state path")
            .to_path_buf();
        let inactive_h1_expectation =
            PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0::new_v0(
                &core_config,
                &prepared,
                &application,
            )
            .map_err(|_| {
                PocoNodeAuthenticatedGenesisCommissioningErrorV0::PreparedBootstrapMismatch
            })?;
        revalidate_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;
        let application_commissioning = application_commissioning_config_v0(application)?;

        // Pinning is first: a non-virgin or non-Exact signer fails before
        // Safety/App mutation.  This operation observes the external watermark
        // but has no compare-and-advance path.
        let mut pinned_signer = PinnedSqliteSignerJournalV0::open_existing_v0(
            &signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )?;
        let initial_signer = pinned_signer.reconciliation_facts();
        validate_initial_virgin_signer_v0(&pinned_signer, initial_signer, &core_config)?;
        revalidate_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;

        let (safety_store, safety_disposition) =
            SqliteSafetyStateStoreV0::initialize_or_resume_authenticated_genesis_application_exact_v0(
                &safety_store_path,
                safety_store_profile,
                StrictEd25519Verifier,
                &prepared,
            )?;
        let initial_safety = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)?;
        validate_safety_capability_v0(
            &prepared,
            &safety_store,
            &safety_store_path,
            &initial_safety,
        )?;
        revalidate_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;

        let mut application_owner =
            NativeAuthenticatedGenesisApplicationCommissioningHostV0::open_existing_commissionable_v0(
                application_commissioning,
            )?;
        let (_application_capability, application_disposition) = application_owner
            .commission_or_confirm_exact_v0(
                &prepared,
                &safety_store,
                &safety_store_path,
                initial_safety,
            )?;
        revalidate_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;

        // Final freshness is read-only: exact Safety readback, fixed-snapshot
        // App confirmation, one final Safety readback and parent-identity
        // comparison, then the external signer watermark is loaded last.  The
        // last observation is the commissioning host's linearization point.
        let safety_before_app = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)?;
        validate_safety_capability_v0(
            &prepared,
            &safety_store,
            &safety_store_path,
            &safety_before_app,
        )?;
        let confirmed_application = application_owner.fresh_confirm_exact_v0(
            &prepared,
            &safety_store,
            &safety_store_path,
        )?;
        let final_safety = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)?;
        validate_safety_capability_v0(&prepared, &safety_store, &safety_store_path, &final_safety)?;
        validate_application_capability_v0(
            &prepared,
            &application_owner,
            &application_path,
            &final_safety,
            &confirmed_application,
        )?;
        revalidate_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;
        let final_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &final_signer,
            &core_config,
        )?;

        let facts = PocoNodeAuthenticatedGenesisCommissioningFactsV0 {
            mode: PocoNodeAuthenticatedGenesisCommissioningModeV0::AuthenticatedGenesisApplicationCommissionedInert,
            safety_disposition,
            application_disposition,
            carrier_binding_ref: confirmed_application.carrier_binding_ref_v0(),
            safety_journal_id: final_safety.journal_id_v0(),
            safety_core_config_ref: final_safety.core_config_ref_v0(),
            safety_state_record_checksum: final_safety.state_record_checksum_v0(),
            safety_transition_context_checksum: final_safety.transition_context_checksum_v0(),
            safety_chain_checksum: final_safety.chain_checksum_v0(),
            safety_head_checksum: final_safety.head_checksum_v0(),
            application_host_config_ref: confirmed_application.application_host_config_ref_v0(),
            application_descriptor_ref: confirmed_application.descriptor_ref_v0(),
            application_projection_profile_ref: confirmed_application.projection_profile_ref_v0(),
            application_recovery_closure_checksum: confirmed_application
                .recovery_closure_checksum_v0(),
            application_row_checksum: confirmed_application.row_checksum_v0(),
            signer_journal_id: final_signer.journal_id(),
            signer_profile_checksum: final_signer.profile_checksum(),
            signer_exact_watermark: final_signer.exact_watermark(),
        };
        drop((
            safety_before_app,
            final_safety,
            confirmed_application,
            final_signer,
        ));
        Ok(Self {
            core_config,
            prepared,
            inactive_h1_expectation,
            safety_store_path,
            signer_journal_path,
            application_path,
            store_parents,
            safety_store,
            application_owner,
            pinned_signer,
            facts,
        })
    }

    pub const fn facts(&self) -> PocoNodeAuthenticatedGenesisCommissioningFactsV0 {
        self.facts
    }

    /// Consumes the commissioned owner and drives exactly one already-signed,
    /// empty h1 through the dedicated Core/App/Safety typestate chain. The
    /// pinned signer is never activated and the external watermark is observed
    /// only by exact readback; no compare-and-advance operation exists here.
    pub fn run_exact_empty_h1_valid_v0(
        self,
        proposal: SignedProposalV0,
    ) -> Result<
        PocoNodeAuthenticatedGenesisH1CompletedHostV0<W>,
        PocoNodeAuthenticatedGenesisH1RunErrorV0,
    > {
        self.run_exact_empty_h1_valid_strict_v0(proposal)
    }

    /// Authors the genuine durable `C+D` owner-drop/reopen cut for the recovery
    /// test matrix. This helper is unavailable in production builds and
    /// deliberately returns no Core, callback, persistence barrier, App owner,
    /// or half-state handle. It is not process-SIGKILL or power-loss evidence.
    #[cfg(all(test, feature = "recovery-test-support", target_os = "linux"))]
    fn author_exact_empty_h1_c_plus_d_cut_for_test_v0(
        self,
        proposal: SignedProposalV0,
    ) -> Result<(), PocoNodeAuthenticatedGenesisH1RunErrorV0> {
        let verifier = &StrictEd25519Verifier;
        let Self {
            core_config,
            prepared,
            inactive_h1_expectation,
            safety_store_path,
            signer_journal_path,
            application_path,
            store_parents,
            mut safety_store,
            application_owner,
            mut pinned_signer,
            facts: commissioning_facts,
        } = self;
        let initial_signer = pinned_signer.reconciliation_facts();
        validate_initial_virgin_signer_v0(&pinned_signer, initial_signer, &core_config)
            .map_err(map_h1_commissioning_error_v0)?;
        let confirmed_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &confirmed_signer,
            &core_config,
        )
        .map_err(map_h1_commissioning_error_v0)?;
        drop(confirmed_signer);
        revalidate_h1_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;
        let tag5 = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)?;
        validate_safety_capability_v0(&prepared, &safety_store, &safety_store_path, &tag5)
            .map_err(map_h1_commissioning_error_v0)?;
        let application_capability = application_owner.fresh_confirm_exact_v0(
            &prepared,
            &safety_store,
            &safety_store_path,
        )?;
        validate_application_capability_v0(
            &prepared,
            &application_owner,
            &application_path,
            &tag5,
            &application_capability,
        )
        .map_err(map_h1_commissioning_error_v0)?;
        if application_capability.row_checksum_v0()
            != commissioning_facts.application_row_checksum()
            || application_capability.recovery_closure_checksum_v0()
                != commissioning_facts.application_recovery_closure_checksum()
        {
            return Err(PocoNodeAuthenticatedGenesisH1RunErrorV0::ApplicationCapabilityMismatch);
        }
        let registrar = application_owner.into_h1_offline_application_registrar_v0(
            application_capability,
            inactive_h1_expectation,
        );
        let activation = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            core_config,
            prepared,
            verifier,
        )?;
        let mut application_owner =
            activation
                .activate_application_v0(registrar)
                .map_err(|rejection| {
                    PocoNodeAuthenticatedGenesisH1RunErrorV0::Application(rejection.cause())
                })?;
        let request = application_owner.admit_h1_and_release_validation_request_v0(
            proposal,
            tag5,
            &mut safety_store,
            verifier,
        )?;
        let accepted =
            application_owner.prepare_seal_and_submit_empty_synced_valid_v0(request, verifier)?;
        let delivered = application_owner.mark_h1_valid_delivered_v0(accepted, &safety_store)?;
        let persisted = application_owner
            .persist_and_confirm_h1_valid_safety_v0(delivered, &mut safety_store)?;
        // Dropping the private linear owners models a process cut after C was
        // durable but before App D was acknowledged to K.
        drop((persisted, application_owner, safety_store, pinned_signer));
        Ok(())
    }

    /// Authors the genuine durable `O + App absent` owner-drop/reopen cut for
    /// the unified obligation-takeover test. The real rev1 Ordinary row is
    /// committed and acknowledged by the original narrow Core owner, but the
    /// released request is dropped before App creates a reservation. No
    /// process-local request, callback, Core, or store owner escapes.
    #[cfg(all(test, feature = "recovery-test-support", target_os = "linux"))]
    fn author_exact_empty_h1_obligation_cut_for_test_v0(
        self,
        proposal: SignedProposalV0,
        cut: AuthenticatedGenesisH1ObligationAppCutForTestV0,
    ) -> Result<(), PocoNodeAuthenticatedGenesisH1RunErrorV0> {
        let verifier = &StrictEd25519Verifier;
        let Self {
            core_config,
            prepared,
            inactive_h1_expectation,
            safety_store_path,
            signer_journal_path,
            application_path,
            store_parents,
            mut safety_store,
            application_owner,
            mut pinned_signer,
            facts: commissioning_facts,
        } = self;
        let initial_signer = pinned_signer.reconciliation_facts();
        validate_initial_virgin_signer_v0(&pinned_signer, initial_signer, &core_config)
            .map_err(map_h1_commissioning_error_v0)?;
        let confirmed_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &confirmed_signer,
            &core_config,
        )
        .map_err(map_h1_commissioning_error_v0)?;
        drop(confirmed_signer);
        revalidate_h1_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;
        let tag5 = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)?;
        validate_safety_capability_v0(&prepared, &safety_store, &safety_store_path, &tag5)
            .map_err(map_h1_commissioning_error_v0)?;
        let application_capability = application_owner.fresh_confirm_exact_v0(
            &prepared,
            &safety_store,
            &safety_store_path,
        )?;
        validate_application_capability_v0(
            &prepared,
            &application_owner,
            &application_path,
            &tag5,
            &application_capability,
        )
        .map_err(map_h1_commissioning_error_v0)?;
        if application_capability.row_checksum_v0()
            != commissioning_facts.application_row_checksum()
            || application_capability.recovery_closure_checksum_v0()
                != commissioning_facts.application_recovery_closure_checksum()
        {
            return Err(PocoNodeAuthenticatedGenesisH1RunErrorV0::ApplicationCapabilityMismatch);
        }
        let registrar = application_owner.into_h1_offline_application_registrar_v0(
            application_capability,
            inactive_h1_expectation,
        );
        let activation = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            core_config,
            prepared,
            verifier,
        )?;
        let mut application_owner =
            activation
                .activate_application_v0(registrar)
                .map_err(|rejection| {
                    PocoNodeAuthenticatedGenesisH1RunErrorV0::Application(rejection.cause())
                })?;
        let request = application_owner.admit_h1_and_release_validation_request_v0(
            proposal,
            tag5,
            &mut safety_store,
            verifier,
        )?;
        match cut {
            AuthenticatedGenesisH1ObligationAppCutForTestV0::Absent => drop(request),
            AuthenticatedGenesisH1ObligationAppCutForTestV0::Reserved => {
                application_owner.stop_after_exact_reserved_for_recovery_test_v0(request)?;
            }
            AuthenticatedGenesisH1ObligationAppCutForTestV0::CallbackPending => {
                let accepted = application_owner
                    .prepare_seal_and_submit_empty_synced_valid_v0(request, verifier)?;
                drop(accepted);
            }
            AuthenticatedGenesisH1ObligationAppCutForTestV0::Delivered => {
                let accepted = application_owner
                    .prepare_seal_and_submit_empty_synced_valid_v0(request, verifier)?;
                let delivered =
                    application_owner.mark_h1_valid_delivered_v0(accepted, &safety_store)?;
                drop(delivered);
            }
        }
        drop((application_owner, safety_store, pinned_signer));
        Ok(())
    }

    fn run_exact_empty_h1_valid_strict_v0(
        self,
        proposal: SignedProposalV0,
    ) -> Result<
        PocoNodeAuthenticatedGenesisH1CompletedHostV0<W>,
        PocoNodeAuthenticatedGenesisH1RunErrorV0,
    > {
        let verifier = &StrictEd25519Verifier;
        let Self {
            core_config,
            prepared,
            inactive_h1_expectation,
            safety_store_path,
            signer_journal_path,
            application_path,
            store_parents,
            mut safety_store,
            application_owner,
            mut pinned_signer,
            facts: commissioning_facts,
        } = self;

        // Signer and all three parent identities are checked before activating
        // the bounded Core owner. This is read-only and performs no CAS.
        let initial_signer = pinned_signer.reconciliation_facts();
        validate_initial_virgin_signer_v0(&pinned_signer, initial_signer, &core_config)
            .map_err(map_h1_commissioning_error_v0)?;
        let confirmed_start_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &confirmed_start_signer,
            &core_config,
        )
        .map_err(map_h1_commissioning_error_v0)?;
        drop(confirmed_start_signer);
        revalidate_h1_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;

        let tag5 = safety_store
            .confirmed_authenticated_genesis_application_bootstrap_head_exact_v0(&prepared)?;
        validate_safety_capability_v0(&prepared, &safety_store, &safety_store_path, &tag5)
            .map_err(map_h1_commissioning_error_v0)?;
        let application_capability = application_owner.fresh_confirm_exact_v0(
            &prepared,
            &safety_store,
            &safety_store_path,
        )?;
        validate_application_capability_v0(
            &prepared,
            &application_owner,
            &application_path,
            &tag5,
            &application_capability,
        )
        .map_err(map_h1_commissioning_error_v0)?;
        if application_capability.row_checksum_v0()
            != commissioning_facts.application_row_checksum()
            || application_capability.recovery_closure_checksum_v0()
                != commissioning_facts.application_recovery_closure_checksum()
        {
            return Err(PocoNodeAuthenticatedGenesisH1RunErrorV0::ApplicationCapabilityMismatch);
        }

        let registrar = application_owner.into_h1_offline_application_registrar_v0(
            application_capability,
            inactive_h1_expectation,
        );
        let activation = Core::begin_authenticated_genesis_application_h1_offline_validation_v0(
            core_config.clone(),
            prepared,
            verifier,
        )?;
        let mut application_owner =
            activation
                .activate_application_v0(registrar)
                .map_err(|rejection| {
                    PocoNodeAuthenticatedGenesisH1RunErrorV0::Application(rejection.cause())
                })?;
        let request = application_owner.admit_h1_and_release_validation_request_v0(
            proposal,
            tag5,
            &mut safety_store,
            verifier,
        )?;
        let accepted =
            application_owner.prepare_seal_and_submit_empty_synced_valid_v0(request, verifier)?;
        let delivered = application_owner.mark_h1_valid_delivered_v0(accepted, &safety_store)?;
        let persisted = application_owner
            .persist_and_confirm_h1_valid_safety_v0(delivered, &mut safety_store)?;
        let acked = application_owner.acknowledge_h1_valid_application_v0(persisted)?;
        let application_facts = acked.app_facts_v0();
        let valid_result_checksum = acked.valid_result_checksum_v0();
        let completed = application_owner.complete_h1_valid_v0(acked, verifier)?;
        let application_confirmation = completed.application_v0();
        let core_completed = completed.core_v0();

        // Safety C was freshly confirmed before App K. App then performed one
        // fixed-snapshot exact K confirmation after Core rev2 completed. A
        // second fresh Safety read below closes the S -> App -> S sequence
        // before path and signer freshness are checked.
        let final_safety = safety_store.confirmed_native_valid_head_v0()?;
        validate_completed_core_safety_v0(
            core_completed,
            application_facts,
            valid_result_checksum,
            commissioning_facts.application_host_config_ref(),
            application_confirmation,
            &final_safety,
        )?;

        revalidate_h1_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;
        let final_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &final_signer,
            &core_config,
        )
        .map_err(map_h1_commissioning_error_v0)?;

        let validation_id = core_completed.validation_id_v0();
        let facts = PocoNodeAuthenticatedGenesisH1CompletedFactsV0 {
            mode: PocoNodeAuthenticatedGenesisH1CompletedModeV0::AuthenticatedGenesisApplicationEmptyH1ValidCompletedInert,
            carrier_binding_ref: core_completed.authenticated_parent_binding_ref_v0(),
            block_id: core_completed.proposal_v0().block().id(),
            validation_id,
            safety_revision: final_safety.revision(),
            safety_journal_id: final_safety.journal_id_v0(),
            safety_state_record_checksum: final_safety.state_record_checksum(),
            safety_chain_checksum: final_safety.chain_checksum(),
            application_facts,
            valid_result_checksum,
            application_host_config_ref: application_confirmation
                .application_host_config_ref_v0(),
            application_delivered_job_row_checksum: application_confirmation
                .delivered_job_row_checksum_v0(),
            application_outbox_checksum: application_confirmation.outbox_checksum_v0(),
            application_acked_job_row_checksum: application_confirmation.acked_job_row_checksum_v0(),
            application_artifact_checksum: application_confirmation.artifact_checksum_v0(),
            application_overlay_checksum: application_confirmation.overlay_checksum_v0(),
            application_completion_carrier_checksum: application_confirmation.completion_carrier_checksum_v0(),
            signer_journal_id: final_signer.journal_id(),
            signer_profile_checksum: final_signer.profile_checksum(),
            signer_exact_watermark: final_signer.exact_watermark(),
        };
        drop((completed, final_safety, final_signer));
        Ok(PocoNodeAuthenticatedGenesisH1CompletedHostV0 {
            safety_store,
            application_owner,
            pinned_signer,
            facts,
        })
    }
}

impl<W> fmt::Debug for PocoNodeAuthenticatedGenesisCommissioningHostV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.core_config,
            &self.prepared,
            &self.safety_store_path,
            &self.signer_journal_path,
            &self.application_path,
            &self.store_parents,
            &self.safety_store,
            &self.application_owner,
            &self.pinned_signer,
        );
        formatter
            .debug_struct("PocoNodeAuthenticatedGenesisCommissioningHostV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0<W> {
    /// Reopens only an already-durable rev2/tag-2 Safety head and its exact
    /// schema-v14 App `Delivered` or `Acked` source. The signer is pinned and
    /// proven Exact first; missing or non-Exact signer state therefore fails
    /// before Safety/App are opened. `C+D` performs the single detached App
    /// D-to-K transaction, while `C+K` remains a read-only confirmation.
    #[allow(clippy::result_large_err)]
    pub fn open_existing_exact_v0(
        config: PocoNodeAuthenticatedGenesisH1StableRecoveryConfigV0,
        prepared: PreparedAuthenticatedGenesisApplicationBootstrapV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0> {
        let PocoNodeAuthenticatedGenesisCommissioningConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
            application,
            store_parents,
        } = config.inner;
        let core_config = safety_store_profile.core_config().clone();
        validate_prepared_bootstrap_v0(
            &core_config,
            safety_store_profile.record_limits(),
            &prepared,
        )
        .map_err(|_| {
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::PreparedBootstrapMismatch
        })?;
        let application_path = application
            .state_path
            .as_deref()
            .ok_or(PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::InvalidConfiguration)?
            .to_path_buf();
        let inactive_expectation =
            PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0::new_v0(
                &core_config,
                &prepared,
                &application,
            )
            .map_err(|_| {
                PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::PreparedBootstrapMismatch
            })?;
        revalidate_stable_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;

        // Strict signer-first ordering: no Safety/App owner has been opened at
        // this point and this pinned owner has no CAS path.
        let mut pinned_signer = PinnedSqliteSignerJournalV0::open_existing_v0(
            &signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )?;
        let initial_signer = pinned_signer.reconciliation_facts();
        validate_initial_virgin_signer_v0(&pinned_signer, initial_signer, &core_config)
            .map_err(map_stable_commissioning_error_v0)?;
        let confirmed_start_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &confirmed_start_signer,
            &core_config,
        )
        .map_err(map_stable_commissioning_error_v0)?;
        drop(confirmed_start_signer);
        revalidate_stable_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;

        let safety_store = SqliteSafetyStateStoreV0::open_existing_authenticated_genesis_application_h1_stable_native_valid_v0(
            &safety_store_path,
            safety_store_profile,
            StrictEd25519Verifier,
        )?;
        let lineage = safety_store
            .authenticated_genesis_application_h1_stable_native_valid_lineage_readback_v0()?;
        let (revision_one, revision_two) = lineage.into_core_states_v0();
        let session =
            Core::begin_authenticated_genesis_application_h1_stable_native_valid_recovery_v0(
                core_config.clone(),
                prepared,
                revision_one,
                revision_two,
                &StrictEd25519Verifier,
            )?;
        let challenge = session.challenge_v0();
        let initial_safety = safety_store
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                challenge,
            )?;
        validate_stable_safety_capability_v0(
            challenge,
            &safety_store,
            &safety_store_path,
            &initial_safety,
        )?;
        revalidate_stable_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;

        let application_config = NativeAuthenticatedGenesisH1StableRecoveryConfigV0::new(
            application,
            inactive_expectation,
        )?;
        let mut application_owner =
            NativeAuthenticatedGenesisH1StableApplicationHostV0::open_existing_v0(
                application_config,
            )?;
        let application_capability = application_owner.recover_or_confirm_exact_v0(
            challenge,
            &safety_store,
            &safety_store_path,
            initial_safety,
        )?;
        validate_stable_application_capability_v0(
            challenge,
            &application_owner,
            &application_path,
            &application_capability,
        )?;
        let source = match application_capability.source_v0() {
            NativeAuthenticatedGenesisH1StableApplicationSourceV0::Delivered => {
                PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0::DeliveredToAcked
            }
            NativeAuthenticatedGenesisH1StableApplicationSourceV0::Acked => {
                PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0::Acked
            }
        };

        // Final freshness is S -> App K -> S. The first App capability may
        // record that this call performed D-to-K; the fresh capability must
        // describe the exact same K poststate and is the reconciler consumed
        // by Core below.
        let safety_before_app = safety_store
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                challenge,
            )?;
        validate_stable_safety_capability_v0(
            challenge,
            &safety_store,
            &safety_store_path,
            &safety_before_app,
        )?;
        let mut final_application = application_owner.fresh_confirm_exact_v0(
            challenge,
            &safety_store,
            &safety_store_path,
        )?;
        validate_stable_application_capability_v0(
            challenge,
            &application_owner,
            &application_path,
            &final_application,
        )?;
        if !same_stable_application_poststate_v0(&application_capability, &final_application) {
            return Err(
                PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::ApplicationCapabilityMismatch,
            );
        }
        let final_safety = safety_store
            .confirmed_authenticated_genesis_application_h1_stable_native_valid_head_exact_v0(
                challenge,
            )?;
        validate_stable_safety_capability_v0(
            challenge,
            &safety_store,
            &safety_store_path,
            &final_safety,
        )?;
        if final_application.safety_head_facts_v0() != final_safety.safety_head_facts_v0() {
            return Err(
                PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch,
            );
        }

        let attestation = challenge.attest_authenticated_reconciliation_v0(
            final_safety.safety_head_facts_v0().clone(),
            &mut final_application,
        )?;
        let mut replay = session.reconcile_and_complete_v0(attestation)?;
        let recovered = replay.release_inert_completed_facts_v0()?;
        validate_stable_recovered_closure_v0(&recovered, &final_application, &final_safety)?;

        // No durable operation occurs after the fixed S/App/S join. Parent
        // identities and the external signer watermark are observed last;
        // the latter is the return linearization point and performs zero CAS.
        revalidate_stable_store_paths_v0(
            &safety_store_path,
            &signer_journal_path,
            &application_path,
            store_parents,
        )?;
        let final_signer = pinned_signer.confirm_node_checkpoint_head_exact_v0()?;
        validate_confirmed_virgin_signer_v0(
            &pinned_signer,
            &signer_journal_path,
            initial_signer,
            &final_signer,
            &core_config,
        )
        .map_err(map_stable_commissioning_error_v0)?;

        let validation_id = final_application.validation_id_v0();
        let safety_facts = final_safety.safety_head_facts_v0();
        let facts = PocoNodeAuthenticatedGenesisH1StableRecoveryFactsV0 {
            mode: PocoNodeAuthenticatedGenesisH1StableRecoveryModeV0::AuthenticatedGenesisApplicationEmptyH1StableNativeValidRecoveredInert,
            source,
            carrier_binding_ref: final_application.carrier_binding_ref_v0(),
            block_id: validation_id.block_id(),
            validation_id,
            valid_result_checksum: final_application.valid_result_checksum_v0(),
            safety_revision: final_safety.state_v0().revision(),
            safety_journal_id: final_safety.journal_id_v0(),
            safety_core_config_ref: final_safety.core_config_ref_v0(),
            safety_state_record_checksum: final_safety.state_record_checksum_v0(),
            safety_chain_checksum: final_safety.chain_checksum_v0(),
            safety_head_checksum: safety_facts.revision_two_head_checksum_v0(),
            application_host_config_ref: final_application.application_host_config_ref_v0(),
            application_delivered_job_row_checksum: final_application.delivered_job_row_checksum_v0(),
            application_acked_job_row_checksum: final_application.acked_job_row_checksum_v0(),
            application_outbox_checksum: final_application.outbox_checksum_v0(),
            application_artifact_checksum: final_application.artifact_checksum_v0(),
            application_overlay_checksum: final_application.overlay_checksum_v0(),
            application_commissioning_row_checksum: final_application.commissioning_row_checksum_v0(),
            application_completion_carrier_checksum: final_application.completion_carrier_checksum_v0(),
            application_recovery_closure_checksum: final_application.recovery_closure_checksum_v0(),
            signer_journal_id: final_signer.journal_id(),
            signer_profile_checksum: final_signer.profile_checksum(),
            signer_exact_watermark: final_signer.exact_watermark(),
        };
        drop((
            application_capability,
            safety_before_app,
            final_safety,
            final_application,
            final_signer,
            recovered,
        ));
        Ok(Self {
            safety_store,
            application_owner,
            pinned_signer,
            facts,
        })
    }
}

fn application_commissioning_config_v0(
    application: ConsensusAppConfig,
) -> Result<
    NativeAuthenticatedGenesisApplicationCommissioningConfigV0,
    PocoNodeAuthenticatedGenesisCommissioningErrorV0,
> {
    NativeAuthenticatedGenesisApplicationCommissioningConfigV0::new(application).map_err(Into::into)
}

pub(crate) fn validate_prepared_bootstrap_v0(
    core_config: &CoreConfig,
    record_limits: SafetyStateRecordLimitsV0,
    prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
) -> Result<(), PocoNodeAuthenticatedGenesisCommissioningErrorV0> {
    let configured = core_config
        .authenticated_genesis_application_parent_v0()
        .copied()
        .ok_or(
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::AuthenticatedGenesisApplicationParentRequired,
        )?;
    let record_context = SafetyStateRecordContextV0::new(
        core_config,
        STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
        record_limits,
    )
    .map_err(|_| PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidCoreConfig)?;
    let derived_config_ref = safety_state_record_config_ref_v0(&record_context)
        .map_err(|_| PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidCoreConfig)?;
    if prepared.safety_state_record_config_ref_v0() != derived_config_ref
        || prepared.authenticated_genesis_application_parent_v0() != configured
        || prepared.safety_state().revision() != 0
        || prepared
            .safety_state()
            .authenticated_genesis_application_parent_v0()
            .copied()
            != Some(configured)
        || prepared.safety_state().state_sync_anchor().is_some()
    {
        return Err(PocoNodeAuthenticatedGenesisCommissioningErrorV0::PreparedBootstrapMismatch);
    }
    Ok(())
}

pub(crate) fn validate_initial_virgin_signer_v0<W: ExternalMonotonicWatermarkV0>(
    pinned: &PinnedSqliteSignerJournalV0<W>,
    facts: SignerJournalReconciliationFactsV0,
    core_config: &CoreConfig,
) -> Result<(), PocoNodeAuthenticatedGenesisCommissioningErrorV0> {
    let profile = pinned.profile();
    let validator_set = core_config.validator_set();
    let capacity = facts.capacity();
    if profile.chain_id() != validator_set.chain_id()
        || profile.protocol_version() != validator_set.protocol_version()
        || profile.epoch() != validator_set.epoch()
        || profile.validator_set_id() != validator_set.id()
        || profile.author() != core_config.local_validator()
        || profile.signer_profile_ref() != SIGNER_JOURNAL_PROFILE_REF_V0
        || profile.external_watermark_scope() != derive_signer_watermark_scope_v0(core_config)
        || facts.profile_checksum() != profile.profile_checksum()
        || facts.external_relation() != SignerExternalWatermarkRelationV0::Exact
        || facts.local_watermark() != facts.observed_external_watermark()
        || facts.local_watermark().scope() != profile.external_watermark_scope()
        || facts.local_watermark().journal_id() != facts.journal_id()
        || facts.local_watermark().sequence() != 0
        || facts.observed_external_watermark().sequence() != 0
        || capacity.intent_count() != 0
        || capacity.event_count() != 0
        || capacity.intent_bytes() != 0
        || capacity.maximum_safety_revision().is_some()
        || capacity.maximum_vote_view().is_some()
        || capacity.maximum_timeout_view().is_some()
        || facts.tail().is_some()
        || facts.pending_intent().is_some()
    {
        return Err(PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerNotVirgin);
    }
    Ok(())
}

pub(crate) fn validate_confirmed_virgin_signer_v0<W: ExternalMonotonicWatermarkV0>(
    pinned: &PinnedSqliteSignerJournalV0<W>,
    expected_path: &Path,
    initial: SignerJournalReconciliationFactsV0,
    confirmed: &ConfirmedSignerNodeCheckpointFactsV0,
    core_config: &CoreConfig,
) -> Result<(), PocoNodeAuthenticatedGenesisCommissioningErrorV0> {
    let profile = pinned.profile();
    let identity = confirmed.identity();
    let validator_set = core_config.validator_set();
    let capacity = confirmed.capacity();
    if !confirmed.belongs_to_pinned_journal_at_path_v0(pinned, expected_path)
        || confirmed.journal_id() != initial.journal_id()
        || confirmed.profile_checksum() != initial.profile_checksum()
        || confirmed.profile_checksum() != profile.profile_checksum()
        || identity.chain_id() != validator_set.chain_id()
        || identity.protocol_version() != validator_set.protocol_version()
        || identity.epoch() != validator_set.epoch()
        || identity.validator_set_id() != validator_set.id()
        || identity.author() != core_config.local_validator()
        || identity.signer_profile_ref() != SIGNER_JOURNAL_PROFILE_REF_V0
        || identity.external_watermark_scope() != derive_signer_watermark_scope_v0(core_config)
        || confirmed.exact_watermark() != initial.local_watermark()
        || confirmed.exact_watermark().scope() != identity.external_watermark_scope()
        || confirmed.exact_watermark().journal_id() != confirmed.journal_id()
        || confirmed.exact_watermark().sequence() != 0
        || capacity.intent_count() != 0
        || capacity.event_count() != 0
        || capacity.intent_bytes() != 0
        || capacity.maximum_safety_revision().is_some()
        || capacity.maximum_vote_view().is_some()
        || capacity.maximum_timeout_view().is_some()
        || confirmed.tail().is_some()
        || confirmed.pending_intent().is_some()
    {
        return Err(PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerCapabilityMismatch);
    }
    Ok(())
}

fn validate_safety_capability_v0(
    prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
    store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    expected_path: &Path,
    confirmed: &ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
) -> Result<(), PocoNodeAuthenticatedGenesisCommissioningErrorV0> {
    let parent = prepared.authenticated_genesis_application_parent_v0();
    let transition = confirmed.transition_v0();
    if !confirmed.belongs_to_store_at_path_v0(store, expected_path)
        || confirmed.state_v0() != prepared.safety_state()
        || confirmed.revision_v0() != 0
        || confirmed.verifier_profile_ref_v0() != STRICT_ED25519_VERIFIER_PROFILE_REF_V0
        || confirmed.core_config_ref_v0() != prepared.safety_state_record_config_ref_v0()
        || transition.carrier() != parent
        || transition.carrier_binding_ref() != parent.binding_ref_v0()
        || transition.transition_revision() != 0
        || transition.state_record_checksum() != confirmed.state_record_checksum_v0()
    {
        return Err(PocoNodeAuthenticatedGenesisCommissioningErrorV0::SafetyCapabilityMismatch);
    }
    Ok(())
}

fn validate_application_capability_v0(
    prepared: &PreparedAuthenticatedGenesisApplicationBootstrapV0,
    host: &NativeAuthenticatedGenesisApplicationCommissioningHostV0,
    expected_path: &Path,
    safety: &ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
    application: &ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
) -> Result<(), PocoNodeAuthenticatedGenesisCommissioningErrorV0> {
    let parent = prepared.authenticated_genesis_application_parent_v0();
    if !application.belongs_to_host_at_path_v0(host, expected_path)
        || application.carrier_binding_ref_v0() != parent.binding_ref_v0()
        || application.descriptor_ref_v0() != parent.descriptor_ref()
        || application.projection_profile_ref_v0() != parent.projection_profile_ref()
        || application.application_host_config_ref_v0() == [0; 32]
        || application.safety_journal_id_v0() != safety.journal_id_v0()
        || application.safety_verifier_profile_ref_v0() != safety.verifier_profile_ref_v0()
        || application.safety_core_config_ref_v0() != safety.core_config_ref_v0()
        || application.safety_revision_v0() != safety.revision_v0()
        || application.safety_state_record_checksum_v0() != safety.state_record_checksum_v0()
        || application.safety_transition_context_checksum_v0()
            != safety.transition_context_checksum_v0()
        || application.safety_chain_checksum_v0() != safety.chain_checksum_v0()
        || application.safety_head_checksum_v0() != safety.head_checksum_v0()
        || application.recovery_closure_checksum_v0() == [0; 32]
        || application.row_checksum_v0() == [0; 32]
    {
        return Err(
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationCapabilityMismatch,
        );
    }
    Ok(())
}

fn revalidate_store_paths_v0(
    safety_path: &Path,
    signer_path: &Path,
    application_path: &Path,
    expected: ProcessStoreParentIdentitiesV0,
) -> Result<(), PocoNodeAuthenticatedGenesisCommissioningErrorV0> {
    revalidate_process_store_paths_v0(safety_path, signer_path, application_path, expected)
        .map_err(|_| PocoNodeAuthenticatedGenesisCommissioningErrorV0::StoreParentIdentityChanged)
}

fn revalidate_h1_store_paths_v0(
    safety_path: &Path,
    signer_path: &Path,
    application_path: &Path,
    expected: ProcessStoreParentIdentitiesV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1RunErrorV0> {
    revalidate_process_store_paths_v0(safety_path, signer_path, application_path, expected)
        .map_err(|_| PocoNodeAuthenticatedGenesisH1RunErrorV0::StoreParentIdentityChanged)
}

fn map_h1_commissioning_error_v0(
    error: PocoNodeAuthenticatedGenesisCommissioningErrorV0,
) -> PocoNodeAuthenticatedGenesisH1RunErrorV0 {
    match error {
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerJournal(error) => {
            PocoNodeAuthenticatedGenesisH1RunErrorV0::SignerJournal(error)
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SafetyStore(error) => {
            PocoNodeAuthenticatedGenesisH1RunErrorV0::SafetyStore(error)
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::Application(error) => {
            PocoNodeAuthenticatedGenesisH1RunErrorV0::ApplicationCommissioning(error)
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerNotVirgin
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1RunErrorV0::SignerCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SafetyCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1RunErrorV0::SafetyCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1RunErrorV0::ApplicationCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::StoreParentIdentityChanged
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::StoreParentUnavailable
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidStorePath
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::OverlappingStoreNamespaces => {
            PocoNodeAuthenticatedGenesisH1RunErrorV0::StoreParentIdentityChanged
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidCoreConfig
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::AuthenticatedGenesisApplicationParentRequired
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::PreparedBootstrapMismatch
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::ProductionActivationRequested
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::NonShadowRolloutRequested
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::UnsupportedEpoch { .. }
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidApplicationConfig
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationChainMismatch
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationAuthorityConfigured => {
            PocoNodeAuthenticatedGenesisH1RunErrorV0::CompletedClosureMismatch
        }
    }
}

fn map_stable_commissioning_error_v0(
    error: PocoNodeAuthenticatedGenesisCommissioningErrorV0,
) -> PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0 {
    match error {
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerJournal(error) => {
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SignerJournal(error)
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerNotVirgin
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SignerCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SafetyStore(error) => {
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyStore(error)
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::SafetyCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationCapabilityMismatch => {
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::ApplicationCapabilityMismatch
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::StoreParentIdentityChanged
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::StoreParentUnavailable
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidStorePath
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::OverlappingStoreNamespaces => {
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::StoreParentIdentityChanged
        }
        PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidCoreConfig
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::AuthenticatedGenesisApplicationParentRequired
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::PreparedBootstrapMismatch
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::ProductionActivationRequested
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::NonShadowRolloutRequested
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::UnsupportedEpoch { .. }
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidApplicationConfig
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationChainMismatch
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::ApplicationAuthorityConfigured
        | PocoNodeAuthenticatedGenesisCommissioningErrorV0::Application(_) => {
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::InvalidConfiguration
        }
    }
}

fn revalidate_stable_store_paths_v0(
    safety_path: &Path,
    signer_path: &Path,
    application_path: &Path,
    expected: ProcessStoreParentIdentitiesV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0> {
    revalidate_process_store_paths_v0(safety_path, signer_path, application_path, expected).map_err(
        |_| PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::StoreParentIdentityChanged,
    )
}

pub(crate) fn validate_stable_safety_capability_v0(
    challenge: &trnm_consensus_core::AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
    store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    expected_path: &Path,
    confirmed: &ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0> {
    let delivery = confirmed.application_delivery_facts_v0();
    if !confirmed.belongs_to_store_at_path_v0(store, expected_path)
        || confirmed.state_v0() != challenge.revision_two_state_v0()
        || confirmed.verifier_profile_ref_v0() != STRICT_ED25519_VERIFIER_PROFILE_REF_V0
        || confirmed.core_config_ref_v0() != challenge.safety_state_record_config_ref_v0()
        || confirmed.state_record_checksum_v0() == [0; 32]
        || confirmed.chain_checksum_v0() == [0; 32]
        || confirmed
            .safety_head_facts_v0()
            .revision_two_head_checksum_v0()
            == [0; 32]
        || delivery.validation_id() != challenge.validation_id_v0()
        || delivery.valid_result_checksum() != challenge.valid_result_checksum_v0()
        || confirmed
            .safety_head_facts_v0()
            .completion_carrier_checksum_v0()
            != challenge.completion_carrier_checksum_v0()
    {
        return Err(PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SafetyCapabilityMismatch);
    }
    Ok(())
}

pub(crate) fn validate_stable_application_capability_v0(
    challenge: &trnm_consensus_core::AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
    host: &NativeAuthenticatedGenesisH1StableApplicationHostV0,
    expected_path: &Path,
    confirmed: &ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0> {
    let carrier_binding_ref = challenge
        .revision_zero_state_v0()
        .authenticated_genesis_application_parent_v0()
        .map(|carrier| carrier.binding_ref_v0());
    if !confirmed.belongs_to_host_at_path_v0(host, expected_path)
        || confirmed.validation_id_v0() != challenge.validation_id_v0()
        || confirmed.valid_result_checksum_v0() != challenge.valid_result_checksum_v0()
        || Some(confirmed.carrier_binding_ref_v0()) != carrier_binding_ref
        || confirmed.completion_carrier_checksum_v0() != challenge.completion_carrier_checksum_v0()
        || [
            confirmed.delivered_job_row_checksum_v0(),
            confirmed.acked_job_row_checksum_v0(),
            confirmed.outbox_checksum_v0(),
            confirmed.artifact_checksum_v0(),
            confirmed.overlay_checksum_v0(),
            confirmed.application_host_config_ref_v0(),
            confirmed.commissioning_row_checksum_v0(),
            confirmed.recovery_closure_checksum_v0(),
        ]
        .contains(&[0; 32])
    {
        return Err(
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::ApplicationCapabilityMismatch,
        );
    }
    Ok(())
}

pub(crate) fn same_stable_application_poststate_v0(
    left: &ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
    right: &ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
) -> bool {
    left.validation_id_v0() == right.validation_id_v0()
        && left.valid_result_checksum_v0() == right.valid_result_checksum_v0()
        && left.delivered_job_row_checksum_v0() == right.delivered_job_row_checksum_v0()
        && left.acked_job_row_checksum_v0() == right.acked_job_row_checksum_v0()
        && left.outbox_checksum_v0() == right.outbox_checksum_v0()
        && left.artifact_checksum_v0() == right.artifact_checksum_v0()
        && left.overlay_checksum_v0() == right.overlay_checksum_v0()
        && left.application_host_config_ref_v0() == right.application_host_config_ref_v0()
        && left.carrier_binding_ref_v0() == right.carrier_binding_ref_v0()
        && left.commissioning_row_checksum_v0() == right.commissioning_row_checksum_v0()
        && left.completion_carrier_checksum_v0() == right.completion_carrier_checksum_v0()
        && left.recovery_closure_checksum_v0() == right.recovery_closure_checksum_v0()
        && left.safety_head_facts_v0() == right.safety_head_facts_v0()
}

pub(crate) fn validate_stable_recovered_closure_v0(
    recovered: &AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0,
    application: &ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
    safety: &ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0> {
    if recovered.proposal_v0().block().id() != application.validation_id_v0().block_id()
        || recovered.completion_v0().id() != application.validation_id_v0()
        || recovered.terminal_fact_v0().block_id() != application.validation_id_v0().block_id()
        || recovered.completion_carrier_checksum_v0()
            != application.completion_carrier_checksum_v0()
        || recovered.safety_head_facts_v0() != safety.safety_head_facts_v0()
    {
        return Err(PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::RecoveredClosureMismatch);
    }
    Ok(())
}

fn validate_completed_core_safety_v0(
    completed: &AuthenticatedGenesisApplicationH1CompletedV0,
    application_facts: NativeValidationValidAppFactsV0,
    valid_result_checksum: [u8; 32],
    commissioned_application_host_config_ref: [u8; 32],
    application: NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
    safety: &trnm_consensus_safety_store::ConfirmedNativeValidHeadV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1RunErrorV0> {
    let completion = completed.completion_v0();
    let terminal = completed.terminal_fact_v0();
    let transition = safety.transition();
    let proposal_id = completed.proposal_v0().block().id();
    if completed.safety_revision_v0() != 2
        || safety.revision() != 2
        || completion.first_recorded_revision() != 2
        || terminal.first_recorded_revision() != 2
        || completion.id() != completed.validation_id_v0()
        || completion.id() != application_facts.validation_id()
        || application.validation_id_v0() != completion.id()
        || application.valid_result_checksum_v0() != valid_result_checksum
        || application.acked_job_row_checksum_v0() == [0; 32]
        || application.artifact_checksum_v0() != application_facts.artifact_checksum()
        || application.overlay_checksum_v0()
            != application_facts
                .artifact_ref()
                .overlay()
                .overlay_checksum()
        || application.completion_carrier_checksum_v0() == [0; 32]
        || completion.id().block_id() != proposal_id
        || terminal.block_id() != proposal_id
        || terminal.valid_overlay().is_none()
        || transition.validation_id() != completion.id()
        || transition.request_fingerprint() != application_facts.request_fingerprint()
        || transition.job_immutable_checksum() != application_facts.immutable_checksum()
        || transition.valid_result_checksum() != valid_result_checksum
        || transition.callback_payload_checksum() != application_facts.callback_payload_checksum()
        || transition.idempotency_key() != application_facts.idempotency_key()
        || transition.delivery_attempt() != application_facts.delivery_attempt()
        || transition.completion_revision() != 2
        || safety.post_ack_action_v0() != trnm_consensus_core::NativeValidPostAckActionV0::None
        || safety.state().payload_validation_completions() != [completion.clone()]
        || safety.state().payload_terminal_facts() != [terminal]
    {
        return Err(PocoNodeAuthenticatedGenesisH1RunErrorV0::CompletedClosureMismatch);
    }
    validate_completed_delivery_provenance_v0(
        commissioned_application_host_config_ref,
        CompletedApplicationDeliveryProvenanceV0::from_confirmation_v0(application),
        CompletedSafetyDeliveryProvenanceV0::from_transition_v0(transition),
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompletedApplicationDeliveryProvenanceV0 {
    application_host_config_ref: [u8; 32],
    delivered_job_row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
}

impl CompletedApplicationDeliveryProvenanceV0 {
    const fn from_confirmation_v0(
        confirmation: NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
    ) -> Self {
        Self {
            application_host_config_ref: confirmation.application_host_config_ref_v0(),
            delivered_job_row_checksum: confirmation.delivered_job_row_checksum_v0(),
            outbox_checksum: confirmation.outbox_checksum_v0(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompletedSafetyDeliveryProvenanceV0 {
    application_host_config_ref: [u8; 32],
    delivered_job_row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
}

impl CompletedSafetyDeliveryProvenanceV0 {
    const fn from_transition_v0(
        transition: &trnm_consensus_safety_store::NativeValidTransitionV0,
    ) -> Self {
        Self {
            application_host_config_ref: transition.application_host_config_ref(),
            delivered_job_row_checksum: transition.delivered_job_row_checksum(),
            outbox_checksum: transition.outbox_checksum(),
        }
    }
}

fn validate_completed_delivery_provenance_v0(
    commissioned_application_host_config_ref: [u8; 32],
    application: CompletedApplicationDeliveryProvenanceV0,
    safety: CompletedSafetyDeliveryProvenanceV0,
) -> Result<(), PocoNodeAuthenticatedGenesisH1RunErrorV0> {
    if commissioned_application_host_config_ref == [0; 32]
        || application.application_host_config_ref != commissioned_application_host_config_ref
        || application.application_host_config_ref != safety.application_host_config_ref
        || application.delivered_job_row_checksum == [0; 32]
        || application.delivered_job_row_checksum != safety.delivered_job_row_checksum
        || application.outbox_checksum == [0; 32]
        || application.outbox_checksum != safety.outbox_checksum
    {
        return Err(PocoNodeAuthenticatedGenesisH1RunErrorV0::CompletedClosureMismatch);
    }
    Ok(())
}

fn map_store_path_error_v0(
    error: crate::PocoNodeProcessHostErrorV0,
) -> PocoNodeAuthenticatedGenesisCommissioningErrorV0 {
    match error {
        crate::PocoNodeProcessHostErrorV0::InvalidStorePath => {
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidStorePath
        }
        crate::PocoNodeProcessHostErrorV0::StoreParentUnavailable
        | crate::PocoNodeProcessHostErrorV0::UnsupportedPlatform => {
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::StoreParentUnavailable
        }
        crate::PocoNodeProcessHostErrorV0::OverlappingStoreNamespaces => {
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::OverlappingStoreNamespaces
        }
        crate::PocoNodeProcessHostErrorV0::StoreParentIdentityChanged => {
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::StoreParentIdentityChanged
        }
        _ => PocoNodeAuthenticatedGenesisCommissioningErrorV0::InvalidStorePath,
    }
}

#[cfg(all(test, feature = "recovery-test-support", target_os = "linux"))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use trnm_consensus_app::{
        initialize_legacy_genesis_application_test_fixture_v0,
        NativeValidationRecoveryTestConfigBundleV0, CONFIG_SCHEMA_V1,
    };
    use trnm_consensus_core::{leader_for, AuthenticatedGenesisApplicationParentV0, Core};
    use trnm_consensus_signer_journal::{
        ExternalWatermarkErrorV0, SignerJournalConflictV0, SqliteSignerJournalV0,
    };
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockKind, ChainId,
        ConsensusParametersV0, ConsensusPublicKey, Epoch, ExecutionReceiptsV0, GenesisHash,
        GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion, QcReferenceV0, SignatureBytes,
        SignatureVerifier, SignedProposalV0, SigningRoot, StateRoot, Validator, ValidatorId,
        ValidatorSet, View, VotingPower,
    };

    use super::*;

    const TEST_CHAIN: ChainId = ChainId::from_static("trnm-authenticated-genesis-node-test");
    const GENESIS_TIMESTAMP_MS: u64 = 0;
    const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
    const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
    const MAXIMUM_SAFETY_DATABASE_BYTES: usize = 192 * 1024 * 1024;
    const MAXIMUM_SIGNER_INTENTS: u64 = 64;
    const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
    const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;
    const APP_VERSION_V0: u64 = 4;

    #[derive(Debug, Default)]
    struct WatermarkStateV0 {
        value: Option<SignerWatermarkV0>,
        load_calls: usize,
        compare_calls: usize,
        replace_on_load: Option<(usize, SignerWatermarkV0)>,
    }

    #[derive(Debug, Clone, Default)]
    struct SpyWatermarkV0 {
        state: Arc<Mutex<WatermarkStateV0>>,
    }

    impl SpyWatermarkV0 {
        fn load_calls(&self) -> usize {
            self.state.lock().expect("watermark test lock").load_calls
        }

        fn compare_calls(&self) -> usize {
            self.state
                .lock()
                .expect("watermark test lock")
                .compare_calls
        }

        fn current(&self) -> SignerWatermarkV0 {
            self.state
                .lock()
                .expect("watermark test lock")
                .value
                .expect("fixture watermark is initialized")
        }

        fn replace(&self, value: SignerWatermarkV0) {
            self.state.lock().expect("watermark test lock").value = Some(value);
        }

        fn replace_on_load(&self, call: usize, value: SignerWatermarkV0) {
            self.state
                .lock()
                .expect("watermark test lock")
                .replace_on_load = Some((call, value));
        }
    }

    impl ExternalMonotonicWatermarkV0 for SpyWatermarkV0 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            let mut state = self.state.lock().expect("watermark test lock");
            state.load_calls += 1;
            if state
                .replace_on_load
                .is_some_and(|(call, _)| call == state.load_calls)
            {
                let (_, replacement) = state
                    .replace_on_load
                    .take()
                    .expect("scheduled replacement remains present");
                state.value = Some(replacement);
            }
            if state.value.is_some_and(|value| value.scope() != scope) {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            Ok(state.value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            let mut state = self.state.lock().expect("watermark test lock");
            state.compare_calls += 1;
            if state.value != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            match expected {
                None if target.sequence() == 0 => {}
                Some(source)
                    if source.scope() == target.scope()
                        && source.journal_id() == target.journal_id()
                        && source.sequence().checked_add(1) == Some(target.sequence()) => {}
                _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
            }
            state.value = Some(target);
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct RootSignaturesV0;

    impl SignatureVerifier for RootSignaturesV0 {
        fn verify(
            &self,
            _validator: &Validator,
            signing_root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            signature.as_bytes()[..32] == signing_root.as_bytes()[..]
                && signature.as_bytes()[32..] == signing_root.as_bytes()[..]
        }
    }

    struct CommissioningFixtureV0 {
        _root: TempDir,
        safety_path: PathBuf,
        signer_path: PathBuf,
        application: ConsensusAppConfig,
        core_config: CoreConfig,
        genesis_qc: GenesisQcV0,
        watermark: SpyWatermarkV0,
    }

    impl CommissioningFixtureV0 {
        fn node_config(
            &self,
        ) -> Result<
            PocoNodeAuthenticatedGenesisCommissioningConfigV0,
            PocoNodeAuthenticatedGenesisCommissioningErrorV0,
        > {
            PocoNodeAuthenticatedGenesisCommissioningConfigV0::new(
                &self.safety_path,
                &self.signer_path,
                self.core_config.clone(),
                record_limits_v0(),
                MAXIMUM_SAFETY_DATABASE_BYTES,
                MAXIMUM_SIGNER_INTENTS,
                MAXIMUM_SIGNER_INTENT_BYTES,
                MAXIMUM_SIGNER_DATABASE_BYTES,
                self.application.clone(),
            )
        }

        fn stable_recovery_config(
            &self,
        ) -> Result<
            PocoNodeAuthenticatedGenesisH1StableRecoveryConfigV0,
            PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0,
        > {
            PocoNodeAuthenticatedGenesisH1StableRecoveryConfigV0::new(
                &self.safety_path,
                &self.signer_path,
                self.core_config.clone(),
                record_limits_v0(),
                MAXIMUM_SAFETY_DATABASE_BYTES,
                MAXIMUM_SIGNER_INTENTS,
                MAXIMUM_SIGNER_INTENT_BYTES,
                MAXIMUM_SIGNER_DATABASE_BYTES,
                self.application.clone(),
            )
        }

        fn takeover_config(
            &self,
        ) -> Result<
            crate::PocoNodeAuthenticatedGenesisH1TakeoverConfigV0,
            crate::PocoNodeAuthenticatedGenesisH1TakeoverErrorV0,
        > {
            crate::PocoNodeAuthenticatedGenesisH1TakeoverConfigV0::new(
                &self.safety_path,
                &self.signer_path,
                self.core_config.clone(),
                record_limits_v0(),
                MAXIMUM_SAFETY_DATABASE_BYTES,
                MAXIMUM_SIGNER_INTENTS,
                MAXIMUM_SIGNER_INTENT_BYTES,
                MAXIMUM_SIGNER_DATABASE_BYTES,
                self.application.clone(),
            )
        }

        fn prepared(&self) -> PreparedAuthenticatedGenesisApplicationBootstrapV0 {
            Core::prepare_authenticated_genesis_application_bootstrap_v0(
                self.core_config.clone(),
                self.genesis_qc.clone(),
                STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
                record_limits_v0(),
                &RootSignaturesV0,
            )
            .expect("prepare exact inert authenticated-genesis facts")
        }

        /// Builds the exact externally signed, empty epoch-zero h1 accepted by
        /// the bounded production driver.  The node host never owns or invokes
        /// this signing key; the helper models an already-authenticated network
        /// proposal entering the offline surface.
        fn externally_signed_empty_h1_v0(&self) -> SignedProposalV0 {
            let set = self.core_config.validator_set();
            let parameters = self.core_config.consensus_parameters();
            let justify = QcReferenceV0::genesis_anchor(self.genesis_qc.clone());
            let proposer = leader_for(set, View::new(1));
            let application_payload =
                ApplicationPayloadV0::new(Vec::new()).expect("empty h1 application payload");
            let receipts = ExecutionReceiptsV0::new(&application_payload, Vec::new())
                .expect("empty h1 execution receipts");
            let body =
                BlockBodyV0::new(application_payload, Vec::new()).expect("empty h1 block body");
            let parent = self
                .core_config
                .authenticated_genesis_application_parent_v0()
                .expect("fixture has an authenticated application parent");
            let header = BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(1),
                Height::new(1),
                BlockKind::Regular,
                parent.genesis_block_id(),
                proposer,
                set.id(),
                set.consensus_parameters_hash(),
                body.payload_root().expect("empty h1 payload root"),
                parent.state_root(),
                receipts.receipts_root().expect("empty h1 receipts root"),
                body.evidence_root().expect("empty h1 evidence root"),
                100,
                None,
            )
            .expect("canonical empty h1 header");
            let block = Block::new(
                header,
                body.application_payload()
                    .try_cev0_bytes()
                    .expect("encode empty h1 application payload"),
                Vec::new(),
            )
            .expect("canonical empty h1 block");
            let signing_root =
                ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
                    .expect("derive empty h1 proposal signing root");
            let proposer_index = set
                .validators()
                .iter()
                .position(|validator| validator.id() == proposer)
                .expect("scheduled leader is in the fixture validator set");
            let key_seed = u8::try_from(proposer_index + 1)
                .expect("fixture proposer index fits u8")
                .saturating_add(40);
            let key = SigningKey::from_bytes(&[key_seed; 32]);
            assert_eq!(
                key.verifying_key().to_bytes(),
                *set.validator(proposer)
                    .expect("fixture proposer exists")
                    .consensus_key()
                    .as_bytes()
            );
            let witness = ProposalWitnessV0::new(
                block.header(),
                justify,
                None,
                None,
                SignatureBytes::from_array(key.sign(signing_root.as_bytes()).to_bytes()),
                set,
                None,
                parameters,
                GENESIS_TIMESTAMP_MS,
            )
            .expect("canonical externally signed empty h1 witness");
            SignedProposalV0::new(block, witness, set, None, parameters, GENESIS_TIMESTAMP_MS)
                .expect("canonical externally signed empty h1 proposal")
        }
    }

    fn record_limits_v0() -> SafetyStateRecordLimitsV0 {
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid commissioning record limits")
    }

    fn protected_root_v0() -> TempDir {
        let root = TempDir::new().expect("create private commissioning root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("protect commissioning root");
        root
    }

    fn protected_parent_v0(root: &TempDir, name: &str) -> PathBuf {
        let path = root.path().join(name);
        fs::create_dir(&path).expect("create isolated commissioning parent");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("protect isolated commissioning parent");
        path
    }

    fn strict_base_core_v0() -> (CoreConfig, GenesisQcV0) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = (1_u8..=4)
            .map(|index| {
                let key = SigningKey::from_bytes(&[index.saturating_add(40); 32]);
                Validator::new(
                    ValidatorId::new([index; 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive validator power"),
                )
                .expect("valid strict validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            TEST_CHAIN,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid commissioning validator set");
        let genesis_qc = GenesisQcV0::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            &validator_set,
        )
        .expect("valid commissioning GenesisQC");
        let core = CoreConfig::new(
            ValidatorId::new([1; 32]),
            validator_set,
            parameters,
            GENESIS_TIMESTAMP_MS,
            64,
            64,
        )
        .expect("valid inert base Core config");
        (core, genesis_qc)
    }

    fn hash_domain_v0(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.domain.hash.v1");
        update_frame_v0(&mut hasher, domain.as_bytes());
        for part in parts {
            update_frame_v0(&mut hasher, part);
        }
        hasher.finalize().into()
    }

    fn update_frame_v0(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    fn signer_policy_commitment_v0(application: &ConsensusAppConfig) -> [u8; 32] {
        let mut signers = application
            .authorized_signers
            .iter()
            .map(|signer| {
                (
                    signer.signer_id.as_str(),
                    signer.signer_role.as_str(),
                    signer.public_key_hex.as_str(),
                )
            })
            .collect::<Vec<_>>();
        signers.sort_unstable();
        let mut leaves = signers
            .iter()
            .map(|(id, role, key)| {
                hash_domain_v0(
                    "trnm.cometbft.authorized-signer.v1",
                    &[id.as_bytes(), role.as_bytes(), key.as_bytes()],
                )
            })
            .collect::<Vec<_>>();
        if leaves.is_empty() {
            return hash_domain_v0(
                "trnm.merkle.empty.v1",
                &[b"trnm.cometbft.authorized-signers.v1"],
            );
        }
        while leaves.len() > 1 {
            leaves = leaves
                .chunks(2)
                .map(|pair| {
                    let left = pair[0];
                    let right = pair.get(1).copied().unwrap_or(left);
                    hash_domain_v0(
                        "trnm.merkle.parent.v1",
                        &[
                            b"trnm.cometbft.authorized-signers.v1",
                            left.as_slice(),
                            right.as_slice(),
                        ],
                    )
                })
                .collect();
        }
        leaves[0]
    }

    fn commissioning_refs_v0(
        application: &ConsensusAppConfig,
        state_root: [u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        let signer_policy = hex_string_v0(signer_policy_commitment_v0(application));
        let app_version = APP_VERSION_V0.to_be_bytes();
        let host_config_ref = hash_domain_v0(
            "trnm.consensus-app.validation-host-config.v0",
            &[
                application.chain_id.as_bytes(),
                &app_version,
                signer_policy.as_bytes(),
                b"jmt-sha256-v0.12.0",
                b"borsh-v1",
            ],
        );
        let profile_codec = 0_u16.to_be_bytes();
        let profile_ref = hash_domain_v0(
            "trnm.consensus-app.authenticated-genesis-commissioning.projection-profile.v0",
            &[
                &profile_codec,
                CONFIG_SCHEMA_V1.as_bytes(),
                b"14",
                &host_config_ref,
                b"jmt-sha256-v0.12.0",
                b"borsh-v1",
                b"trnm_validator_lifecycle_v1",
                b"poco-inactive-namespace-absent-v0",
                b"latest-only-exact-reachable-jmt-v0",
                b"virgin-command-nonce-validation-overlay-receipt-authority-v0",
                b"canonical-sqlite-row-stream-v0",
            ],
        );
        let descriptor_codec = 0_u16.to_be_bytes();
        let height = 0_u64.to_be_bytes();
        let descriptor_ref = hash_domain_v0(
            "trnm.consensus-app.authenticated-genesis-commissioning.descriptor.v0",
            &[
                &descriptor_codec,
                &host_config_ref,
                &profile_ref,
                &height,
                &state_root,
            ],
        );
        (descriptor_ref, profile_ref)
    }

    fn hex_string_v0(bytes: [u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(64);
        for byte in bytes {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        value
    }

    fn initialize_real_application_v13_v0(
        status_path: &Path,
        base_core: &CoreConfig,
    ) -> (ConsensusAppConfig, [u8; 32]) {
        let bundle = NativeValidationRecoveryTestConfigBundleV0::new(
            status_path,
            TEST_CHAIN,
            [0x71; 32],
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
        )
        .expect("construct real commissioning application config");
        let fixture = initialize_legacy_genesis_application_test_fixture_v0(&bundle, base_core)
            .expect("initialize real schema-v13 application");
        require_clean_application_checkpoint_v0(status_path);
        (fixture.application_config_v0(), fixture.state_root_v0())
    }

    fn require_clean_application_checkpoint_v0(status_path: &Path) {
        let database = PathBuf::from(format!("{}.sqlite3", status_path.display()));
        assert!(database.is_file(), "application database must exist");
        for suffix in ["-wal", "-shm", "-journal"] {
            let path = PathBuf::from(format!("{}{suffix}", database.display()));
            assert!(
                !path.exists()
                    || fs::metadata(&path)
                        .expect("inspect application sidecar")
                        .len()
                        == 0,
                "application commissioning fixture is not checkpoint-clean: {}",
                path.display()
            );
        }
    }

    fn signer_profile_v0(core: &CoreConfig) -> SignerJournalProfileV0 {
        SignerJournalProfileV0::new(
            core.validator_set().clone(),
            core.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(core),
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect("construct exact commissioning signer profile")
    }

    fn initialize_signer_v0(signer_path: &Path, core: &CoreConfig, watermark: &SpyWatermarkV0) {
        let signer = SqliteSignerJournalV0::initialize_new(
            signer_path,
            signer_profile_v0(core),
            watermark.clone(),
        )
        .expect("initialize exact virgin signer journal");
        assert_eq!(
            signer
                .capacity()
                .expect("read virgin signer capacity")
                .intent_count(),
            0
        );
        drop(signer);
    }

    fn full_commissioning_fixture_v0() -> CommissioningFixtureV0 {
        let root = protected_root_v0();
        let safety_parent = protected_parent_v0(&root, "safety");
        let signer_parent = protected_parent_v0(&root, "signer");
        let app_parent = protected_parent_v0(&root, "application");
        let safety_path = safety_parent.join("safety.sqlite3");
        let signer_path = signer_parent.join("signer.sqlite3");
        let status_path = app_parent.join("application.status");
        let (base_core, genesis_qc) = strict_base_core_v0();
        let (application, state_root) =
            initialize_real_application_v13_v0(&status_path, &base_core);
        let (descriptor_ref, projection_profile_ref) =
            commissioning_refs_v0(&application, state_root);
        let parent = AuthenticatedGenesisApplicationParentV0::new(
            base_core.genesis_block_id(),
            GENESIS_TIMESTAMP_MS,
            0,
            StateRoot::new(state_root),
            descriptor_ref,
            projection_profile_ref,
        )
        .expect("construct exact application-root carrier");
        let core_config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            base_core.local_validator(),
            base_core.validator_set().clone(),
            *base_core.consensus_parameters(),
            GENESIS_TIMESTAMP_MS,
            parent,
            base_core.max_blocks(),
            base_core.max_observed_messages(),
        )
        .expect("construct exact authenticated-genesis Core config");
        let watermark = SpyWatermarkV0::default();
        initialize_signer_v0(&signer_path, &core_config, &watermark);
        CommissioningFixtureV0 {
            _root: root,
            safety_path,
            signer_path,
            application,
            core_config,
            genesis_qc,
            watermark,
        }
    }

    fn successor_watermark_v0(current: SignerWatermarkV0) -> SignerWatermarkV0 {
        SignerWatermarkV0::from_persisted_parts(
            current.scope(),
            current.journal_id(),
            current.sequence() + 1,
            [0xee; 32],
        )
        .expect("construct external-ahead test watermark")
    }

    fn assert_parent_empty_v0(path: &Path) {
        let entries = fs::read_dir(path.parent().expect("store has a parent"))
            .expect("read store parent")
            .map(|entry| entry.expect("read store-parent entry").file_name())
            .collect::<Vec<_>>();
        assert!(entries.is_empty(), "store parent changed: {entries:?}");
    }

    #[test]
    fn authenticated_genesis_external_empty_h1_fixture_is_strictly_signed_v0() {
        let fixture = full_commissioning_fixture_v0();
        let proposal = fixture.externally_signed_empty_h1_v0();
        proposal
            .verify(
                fixture.core_config.validator_set(),
                None,
                fixture.core_config.consensus_parameters(),
                GENESIS_TIMESTAMP_MS,
                &StrictEd25519Verifier,
            )
            .expect("external empty h1 has a strict Ed25519 proposer signature");
        let header = proposal.block().header();
        let parent = fixture
            .core_config
            .authenticated_genesis_application_parent_v0()
            .expect("fixture has an authenticated application parent");
        assert_eq!(header.parent_id(), parent.genesis_block_id());
        assert_eq!(header.state_root(), parent.state_root());
        assert!(proposal.block().evidence_objects().is_empty());
    }

    #[test]
    fn authenticated_genesis_real_three_owner_empty_h1_closes_without_signing_or_cas_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-empty-h1".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let baseline_compare = fixture.watermark.compare_calls();
                let baseline_load = fixture.watermark.load_calls();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let expected_block_id = proposal.block().id();
                let host =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture.node_config().expect("construct node config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission three real owners");
                let expected_application_host_config_ref =
                    host.facts().application_host_config_ref();
                let completed = host
                    .run_exact_empty_h1_valid_v0(proposal)
                    .expect("drive exact empty h1 through P/D/C/K and Core rev2");
                let facts = completed.facts();
                assert_eq!(
                    facts.mode(),
                    PocoNodeAuthenticatedGenesisH1CompletedModeV0::AuthenticatedGenesisApplicationEmptyH1ValidCompletedInert
                );
                assert_eq!(facts.block_id(), expected_block_id);
                assert_eq!(facts.validation_id().block_id(), expected_block_id);
                assert_eq!(facts.safety_revision(), 2);
                assert_eq!(
                    facts.application_facts().validation_id(),
                    facts.validation_id()
                );
                assert_eq!(facts.application_facts().delivery_attempt(), 1);
                assert_ne!(facts.valid_result_checksum(), [0; 32]);
                assert_eq!(
                    facts.application_host_config_ref(),
                    expected_application_host_config_ref
                );
                assert_ne!(facts.application_delivered_job_row_checksum(), [0; 32]);
                assert_ne!(facts.application_outbox_checksum(), [0; 32]);
                assert_ne!(facts.application_acked_job_row_checksum(), [0; 32]);
                assert_ne!(
                    facts.application_delivered_job_row_checksum(),
                    facts.application_acked_job_row_checksum(),
                    "D and K must retain distinct canonical job-row checksums"
                );
                assert_eq!(
                    facts.application_artifact_checksum(),
                    facts.application_facts().artifact_checksum()
                );
                assert_eq!(
                    facts.application_overlay_checksum(),
                    facts
                        .application_facts()
                        .artifact_ref()
                        .overlay()
                        .overlay_checksum()
                );
                assert_ne!(facts.application_completion_carrier_checksum(), [0; 32]);
                assert!(!facts.signer_activated());
                assert!(!facts.network_started());
                assert!(!facts.timer_started());
                assert!(!facts.finalization_started());
                assert!(!facts.production_activation_enabled());
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
                assert_eq!(fixture.watermark.load_calls(), baseline_load + 4);
            })
            .expect("spawn bounded authenticated-genesis empty-h1 worker")
            .join()
            .expect("authenticated-genesis empty-h1 worker must not panic");
    }

    #[test]
    fn authenticated_genesis_completed_join_rejects_each_d_provenance_splice_v0() {
        let commissioned_host_config_ref = [0x31; 32];
        let exact_application = CompletedApplicationDeliveryProvenanceV0 {
            application_host_config_ref: commissioned_host_config_ref,
            delivered_job_row_checksum: [0x32; 32],
            outbox_checksum: [0x33; 32],
        };
        let exact_safety = CompletedSafetyDeliveryProvenanceV0 {
            application_host_config_ref: commissioned_host_config_ref,
            delivered_job_row_checksum: [0x32; 32],
            outbox_checksum: [0x33; 32],
        };
        validate_completed_delivery_provenance_v0(
            commissioned_host_config_ref,
            exact_application,
            exact_safety,
        )
        .expect("exact App K and Safety C delivery provenance joins");

        let splices = [
            CompletedApplicationDeliveryProvenanceV0 {
                application_host_config_ref: [0x41; 32],
                ..exact_application
            },
            CompletedApplicationDeliveryProvenanceV0 {
                delivered_job_row_checksum: [0x42; 32],
                ..exact_application
            },
            CompletedApplicationDeliveryProvenanceV0 {
                outbox_checksum: [0x43; 32],
                ..exact_application
            },
        ];
        for splice in splices {
            assert!(matches!(
                validate_completed_delivery_provenance_v0(
                    commissioned_host_config_ref,
                    splice,
                    exact_safety,
                ),
                Err(PocoNodeAuthenticatedGenesisH1RunErrorV0::CompletedClosureMismatch)
            ));
        }

        let safety_splices = [
            CompletedSafetyDeliveryProvenanceV0 {
                application_host_config_ref: [0x51; 32],
                ..exact_safety
            },
            CompletedSafetyDeliveryProvenanceV0 {
                delivered_job_row_checksum: [0x52; 32],
                ..exact_safety
            },
            CompletedSafetyDeliveryProvenanceV0 {
                outbox_checksum: [0x53; 32],
                ..exact_safety
            },
        ];
        for splice in safety_splices {
            assert!(matches!(
                validate_completed_delivery_provenance_v0(
                    commissioned_host_config_ref,
                    exact_application,
                    splice,
                ),
                Err(PocoNodeAuthenticatedGenesisH1RunErrorV0::CompletedClosureMismatch)
            ));
        }
    }

    #[test]
    fn authenticated_genesis_h1_takeover_a_r_p_d_complete_and_stable_dispatch_reopens_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-takeover-a-p-d".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let cases = [
                    (
                        AuthenticatedGenesisH1ObligationAppCutForTestV0::Absent,
                        crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationAbsent,
                    ),
                    (
                        AuthenticatedGenesisH1ObligationAppCutForTestV0::Reserved,
                        crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationReserved,
                    ),
                    (
                        AuthenticatedGenesisH1ObligationAppCutForTestV0::CallbackPending,
                        crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationCallbackPending,
                    ),
                    (
                        AuthenticatedGenesisH1ObligationAppCutForTestV0::Delivered,
                        crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationDelivered,
                    ),
                ];
                for (cut, expected_source) in cases {
                    let fixture = full_commissioning_fixture_v0();
                    let baseline_compare = fixture.watermark.compare_calls();
                    let proposal = fixture.externally_signed_empty_h1_v0();
                    let expected_block_id = proposal.block().id();
                    let commissioned = PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture.node_config().expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                    commissioned
                        .author_exact_empty_h1_obligation_cut_for_test_v0(proposal, cut)
                        .expect("author exact obligation plus requested App cut");

                    let recovered = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                        fixture.takeover_config().expect("construct unified takeover config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("take over obligation and close exact C+K");
                    let first = recovered.facts();
                    assert_eq!(
                        first.mode(),
                        crate::PocoNodeAuthenticatedGenesisH1TakeoverModeV0::AuthenticatedGenesisApplicationEmptyH1RecoveredInert
                    );
                    assert_eq!(first.source(), expected_source);
                    assert_eq!(first.block_id(), expected_block_id);
                    assert_eq!(first.validation_id().block_id(), expected_block_id);
                    assert_eq!(first.safety_revision(), 2);
                    assert_ne!(first.carrier_binding_ref(), [0; 32]);
                    assert_ne!(first.safety_journal_id(), [0; 32]);
                    assert_ne!(first.safety_core_config_ref(), [0; 32]);
                    assert_ne!(first.valid_result_checksum(), [0; 32]);
                    assert_ne!(first.safety_state_record_checksum(), [0; 32]);
                    assert_ne!(first.safety_chain_checksum(), [0; 32]);
                    assert_ne!(first.application_host_config_ref(), [0; 32]);
                    assert_ne!(first.application_delivered_job_row_checksum(), [0; 32]);
                    assert_ne!(first.application_acked_job_row_checksum(), [0; 32]);
                    assert_ne!(first.application_outbox_checksum(), [0; 32]);
                    assert_ne!(first.application_artifact_checksum(), [0; 32]);
                    assert_ne!(first.application_overlay_checksum(), [0; 32]);
                    assert_ne!(first.application_completion_carrier_checksum(), [0; 32]);
                    assert_ne!(first.signer_journal_id(), [0; 32]);
                    assert_ne!(first.signer_profile_checksum(), [0; 32]);
                    assert_eq!(first.signer_exact_watermark(), fixture.watermark.current());
                    assert!(!first.signer_activated());
                    assert!(!first.application_authorities_installed());
                    assert!(!first.network_started());
                    assert!(!first.timer_started());
                    assert!(!first.finalization_started());
                    assert!(!first.production_activation_enabled());
                    drop(recovered);

                    let reopened = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                        fixture.takeover_config().expect("construct stable-dispatch takeover config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("dispatch the same journal to stable C+K recovery");
                    let second = reopened.facts();
                    assert_eq!(
                        second.source(),
                        crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::StableAcked
                    );
                    assert_eq!(second.validation_id(), first.validation_id());
                    assert_eq!(second.block_id(), first.block_id());
                    assert_eq!(second.valid_result_checksum(), first.valid_result_checksum());
                    assert_eq!(second.safety_revision(), 2);
                    assert_eq!(second.carrier_binding_ref(), first.carrier_binding_ref());
                    assert_eq!(second.safety_journal_id(), first.safety_journal_id());
                    assert_eq!(second.safety_core_config_ref(), first.safety_core_config_ref());
                    assert_eq!(
                        second.application_host_config_ref(),
                        first.application_host_config_ref()
                    );
                    assert_eq!(second.signer_journal_id(), first.signer_journal_id());
                    assert_eq!(
                        second.signer_profile_checksum(),
                        first.signer_profile_checksum()
                    );
                    assert_eq!(second.signer_exact_watermark(), first.signer_exact_watermark());
                    assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
                }
            })
            .expect("spawn bounded unified takeover worker")
            .join()
            .expect("unified takeover worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_takeover_stable_c_plus_d_dispatches_to_k_then_reopens_acked_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-takeover-stable-c-d".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let baseline_compare = fixture.watermark.compare_calls();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let expected_block_id = proposal.block().id();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                commissioned
                    .author_exact_empty_h1_c_plus_d_cut_for_test_v0(proposal)
                    .expect("author genuine durable Safety C plus App D cut");

                let recovered = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture
                        .takeover_config()
                        .expect("construct unified C+D takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect("unified dispatch closes stable C+D to K");
                let first = recovered.facts();
                assert_eq!(
                    first.source(),
                    crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::StableDeliveredToAcked
                );
                assert_eq!(first.block_id(), expected_block_id);
                assert_eq!(first.validation_id().block_id(), expected_block_id);
                assert_eq!(first.safety_revision(), 2);
                assert_ne!(first.application_delivered_job_row_checksum(), [0; 32]);
                assert_ne!(first.application_acked_job_row_checksum(), [0; 32]);
                assert_ne!(
                    first.application_delivered_job_row_checksum(),
                    first.application_acked_job_row_checksum()
                );
                assert!(!first.signer_activated());
                assert!(!first.application_authorities_installed());
                assert!(!first.network_started());
                assert!(!first.timer_started());
                assert!(!first.finalization_started());
                assert!(!first.production_activation_enabled());
                drop(recovered);

                let reopened = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture
                        .takeover_config()
                        .expect("construct unified C+K takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect("unified dispatch reopens stable C+K");
                let second = reopened.facts();
                assert_eq!(
                    second.source(),
                    crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::StableAcked
                );
                assert_eq!(second.validation_id(), first.validation_id());
                assert_eq!(second.block_id(), first.block_id());
                assert_eq!(second.valid_result_checksum(), first.valid_result_checksum());
                assert_eq!(second.application_acked_job_row_checksum(), first.application_acked_job_row_checksum());
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn unified stable C+D takeover worker")
            .join()
            .expect("unified stable C+D takeover worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_takeover_prepared_mismatch_fails_before_watermark_or_store_mutation_v0(
    ) {
        std::thread::Builder::new()
            .name("authenticated-genesis-takeover-prepared-mismatch".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                commissioned
                    .author_exact_empty_h1_obligation_cut_for_test_v0(
                        proposal,
                        AuthenticatedGenesisH1ObligationAppCutForTestV0::Absent,
                    )
                    .expect("author exact O plus App-absent cut");

                let mismatched_limits = SafetyStateRecordLimitsV0::new(
                    MAXIMUM_RECORD_BYTES - 1,
                    MAXIMUM_BLOB_BYTES,
                )
                .expect("construct distinct valid record limits");
                let mismatched_prepared =
                    Core::prepare_authenticated_genesis_application_bootstrap_v0(
                        fixture.core_config.clone(),
                        fixture.genesis_qc.clone(),
                        STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
                        mismatched_limits,
                        &RootSignaturesV0,
                    )
                    .expect("prepare facts under a foreign record-limit configuration");
                let namespace_image = |store_path: &Path| {
                    let mut paths = fs::read_dir(
                        store_path
                            .parent()
                            .expect("durable store has an isolated parent"),
                    )
                    .expect("read durable store parent")
                    .map(|entry| entry.expect("read durable store entry").path())
                    .collect::<Vec<_>>();
                    paths.sort();
                    paths
                        .into_iter()
                        .map(|path| {
                            let bytes = fs::read(&path).unwrap_or_else(|error| {
                                panic!("read durable namespace file {}: {error}", path.display())
                            });
                            (path, bytes)
                        })
                        .collect::<Vec<_>>()
                };
                let application_path = fixture
                    .application
                    .state_path
                    .as_deref()
                    .expect("fixture App path");
                let safety_before = namespace_image(&fixture.safety_path);
                let application_before = namespace_image(application_path);
                let baseline_load = fixture.watermark.load_calls();
                let baseline_compare = fixture.watermark.compare_calls();

                let error = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture
                        .takeover_config()
                        .expect("construct exact takeover config"),
                    mismatched_prepared,
                    fixture.watermark.clone(),
                )
                .expect_err("foreign prepared facts must fail before opening any owner");
                assert!(matches!(
                    error,
                    crate::PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::PreparedBootstrapMismatch
                ));
                assert_eq!(fixture.watermark.load_calls(), baseline_load);
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
                assert_eq!(namespace_image(&fixture.safety_path), safety_before);
                assert_eq!(namespace_image(application_path), application_before);
            })
            .expect("spawn prepared-mismatch takeover worker")
            .join()
            .expect("prepared-mismatch takeover worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_takeover_public_entry_owns_deep_audit_stack_v0() {
        // Author the durable cut on the explicitly large setup stack used by
        // these fixtures, then invoke the public takeover entry directly on
        // libtest's ordinary caller stack. The entry must own its deep decoder
        // stack rather than requiring callers to wrap it.
        let fixture = std::thread::Builder::new()
            .name("authenticated-genesis-takeover-stack-setup".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                commissioned
                    .author_exact_empty_h1_obligation_cut_for_test_v0(
                        proposal,
                        AuthenticatedGenesisH1ObligationAppCutForTestV0::Absent,
                    )
                    .expect("author exact O plus App-absent cut");
                fixture
            })
            .expect("spawn large-stack takeover setup worker")
            .join()
            .expect("large-stack takeover setup worker must not panic");

        let baseline_compare = fixture.watermark.compare_calls();
        let recovered = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
            fixture.takeover_config().expect("construct takeover config"),
            fixture.prepared(),
            fixture.watermark.clone(),
        )
        .expect("public takeover entry owns and joins its deep audit stack");
        assert_eq!(
            recovered.facts().source(),
            crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationAbsent
        );
        assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
    }

    #[test]
    fn authenticated_genesis_h1_takeover_stable_c_plus_d_rejects_final_external_advancement_without_cas_v0(
    ) {
        std::thread::Builder::new()
            .name("authenticated-genesis-takeover-stable-final-watermark".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                commissioned
                    .author_exact_empty_h1_c_plus_d_cut_for_test_v0(proposal)
                    .expect("author genuine durable Safety C plus App D cut");

                let baseline_compare = fixture.watermark.compare_calls();
                let baseline_load = fixture.watermark.load_calls();
                let exact = fixture.watermark.current();
                fixture
                    .watermark
                    .replace_on_load(baseline_load + 3, successor_watermark_v0(exact));
                let error = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture
                        .takeover_config()
                        .expect("construct unified stable C+D takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect_err("final external advancement must reject stable C+D takeover return");
                assert!(
                    matches!(
                        error,
                        crate::PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SignerJournal(
                            SignerJournalErrorV0::Conflict(
                                SignerJournalConflictV0::ExternalWatermarkAhead
                            )
                        )
                    ),
                    "unexpected stable C+D takeover final-watermark error: {error:?}"
                );
                assert_eq!(fixture.watermark.load_calls(), baseline_load + 3);
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);

                fixture.watermark.replace(exact);
                let reopened = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture
                        .takeover_config()
                        .expect("construct exact post-rejection takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect("failed final freshness leaves exact C+K stores reopenable");
                assert_eq!(
                    reopened.facts().source(),
                    crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::StableAcked
                );
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn stable C+D takeover final-watermark worker")
            .join()
            .expect("stable C+D takeover final-watermark worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_takeover_rejects_final_external_advancement_without_cas_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-takeover-final-watermark".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture.node_config().expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                commissioned
                    .author_exact_empty_h1_obligation_cut_for_test_v0(
                        proposal,
                        AuthenticatedGenesisH1ObligationAppCutForTestV0::Absent,
                    )
                    .expect("author exact O plus App-absent cut");

                let baseline_compare = fixture.watermark.compare_calls();
                let baseline_load = fixture.watermark.load_calls();
                let exact = fixture.watermark.current();
                // Pin-open loads twice. The third load is the final signer
                // freshness observation after the complete S/App/S join.
                fixture
                    .watermark
                    .replace_on_load(baseline_load + 3, successor_watermark_v0(exact));
                let error = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture.takeover_config().expect("construct takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect_err("final external advancement must reject takeover return");
                assert!(matches!(
                    error,
                    crate::PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SignerJournal(
                        SignerJournalErrorV0::Conflict(
                            SignerJournalConflictV0::ExternalWatermarkAhead
                        )
                    )
                ), "unexpected takeover final-watermark error: {error:?}");
                assert_eq!(fixture.watermark.load_calls(), baseline_load + 3);
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);

                fixture.watermark.replace(exact);
                let reopened = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture
                        .takeover_config()
                        .expect("construct post-rejection takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect("exact watermark permits stable C+K reopen");
                assert_eq!(
                    reopened.facts().source(),
                    crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::StableAcked
                );
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn takeover final-watermark worker")
            .join()
            .expect("takeover final-watermark worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_takeover_nonexact_signer_fails_before_safety_or_app_open_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-takeover-signer-first".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture.node_config().expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                commissioned
                    .author_exact_empty_h1_obligation_cut_for_test_v0(
                        proposal,
                        AuthenticatedGenesisH1ObligationAppCutForTestV0::Absent,
                    )
                    .expect("author exact O plus App-absent cut");

                let baseline_compare = fixture.watermark.compare_calls();
                let exact = fixture.watermark.current();
                fixture.watermark.replace(successor_watermark_v0(exact));
                let safety_lock = PathBuf::from(format!("{}.safety.lock", fixture.safety_path.display()));
                let status_path = fixture
                    .application
                    .state_path
                    .as_deref()
                    .expect("fixture App path");
                let app_database = status_path.with_extension("status.sqlite3");
                let app_lock = app_database.with_file_name(format!(
                    "{}.owner.lock",
                    app_database
                        .file_name()
                        .expect("fixture App database has a filename")
                        .to_string_lossy()
                ));
                let safety_lock_before = fs::read(&safety_lock).expect("read stable Safety lock");
                let app_lock_before = fs::read(&app_lock).expect("read stable App lock");
                let error = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture.takeover_config().expect("construct takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect_err("non-Exact signer must reject before later owners open");
                assert!(matches!(
                    error,
                    crate::PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SignerJournal(
                        SignerJournalErrorV0::Conflict(
                            SignerJournalConflictV0::ExternalWatermarkAhead
                        )
                    )
                ), "unexpected takeover signer-first error: {error:?}");
                assert_eq!(fs::read(&safety_lock).expect("reread Safety lock"), safety_lock_before);
                assert_eq!(fs::read(&app_lock).expect("reread App lock"), app_lock_before);
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);

                fixture.watermark.replace(exact);
                let recovered = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture.takeover_config().expect("construct exact takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect("exact signer permits obligation takeover");
                assert_eq!(
                    recovered.facts().source(),
                    crate::PocoNodeAuthenticatedGenesisH1TakeoverSourceV0::ObligationAbsent
                );
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn takeover signer-first worker")
            .join()
            .expect("takeover signer-first worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_takeover_rejects_commissioned_tag5_rev0_without_app_mutation_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-takeover-tag5-rejection".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let baseline_compare = fixture.watermark.compare_calls();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact tag-5 Safety and App owners");
                let commissioned_facts = commissioned.facts();
                drop(commissioned);

                let status_path = fixture
                    .application
                    .state_path
                    .as_deref()
                    .expect("fixture App path");
                let app_database = status_path.with_extension("status.sqlite3");
                let app_lock = app_database.with_file_name(format!(
                    "{}.owner.lock",
                    app_database
                        .file_name()
                        .expect("fixture App database has a filename")
                        .to_string_lossy()
                ));
                let app_database_before =
                    fs::read(&app_database).expect("read commissioned App database");
                let app_lock_before = fs::read(&app_lock).expect("read commissioned App lock");

                let error = crate::PocoNodeAuthenticatedGenesisH1TakeoverHostV0::open_existing_and_complete_exact_v0(
                    fixture
                        .takeover_config()
                        .expect("construct exact takeover config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect_err("commissioned tag-5/rev0 is not a supported h1 takeover cut");
                assert!(
                    matches!(
                        error,
                        crate::PocoNodeAuthenticatedGenesisH1TakeoverErrorV0::SafetyStore(
                            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                                "authenticated-genesis h1 dispatch supports only exact rev1 obligation or rev2 NativeValid"
                            )
                        )
                    ),
                    "unexpected commissioned tag-5 takeover error: {error:?}"
                );
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
                assert_eq!(
                    fs::read(&app_database).expect("reread commissioned App database"),
                    app_database_before
                );
                assert_eq!(
                    fs::read(&app_lock).expect("reread commissioned App lock"),
                    app_lock_before
                );

                let reopened =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct post-rejection commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("unsupported dispatch leaves exact commissioned owners reopenable");
                let expected_reopened_facts = PocoNodeAuthenticatedGenesisCommissioningFactsV0 {
                    safety_disposition:
                        AuthenticatedGenesisApplicationInitializationDispositionV0::Existing,
                    application_disposition:
                        NativeAuthenticatedGenesisApplicationCommissioningDispositionV0::Existing,
                    ..commissioned_facts
                };
                assert_eq!(reopened.facts(), expected_reopened_facts);
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn commissioned tag-5 rejection worker")
            .join()
            .expect("commissioned tag-5 rejection worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_stable_c_plus_k_reopens_idempotently_without_cas_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-stable-c-k".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let baseline_compare = fixture.watermark.compare_calls();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture.node_config().expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                let completed = commissioned
                    .run_exact_empty_h1_valid_v0(proposal)
                    .expect("author exact C+K cut");
                let expected = completed.facts();
                drop(completed);

                let first = PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0::open_existing_exact_v0(
                    fixture
                        .stable_recovery_config()
                        .expect("construct stable recovery config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect("reopen exact C+K cut");
                let first_facts = first.facts();
                assert_eq!(
                    first_facts.mode(),
                    PocoNodeAuthenticatedGenesisH1StableRecoveryModeV0::AuthenticatedGenesisApplicationEmptyH1StableNativeValidRecoveredInert
                );
                assert_eq!(
                    first_facts.source(),
                    PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0::Acked
                );
                assert_eq!(first_facts.validation_id(), expected.validation_id());
                assert_eq!(first_facts.block_id(), expected.block_id());
                assert_eq!(first_facts.safety_revision(), 2);
                assert_eq!(
                    first_facts.application_acked_job_row_checksum(),
                    expected.application_acked_job_row_checksum()
                );
                assert_eq!(
                    first_facts.application_completion_carrier_checksum(),
                    expected.application_completion_carrier_checksum()
                );
                assert!(!first_facts.signer_activated());
                assert!(!first_facts.callback_reminted());
                assert!(!first_facts.storage_ack_emitted());
                assert!(!first_facts.application_authorities_installed());
                assert!(!first_facts.network_started());
                assert!(!first_facts.timer_started());
                assert!(!first_facts.finalization_started());
                assert!(!first_facts.production_activation_enabled());
                drop(first);

                let second = PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0::open_existing_exact_v0(
                    fixture
                        .stable_recovery_config()
                        .expect("construct second stable recovery config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect("reopen exact C+K idempotently");
                assert_eq!(second.facts(), first_facts);
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn bounded stable C+K worker")
            .join()
            .expect("stable C+K worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_stable_c_plus_d_recovers_once_to_k_then_reopens_acked_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-stable-c-d".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let baseline_compare = fixture.watermark.compare_calls();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                commissioned
                    .author_exact_empty_h1_c_plus_d_cut_for_test_v0(proposal)
                    .expect("author genuine durable Safety C plus App D reopen cut");

                let first =
                    PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0::open_existing_exact_v0(
                        fixture
                            .stable_recovery_config()
                            .expect("construct stable C+D recovery config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("atomically recover C+D to C+K");
                let first_facts = first.facts();
                assert_eq!(
                    first_facts.source(),
                    PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0::DeliveredToAcked
                );
                assert_eq!(first_facts.safety_revision(), 2);
                assert_ne!(
                    first_facts.application_delivered_job_row_checksum(),
                    [0; 32]
                );
                assert_ne!(first_facts.application_acked_job_row_checksum(), [0; 32]);
                assert_ne!(
                    first_facts.application_delivered_job_row_checksum(),
                    first_facts.application_acked_job_row_checksum()
                );
                assert!(!first_facts.callback_reminted());
                assert!(!first_facts.storage_ack_emitted());
                assert!(!first_facts.signer_activated());
                drop(first);

                let second =
                    PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0::open_existing_exact_v0(
                        fixture
                            .stable_recovery_config()
                            .expect("construct stable C+K reopen config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("reopen recovered C+K idempotently");
                let second_facts = second.facts();
                assert_eq!(
                    second_facts.source(),
                    PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0::Acked
                );
                assert_eq!(
                    second_facts.application_acked_job_row_checksum(),
                    first_facts.application_acked_job_row_checksum()
                );
                assert_eq!(
                    second_facts.application_recovery_closure_checksum(),
                    first_facts.application_recovery_closure_checksum()
                );
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn bounded stable C+D worker")
            .join()
            .expect("stable C+D worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_stable_recovery_rejects_final_external_advancement_without_cas_v0()
    {
        std::thread::Builder::new()
            .name("authenticated-genesis-stable-final-watermark".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                commissioned
                    .author_exact_empty_h1_c_plus_d_cut_for_test_v0(proposal)
                    .expect("author genuine durable Safety C plus App D reopen cut");

                let baseline_compare = fixture.watermark.compare_calls();
                let baseline_load = fixture.watermark.load_calls();
                let exact = fixture.watermark.current();
                fixture
                    .watermark
                    .replace_on_load(baseline_load + 3, successor_watermark_v0(exact));
                let error =
                    PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0::open_existing_exact_v0(
                        fixture
                            .stable_recovery_config()
                            .expect("construct stable C+D recovery config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect_err(
                        "final external advancement must invalidate stable recovered return",
                    );
                assert!(
                    matches!(
                        error,
                        PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SignerJournal(
                            SignerJournalErrorV0::Conflict(
                                SignerJournalConflictV0::ExternalWatermarkAhead
                            )
                        )
                    ),
                    "unexpected stable final-watermark error: {error:?}"
                );
                assert_eq!(fixture.watermark.load_calls(), baseline_load + 3);
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);

                fixture.watermark.replace(exact);
                let recovered =
                    PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0::open_existing_exact_v0(
                        fixture
                            .stable_recovery_config()
                            .expect("construct exact C+K retry config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("failed final signer freshness leaves exact C+K stores reopenable");
                assert_eq!(
                    recovered.facts().source(),
                    PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0::Acked
                );
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn bounded stable final-watermark worker")
            .join()
            .expect("stable final-watermark worker must not panic");
    }

    #[test]
    fn authenticated_genesis_h1_stable_recovery_nonexact_signer_fails_before_later_owners_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-stable-signer-first".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let commissioned =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture.node_config().expect("construct commissioning config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission exact owners");
                drop(
                    commissioned
                        .run_exact_empty_h1_valid_v0(proposal)
                        .expect("author exact C+K cut"),
                );
                let baseline_compare = fixture.watermark.compare_calls();
                let exact = fixture.watermark.current();
                fixture.watermark.replace(successor_watermark_v0(exact));
                let error = PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0::open_existing_exact_v0(
                    fixture
                        .stable_recovery_config()
                        .expect("construct stable recovery config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect_err("external-ahead signer must fail before Safety/App open");
                assert!(matches!(
                    error,
                    PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SignerJournal(_)
                        | PocoNodeAuthenticatedGenesisH1StableRecoveryErrorV0::SignerCapabilityMismatch
                ));
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);

                fixture.watermark.replace(exact);
                let recovered = PocoNodeAuthenticatedGenesisH1StableRecoveryHostV0::open_existing_exact_v0(
                    fixture
                        .stable_recovery_config()
                        .expect("construct exact retry config"),
                    fixture.prepared(),
                    fixture.watermark.clone(),
                )
                .expect("signer-first refusal leaves stable stores exact");
                assert_eq!(
                    recovered.facts().source(),
                    PocoNodeAuthenticatedGenesisH1StableRecoverySourceV0::Acked
                );
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn bounded signer-first worker")
            .join()
            .expect("signer-first worker must not panic");
    }

    #[test]
    fn authenticated_genesis_empty_h1_rejects_final_external_advancement_without_cas_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-h1-final-watermark".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let baseline_compare = fixture.watermark.compare_calls();
                let baseline_load = fixture.watermark.load_calls();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let host =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture.node_config().expect("construct node config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission three real owners");
                fixture.watermark.replace_on_load(
                    baseline_load + 4,
                    successor_watermark_v0(fixture.watermark.current()),
                );
                let error = host
                    .run_exact_empty_h1_valid_v0(proposal)
                    .expect_err("final external advancement must invalidate completed return");
                assert!(matches!(
                    error,
                    PocoNodeAuthenticatedGenesisH1RunErrorV0::SignerJournal(_)
                        | PocoNodeAuthenticatedGenesisH1RunErrorV0::SignerCapabilityMismatch
                ));
                assert_eq!(fixture.watermark.load_calls(), baseline_load + 4);
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
            })
            .expect("spawn bounded final-watermark worker")
            .join()
            .expect("final-watermark worker must not panic");
    }

    #[test]
    fn authenticated_genesis_empty_h1_nonexact_signer_fails_before_safety_or_app_mutation_v0() {
        std::thread::Builder::new()
            .name("authenticated-genesis-h1-nonexact-signer".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let fixture = full_commissioning_fixture_v0();
                let baseline_compare = fixture.watermark.compare_calls();
                let baseline_load = fixture.watermark.load_calls();
                let proposal = fixture.externally_signed_empty_h1_v0();
                let host =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture.node_config().expect("construct node config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("commission three real owners");
                let exact = fixture.watermark.current();
                fixture
                    .watermark
                    .replace_on_load(baseline_load + 3, successor_watermark_v0(exact));
                let error = host
                    .run_exact_empty_h1_valid_v0(proposal)
                    .expect_err("non-Exact start signer must fail before h1 mutation");
                assert!(matches!(
                    error,
                    PocoNodeAuthenticatedGenesisH1RunErrorV0::SignerJournal(_)
                        | PocoNodeAuthenticatedGenesisH1RunErrorV0::SignerCapabilityMismatch
                ));
                assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
                assert_eq!(fixture.watermark.load_calls(), baseline_load + 3);

                fixture.watermark.replace(exact);
                let reopened =
                    PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
                        fixture
                            .node_config()
                            .expect("construct exact reopen config"),
                        fixture.prepared(),
                        fixture.watermark.clone(),
                    )
                    .expect("signer-first rejection leaves exact commissioned rev0/App v14");
                assert_eq!(
                    reopened.facts().safety_disposition(),
                    AuthenticatedGenesisApplicationInitializationDispositionV0::Existing
                );
                assert_eq!(
                    reopened.facts().application_disposition(),
                    NativeAuthenticatedGenesisApplicationCommissioningDispositionV0::Existing
                );
            })
            .expect("spawn bounded non-Exact signer worker")
            .join()
            .expect("non-Exact signer worker must not panic");
    }

    #[test]
    fn authenticated_genesis_commissioning_real_three_owner_reopens_existing_without_cas_v0() {
        let fixture = full_commissioning_fixture_v0();
        let baseline_compare = fixture.watermark.compare_calls();
        let baseline_load = fixture.watermark.load_calls();
        let first = PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
            fixture.node_config().expect("construct first node config"),
            fixture.prepared(),
            fixture.watermark.clone(),
        )
        .expect("commission three real owners");
        let first_facts = first.facts();
        assert_eq!(
            first_facts.safety_disposition(),
            AuthenticatedGenesisApplicationInitializationDispositionV0::Initialized
        );
        assert_eq!(
            first_facts.application_disposition(),
            NativeAuthenticatedGenesisApplicationCommissioningDispositionV0::Commissioned
        );
        assert!(!first_facts.signer_activated());
        assert!(!first_facts.application_authorities_installed());
        assert!(!first_facts.production_activation_enabled());
        assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
        assert_eq!(fixture.watermark.load_calls(), baseline_load + 2);
        drop(first);

        let second = PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
            fixture.node_config().expect("construct reopen node config"),
            fixture.prepared(),
            fixture.watermark.clone(),
        )
        .expect("reopen three exact commissioned owners");
        let second_facts = second.facts();
        assert_eq!(
            second_facts.safety_disposition(),
            AuthenticatedGenesisApplicationInitializationDispositionV0::Existing
        );
        assert_eq!(
            second_facts.application_disposition(),
            NativeAuthenticatedGenesisApplicationCommissioningDispositionV0::Existing
        );
        assert_eq!(
            second_facts.carrier_binding_ref(),
            first_facts.carrier_binding_ref()
        );
        assert_eq!(
            second_facts.safety_journal_id(),
            first_facts.safety_journal_id()
        );
        assert_eq!(
            second_facts.application_recovery_closure_checksum(),
            first_facts.application_recovery_closure_checksum()
        );
        assert_eq!(
            second_facts.signer_journal_id(),
            first_facts.signer_journal_id()
        );
        assert_eq!(
            second_facts.signer_exact_watermark(),
            first_facts.signer_exact_watermark()
        );
        assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
        assert_eq!(fixture.watermark.load_calls(), baseline_load + 4);
    }

    #[test]
    fn authenticated_genesis_commissioning_rejects_final_external_advancement_without_cas_v0() {
        let fixture = full_commissioning_fixture_v0();
        let baseline_compare = fixture.watermark.compare_calls();
        let baseline_load = fixture.watermark.load_calls();
        fixture.watermark.replace_on_load(
            baseline_load + 2,
            successor_watermark_v0(fixture.watermark.current()),
        );
        let error = PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
            fixture.node_config().expect("construct node config"),
            fixture.prepared(),
            fixture.watermark.clone(),
        )
        .expect_err("final external advancement must invalidate commissioning");
        assert!(matches!(
            error,
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerJournal(_)
        ));
        assert_eq!(fixture.watermark.load_calls(), baseline_load + 2);
        assert_eq!(fixture.watermark.compare_calls(), baseline_compare);
    }

    #[test]
    fn authenticated_genesis_commissioning_nonexact_signer_fails_before_safety_or_app_creation_v0()
    {
        let root = protected_root_v0();
        let safety_parent = protected_parent_v0(&root, "safety");
        let signer_parent = protected_parent_v0(&root, "signer");
        let app_parent = protected_parent_v0(&root, "application");
        let safety_path = safety_parent.join("safety.sqlite3");
        let signer_path = signer_parent.join("signer.sqlite3");
        let status_path = app_parent.join("application.status");
        let (base_core, genesis_qc) = strict_base_core_v0();
        let bundle = NativeValidationRecoveryTestConfigBundleV0::new(
            &status_path,
            TEST_CHAIN,
            [0x71; 32],
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
        )
        .expect("construct absent application config");
        let application = bundle.application_config_v0();
        let parent = AuthenticatedGenesisApplicationParentV0::new(
            base_core.genesis_block_id(),
            GENESIS_TIMESTAMP_MS,
            0,
            StateRoot::new([0x31; 32]),
            [0x41; 32],
            [0x51; 32],
        )
        .expect("construct shape-valid absent-application carrier");
        let core_config = CoreConfig::new_with_authenticated_genesis_application_parent_v0(
            base_core.local_validator(),
            base_core.validator_set().clone(),
            *base_core.consensus_parameters(),
            GENESIS_TIMESTAMP_MS,
            parent,
            base_core.max_blocks(),
            base_core.max_observed_messages(),
        )
        .expect("construct absent-application Core config");
        let prepared = Core::prepare_authenticated_genesis_application_bootstrap_v0(
            core_config.clone(),
            genesis_qc,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits_v0(),
            &RootSignaturesV0,
        )
        .expect("prepare absent-application commissioning facts");
        let watermark = SpyWatermarkV0::default();
        initialize_signer_v0(&signer_path, &core_config, &watermark);
        let baseline_compare = watermark.compare_calls();
        watermark.replace(successor_watermark_v0(watermark.current()));
        let config = PocoNodeAuthenticatedGenesisCommissioningConfigV0::new(
            &safety_path,
            &signer_path,
            core_config,
            record_limits_v0(),
            MAXIMUM_SAFETY_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
            application,
        )
        .expect("construct signer-first node config");
        let error = PocoNodeAuthenticatedGenesisCommissioningHostV0::commission_or_open_exact_v0(
            config,
            prepared,
            watermark.clone(),
        )
        .expect_err("external-ahead signer must fail before later owners");
        assert!(matches!(
            error,
            PocoNodeAuthenticatedGenesisCommissioningErrorV0::SignerJournal(_)
        ));
        assert_eq!(watermark.compare_calls(), baseline_compare);
        assert_parent_empty_v0(&safety_path);
        assert_parent_empty_v0(&status_path);
    }
}
