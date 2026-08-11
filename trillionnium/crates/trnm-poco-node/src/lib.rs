#![forbid(unsafe_code)]
//! Fail-closed lifecycle scaffold for the future PoCO-BFT node.
//!
//! This package is deliberately separate from the frozen legacy `trnm-node`
//! harness. It is the first process-ownership boundary for one [`Core`] and
//! one [`SqliteSafetyStateStoreV0`] plus one independent signer journal.
//! The recovery-only owner added in G1c also owns one existing native
//! application validation journal. Construction or recovery keeps every
//! selected store under one process-local owner, and none can be detached from
//! the host through this API.
//!
//! This is not a general effect driver or a production node. Its recovery-only
//! owner calls `Core::step` solely for one reconciled deterministic-invalid
//! callback and its exact durable `StorageAck`; it does not sign, broadcast,
//! execute fresh application payloads, finalize blocks, run a pacemaker, serve
//! a network, or install state sync. The binary always exits non-zero. These
//! omissions keep the scaffold inert until the frozen production contracts
//! have real adapters; they must not be bypassed with the private CometBFT
//! application fixture.
//!
//! The safety store, signer journal, and optional application recovery store
//! must live in non-overlapping, already-existing canonical parent
//! directories. Equal, ancestor, and descendant parent namespaces are all
//! refused. This limits one directory replacement from replacing several
//! local histories, but does not create an atomic transaction across any store
//! or the external signer watermark. New initialization writes the safety
//! store first and the signer journal second. A crash between those operations
//! can therefore leave a safety-only namespace; any partial namespace fails
//! closed on recovery and requires explicit operator quarantine or recovery.
//! This scaffold deliberately does not reconcile the Core lock state, safety
//! revision, and signer watermark across those stores.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
#[cfg(feature = "recovery-process-test-support")]
use trnm_consensus_app::NativeValidationRecoveredInvalidReasonV0;
use trnm_consensus_app::{
    NativeValidationRecoveredAckedFactsV0, NativeValidationRecoveredInvalidCallbackFactsV0,
    NativeValidationRecoveredInvalidStateV0, NativeValidationRecoveryOpenFailureV0,
    NativeValidationRecoveryReconcileFailureV0, NativeValidationRecoveryStoreConfigV0,
    NativeValidationRecoveryStoreV0, NativeValidationRecoveryTransitionFailureV0,
};
use trnm_consensus_core::{
    Core, CoreConfig, DurablePayloadValidationResultV1, Effect, Input, PayloadValidationResult,
    PayloadValidationRouteV0, SafetyState, SafetyStatePersistenceV0, SafetyStateRecordLimitsV0,
    ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    ConfirmedNativeDeterministicInvalidHeadV0, NativeDeterministicInvalidTransitionV0,
    RecoveredSafetyStateV0, SafetyStateStoreProfileV0, SafetyStoreErrorV0,
    SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, JournalCapacityV0, SignerJournalErrorV0, SignerJournalProfileV0,
    SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{GenesisQcV0, RolloutPhase};

/// This package must not be interpreted as a deployable consensus candidate.
pub const PRODUCTION_CANDIDATE_V0: bool = false;

/// This package deliberately has no effect-driving/running state.
pub const HOST_IMPLEMENTATION_COMPLETE_V0: bool = false;

/// SHA-256 of `trnm.poco-node.strict-ed25519-verifier-profile.v0`.
///
/// The safety journal binds this exact verification implementation profile;
/// callers cannot substitute a caller-selected profile reference.
pub const STRICT_ED25519_VERIFIER_PROFILE_REF_V0: [u8; 32] = [
    0x21, 0xc6, 0x12, 0x2a, 0xbb, 0xc2, 0xae, 0x7c, 0x72, 0xf0, 0x22, 0x72, 0xc1, 0xdc, 0x24, 0x1b,
    0xb0, 0x3a, 0x52, 0x67, 0x7d, 0xc4, 0x1f, 0xd2, 0x53, 0x63, 0x3f, 0x17, 0x89, 0xcc, 0x41, 0x1a,
];

/// SHA-256 of `trnm.poco-node.signer-journal-profile.v0`.
///
/// This binds the inert host's frozen strict-Ed25519 signer-journal profile;
/// it is not a key identifier or a claim that a producer is wired.
pub const SIGNER_JOURNAL_PROFILE_REF_V0: [u8; 32] = [
    0xe4, 0xff, 0xb8, 0x35, 0x52, 0x4b, 0xfd, 0x25, 0x4a, 0xb3, 0x11, 0x0c, 0xa6, 0xad, 0xcf, 0x13,
    0xc4, 0x85, 0x57, 0x4c, 0xdf, 0xdf, 0xc0, 0x0d, 0x1e, 0x84, 0x42, 0x2d, 0x42, 0xb9, 0x36, 0x69,
];

const SIGNER_WATERMARK_SCOPE_DOMAIN_V0: &[u8] = b"trnm.poco-node.signer-watermark-scope.v0";

/// A frozen production contract which this scaffold intentionally does not
/// implement or claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwiredProductionContractV0 {
    CanonicalSignIntentSignerAdapter,
    IndependentSignerWatermark,
    CompleteHotstuffSafetyRules,
    SafetyStateSignerLockReconciliation,
    ApplicationStoreAdapter,
    ApplicationValidationRecoveryBeyondDeterministicInvalid,
    BlockIdSpeculativeOverlay,
    OrderedFinalizationQueue,
    EffectDriver,
    AuthenticatedPacemakerTransport,
    StateSync,
}

impl UnwiredProductionContractV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalSignIntentSignerAdapter => "canonical_sign_intent_signer_adapter_v0",
            Self::IndependentSignerWatermark => "independent_signer_watermark",
            Self::CompleteHotstuffSafetyRules => "complete_hotstuff_safety_rules",
            Self::SafetyStateSignerLockReconciliation => "safety_state_signer_lock_reconciliation",
            Self::ApplicationStoreAdapter => "application_store_adapter",
            Self::ApplicationValidationRecoveryBeyondDeterministicInvalid => {
                "application_validation_recovery_beyond_deterministic_invalid_v0"
            }
            Self::BlockIdSpeculativeOverlay => "block_id_speculative_overlay",
            Self::OrderedFinalizationQueue => "ordered_finalization_queue",
            Self::EffectDriver => "core_effect_driver",
            Self::AuthenticatedPacemakerTransport => "authenticated_pacemaker_transport",
            Self::StateSync => "state_sync",
        }
    }
}

/// Exact activation blockers at this host boundary.
pub const UNWIRED_PRODUCTION_CONTRACTS_V0: &[UnwiredProductionContractV0] = &[
    UnwiredProductionContractV0::CanonicalSignIntentSignerAdapter,
    UnwiredProductionContractV0::IndependentSignerWatermark,
    UnwiredProductionContractV0::CompleteHotstuffSafetyRules,
    UnwiredProductionContractV0::SafetyStateSignerLockReconciliation,
    UnwiredProductionContractV0::ApplicationStoreAdapter,
    UnwiredProductionContractV0::ApplicationValidationRecoveryBeyondDeterministicInvalid,
    UnwiredProductionContractV0::BlockIdSpeculativeOverlay,
    UnwiredProductionContractV0::OrderedFinalizationQueue,
    UnwiredProductionContractV0::EffectDriver,
    UnwiredProductionContractV0::AuthenticatedPacemakerTransport,
    UnwiredProductionContractV0::StateSync,
];

/// Typed, local-only startup configuration for an inert host.
///
/// Consensus parameters remain inside [`CoreConfig`]. Record and database
/// capacities are node-local resource bounds and never become block-validity
/// inputs.
#[derive(Debug, Clone)]
pub struct PocoNodeStartConfigV0 {
    safety_store_path: PathBuf,
    safety_store_profile: SafetyStateStoreProfileV0,
    signer_journal_path: PathBuf,
    signer_journal_profile: SignerJournalProfileV0,
}

impl PocoNodeStartConfigV0 {
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
    ) -> Result<Self, PocoNodeHostErrorV0> {
        let safety_store_path = safety_store_path.as_ref();
        if !safety_store_path.is_absolute() {
            return Err(PocoNodeHostErrorV0::RelativeSafetyStorePath);
        }
        if safety_store_path.file_name().is_none() {
            return Err(PocoNodeHostErrorV0::InvalidSafetyStorePath);
        }
        let signer_journal_path = signer_journal_path.as_ref();
        if !signer_journal_path.is_absolute() {
            return Err(PocoNodeHostErrorV0::RelativeSignerJournalPath);
        }
        if signer_journal_path.file_name().is_none() {
            return Err(PocoNodeHostErrorV0::InvalidSignerJournalPath);
        }
        if core_config.consensus_parameters().production_activation() {
            return Err(PocoNodeHostErrorV0::ProductionActivationRequested);
        }
        let rollout_phase = core_config.consensus_parameters().rollout_phase();
        if rollout_phase != RolloutPhase::Shadow {
            return Err(PocoNodeHostErrorV0::NonShadowRolloutRequested { rollout_phase });
        }
        let epoch = core_config.validator_set().epoch().get();
        if epoch != 0 {
            return Err(PocoNodeHostErrorV0::UnsupportedEpoch { epoch });
        }
        let safety_store_file_name = safety_store_path
            .file_name()
            .expect("validated safety-store file name");
        let safety_store_parent = fs::canonicalize(
            safety_store_path
                .parent()
                .ok_or(PocoNodeHostErrorV0::InvalidSafetyStorePath)?,
        )
        .map_err(PocoNodeHostErrorV0::safety_store_parent)?;
        if !safety_store_parent.is_dir() {
            return Err(PocoNodeHostErrorV0::InvalidSafetyStoreParent);
        }
        let signer_journal_file_name = signer_journal_path
            .file_name()
            .expect("validated signer-journal file name");
        let signer_journal_parent = fs::canonicalize(
            signer_journal_path
                .parent()
                .ok_or(PocoNodeHostErrorV0::InvalidSignerJournalPath)?,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal_parent)?;
        if !signer_journal_parent.is_dir() {
            return Err(PocoNodeHostErrorV0::InvalidSignerJournalParent);
        }
        if canonical_parent_namespaces_overlap_v0(&safety_store_parent, &signer_journal_parent) {
            return Err(PocoNodeHostErrorV0::SharedStoreParentNamespace);
        }
        let safety_store_path = safety_store_parent.join(safety_store_file_name);
        let signer_journal_path = signer_journal_parent.join(signer_journal_file_name);
        let signer_journal_profile = SignerJournalProfileV0::new(
            core_config.validator_set().clone(),
            core_config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&core_config),
            maximum_signer_intents,
            maximum_signer_intent_bytes,
            maximum_signer_database_bytes,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let safety_store_profile = SafetyStateStoreProfileV0::new(
            core_config,
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            record_limits,
            maximum_safety_database_bytes,
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        Ok(Self {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        })
    }

    pub fn safety_store_path(&self) -> &Path {
        self.safety_store_path.as_path()
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.safety_store_profile.core_config()
    }

    pub const fn record_limits(&self) -> SafetyStateRecordLimitsV0 {
        self.safety_store_profile.record_limits()
    }

    pub const fn maximum_database_bytes(&self) -> usize {
        self.safety_store_profile.maximum_database_bytes()
    }

    pub fn signer_journal_path(&self) -> &Path {
        self.signer_journal_path.as_path()
    }

    pub const fn maximum_signer_intents(&self) -> u64 {
        self.signer_journal_profile.maximum_intents()
    }

    pub const fn maximum_signer_intent_bytes(&self) -> usize {
        self.signer_journal_profile.maximum_intent_bytes()
    }

    pub const fn maximum_signer_database_bytes(&self) -> usize {
        self.signer_journal_profile.maximum_database_bytes()
    }

    /// Exact SafetyStore profile used only by the required-feature process
    /// recovery helper while it constructs an initial authentic O+P case.
    #[cfg(feature = "recovery-process-test-support")]
    pub fn recovery_process_safety_store_profile_v0(&self) -> SafetyStateStoreProfileV0 {
        self.safety_store_profile.clone()
    }

    /// Exact signer-journal profile used only by the required-feature process
    /// recovery helper while it constructs an initial authentic O+P case.
    #[cfg(feature = "recovery-process-test-support")]
    pub fn recovery_process_signer_journal_profile_v0(&self) -> SignerJournalProfileV0 {
        self.signer_journal_profile.clone()
    }
}

/// Existing-only startup configuration for the bounded G1c validation
/// recovery path.
///
/// The application status path is canonicalized only through its already-
/// existing parent. The application facade separately derives and verifies
/// its exact SQLite path before opening it. All three store parents must be
/// non-overlapping canonical namespaces: equal, ancestor, and descendant
/// parents are refused.
#[derive(Debug)]
pub struct PocoNodeValidationRecoveryConfigV0 {
    node: PocoNodeStartConfigV0,
    application_status_path: PathBuf,
    signer_policy_hash: [u8; 32],
}

impl PocoNodeValidationRecoveryConfigV0 {
    pub fn new(
        node: PocoNodeStartConfigV0,
        application_status_path: impl AsRef<Path>,
        signer_policy_hash: [u8; 32],
    ) -> Result<Self, PocoNodeHostErrorV0> {
        let application_status_path = application_status_path.as_ref();
        if !application_status_path.is_absolute() {
            return Err(PocoNodeHostErrorV0::RelativeApplicationStatusPath);
        }
        let application_file_name = application_status_path
            .file_name()
            .ok_or(PocoNodeHostErrorV0::InvalidApplicationStatusPath)?;
        let application_parent = fs::canonicalize(
            application_status_path
                .parent()
                .ok_or(PocoNodeHostErrorV0::InvalidApplicationStatusPath)?,
        )
        .map_err(PocoNodeHostErrorV0::application_store_parent)?;
        if !application_parent.is_dir() {
            return Err(PocoNodeHostErrorV0::InvalidApplicationStoreParent);
        }
        let safety_parent = node
            .safety_store_path
            .parent()
            .ok_or(PocoNodeHostErrorV0::InvalidSafetyStorePath)?;
        let signer_parent = node
            .signer_journal_path
            .parent()
            .ok_or(PocoNodeHostErrorV0::InvalidSignerJournalPath)?;
        if canonical_parent_namespaces_overlap_v0(&application_parent, safety_parent)
            || canonical_parent_namespaces_overlap_v0(&application_parent, signer_parent)
        {
            return Err(PocoNodeHostErrorV0::SharedApplicationStoreParentNamespace);
        }
        Ok(Self {
            node,
            application_status_path: application_parent.join(application_file_name),
            signer_policy_hash,
        })
    }

    pub const fn node_config(&self) -> &PocoNodeStartConfigV0 {
        &self.node
    }

    pub fn application_status_path(&self) -> &Path {
        self.application_status_path.as_path()
    }

    pub const fn signer_policy_hash(&self) -> [u8; 32] {
        self.signer_policy_hash
    }
}

fn canonical_parent_namespaces_overlap_v0(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn derive_signer_watermark_scope_v0(core_config: &CoreConfig) -> [u8; 32] {
    let validator_set = core_config.validator_set();
    let author = core_config.local_validator();
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_WATERMARK_SCOPE_DOMAIN_V0);
    hasher.update((validator_set.chain_id().as_bytes().len() as u64).to_be_bytes());
    hasher.update(validator_set.chain_id().as_bytes());
    hasher.update(validator_set.protocol_version().get().to_be_bytes());
    hasher.update(validator_set.epoch().get().to_be_bytes());
    hasher.update(validator_set.id().as_bytes());
    hasher.update((author.as_bytes().len() as u64).to_be_bytes());
    hasher.update(author.as_bytes());
    hasher.finalize().into()
}

/// How the inert owner acquired its exact safety state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostBootstrapModeV0 {
    InitializedGenesis,
    RecoveredExisting,
}

/// The only lifecycle phase currently expressible by this package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLifecyclePhaseV0 {
    BootstrappedInert,
}

/// Application-journal state observed before the bounded recovery transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationRecoverySourceStateV0 {
    CallbackPending,
    Delivered,
    Acked,
}

/// Exact result of the recovery-aware inert bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationRecoveryBootstrapV0 {
    NotRequired,
    ObligationCompleted {
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        completion_revision: u64,
        source: ValidationRecoverySourceStateV0,
    },
    CompletionConfirmed {
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        completion_revision: u64,
        source: ValidationRecoverySourceStateV0,
    },
}

/// A durable boundary exposed only to the real-process recovery test helper.
///
/// These names describe the exact SafetyState/ApplicationStore pair after
/// both stores have completed their own durability and exact-readback checks.
/// The observer cannot alter either store and is absent from default builds
/// and the official `--no-default-features` development-library artifact.
#[cfg(feature = "recovery-process-test-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationRecoveryProcessCheckpointPhaseV0 {
    ObligationCallbackPending,
    ObligationDelivered,
    CompletionDelivered,
    CompletionAcked,
}

#[cfg(feature = "recovery-process-test-support")]
impl ValidationRecoveryProcessCheckpointPhaseV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObligationCallbackPending => "obligation_callback_pending",
            Self::ObligationDelivered => "obligation_delivered",
            Self::CompletionDelivered => "completion_delivered",
            Self::CompletionAcked => "completion_acked",
        }
    }
}

/// Exact facts supplied to the feature-only real-process checkpoint observer.
#[cfg(feature = "recovery-process-test-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationRecoveryProcessCheckpointV0 {
    phase: ValidationRecoveryProcessCheckpointPhaseV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    reason: NativeValidationRecoveredInvalidReasonV0,
    obligation_revision: u64,
    safety_revision: u64,
}

#[cfg(feature = "recovery-process-test-support")]
impl ValidationRecoveryProcessCheckpointV0 {
    pub const fn phase(self) -> ValidationRecoveryProcessCheckpointPhaseV0 {
        self.phase
    }

    pub const fn route(self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id(self) -> ValidationId {
        self.validation_id
    }

    pub const fn reason(self) -> NativeValidationRecoveredInvalidReasonV0 {
        self.reason
    }

    pub const fn obligation_revision(self) -> u64 {
        self.obligation_revision
    }

    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }
}

/// Non-cloneable owner of one Core, its safety store, and signer journal.
///
/// There is intentionally no mutable Core accessor, `step`, `run`, signer,
/// application adapter, or escape hatch returning the two owned parts.
pub struct PocoNodeHostV0<W> {
    core: Core,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer_journal: SqliteSignerJournalV0<W>,
    signer_journal_head: SignerWatermarkV0,
    bootstrap_mode: HostBootstrapModeV0,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeHostV0<W> {
    /// Creates the epoch-zero Core, initializes its journal at revision zero,
    /// and binds future persistence to this exact Core instance.
    ///
    /// The safety store is initialized before the signer journal. There is no
    /// atomic transaction across the two SQLite stores or the external
    /// watermark. An interrupted partial initialization is intentionally not
    /// repaired here: subsequent recovery fails closed and requires explicit
    /// operator quarantine or recovery.
    pub fn initialize_new(
        config: PocoNodeStartConfigV0,
        genesis_qc: GenesisQcV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(&config)?;
        let core_config = config.core_config().clone();
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = config;
        let verifier = StrictEd25519Verifier;
        let core =
            Core::new(core_config, genesis_qc, &verifier).map_err(PocoNodeHostErrorV0::core)?;
        let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
            safety_store_path,
            safety_store_profile,
            verifier,
            core.safety_state(),
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        let mut signer_journal = SqliteSignerJournalV0::initialize_new(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let signer_journal_head = signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signer_journal_head,
            bootstrap_mode: HostBootstrapModeV0::InitializedGenesis,
        })
    }

    /// Opens and authenticates an ordinary exact journal head, recovers Core,
    /// and binds the journal to that recovered instance.
    ///
    /// Obligation-bearing or native-invalid-context heads fail before Core
    /// construction. Call [`PocoNodeValidationRecoveryHostV0::open_existing`]
    /// for the bounded G1c recovery join. This legacy inert entry point cannot
    /// inspect an independent application journal and must never be used as a
    /// production recovery path.
    pub fn open_existing(
        config: PocoNodeStartConfigV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(&config)?;
        let core_config = config.core_config().clone();
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = config;
        let verifier = StrictEd25519Verifier;
        let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
            safety_store_path,
            safety_store_profile,
            verifier,
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        let head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        if !matches!(
            head.transition_context(),
            SafetyTransitionContextV0::Ordinary
        ) || head_has_current_invalid_completion_v0(head.state())
        {
            return Err(PocoNodeHostErrorV0::ValidationRecoveryAwareOpenRequired {
                revision: head.revision(),
            });
        }
        let obligation_count = head.state().payload_validation_obligations().len();
        if obligation_count != 0 {
            return Err(
                PocoNodeHostErrorV0::AuthenticatedObligationReplayUnavailable {
                    revision: head.revision(),
                    obligation_count,
                },
            );
        }
        let mut signer_journal = SqliteSignerJournalV0::open_existing(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let signer_journal_head = signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let core = Core::recover(core_config, head.state().clone(), &verifier)
            .map_err(PocoNodeHostErrorV0::core)?;
        if core.safety_state() != head.state() {
            return Err(PocoNodeHostErrorV0::RecoveredHeadMismatch);
        }
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signer_journal_head,
            bootstrap_mode: HostBootstrapModeV0::RecoveredExisting,
        })
    }

    pub const fn bootstrap_mode(&self) -> HostBootstrapModeV0 {
        self.bootstrap_mode
    }

    pub const fn lifecycle_phase(&self) -> HostLifecyclePhaseV0 {
        HostLifecyclePhaseV0::BootstrappedInert
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.core.config()
    }

    /// Exposes inert state facts, not the live Core or a persistence binding.
    pub const fn safety_state(&self) -> &SafetyState {
        self.core.safety_state()
    }

    pub fn safety_store_path(&self) -> &Path {
        self.safety_store.path()
    }

    pub fn signer_journal_path(&self) -> &Path {
        self.signer_journal.path()
    }

    /// Captured exact external/local signer head at successful bootstrap.
    /// The inert host has no API capable of advancing it.
    pub const fn signer_journal_head(&self) -> SignerWatermarkV0 {
        self.signer_journal_head
    }

    pub fn signer_journal_capacity(&self) -> Result<JournalCapacityV0, PocoNodeHostErrorV0> {
        self.signer_journal
            .capacity()
            .map_err(PocoNodeHostErrorV0::signer_journal)
    }

    pub fn safety_head(&self) -> Result<RecoveredSafetyStateV0, PocoNodeHostErrorV0> {
        self.safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)
    }

    /// No running/effect-driving state is constructible in this slice.
    pub fn production_activation_check(&self) -> Result<(), ProductionActivationBlockedV0> {
        Err(ProductionActivationBlockedV0::new())
    }
}

/// Non-cloneable, recovery-aware owner of the Core and all three local
/// journals used by the bounded deterministic-invalid G1c slice.
///
/// This type has no constructor for fresh application state and no effect-
/// driving API. It can only authenticate an existing schema-v8 application
/// journal and either complete one exact durable invalid obligation, confirm
/// one exact already-persisted completion, or prove that no active recovery
/// work exists.
pub struct PocoNodeValidationRecoveryHostV0<W> {
    core: Core,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer_journal: SqliteSignerJournalV0<W>,
    signer_journal_head: SignerWatermarkV0,
    _application_recovery: NativeValidationRecoveryStoreV0,
    application_status_path: PathBuf,
    recovery: ValidationRecoveryBootstrapV0,
    pending_inert_effects: Vec<Effect>,
}

type ValidationRecoveryOpenPartsV0 = (Core, ValidationRecoveryBootstrapV0, Vec<Effect>, bool);

impl<W: ExternalMonotonicWatermarkV0> PocoNodeValidationRecoveryHostV0<W> {
    /// Opens all three existing stores and closes the bounded O/P/D/C/K crash
    /// matrix for one deterministic-invalid validation job.
    ///
    /// The order is intentionally a recoverable join, not a cross-WAL atomic
    /// transaction. For an obligation head the exact callback is first
    /// accepted by Core, the application row becomes Delivered, the opaque
    /// Core persistence request is written with its complete application
    /// context, that exact SafetyStore head is read back, the application row
    /// becomes Acked, and only then is `StorageAck` returned to Core. For an
    /// already-complete head no callback or synthetic `StorageAck` is issued.
    pub fn open_existing(
        config: PocoNodeValidationRecoveryConfigV0,
        external_watermark: W,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        #[cfg(feature = "recovery-process-test-support")]
        {
            Self::open_existing_inner_v0(config, external_watermark, None)
        }
        #[cfg(not(feature = "recovery-process-test-support"))]
        {
            Self::open_existing_inner_v0(config, external_watermark)
        }
    }

    /// Opens through the official host while observing authenticated durable
    /// boundaries for the feature-gated real-process SIGKILL matrix.
    ///
    /// The observer is invoked only after the named store pair has completed
    /// its normal durability and exact-readback checks. Returning from the
    /// observer allows the official transition to continue unchanged. This
    /// API does not exist in default builds or the official
    /// `--no-default-features` development-library artifact.
    #[cfg(feature = "recovery-process-test-support")]
    pub fn open_existing_with_process_checkpoint_observer_v0<F>(
        config: PocoNodeValidationRecoveryConfigV0,
        external_watermark: W,
        mut observer: F,
    ) -> Result<Self, PocoNodeHostErrorV0>
    where
        F: FnMut(ValidationRecoveryProcessCheckpointV0),
    {
        Self::open_existing_inner_v0(config, external_watermark, Some(&mut observer))
    }

    fn open_existing_inner_v0(
        config: PocoNodeValidationRecoveryConfigV0,
        external_watermark: W,
        #[cfg(feature = "recovery-process-test-support")] checkpoint_observer: Option<
            &mut dyn FnMut(ValidationRecoveryProcessCheckpointV0),
        >,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(config.node_config())?;
        let core_config = config.node.core_config().clone();
        let chain_id = core_config.validator_set().chain_id();
        let PocoNodeValidationRecoveryConfigV0 {
            node,
            application_status_path,
            signer_policy_hash,
        } = config;
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = node;
        let verifier = StrictEd25519Verifier;
        let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
            safety_store_path,
            safety_store_profile,
            verifier,
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        let head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        let mut signer_journal = SqliteSignerJournalV0::open_existing(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let signer_journal_head = signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let mut application_recovery = NativeValidationRecoveryStoreV0::open_existing_v8(
            NativeValidationRecoveryStoreConfigV0::new(
                application_status_path.clone(),
                chain_id,
                signer_policy_hash,
                safety_store.journal_id_v0(),
                safety_store.verifier_profile_ref_v0(),
            ),
        )
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryOpen)?;
        let active_application_jobs = application_recovery.active_recovery_job_count_v0();
        let obligation_count = head.state().payload_validation_obligations().len();

        let (core, recovery, pending_inert_effects, safety_already_bound) = match obligation_count {
            0 => recover_without_obligation_v0(
                core_config,
                head,
                &safety_store,
                &mut application_recovery,
                active_application_jobs,
                &verifier,
            )?,
            1 => recover_one_invalid_obligation_v0(
                core_config,
                head,
                &mut safety_store,
                &mut application_recovery,
                active_application_jobs,
                &verifier,
                #[cfg(feature = "recovery-process-test-support")]
                checkpoint_observer,
            )?,
            count => {
                return Err(PocoNodeHostErrorV0::UnsupportedValidationObligationCount { count });
            }
        };
        if !safety_already_bound {
            safety_store
                .bind_core_v0(core.safety_state_persistence_binding_v0())
                .map_err(PocoNodeHostErrorV0::safety_store)?;
        }
        let final_head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        if final_head.state() != core.safety_state() {
            return Err(PocoNodeHostErrorV0::RecoveredHeadMismatch);
        }
        application_recovery
            .final_exact_audit_v0()
            .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signer_journal_head,
            _application_recovery: application_recovery,
            application_status_path,
            recovery,
            pending_inert_effects,
        })
    }

    pub const fn lifecycle_phase(&self) -> HostLifecyclePhaseV0 {
        HostLifecyclePhaseV0::BootstrappedInert
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.core.config()
    }

    pub const fn safety_state(&self) -> &SafetyState {
        self.core.safety_state()
    }

    pub const fn recovery(&self) -> ValidationRecoveryBootstrapV0 {
        self.recovery
    }

    pub fn safety_store_path(&self) -> &Path {
        self.safety_store.path()
    }

    pub fn signer_journal_path(&self) -> &Path {
        self.signer_journal.path()
    }

    pub fn application_status_path(&self) -> &Path {
        self.application_status_path.as_path()
    }

    pub const fn signer_journal_head(&self) -> SignerWatermarkV0 {
        self.signer_journal_head
    }

    pub fn signer_journal_capacity(&self) -> Result<JournalCapacityV0, PocoNodeHostErrorV0> {
        self.signer_journal
            .capacity()
            .map_err(PocoNodeHostErrorV0::signer_journal)
    }

    /// Effects made durable by the final same-process `StorageAck` but kept
    /// inert by this scaffold. V0 permits only a durable safety-halt notice;
    /// no effect is signed, broadcast, or delivered by this package.
    pub fn pending_inert_effect_count(&self) -> usize {
        self.pending_inert_effects.len()
    }

    pub fn safety_head(&self) -> Result<RecoveredSafetyStateV0, PocoNodeHostErrorV0> {
        self.safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)
    }

    pub fn production_activation_check(&self) -> Result<(), ProductionActivationBlockedV0> {
        Err(ProductionActivationBlockedV0::new())
    }
}

fn recover_without_obligation_v0(
    core_config: CoreConfig,
    head: RecoveredSafetyStateV0,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: &mut NativeValidationRecoveryStoreV0,
    active_application_jobs: usize,
    verifier: &StrictEd25519Verifier,
) -> Result<ValidationRecoveryOpenPartsV0, PocoNodeHostErrorV0> {
    match head.transition_context() {
        SafetyTransitionContextV0::Ordinary => {
            if head_has_current_invalid_completion_v0(head.state()) {
                return Err(PocoNodeHostErrorV0::OrdinaryContextForInvalidCompletion {
                    revision: head.revision(),
                });
            }
            if active_application_jobs != 0 {
                return Err(
                    PocoNodeHostErrorV0::UnexpectedActiveApplicationRecoveryJobs {
                        expected: 0,
                        actual: active_application_jobs,
                    },
                );
            }
            let core = Core::recover(core_config, head.state().clone(), verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            Ok((
                core,
                ValidationRecoveryBootstrapV0::NotRequired,
                Vec::new(),
                false,
            ))
        }
        SafetyTransitionContextV0::NativeDeterministicInvalid(_) => {
            if active_application_jobs > 1 {
                return Err(
                    PocoNodeHostErrorV0::UnexpectedActiveApplicationRecoveryJobs {
                        expected: 1,
                        actual: active_application_jobs,
                    },
                );
            }
            let confirmed = safety_store
                .confirmed_native_deterministic_invalid_head_v0()
                .map_err(PocoNodeHostErrorV0::safety_store)?;
            let source = application
                .recover_confirmed_invalid_completion_v0(&confirmed)
                .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
            let expected_active = match source {
                NativeValidationRecoveredInvalidStateV0::Delivered => 1,
                NativeValidationRecoveredInvalidStateV0::Acked => 0,
                NativeValidationRecoveredInvalidStateV0::CallbackPending => {
                    return Err(PocoNodeHostErrorV0::UnexpectedCompletionApplicationState);
                }
            };
            if active_application_jobs != expected_active {
                return Err(
                    PocoNodeHostErrorV0::UnexpectedActiveApplicationRecoveryJobs {
                        expected: expected_active,
                        actual: active_application_jobs,
                    },
                );
            }
            let acked = application
                .acknowledge_recovered_invalid_completion_v0(&confirmed)
                .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
            validate_acked_facts_against_confirmation_v0(&acked, &confirmed)?;
            let core = Core::recover(core_config, confirmed.state().clone(), verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            Ok((
                core,
                ValidationRecoveryBootstrapV0::CompletionConfirmed {
                    route: confirmed.transition().route(),
                    validation_id: confirmed.transition().validation_id(),
                    completion_revision: confirmed.transition().completion_revision(),
                    source: source.into(),
                },
                Vec::new(),
                false,
            ))
        }
    }
}

fn recover_one_invalid_obligation_v0(
    core_config: CoreConfig,
    head: RecoveredSafetyStateV0,
    safety_store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: &mut NativeValidationRecoveryStoreV0,
    active_application_jobs: usize,
    verifier: &StrictEd25519Verifier,
    #[cfg(feature = "recovery-process-test-support")] mut checkpoint_observer: Option<
        &mut dyn FnMut(ValidationRecoveryProcessCheckpointV0),
    >,
) -> Result<ValidationRecoveryOpenPartsV0, PocoNodeHostErrorV0> {
    if !matches!(
        head.transition_context(),
        SafetyTransitionContextV0::Ordinary
    ) {
        return Err(PocoNodeHostErrorV0::UnexpectedObligationTransitionContext {
            revision: head.revision(),
        });
    }
    if active_application_jobs != 1 {
        return Err(
            PocoNodeHostErrorV0::UnexpectedActiveApplicationRecoveryJobs {
                expected: 1,
                actual: active_application_jobs,
            },
        );
    }
    #[cfg(feature = "recovery-process-test-support")]
    let obligation_revision = head.revision();
    let session = Core::begin_payload_validation_obligation_recovery_v0(
        core_config,
        head.state().clone(),
        verifier,
    )
    .map_err(PocoNodeHostErrorV0::core)?;
    let route = session.challenge().route();
    let validation_id = session.challenge().id();
    let mut core = match session.reconcile_and_activate_v0(application) {
        Ok(core) => core,
        Err(error) => {
            if let Some(failure) = application.last_reconcile_failure_v0() {
                return Err(PocoNodeHostErrorV0::ApplicationRecoveryReconcile(failure));
            }
            return Err(PocoNodeHostErrorV0::core(error));
        }
    };
    let source = application
        .recovered_obligation_state_v0()
        .ok_or(PocoNodeHostErrorV0::MissingReconciledApplicationOwner)?;
    if !matches!(
        source,
        NativeValidationRecoveredInvalidStateV0::CallbackPending
            | NativeValidationRecoveredInvalidStateV0::Delivered
    ) {
        return Err(PocoNodeHostErrorV0::UnexpectedObligationApplicationState);
    }
    let reconciled_callback = application
        .recovered_obligation_callback_facts_v0()
        .ok_or(PocoNodeHostErrorV0::MissingReconciledApplicationOwner)?;
    validate_callback_identity_v0(&reconciled_callback, route, validation_id)?;
    #[cfg(feature = "recovery-process-test-support")]
    if source == NativeValidationRecoveredInvalidStateV0::CallbackPending {
        emit_recovery_process_checkpoint_v0(
            &mut checkpoint_observer,
            ValidationRecoveryProcessCheckpointPhaseV0::ObligationCallbackPending,
            reconciled_callback,
            obligation_revision,
            obligation_revision,
        );
    }
    let input = match route {
        PayloadValidationRouteV0::Proposal => Input::PayloadValidated {
            id: validation_id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
        PayloadValidationRouteV0::Synced => Input::SyncedPayloadValidated {
            id: validation_id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
    };
    let effects = core
        .step(input, verifier)
        .map_err(PocoNodeHostErrorV0::core)?;
    let request = take_exact_recovery_persistence_v0(effects)?;
    let callback_facts = application
        .record_recovered_core_acceptance_v0(&request)
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    validate_callback_identity_v0(&callback_facts, route, validation_id)?;
    application
        .final_exact_audit_v0()
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    #[cfg(feature = "recovery-process-test-support")]
    emit_recovery_process_checkpoint_v0(
        &mut checkpoint_observer,
        ValidationRecoveryProcessCheckpointPhaseV0::ObligationDelivered,
        callback_facts,
        obligation_revision,
        obligation_revision,
    );
    let context =
        native_invalid_transition_context_v0(&callback_facts, request.state().revision())?;
    safety_store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .map_err(PocoNodeHostErrorV0::safety_store)?;
    safety_store
        .persist_exact_v0(&request, &context)
        .map_err(PocoNodeHostErrorV0::safety_store)?;
    let confirmed = safety_store
        .confirmed_native_deterministic_invalid_head_exact_v0(request.state(), &context)
        .map_err(PocoNodeHostErrorV0::safety_store)?;
    application
        .final_exact_audit_v0()
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    #[cfg(feature = "recovery-process-test-support")]
    emit_recovery_process_checkpoint_v0(
        &mut checkpoint_observer,
        ValidationRecoveryProcessCheckpointPhaseV0::CompletionDelivered,
        callback_facts,
        obligation_revision,
        confirmed.revision(),
    );
    let completion_state = application
        .recover_confirmed_invalid_completion_v0(&confirmed)
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    if completion_state != NativeValidationRecoveredInvalidStateV0::Delivered {
        return Err(PocoNodeHostErrorV0::UnexpectedCompletionApplicationState);
    }
    let acked = application
        .acknowledge_recovered_invalid_completion_v0(&confirmed)
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    validate_acked_facts_against_confirmation_v0(&acked, &confirmed)?;
    application
        .final_exact_audit_v0()
        .map_err(PocoNodeHostErrorV0::ApplicationRecoveryTransition)?;
    #[cfg(feature = "recovery-process-test-support")]
    emit_recovery_process_checkpoint_v0(
        &mut checkpoint_observer,
        ValidationRecoveryProcessCheckpointPhaseV0::CompletionAcked,
        callback_facts,
        obligation_revision,
        confirmed.revision(),
    );
    let barrier = request.barrier();
    let pending_inert_effects = core
        .step(Input::StorageAck { barrier }, verifier)
        .map_err(PocoNodeHostErrorV0::core)?;
    validate_inert_post_ack_effects_v0(&pending_inert_effects)?;
    if core.safety_state() != confirmed.state() {
        return Err(PocoNodeHostErrorV0::RecoveredHeadMismatch);
    }
    Ok((
        core,
        ValidationRecoveryBootstrapV0::ObligationCompleted {
            route,
            validation_id,
            completion_revision: confirmed.transition().completion_revision(),
            source: source.into(),
        },
        pending_inert_effects,
        true,
    ))
}

#[cfg(feature = "recovery-process-test-support")]
fn emit_recovery_process_checkpoint_v0(
    observer: &mut Option<&mut dyn FnMut(ValidationRecoveryProcessCheckpointV0)>,
    phase: ValidationRecoveryProcessCheckpointPhaseV0,
    callback: NativeValidationRecoveredInvalidCallbackFactsV0,
    obligation_revision: u64,
    safety_revision: u64,
) {
    if let Some(observer) = observer.as_deref_mut() {
        observer(ValidationRecoveryProcessCheckpointV0 {
            phase,
            route: callback.route(),
            validation_id: callback.validation_id(),
            reason: callback.reason(),
            obligation_revision,
            safety_revision,
        });
    }
}

impl From<NativeValidationRecoveredInvalidStateV0> for ValidationRecoverySourceStateV0 {
    fn from(state: NativeValidationRecoveredInvalidStateV0) -> Self {
        match state {
            NativeValidationRecoveredInvalidStateV0::CallbackPending => Self::CallbackPending,
            NativeValidationRecoveredInvalidStateV0::Delivered => Self::Delivered,
            NativeValidationRecoveredInvalidStateV0::Acked => Self::Acked,
        }
    }
}

fn head_has_current_invalid_completion_v0(state: &SafetyState) -> bool {
    state
        .payload_validation_completions()
        .iter()
        .any(|completion| {
            completion.first_recorded_revision() == state.revision()
                && completion.result() == DurablePayloadValidationResultV1::DeterministicallyInvalid
        })
}

fn take_exact_recovery_persistence_v0(
    effects: Vec<Effect>,
) -> Result<SafetyStatePersistenceV0, PocoNodeHostErrorV0> {
    if effects.len() != 1 {
        return Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffectSet {
            expected: 1,
            actual: effects.len(),
        });
    }
    match effects
        .into_iter()
        .next()
        .expect("exact effect count checked")
    {
        Effect::PersistSafetyState(request) => Ok(request),
        effect => Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffect {
            effect: effect_name_v0(&effect),
        }),
    }
}

fn effect_name_v0(effect: &Effect) -> &'static str {
    match effect {
        Effect::PersistSafetyState(_) => "persist_safety_state",
        Effect::ValidatePayload(_) => "validate_payload",
        Effect::ValidateSyncedPayload(_) => "validate_synced_payload",
        Effect::RequestSignature { .. } => "request_signature",
        Effect::Broadcast(_) => "broadcast",
        Effect::ArmViewTimer { .. } => "arm_view_timer",
        Effect::RequestSafetyReplay { .. } => "request_safety_replay",
        Effect::RequestTcHighQcSync { .. } => "request_tc_high_qc_sync",
        Effect::RequestStandaloneQcSync { .. } => "request_standalone_qc_sync",
        Effect::SafetyHalted(_) => "safety_halted",
        Effect::Finalize(_) => "finalize",
        Effect::Evidence(_) => "evidence",
    }
}

fn validate_inert_post_ack_effects_v0(effects: &[Effect]) -> Result<(), PocoNodeHostErrorV0> {
    if let Some(effect) = effects
        .iter()
        .find(|effect| !matches!(effect, Effect::SafetyHalted(_)))
    {
        return Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffect {
            effect: effect_name_v0(effect),
        });
    }
    Ok(())
}

fn validate_callback_identity_v0(
    facts: &NativeValidationRecoveredInvalidCallbackFactsV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
) -> Result<(), PocoNodeHostErrorV0> {
    if facts.route() != route || facts.validation_id() != validation_id {
        return Err(PocoNodeHostErrorV0::ApplicationCallbackIdentityMismatch);
    }
    Ok(())
}

fn native_invalid_transition_context_v0(
    facts: &NativeValidationRecoveredInvalidCallbackFactsV0,
    completion_revision: u64,
) -> Result<SafetyTransitionContextV0, PocoNodeHostErrorV0> {
    let transition = NativeDeterministicInvalidTransitionV0::new(
        facts.route(),
        facts.validation_id(),
        facts.request_fingerprint(),
        facts.immutable_checksum(),
        facts.host_config_ref(),
        facts.reason().code_v0(),
        facts.artifact_checksum(),
        facts.callback_payload_checksum(),
        facts.idempotency_key(),
        facts.delivery_attempt(),
        facts.row_checksum(),
        facts.outbox_checksum(),
        completion_revision,
    )
    .map_err(PocoNodeHostErrorV0::safety_store)?;
    Ok(SafetyTransitionContextV0::native_deterministic_invalid(
        transition,
    ))
}

fn validate_acked_facts_against_confirmation_v0(
    acked: &NativeValidationRecoveredAckedFactsV0,
    confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
) -> Result<(), PocoNodeHostErrorV0> {
    let transition = confirmed.transition();
    if acked.route() != transition.route()
        || acked.validation_id() != transition.validation_id()
        || acked.request_fingerprint() != transition.request_fingerprint()
        || acked.immutable_checksum() != transition.job_immutable_checksum()
        || acked.host_config_ref() != transition.application_host_config_ref()
        || acked.reason().code_v0() != transition.reason_code()
        || acked.artifact_checksum() != transition.artifact_checksum()
        || acked.callback_payload_checksum() != transition.callback_payload_checksum()
        || acked.accepted_core_revision() != transition.completion_revision()
        || acked.predecessor_idempotency_key() != transition.idempotency_key()
        || acked.predecessor_delivery_attempt() != transition.delivery_attempt()
        || acked.predecessor_delivered_row_checksum() != transition.delivered_job_row_checksum()
        || acked.predecessor_outbox_checksum() != transition.outbox_checksum()
    {
        return Err(PocoNodeHostErrorV0::ApplicationAcknowledgementMismatch);
    }
    Ok(())
}

fn reject_activation_request(config: &PocoNodeStartConfigV0) -> Result<(), PocoNodeHostErrorV0> {
    let parameters = config.core_config().consensus_parameters();
    if parameters.production_activation() {
        return Err(PocoNodeHostErrorV0::ProductionActivationRequested);
    }
    let rollout_phase = parameters.rollout_phase();
    if rollout_phase != RolloutPhase::Shadow {
        return Err(PocoNodeHostErrorV0::NonShadowRolloutRequested { rollout_phase });
    }
    Ok(())
}

/// The static production gate used by the inert binary and live owner alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionActivationBlockedV0 {
    _private: (),
}

impl ProductionActivationBlockedV0 {
    const fn new() -> Self {
        Self { _private: () }
    }

    pub const fn blockers(self) -> &'static [UnwiredProductionContractV0] {
        UNWIRED_PRODUCTION_CONTRACTS_V0
    }
}

impl fmt::Display for ProductionActivationBlockedV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("production activation is blocked; unwired contracts: ")?;
        for (index, contract) in UNWIRED_PRODUCTION_CONTRACTS_V0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            formatter.write_str(contract.as_str())?;
        }
        Ok(())
    }
}

impl Error for ProductionActivationBlockedV0 {}

pub const fn production_activation_gate_v0() -> Result<(), ProductionActivationBlockedV0> {
    Err(ProductionActivationBlockedV0::new())
}

/// Startup failures are fail-closed and never converted into consensus
/// invalidity.
#[derive(Debug)]
pub enum PocoNodeHostErrorV0 {
    RelativeSafetyStorePath,
    InvalidSafetyStorePath,
    SafetyStoreParentIo(Box<io::Error>),
    InvalidSafetyStoreParent,
    RelativeSignerJournalPath,
    InvalidSignerJournalPath,
    SignerJournalParentIo(Box<io::Error>),
    InvalidSignerJournalParent,
    SharedStoreParentNamespace,
    RelativeApplicationStatusPath,
    InvalidApplicationStatusPath,
    ApplicationStoreParentIo(Box<io::Error>),
    InvalidApplicationStoreParent,
    SharedApplicationStoreParentNamespace,
    ProductionActivationRequested,
    NonShadowRolloutRequested {
        rollout_phase: RolloutPhase,
    },
    UnsupportedEpoch {
        epoch: u64,
    },
    AuthenticatedObligationReplayUnavailable {
        revision: u64,
        obligation_count: usize,
    },
    ValidationRecoveryAwareOpenRequired {
        revision: u64,
    },
    UnsupportedValidationObligationCount {
        count: usize,
    },
    UnexpectedActiveApplicationRecoveryJobs {
        expected: usize,
        actual: usize,
    },
    OrdinaryContextForInvalidCompletion {
        revision: u64,
    },
    UnexpectedObligationTransitionContext {
        revision: u64,
    },
    MissingNativeInvalidTransitionContext {
        revision: u64,
    },
    MissingReconciledApplicationOwner,
    UnexpectedObligationApplicationState,
    UnexpectedCompletionApplicationState,
    ApplicationCallbackIdentityMismatch,
    ApplicationAcknowledgementMismatch,
    UnexpectedRecoveryEffectSet {
        expected: usize,
        actual: usize,
    },
    UnexpectedRecoveryEffect {
        effect: &'static str,
    },
    RecoveredHeadMismatch,
    RecoveredTransitionHeadMismatch,
    Core(Box<trnm_consensus_core::CoreError>),
    SafetyStore(Box<SafetyStoreErrorV0>),
    SignerJournal(Box<SignerJournalErrorV0>),
    ApplicationRecoveryOpen(NativeValidationRecoveryOpenFailureV0),
    ApplicationRecoveryReconcile(NativeValidationRecoveryReconcileFailureV0),
    ApplicationRecoveryTransition(NativeValidationRecoveryTransitionFailureV0),
}

impl PocoNodeHostErrorV0 {
    fn core(error: trnm_consensus_core::CoreError) -> Self {
        Self::Core(Box::new(error))
    }

    fn safety_store(error: SafetyStoreErrorV0) -> Self {
        Self::SafetyStore(Box::new(error))
    }

    fn signer_journal(error: SignerJournalErrorV0) -> Self {
        Self::SignerJournal(Box::new(error))
    }

    fn safety_store_parent(error: io::Error) -> Self {
        Self::SafetyStoreParentIo(Box::new(error))
    }

    fn signer_journal_parent(error: io::Error) -> Self {
        Self::SignerJournalParentIo(Box::new(error))
    }

    fn application_store_parent(error: io::Error) -> Self {
        Self::ApplicationStoreParentIo(Box::new(error))
    }
}

impl fmt::Display for PocoNodeHostErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeSafetyStorePath => {
                formatter.write_str("safety-store path must be absolute")
            }
            Self::InvalidSafetyStorePath => {
                formatter.write_str("safety-store path must name a database file")
            }
            Self::SafetyStoreParentIo(error) => {
                write!(formatter, "safety-store parent must already exist: {error}")
            }
            Self::InvalidSafetyStoreParent => {
                formatter.write_str("safety-store parent must be a directory")
            }
            Self::RelativeSignerJournalPath => {
                formatter.write_str("signer-journal path must be absolute")
            }
            Self::InvalidSignerJournalPath => {
                formatter.write_str("signer-journal path must name a database file")
            }
            Self::SignerJournalParentIo(error) => {
                write!(formatter, "signer-journal parent must already exist: {error}")
            }
            Self::InvalidSignerJournalParent => {
                formatter.write_str("signer-journal parent must be a directory")
            }
            Self::SharedStoreParentNamespace => {
                formatter.write_str(
                    "safety-store and signer-journal must use non-overlapping canonical parent directories",
                )
            }
            Self::RelativeApplicationStatusPath => {
                formatter.write_str("application status path must be absolute")
            }
            Self::InvalidApplicationStatusPath => {
                formatter.write_str("application status path must name a file")
            }
            Self::ApplicationStoreParentIo(error) => {
                write!(formatter, "application-store parent must already exist: {error}")
            }
            Self::InvalidApplicationStoreParent => {
                formatter.write_str("application-store parent must be a directory")
            }
            Self::SharedApplicationStoreParentNamespace => formatter.write_str(
                "application, safety, and signer stores must use non-overlapping canonical parent directories",
            ),
            Self::ProductionActivationRequested => formatter.write_str(
                "incomplete PoCO host refuses production-activated consensus parameters",
            ),
            Self::NonShadowRolloutRequested { rollout_phase } => write!(
                formatter,
                "incomplete PoCO host supports only shadow rollout, got {rollout_phase:?}",
            ),
            Self::UnsupportedEpoch { epoch } => {
                write!(formatter, "incomplete PoCO host supports only epoch zero, got {epoch}")
            }
            Self::AuthenticatedObligationReplayUnavailable {
                revision,
                obligation_count,
            } => write!(
                formatter,
                "safety revision {revision} retains {obligation_count} validation obligation(s); this legacy open cannot authenticate the application recovery join",
            ),
            Self::ValidationRecoveryAwareOpenRequired { revision } => write!(
                formatter,
                "safety revision {revision} requires the application-aware validation recovery host",
            ),
            Self::UnsupportedValidationObligationCount { count } => write!(
                formatter,
                "bounded validation recovery requires at most one obligation, got {count}",
            ),
            Self::UnexpectedActiveApplicationRecoveryJobs { expected, actual } => write!(
                formatter,
                "validation recovery expected {expected} active application job(s), got {actual}",
            ),
            Self::OrdinaryContextForInvalidCompletion { revision } => write!(
                formatter,
                "safety revision {revision} records a deterministic-invalid completion with an ordinary transition context",
            ),
            Self::UnexpectedObligationTransitionContext { revision } => write!(
                formatter,
                "obligation-bearing safety revision {revision} has a non-ordinary transition context",
            ),
            Self::MissingNativeInvalidTransitionContext { revision } => write!(
                formatter,
                "safety revision {revision} lacks its authenticated native-invalid transition context",
            ),
            Self::MissingReconciledApplicationOwner => formatter.write_str(
                "application recovery accepted the Core challenge without retaining its exact owner",
            ),
            Self::UnexpectedObligationApplicationState => formatter.write_str(
                "obligation recovery did not bind a CallbackPending or Delivered application row",
            ),
            Self::UnexpectedCompletionApplicationState => formatter.write_str(
                "completion recovery encountered an application state outside Delivered/Acked",
            ),
            Self::ApplicationCallbackIdentityMismatch => formatter.write_str(
                "application callback facts differ from the Core recovery challenge",
            ),
            Self::ApplicationAcknowledgementMismatch => formatter.write_str(
                "application acknowledgement differs from the authenticated SafetyStore context",
            ),
            Self::UnexpectedRecoveryEffectSet { expected, actual } => write!(
                formatter,
                "Core recovery expected {expected} effect(s), got {actual}",
            ),
            Self::UnexpectedRecoveryEffect { effect } => {
                write!(formatter, "Core recovery emitted unsupported effect {effect}")
            }
            Self::RecoveredHeadMismatch => {
                formatter.write_str("recovered Core state differs from the authenticated journal head")
            }
            Self::RecoveredTransitionHeadMismatch => formatter.write_str(
                "SafetyStore exact readback differs from the Core request or application transition context",
            ),
            Self::Core(error) => write!(formatter, "PoCO Core startup failed: {error}"),
            Self::SafetyStore(error) => write!(formatter, "PoCO safety-store startup failed: {error}"),
            Self::SignerJournal(error) => {
                write!(formatter, "PoCO signer-journal startup failed: {error}")
            }
            Self::ApplicationRecoveryOpen(error) => {
                write!(formatter, "application recovery open failed: {error}")
            }
            Self::ApplicationRecoveryReconcile(error) => {
                write!(formatter, "application recovery reconciliation failed: {error:?}")
            }
            Self::ApplicationRecoveryTransition(error) => {
                write!(formatter, "application recovery transition failed: {error:?}")
            }
        }
    }
}

impl Error for PocoNodeHostErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SafetyStoreParentIo(error) => Some(error.as_ref()),
            Self::SignerJournalParentIo(error) => Some(error.as_ref()),
            Self::ApplicationStoreParentIo(error) => Some(error.as_ref()),
            Self::SafetyStore(error) => Some(error.as_ref()),
            Self::SignerJournal(error) => Some(error.as_ref()),
            Self::ApplicationRecoveryOpen(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "recovery-test-support", target_os = "linux"))]
mod recovery_tests;

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::{
        fs,
        sync::{Arc, Mutex},
    };

    #[cfg(target_os = "linux")]
    use tempfile::TempDir;
    use trnm_consensus_core::SafetyStateRecordLimitsV0;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, GenesisQcV0,
        ProtocolVersion, Validator, ValidatorId, ValidatorSet, VotingPower,
    };

    use super::*;

    const _: () = {
        assert!(!PRODUCTION_CANDIDATE_V0);
        assert!(!HOST_IMPLEMENTATION_COMPLETE_V0);
    };

    const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
    const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
    const MAXIMUM_DATABASE_BYTES: usize = 192 * 1024 * 1024;
    const MAXIMUM_SIGNER_INTENTS: u64 = 64;
    const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
    const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;

    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Default)]
    struct MemoryWatermark(Arc<Mutex<Option<SignerWatermarkV0>>>);

    #[cfg(target_os = "linux")]
    impl ExternalMonotonicWatermarkV0 for MemoryWatermark {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<
            Option<SignerWatermarkV0>,
            trnm_consensus_signer_journal::ExternalWatermarkErrorV0,
        > {
            let value = *self.0.lock().expect("test watermark lock");
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(
                    trnm_consensus_signer_journal::ExternalWatermarkErrorV0::InvalidPersistedState,
                );
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), trnm_consensus_signer_journal::ExternalWatermarkErrorV0> {
            use trnm_consensus_signer_journal::ExternalWatermarkErrorV0;

            let mut value = self.0.lock().expect("test watermark lock");
            if *value != expected {
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
            *value = Some(target);
            Ok(())
        }
    }

    fn validator_id(index: u8) -> ValidatorId {
        ValidatorId::new([index; 32])
    }

    fn core_config(parameters: ConsensusParametersV0) -> CoreConfig {
        let validators = (1u8..=4)
            .map(|index| {
                Validator::new(
                    validator_id(index),
                    ConsensusPublicKey::new([index.saturating_add(100); 32]),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-poco-node-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        CoreConfig::new(validator_id(1), validator_set, parameters, 17, 64, 64)
            .expect("valid Core config")
    }

    fn record_limits() -> SafetyStateRecordLimitsV0 {
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid local record limits")
    }

    fn start_config(
        safety_store_path: impl AsRef<Path>,
        signer_journal_path: impl AsRef<Path>,
        core_config: CoreConfig,
    ) -> Result<PocoNodeStartConfigV0, PocoNodeHostErrorV0> {
        PocoNodeStartConfigV0::new(
            safety_store_path,
            signer_journal_path,
            core_config,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
    }

    fn genesis_qc(core_config: &CoreConfig) -> GenesisQcV0 {
        GenesisQcV0::new(
            core_config.validator_set().genesis_hash(),
            core_config.validator_set().chain_id(),
            core_config.validator_set(),
        )
        .expect("valid genesis anchor")
    }

    #[cfg(target_os = "linux")]
    fn protected_temp_dir() -> TempDir {
        let directory = TempDir::new().expect("temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("protect temporary safety-store directory");
        }
        directory
    }

    #[cfg(target_os = "linux")]
    fn protected_store_namespace(root: &TempDir, name: &str) -> PathBuf {
        let namespace = root.path().join(name);
        create_protected_directory(&namespace);
        namespace
    }

    #[cfg(target_os = "linux")]
    fn create_protected_directory(path: &Path) {
        fs::create_dir_all(path).expect("create isolated store namespace");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("protect isolated store namespace");
        }
    }

    #[cfg(target_os = "linux")]
    fn dual_store_paths(root: &TempDir) -> (PathBuf, PathBuf) {
        (
            protected_store_namespace(root, "safety").join("safety.sqlite3"),
            protected_store_namespace(root, "signer").join("signer.sqlite3"),
        )
    }

    #[cfg(target_os = "linux")]
    fn triple_store_paths(root: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
        let (safety, signer) = dual_store_paths(root);
        let application = protected_store_namespace(root, "application").join("state.json");
        (safety, signer, application)
    }

    #[test]
    fn static_activation_gate_names_real_unwired_contracts() {
        let error = production_activation_gate_v0().expect_err("activation must remain blocked");
        assert_eq!(error.blockers(), UNWIRED_PRODUCTION_CONTRACTS_V0);
        assert!(error.to_string().contains("independent_signer_watermark"));
        assert!(error.to_string().contains("complete_hotstuff_safety_rules"));
        assert!(!error.to_string().contains("append_only_sign_journal"));
        assert!(error.to_string().contains("block_id_speculative_overlay"));
        assert!(error
            .to_string()
            .contains("application_validation_recovery_beyond_deterministic_invalid_v0"));
        assert!(!error
            .to_string()
            .contains(",application_validation_recovery,"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validation_recovery_config_requires_a_third_canonical_namespace() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let application_path = safety_path
            .parent()
            .expect("safety namespace")
            .join("state.json");
        let node = start_config(
            &safety_path,
            &signer_path,
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect("valid dual-store config");
        let error = PocoNodeValidationRecoveryConfigV0::new(node, application_path, [0x5a; 32])
            .expect_err("application WAL must not share the safety namespace");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedApplicationStoreParentNamespace
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validation_recovery_config_rejects_application_ancestor_and_descendant_namespaces() {
        let directory = protected_temp_dir();
        let cases = [
            (
                "application-under-safety",
                "safety",
                "signer",
                "safety/application",
            ),
            (
                "application-over-safety",
                "application/safety",
                "signer",
                "application",
            ),
            (
                "application-under-signer",
                "safety",
                "signer",
                "signer/application",
            ),
            (
                "application-over-signer",
                "safety",
                "application/signer",
                "application",
            ),
        ];

        for (case, safety_parent, signer_parent, application_parent) in cases {
            let case_root = directory.path().join(case);
            let safety_parent = case_root.join(safety_parent);
            let signer_parent = case_root.join(signer_parent);
            let application_parent = case_root.join(application_parent);
            create_protected_directory(&safety_parent);
            create_protected_directory(&signer_parent);
            create_protected_directory(&application_parent);

            let node = start_config(
                safety_parent.join("safety.sqlite3"),
                signer_parent.join("signer.sqlite3"),
                core_config(ConsensusParametersV0::reference_shadow_v0()),
            )
            .expect("safety and signer parents remain non-overlapping");
            let error = PocoNodeValidationRecoveryConfigV0::new(
                node,
                application_parent.join("state.json"),
                [0x5a; 32],
            )
            .expect_err("application parent must not contain or be contained by another store");
            assert!(matches!(
                error,
                PocoNodeHostErrorV0::SharedApplicationStoreParentNamespace
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validation_recovery_config_rejects_nested_application_after_symlink_canonicalization() {
        use std::os::unix::fs::symlink;

        let directory = protected_temp_dir();
        let safety_parent = protected_store_namespace(&directory, "safety");
        let signer_parent = protected_store_namespace(&directory, "signer");
        let nested_application_parent = safety_parent.join("nested-application");
        create_protected_directory(&nested_application_parent);
        let application_alias = directory.path().join("application-alias");
        symlink(&nested_application_parent, &application_alias)
            .expect("create application namespace symlink");

        let node = start_config(
            safety_parent.join("safety.sqlite3"),
            signer_parent.join("signer.sqlite3"),
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect("raw safety and signer paths are valid siblings");
        let error = PocoNodeValidationRecoveryConfigV0::new(
            node,
            application_alias.join("state.json"),
            [0x5a; 32],
        )
        .expect_err("canonicalized application alias must reveal the nested namespace");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedApplicationStoreParentNamespace
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validation_recovery_config_freezes_three_distinct_paths() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path, application_path) = triple_store_paths(&directory);
        let node = start_config(
            &safety_path,
            &signer_path,
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect("valid dual-store config");
        let recovery = PocoNodeValidationRecoveryConfigV0::new(node, &application_path, [0x5a; 32])
            .expect("valid triple-store recovery config");
        assert_eq!(recovery.application_status_path(), application_path);
        assert_eq!(recovery.signer_policy_hash(), [0x5a; 32]);
        assert_eq!(recovery.node_config().safety_store_path(), safety_path);
        assert_eq!(recovery.node_config().signer_journal_path(), signer_path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validation_recovery_config_rejects_relative_application_path() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let node = start_config(
            &safety_path,
            &signer_path,
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect("valid dual-store config");
        let error =
            PocoNodeValidationRecoveryConfigV0::new(node, "relative/state.json", [0x5a; 32])
                .expect_err("relative application recovery state must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::RelativeApplicationStatusPath
        ));
    }

    #[test]
    fn startup_config_rejects_relative_store_path() {
        let error = PocoNodeStartConfigV0::new(
            "relative/safety.sqlite3",
            "/tmp/trnm-poco-node-relative-safety-signer.sqlite3",
            core_config(ConsensusParametersV0::reference_shadow_v0()),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("relative startup state must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::RelativeSafetyStorePath
        ));
    }

    #[test]
    fn startup_config_rejects_relative_signer_journal_path() {
        let error = start_config(
            "/tmp/trnm-poco-node-relative-signer-safety.sqlite3",
            "relative/signer.sqlite3",
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect_err("relative signer state must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::RelativeSignerJournalPath
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_config_rejects_shared_canonical_parent_namespace() {
        let directory = protected_temp_dir();
        let error = start_config(
            directory.path().join("safety.sqlite3"),
            directory.path().join("signer.sqlite3"),
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect_err("two histories in one canonical parent must be refused");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedStoreParentNamespace
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_config_rejects_safety_signer_ancestor_and_descendant_namespaces() {
        let directory = protected_temp_dir();
        let outer = protected_store_namespace(&directory, "outer");
        let nested = outer.join("nested");
        create_protected_directory(&nested);

        for (safety_parent, signer_parent) in [(&outer, &nested), (&nested, &outer)] {
            let error = start_config(
                safety_parent.join("safety.sqlite3"),
                signer_parent.join("signer.sqlite3"),
                core_config(ConsensusParametersV0::reference_shadow_v0()),
            )
            .expect_err("safety and signer parents must not contain one another");
            assert!(matches!(
                error,
                PocoNodeHostErrorV0::SharedStoreParentNamespace
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_config_rejects_nested_store_after_symlink_canonicalization() {
        use std::os::unix::fs::symlink;

        let directory = protected_temp_dir();
        let safety_parent = protected_store_namespace(&directory, "safety");
        let nested_signer_parent = safety_parent.join("nested-signer");
        create_protected_directory(&nested_signer_parent);
        let signer_alias = directory.path().join("signer-alias");
        symlink(&nested_signer_parent, &signer_alias).expect("create signer namespace symlink");

        let error = start_config(
            safety_parent.join("safety.sqlite3"),
            signer_alias.join("signer.sqlite3"),
            core_config(ConsensusParametersV0::reference_shadow_v0()),
        )
        .expect_err("canonicalized signer alias must reveal the nested namespace");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SharedStoreParentNamespace
        ));
    }

    #[test]
    fn startup_config_rejects_production_activation() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.production_activation = true;
        let activated = ConsensusParametersV0::new(fields)
            .expect("production flag is a future policy value, not a shape error");
        let error = PocoNodeStartConfigV0::new(
            "/tmp/trnm-poco-node-production-refusal.sqlite3",
            "/tmp/trnm-poco-node-production-refusal-signer.sqlite3",
            core_config(activated),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("incomplete host must refuse production activation");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::ProductionActivationRequested
        ));
    }

    #[test]
    fn startup_config_rejects_non_shadow_rollout() {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.rollout_phase = RolloutPhase::EligibilityOnly;
        let non_shadow = ConsensusParametersV0::new(fields)
            .expect("eligibility-only is a future policy value, not a shape error");
        let error = PocoNodeStartConfigV0::new(
            "/tmp/trnm-poco-node-rollout-refusal.sqlite3",
            "/tmp/trnm-poco-node-rollout-refusal-signer.sqlite3",
            core_config(non_shadow),
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect_err("incomplete host must refuse non-shadow rollout");
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::NonShadowRolloutRequested {
                rollout_phase: RolloutPhase::EligibilityOnly
            }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn one_host_initializes_and_recovers_exact_dual_store_ownership() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let genesis_qc = genesis_qc(&core_config);
        let config =
            start_config(&safety_path, &signer_path, core_config).expect("valid inert host config");
        let watermark = MemoryWatermark::default();

        let host = PocoNodeHostV0::initialize_new(config.clone(), genesis_qc, watermark.clone())
            .expect("initialize exact dual-store owner");
        assert_eq!(
            host.bootstrap_mode(),
            HostBootstrapModeV0::InitializedGenesis
        );
        assert_eq!(
            host.lifecycle_phase(),
            HostLifecyclePhaseV0::BootstrappedInert
        );
        assert_eq!(host.safety_state().revision(), 0);
        assert_eq!(host.safety_head().expect("journal head").revision(), 0);
        assert_eq!(host.safety_store_path(), safety_path.as_path());
        assert_eq!(host.signer_journal_path(), signer_path.as_path());
        assert_eq!(host.signer_journal_head().sequence(), 0);
        assert_eq!(
            host.signer_journal_capacity()
                .expect("signer capacity")
                .intent_count(),
            0
        );
        assert!(host.production_activation_check().is_err());

        let duplicate_open = match PocoNodeHostV0::open_existing(config.clone(), watermark.clone())
        {
            Ok(_) => panic!("a second live owner must not open the same journal"),
            Err(error) => error,
        };
        assert!(matches!(
            duplicate_open,
            PocoNodeHostErrorV0::SafetyStore(error)
                if matches!(error.as_ref(), SafetyStoreErrorV0::Locked)
        ));
        drop(host);

        let recovered = PocoNodeHostV0::open_existing(config, watermark)
            .expect("recover exact dual-store owner");
        assert_eq!(
            recovered.bootstrap_mode(),
            HostBootstrapModeV0::RecoveredExisting
        );
        assert_eq!(recovered.safety_state().revision(), 0);
        assert_eq!(recovered.safety_store_path(), safety_path.as_path());
        assert_eq!(recovered.signer_journal_path(), signer_path.as_path());
        assert_eq!(recovered.signer_journal_head().sequence(), 0);
        assert!(recovered.production_activation_check().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signer_profile_mismatch_fails_after_safety_store_authentication() {
        let directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&directory);
        let core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let genesis_qc = genesis_qc(&core_config);
        let config = start_config(&safety_path, &signer_path, core_config.clone())
            .expect("valid initial config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(config, genesis_qc, watermark.clone())
            .expect("initialize dual stores");
        drop(host);

        let mismatched = PocoNodeStartConfigV0::new(
            &safety_path,
            &signer_path,
            core_config,
            record_limits(),
            MAXIMUM_DATABASE_BYTES,
            MAXIMUM_SIGNER_INTENTS + 1,
            MAXIMUM_SIGNER_INTENT_BYTES,
            MAXIMUM_SIGNER_DATABASE_BYTES,
        )
        .expect("shape-valid alternate local capacity profile");
        let error = match PocoNodeHostV0::open_existing(mismatched, watermark) {
            Ok(_) => panic!("different signer profile must not open"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SignerJournal(error)
                if matches!(error.as_ref(), SignerJournalErrorV0::MetadataMismatch)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn either_partial_dual_store_namespace_fails_closed() {
        let missing_signer_directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&missing_signer_directory);
        let safety_only_core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let config = start_config(&safety_path, &signer_path, safety_only_core_config.clone())
            .expect("valid missing-signer config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc(&safety_only_core_config),
            watermark.clone(),
        )
        .expect("initialize missing-signer fixture");
        drop(host);
        fs::remove_file(&signer_path).expect("remove signer database only");
        let error = match PocoNodeHostV0::open_existing(config, watermark) {
            Ok(_) => panic!("safety-only namespace must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SignerJournal(error)
                if matches!(error.as_ref(), SignerJournalErrorV0::Missing("database"))
        ));

        let missing_safety_directory = protected_temp_dir();
        let (safety_path, signer_path) = dual_store_paths(&missing_safety_directory);
        let signer_only_core_config = core_config(ConsensusParametersV0::reference_shadow_v0());
        let config = start_config(&safety_path, &signer_path, signer_only_core_config.clone())
            .expect("valid missing-safety config");
        let watermark = MemoryWatermark::default();
        let host = PocoNodeHostV0::initialize_new(
            config.clone(),
            genesis_qc(&signer_only_core_config),
            watermark.clone(),
        )
        .expect("initialize missing-safety fixture");
        drop(host);
        fs::remove_file(&safety_path).expect("remove safety database only");
        let error = match PocoNodeHostV0::open_existing(config, watermark) {
            Ok(_) => panic!("signer-only namespace must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PocoNodeHostErrorV0::SafetyStore(error)
                if matches!(error.as_ref(), SafetyStoreErrorV0::Missing("database"))
        ));
    }
}
