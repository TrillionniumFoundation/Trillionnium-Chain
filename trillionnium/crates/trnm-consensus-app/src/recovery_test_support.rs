//! Explicitly non-production fixture support for the G1c recovery join.
//!
//! This module exists only with the `recovery-test-support` feature. It never
//! constructs a Core request, recovery challenge, SafetyState, signature, or
//! persistence authority. A caller must supply the non-constructible recovery
//! challenge emitted by a real Core; advancing the application journal to D
//! additionally requires that Core's opaque persistence request.
//!
//! The helper creates one fresh schema-v8 ApplicationStore namespace and uses
//! the same reservation, checksum, artifact, outbox, delivery, and recovery
//! transitions as the application. It exposes no connection, SQL, arbitrary
//! row parts, checksum override, or mutation hook. Constructing K is
//! intentionally unsupported until the host supplies a concrete,
//! SafetyStore-authenticated completion token.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use bytes::Bytes;
use tendermint_abci::Application;
use tendermint_proto::v0_38::types::{ConsensusParams, VersionParams};
use trnm_consensus_core::{
    CoreConfig, PayloadValidationRecoveryChallengeV0, PayloadValidationRecoveryDecisionV0,
    PayloadValidationRecoveryReconcilerV0, PayloadValidationRouteV0, SafetyState,
    SafetyStatePersistenceV0, ValidationId,
};
use trnm_consensus_types::ChainId;

use crate::{
    native_execution::NativeBlockExecutionV0,
    native_payload_validation::prepare_recovery_test_durable_invalid_v0,
    native_validation_artifact::DurableDeterministicInvalidReasonV0,
    signer_policy_commitment,
    store::{
        empty_native_application_trusted_base_root_for_recovery_test_v0 as empty_trusted_base_root_v0,
        native_application_h1_trusted_base_v0,
        native_application_h1_validator_lifecycle_expectation_v0,
        native_validation_recovery::{
            bootstrap_native_validation_safety_binding_manifest_v0,
            NativeValidationRecoveredInvalidCallbackFactsV0,
            NativeValidationRecoveredInvalidReasonV0, NativeValidationRecoveredInvalidStateV0,
            NativeValidationRecoveryOpenFailureV0, NativeValidationRecoveryReconcileFailureV0,
            NativeValidationRecoveryStoreConfigV0, NativeValidationRecoveryStoreV0,
            NativeValidationRecoveryTransitionFailureV0,
        },
        native_validation_request_fingerprint_v0, ApplicationStore,
        NativeValidationInvalidSealDecisionV0, NativeValidationJobStateV0,
        NativeValidationReservationDecisionV0, NativeValidationReservationFactsV0,
    },
    validator_lifecycle::{
        validators_to_abci, ConsensusValidatorV1, ValidatorGovernanceV1, ValidatorLifecycleStateV1,
        VALIDATOR_GOVERNANCE_SCHEMA_V1,
    },
    AuthorizedSignerV1, CometBftApplication, ConsensusAppConfig, GenesisAppStateV2, APP_VERSION,
    CONFIG_SCHEMA_V1, GENESIS_SCHEMA_V2,
};

/// Deterministic execution commitments for the empty h2/h3 bodies above the
/// canonical h1 test checkpoint. These are derived by the same JMT planner
/// and empty receipt implementation used by production validation; no durable
/// job, callback, overlay, or Core authority is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeEmptyAnchorSuccessorCommitmentsV0 {
    h2_state_root: [u8; 32],
    h2_receipts_root: [u8; 32],
    h3_state_root: [u8; 32],
    h3_receipts_root: [u8; 32],
}

impl NativeEmptyAnchorSuccessorCommitmentsV0 {
    pub const fn h2_state_root(self) -> [u8; 32] {
        self.h2_state_root
    }

    pub const fn h2_receipts_root(self) -> [u8; 32] {
        self.h2_receipts_root
    }

    pub const fn h3_state_root(self) -> [u8; 32] {
        self.h3_state_root
    }

    pub const fn h3_receipts_root(self) -> [u8; 32] {
        self.h3_receipts_root
    }
}

/// Plans the exact empty h2 and h3 speculative state roots without opening a
/// durable namespace. V0 rejects a geometry whose scheduled PoCO cutoff falls
/// on either height because that body would require a manifest refresh write.
pub fn empty_state_sync_anchor_successor_commitments_for_recovery_test_v0(
    bundle: &NativeValidationRecoveryTestConfigBundleV0,
    core_config: &CoreConfig,
) -> Result<NativeEmptyAnchorSuccessorCommitmentsV0, NativeValidationRecoveryTestFixtureErrorV0> {
    let lifecycle = recovery_test_validator_lifecycle_v0(bundle, core_config)?;
    let mut h2_lifecycle = lifecycle.clone();
    h2_lifecycle
        .prepare_height(2)
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    let mut h3_lifecycle = h2_lifecycle.clone();
    h3_lifecycle
        .prepare_height(3)
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    if h2_lifecycle != lifecycle || h3_lifecycle != lifecycle {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization);
    }
    let geometry = trnm_consensus_types::EpochGeometryV0::new(
        core_config.validator_set().epoch(),
        core_config.consensus_parameters(),
    )
    .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    let cutoff = geometry
        .checkpoint_height()
        .get()
        .checked_sub(core_config.consensus_parameters().snapshot_lead_blocks())
        .ok_or(NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    if matches!(cutoff, 2 | 3) {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization);
    }
    let (mut authenticated, _) = native_application_h1_trusted_base_v0(1, core_config, &lifecycle)
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    let h2 = authenticated
        .plan_put_value_set(2, Vec::new())
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    let h2_state_root = h2.root_hash.0;
    authenticated
        .apply(h2)
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    let h3 = authenticated
        .plan_put_value_set(3, Vec::new())
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    let h3_state_root = h3.root_hash.0;
    let receipts_root = NativeBlockExecutionV0::try_new(&[], Vec::new())
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?
        .execution_receipts()
        .receipts_root()
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    Ok(NativeEmptyAnchorSuccessorCommitmentsV0 {
        h2_state_root,
        h2_receipts_root: *receipts_root.as_bytes(),
        h3_state_root,
        h3_receipts_root: *receipts_root.as_bytes(),
    })
}

/// Deterministically derives the exact fresh schema-v12 h1 JMT root used by
/// the recovery fixture. The projection contains the validator lifecycle and
/// the Core-pinned kind-13/kind-14 configuration, but no kind-16 application
/// authority or node-local replay history.
pub fn empty_native_application_trusted_base_root_for_recovery_test_v0(
    height: u64,
    bundle: &NativeValidationRecoveryTestConfigBundleV0,
    core_config: &CoreConfig,
) -> Result<[u8; 32], NativeValidationRecoveryTestFixtureErrorV0> {
    if height == 0 {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::PositiveHeightCheckpointRequired);
    }
    let lifecycle = recovery_test_validator_lifecycle_v0(bundle, core_config)?;
    empty_trusted_base_root_v0(height, core_config, &lifecycle)
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)
}

fn recovery_test_validator_lifecycle_v0(
    bundle: &NativeValidationRecoveryTestConfigBundleV0,
    core_config: &CoreConfig,
) -> Result<ValidatorLifecycleStateV1, NativeValidationRecoveryTestFixtureErrorV0> {
    native_application_h1_validator_lifecycle_expectation_v0(core_config, &bundle.application)
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::InvalidApplicationConfig)
}

const RECOVERY_TEST_SIGNER_PUBLIC_KEY_HEX_V0: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// Paired application/recovery configuration derived from one canonical
/// signer-policy preimage. Callers cannot supply a detached policy hash that
/// disagrees with the `ConsensusAppConfig` later opened by the process host.
#[derive(Debug, Clone)]
pub struct NativeValidationRecoveryTestConfigBundleV0 {
    application: ConsensusAppConfig,
    recovery: NativeValidationRecoveryTestFixtureConfigV0,
}

impl NativeValidationRecoveryTestConfigBundleV0 {
    pub fn new(
        status_path: impl AsRef<Path>,
        chain_id: ChainId,
        expected_safety_journal_id: [u8; 32],
        expected_safety_verifier_profile_ref: [u8; 32],
    ) -> Result<Self, NativeValidationRecoveryTestFixtureErrorV0> {
        let authorized_signers = vec![AuthorizedSignerV1 {
            signer_id: "did:operator:recovery-test".to_string(),
            signer_role: "operator".to_string(),
            public_key_hex: RECOVERY_TEST_SIGNER_PUBLIC_KEY_HEX_V0.to_string(),
        }];
        let signer_policy_hash = signer_policy_commitment(&authorized_signers);
        let recovery = NativeValidationRecoveryTestFixtureConfigV0::new(
            status_path,
            chain_id,
            signer_policy_hash,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        )?;
        let application = ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: chain_id.as_str().to_string(),
            authorized_signers,
            poco_authority: None,
            state_path: Some(recovery.status_path().to_path_buf()),
        };
        application
            .validate()
            .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::InvalidApplicationConfig)?;
        Ok(Self {
            application,
            recovery,
        })
    }

    pub fn application_config_v0(&self) -> ConsensusAppConfig {
        self.application.clone()
    }

    pub const fn recovery_fixture_config_v0(&self) -> &NativeValidationRecoveryTestFixtureConfigV0 {
        &self.recovery
    }
}

/// Test-only result of initializing the legacy ABCI application at genesis.
///
/// This type deliberately exposes only TRNM-owned configuration and the
/// resulting state commitment. The temporary transport request used to open
/// the migration-residue application stays inside this feature-gated helper,
/// so native node tests do not acquire a direct ABCI/protobuf dependency.
#[derive(Debug, Clone)]
pub struct LegacyGenesisApplicationTestFixtureV0 {
    application: ConsensusAppConfig,
    state_root: [u8; 32],
}

impl LegacyGenesisApplicationTestFixtureV0 {
    pub fn application_config_v0(&self) -> ConsensusAppConfig {
        self.application.clone()
    }

    pub const fn state_root_v0(&self) -> [u8; 32] {
        self.state_root
    }
}

/// Initializes the current legacy application schema through its ABCI genesis
/// adapter while keeping every external transport type private to the legacy
/// application crate.
///
/// This is migration test support, not a native production initialization
/// API. Removing the legacy adapter remains a separate G0 obligation.
pub fn initialize_legacy_genesis_application_test_fixture_v0(
    bundle: &NativeValidationRecoveryTestConfigBundleV0,
    core_config: &CoreConfig,
) -> Result<LegacyGenesisApplicationTestFixtureV0, NativeValidationRecoveryTestFixtureErrorV0> {
    let application = bundle.application_config_v0();
    let governance_signer = application
        .authorized_signers
        .first()
        .filter(|signer| signer.signer_role == "operator")
        .ok_or(NativeValidationRecoveryTestFixtureErrorV0::InvalidApplicationConfig)?;
    let mut initial_validators = core_config
        .validator_set()
        .validators()
        .iter()
        .map(|validator| ConsensusValidatorV1 {
            public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
            voting_power: validator.voting_power().get(),
        })
        .collect::<Vec<_>>();
    initial_validators
        .sort_unstable_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
    let request_validators = validators_to_abci(&initial_validators)
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::InvalidApplicationConfig)?;
    let genesis = GenesisAppStateV2 {
        schema: GENESIS_SCHEMA_V2.to_string(),
        chain_id: application.chain_id.clone(),
        app_version: APP_VERSION,
        authorized_signers: application.authorized_signers.clone(),
        poco_authority: application.poco_authority.clone(),
        poco_genesis_entries: Vec::new(),
        validator_governance: ValidatorGovernanceV1 {
            schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
            signer_id: governance_signer.signer_id.clone(),
            min_activation_delay_blocks: 2,
            unsafe_allow_single_validator_genesis: false,
        },
        initial_validators,
    };
    let app_state_bytes = serde_json::to_vec(&genesis)
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::InvalidApplicationConfig)?;
    let request = tendermint_proto::v0_38::abci::RequestInitChain {
        chain_id: application.chain_id.clone(),
        app_state_bytes: Bytes::from(app_state_bytes),
        consensus_params: Some(ConsensusParams {
            version: Some(VersionParams { app: APP_VERSION }),
            ..Default::default()
        }),
        validators: request_validators,
        ..Default::default()
    };
    let expected_validator_count = request.validators.len();
    let app = CometBftApplication::new(application.clone())
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    let response = app.init_chain(request);
    if response.validators.len() != expected_validator_count {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization);
    }
    let (height, state_root) = app
        .height_and_app_hash()
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    if height != 0 {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization);
    }
    drop(app);
    Ok(LegacyGenesisApplicationTestFixtureV0 {
        application,
        state_root,
    })
}

/// Read-only paths/facts for a fresh schema-v12 h1 TrustedBase fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEmptyApplicationTestFixtureV0 {
    status_path: PathBuf,
    database_path: PathBuf,
    height: u64,
    state_root: [u8; 32],
}

impl NativeEmptyApplicationTestFixtureV0 {
    pub fn status_path(&self) -> &Path {
        self.status_path.as_path()
    }

    pub fn database_path(&self) -> &Path {
        self.database_path.as_path()
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }
}

/// Canonical target state names used by the cross-crate recovery fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationRecoveryTestFixtureStateV0 {
    CallbackPending,
    Delivered,
}

/// Fresh, isolated ApplicationStore namespace used by one recovery fixture.
///
/// Construction canonicalizes an already-existing parent. The status path and
/// its derived SQLite path must both be absent when P is initialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeValidationRecoveryTestFixtureConfigV0 {
    status_path: PathBuf,
    database_path: PathBuf,
    chain_id: ChainId,
    signer_policy_hash: [u8; 32],
    expected_safety_journal_id: [u8; 32],
    expected_safety_verifier_profile_ref: [u8; 32],
}

impl NativeValidationRecoveryTestFixtureConfigV0 {
    pub fn new(
        status_path: impl AsRef<Path>,
        chain_id: ChainId,
        signer_policy_hash: [u8; 32],
        expected_safety_journal_id: [u8; 32],
        expected_safety_verifier_profile_ref: [u8; 32],
    ) -> Result<Self, NativeValidationRecoveryTestFixtureErrorV0> {
        let status_path = status_path.as_ref();
        if !status_path.is_absolute() {
            return Err(NativeValidationRecoveryTestFixtureErrorV0::StatusPathNotAbsolute);
        }
        let file_name = status_path
            .file_name()
            .ok_or(NativeValidationRecoveryTestFixtureErrorV0::InvalidStatusPath)?;
        let parent = fs::canonicalize(
            status_path
                .parent()
                .ok_or(NativeValidationRecoveryTestFixtureErrorV0::InvalidStatusPath)?,
        )
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StatusParentUnavailable)?;
        if !parent.is_dir() {
            return Err(NativeValidationRecoveryTestFixtureErrorV0::StatusParentUnavailable);
        }
        let status_path = parent.join(file_name);
        let database_path = database_path_for_status_v0(&status_path);
        Ok(Self {
            status_path,
            database_path,
            chain_id,
            signer_policy_hash,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        })
    }

    pub fn status_path(&self) -> &Path {
        self.status_path.as_path()
    }

    pub fn database_path(&self) -> &Path {
        self.database_path.as_path()
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn signer_policy_hash(&self) -> [u8; 32] {
        self.signer_policy_hash
    }

    pub const fn expected_safety_journal_id(&self) -> [u8; 32] {
        self.expected_safety_journal_id
    }

    pub const fn expected_safety_verifier_profile_ref(&self) -> [u8; 32] {
        self.expected_safety_verifier_profile_ref
    }
}

/// Read-only result of one canonical fixture transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeValidationRecoveryTestFixtureV0 {
    status_path: PathBuf,
    database_path: PathBuf,
    state: NativeValidationRecoveryTestFixtureStateV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    reason: NativeValidationRecoveredInvalidReasonV0,
    callback_facts: NativeValidationRecoveredInvalidCallbackFactsV0,
}

impl NativeValidationRecoveryTestFixtureV0 {
    pub fn status_path(&self) -> &Path {
        self.status_path.as_path()
    }

    pub fn database_path(&self) -> &Path {
        self.database_path.as_path()
    }

    pub const fn state(&self) -> NativeValidationRecoveryTestFixtureStateV0 {
        self.state
    }

    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id(&self) -> ValidationId {
        self.validation_id
    }

    pub const fn reason(&self) -> NativeValidationRecoveredInvalidReasonV0 {
        self.reason
    }

    pub const fn callback_facts(&self) -> NativeValidationRecoveredInvalidCallbackFactsV0 {
        self.callback_facts
    }
}

/// Closed failure taxonomy. No variant exposes an ApplicationStore, SQL error,
/// reservation token, or retryable owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationRecoveryTestFixtureErrorV0 {
    StatusPathNotAbsolute,
    InvalidStatusPath,
    StatusParentUnavailable,
    NamespaceAlreadyExists,
    NamespaceMetadataUnavailable,
    InvalidApplicationConfig,
    PositiveHeightCheckpointRequired,
    StoreInitialization,
    ChallengeRevisionMismatch,
    ChallengeRequestMalformed,
    ReservationFailed,
    ExistingReservation,
    InvalidSealFailed,
    UnexpectedFixtureState,
    RecoveryOpen(NativeValidationRecoveryOpenFailureV0),
    RecoveryReconcile(NativeValidationRecoveryReconcileFailureV0),
    PersistenceRevisionMismatch,
    RecoveryTransition(NativeValidationRecoveryTransitionFailureV0),
}

impl fmt::Display for NativeValidationRecoveryTestFixtureErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StatusPathNotAbsolute => "recovery fixture status path is not absolute",
            Self::InvalidStatusPath => "recovery fixture status path does not name a file",
            Self::StatusParentUnavailable => {
                "recovery fixture status parent is not an existing canonical directory"
            }
            Self::NamespaceAlreadyExists => "recovery fixture namespace already exists",
            Self::NamespaceMetadataUnavailable => {
                "recovery fixture namespace metadata is unavailable"
            }
            Self::InvalidApplicationConfig => "recovery fixture application config is invalid",
            Self::PositiveHeightCheckpointRequired => {
                "recovery fixture requires an authenticated positive-height checkpoint"
            }
            Self::StoreInitialization => "recovery fixture store initialization failed",
            Self::ChallengeRevisionMismatch => {
                "recovery fixture challenge revision lineage is invalid"
            }
            Self::ChallengeRequestMalformed => "recovery fixture challenge request is malformed",
            Self::ReservationFailed => "recovery fixture reservation failed",
            Self::ExistingReservation => "recovery fixture unexpectedly found an existing job",
            Self::InvalidSealFailed => "recovery fixture deterministic-invalid seal failed",
            Self::UnexpectedFixtureState => "recovery fixture reached an unexpected durable state",
            Self::RecoveryOpen(_) => "recovery fixture existing-only open failed",
            Self::RecoveryReconcile(_) => "recovery fixture challenge reconciliation failed",
            Self::PersistenceRevisionMismatch => {
                "recovery fixture persistence request is not the exact next revision"
            }
            Self::RecoveryTransition(_) => "recovery fixture durable transition failed",
        })
    }
}

/// Initializes a fresh current-schema ApplicationStore only when Safety
/// already authenticates a positive-height application checkpoint. Synthetic
/// Core genesis is rejected: it carries no exact application state root and
/// must not be silently converted into a v12 TrustedBase. This fixture writes
/// the Core-pinned active configuration, but no application authority.
pub fn initialize_empty_native_application_test_fixture_v0(
    bundle: &NativeValidationRecoveryTestConfigBundleV0,
    core_config: &CoreConfig,
    safety_state: &SafetyState,
) -> Result<NativeEmptyApplicationTestFixtureV0, NativeValidationRecoveryTestFixtureErrorV0> {
    let config = bundle.recovery_fixture_config_v0();
    let applied = safety_state.application_applied();
    let Some(anchor) = safety_state.state_sync_anchor() else {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::PositiveHeightCheckpointRequired);
    };
    let target = anchor.proof().finalized_block().header();
    if safety_state.chain_id() != config.chain_id()
        || safety_state.chain_id() != core_config.validator_set().chain_id()
        || safety_state.validator_set_id() != core_config.validator_set().id()
        || safety_state.genesis_block_id() != core_config.genesis_block_id()
        || applied.height().get() == 0
        || applied.block_id() != target.id()
        || applied.height() != target.height()
        || applied.view() != target.view()
        || applied.timestamp_ms() != target.timestamp_ms()
    {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::PositiveHeightCheckpointRequired);
    }
    let lifecycle = recovery_test_validator_lifecycle_v0(bundle, core_config)?;
    let expected_state_root =
        empty_trusted_base_root_v0(applied.height().get(), core_config, &lifecycle)
            .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    if expected_state_root != *target.state_root().as_bytes() {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization);
    }
    require_absent_v0(config.status_path())?;
    require_absent_v0(config.database_path())?;
    let store = ApplicationStore::open(
        config.status_path(),
        config.chain_id().as_str(),
        &hex::encode(config.signer_policy_hash()),
    )
    .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    store
        .load_or_migrate()
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    let state_root = store
        .initialize_empty_native_trusted_base_for_recovery_test_v0(
            applied.block_id(),
            applied.height().get(),
            core_config,
            lifecycle,
        )
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    if state_root != expected_state_root {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization);
    }
    bootstrap_native_validation_safety_binding_manifest_v0(
        &store,
        config.expected_safety_journal_id(),
        config.expected_safety_verifier_profile_ref(),
    )
    .map_err(NativeValidationRecoveryTestFixtureErrorV0::RecoveryOpen)?;
    drop(store);
    Ok(NativeEmptyApplicationTestFixtureV0 {
        status_path: config.status_path().to_path_buf(),
        database_path: config.database_path().to_path_buf(),
        height: applied.height().get(),
        state_root,
    })
}

impl Error for NativeValidationRecoveryTestFixtureErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RecoveryOpen(error) => Some(error),
            _ => None,
        }
    }
}

/// Creates one fresh schema-v8 CallbackPending (P) job from an authentic Core
/// recovery challenge. The two-valued reason is the only simulated execution
/// outcome; every durable identity, request record, checksum, artifact, and
/// outbox value is derived by the normal application implementation.
pub fn initialize_native_validation_recovery_test_fixture_v0(
    config: &NativeValidationRecoveryTestFixtureConfigV0,
    challenge: &PayloadValidationRecoveryChallengeV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) -> Result<NativeValidationRecoveryTestFixtureV0, NativeValidationRecoveryTestFixtureErrorV0> {
    validate_challenge_revision_v0(challenge)?;
    require_absent_v0(config.status_path())?;
    require_absent_v0(config.database_path())?;

    let store = ApplicationStore::open(
        config.status_path(),
        config.chain_id().as_str(),
        &hex::encode(config.signer_policy_hash()),
    )
    .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    store
        .load_or_migrate()
        .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::StoreInitialization)?;
    bootstrap_native_validation_safety_binding_manifest_v0(
        &store,
        config.expected_safety_journal_id(),
        config.expected_safety_verifier_profile_ref(),
    )
    .map_err(NativeValidationRecoveryTestFixtureErrorV0::RecoveryOpen)?;

    let fingerprint = native_validation_request_fingerprint_v0(
        challenge.route(),
        challenge.id(),
        challenge.proposal().block(),
        challenge.parent(),
    )
    .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::ChallengeRequestMalformed)?;
    let reservation_facts = NativeValidationReservationFactsV0::from_core_request_v0(
        challenge.route(),
        challenge.id(),
        challenge.proposal().block(),
        challenge.parent(),
        fingerprint,
    )
    .map_err(|_| NativeValidationRecoveryTestFixtureErrorV0::ChallengeRequestMalformed)?;
    let reservation = match store.reserve_or_reopen_native_validation_job_v0(reservation_facts) {
        Ok(NativeValidationReservationDecisionV0::Reserved(reservation)) => reservation,
        Ok(NativeValidationReservationDecisionV0::Existing(_)) => {
            return Err(NativeValidationRecoveryTestFixtureErrorV0::ExistingReservation);
        }
        Err(_) => {
            return Err(NativeValidationRecoveryTestFixtureErrorV0::ReservationFailed);
        }
    };
    let prepared = prepare_recovery_test_durable_invalid_v0(reservation, durable_reason_v0(reason));
    let live = match store.seal_durable_invalid_and_enqueue_callback_v0(prepared) {
        Ok(NativeValidationInvalidSealDecisionV0::CallbackPending(live)) => live,
        Ok(NativeValidationInvalidSealDecisionV0::Existing(_)) => {
            return Err(NativeValidationRecoveryTestFixtureErrorV0::ExistingReservation);
        }
        Err(_) => return Err(NativeValidationRecoveryTestFixtureErrorV0::InvalidSealFailed),
    };
    if live.state() != NativeValidationJobStateV0::CallbackPending
        || live.route() != challenge.route()
        || live.validation_id() != challenge.id()
        || live.reason() != durable_reason_v0(reason)
        || live.delivery_attempt() != 0
    {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::UnexpectedFixtureState);
    }
    drop(live);
    drop(store);

    let mut recovery = open_single_active_fixture_v0(config)?;
    reconcile_exact_challenge_v0(&mut recovery, challenge)?;
    if recovery.recovered_obligation_state_v0()
        != Some(NativeValidationRecoveredInvalidStateV0::CallbackPending)
    {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::UnexpectedFixtureState);
    }
    let callback_facts = exact_callback_facts_v0(&recovery, challenge, reason, 0)?;
    Ok(fixture_result_v0(
        config,
        NativeValidationRecoveryTestFixtureStateV0::CallbackPending,
        reason,
        callback_facts,
    ))
}

/// Advances the sole P job to Delivered (D), or exact-reloads an already-D
/// job, using the real Core persistence request that completed the challenge.
pub fn advance_native_validation_recovery_test_fixture_to_delivered_v0(
    config: &NativeValidationRecoveryTestFixtureConfigV0,
    challenge: &PayloadValidationRecoveryChallengeV0,
    persistence: &SafetyStatePersistenceV0,
) -> Result<NativeValidationRecoveryTestFixtureV0, NativeValidationRecoveryTestFixtureErrorV0> {
    validate_completion_request_v0(challenge, persistence)?;
    let mut recovery = open_single_active_fixture_v0(config)?;
    reconcile_exact_challenge_v0(&mut recovery, challenge)?;
    let callback_facts = recovery
        .record_recovered_core_acceptance_v0(persistence)
        .map_err(NativeValidationRecoveryTestFixtureErrorV0::RecoveryTransition)?;
    if callback_facts.route() != challenge.route()
        || callback_facts.validation_id() != challenge.id()
        || callback_facts.delivery_attempt() != 1
        || recovery.active_recovery_job_count_v0() != 1
        || recovery.acked_history_job_count_v0() != 0
    {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::UnexpectedFixtureState);
    }
    Ok(fixture_result_v0(
        config,
        NativeValidationRecoveryTestFixtureStateV0::Delivered,
        callback_facts.reason(),
        callback_facts,
    ))
}

fn database_path_for_status_v0(status_path: &Path) -> PathBuf {
    let extension = status_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.sqlite3"))
        .unwrap_or_else(|| "sqlite3".to_string());
    status_path.with_extension(extension)
}

fn require_absent_v0(path: &Path) -> Result<(), NativeValidationRecoveryTestFixtureErrorV0> {
    match path.symlink_metadata() {
        Ok(_) => Err(NativeValidationRecoveryTestFixtureErrorV0::NamespaceAlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(NativeValidationRecoveryTestFixtureErrorV0::NamespaceMetadataUnavailable),
    }
}

fn validate_challenge_revision_v0(
    challenge: &PayloadValidationRecoveryChallengeV0,
) -> Result<(), NativeValidationRecoveryTestFixtureErrorV0> {
    if challenge.first_recorded_revision() == 0
        || challenge.first_recorded_revision() != challenge.id().generation()
        || challenge.first_recorded_revision() > challenge.safety_head_revision()
    {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::ChallengeRevisionMismatch);
    }
    Ok(())
}

fn validate_completion_request_v0(
    challenge: &PayloadValidationRecoveryChallengeV0,
    persistence: &SafetyStatePersistenceV0,
) -> Result<(), NativeValidationRecoveryTestFixtureErrorV0> {
    validate_challenge_revision_v0(challenge)?;
    let expected_revision = challenge
        .safety_head_revision()
        .checked_add(1)
        .ok_or(NativeValidationRecoveryTestFixtureErrorV0::PersistenceRevisionMismatch)?;
    if persistence.state().revision() != expected_revision {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::PersistenceRevisionMismatch);
    }
    Ok(())
}

fn recovery_config_v0(
    config: &NativeValidationRecoveryTestFixtureConfigV0,
) -> NativeValidationRecoveryStoreConfigV0 {
    NativeValidationRecoveryStoreConfigV0::new(
        config.status_path().to_path_buf(),
        config.chain_id(),
        config.signer_policy_hash(),
        config.expected_safety_journal_id(),
        config.expected_safety_verifier_profile_ref(),
    )
}

fn open_single_active_fixture_v0(
    config: &NativeValidationRecoveryTestFixtureConfigV0,
) -> Result<NativeValidationRecoveryStoreV0, NativeValidationRecoveryTestFixtureErrorV0> {
    let recovery = NativeValidationRecoveryStoreV0::open_existing_v8(recovery_config_v0(config))
        .map_err(NativeValidationRecoveryTestFixtureErrorV0::RecoveryOpen)?;
    if recovery.supported_recovery_job_count_v0() != 1
        || recovery.active_recovery_job_count_v0() != 1
        || recovery.acked_history_job_count_v0() != 0
    {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::UnexpectedFixtureState);
    }
    Ok(recovery)
}

fn reconcile_exact_challenge_v0(
    recovery: &mut NativeValidationRecoveryStoreV0,
    challenge: &PayloadValidationRecoveryChallengeV0,
) -> Result<(), NativeValidationRecoveryTestFixtureErrorV0> {
    if recovery.reconcile_deterministically_invalid_obligation_v0(challenge)
        != PayloadValidationRecoveryDecisionV0::AcceptDeterministicallyInvalid
    {
        return Err(
            NativeValidationRecoveryTestFixtureErrorV0::RecoveryReconcile(
                recovery
                    .last_reconcile_failure_v0()
                    .unwrap_or(NativeValidationRecoveryReconcileFailureV0::StoreIntegrity),
            ),
        );
    }
    Ok(())
}

fn exact_callback_facts_v0(
    recovery: &NativeValidationRecoveryStoreV0,
    challenge: &PayloadValidationRecoveryChallengeV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
    delivery_attempt: u64,
) -> Result<
    NativeValidationRecoveredInvalidCallbackFactsV0,
    NativeValidationRecoveryTestFixtureErrorV0,
> {
    let facts = recovery
        .recovered_obligation_callback_facts_v0()
        .ok_or(NativeValidationRecoveryTestFixtureErrorV0::UnexpectedFixtureState)?;
    if facts.route() != challenge.route()
        || facts.validation_id() != challenge.id()
        || facts.reason() != reason
        || facts.delivery_attempt() != delivery_attempt
    {
        return Err(NativeValidationRecoveryTestFixtureErrorV0::UnexpectedFixtureState);
    }
    Ok(facts)
}

fn durable_reason_v0(
    reason: NativeValidationRecoveredInvalidReasonV0,
) -> DurableDeterministicInvalidReasonV0 {
    match reason {
        NativeValidationRecoveredInvalidReasonV0::ComputedStateRootMismatch => {
            DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch
        }
        NativeValidationRecoveredInvalidReasonV0::ComputedReceiptsRootMismatch => {
            DurableDeterministicInvalidReasonV0::ComputedReceiptsRootMismatch
        }
    }
}

fn fixture_result_v0(
    config: &NativeValidationRecoveryTestFixtureConfigV0,
    state: NativeValidationRecoveryTestFixtureStateV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
    callback_facts: NativeValidationRecoveredInvalidCallbackFactsV0,
) -> NativeValidationRecoveryTestFixtureV0 {
    NativeValidationRecoveryTestFixtureV0 {
        status_path: config.status_path().to_path_buf(),
        database_path: config.database_path().to_path_buf(),
        state,
        route: callback_facts.route(),
        validation_id: callback_facts.validation_id(),
        reason,
        callback_facts,
    }
}
