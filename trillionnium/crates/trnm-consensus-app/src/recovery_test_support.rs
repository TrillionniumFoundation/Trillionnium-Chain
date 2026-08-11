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

use trnm_consensus_core::{
    PayloadValidationRecoveryChallengeV0, PayloadValidationRecoveryDecisionV0,
    PayloadValidationRecoveryReconcilerV0, PayloadValidationRouteV0, SafetyStatePersistenceV0,
    ValidationId,
};
use trnm_consensus_types::ChainId;

use crate::{
    native_payload_validation::prepare_recovery_test_durable_invalid_v0,
    native_validation_artifact::DurableDeterministicInvalidReasonV0,
    store::{
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
};

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
        Err(_) => return Err(NativeValidationRecoveryTestFixtureErrorV0::ReservationFailed),
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
