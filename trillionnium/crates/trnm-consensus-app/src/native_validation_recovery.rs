//! Narrow, owner-bound recovery facade for deterministic-invalid validation.
//!
//! This module deliberately does not publish `ApplicationStore`, reservation
//! tokens, prepared execution owners, or detached transition parts.  It opens
//! only an existing schema-v8 store, deeply revalidates the complete local
//! journal, and retains every recovered state owner behind one non-`Clone`
//! facade.  Cross-database ordering remains the responsibility of the node
//! host: no SQLite transition in this module claims atomicity with a Core
//! SafetyState store. The facade exclusively owns the shared ApplicationStore
//! sidecar lock and pins the parent, lock, and main-database identities for its
//! complete lifetime. SQLite WAL/SHM files remain SQLite-managed auxiliary
//! state: V0 rejects unsafe existing auxiliary files and authenticates their
//! contents through SQLite recovery, but does not independently pin their
//! inodes. The fixed SafetyStore binding prevents a later startup from
//! nominating a different journal; it does not detect rollback or cloning of
//! the complete application/SafetyStore namespace.

use std::{
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    os::unix::fs::{FileExt as UnixFileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use rusqlite::{params, TransactionBehavior};
use trnm_consensus_core::{
    DurablePayloadValidationResultV1, PayloadTerminalResult, PayloadValidationParentV0,
    PayloadValidationRecoveryChallengeV0, PayloadValidationRecoveryDecisionV0,
    PayloadValidationRecoveryReconcilerV0, PayloadValidationRouteV0, SafetyState,
    SafetyStatePersistenceV0, ValidationId,
};
use trnm_consensus_safety_store::{
    ConfirmedNativeDeterministicInvalidHeadV0, NativeDeterministicInvalidTransitionV0,
};
use trnm_consensus_types::{Block, ChainId};

use super::*;

const NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_MAGIC_V0: [u8; 8] = *b"TRNMASB0";
const NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_SCHEMA_V0: u32 = 0;
const NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_DOMAIN_V0: &str =
    "trnm.application.native-validation.safety-binding-manifest.v0";
const NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0: usize = 8 + 4 + (32 * 4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeValidationSafetyBindingManifestV0 {
    application_host_config_ref: [u8; 32],
    safety_journal_id: [u8; 32],
    safety_verifier_profile_ref: [u8; 32],
}

impl NativeValidationSafetyBindingManifestV0 {
    fn new_v0(
        application_host_config_ref: [u8; 32],
        safety_journal_id: [u8; 32],
        safety_verifier_profile_ref: [u8; 32],
    ) -> Result<Self, NativeValidationRecoveryOpenFailureV0> {
        if application_host_config_ref == [0; 32]
            || safety_journal_id == [0; 32]
            || safety_verifier_profile_ref == [0; 32]
        {
            return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyProvenance);
        }
        Ok(Self {
            application_host_config_ref,
            safety_journal_id,
            safety_verifier_profile_ref,
        })
    }

    fn encode_v0(self) -> [u8; NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0] {
        let schema = NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_SCHEMA_V0.to_be_bytes();
        let checksum = hash_domain(
            NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_DOMAIN_V0,
            &[
                &NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_MAGIC_V0,
                &schema,
                &self.application_host_config_ref,
                &self.safety_journal_id,
                &self.safety_verifier_profile_ref,
            ],
        );
        let mut bytes = [0_u8; NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0];
        bytes[..8].copy_from_slice(&NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_MAGIC_V0);
        bytes[8..12].copy_from_slice(&schema);
        bytes[12..44].copy_from_slice(&self.application_host_config_ref);
        bytes[44..76].copy_from_slice(&self.safety_journal_id);
        bytes[76..108].copy_from_slice(&self.safety_verifier_profile_ref);
        bytes[108..140].copy_from_slice(&checksum);
        bytes
    }

    fn decode_exact_v0(bytes: &[u8]) -> Result<Self, NativeValidationRecoveryOpenFailureV0> {
        if bytes.len() != NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0
            || bytes[..8] != NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_MAGIC_V0
            || bytes[8..12] != NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_SCHEMA_V0.to_be_bytes()
        {
            return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding);
        }
        let mut application_host_config_ref = [0_u8; 32];
        application_host_config_ref.copy_from_slice(&bytes[12..44]);
        let mut safety_journal_id = [0_u8; 32];
        safety_journal_id.copy_from_slice(&bytes[44..76]);
        let mut safety_verifier_profile_ref = [0_u8; 32];
        safety_verifier_profile_ref.copy_from_slice(&bytes[76..108]);
        let manifest = Self::new_v0(
            application_host_config_ref,
            safety_journal_id,
            safety_verifier_profile_ref,
        )?;
        if manifest.encode_v0().as_slice() != bytes {
            return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding);
        }
        Ok(manifest)
    }
}

/// Typed configuration for the recovery-only ApplicationStore owner.
///
/// The signer-policy digest is accepted as bytes and encoded internally; the
/// facade never accepts the detached hexadecimal database binding used by the
/// legacy application constructor.
#[derive(Debug)]
pub struct NativeValidationRecoveryStoreConfigV0 {
    status_path: PathBuf,
    chain_id: ChainId,
    signer_policy_hash: [u8; 32],
    expected_safety_journal_id: [u8; 32],
    expected_safety_verifier_profile_ref: [u8; 32],
}

impl NativeValidationRecoveryStoreConfigV0 {
    pub fn new(
        status_path: impl Into<PathBuf>,
        chain_id: ChainId,
        signer_policy_hash: [u8; 32],
        expected_safety_journal_id: [u8; 32],
        expected_safety_verifier_profile_ref: [u8; 32],
    ) -> Self {
        Self {
            status_path: status_path.into(),
            chain_id,
            signer_policy_hash,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationRecoveryUnsupportedV0 {
    Reserved,
    Evaluated,
    Applied,
    Valid,
    Unavailable,
    UnknownState,
    UnknownResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationRecoveryOpenFailureV0 {
    StatusPathNotAbsolute,
    ParentUnavailable,
    MissingDatabase,
    DatabaseIsNotRegularFile,
    MissingSafetyBinding,
    InvalidSafetyBinding,
    Locked,
    UnsafeNamespace,
    NamespaceChanged,
    ProcessChanged,
    InvalidSafetyProvenance,
    UnsupportedSchema,
    UnsupportedJob(NativeValidationRecoveryUnsupportedV0),
    DuplicateIdentity,
    DatabaseUnavailable,
    HostResourceUnavailable,
    AuthenticatedGenesisApplicationActivationUnavailable,
    Integrity,
}

impl fmt::Display for NativeValidationRecoveryOpenFailureV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StatusPathNotAbsolute => "validation recovery status path is not absolute",
            Self::ParentUnavailable => "validation recovery namespace parent is unavailable",
            Self::MissingDatabase => "validation recovery database is missing",
            Self::DatabaseIsNotRegularFile => {
                "validation recovery database is not a regular non-symlink file"
            }
            Self::MissingSafetyBinding => {
                "validation recovery SafetyStore binding manifest is missing"
            }
            Self::InvalidSafetyBinding => {
                "validation recovery SafetyStore binding manifest is invalid"
            }
            Self::Locked => "validation recovery namespace already has a live owner",
            Self::UnsafeNamespace => "validation recovery namespace ownership or mode is unsafe",
            Self::NamespaceChanged => "validation recovery namespace identity changed",
            Self::ProcessChanged => "validation recovery owner crossed a process boundary",
            Self::InvalidSafetyProvenance => {
                "validation recovery expected SafetyStore provenance is invalid"
            }
            Self::UnsupportedSchema => "validation recovery requires exact schema v8",
            Self::UnsupportedJob(_) => "validation recovery found an unsupported job state",
            Self::DuplicateIdentity => "validation recovery found a duplicate full identity",
            Self::DatabaseUnavailable => "validation recovery database is unavailable",
            Self::HostResourceUnavailable => {
                "validation recovery host resources are temporarily unavailable"
            }
            Self::AuthenticatedGenesisApplicationActivationUnavailable => {
                "authenticated-genesis application requires its dedicated inert bootstrap owner"
            }
            Self::Integrity => "validation recovery database integrity validation failed",
        })
    }
}

impl Error for NativeValidationRecoveryOpenFailureV0 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationRecoveryReconcileFailureV0 {
    AlreadyReconciled,
    Missing,
    Duplicate,
    Reserved,
    Evaluated,
    Acked,
    Applied,
    Valid,
    Unavailable,
    ChallengeRevisionMismatch,
    ChallengeRequestMalformed,
    ChallengeFactsMismatch,
    NamespaceChanged,
    ProcessChanged,
    ActiveSetMismatch,
    StoreUnavailable,
    StoreIntegrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationRecoveryTransitionFailureV0 {
    MissingOwner,
    WrongOwnerState,
    IssuingStoreMismatch,
    SafetyConfigurationMismatch,
    SafetyCompletionMissingOrAmbiguous,
    SafetyCompletionMismatch,
    SafetyTerminalFactMismatch,
    SafetyProvenanceMismatch,
    PersistenceRevisionMismatch,
    NamespaceChanged,
    ProcessChanged,
    ActiveSetMismatch,
    StoreUnavailable,
    StoreIntegrity,
    DeliveryAttemptOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationRecoveredInvalidReasonV0 {
    ComputedStateRootMismatch,
    ComputedReceiptsRootMismatch,
}

impl NativeValidationRecoveredInvalidReasonV0 {
    pub const fn code_v0(self) -> u32 {
        match self {
            Self::ComputedStateRootMismatch => 1,
            Self::ComputedReceiptsRootMismatch => 2,
        }
    }
}

impl From<DurableDeterministicInvalidReasonV0> for NativeValidationRecoveredInvalidReasonV0 {
    fn from(reason: DurableDeterministicInvalidReasonV0) -> Self {
        match reason {
            DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch => {
                Self::ComputedStateRootMismatch
            }
            DurableDeterministicInvalidReasonV0::ComputedReceiptsRootMismatch => {
                Self::ComputedReceiptsRootMismatch
            }
        }
    }
}

/// Test-only compatibility projection. Production and feature builds accept
/// only the concrete non-forgeable SafetyStore token.
#[cfg(test)]
pub(crate) trait NativeValidationConfirmedInvalidTransitionV0 {
    fn route_v0(&self) -> PayloadValidationRouteV0;
    fn validation_id_v0(&self) -> ValidationId;
    fn request_fingerprint_v0(&self) -> [u8; 32];
    fn job_immutable_checksum_v0(&self) -> [u8; 32];
    fn application_host_config_ref_v0(&self) -> [u8; 32];
    fn reason_code_v0(&self) -> u32;
    fn artifact_checksum_v0(&self) -> [u8; 32];
    fn callback_payload_checksum_v0(&self) -> [u8; 32];
    fn idempotency_key_v0(&self) -> [u8; 32];
    fn delivery_attempt_v0(&self) -> u64;
    fn delivered_job_row_checksum_v0(&self) -> [u8; 32];
    fn outbox_checksum_v0(&self) -> [u8; 32];
    fn completion_revision_v0(&self) -> u64;
}

trait NativeValidationConfirmedInvalidViewV0 {
    fn route_v0(&self) -> PayloadValidationRouteV0;
    fn validation_id_v0(&self) -> ValidationId;
    fn request_fingerprint_v0(&self) -> [u8; 32];
    fn job_immutable_checksum_v0(&self) -> [u8; 32];
    fn application_host_config_ref_v0(&self) -> [u8; 32];
    fn reason_code_v0(&self) -> u32;
    fn artifact_checksum_v0(&self) -> [u8; 32];
    fn callback_payload_checksum_v0(&self) -> [u8; 32];
    fn idempotency_key_v0(&self) -> [u8; 32];
    fn delivery_attempt_v0(&self) -> u64;
    fn delivered_job_row_checksum_v0(&self) -> [u8; 32];
    fn outbox_checksum_v0(&self) -> [u8; 32];
    fn completion_revision_v0(&self) -> u64;
}

impl NativeValidationConfirmedInvalidViewV0 for ConfirmedNativeDeterministicInvalidHeadV0 {
    fn route_v0(&self) -> PayloadValidationRouteV0 {
        self.transition().route()
    }

    fn validation_id_v0(&self) -> ValidationId {
        self.transition().validation_id()
    }

    fn request_fingerprint_v0(&self) -> [u8; 32] {
        self.transition().request_fingerprint()
    }

    fn job_immutable_checksum_v0(&self) -> [u8; 32] {
        self.transition().job_immutable_checksum()
    }

    fn application_host_config_ref_v0(&self) -> [u8; 32] {
        self.transition().application_host_config_ref()
    }

    fn reason_code_v0(&self) -> u32 {
        self.transition().reason_code()
    }

    fn artifact_checksum_v0(&self) -> [u8; 32] {
        self.transition().artifact_checksum()
    }

    fn callback_payload_checksum_v0(&self) -> [u8; 32] {
        self.transition().callback_payload_checksum()
    }

    fn idempotency_key_v0(&self) -> [u8; 32] {
        self.transition().idempotency_key()
    }

    fn delivery_attempt_v0(&self) -> u64 {
        self.transition().delivery_attempt()
    }

    fn delivered_job_row_checksum_v0(&self) -> [u8; 32] {
        self.transition().delivered_job_row_checksum()
    }

    fn outbox_checksum_v0(&self) -> [u8; 32] {
        self.transition().outbox_checksum()
    }

    fn completion_revision_v0(&self) -> u64 {
        self.transition().completion_revision()
    }
}

#[cfg(test)]
impl<T: NativeValidationConfirmedInvalidTransitionV0> NativeValidationConfirmedInvalidViewV0 for T {
    fn route_v0(&self) -> PayloadValidationRouteV0 {
        NativeValidationConfirmedInvalidTransitionV0::route_v0(self)
    }

    fn validation_id_v0(&self) -> ValidationId {
        NativeValidationConfirmedInvalidTransitionV0::validation_id_v0(self)
    }

    fn request_fingerprint_v0(&self) -> [u8; 32] {
        NativeValidationConfirmedInvalidTransitionV0::request_fingerprint_v0(self)
    }

    fn job_immutable_checksum_v0(&self) -> [u8; 32] {
        NativeValidationConfirmedInvalidTransitionV0::job_immutable_checksum_v0(self)
    }

    fn application_host_config_ref_v0(&self) -> [u8; 32] {
        NativeValidationConfirmedInvalidTransitionV0::application_host_config_ref_v0(self)
    }

    fn reason_code_v0(&self) -> u32 {
        NativeValidationConfirmedInvalidTransitionV0::reason_code_v0(self)
    }

    fn artifact_checksum_v0(&self) -> [u8; 32] {
        NativeValidationConfirmedInvalidTransitionV0::artifact_checksum_v0(self)
    }

    fn callback_payload_checksum_v0(&self) -> [u8; 32] {
        NativeValidationConfirmedInvalidTransitionV0::callback_payload_checksum_v0(self)
    }

    fn idempotency_key_v0(&self) -> [u8; 32] {
        NativeValidationConfirmedInvalidTransitionV0::idempotency_key_v0(self)
    }

    fn delivery_attempt_v0(&self) -> u64 {
        NativeValidationConfirmedInvalidTransitionV0::delivery_attempt_v0(self)
    }

    fn delivered_job_row_checksum_v0(&self) -> [u8; 32] {
        NativeValidationConfirmedInvalidTransitionV0::delivered_job_row_checksum_v0(self)
    }

    fn outbox_checksum_v0(&self) -> [u8; 32] {
        NativeValidationConfirmedInvalidTransitionV0::outbox_checksum_v0(self)
    }

    fn completion_revision_v0(&self) -> u64 {
        NativeValidationConfirmedInvalidTransitionV0::completion_revision_v0(self)
    }
}

/// Complete, inert facts for one deeply verified callback row.
///
/// These values permit an exact Core/SafetyStore comparison but grant no
/// transition authority.  The authority stays in the facade's private owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeValidationRecoveredInvalidCallbackFactsV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    reason: NativeValidationRecoveredInvalidReasonV0,
    request_fingerprint: [u8; 32],
    immutable_checksum: [u8; 32],
    host_config_ref: [u8; 32],
    artifact_checksum: [u8; 32],
    callback_payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
    row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
}

impl NativeValidationRecoveredInvalidCallbackFactsV0 {
    pub const fn route(self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id(self) -> ValidationId {
        self.validation_id
    }

    pub const fn reason(self) -> NativeValidationRecoveredInvalidReasonV0 {
        self.reason
    }

    pub const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub const fn immutable_checksum(self) -> [u8; 32] {
        self.immutable_checksum
    }

    pub const fn host_config_ref(self) -> [u8; 32] {
        self.host_config_ref
    }

    pub const fn artifact_checksum(self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub const fn callback_payload_checksum(self) -> [u8; 32] {
        self.callback_payload_checksum
    }

    pub const fn idempotency_key(self) -> [u8; 32] {
        self.idempotency_key
    }

    pub const fn delivery_attempt(self) -> u64 {
        self.delivery_attempt
    }

    pub const fn row_checksum(self) -> [u8; 32] {
        self.row_checksum
    }

    pub const fn outbox_checksum(self) -> [u8; 32] {
        self.outbox_checksum
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationRecoveredInvalidStateV0 {
    CallbackPending,
    Delivered,
    Acked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeValidationRecoveredAckedFactsV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    reason: NativeValidationRecoveredInvalidReasonV0,
    request_fingerprint: [u8; 32],
    immutable_checksum: [u8; 32],
    host_config_ref: [u8; 32],
    artifact_checksum: [u8; 32],
    callback_payload_checksum: [u8; 32],
    accepted_core_revision: u64,
    predecessor_idempotency_key: [u8; 32],
    predecessor_delivery_attempt: u64,
    predecessor_delivered_row_checksum: [u8; 32],
    predecessor_outbox_checksum: [u8; 32],
    row_checksum: [u8; 32],
}

impl NativeValidationRecoveredAckedFactsV0 {
    pub const fn route(self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id(self) -> ValidationId {
        self.validation_id
    }

    pub const fn reason(self) -> NativeValidationRecoveredInvalidReasonV0 {
        self.reason
    }

    pub const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub const fn immutable_checksum(self) -> [u8; 32] {
        self.immutable_checksum
    }

    pub const fn host_config_ref(self) -> [u8; 32] {
        self.host_config_ref
    }

    pub const fn artifact_checksum(self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub const fn callback_payload_checksum(self) -> [u8; 32] {
        self.callback_payload_checksum
    }

    pub const fn accepted_core_revision(self) -> u64 {
        self.accepted_core_revision
    }

    pub const fn predecessor_idempotency_key(self) -> [u8; 32] {
        self.predecessor_idempotency_key
    }

    pub const fn predecessor_delivery_attempt(self) -> u64 {
        self.predecessor_delivery_attempt
    }

    pub const fn predecessor_delivered_row_checksum(self) -> [u8; 32] {
        self.predecessor_delivered_row_checksum
    }

    pub const fn predecessor_outbox_checksum(self) -> [u8; 32] {
        self.predecessor_outbox_checksum
    }

    pub const fn row_checksum(self) -> [u8; 32] {
        self.row_checksum
    }
}

struct RecoveredCallbackPendingInvalidV0 {
    verified: VerifiedNativeValidationInvalidCallbackV0,
    issuing_writer_gate: Arc<Mutex<()>>,
}

struct RecoveredDeliveredInvalidV0 {
    verified: VerifiedNativeValidationInvalidCallbackV0,
    issuing_writer_gate: Arc<Mutex<()>>,
}

struct RecoveredAckedInvalidV0 {
    durable: Box<DurableNativeValidationJobV0>,
    issuing_writer_gate: Arc<Mutex<()>>,
}

enum RecoveredObligationInvalidV0 {
    CallbackPending(Box<RecoveredCallbackPendingInvalidV0>),
    Delivered(Box<RecoveredDeliveredInvalidV0>),
}

enum RecoveredCompletionInvalidV0 {
    Delivered(Box<RecoveredDeliveredInvalidV0>),
    Acked(Box<RecoveredAckedInvalidV0>),
}

/// The only public owner of this recovery slice.
///
/// It is intentionally non-`Clone`, does not expose `ApplicationStore`, and
/// may bind at most one Core obligation and one confirmed completion at a
/// time.  Reconciliation failures are retained as typed read-only state.
#[must_use = "the validation recovery store owns recovered journal authority"]
pub struct NativeValidationRecoveryStoreV0 {
    store: ApplicationStore,
    namespace_pin: NativeValidationRecoveryNamespacePinV0,
    coordinator: NativeValidationRecoveryCoordinatorV0,
}

/// Store-less owner of deterministic-invalid recovery state.
///
/// The coordinator deliberately owns neither the application database nor its
/// namespace pin.  Every operation receives both as borrowed authorities, so
/// a wider application host can retain one exclusive store owner while using
/// the same deterministic-invalid reconciliation machinery.  It is
/// intentionally non-`Clone` and never exposes recovered callback owners.
#[must_use = "the recovery coordinator owns recovered callback authority"]
pub(crate) struct NativeValidationRecoveryCoordinatorV0 {
    expected_safety_journal_id: [u8; 32],
    expected_safety_verifier_profile_ref: [u8; 32],
    coexisting_native_history: bool,
    supported_job_count: usize,
    active_recovery_job_count: usize,
    acked_history_job_count: usize,
    audited_active_jobs: Vec<NativeValidationRecoveryActiveJobV0>,
    obligation: Option<RecoveredObligationInvalidV0>,
    completion: Option<RecoveredCompletionInvalidV0>,
    reconciled_safety_head_revision: Option<u64>,
    last_reconcile_failure: Option<NativeValidationRecoveryReconcileFailureV0>,
}

struct NativeValidationRecoveryBorrowedV0<'a> {
    coordinator: &'a mut NativeValidationRecoveryCoordinatorV0,
    store: &'a ApplicationStore,
    namespace_pin: &'a NativeValidationRecoveryNamespacePinV0,
}

impl std::ops::Deref for NativeValidationRecoveryBorrowedV0<'_> {
    type Target = NativeValidationRecoveryCoordinatorV0;

    fn deref(&self) -> &Self::Target {
        self.coordinator
    }
}

impl std::ops::DerefMut for NativeValidationRecoveryBorrowedV0<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.coordinator
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NativeValidationRecoveryActiveJobV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    state: NativeValidationJobStateV0,
    row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
}

pub(crate) fn native_validation_safety_binding_manifest_path_v0(
    database_path: &Path,
) -> Result<PathBuf, NativeValidationRecoveryOpenFailureV0> {
    let mut file_name = database_path
        .file_name()
        .ok_or(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding)?
        .to_os_string();
    file_name.push(".safety-binding-v0");
    Ok(database_path.with_file_name(file_name))
}

fn read_native_validation_safety_binding_manifest_bytes_v0(
    handle: &File,
) -> Result<
    [u8; NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0],
    NativeValidationRecoveryOpenFailureV0,
> {
    let mut bytes = [0_u8; NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let read = handle
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|_| NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding)?;
        if read == 0 {
            return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding);
        }
        offset = offset
            .checked_add(read)
            .ok_or(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding)?;
    }
    let mut trailing = [0_u8; 1];
    if handle
        .read_at(&mut trailing, bytes.len() as u64)
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding)?
        != 0
    {
        return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding);
    }
    Ok(bytes)
}

fn validate_native_validation_safety_binding_manifest_file_v0(
    path: &Path,
    handle: &File,
    expected_owner_uid: u32,
) -> Result<ApplicationStoreFileIdentityV0, NativeValidationRecoveryOpenFailureV0> {
    let handle_metadata = handle
        .metadata()
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding)?;
    let path_metadata = path
        .symlink_metadata()
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => {
                NativeValidationRecoveryOpenFailureV0::MissingSafetyBinding
            }
            _ => NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding,
        })?;
    let handle_identity = ApplicationStoreFileIdentityV0::from_metadata(&handle_metadata);
    if !handle_metadata.is_file()
        || !path_metadata.file_type().is_file()
        || path_metadata.file_type().is_symlink()
        || handle_metadata.nlink() != 1
        || path_metadata.nlink() != 1
        || handle_metadata.uid() != expected_owner_uid
        || path_metadata.uid() != expected_owner_uid
        || handle_metadata.mode() & 0o777 != 0o600
        || path_metadata.mode() & 0o777 != 0o600
        || handle_metadata.len() as usize != NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0
        || path_metadata.len() as usize != NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0
        || handle_identity != ApplicationStoreFileIdentityV0::from_metadata(&path_metadata)
    {
        return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding);
    }
    Ok(handle_identity)
}

struct NativeValidationSafetyBindingManifestPinV0 {
    path: PathBuf,
    handle: File,
    identity: ApplicationStoreFileIdentityV0,
    bytes: [u8; NATIVE_VALIDATION_SAFETY_BINDING_MANIFEST_BYTES_V0],
    manifest: NativeValidationSafetyBindingManifestV0,
}

fn open_and_pin_native_validation_safety_binding_manifest_v0(
    store: &ApplicationStore,
) -> Result<NativeValidationSafetyBindingManifestPinV0, NativeValidationRecoveryOpenFailureV0> {
    store
        .validate_secure_native_validation_recovery_namespace_v0()
        .map_err(map_namespace_open_failure_v0)?;
    let path = native_validation_safety_binding_manifest_path_v0(&store.database_path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let handle = options.open(&path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => NativeValidationRecoveryOpenFailureV0::MissingSafetyBinding,
        _ => NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding,
    })?;
    let identity = validate_native_validation_safety_binding_manifest_file_v0(
        &path,
        &handle,
        store.namespace_owner.parent_uid,
    )?;
    let bytes = read_native_validation_safety_binding_manifest_bytes_v0(&handle)?;
    let manifest = NativeValidationSafetyBindingManifestV0::decode_exact_v0(&bytes)?;
    if manifest.application_host_config_ref != native_validation_host_config_ref_v0(store) {
        return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding);
    }
    store
        .validate_secure_native_validation_recovery_namespace_v0()
        .map_err(map_namespace_open_failure_v0)?;
    Ok(NativeValidationSafetyBindingManifestPinV0 {
        path,
        handle,
        identity,
        bytes,
        manifest,
    })
}

#[cfg(any(test, feature = "recovery-test-support"))]
pub(crate) fn bootstrap_native_validation_safety_binding_manifest_v0(
    store: &ApplicationStore,
    safety_journal_id: [u8; 32],
    safety_verifier_profile_ref: [u8; 32],
) -> Result<(), NativeValidationRecoveryOpenFailureV0> {
    store
        .validate_secure_native_validation_recovery_namespace_v0()
        .map_err(map_namespace_open_failure_v0)?;
    let connection = store
        .connect_read()
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?;
    if metadata(&connection, "schema_version")
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?
        != STORE_SCHEMA_VERSION
    {
        return Err(NativeValidationRecoveryOpenFailureV0::UnsupportedSchema);
    }
    let job_count = connection
        .query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
            row.get::<_, u64>(0)
        })
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?;
    let outbox_count = connection
        .query_row(
            "SELECT COUNT(*) FROM validation_callback_outbox_v0",
            [],
            |row| row.get::<_, u64>(0),
        )
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?;
    if job_count != 0 || outbox_count != 0 {
        return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding);
    }
    drop(connection);
    let manifest = NativeValidationSafetyBindingManifestV0::new_v0(
        native_validation_host_config_ref_v0(store),
        safety_journal_id,
        safety_verifier_profile_ref,
    )?;
    let bytes = manifest.encode_v0();
    let path = native_validation_safety_binding_manifest_path_v0(&store.database_path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut handle = options
        .open(&path)
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding)?;
    std::io::Write::write_all(&mut handle, &bytes)
        .and_then(|()| handle.sync_all())
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding)?;
    validate_native_validation_safety_binding_manifest_file_v0(
        &path,
        &handle,
        store.namespace_owner.parent_uid,
    )?;
    if read_native_validation_safety_binding_manifest_bytes_v0(&handle)? != bytes {
        return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding);
    }
    store
        .namespace_owner
        .parent_handle
        .sync_all()
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::InvalidSafetyBinding)?;
    store
        .validate_secure_native_validation_recovery_namespace_v0()
        .map_err(map_namespace_open_failure_v0)?;
    Ok(())
}

pub(crate) struct NativeValidationRecoveryNamespacePinV0 {
    owner_pid: u32,
    canonical_parent: PathBuf,
    parent_handle: File,
    parent_identity: ApplicationStoreFileIdentityV0,
    database_path: PathBuf,
    database_handle: File,
    database_identity: ApplicationStoreFileIdentityV0,
    lock_path: PathBuf,
    lock_identity: ApplicationStoreFileIdentityV0,
    safety_binding: NativeValidationSafetyBindingManifestPinV0,
}

impl NativeValidationRecoveryNamespacePinV0 {
    pub(crate) fn capture(
        store: &ApplicationStore,
    ) -> Result<Self, NativeValidationRecoveryOpenFailureV0> {
        store
            .validate_namespace_owner_v0()
            .map_err(map_namespace_open_failure_v0)?;
        if store.namespace_owner.mode != ApplicationStoreOwnerModeV0::RecoveryExclusive {
            return Err(NativeValidationRecoveryOpenFailureV0::Locked);
        }
        let safety_binding = open_and_pin_native_validation_safety_binding_manifest_v0(store)?;
        let parent_handle =
            open_application_store_parent_v0(store.namespace_owner.canonical_parent.as_path())
                .map_err(map_namespace_open_failure_v0)?;
        let mut database_options = OpenOptions::new();
        database_options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let database_handle = database_options
            .open(&store.database_path)
            .map_err(|_| NativeValidationRecoveryOpenFailureV0::NamespaceChanged)?;
        let parent_identity = ApplicationStoreFileIdentityV0::from_metadata(
            &parent_handle
                .metadata()
                .map_err(|_| NativeValidationRecoveryOpenFailureV0::NamespaceChanged)?,
        );
        let database_identity = ApplicationStoreFileIdentityV0::from_metadata(
            &database_handle
                .metadata()
                .map_err(|_| NativeValidationRecoveryOpenFailureV0::NamespaceChanged)?,
        );
        let pin = Self {
            owner_pid: std::process::id(),
            canonical_parent: store.namespace_owner.canonical_parent.clone(),
            parent_handle,
            parent_identity,
            database_path: store.database_path.clone(),
            database_handle,
            database_identity,
            lock_path: store.namespace_owner.lock_path.clone(),
            lock_identity: store.namespace_owner.lock_identity,
            safety_binding,
        };
        pin.validate_raw_v0(store)
            .map_err(map_namespace_open_failure_v0)?;
        Ok(pin)
    }

    pub(crate) fn validate_open_v0(
        &self,
        store: &ApplicationStore,
    ) -> Result<(), NativeValidationRecoveryOpenFailureV0> {
        self.validate_raw_v0(store)
            .map_err(map_namespace_open_failure_v0)
    }

    pub(crate) fn matches_safety_provenance_v0(
        &self,
        safety_journal_id: [u8; 32],
        safety_verifier_profile_ref: [u8; 32],
    ) -> bool {
        self.safety_binding.manifest.safety_journal_id == safety_journal_id
            && self.safety_binding.manifest.safety_verifier_profile_ref
                == safety_verifier_profile_ref
    }

    /// Commits to the exact, already decoded and lifetime-pinned canonical
    /// Safety binding bytes.  This is comparison material only: it does not
    /// recreate the manifest, relax the namespace pin, or grant SafetyStore
    /// authority.
    pub(crate) fn safety_binding_manifest_checksum_v0(&self) -> [u8; 32] {
        hash_domain(
            "trnm.application.native-validation.safety-binding-canonical-bytes.v0",
            &[&self.safety_binding.bytes],
        )
    }

    fn validate_reconcile_v0(
        &self,
        store: &ApplicationStore,
    ) -> Result<(), NativeValidationRecoveryReconcileFailureV0> {
        self.validate_raw_v0(store)
            .map_err(map_namespace_reconcile_failure_v0)
    }

    fn validate_transition_v0(
        &self,
        store: &ApplicationStore,
    ) -> Result<(), NativeValidationRecoveryTransitionFailureV0> {
        self.validate_raw_v0(store)
            .map_err(map_namespace_transition_failure_v0)
    }

    fn validate_raw_v0(
        &self,
        store: &ApplicationStore,
    ) -> Result<(), ApplicationStoreNamespaceOpenFailureV0> {
        if std::process::id() != self.owner_pid
            || std::process::id() != store.namespace_owner.owner_pid
        {
            return Err(ApplicationStoreNamespaceOpenFailureV0::ProcessChanged);
        }
        store.validate_namespace_owner_v0()?;
        store.validate_secure_native_validation_recovery_namespace_v0()?;
        if store.namespace_owner.mode != ApplicationStoreOwnerModeV0::RecoveryExclusive
            || store.status_path.parent() != Some(self.canonical_parent.as_path())
            || store.database_path != self.database_path
            || store.database_path.parent() != Some(self.canonical_parent.as_path())
            || store.namespace_owner.lock_path != self.lock_path
            || store.namespace_owner.lock_identity != self.lock_identity
        {
            return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
        }
        let parent_handle_metadata = self
            .parent_handle
            .metadata()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        let parent_path_metadata = self
            .canonical_parent
            .symlink_metadata()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        if !parent_handle_metadata.is_dir()
            || !parent_path_metadata.file_type().is_dir()
            || parent_path_metadata.file_type().is_symlink()
            || ApplicationStoreFileIdentityV0::from_metadata(&parent_handle_metadata)
                != self.parent_identity
            || ApplicationStoreFileIdentityV0::from_metadata(&parent_path_metadata)
                != self.parent_identity
            || self.parent_identity != store.namespace_owner.parent_identity
        {
            return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
        }
        let database_handle_metadata = self
            .database_handle
            .metadata()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        let database_path_metadata = self
            .database_path
            .symlink_metadata()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        if !database_handle_metadata.is_file()
            || !database_path_metadata.file_type().is_file()
            || database_path_metadata.file_type().is_symlink()
            || database_handle_metadata.nlink() != 1
            || database_path_metadata.nlink() != 1
            || database_handle_metadata.uid() != store.namespace_owner.parent_uid
            || database_path_metadata.uid() != store.namespace_owner.parent_uid
            || ApplicationStoreFileIdentityV0::from_metadata(&database_handle_metadata)
                != self.database_identity
            || ApplicationStoreFileIdentityV0::from_metadata(&database_path_metadata)
                != self.database_identity
        {
            return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
        }
        let lock_metadata = validate_application_store_lock_v0(
            &self.lock_path,
            &store.namespace_owner.lock_handle,
            store.namespace_owner.parent_uid,
        )?;
        if ApplicationStoreFileIdentityV0::from_metadata(&lock_metadata) != self.lock_identity {
            return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
        }
        let manifest_identity = validate_native_validation_safety_binding_manifest_file_v0(
            &self.safety_binding.path,
            &self.safety_binding.handle,
            store.namespace_owner.parent_uid,
        )
        .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        let manifest_bytes =
            read_native_validation_safety_binding_manifest_bytes_v0(&self.safety_binding.handle)
                .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        let manifest = NativeValidationSafetyBindingManifestV0::decode_exact_v0(&manifest_bytes)
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        if manifest_identity != self.safety_binding.identity
            || manifest_bytes != self.safety_binding.bytes
            || manifest != self.safety_binding.manifest
            || manifest.application_host_config_ref != native_validation_host_config_ref_v0(store)
        {
            return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
        }
        Ok(())
    }
}

fn map_namespace_open_failure_v0(
    failure: ApplicationStoreNamespaceOpenFailureV0,
) -> NativeValidationRecoveryOpenFailureV0 {
    match failure {
        ApplicationStoreNamespaceOpenFailureV0::ParentUnavailable => {
            NativeValidationRecoveryOpenFailureV0::ParentUnavailable
        }
        ApplicationStoreNamespaceOpenFailureV0::MissingDatabase => {
            NativeValidationRecoveryOpenFailureV0::MissingDatabase
        }
        ApplicationStoreNamespaceOpenFailureV0::DatabaseIsNotRegularFile => {
            NativeValidationRecoveryOpenFailureV0::DatabaseIsNotRegularFile
        }
        ApplicationStoreNamespaceOpenFailureV0::Locked => {
            NativeValidationRecoveryOpenFailureV0::Locked
        }
        ApplicationStoreNamespaceOpenFailureV0::UnsafeNamespace => {
            NativeValidationRecoveryOpenFailureV0::UnsafeNamespace
        }
        ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged => {
            NativeValidationRecoveryOpenFailureV0::NamespaceChanged
        }
        ApplicationStoreNamespaceOpenFailureV0::ProcessChanged => {
            NativeValidationRecoveryOpenFailureV0::ProcessChanged
        }
        ApplicationStoreNamespaceOpenFailureV0::
            AuthenticatedGenesisApplicationActivationUnavailable => {
                NativeValidationRecoveryOpenFailureV0::
                    AuthenticatedGenesisApplicationActivationUnavailable
            }
        ApplicationStoreNamespaceOpenFailureV0::InvalidPath
        | ApplicationStoreNamespaceOpenFailureV0::Io => {
            NativeValidationRecoveryOpenFailureV0::Integrity
        }
    }
}

fn map_namespace_reconcile_failure_v0(
    failure: ApplicationStoreNamespaceOpenFailureV0,
) -> NativeValidationRecoveryReconcileFailureV0 {
    match failure {
        ApplicationStoreNamespaceOpenFailureV0::ProcessChanged => {
            NativeValidationRecoveryReconcileFailureV0::ProcessChanged
        }
        ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged
        | ApplicationStoreNamespaceOpenFailureV0::UnsafeNamespace
        | ApplicationStoreNamespaceOpenFailureV0::MissingDatabase
        | ApplicationStoreNamespaceOpenFailureV0::DatabaseIsNotRegularFile => {
            NativeValidationRecoveryReconcileFailureV0::NamespaceChanged
        }
        _ => NativeValidationRecoveryReconcileFailureV0::StoreUnavailable,
    }
}

fn map_namespace_transition_failure_v0(
    failure: ApplicationStoreNamespaceOpenFailureV0,
) -> NativeValidationRecoveryTransitionFailureV0 {
    match failure {
        ApplicationStoreNamespaceOpenFailureV0::ProcessChanged => {
            NativeValidationRecoveryTransitionFailureV0::ProcessChanged
        }
        ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged
        | ApplicationStoreNamespaceOpenFailureV0::UnsafeNamespace
        | ApplicationStoreNamespaceOpenFailureV0::MissingDatabase
        | ApplicationStoreNamespaceOpenFailureV0::DatabaseIsNotRegularFile => {
            NativeValidationRecoveryTransitionFailureV0::NamespaceChanged
        }
        _ => NativeValidationRecoveryTransitionFailureV0::StoreUnavailable,
    }
}

fn map_transition_reconcile_failure_v0(
    failure: NativeValidationRecoveryTransitionFailureV0,
) -> NativeValidationRecoveryReconcileFailureV0 {
    match failure {
        NativeValidationRecoveryTransitionFailureV0::ProcessChanged => {
            NativeValidationRecoveryReconcileFailureV0::ProcessChanged
        }
        NativeValidationRecoveryTransitionFailureV0::NamespaceChanged => {
            NativeValidationRecoveryReconcileFailureV0::NamespaceChanged
        }
        NativeValidationRecoveryTransitionFailureV0::ActiveSetMismatch => {
            NativeValidationRecoveryReconcileFailureV0::ActiveSetMismatch
        }
        NativeValidationRecoveryTransitionFailureV0::StoreUnavailable => {
            NativeValidationRecoveryReconcileFailureV0::StoreUnavailable
        }
        _ => NativeValidationRecoveryReconcileFailureV0::StoreIntegrity,
    }
}

impl NativeValidationRecoveryStoreV0 {
    pub fn open_existing_v8(
        config: NativeValidationRecoveryStoreConfigV0,
    ) -> Result<Self, NativeValidationRecoveryOpenFailureV0> {
        if !config.status_path.is_absolute() {
            return Err(NativeValidationRecoveryOpenFailureV0::StatusPathNotAbsolute);
        }
        if config.expected_safety_journal_id == [0; 32]
            || config.expected_safety_verifier_profile_ref == [0; 32]
        {
            return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyProvenance);
        }
        let expected_safety_journal_id = config.expected_safety_journal_id;
        let expected_safety_verifier_profile_ref = config.expected_safety_verifier_profile_ref;
        let expected_database_path = application_store_database_path_v0(&config.status_path);
        let database_metadata =
            expected_database_path
                .symlink_metadata()
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::NotFound => {
                        NativeValidationRecoveryOpenFailureV0::MissingDatabase
                    }
                    _ => NativeValidationRecoveryOpenFailureV0::Integrity,
                })?;
        if !database_metadata.file_type().is_file() || database_metadata.file_type().is_symlink() {
            return Err(NativeValidationRecoveryOpenFailureV0::DatabaseIsNotRegularFile);
        }
        let signer_policy_hash_hex = hex::encode(config.signer_policy_hash);
        let store = ApplicationStore::open_existing_recovery_v0(
            &config.status_path,
            config.chain_id.as_str(),
            &signer_policy_hash_hex,
        )
        .map_err(map_namespace_open_failure_v0)?;
        let namespace_pin = NativeValidationRecoveryNamespacePinV0::capture(&store)?;
        let coordinator = NativeValidationRecoveryCoordinatorV0::open_existing_v0(
            &store,
            &namespace_pin,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
        )?;
        Ok(Self {
            store,
            namespace_pin,
            coordinator,
        })
    }
}

impl NativeValidationRecoveryBorrowedV0<'_> {
    fn install_audit_v0(&mut self, audit: NativeValidationRecoveryJournalAuditV0) {
        self.supported_job_count = audit.supported_job_count;
        self.active_recovery_job_count = audit.active_recovery_job_count;
        self.acked_history_job_count = audit.acked_history_job_count;
        self.audited_active_jobs = audit.active_jobs;
    }

    fn validate_confirmed_safety_head_provenance_v0(
        &self,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> std::result::Result<(), NativeValidationRecoveryTransitionFailureV0> {
        let transition: &NativeDeterministicInvalidTransitionV0 = confirmed.transition();
        if confirmed.journal_id_v0() != self.expected_safety_journal_id
            || confirmed.verifier_profile_ref_v0() != self.expected_safety_verifier_profile_ref
            || confirmed.revision() == 0
            || confirmed.state().revision() != confirmed.revision()
            || transition.completion_revision() != confirmed.revision()
        {
            return Err(NativeValidationRecoveryTransitionFailureV0::SafetyProvenanceMismatch);
        }
        Ok(())
    }

    /// Records Core acceptance after the caller has stepped the recovered
    /// deterministic-invalid callback and obtained the exact resulting
    /// SafetyState.  `CallbackPending` advances atomically to `Delivered`;
    /// an already-`Delivered` recovery is exact-readback only and retains its
    /// original delivery attempt.
    pub fn record_recovered_core_acceptance_v0(
        &mut self,
        persistence: &SafetyStatePersistenceV0,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidCallbackFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.namespace_pin.validate_transition_v0(self.store)?;
        let expected_revision = self
            .reconciled_safety_head_revision
            .ok_or(NativeValidationRecoveryTransitionFailureV0::MissingOwner)?
            .checked_add(1)
            .ok_or(NativeValidationRecoveryTransitionFailureV0::PersistenceRevisionMismatch)?;
        if persistence.barrier().get() != expected_revision
            || persistence.state().revision() != expected_revision
        {
            return Err(NativeValidationRecoveryTransitionFailureV0::PersistenceRevisionMismatch);
        }
        let (route, id) = self
            .obligation
            .as_ref()
            .map(recovered_obligation_identity_v0)
            .ok_or(NativeValidationRecoveryTransitionFailureV0::MissingOwner)?;
        validate_exact_invalid_completion_head_v0(self.store, persistence.state(), route, id)?;

        let next_owner = match self
            .obligation
            .as_ref()
            .ok_or(NativeValidationRecoveryTransitionFailureV0::MissingOwner)?
        {
            RecoveredObligationInvalidV0::CallbackPending(owner) => {
                let verified = mark_recovered_callback_pending_delivered_v0(
                    self.store,
                    owner.as_ref(),
                    self.coexisting_native_history,
                )?;
                RecoveredObligationInvalidV0::Delivered(Box::new(RecoveredDeliveredInvalidV0 {
                    verified,
                    issuing_writer_gate: Arc::clone(&self.store.writer_gate),
                }))
            }
            RecoveredObligationInvalidV0::Delivered(owner) => {
                let verified = reload_exact_delivered_owner_v0(
                    self.store,
                    owner.as_ref(),
                    self.coexisting_native_history,
                )?;
                RecoveredObligationInvalidV0::Delivered(Box::new(RecoveredDeliveredInvalidV0 {
                    verified,
                    issuing_writer_gate: Arc::clone(&self.store.writer_gate),
                }))
            }
        };
        let facts = match &next_owner {
            RecoveredObligationInvalidV0::Delivered(owner) => callback_facts_v0(&owner.verified),
            RecoveredObligationInvalidV0::CallbackPending(_) => {
                unreachable!("Core acceptance always yields Delivered")
            }
        };
        let connection = self
            .store
            .connect_read()
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
        let audit =
            audit_recovery_journal_v0(self.store, &connection, self.coexisting_native_history)?;
        require_exact_active_recovery_job_v0(
            &audit,
            route,
            id,
            NativeValidationJobStateV0::Delivered,
        )?;
        self.namespace_pin.validate_transition_v0(self.store)?;
        self.install_audit_v0(audit);
        self.obligation = Some(next_owner);
        Ok(facts)
    }

    /// Rebinds the newest exact deterministic-invalid completion from one
    /// concrete SafetyStore-confirmed head to a deeply verified
    /// Delivered/Acked row.
    pub fn recover_confirmed_invalid_completion_v0(
        &mut self,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidStateV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.validate_confirmed_safety_head_provenance_v0(confirmed)?;
        self.recover_confirmed_invalid_completion_inner_v0(confirmed.state(), confirmed)
    }

    #[cfg(test)]
    pub(crate) fn recover_confirmed_invalid_completion_for_test_v0<C>(
        &mut self,
        safety_state: &SafetyState,
        confirmation: &C,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidStateV0,
        NativeValidationRecoveryTransitionFailureV0,
    >
    where
        C: NativeValidationConfirmedInvalidTransitionV0,
    {
        self.recover_confirmed_invalid_completion_inner_v0(safety_state, confirmation)
    }

    fn recover_confirmed_invalid_completion_inner_v0<C>(
        &mut self,
        safety_state: &SafetyState,
        confirmation: &C,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidStateV0,
        NativeValidationRecoveryTransitionFailureV0,
    >
    where
        C: NativeValidationConfirmedInvalidViewV0,
    {
        self.namespace_pin.validate_transition_v0(self.store)?;
        if self.completion.is_some() {
            return Err(NativeValidationRecoveryTransitionFailureV0::WrongOwnerState);
        }
        let (route, id, completion_revision) =
            exact_invalid_completion_at_head_v0(self.store, safety_state)?;
        let connection = self
            .store
            .connect_read()
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
        let audit =
            audit_recovery_journal_v0(self.store, &connection, self.coexisting_native_history)?;
        let mut matched = None;
        self.store
            .visit_native_validation_recovery_work_v0(&connection, |job| {
                if job.validation_id() == id {
                    if matched.is_some() {
                        return Err(anyhow!("duplicate completion recovery match"));
                    }
                    matched = Some(job);
                }
                Ok(())
            })
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
        let job =
            matched.ok_or(NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch)?;
        if job.route() != route || job.creation_revision() != id.generation() {
            return Err(NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch);
        }
        let (owner, state) = match job.state() {
            NativeValidationJobStateV0::Delivered => {
                require_exact_active_recovery_job_v0(
                    &audit,
                    route,
                    id,
                    NativeValidationJobStateV0::Delivered,
                )?;
                let outbox = revalidate_native_validation_job_outbox_v0(
                    &connection,
                    &job,
                    NativeValidationReservationStageV0::ReadExisting,
                )
                .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?
                .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
                let verified = VerifiedNativeValidationInvalidCallbackV0::new_v0(job, outbox);
                if !confirmation_matches_callback_v0(
                    confirmation,
                    &callback_facts_v0(&verified),
                    completion_revision,
                ) {
                    return Err(
                        NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch,
                    );
                }
                (
                    RecoveredCompletionInvalidV0::Delivered(Box::new(
                        RecoveredDeliveredInvalidV0 {
                            verified,
                            issuing_writer_gate: Arc::clone(&self.store.writer_gate),
                        },
                    )),
                    NativeValidationRecoveredInvalidStateV0::Delivered,
                )
            }
            NativeValidationJobStateV0::Acked => {
                require_empty_active_recovery_set_v0(&audit)?;
                verify_acked_completion_v0(&job, completion_revision)?;
                let facts = acked_facts_v0(&job)?;
                if !confirmation_matches_acked_v0(confirmation, &facts) {
                    return Err(
                        NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch,
                    );
                }
                (
                    RecoveredCompletionInvalidV0::Acked(Box::new(RecoveredAckedInvalidV0 {
                        durable: Box::new(job),
                        issuing_writer_gate: Arc::clone(&self.store.writer_gate),
                    })),
                    NativeValidationRecoveredInvalidStateV0::Acked,
                )
            }
            _ => return Err(NativeValidationRecoveryTransitionFailureV0::WrongOwnerState),
        };
        self.namespace_pin.validate_transition_v0(self.store)?;
        self.install_audit_v0(audit);
        self.completion = Some(owner);
        Ok(state)
    }

    /// Atomically retires a recovered Delivered outbox after exact SafetyState
    /// confirmation, or idempotently authenticates an existing Acked row.
    pub fn acknowledge_recovered_invalid_completion_v0(
        &mut self,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> std::result::Result<
        NativeValidationRecoveredAckedFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.validate_confirmed_safety_head_provenance_v0(confirmed)?;
        self.acknowledge_recovered_invalid_completion_inner_v0(confirmed.state(), confirmed)
    }

    #[cfg(test)]
    pub(crate) fn acknowledge_recovered_invalid_completion_for_test_v0<C>(
        &mut self,
        safety_state: &SafetyState,
        confirmation: &C,
    ) -> std::result::Result<
        NativeValidationRecoveredAckedFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    >
    where
        C: NativeValidationConfirmedInvalidTransitionV0,
    {
        self.acknowledge_recovered_invalid_completion_inner_v0(safety_state, confirmation)
    }

    fn acknowledge_recovered_invalid_completion_inner_v0<C>(
        &mut self,
        safety_state: &SafetyState,
        confirmation: &C,
    ) -> std::result::Result<
        NativeValidationRecoveredAckedFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    >
    where
        C: NativeValidationConfirmedInvalidViewV0,
    {
        self.namespace_pin.validate_transition_v0(self.store)?;
        let (route, id) = self
            .completion
            .as_ref()
            .map(recovered_completion_identity_v0)
            .ok_or(NativeValidationRecoveryTransitionFailureV0::MissingOwner)?;
        let completion_revision =
            validate_exact_invalid_completion_head_v0(self.store, safety_state, route, id)?;
        let next_owner = match self
            .completion
            .as_ref()
            .ok_or(NativeValidationRecoveryTransitionFailureV0::MissingOwner)?
        {
            RecoveredCompletionInvalidV0::Delivered(owner) => {
                if !confirmation_matches_callback_v0(
                    confirmation,
                    &callback_facts_v0(&owner.verified),
                    completion_revision,
                ) {
                    return Err(
                        NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch,
                    );
                }
                let durable = acknowledge_recovered_delivered_v0(
                    self.store,
                    owner.as_ref(),
                    completion_revision,
                    self.coexisting_native_history,
                )?;
                RecoveredCompletionInvalidV0::Acked(Box::new(RecoveredAckedInvalidV0 {
                    durable: Box::new(durable),
                    issuing_writer_gate: Arc::clone(&self.store.writer_gate),
                }))
            }
            RecoveredCompletionInvalidV0::Acked(owner) => {
                if !Arc::ptr_eq(&owner.issuing_writer_gate, &self.store.writer_gate) {
                    return Err(NativeValidationRecoveryTransitionFailureV0::IssuingStoreMismatch);
                }
                if !confirmation_matches_acked_v0(confirmation, &acked_facts_v0(&owner.durable)?) {
                    return Err(
                        NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch,
                    );
                }
                let durable = reload_exact_acked_owner_v0(
                    self.store,
                    owner.as_ref(),
                    completion_revision,
                    self.coexisting_native_history,
                )?;
                RecoveredCompletionInvalidV0::Acked(Box::new(RecoveredAckedInvalidV0 {
                    durable: Box::new(durable),
                    issuing_writer_gate: Arc::clone(&self.store.writer_gate),
                }))
            }
        };
        let facts = match &next_owner {
            RecoveredCompletionInvalidV0::Acked(owner) => acked_facts_v0(&owner.durable)?,
            RecoveredCompletionInvalidV0::Delivered(_) => {
                unreachable!("completion acknowledgement always yields Acked")
            }
        };
        if !confirmation_matches_acked_v0(confirmation, &facts) {
            return Err(NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch);
        }
        let connection = self
            .store
            .connect_read()
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
        let audit =
            audit_recovery_journal_v0(self.store, &connection, self.coexisting_native_history)?;
        require_empty_active_recovery_set_v0(&audit)?;
        self.namespace_pin.validate_transition_v0(self.store)?;
        self.install_audit_v0(audit);
        self.completion = Some(next_owner);
        Ok(facts)
    }

    fn reconcile_obligation_v0(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        proposal: &Block,
        parent: &PayloadValidationParentV0,
        safety_head_revision: u64,
        first_recorded_revision: u64,
    ) -> std::result::Result<(), NativeValidationRecoveryReconcileFailureV0> {
        self.namespace_pin.validate_reconcile_v0(self.store)?;
        if self.obligation.is_some() || self.reconciled_safety_head_revision.is_some() {
            return Err(NativeValidationRecoveryReconcileFailureV0::AlreadyReconciled);
        }
        if first_recorded_revision == 0
            || first_recorded_revision != id.generation()
            || first_recorded_revision > safety_head_revision
        {
            return Err(NativeValidationRecoveryReconcileFailureV0::ChallengeRevisionMismatch);
        }
        let request_fingerprint = native_validation_request_fingerprint_v0(
            route, id, proposal, parent,
        )
        .map_err(|_| NativeValidationRecoveryReconcileFailureV0::ChallengeRequestMalformed)?;
        let expected = NativeValidationReservationFactsV0::from_core_request_v0(
            route,
            id,
            proposal,
            parent,
            request_fingerprint,
        )
        .map_err(|_| NativeValidationRecoveryReconcileFailureV0::ChallengeRequestMalformed)?;
        let connection = self
            .store
            .connect_read()
            .map_err(|_| NativeValidationRecoveryReconcileFailureV0::StoreUnavailable)?;
        self.namespace_pin.validate_reconcile_v0(self.store)?;
        let audit =
            audit_recovery_journal_v0(self.store, &connection, self.coexisting_native_history)
                .map_err(map_transition_reconcile_failure_v0)?;
        let mut matched = None;
        self.store
            .visit_native_validation_recovery_work_v0(&connection, |job| {
                if job.validation_id() == id {
                    if matched.is_some() {
                        return Err(anyhow!("duplicate native validation recovery match"));
                    }
                    matched = Some(job);
                }
                Ok(())
            })
            .map_err(|error| {
                if error
                    .to_string()
                    .contains("duplicate native validation recovery match")
                {
                    NativeValidationRecoveryReconcileFailureV0::Duplicate
                } else {
                    NativeValidationRecoveryReconcileFailureV0::StoreIntegrity
                }
            })?;
        let job = matched.ok_or(NativeValidationRecoveryReconcileFailureV0::Missing)?;
        validate_native_validation_job_congruence_v0(&expected, &job, self.store)
            .map_err(|_| NativeValidationRecoveryReconcileFailureV0::ChallengeFactsMismatch)?;
        if job.creation_revision() != first_recorded_revision {
            return Err(NativeValidationRecoveryReconcileFailureV0::ChallengeRevisionMismatch);
        }
        let state = job.state();
        let outbox = revalidate_native_validation_job_outbox_v0(
            &connection,
            &job,
            NativeValidationReservationStageV0::ReadExisting,
        )
        .map_err(|_| NativeValidationRecoveryReconcileFailureV0::StoreIntegrity)?;
        let owner = match state {
            NativeValidationJobStateV0::CallbackPending => {
                let verified = VerifiedNativeValidationInvalidCallbackV0::new_v0(
                    job,
                    outbox.ok_or(NativeValidationRecoveryReconcileFailureV0::StoreIntegrity)?,
                );
                RecoveredObligationInvalidV0::CallbackPending(Box::new(
                    RecoveredCallbackPendingInvalidV0 {
                        verified,
                        issuing_writer_gate: Arc::clone(&self.store.writer_gate),
                    },
                ))
            }
            NativeValidationJobStateV0::Delivered => {
                let verified = VerifiedNativeValidationInvalidCallbackV0::new_v0(
                    job,
                    outbox.ok_or(NativeValidationRecoveryReconcileFailureV0::StoreIntegrity)?,
                );
                RecoveredObligationInvalidV0::Delivered(Box::new(RecoveredDeliveredInvalidV0 {
                    verified,
                    issuing_writer_gate: Arc::clone(&self.store.writer_gate),
                }))
            }
            NativeValidationJobStateV0::Reserved => {
                return Err(NativeValidationRecoveryReconcileFailureV0::Reserved);
            }
            NativeValidationJobStateV0::Evaluated => {
                return Err(NativeValidationRecoveryReconcileFailureV0::Evaluated);
            }
            NativeValidationJobStateV0::Acked => {
                return Err(NativeValidationRecoveryReconcileFailureV0::Acked);
            }
            NativeValidationJobStateV0::Applied => {
                return Err(NativeValidationRecoveryReconcileFailureV0::Applied);
            }
        };
        require_exact_active_recovery_job_v0(&audit, route, id, state)
            .map_err(map_transition_reconcile_failure_v0)?;
        self.namespace_pin.validate_reconcile_v0(self.store)?;
        self.install_audit_v0(audit);
        self.obligation = Some(owner);
        self.reconciled_safety_head_revision = Some(safety_head_revision);
        Ok(())
    }
}

impl NativeValidationRecoveryCoordinatorV0 {
    pub(crate) fn open_existing_v0(
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        expected_safety_journal_id: [u8; 32],
        expected_safety_verifier_profile_ref: [u8; 32],
    ) -> Result<Self, NativeValidationRecoveryOpenFailureV0> {
        Self::open_existing_inner_v0(
            store,
            namespace_pin,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
            false,
        )
    }

    /// Creates the invalid-recovery coordinator after the enclosing native
    /// application facade has authenticated the complete schema-v12 history.
    /// Valid and Applied history remains owned by that facade and is ignored
    /// here; every deterministic-invalid P/D/K row is still deeply audited.
    pub(crate) fn open_coexisting_existing_v0(
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        expected_safety_journal_id: [u8; 32],
        expected_safety_verifier_profile_ref: [u8; 32],
    ) -> Result<Self, NativeValidationRecoveryOpenFailureV0> {
        Self::open_existing_inner_v0(
            store,
            namespace_pin,
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
            true,
        )
    }

    fn open_existing_inner_v0(
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        expected_safety_journal_id: [u8; 32],
        expected_safety_verifier_profile_ref: [u8; 32],
        coexisting_native_history: bool,
    ) -> Result<Self, NativeValidationRecoveryOpenFailureV0> {
        if expected_safety_journal_id == [0; 32]
            || expected_safety_verifier_profile_ref == [0; 32]
            || !namespace_pin.matches_safety_provenance_v0(
                expected_safety_journal_id,
                expected_safety_verifier_profile_ref,
            )
        {
            return Err(NativeValidationRecoveryOpenFailureV0::InvalidSafetyProvenance);
        }
        namespace_pin.validate_open_v0(store)?;
        if !coexisting_native_history {
            store
                .probe_existing_database()
                .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?;
            namespace_pin.validate_open_v0(store)?;
        }
        let connection = store
            .connect_read()
            .map_err(|_| NativeValidationRecoveryOpenFailureV0::DatabaseUnavailable)?;
        namespace_pin.validate_open_v0(store)?;
        if coexisting_native_history {
            connection
                .execute_batch("BEGIN DEFERRED")
                .map_err(|_| NativeValidationRecoveryOpenFailureV0::DatabaseUnavailable)?;
        }
        let mut identities = Vec::new();
        let mut active_recovery_job_count = 0_usize;
        let mut acked_history_job_count = 0_usize;
        let mut audited_active_jobs = Vec::new();
        let mut collect = |job: DurableNativeValidationJobV0| -> Result<()> {
            if job.result_kind != Some(i64::from(durable_deterministic_invalid_result_kind_v0())) {
                if coexisting_native_history {
                    return Ok(());
                }
                return Err(anyhow!("unsupported recovery result passed preflight"));
            }
            identities
                .try_reserve(1)
                .context("reserve native validation recovery identity index")?;
            identities.push((job.validation_id(), job.route()));
            match job.state() {
                NativeValidationJobStateV0::CallbackPending => {
                    let outbox = revalidate_native_validation_job_outbox_v0(
                        &connection,
                        &job,
                        NativeValidationReservationStageV0::ReadExisting,
                    )
                    .map_err(|cause| {
                        native_application_startup_reservation_error_v0(
                            "CallbackPending recovery outbox",
                            cause,
                        )
                    })?
                    .ok_or_else(|| anyhow!("missing CallbackPending recovery outbox"))?;
                    ensure!(
                        outbox.delivery_attempt == 0,
                        "CallbackPending recovery attempt is not zero"
                    );
                    active_recovery_job_count = active_recovery_job_count
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("active recovery count overflow"))?;
                    audited_active_jobs
                        .try_reserve(1)
                        .context("reserve active recovery job index")?;
                    audited_active_jobs.push(NativeValidationRecoveryActiveJobV0 {
                        route: job.route(),
                        validation_id: job.validation_id(),
                        state: job.state(),
                        row_checksum: job.row_checksum,
                        outbox_checksum: outbox.callback.outbox_checksum(),
                    });
                }
                NativeValidationJobStateV0::Delivered => {
                    let outbox = revalidate_native_validation_job_outbox_v0(
                        &connection,
                        &job,
                        NativeValidationReservationStageV0::ReadExisting,
                    )
                    .map_err(|cause| {
                        native_application_startup_reservation_error_v0(
                            "Delivered recovery outbox",
                            cause,
                        )
                    })?
                    .ok_or_else(|| anyhow!("missing Delivered recovery outbox"))?;
                    ensure!(
                        outbox.delivery_attempt == 1,
                        "Delivered recovery attempt is not canonical V0 attempt one"
                    );
                    active_recovery_job_count = active_recovery_job_count
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("active recovery count overflow"))?;
                    audited_active_jobs
                        .try_reserve(1)
                        .context("reserve active recovery job index")?;
                    audited_active_jobs.push(NativeValidationRecoveryActiveJobV0 {
                        route: job.route(),
                        validation_id: job.validation_id(),
                        state: job.state(),
                        row_checksum: job.row_checksum,
                        outbox_checksum: outbox.callback.outbox_checksum(),
                    });
                }
                NativeValidationJobStateV0::Acked => {
                    acked_history_job_count = acked_history_job_count
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("Acked history count overflow"))?;
                }
                NativeValidationJobStateV0::Reserved
                | NativeValidationJobStateV0::Evaluated
                | NativeValidationJobStateV0::Applied => {
                    return Err(anyhow!("unsupported recovery state passed preflight"));
                }
            }
            Ok(())
        };
        let audit = if coexisting_native_history {
            store
                .audit_native_consensus_application_open_snapshot_v0(
                    &connection,
                    &mut collect,
                    |_| Ok(()),
                )
                .map_err(|cause| match cause {
                    NativeApplicationFinalizationApplyFailureCauseV0::DatabaseUnavailable
                    | NativeApplicationFinalizationApplyFailureCauseV0::CommitUncertain => {
                        NativeValidationRecoveryOpenFailureV0::DatabaseUnavailable
                    }
                    NativeApplicationFinalizationApplyFailureCauseV0::HostResourceUnavailable => {
                        NativeValidationRecoveryOpenFailureV0::HostResourceUnavailable
                    }
                    _ => NativeValidationRecoveryOpenFailureV0::Integrity,
                })
        } else {
            (|| {
                if metadata(&connection, "schema_version")
                    .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?
                    != STORE_SCHEMA_VERSION
                {
                    return Err(NativeValidationRecoveryOpenFailureV0::UnsupportedSchema);
                }
                preflight_supported_recovery_rows_v0(&connection)?;
                store
                    .visit_native_validation_recovery_work_v0(&connection, &mut collect)
                    .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)
            })()
        };
        if coexisting_native_history {
            connection
                .execute_batch("ROLLBACK")
                .map_err(|_| NativeValidationRecoveryOpenFailureV0::DatabaseUnavailable)?;
        }
        audit?;
        identities.sort_unstable();
        if identities.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(NativeValidationRecoveryOpenFailureV0::DuplicateIdentity);
        }
        let supported_job_count = identities.len();
        audited_active_jobs.sort_unstable();
        namespace_pin.validate_open_v0(store)?;
        Ok(Self {
            expected_safety_journal_id,
            expected_safety_verifier_profile_ref,
            coexisting_native_history,
            supported_job_count,
            active_recovery_job_count,
            acked_history_job_count,
            audited_active_jobs,
            obligation: None,
            completion: None,
            reconciled_safety_head_revision: None,
            last_reconcile_failure: None,
        })
    }

    fn borrowed_v0<'a>(
        &'a mut self,
        store: &'a ApplicationStore,
        namespace_pin: &'a NativeValidationRecoveryNamespacePinV0,
    ) -> NativeValidationRecoveryBorrowedV0<'a> {
        NativeValidationRecoveryBorrowedV0 {
            coordinator: self,
            store,
            namespace_pin,
        }
    }

    pub(crate) const fn last_reconcile_failure_v0(
        &self,
    ) -> Option<NativeValidationRecoveryReconcileFailureV0> {
        self.last_reconcile_failure
    }

    pub(crate) const fn supported_recovery_job_count_v0(&self) -> usize {
        self.supported_job_count
    }

    pub(crate) const fn active_recovery_job_count_v0(&self) -> usize {
        self.active_recovery_job_count
    }

    pub(crate) const fn acked_history_job_count_v0(&self) -> usize {
        self.acked_history_job_count
    }

    pub(crate) fn final_exact_audit_v0(
        &self,
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
    ) -> std::result::Result<(), NativeValidationRecoveryTransitionFailureV0> {
        namespace_pin.validate_transition_v0(store)?;
        let connection = store
            .connect_read()
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
        if self.coexisting_native_history {
            store
                .preflight_native_consensus_application_host_v0()
                .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
        }
        let audit = audit_recovery_journal_v0(store, &connection, self.coexisting_native_history)?;
        if let Some(completion) = self.completion.as_ref() {
            let (route, id) = recovered_completion_identity_v0(completion);
            match completion {
                RecoveredCompletionInvalidV0::Delivered(_) => {
                    require_exact_active_recovery_job_v0(
                        &audit,
                        route,
                        id,
                        NativeValidationJobStateV0::Delivered,
                    )?;
                }
                RecoveredCompletionInvalidV0::Acked(_) => {
                    require_empty_active_recovery_set_v0(&audit)?;
                }
            }
        } else if let Some(obligation) = self.obligation.as_ref() {
            let (route, id) = recovered_obligation_identity_v0(obligation);
            let state = match obligation {
                RecoveredObligationInvalidV0::CallbackPending(_) => {
                    NativeValidationJobStateV0::CallbackPending
                }
                RecoveredObligationInvalidV0::Delivered(_) => NativeValidationJobStateV0::Delivered,
            };
            require_exact_active_recovery_job_v0(&audit, route, id, state)?;
        }
        if audit.supported_job_count != self.supported_job_count
            || audit.active_recovery_job_count != self.active_recovery_job_count
            || audit.acked_history_job_count != self.acked_history_job_count
            || audit.active_jobs != self.audited_active_jobs
        {
            return Err(NativeValidationRecoveryTransitionFailureV0::ActiveSetMismatch);
        }
        namespace_pin.validate_transition_v0(store)?;
        Ok(())
    }

    pub(crate) fn recovered_obligation_state_v0(
        &self,
    ) -> Option<NativeValidationRecoveredInvalidStateV0> {
        self.obligation.as_ref().map(|owner| match owner {
            RecoveredObligationInvalidV0::CallbackPending(_) => {
                NativeValidationRecoveredInvalidStateV0::CallbackPending
            }
            RecoveredObligationInvalidV0::Delivered(_) => {
                NativeValidationRecoveredInvalidStateV0::Delivered
            }
        })
    }

    pub(crate) fn recovered_obligation_callback_facts_v0(
        &self,
    ) -> Option<NativeValidationRecoveredInvalidCallbackFactsV0> {
        self.obligation.as_ref().map(|owner| match owner {
            RecoveredObligationInvalidV0::CallbackPending(owner) => {
                callback_facts_v0(&owner.verified)
            }
            RecoveredObligationInvalidV0::Delivered(owner) => callback_facts_v0(&owner.verified),
        })
    }

    fn validate_coexisting_history_v0(
        &self,
        store: &ApplicationStore,
    ) -> std::result::Result<(), NativeValidationRecoveryTransitionFailureV0> {
        if self.coexisting_native_history {
            store
                .preflight_native_consensus_application_host_v0()
                .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
        }
        Ok(())
    }

    pub(crate) fn record_recovered_core_acceptance_v0(
        &mut self,
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        persistence: &SafetyStatePersistenceV0,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidCallbackFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.validate_coexisting_history_v0(store)?;
        self.borrowed_v0(store, namespace_pin)
            .record_recovered_core_acceptance_v0(persistence)
    }

    pub(crate) fn recover_confirmed_invalid_completion_v0(
        &mut self,
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidStateV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.validate_coexisting_history_v0(store)?;
        self.borrowed_v0(store, namespace_pin)
            .recover_confirmed_invalid_completion_v0(confirmed)
    }

    #[cfg(test)]
    pub(crate) fn recover_confirmed_invalid_completion_for_test_v0<C>(
        &mut self,
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        safety_state: &SafetyState,
        confirmation: &C,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidStateV0,
        NativeValidationRecoveryTransitionFailureV0,
    >
    where
        C: NativeValidationConfirmedInvalidTransitionV0,
    {
        self.validate_coexisting_history_v0(store)?;
        self.borrowed_v0(store, namespace_pin)
            .recover_confirmed_invalid_completion_for_test_v0(safety_state, confirmation)
    }

    pub(crate) fn acknowledge_recovered_invalid_completion_v0(
        &mut self,
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> std::result::Result<
        NativeValidationRecoveredAckedFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.validate_coexisting_history_v0(store)?;
        self.borrowed_v0(store, namespace_pin)
            .acknowledge_recovered_invalid_completion_v0(confirmed)
    }

    #[cfg(test)]
    pub(crate) fn acknowledge_recovered_invalid_completion_for_test_v0<C>(
        &mut self,
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        safety_state: &SafetyState,
        confirmation: &C,
    ) -> std::result::Result<
        NativeValidationRecoveredAckedFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    >
    where
        C: NativeValidationConfirmedInvalidTransitionV0,
    {
        self.validate_coexisting_history_v0(store)?;
        self.borrowed_v0(store, namespace_pin)
            .acknowledge_recovered_invalid_completion_for_test_v0(safety_state, confirmation)
    }

    pub(crate) fn reconcile_deterministically_invalid_obligation_v0(
        &mut self,
        store: &ApplicationStore,
        namespace_pin: &NativeValidationRecoveryNamespacePinV0,
        challenge: &PayloadValidationRecoveryChallengeV0,
    ) -> PayloadValidationRecoveryDecisionV0 {
        if let Err(failure) = self.validate_coexisting_history_v0(store) {
            self.last_reconcile_failure = Some(map_transition_reconcile_failure_v0(failure));
            return PayloadValidationRecoveryDecisionV0::Reject;
        }
        let mut borrowed = self.borrowed_v0(store, namespace_pin);
        let result = borrowed.reconcile_obligation_v0(
            challenge.route(),
            challenge.id(),
            challenge.proposal().block(),
            challenge.parent(),
            challenge.safety_head_revision(),
            challenge.first_recorded_revision(),
        );
        match result {
            Ok(()) => {
                borrowed.last_reconcile_failure = None;
                PayloadValidationRecoveryDecisionV0::AcceptDeterministicallyInvalid
            }
            Err(failure) => {
                borrowed.last_reconcile_failure = Some(failure);
                PayloadValidationRecoveryDecisionV0::Reject
            }
        }
    }
}

impl NativeValidationRecoveryStoreV0 {
    pub const fn last_reconcile_failure_v0(
        &self,
    ) -> Option<NativeValidationRecoveryReconcileFailureV0> {
        self.coordinator.last_reconcile_failure_v0()
    }

    pub const fn supported_recovery_job_count_v0(&self) -> usize {
        self.coordinator.supported_recovery_job_count_v0()
    }

    pub const fn active_recovery_job_count_v0(&self) -> usize {
        self.coordinator.active_recovery_job_count_v0()
    }

    pub const fn acked_history_job_count_v0(&self) -> usize {
        self.coordinator.acked_history_job_count_v0()
    }

    pub fn final_exact_audit_v0(
        &self,
    ) -> std::result::Result<(), NativeValidationRecoveryTransitionFailureV0> {
        self.coordinator
            .final_exact_audit_v0(&self.store, &self.namespace_pin)
    }

    pub fn recovered_obligation_state_v0(&self) -> Option<NativeValidationRecoveredInvalidStateV0> {
        self.coordinator.recovered_obligation_state_v0()
    }

    pub fn recovered_obligation_callback_facts_v0(
        &self,
    ) -> Option<NativeValidationRecoveredInvalidCallbackFactsV0> {
        self.coordinator.recovered_obligation_callback_facts_v0()
    }

    pub fn record_recovered_core_acceptance_v0(
        &mut self,
        persistence: &SafetyStatePersistenceV0,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidCallbackFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.coordinator.record_recovered_core_acceptance_v0(
            &self.store,
            &self.namespace_pin,
            persistence,
        )
    }

    pub fn recover_confirmed_invalid_completion_v0(
        &mut self,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidStateV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.coordinator.recover_confirmed_invalid_completion_v0(
            &self.store,
            &self.namespace_pin,
            confirmed,
        )
    }

    #[cfg(test)]
    pub(crate) fn recover_confirmed_invalid_completion_for_test_v0<C>(
        &mut self,
        safety_state: &SafetyState,
        confirmation: &C,
    ) -> std::result::Result<
        NativeValidationRecoveredInvalidStateV0,
        NativeValidationRecoveryTransitionFailureV0,
    >
    where
        C: NativeValidationConfirmedInvalidTransitionV0,
    {
        self.coordinator
            .recover_confirmed_invalid_completion_for_test_v0(
                &self.store,
                &self.namespace_pin,
                safety_state,
                confirmation,
            )
    }

    pub fn acknowledge_recovered_invalid_completion_v0(
        &mut self,
        confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,
    ) -> std::result::Result<
        NativeValidationRecoveredAckedFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    > {
        self.coordinator
            .acknowledge_recovered_invalid_completion_v0(
                &self.store,
                &self.namespace_pin,
                confirmed,
            )
    }

    #[cfg(test)]
    pub(crate) fn acknowledge_recovered_invalid_completion_for_test_v0<C>(
        &mut self,
        safety_state: &SafetyState,
        confirmation: &C,
    ) -> std::result::Result<
        NativeValidationRecoveredAckedFactsV0,
        NativeValidationRecoveryTransitionFailureV0,
    >
    where
        C: NativeValidationConfirmedInvalidTransitionV0,
    {
        self.coordinator
            .acknowledge_recovered_invalid_completion_for_test_v0(
                &self.store,
                &self.namespace_pin,
                safety_state,
                confirmation,
            )
    }
}

impl PayloadValidationRecoveryReconcilerV0 for NativeValidationRecoveryStoreV0 {
    fn reconcile_deterministically_invalid_obligation_v0(
        &mut self,
        challenge: &PayloadValidationRecoveryChallengeV0,
    ) -> PayloadValidationRecoveryDecisionV0 {
        self.coordinator
            .reconcile_deterministically_invalid_obligation_v0(
                &self.store,
                &self.namespace_pin,
                challenge,
            )
    }
}

fn recovered_obligation_identity_v0(
    owner: &RecoveredObligationInvalidV0,
) -> (PayloadValidationRouteV0, ValidationId) {
    match owner {
        RecoveredObligationInvalidV0::CallbackPending(owner) => {
            (owner.verified.route(), owner.verified.validation_id())
        }
        RecoveredObligationInvalidV0::Delivered(owner) => {
            (owner.verified.route(), owner.verified.validation_id())
        }
    }
}

fn recovered_completion_identity_v0(
    owner: &RecoveredCompletionInvalidV0,
) -> (PayloadValidationRouteV0, ValidationId) {
    match owner {
        RecoveredCompletionInvalidV0::Delivered(owner) => {
            (owner.verified.route(), owner.verified.validation_id())
        }
        RecoveredCompletionInvalidV0::Acked(owner) => {
            (owner.durable.route(), owner.durable.validation_id())
        }
    }
}

fn validate_safety_configuration_v0(
    store: &ApplicationStore,
    safety_state: &SafetyState,
) -> std::result::Result<(), NativeValidationRecoveryTransitionFailureV0> {
    if safety_state.chain_id().as_str() != store.chain_id {
        return Err(NativeValidationRecoveryTransitionFailureV0::SafetyConfigurationMismatch);
    }
    Ok(())
}

fn exact_invalid_completion_at_head_v0(
    store: &ApplicationStore,
    safety_state: &SafetyState,
) -> std::result::Result<
    (PayloadValidationRouteV0, ValidationId, u64),
    NativeValidationRecoveryTransitionFailureV0,
> {
    validate_safety_configuration_v0(store, safety_state)?;
    let mut matches = safety_state
        .payload_validation_completions()
        .iter()
        .filter(|completion| {
            completion.first_recorded_revision() == safety_state.revision()
                && completion.result() == DurablePayloadValidationResultV1::DeterministicallyInvalid
        });
    let completion = matches
        .next()
        .ok_or(NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMissingOrAmbiguous)?;
    if matches.next().is_some() {
        return Err(
            NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMissingOrAmbiguous,
        );
    }
    let route = completion.route();
    let id = completion.id();
    let completion_revision = completion.first_recorded_revision();
    if completion_revision == 0
        || id.generation() == 0
        || id.generation() >= completion_revision
        || safety_state
            .payload_validation_obligations()
            .iter()
            .any(|obligation| obligation.route() == route && obligation.id() == id)
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch);
    }
    let mut terminal_matches = safety_state
        .payload_terminal_facts()
        .iter()
        .filter(|fact| fact.block_id() == id.block_id());
    let terminal = terminal_matches
        .next()
        .ok_or(NativeValidationRecoveryTransitionFailureV0::SafetyTerminalFactMismatch)?;
    if terminal_matches.next().is_some()
        || terminal.result() != PayloadTerminalResult::DeterministicallyInvalid
        || terminal.first_recorded_revision() != completion_revision
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::SafetyTerminalFactMismatch);
    }
    Ok((route, id, completion_revision))
}

fn validate_exact_invalid_completion_head_v0(
    store: &ApplicationStore,
    safety_state: &SafetyState,
    route: PayloadValidationRouteV0,
    id: ValidationId,
) -> std::result::Result<u64, NativeValidationRecoveryTransitionFailureV0> {
    let (actual_route, actual_id, revision) =
        exact_invalid_completion_at_head_v0(store, safety_state)?;
    if actual_route != route || actual_id != id {
        return Err(NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch);
    }
    Ok(revision)
}

fn same_callback_lineage_v0(
    first: &VerifiedNativeValidationInvalidCallbackV0,
    second: &VerifiedNativeValidationInvalidCallbackV0,
) -> bool {
    first.route() == second.route()
        && first.validation_id() == second.validation_id()
        && first.reason() == second.reason()
        && first.request_fingerprint() == second.request_fingerprint()
        && first.immutable_checksum() == second.immutable_checksum()
        && first.job.host_config_ref == second.job.host_config_ref
        && first.artifact_checksum() == second.artifact_checksum()
        && first.callback_payload_checksum() == second.callback_payload_checksum()
        && first.idempotency_key() == second.idempotency_key()
}

fn exact_callback_lineage_v0(
    first: &VerifiedNativeValidationInvalidCallbackV0,
    second: &VerifiedNativeValidationInvalidCallbackV0,
) -> bool {
    same_callback_lineage_v0(first, second)
        && first.delivery_attempt() == second.delivery_attempt()
        && first.job.row_checksum == second.job.row_checksum
        && first.outbox_checksum() == second.outbox_checksum()
}

fn load_verified_callback_v0(
    connection: &rusqlite::Connection,
    store: &ApplicationStore,
    id: ValidationId,
) -> std::result::Result<
    VerifiedNativeValidationInvalidCallbackV0,
    NativeValidationRecoveryTransitionFailureV0,
> {
    let row = load_native_validation_job_v0(connection, id)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let job = durable_native_validation_job_from_existing_v0(row, store)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let outbox = revalidate_native_validation_job_outbox_v0(
        connection,
        &job,
        NativeValidationReservationStageV0::ReadExisting,
    )
    .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?
    .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    Ok(VerifiedNativeValidationInvalidCallbackV0::new_v0(
        job, outbox,
    ))
}

fn reload_exact_delivered_owner_v0(
    store: &ApplicationStore,
    owner: &RecoveredDeliveredInvalidV0,
    coexisting_native_history: bool,
) -> std::result::Result<
    VerifiedNativeValidationInvalidCallbackV0,
    NativeValidationRecoveryTransitionFailureV0,
> {
    if !Arc::ptr_eq(&owner.issuing_writer_gate, &store.writer_gate) {
        return Err(NativeValidationRecoveryTransitionFailureV0::IssuingStoreMismatch);
    }
    let connection = store
        .connect_read()
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    let audit = audit_recovery_journal_v0(store, &connection, coexisting_native_history)?;
    require_exact_active_recovery_job_v0(
        &audit,
        owner.verified.route(),
        owner.verified.validation_id(),
        NativeValidationJobStateV0::Delivered,
    )?;
    let verified = load_verified_callback_v0(&connection, store, owner.verified.validation_id())?;
    if verified.job.state() != NativeValidationJobStateV0::Delivered
        || !exact_callback_lineage_v0(&verified, &owner.verified)
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    Ok(verified)
}

fn mark_recovered_callback_pending_delivered_v0(
    store: &ApplicationStore,
    owner: &RecoveredCallbackPendingInvalidV0,
    coexisting_native_history: bool,
) -> std::result::Result<
    VerifiedNativeValidationInvalidCallbackV0,
    NativeValidationRecoveryTransitionFailureV0,
> {
    if !Arc::ptr_eq(&owner.issuing_writer_gate, &store.writer_gate) {
        return Err(NativeValidationRecoveryTransitionFailureV0::IssuingStoreMismatch);
    }
    store.writer_waiters.fetch_add(1, Ordering::AcqRel);
    let writer = store.writer_gate.lock();
    store.writer_waiters.fetch_sub(1, Ordering::AcqRel);
    let _writer =
        writer.map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    let mut connection = store
        .connect_native_validation_job_v0()
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    validate_native_validation_job_bindings_v0(&transaction, store)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    read_bounded_native_validation_journal_accounting_v0(
        &transaction,
        NativeValidationReservationStageV0::ReadCapacity,
    )
    .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let before_audit = audit_recovery_journal_v0(store, &transaction, coexisting_native_history)?;
    require_exact_active_recovery_job_v0(
        &before_audit,
        owner.verified.route(),
        owner.verified.validation_id(),
        NativeValidationJobStateV0::CallbackPending,
    )?;
    let existing = load_verified_callback_v0(&transaction, store, owner.verified.validation_id())?;
    if existing.job.state() != NativeValidationJobStateV0::CallbackPending
        || !exact_callback_lineage_v0(&existing, &owner.verified)
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let next_attempt = existing
        .delivery_attempt()
        .checked_add(1)
        .ok_or(NativeValidationRecoveryTransitionFailureV0::DeliveryAttemptOverflow)?;
    let next_outbox_checksum = durable_invalid_callback_outbox_checksum_v0(
        native_validation_artifact_identity_v0(&existing.job),
        existing.artifact_checksum(),
        DURABLE_INVALID_CALLBACK_CODEC_V0,
        existing.callback_payload_checksum(),
        existing.idempotency_key(),
        next_attempt,
    );
    let next_row_checksum = native_validation_job_delivery_row_checksum_v0(
        &existing.job.immutable_checksum,
        NativeValidationJobStateV0::Delivered,
        existing.job.result_kind,
        existing.job.invalid_reason_code_be.as_deref(),
        existing.job.artifact_codec.as_deref(),
        existing.job.artifact_checksum.as_ref(),
        None,
        None,
        Some(&next_outbox_checksum),
    );
    let outbox_updated = transaction
        .execute(
            "UPDATE validation_callback_outbox_v0
             SET delivery_attempt_be=?1, outbox_checksum=?2
             WHERE route=?3 AND block_id=?4 AND view_be=?5 AND generation_be=?6
               AND delivery_attempt_be=?7 AND outbox_checksum=?8",
            params![
                next_attempt.to_be_bytes().as_slice(),
                next_outbox_checksum.as_slice(),
                native_validation_route_code_v0(existing.route()),
                existing.validation_id().block_id().as_bytes().as_slice(),
                existing
                    .validation_id()
                    .view()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
                existing
                    .validation_id()
                    .generation()
                    .to_be_bytes()
                    .as_slice(),
                existing.delivery_attempt().to_be_bytes().as_slice(),
                existing.outbox_checksum().as_slice(),
            ],
        )
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    if outbox_updated != 1 {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let job_updated = transaction
        .execute(
            "UPDATE validation_jobs_v0 SET state=3, row_checksum=?1
             WHERE route=?2 AND block_id=?3 AND view_be=?4 AND generation_be=?5
               AND state=2 AND row_checksum=?6",
            params![
                next_row_checksum.as_slice(),
                native_validation_route_code_v0(existing.route()),
                existing.validation_id().block_id().as_bytes().as_slice(),
                existing
                    .validation_id()
                    .view()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
                existing
                    .validation_id()
                    .generation()
                    .to_be_bytes()
                    .as_slice(),
                existing.job.row_checksum.as_slice(),
            ],
        )
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    if job_updated != 1 {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let delivered = load_verified_callback_v0(&transaction, store, owner.verified.validation_id())?;
    if delivered.job.state() != NativeValidationJobStateV0::Delivered
        || delivered.delivery_attempt() != next_attempt
        || !same_callback_lineage_v0(&delivered, &owner.verified)
        || delivered.outbox_checksum() != next_outbox_checksum
        || delivered.job.row_checksum != next_row_checksum
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let after_audit = audit_recovery_journal_v0(store, &transaction, coexisting_native_history)?;
    require_exact_active_recovery_job_v0(
        &after_audit,
        owner.verified.route(),
        owner.verified.validation_id(),
        NativeValidationJobStateV0::Delivered,
    )?;
    if transaction.commit().is_err() {
        let confirmation = store
            .connect_read()
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
        let observed =
            load_verified_callback_v0(&confirmation, store, owner.verified.validation_id())?;
        let confirmation_audit =
            audit_recovery_journal_v0(store, &confirmation, coexisting_native_history)?;
        if observed.job.state() == NativeValidationJobStateV0::Delivered
            && observed.delivery_attempt() == next_attempt
            && observed.outbox_checksum() == next_outbox_checksum
            && observed.job.row_checksum == next_row_checksum
            && same_callback_lineage_v0(&observed, &owner.verified)
        {
            require_exact_active_recovery_job_v0(
                &confirmation_audit,
                owner.verified.route(),
                owner.verified.validation_id(),
                NativeValidationJobStateV0::Delivered,
            )?;
            return Ok(observed);
        }
        if observed.job.state() == NativeValidationJobStateV0::CallbackPending
            && exact_callback_lineage_v0(&observed, &owner.verified)
        {
            require_exact_active_recovery_job_v0(
                &confirmation_audit,
                owner.verified.route(),
                owner.verified.validation_id(),
                NativeValidationJobStateV0::CallbackPending,
            )?;
            return Err(NativeValidationRecoveryTransitionFailureV0::StoreUnavailable);
        }
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    Ok(delivered)
}

fn verify_acked_completion_v0(
    job: &DurableNativeValidationJobV0,
    completion_revision: u64,
) -> std::result::Result<(), NativeValidationRecoveryTransitionFailureV0> {
    if job.state() != NativeValidationJobStateV0::Acked
        || job
            .accepted_core_revision_be
            .as_deref()
            .and_then(native_validation_u64_v0)
            != Some(completion_revision)
        || job.accepted_core_payload_checksum.is_none()
        || job.artifact_checksum.is_none()
        || native_validation_job_invalid_reason_v0(job).is_none()
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch);
    }
    Ok(())
}

fn acked_facts_v0(
    job: &DurableNativeValidationJobV0,
) -> std::result::Result<
    NativeValidationRecoveredAckedFactsV0,
    NativeValidationRecoveryTransitionFailureV0,
> {
    let reason = native_validation_job_invalid_reason_v0(job)
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let artifact_checksum = job
        .artifact_checksum
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let callback_payload_checksum = job
        .accepted_core_payload_checksum
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let accepted_core_revision = job
        .accepted_core_revision_be
        .as_deref()
        .and_then(native_validation_u64_v0)
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let identity = native_validation_artifact_identity_v0(job);
    let prepared_artifact = prepare_durable_invalid_artifact_v0(identity, reason);
    if prepared_artifact.checksum() != artifact_checksum
        || job.artifact_codec.as_deref() != Some(prepared_artifact.artifact_codec())
        || job.artifact_bytes.as_deref() != Some(prepared_artifact.encoded().as_slice())
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let predecessor = prepare_durable_invalid_callback_v0(&prepared_artifact);
    if predecessor.payload_checksum() != callback_payload_checksum {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let predecessor_delivery_attempt = 1_u64;
    let predecessor_outbox_checksum = durable_invalid_callback_outbox_checksum_v0(
        identity,
        artifact_checksum,
        predecessor.payload_codec(),
        callback_payload_checksum,
        predecessor.idempotency_key(),
        predecessor_delivery_attempt,
    );
    let predecessor_delivered_row_checksum = native_validation_job_delivery_row_checksum_v0(
        &job.immutable_checksum,
        NativeValidationJobStateV0::Delivered,
        job.result_kind,
        job.invalid_reason_code_be.as_deref(),
        job.artifact_codec.as_deref(),
        job.artifact_checksum.as_ref(),
        None,
        None,
        Some(&predecessor_outbox_checksum),
    );
    Ok(NativeValidationRecoveredAckedFactsV0 {
        route: job.route(),
        validation_id: job.validation_id(),
        reason: reason.into(),
        request_fingerprint: job.request_fingerprint(),
        immutable_checksum: job.immutable_checksum(),
        host_config_ref: job.host_config_ref,
        artifact_checksum,
        callback_payload_checksum,
        accepted_core_revision,
        predecessor_idempotency_key: predecessor.idempotency_key(),
        predecessor_delivery_attempt,
        predecessor_delivered_row_checksum,
        predecessor_outbox_checksum,
        row_checksum: job.row_checksum,
    })
}

fn reload_exact_acked_owner_v0(
    store: &ApplicationStore,
    owner: &RecoveredAckedInvalidV0,
    completion_revision: u64,
    coexisting_native_history: bool,
) -> std::result::Result<DurableNativeValidationJobV0, NativeValidationRecoveryTransitionFailureV0>
{
    let connection = store
        .connect_read()
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    let audit = audit_recovery_journal_v0(store, &connection, coexisting_native_history)?;
    require_empty_active_recovery_set_v0(&audit)?;
    let row = load_native_validation_job_v0(&connection, owner.durable.validation_id())
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let durable = durable_native_validation_job_from_existing_v0(row, store)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    verify_native_validation_job_outbox_v0(
        &connection,
        &durable,
        NativeValidationReservationStageV0::ReadExisting,
    )
    .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    verify_acked_completion_v0(&durable, completion_revision)?;
    if durable.route() != owner.durable.route()
        || durable.validation_id() != owner.durable.validation_id()
        || durable.request_fingerprint() != owner.durable.request_fingerprint()
        || durable.immutable_checksum() != owner.durable.immutable_checksum()
        || durable.host_config_ref != owner.durable.host_config_ref
        || durable.artifact_checksum != owner.durable.artifact_checksum
        || durable.accepted_core_payload_checksum != owner.durable.accepted_core_payload_checksum
        || durable.row_checksum != owner.durable.row_checksum
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    Ok(durable)
}

fn acknowledge_recovered_delivered_v0(
    store: &ApplicationStore,
    owner: &RecoveredDeliveredInvalidV0,
    completion_revision: u64,
    coexisting_native_history: bool,
) -> std::result::Result<DurableNativeValidationJobV0, NativeValidationRecoveryTransitionFailureV0>
{
    if !Arc::ptr_eq(&owner.issuing_writer_gate, &store.writer_gate) {
        return Err(NativeValidationRecoveryTransitionFailureV0::IssuingStoreMismatch);
    }
    if completion_revision <= owner.verified.job.creation_revision() {
        return Err(NativeValidationRecoveryTransitionFailureV0::SafetyCompletionMismatch);
    }
    store.writer_waiters.fetch_add(1, Ordering::AcqRel);
    let writer = store.writer_gate.lock();
    store.writer_waiters.fetch_sub(1, Ordering::AcqRel);
    let _writer =
        writer.map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    let mut connection = store
        .connect_native_validation_job_v0()
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    validate_native_validation_job_bindings_v0(&transaction, store)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let accounting = read_bounded_native_validation_journal_accounting_v0(
        &transaction,
        NativeValidationReservationStageV0::ReadCapacity,
    )
    .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let before_audit = audit_recovery_journal_v0(store, &transaction, coexisting_native_history)?;
    require_exact_active_recovery_job_v0(
        &before_audit,
        owner.verified.route(),
        owner.verified.validation_id(),
        NativeValidationJobStateV0::Delivered,
    )?;
    let existing = load_verified_callback_v0(&transaction, store, owner.verified.validation_id())?;
    if existing.job.state() != NativeValidationJobStateV0::Delivered
        || !exact_callback_lineage_v0(&existing, &owner.verified)
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let callback_bytes = u64::try_from(DURABLE_INVALID_CALLBACK_BYTES_V0)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let next_outbox_count = accounting
        .outbox_count
        .checked_sub(1)
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let next_outbox_bytes = accounting
        .outbox_bytes
        .checked_sub(callback_bytes)
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let accepted_core_revision_be = completion_revision.to_be_bytes();
    let callback_payload_checksum = existing.callback_payload_checksum();
    let acked_row_checksum = native_validation_job_delivery_row_checksum_v0(
        &existing.job.immutable_checksum,
        NativeValidationJobStateV0::Acked,
        existing.job.result_kind,
        existing.job.invalid_reason_code_be.as_deref(),
        existing.job.artifact_codec.as_deref(),
        existing.job.artifact_checksum.as_ref(),
        Some(&accepted_core_revision_be),
        Some(&callback_payload_checksum),
        None,
    );
    let deleted = transaction
        .execute(
            "DELETE FROM validation_callback_outbox_v0
             WHERE route=?1 AND block_id=?2 AND view_be=?3 AND generation_be=?4
               AND delivery_attempt_be=?5 AND outbox_checksum=?6",
            params![
                native_validation_route_code_v0(existing.route()),
                existing.validation_id().block_id().as_bytes().as_slice(),
                existing
                    .validation_id()
                    .view()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
                existing
                    .validation_id()
                    .generation()
                    .to_be_bytes()
                    .as_slice(),
                existing.delivery_attempt().to_be_bytes().as_slice(),
                existing.outbox_checksum().as_slice(),
            ],
        )
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    if deleted != 1 {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let job_updated = transaction
        .execute(
            "UPDATE validation_jobs_v0
             SET state=4, accepted_core_revision_be=?1,
                 accepted_core_payload_checksum=?2, row_checksum=?3
             WHERE route=?4 AND block_id=?5 AND view_be=?6 AND generation_be=?7
               AND state=3 AND row_checksum=?8",
            params![
                accepted_core_revision_be.as_slice(),
                callback_payload_checksum.as_slice(),
                acked_row_checksum.as_slice(),
                native_validation_route_code_v0(existing.route()),
                existing.validation_id().block_id().as_bytes().as_slice(),
                existing
                    .validation_id()
                    .view()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
                existing
                    .validation_id()
                    .generation()
                    .to_be_bytes()
                    .as_slice(),
                existing.job.row_checksum.as_slice(),
            ],
        )
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    if job_updated != 1 {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let accounting_updated = transaction
        .execute(
            "UPDATE validation_journal_accounting_v0
             SET outbox_count_be=?1, outbox_bytes_be=?2
             WHERE singleton=1 AND outbox_count_be=?3 AND outbox_bytes_be=?4",
            params![
                next_outbox_count.to_be_bytes().as_slice(),
                next_outbox_bytes.to_be_bytes().as_slice(),
                accounting.outbox_count.to_be_bytes().as_slice(),
                accounting.outbox_bytes.to_be_bytes().as_slice(),
            ],
        )
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
    if accounting_updated != 1 {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let row = load_native_validation_job_v0(&transaction, existing.validation_id())
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?
        .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    let acked = durable_native_validation_job_from_existing_v0(row, store)
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    verify_native_validation_job_outbox_v0(
        &transaction,
        &acked,
        NativeValidationReservationStageV0::ConfirmCommit,
    )
    .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    verify_acked_completion_v0(&acked, completion_revision)?;
    if acked.request_fingerprint() != existing.request_fingerprint()
        || acked.immutable_checksum() != existing.immutable_checksum()
        || acked.artifact_checksum != Some(existing.artifact_checksum())
        || acked.accepted_core_payload_checksum != Some(callback_payload_checksum)
        || acked.row_checksum != acked_row_checksum
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity);
    }
    let after_audit = audit_recovery_journal_v0(store, &transaction, coexisting_native_history)?;
    require_empty_active_recovery_set_v0(&after_audit)?;
    if transaction.commit().is_err() {
        let confirmation = store
            .connect_read()
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?;
        let row = load_native_validation_job_v0(&confirmation, existing.validation_id())
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreUnavailable)?
            .ok_or(NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
        let observed = durable_native_validation_job_from_existing_v0(row, store)
            .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
        verify_native_validation_job_outbox_v0(
            &confirmation,
            &observed,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
        let confirmation_audit =
            audit_recovery_journal_v0(store, &confirmation, coexisting_native_history)?;
        if observed.state() == NativeValidationJobStateV0::Acked
            && verify_acked_completion_v0(&observed, completion_revision).is_ok()
            && observed.request_fingerprint() == existing.request_fingerprint()
            && observed.immutable_checksum() == existing.immutable_checksum()
            && observed.artifact_checksum == Some(existing.artifact_checksum())
            && observed.accepted_core_payload_checksum == Some(callback_payload_checksum)
            && observed.row_checksum == acked_row_checksum
        {
            require_empty_active_recovery_set_v0(&confirmation_audit)?;
            return Ok(observed);
        }
        if observed.state() == NativeValidationJobStateV0::Delivered {
            require_exact_active_recovery_job_v0(
                &confirmation_audit,
                owner.verified.route(),
                owner.verified.validation_id(),
                NativeValidationJobStateV0::Delivered,
            )?;
        }
        return Err(NativeValidationRecoveryTransitionFailureV0::StoreUnavailable);
    }
    Ok(acked)
}

fn callback_facts_v0(
    verified: &VerifiedNativeValidationInvalidCallbackV0,
) -> NativeValidationRecoveredInvalidCallbackFactsV0 {
    NativeValidationRecoveredInvalidCallbackFactsV0 {
        route: verified.route(),
        validation_id: verified.validation_id(),
        reason: verified.reason().into(),
        request_fingerprint: verified.request_fingerprint(),
        immutable_checksum: verified.immutable_checksum(),
        host_config_ref: verified.job.host_config_ref,
        artifact_checksum: verified.artifact_checksum(),
        callback_payload_checksum: verified.callback_payload_checksum(),
        idempotency_key: verified.idempotency_key(),
        delivery_attempt: verified.delivery_attempt(),
        row_checksum: verified.job.row_checksum,
        outbox_checksum: verified.outbox_checksum(),
    }
}

fn confirmation_matches_callback_v0<C: NativeValidationConfirmedInvalidViewV0>(
    confirmation: &C,
    facts: &NativeValidationRecoveredInvalidCallbackFactsV0,
    completion_revision: u64,
) -> bool {
    confirmation.route_v0() == facts.route
        && confirmation.validation_id_v0() == facts.validation_id
        && confirmation.request_fingerprint_v0() == facts.request_fingerprint
        && confirmation.job_immutable_checksum_v0() == facts.immutable_checksum
        && confirmation.application_host_config_ref_v0() == facts.host_config_ref
        && confirmation.reason_code_v0() == facts.reason.code_v0()
        && confirmation.artifact_checksum_v0() == facts.artifact_checksum
        && confirmation.callback_payload_checksum_v0() == facts.callback_payload_checksum
        && confirmation.idempotency_key_v0() == facts.idempotency_key
        && confirmation.delivery_attempt_v0() == facts.delivery_attempt
        && confirmation.delivered_job_row_checksum_v0() == facts.row_checksum
        && confirmation.outbox_checksum_v0() == facts.outbox_checksum
        && confirmation.completion_revision_v0() == completion_revision
}

fn confirmation_matches_acked_v0<C: NativeValidationConfirmedInvalidViewV0>(
    confirmation: &C,
    facts: &NativeValidationRecoveredAckedFactsV0,
) -> bool {
    confirmation.route_v0() == facts.route
        && confirmation.validation_id_v0() == facts.validation_id
        && confirmation.request_fingerprint_v0() == facts.request_fingerprint
        && confirmation.job_immutable_checksum_v0() == facts.immutable_checksum
        && confirmation.application_host_config_ref_v0() == facts.host_config_ref
        && confirmation.reason_code_v0() == facts.reason.code_v0()
        && confirmation.artifact_checksum_v0() == facts.artifact_checksum
        && confirmation.callback_payload_checksum_v0() == facts.callback_payload_checksum
        && confirmation.idempotency_key_v0() == facts.predecessor_idempotency_key
        && confirmation.delivery_attempt_v0() == facts.predecessor_delivery_attempt
        && confirmation.delivered_job_row_checksum_v0() == facts.predecessor_delivered_row_checksum
        && confirmation.outbox_checksum_v0() == facts.predecessor_outbox_checksum
        && confirmation.completion_revision_v0() == facts.accepted_core_revision
}

struct NativeValidationRecoveryJournalAuditV0 {
    supported_job_count: usize,
    active_recovery_job_count: usize,
    acked_history_job_count: usize,
    active_jobs: Vec<NativeValidationRecoveryActiveJobV0>,
}

fn audit_recovery_journal_v0(
    store: &ApplicationStore,
    connection: &rusqlite::Connection,
    coexisting_native_history: bool,
) -> std::result::Result<
    NativeValidationRecoveryJournalAuditV0,
    NativeValidationRecoveryTransitionFailureV0,
> {
    let mut identities = BTreeMap::new();
    let mut active_jobs = Vec::new();
    let mut acked_history_job_count = 0_usize;
    store
        .visit_native_validation_recovery_work_v0(connection, |job| {
            if job.result_kind != Some(i64::from(durable_deterministic_invalid_result_kind_v0())) {
                if coexisting_native_history {
                    return Ok(());
                }
                return Err(anyhow!("unsupported result entered invalid recovery"));
            }
            if identities
                .insert(job.validation_id(), job.route())
                .is_some()
            {
                return Err(anyhow!("duplicate native validation recovery identity"));
            }
            match job.state() {
                NativeValidationJobStateV0::CallbackPending
                | NativeValidationJobStateV0::Delivered => {
                    let outbox = revalidate_native_validation_job_outbox_v0(
                        connection,
                        &job,
                        NativeValidationReservationStageV0::ReadExisting,
                    )
                    .map_err(|cause| anyhow!("active recovery outbox: {cause:?}"))?
                    .ok_or_else(|| anyhow!("active recovery row is missing its outbox"))?;
                    let expected_attempt =
                        if job.state() == NativeValidationJobStateV0::CallbackPending {
                            0
                        } else {
                            1
                        };
                    ensure!(
                        outbox.delivery_attempt == expected_attempt,
                        "active recovery delivery attempt is non-canonical"
                    );
                    active_jobs.push(NativeValidationRecoveryActiveJobV0 {
                        route: job.route(),
                        validation_id: job.validation_id(),
                        state: job.state(),
                        row_checksum: job.row_checksum,
                        outbox_checksum: outbox.callback.outbox_checksum(),
                    });
                }
                NativeValidationJobStateV0::Acked => {
                    acked_history_job_count = acked_history_job_count
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("Acked recovery history count overflow"))?;
                }
                NativeValidationJobStateV0::Reserved
                | NativeValidationJobStateV0::Evaluated
                | NativeValidationJobStateV0::Applied => {
                    return Err(anyhow!(
                        "unsupported recovery row entered the active namespace"
                    ));
                }
            }
            Ok(())
        })
        .map_err(|_| NativeValidationRecoveryTransitionFailureV0::StoreIntegrity)?;
    active_jobs.sort_unstable();
    Ok(NativeValidationRecoveryJournalAuditV0 {
        supported_job_count: identities.len(),
        active_recovery_job_count: active_jobs.len(),
        acked_history_job_count,
        active_jobs,
    })
}

fn require_exact_active_recovery_job_v0(
    audit: &NativeValidationRecoveryJournalAuditV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    state: NativeValidationJobStateV0,
) -> std::result::Result<(), NativeValidationRecoveryTransitionFailureV0> {
    if audit.active_jobs.len() != 1
        || audit.active_jobs[0].route != route
        || audit.active_jobs[0].validation_id != validation_id
        || audit.active_jobs[0].state != state
    {
        return Err(NativeValidationRecoveryTransitionFailureV0::ActiveSetMismatch);
    }
    Ok(())
}

fn require_empty_active_recovery_set_v0(
    audit: &NativeValidationRecoveryJournalAuditV0,
) -> std::result::Result<(), NativeValidationRecoveryTransitionFailureV0> {
    if !audit.active_jobs.is_empty() {
        return Err(NativeValidationRecoveryTransitionFailureV0::ActiveSetMismatch);
    }
    Ok(())
}

fn preflight_supported_recovery_rows_v0(
    connection: &rusqlite::Connection,
) -> Result<(), NativeValidationRecoveryOpenFailureV0> {
    let mut statement = connection
        .prepare("SELECT state, result_kind FROM validation_jobs_v0 ORDER BY rowid")
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
        })
        .map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?;
    for row in rows {
        let (state, result_kind) =
            row.map_err(|_| NativeValidationRecoveryOpenFailureV0::Integrity)?;
        let unsupported = match (state, result_kind) {
            (0, _) => Some(NativeValidationRecoveryUnsupportedV0::Reserved),
            (1, _) => Some(NativeValidationRecoveryUnsupportedV0::Evaluated),
            (5, _) => Some(NativeValidationRecoveryUnsupportedV0::Applied),
            (2..=4, Some(0)) => Some(NativeValidationRecoveryUnsupportedV0::Valid),
            (2..=4, Some(2)) => Some(NativeValidationRecoveryUnsupportedV0::Unavailable),
            (2..=4, Some(1)) => None,
            (2..=4, _) => Some(NativeValidationRecoveryUnsupportedV0::UnknownResult),
            _ => Some(NativeValidationRecoveryUnsupportedV0::UnknownState),
        };
        if let Some(unsupported) = unsupported {
            return Err(NativeValidationRecoveryOpenFailureV0::UnsupportedJob(
                unsupported,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod coordinator_surface_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn unique_test_root_v0(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "trnm-native-invalid-coordinator-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock follows Unix epoch")
                .as_nanos()
        ))
    }

    fn install_authenticated_trusted_base_v0(store: &ApplicationStore) {
        let height = 1_u64;
        let state_root = [0x83; 32];
        let block_id = trnm_consensus_types::BlockId::new([0x84; 32]);
        let mut connection = store
            .connect()
            .expect("open coordinator trusted-base fixture");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin coordinator trusted-base fixture");
        write_head_values(&transaction, height, state_root)
            .expect("install coordinator authenticated application head");
        write_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY, height)
            .expect("install coordinator authenticated query floor");
        transaction
            .execute(
                "DELETE FROM metadata WHERE key=?1",
                params![AUTH_PRUNE_TARGET_KEY],
            )
            .expect("clear coordinator authenticated prune target");
        transaction
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                params![height.to_be_bytes().as_slice(), state_root.as_slice()],
            )
            .expect("install coordinator authenticated head root");
        write_committed_native_anchor_v0(
            &transaction,
            CommittedNativeAnchorV0 {
                block_id,
                height,
                state_root: RootHash(state_root),
            },
        )
        .expect("install coordinator exact trusted-base BlockId anchor");
        transaction
            .commit()
            .expect("commit coordinator trusted-base fixture");
    }

    type OpenCoordinatorFnV0 =
        fn(
            &ApplicationStore,
            &NativeValidationRecoveryNamespacePinV0,
            [u8; 32],
            [u8; 32],
        )
            -> Result<NativeValidationRecoveryCoordinatorV0, NativeValidationRecoveryOpenFailureV0>;

    type ReconcileCoordinatorFnV0 = fn(
        &mut NativeValidationRecoveryCoordinatorV0,
        &ApplicationStore,
        &NativeValidationRecoveryNamespacePinV0,
        &PayloadValidationRecoveryChallengeV0,
    ) -> PayloadValidationRecoveryDecisionV0;

    #[test]
    fn coordinator_api_borrows_the_unique_store_and_namespace_pin() {
        let open: OpenCoordinatorFnV0 = NativeValidationRecoveryCoordinatorV0::open_existing_v0;
        let open_coexisting: OpenCoordinatorFnV0 =
            NativeValidationRecoveryCoordinatorV0::open_coexisting_existing_v0;
        let reconcile: ReconcileCoordinatorFnV0 =
            NativeValidationRecoveryCoordinatorV0::reconcile_deterministically_invalid_obligation_v0;
        std::hint::black_box((open, open_coexisting, reconcile));
    }

    #[test]
    fn coordinator_owns_only_recovery_state_for_compatibility_wrapping() {
        let coordinator = NativeValidationRecoveryCoordinatorV0 {
            expected_safety_journal_id: [0x71; 32],
            expected_safety_verifier_profile_ref: [0x72; 32],
            coexisting_native_history: true,
            supported_job_count: 0,
            active_recovery_job_count: 0,
            acked_history_job_count: 0,
            audited_active_jobs: Vec::new(),
            obligation: None,
            completion: None,
            reconciled_safety_head_revision: None,
            last_reconcile_failure: None,
        };
        assert_eq!(coordinator.supported_recovery_job_count_v0(), 0);
        assert_eq!(coordinator.active_recovery_job_count_v0(), 0);
        assert_eq!(coordinator.acked_history_job_count_v0(), 0);
        assert_eq!(coordinator.recovered_obligation_state_v0(), None);
        assert!(std::mem::needs_drop::<NativeValidationRecoveryCoordinatorV0>());
        assert!(std::mem::needs_drop::<NativeValidationRecoveryStoreV0>());
    }

    #[test]
    fn coordinator_opens_against_borrowed_store_and_pin_without_taking_them() {
        let root = unique_test_root_v0("borrowed-open");
        std::fs::create_dir_all(&root).expect("create coordinator test root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("protect coordinator test namespace");
        let status_path = root.join("state.json");
        let chain_id = "native-invalid-coordinator-test";
        let signer_policy = "31".repeat(32);
        let safety_journal_id = [0x81; 32];
        let safety_profile = [0x82; 32];

        let ordinary = ApplicationStore::open(&status_path, chain_id, &signer_policy)
            .expect("open ordinary test store");
        ordinary
            .load_or_migrate()
            .expect("initialize current application schema");
        install_authenticated_trusted_base_v0(&ordinary);
        bootstrap_native_validation_safety_binding_manifest_v0(
            &ordinary,
            safety_journal_id,
            safety_profile,
        )
        .expect("bind test application namespace to SafetyStore identity");
        ordinary
            .release_namespace_owner_for_recovery_test_v0()
            .expect("release ordinary owner for recovery open");
        drop(ordinary);

        let store =
            ApplicationStore::open_existing_recovery_v0(&status_path, chain_id, &signer_policy)
                .expect("open one exclusive recovery store");
        let namespace_pin = NativeValidationRecoveryNamespacePinV0::capture(&store)
            .expect("capture the shared recovery namespace pin");
        let coordinator = NativeValidationRecoveryCoordinatorV0::open_coexisting_existing_v0(
            &store,
            &namespace_pin,
            safety_journal_id,
            safety_profile,
        )
        .expect("open store-less coordinator through borrowed owners");
        assert_eq!(coordinator.supported_recovery_job_count_v0(), 0);
        coordinator
            .final_exact_audit_v0(&store, &namespace_pin)
            .expect("repeat exact borrowed-owner audit");
        assert!(namespace_pin.matches_safety_provenance_v0(safety_journal_id, safety_profile));

        drop(coordinator);
        drop(namespace_pin);
        drop(store);
        std::fs::remove_dir_all(root).expect("remove coordinator test root");
    }
}
