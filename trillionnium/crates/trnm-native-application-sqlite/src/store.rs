use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    CoreAcceptedApplicationValidDV0, NativeValidPostAckActionV0, PayloadValidationRouteV0, SignKind,
};
use trnm_consensus_safety_store::{
    NativeValidTransitionV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_types::SignatureVerifier;
use trnm_native_application::{
    decode_native_executed_block_artifact_v0, encode_native_executed_block_artifact_v0,
    NativeExecutedBlockV0, MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0,
};

use crate::{
    binding::{
        BindingRecordV0, CoreDeliveryConfirmationV0, NonZeroDigestV0, ProposalRouteV0,
        ProposalValidationBindingV0, ProposalValidationOwnerIdV0, RequestBoundSafetyConfirmationV0,
        SafetyConfirmationReadRequestV0, SafetyConfirmationReadbackV0, ValidationIdV0,
    },
    error::{error, ValidationStoreErrorCodeV0, ValidationStoreResultV0},
};

const SCHEMA_VERSION_V0: i64 = 5;
const ROW_CHECKSUM_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_ROW_CHECKSUM_V0";
const REPLAY_LINK_ROW_CHECKSUM_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_REPLAY_LINK_ROW_CHECKSUM_V0";
const REPLAY_SESSION_ID_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_REPLAY_SESSION_ID_V0";
const REPLAY_SESSION_ROW_CHECKSUM_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_REPLAY_SESSION_ROW_CHECKSUM_V0";
const REPLAY_ACTIVATION_BINDING_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_REPLAY_ACTIVATION_BINDING_V0";
const REPLAY_INITIAL_PROGRESS_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_REPLAY_INITIAL_PROGRESS_V0";
const REPLAY_ALIAS_CLOSURE_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_REPLAY_ALIAS_CLOSURE_V0";
const REPLAY_CHECKPOINT_PROGRESS_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_REPLAY_CHECKPOINT_PROGRESS_V0";
const REPLAY_LINK_DELIVERY_CHECKSUM_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_REPLAY_LINK_DELIVERY_CHECKSUM_V0";
const REPLAY_CHECKPOINT_PREIMAGE_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_REPLAY_CHECKPOINT_PREIMAGE_V0";
const TERMINAL_AUDIT_DIGEST_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_TERMINAL_AUDIT_DIGEST_V0";
const ARTIFACT_DIGEST_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_EXECUTION_ARTIFACT_DIGEST_V0";
const STORE_ID_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_STORE_ID_V0";
const REQUEST_FINGERPRINT_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_REQUEST_FINGERPRINT_V0";
const JOB_IMMUTABLE_CHECKSUM_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_JOB_IMMUTABLE_CHECKSUM_V0";
const APPLICATION_HOST_CONFIG_REF_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_APPLICATION_HOST_CONFIG_REF_V0";
const CALLBACK_PAYLOAD_CHECKSUM_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_VALIDATION_CALLBACK_PAYLOAD_CHECKSUM_V0";
const IDEMPOTENCY_KEY_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_IDEMPOTENCY_KEY_V0";
const OUTBOX_CHECKSUM_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_VALIDATION_OUTBOX_CHECKSUM_V0";
const ANCHORED_SUCCESSOR_SAFETY_CLOSURE_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_ANCHORED_SUCCESSOR_SAFETY_CLOSURE_V0";
const ORDINARY_REPLAY_SAFETY_CLOSURE_DOMAIN_V0: &[u8] =
    b"TRNM_NATIVE_ORDINARY_REPLAY_SAFETY_CLOSURE_V0";

type ReplayMetadataRowV0 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

const fn payload_validation_route_v0(route: ProposalRouteV0) -> PayloadValidationRouteV0 {
    match route {
        ProposalRouteV0::Proposal => PayloadValidationRouteV0::Proposal,
        ProposalRouteV0::Synced => PayloadValidationRouteV0::Synced,
    }
}
const EXPECTED_SCHEMA_V0: &[(&str, &str)] = &[
    (
        "proposal_validation_jobs_v0",
        "CREATE TABLE proposal_validation_jobs_v0 (validation_id BLOB PRIMARY KEY CHECK (length(validation_id) = 32),binding BLOB NOT NULL,owner_id BLOB NOT NULL CHECK (length(owner_id) = 32),artifact_digest BLOB NOT NULL CHECK (length(artifact_digest) = 32),artifact BLOB NOT NULL CHECK (typeof(artifact) = 'blob' AND length(artifact) > 0 AND length(artifact) <= 16777216),stage INTEGER NOT NULL CHECK (stage IN (1, 2, 3)),core_revision BLOB,core_state_digest BLOB,accepted_validation_digest BLOB,safety_core_delivery_digest BLOB,safety_revision BLOB,safety_record_digest BLOB,vote_intent_digest BLOB,row_revision BLOB NOT NULL CHECK (length(row_revision) = 8),row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32),CHECK ((stage = 1 AND core_revision IS NULL AND core_state_digest IS NULL AND accepted_validation_digest IS NULL AND safety_core_delivery_digest IS NULL AND safety_revision IS NULL AND safety_record_digest IS NULL AND vote_intent_digest IS NULL) OR (stage = 2 AND length(core_revision) = 8 AND length(core_state_digest) = 32 AND length(accepted_validation_digest) = 32 AND safety_core_delivery_digest IS NULL AND safety_revision IS NULL AND safety_record_digest IS NULL AND vote_intent_digest IS NULL) OR (stage = 3 AND length(core_revision) = 8 AND length(core_state_digest) = 32 AND length(accepted_validation_digest) = 32 AND length(safety_core_delivery_digest) = 32 AND length(safety_revision) = 8 AND length(safety_record_digest) = 32 AND length(vote_intent_digest) = 32)))",
    ),
    (
        "proposal_validation_outbox_v0",
        "CREATE TABLE proposal_validation_outbox_v0 (validation_id BLOB PRIMARY KEY REFERENCES proposal_validation_jobs_v0(validation_id),core_revision BLOB NOT NULL CHECK (length(core_revision) = 8),core_state_digest BLOB NOT NULL CHECK (length(core_state_digest) = 32),accepted_validation_digest BLOB NOT NULL CHECK (length(accepted_validation_digest) = 32))",
    ),
    (
        "proposal_validation_replay_links_v0",
        "CREATE TABLE proposal_validation_replay_links_v0 (target_validation_id BLOB PRIMARY KEY CHECK (length(target_validation_id) = 32),session_id BLOB NOT NULL REFERENCES proposal_validation_replay_session_v0(session_id) CHECK (length(session_id) = 32),cursor BLOB NOT NULL CHECK (length(cursor) = 8),source_validation_id BLOB NOT NULL REFERENCES proposal_validation_jobs_v0(validation_id) CHECK (length(source_validation_id) = 32),source_store_sequence BLOB NOT NULL CHECK (length(source_store_sequence) = 8),source_row_revision BLOB NOT NULL CHECK (length(source_row_revision) = 8),source_row_checksum BLOB NOT NULL CHECK (length(source_row_checksum) = 32),source_application_history_checksum BLOB NOT NULL CHECK (length(source_application_history_checksum) = 32),target_binding BLOB NOT NULL,owner_id BLOB NOT NULL CHECK (length(owner_id) = 32),artifact_digest BLOB NOT NULL CHECK (length(artifact_digest) = 32),previous_progress_checksum BLOB NOT NULL CHECK (length(previous_progress_checksum) = 32),stage INTEGER NOT NULL CHECK (stage IN (1, 2, 3, 4, 5)),core_revision BLOB,core_state_digest BLOB,accepted_validation_digest BLOB,safety_core_delivery_digest BLOB,safety_revision BLOB,safety_record_digest BLOB,no_sign_closure_digest BLOB,alias_closure_checksum BLOB,checkpoint_scope BLOB,checkpoint_profile_ref BLOB,checkpoint_predecessor_checksum BLOB,checkpoint_generation BLOB,checkpoint_checksum BLOB,row_revision BLOB NOT NULL CHECK (length(row_revision) = 8),row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32),UNIQUE (session_id, cursor),UNIQUE (session_id, source_validation_id),CHECK ((stage = 1 AND core_revision IS NULL AND core_state_digest IS NULL AND accepted_validation_digest IS NULL AND safety_core_delivery_digest IS NULL AND safety_revision IS NULL AND safety_record_digest IS NULL AND no_sign_closure_digest IS NULL AND alias_closure_checksum IS NULL AND checkpoint_scope IS NULL AND checkpoint_profile_ref IS NULL AND checkpoint_predecessor_checksum IS NULL AND checkpoint_generation IS NULL AND checkpoint_checksum IS NULL) OR (stage = 2 AND length(core_revision) = 8 AND length(core_state_digest) = 32 AND length(accepted_validation_digest) = 32 AND safety_core_delivery_digest IS NULL AND safety_revision IS NULL AND safety_record_digest IS NULL AND no_sign_closure_digest IS NULL AND alias_closure_checksum IS NULL AND checkpoint_scope IS NULL AND checkpoint_profile_ref IS NULL AND checkpoint_predecessor_checksum IS NULL AND checkpoint_generation IS NULL AND checkpoint_checksum IS NULL) OR (stage = 3 AND length(core_revision) = 8 AND length(core_state_digest) = 32 AND length(accepted_validation_digest) = 32 AND length(safety_core_delivery_digest) = 32 AND length(safety_revision) = 8 AND length(safety_record_digest) = 32 AND length(no_sign_closure_digest) = 32 AND alias_closure_checksum IS NULL AND checkpoint_scope IS NULL AND checkpoint_profile_ref IS NULL AND checkpoint_predecessor_checksum IS NULL AND checkpoint_generation IS NULL AND checkpoint_checksum IS NULL) OR (stage = 4 AND length(core_revision) = 8 AND length(core_state_digest) = 32 AND length(accepted_validation_digest) = 32 AND length(safety_core_delivery_digest) = 32 AND length(safety_revision) = 8 AND length(safety_record_digest) = 32 AND length(no_sign_closure_digest) = 32 AND length(alias_closure_checksum) = 32 AND checkpoint_scope IS NULL AND checkpoint_profile_ref IS NULL AND checkpoint_predecessor_checksum IS NULL AND checkpoint_generation IS NULL AND checkpoint_checksum IS NULL) OR (stage = 5 AND length(core_revision) = 8 AND length(core_state_digest) = 32 AND length(accepted_validation_digest) = 32 AND length(safety_core_delivery_digest) = 32 AND length(safety_revision) = 8 AND length(safety_record_digest) = 32 AND length(no_sign_closure_digest) = 32 AND length(alias_closure_checksum) = 32 AND length(checkpoint_scope) = 32 AND length(checkpoint_profile_ref) = 32 AND length(checkpoint_predecessor_checksum) = 32 AND length(checkpoint_generation) = 8 AND length(checkpoint_checksum) = 32)))",
    ),
    (
        "proposal_validation_replay_metadata_v0",
        "CREATE TABLE proposal_validation_replay_metadata_v0 (singleton INTEGER PRIMARY KEY CHECK (singleton = 1),sequence BLOB NOT NULL CHECK (length(sequence) = 8),reserved BLOB NOT NULL CHECK (length(reserved) = 8),core_delivered BLOB NOT NULL CHECK (length(core_delivered) = 8),safety_closed BLOB NOT NULL CHECK (length(safety_closed) = 8),alias_closed BLOB NOT NULL CHECK (length(alias_closed) = 8),checkpointed BLOB NOT NULL CHECK (length(checkpointed) = 8))",
    ),
    (
        "proposal_validation_replay_session_v0",
        "CREATE TABLE proposal_validation_replay_session_v0 (singleton INTEGER PRIMARY KEY CHECK (singleton = 1),session_id BLOB NOT NULL UNIQUE CHECK (length(session_id) = 32),core_config_ref BLOB NOT NULL CHECK (length(core_config_ref) = 32),validation_scope BLOB NOT NULL CHECK (length(validation_scope) = 32),validation_store_id BLOB NOT NULL CHECK (length(validation_store_id) = 32),recovery_challenge_digest BLOB NOT NULL CHECK (length(recovery_challenge_digest) = 32),archive_context_digest BLOB NOT NULL CHECK (length(archive_context_digest) = 32),archive_sequence BLOB NOT NULL CHECK (length(archive_sequence) = 8),archive_record_digest BLOB NOT NULL CHECK (length(archive_record_digest) = 32),expected_count BLOB NOT NULL CHECK (length(expected_count) = 8),next_cursor BLOB NOT NULL CHECK (length(next_cursor) = 8),canonical_store_sequence BLOB NOT NULL CHECK (length(canonical_store_sequence) = 8),canonical_terminal_row_count BLOB NOT NULL CHECK (length(canonical_terminal_row_count) = 8),canonical_terminal_audit_digest BLOB NOT NULL CHECK (length(canonical_terminal_audit_digest) = 32),application_history_digest BLOB NOT NULL CHECK (length(application_history_digest) = 32),initial_safety_revision BLOB NOT NULL CHECK (length(initial_safety_revision) = 8),initial_safety_state_checksum BLOB NOT NULL CHECK (length(initial_safety_state_checksum) = 32),initial_safety_chain_checksum BLOB NOT NULL CHECK (length(initial_safety_chain_checksum) = 32),initial_checkpoint_scope BLOB NOT NULL CHECK (length(initial_checkpoint_scope) = 32),initial_checkpoint_profile_ref BLOB NOT NULL CHECK (length(initial_checkpoint_profile_ref) = 32),initial_checkpoint_generation BLOB NOT NULL CHECK (length(initial_checkpoint_generation) = 8),initial_checkpoint_checksum BLOB NOT NULL CHECK (length(initial_checkpoint_checksum) = 32),signer_scope BLOB NOT NULL CHECK (length(signer_scope) = 32),signer_journal_id BLOB NOT NULL CHECK (length(signer_journal_id) = 32),signer_sequence BLOB NOT NULL CHECK (length(signer_sequence) = 8),signer_chain_checksum BLOB NOT NULL CHECK (length(signer_chain_checksum) = 32),previous_progress_checksum BLOB NOT NULL CHECK (length(previous_progress_checksum) = 32),state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),activation_binding_digest BLOB,activation_source_row_revision BLOB,activation_source_row_checksum BLOB,row_revision BLOB NOT NULL CHECK (length(row_revision) = 8),row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32),CHECK (next_cursor <= expected_count),CHECK ((state = 1 AND next_cursor < expected_count AND activation_binding_digest IS NULL AND activation_source_row_revision IS NULL AND activation_source_row_checksum IS NULL) OR (state = 2 AND next_cursor = expected_count AND activation_binding_digest IS NULL AND activation_source_row_revision IS NULL AND activation_source_row_checksum IS NULL) OR (state = 3 AND next_cursor = expected_count AND length(activation_binding_digest) = 32 AND length(activation_source_row_revision) = 8 AND length(activation_source_row_checksum) = 32)))",
    ),

    (
        "validation_store_accounting_v0",
        "CREATE TABLE validation_store_accounting_v0 (singleton INTEGER PRIMARY KEY CHECK (singleton = 1),reserved BLOB NOT NULL CHECK (length(reserved) = 8),delivered BLOB NOT NULL CHECK (length(delivered) = 8),acked BLOB NOT NULL CHECK (length(acked) = 8))",
    ),
    (
        "validation_store_metadata_v0",
        "CREATE TABLE validation_store_metadata_v0 (singleton INTEGER PRIMARY KEY CHECK (singleton = 1),schema_version INTEGER NOT NULL,scope BLOB NOT NULL CHECK (length(scope) = 32),store_id BLOB NOT NULL CHECK (length(store_id) = 32),sequence BLOB NOT NULL CHECK (length(sequence) = 8))",
    ),
];

type MetadataRowV0 = (i64, Vec<u8>, Vec<u8>, Vec<u8>);
type EncodedConfirmationV0 = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);
type EncodedSafetyConfirmationV0 = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalValidationStoreScopeV0([u8; 32]);

impl ProposalValidationStoreScopeV0 {
    pub fn new(bytes: [u8; 32]) -> ValidationStoreResultV0<Self> {
        if bytes == [0; 32] {
            return Err(error(ValidationStoreErrorCodeV0::ZeroValue, "store_scope"));
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DurableValidationStageV0 {
    Reserved = 1,
    Delivered = 2,
    Acked = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DurableReplayLinkStageV0 {
    Reserved = 1,
    CoreDelivered = 2,
    SafetyClosed = 3,
    AliasClosed = 4,
    Checkpointed = 5,
}

impl DurableReplayLinkStageV0 {
    fn from_i64(value: i64) -> ValidationStoreResultV0<Self> {
        match value {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::CoreDelivered),
            3 => Ok(Self::SafetyClosed),
            4 => Ok(Self::AliasClosed),
            5 => Ok(Self::Checkpointed),
            _ => Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_link.stage",
            )),
        }
    }
}

impl DurableValidationStageV0 {
    fn from_i64(value: i64) -> ValidationStoreResultV0<Self> {
        match value {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::Delivered),
            3 => Ok(Self::Acked),
            _ => Err(error(ValidationStoreErrorCodeV0::CorruptStore, "job.stage")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalValidationFactV0 {
    validation_id: ValidationIdV0,
    stage: DurableValidationStageV0,
    row_revision: u64,
    store_sequence: u64,
    outbox_present: bool,
}

/// Request-bound, C-shaped provenance retained by a durable terminal `K` row.
///
/// This is restart/audit evidence only. It is not a live Safety-store
/// authority and cannot authorize signing or advance Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableRequestBoundSafetyClosureFactV0 {
    validation_id: ValidationIdV0,
    core_delivery_digest: NonZeroDigestV0,
    safety_revision: u64,
    safety_record_digest: NonZeroDigestV0,
    vote_intent_digest: NonZeroDigestV0,
}

/// Non-cloneable proof of the exact terminal application-validation `K` head.
///
/// This capability is issued only after a fresh full-database audit has
/// reloaded the exact binding, canonical execution artifact, row checksum,
/// Core-delivery record, and request-bound Safety provenance from the pinned
/// SQLite owner.  It is intentionally non-`Clone`, non-serializable, and has
/// no public constructor.  The scalar accessors are checkpoint inputs only;
/// they cannot recreate the live P/D/C/K transition tokens.
///
/// ```compile_fail
/// use trnm_native_application_sqlite::ConfirmedProposalValidationCheckpointFactsV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedProposalValidationCheckpointFactsV0>();
/// ```
///
/// ```compile_fail
/// use trnm_native_application_sqlite::ConfirmedProposalValidationCheckpointFactsV0;
/// fn forge() -> ConfirmedProposalValidationCheckpointFactsV0 {
///     ConfirmedProposalValidationCheckpointFactsV0 {
///         database_path: "/tmp/forged".into(),
///     }
/// }
/// ```
#[derive(Debug)]
#[must_use = "confirmed application K facts must be freshly reconfirmed at a trusted checkpoint join"]
pub struct ConfirmedProposalValidationCheckpointFactsV0 {
    database_path: PathBuf,
    owner_affinity: Arc<()>,
    scope: ProposalValidationStoreScopeV0,
    store_id: [u8; 32],
    binding: ProposalValidationBindingV0,
    owner_id: ProposalValidationOwnerIdV0,
    store_sequence: u64,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
    artifact_digest: NonZeroDigestV0,
    core_delivery_digest: NonZeroDigestV0,
    safety_closure: DurableRequestBoundSafetyClosureFactV0,
}

/// Fresh full-store proof that every durable proposal-validation job has
/// reached terminal `K`, that no callback outbox remains, and that the
/// maximum submitted height came from one canonical persisted binding.
///
/// This is inert terminal evidence. It is deliberately non-`Clone` and keeps
/// the exact store/path affinity so a Node terminal owner can reject scalar
/// facts copied from a different namespace.
#[derive(Debug)]
#[must_use = "confirmed terminal K audit facts must be consumed by a trusted terminal join"]
pub struct ConfirmedProposalValidationTerminalAuditV0 {
    database_path: PathBuf,
    owner_affinity: Arc<()>,
    scope: ProposalValidationStoreScopeV0,
    store_id: [u8; 32],
    owner_id: ProposalValidationOwnerIdV0,
    store_sequence: u64,
    terminal_row_count: u64,
    maximum_terminal_height: u64,
    terminal_audit_digest: NonZeroDigestV0,
    terminal_bindings: Vec<ProposalValidationBindingV0>,
}

impl ConfirmedProposalValidationCheckpointFactsV0 {
    pub const fn scope_v0(&self) -> ProposalValidationStoreScopeV0 {
        self.scope
    }

    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn binding_v0(&self) -> &ProposalValidationBindingV0 {
        &self.binding
    }

    /// Exact owner persisted in the freshly audited terminal K row. This is
    /// row-derived identity, not a reconstruction from a caller's journal
    /// configuration.
    pub const fn owner_id_v0(&self) -> ProposalValidationOwnerIdV0 {
        self.owner_id
    }

    pub const fn store_sequence_v0(&self) -> u64 {
        self.store_sequence
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> NonZeroDigestV0 {
        self.row_checksum
    }

    pub const fn artifact_digest_v0(&self) -> NonZeroDigestV0 {
        self.artifact_digest
    }

    pub const fn core_delivery_digest_v0(&self) -> NonZeroDigestV0 {
        self.core_delivery_digest
    }

    pub const fn safety_closure_v0(&self) -> DurableRequestBoundSafetyClosureFactV0 {
        self.safety_closure
    }

    /// Owner-affinity and pinned-path check only.  A trusted coordinator must
    /// still call the store's fresh reconfirmation method immediately before
    /// constructing or advancing a whole-node checkpoint.
    pub fn belongs_to_store_at_path_v0(
        &self,
        store: &SqliteProposalValidationStoreV0,
        expected_path: &Path,
    ) -> bool {
        #[cfg(unix)]
        {
            Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
                && self.database_path == expected_path
                && store.path == expected_path
                && self.scope == store.scope
                && self.store_id == store.store_id
                && read_file_identity_v0(&store.path)
                    .is_ok_and(|identity| identity == store.file_identity)
        }
        #[cfg(not(unix))]
        {
            let _ = (store, expected_path);
            false
        }
    }
}

impl ConfirmedProposalValidationTerminalAuditV0 {
    pub const fn scope_v0(&self) -> ProposalValidationStoreScopeV0 {
        self.scope
    }

    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn owner_id_v0(&self) -> ProposalValidationOwnerIdV0 {
        self.owner_id
    }

    pub const fn store_sequence_v0(&self) -> u64 {
        self.store_sequence
    }

    pub const fn terminal_row_count_v0(&self) -> u64 {
        self.terminal_row_count
    }

    pub const fn maximum_terminal_height_v0(&self) -> u64 {
        self.maximum_terminal_height
    }

    pub const fn terminal_audit_digest_v0(&self) -> NonZeroDigestV0 {
        self.terminal_audit_digest
    }

    /// Exact terminal bindings observed by the same full-store audit.
    ///
    /// These values are inert reconstruction inputs.  They grant no callback,
    /// application, Safety, signing, or checkpoint authority; a recovering
    /// Node owner must still re-open every referenced artifact and join it to
    /// the independently authenticated application and Safety heads.
    pub fn terminal_bindings_v0(&self) -> &[ProposalValidationBindingV0] {
        &self.terminal_bindings
    }

    pub fn belongs_to_store_at_path_v0(
        &self,
        store: &SqliteProposalValidationStoreV0,
        expected_path: &Path,
    ) -> bool {
        #[cfg(unix)]
        {
            Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
                && self.database_path == expected_path
                && store.path == expected_path
                && self.scope == store.scope
                && self.store_id == store.store_id
                && read_file_identity_v0(&store.path)
                    .is_ok_and(|identity| identity == store.file_identity)
        }
        #[cfg(not(unix))]
        {
            let _ = (store, expected_path);
            false
        }
    }
}

impl DurableRequestBoundSafetyClosureFactV0 {
    pub const fn validation_id(self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn core_delivery_digest(self) -> NonZeroDigestV0 {
        self.core_delivery_digest
    }

    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_record_digest(self) -> NonZeroDigestV0 {
        self.safety_record_digest
    }

    pub const fn vote_intent_digest(self) -> NonZeroDigestV0 {
        self.vote_intent_digest
    }
}

impl ProposalValidationFactV0 {
    pub const fn validation_id(self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn stage(self) -> DurableValidationStageV0 {
        self.stage
    }

    pub const fn row_revision(self) -> u64 {
        self.row_revision
    }

    pub const fn store_sequence(self) -> u64 {
        self.store_sequence
    }

    pub const fn outbox_present(self) -> bool {
        self.outbox_present
    }
}

/// Inert manifest for one authenticated process2 replay session. Constructing
/// it grants no Core, application, Safety, signer, or checkpoint authority;
/// the Node-private caller must still consume the corresponding typed owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplaySessionPlanV0 {
    core_config_ref: NonZeroDigestV0,
    recovery_challenge_digest: NonZeroDigestV0,
    archive_context_digest: NonZeroDigestV0,
    archive_sequence: u64,
    archive_record_digest: NonZeroDigestV0,
    expected_count: u64,
    application_history_digest: NonZeroDigestV0,
    initial_safety_revision: u64,
    initial_safety_state_checksum: NonZeroDigestV0,
    initial_safety_chain_checksum: NonZeroDigestV0,
    initial_checkpoint_scope: NonZeroDigestV0,
    initial_checkpoint_profile_ref: NonZeroDigestV0,
    initial_checkpoint_generation: u64,
    initial_checkpoint_checksum: NonZeroDigestV0,
    signer_scope: NonZeroDigestV0,
    signer_journal_id: NonZeroDigestV0,
    signer_sequence: u64,
    signer_chain_checksum: NonZeroDigestV0,
}

impl ReplaySessionPlanV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_config_ref: NonZeroDigestV0,
        recovery_challenge_digest: NonZeroDigestV0,
        archive_context_digest: NonZeroDigestV0,
        archive_sequence: u64,
        archive_record_digest: NonZeroDigestV0,
        expected_count: u64,
        application_history_digest: NonZeroDigestV0,
        initial_safety_revision: u64,
        initial_safety_state_checksum: NonZeroDigestV0,
        initial_safety_chain_checksum: NonZeroDigestV0,
        initial_checkpoint_scope: NonZeroDigestV0,
        initial_checkpoint_profile_ref: NonZeroDigestV0,
        initial_checkpoint_generation: u64,
        initial_checkpoint_checksum: NonZeroDigestV0,
        signer_scope: NonZeroDigestV0,
        signer_journal_id: NonZeroDigestV0,
        signer_sequence: u64,
        signer_chain_checksum: NonZeroDigestV0,
    ) -> ValidationStoreResultV0<Self> {
        let replay_safety_span = expected_count
            .checked_mul(2)
            .and_then(|value| initial_safety_revision.checked_add(value));
        if archive_sequence == 0
            || expected_count == 0
            || initial_safety_revision == 0
            || replay_safety_span.is_none()
            || initial_checkpoint_generation
                .checked_add(expected_count)
                .is_none()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "replay_session_plan.scalar",
            ));
        }
        Ok(Self {
            core_config_ref,
            recovery_challenge_digest,
            archive_context_digest,
            archive_sequence,
            archive_record_digest,
            expected_count,
            application_history_digest,
            initial_safety_revision,
            initial_safety_state_checksum,
            initial_safety_chain_checksum,
            initial_checkpoint_scope,
            initial_checkpoint_profile_ref,
            initial_checkpoint_generation,
            initial_checkpoint_checksum,
            signer_scope,
            signer_journal_id,
            signer_sequence,
            signer_chain_checksum,
        })
    }
}

/// Inert exact preimage for the durable process2 activation fence.
///
/// This scalar claim grants no Core, signer, application, checkpoint, or
/// networking authority.  The SQLite transition additionally requires the
/// non-cloneable owner-affined replay inventory from the same live store. The
/// signer-inventory digest is an opaque commitment here: only the trusted Node
/// join can derive and authenticate it from a fresh signer owner; this store
/// never accepts or persists caller-supplied accounting columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayActivationBindingV0 {
    session_id: NonZeroDigestV0,
    core_rehydrate_digest: NonZeroDigestV0,
    safety_revision: u64,
    safety_chain_checksum: NonZeroDigestV0,
    application_history_digest: NonZeroDigestV0,
    application_parent_height: u64,
    application_parent_block_id: NonZeroDigestV0,
    application_parent_state_root: NonZeroDigestV0,
    application_parent_commit_id: NonZeroDigestV0,
    checkpoint_generation: u64,
    checkpoint_checksum: NonZeroDigestV0,
    signer_scope: NonZeroDigestV0,
    signer_journal_id: NonZeroDigestV0,
    signer_sequence: u64,
    signer_chain_checksum: NonZeroDigestV0,
    signer_inventory_digest: NonZeroDigestV0,
    selected_replay_digest: NonZeroDigestV0,
    binding_digest: NonZeroDigestV0,
}

impl ReplayActivationBindingV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: NonZeroDigestV0,
        core_rehydrate_digest: NonZeroDigestV0,
        safety_revision: u64,
        safety_chain_checksum: NonZeroDigestV0,
        application_history_digest: NonZeroDigestV0,
        application_parent_height: u64,
        application_parent_block_id: NonZeroDigestV0,
        application_parent_state_root: NonZeroDigestV0,
        application_parent_commit_id: NonZeroDigestV0,
        checkpoint_generation: u64,
        checkpoint_checksum: NonZeroDigestV0,
        signer_scope: NonZeroDigestV0,
        signer_journal_id: NonZeroDigestV0,
        signer_sequence: u64,
        signer_chain_checksum: NonZeroDigestV0,
        signer_inventory_digest: NonZeroDigestV0,
        selected_replay_digest: NonZeroDigestV0,
    ) -> ValidationStoreResultV0<Self> {
        if safety_revision == 0 || application_parent_height == 0 || checkpoint_generation == 0 {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "replay_activation.scalar",
            ));
        }
        let mut value = Self {
            session_id,
            core_rehydrate_digest,
            safety_revision,
            safety_chain_checksum,
            application_history_digest,
            application_parent_height,
            application_parent_block_id,
            application_parent_state_root,
            application_parent_commit_id,
            checkpoint_generation,
            checkpoint_checksum,
            signer_scope,
            signer_journal_id,
            signer_sequence,
            signer_chain_checksum,
            signer_inventory_digest,
            selected_replay_digest,
            binding_digest: NonZeroDigestV0::new([1; 32])?,
        };
        value.binding_digest = NonZeroDigestV0::new(compute_replay_activation_binding_v0(&value))?;
        Ok(value)
    }

    pub const fn session_id_v0(self) -> [u8; 32] {
        *self.session_id.as_bytes()
    }

    pub const fn core_rehydrate_digest_v0(self) -> [u8; 32] {
        *self.core_rehydrate_digest.as_bytes()
    }

    pub const fn safety_revision_v0(self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_chain_checksum_v0(self) -> [u8; 32] {
        *self.safety_chain_checksum.as_bytes()
    }

    pub const fn application_history_digest_v0(self) -> [u8; 32] {
        *self.application_history_digest.as_bytes()
    }

    pub const fn application_parent_height_v0(self) -> u64 {
        self.application_parent_height
    }

    pub const fn application_parent_block_id_v0(self) -> [u8; 32] {
        *self.application_parent_block_id.as_bytes()
    }

    pub const fn application_parent_state_root_v0(self) -> [u8; 32] {
        *self.application_parent_state_root.as_bytes()
    }

    pub const fn application_parent_commit_id_v0(self) -> [u8; 32] {
        *self.application_parent_commit_id.as_bytes()
    }

    pub const fn checkpoint_generation_v0(self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn checkpoint_checksum_v0(self) -> [u8; 32] {
        *self.checkpoint_checksum.as_bytes()
    }

    pub const fn signer_scope_v0(self) -> [u8; 32] {
        *self.signer_scope.as_bytes()
    }

    pub const fn signer_journal_id_v0(self) -> [u8; 32] {
        *self.signer_journal_id.as_bytes()
    }

    pub const fn signer_sequence_v0(self) -> u64 {
        self.signer_sequence
    }

    pub const fn signer_chain_checksum_v0(self) -> [u8; 32] {
        *self.signer_chain_checksum.as_bytes()
    }

    pub const fn signer_inventory_digest_v1(self) -> [u8; 32] {
        *self.signer_inventory_digest.as_bytes()
    }

    pub const fn selected_replay_digest_v0(self) -> [u8; 32] {
        *self.selected_replay_digest.as_bytes()
    }

    pub const fn binding_digest_v0(self) -> [u8; 32] {
        *self.binding_digest.as_bytes()
    }
}

/// Process-affined, non-cloneable cursor authority for one exact active replay
/// session. A checkpointed link returns the successor cursor authority.
#[derive(Debug)]
pub struct ActiveReplaySessionV0 {
    store_id: [u8; 32],
    session_id: [u8; 32],
    next_cursor: u64,
    expected_count: u64,
    previous_progress_checksum: NonZeroDigestV0,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
}

impl ActiveReplaySessionV0 {
    pub const fn session_id_v0(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn next_cursor_v0(&self) -> u64 {
        self.next_cursor
    }

    pub const fn expected_count_v0(&self) -> u64 {
        self.expected_count
    }

    pub const fn previous_progress_checksum_v0(&self) -> NonZeroDigestV0 {
        self.previous_progress_checksum
    }
}

#[derive(Debug)]
pub enum ReplaySessionOpenOutcomeV0 {
    Applied(ActiveReplaySessionV0),
    Existing(ActiveReplaySessionV0),
    NotApplied,
}

#[derive(Debug)]
pub struct DurableReplayCompleteV0 {
    store_id: [u8; 32],
    session_id: [u8; 32],
    expected_count: u64,
    final_progress_checksum: NonZeroDigestV0,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
}

impl DurableReplayCompleteV0 {
    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn session_id_v0(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn expected_count_v0(&self) -> u64 {
        self.expected_count
    }

    pub const fn final_progress_checksum_v0(&self) -> NonZeroDigestV0 {
        self.final_progress_checksum
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> NonZeroDigestV0 {
        self.row_checksum
    }
}

#[derive(Debug)]
pub enum ReplaySessionResumeOutcomeV0 {
    Ready(ActiveReplaySessionV0),
    Reserved(ReservedReplayLinkPV0),
    CoreDelivered(CoreDeliveredReplayLinkDV0),
    SafetyClosed(SafetyClosedReplayLinkCV0),
    AliasClosed(AliasClosedReplayLinkKV0),
    DurableReplayComplete(DurableReplayCompleteV0),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaySessionPresenceV0 {
    None,
    Active {
        session_id: [u8; 32],
        next_cursor: u64,
        expected_count: u64,
    },
    DurableReplayComplete {
        session_id: [u8; 32],
        expected_count: u64,
    },
    ActivationReady {
        session_id: [u8; 32],
        expected_count: u64,
    },
}

/// Inert, complete scalar projection of one durable replay session row.
///
/// These values are comparison material only.  They do not carry the live
/// SQLite owner affinity retained by [`ConfirmedReplayInventoryV0`] and cannot
/// reserve a link, acknowledge a cursor, or authorize Core rehydration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplaySessionFactsV0 {
    session_id: [u8; 32],
    core_config_ref: [u8; 32],
    validation_scope: [u8; 32],
    validation_store_id: [u8; 32],
    recovery_challenge_digest: [u8; 32],
    archive_context_digest: [u8; 32],
    archive_sequence: u64,
    archive_record_digest: [u8; 32],
    expected_count: u64,
    next_cursor: u64,
    canonical_store_sequence: u64,
    canonical_terminal_row_count: u64,
    canonical_terminal_audit_digest: [u8; 32],
    application_history_digest: [u8; 32],
    initial_safety_revision: u64,
    initial_safety_state_checksum: [u8; 32],
    initial_safety_chain_checksum: [u8; 32],
    initial_checkpoint_scope: [u8; 32],
    initial_checkpoint_profile_ref: [u8; 32],
    initial_checkpoint_generation: u64,
    initial_checkpoint_checksum: [u8; 32],
    signer_scope: [u8; 32],
    signer_journal_id: [u8; 32],
    signer_sequence: u64,
    signer_chain_checksum: [u8; 32],
    previous_progress_checksum: [u8; 32],
    durable_complete: bool,
    activation_ready: bool,
    activation_binding_digest: Option<[u8; 32]>,
    activation_source_row_revision: Option<u64>,
    activation_source_row_checksum: Option<[u8; 32]>,
    row_revision: u64,
    row_checksum: [u8; 32],
}

impl ReplaySessionFactsV0 {
    pub const fn session_id_v0(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn core_config_ref_v0(self) -> [u8; 32] {
        self.core_config_ref
    }

    pub const fn validation_scope_v0(self) -> [u8; 32] {
        self.validation_scope
    }

    pub const fn validation_store_id_v0(self) -> [u8; 32] {
        self.validation_store_id
    }

    pub const fn recovery_challenge_digest_v0(self) -> [u8; 32] {
        self.recovery_challenge_digest
    }

    pub const fn archive_context_digest_v0(self) -> [u8; 32] {
        self.archive_context_digest
    }

    pub const fn archive_sequence_v0(self) -> u64 {
        self.archive_sequence
    }

    pub const fn archive_record_digest_v0(self) -> [u8; 32] {
        self.archive_record_digest
    }

    pub const fn expected_count_v0(self) -> u64 {
        self.expected_count
    }

    pub const fn next_cursor_v0(self) -> u64 {
        self.next_cursor
    }

    pub const fn canonical_store_sequence_v0(self) -> u64 {
        self.canonical_store_sequence
    }

    pub const fn canonical_terminal_row_count_v0(self) -> u64 {
        self.canonical_terminal_row_count
    }

    pub const fn canonical_terminal_audit_digest_v0(self) -> [u8; 32] {
        self.canonical_terminal_audit_digest
    }

    pub const fn application_history_digest_v0(self) -> [u8; 32] {
        self.application_history_digest
    }

    pub const fn initial_safety_revision_v0(self) -> u64 {
        self.initial_safety_revision
    }

    pub const fn initial_safety_state_checksum_v0(self) -> [u8; 32] {
        self.initial_safety_state_checksum
    }

    pub const fn initial_safety_chain_checksum_v0(self) -> [u8; 32] {
        self.initial_safety_chain_checksum
    }

    pub const fn initial_checkpoint_scope_v0(self) -> [u8; 32] {
        self.initial_checkpoint_scope
    }

    pub const fn initial_checkpoint_profile_ref_v0(self) -> [u8; 32] {
        self.initial_checkpoint_profile_ref
    }

    pub const fn initial_checkpoint_generation_v0(self) -> u64 {
        self.initial_checkpoint_generation
    }

    pub const fn initial_checkpoint_checksum_v0(self) -> [u8; 32] {
        self.initial_checkpoint_checksum
    }

    pub const fn signer_scope_v0(self) -> [u8; 32] {
        self.signer_scope
    }

    pub const fn signer_journal_id_v0(self) -> [u8; 32] {
        self.signer_journal_id
    }

    pub const fn signer_sequence_v0(self) -> u64 {
        self.signer_sequence
    }

    pub const fn signer_chain_checksum_v0(self) -> [u8; 32] {
        self.signer_chain_checksum
    }

    pub const fn previous_progress_checksum_v0(self) -> [u8; 32] {
        self.previous_progress_checksum
    }

    pub const fn is_durable_complete_v0(self) -> bool {
        self.durable_complete
    }

    pub const fn is_activation_ready_v0(self) -> bool {
        self.activation_ready
    }

    pub const fn activation_binding_digest_v0(self) -> Option<[u8; 32]> {
        self.activation_binding_digest
    }

    /// Exact `DurableReplayComplete` predecessor revision retained by the
    /// one-way `ActivationReady` CAS.  Rehydration after process loss binds
    /// this predecessor rather than the successor row checksum.
    pub const fn activation_source_row_revision_v0(self) -> Option<u64> {
        self.activation_source_row_revision
    }

    /// Exact `DurableReplayComplete` predecessor checksum retained by the
    /// one-way `ActivationReady` CAS.
    pub const fn activation_source_row_checksum_v0(self) -> Option<[u8; 32]> {
        self.activation_source_row_checksum
    }

    pub const fn row_revision_v0(self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(self) -> [u8; 32] {
        self.row_checksum
    }
}

/// Inert scalar projection of one replay-link row at any durable stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayLinkFactsV0 {
    session_id: [u8; 32],
    cursor: u64,
    source_validation_id: ValidationIdV0,
    target_binding: ProposalValidationBindingV0,
    owner_id: ProposalValidationOwnerIdV0,
    source_store_sequence: u64,
    source_row_revision: u64,
    source_row_checksum: [u8; 32],
    source_application_history_checksum: [u8; 32],
    artifact_digest: [u8; 32],
    previous_progress_checksum: [u8; 32],
    stage: DurableReplayLinkStageV0,
    core_revision: Option<u64>,
    core_state_digest: Option<[u8; 32]>,
    accepted_validation_digest: Option<[u8; 32]>,
    safety_core_delivery_digest: Option<[u8; 32]>,
    safety_revision: Option<u64>,
    safety_record_digest: Option<[u8; 32]>,
    no_sign_closure_digest: Option<[u8; 32]>,
    alias_closure_checksum: Option<[u8; 32]>,
    checkpoint_scope: Option<[u8; 32]>,
    checkpoint_profile_ref: Option<[u8; 32]>,
    checkpoint_predecessor_checksum: Option<[u8; 32]>,
    checkpoint_generation: Option<u64>,
    checkpoint_checksum: Option<[u8; 32]>,
    progress_checksum: Option<[u8; 32]>,
    row_revision: u64,
    row_checksum: [u8; 32],
}

impl ReplayLinkFactsV0 {
    pub const fn session_id_v0(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn cursor_v0(&self) -> u64 {
        self.cursor
    }

    pub const fn source_validation_id_v0(&self) -> ValidationIdV0 {
        self.source_validation_id
    }

    pub const fn target_binding_v0(&self) -> &ProposalValidationBindingV0 {
        &self.target_binding
    }

    pub const fn owner_id_v0(&self) -> ProposalValidationOwnerIdV0 {
        self.owner_id
    }

    pub const fn source_store_sequence_v0(&self) -> u64 {
        self.source_store_sequence
    }

    pub const fn source_row_revision_v0(&self) -> u64 {
        self.source_row_revision
    }

    pub const fn source_row_checksum_v0(&self) -> [u8; 32] {
        self.source_row_checksum
    }

    pub const fn source_application_history_checksum_v0(&self) -> [u8; 32] {
        self.source_application_history_checksum
    }

    pub const fn artifact_digest_v0(&self) -> [u8; 32] {
        self.artifact_digest
    }

    pub const fn previous_progress_checksum_v0(&self) -> [u8; 32] {
        self.previous_progress_checksum
    }

    pub const fn stage_v0(&self) -> DurableReplayLinkStageV0 {
        self.stage
    }

    pub const fn core_revision_v0(&self) -> Option<u64> {
        self.core_revision
    }

    pub const fn core_state_digest_v0(&self) -> Option<[u8; 32]> {
        self.core_state_digest
    }

    pub const fn accepted_validation_digest_v0(&self) -> Option<[u8; 32]> {
        self.accepted_validation_digest
    }

    pub const fn safety_core_delivery_digest_v0(&self) -> Option<[u8; 32]> {
        self.safety_core_delivery_digest
    }

    pub const fn safety_revision_v0(&self) -> Option<u64> {
        self.safety_revision
    }

    pub const fn safety_record_digest_v0(&self) -> Option<[u8; 32]> {
        self.safety_record_digest
    }

    pub const fn no_sign_closure_digest_v0(&self) -> Option<[u8; 32]> {
        self.no_sign_closure_digest
    }

    pub const fn alias_closure_checksum_v0(&self) -> Option<[u8; 32]> {
        self.alias_closure_checksum
    }

    pub const fn checkpoint_scope_v0(&self) -> Option<[u8; 32]> {
        self.checkpoint_scope
    }

    pub const fn checkpoint_profile_ref_v0(&self) -> Option<[u8; 32]> {
        self.checkpoint_profile_ref
    }

    pub const fn checkpoint_predecessor_checksum_v0(&self) -> Option<[u8; 32]> {
        self.checkpoint_predecessor_checksum
    }

    pub const fn checkpoint_generation_v0(&self) -> Option<u64> {
        self.checkpoint_generation
    }

    pub const fn checkpoint_checksum_v0(&self) -> Option<[u8; 32]> {
        self.checkpoint_checksum
    }

    pub const fn progress_checksum_v0(&self) -> Option<[u8; 32]> {
        self.progress_checksum
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> [u8; 32] {
        self.row_checksum
    }
}

/// Fresh owner-affined audit of the complete replay sidecar.
#[derive(Debug)]
#[must_use = "the replay inventory must remain joined to its live SQLite owner"]
pub struct ConfirmedReplayInventoryV0 {
    database_path: PathBuf,
    owner_affinity: Arc<()>,
    store_id: [u8; 32],
    session: ReplaySessionFactsV0,
    links: Vec<ReplayLinkFactsV0>,
}

impl ConfirmedReplayInventoryV0 {
    pub const fn session_v0(&self) -> ReplaySessionFactsV0 {
        self.session
    }

    pub fn links_v0(&self) -> &[ReplayLinkFactsV0] {
        &self.links
    }

    pub fn belongs_to_store_at_path_v0(
        &self,
        store: &SqliteProposalValidationStoreV0,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
            && self.database_path == expected_path
            && store.path == expected_path
            && self.store_id == store.store_id
            && read_file_identity_v0(&store.path)
                .is_ok_and(|identity| identity == store.file_identity)
    }
}

/// Non-cloneable, owner-affined confirmation of the durable process2
/// activation fence.  It carries no Core, signer, timer, or ingress authority.
///
/// ```compile_fail
/// use trnm_native_application_sqlite::ConfirmedReplayActivationReadyV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedReplayActivationReadyV0>();
/// ```
///
/// ```compile_fail
/// use trnm_native_application_sqlite::ConfirmedReplayActivationReadyV0;
/// fn forge() -> ConfirmedReplayActivationReadyV0 {
///     ConfirmedReplayActivationReadyV0 { store_id: [1; 32] }
/// }
/// ```
#[derive(Debug)]
#[must_use = "activation-ready facts must remain joined to the live replay store"]
pub struct ConfirmedReplayActivationReadyV0 {
    database_path: PathBuf,
    owner_affinity: Arc<()>,
    store_id: [u8; 32],
    binding: ReplayActivationBindingV0,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
}

impl ConfirmedReplayActivationReadyV0 {
    pub const fn binding_v0(&self) -> ReplayActivationBindingV0 {
        self.binding
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> NonZeroDigestV0 {
        self.row_checksum
    }

    pub fn belongs_to_store_at_path_v0(
        &self,
        store: &SqliteProposalValidationStoreV0,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &store.owner_affinity)
            && self.database_path == expected_path
            && store.path == expected_path
            && self.store_id == store.store_id
            && read_file_identity_v0(&store.path)
                .is_ok_and(|identity| identity == store.file_identity)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplaySourceHistoryReadRequestV0 {
    source_validation_id: ValidationIdV0,
    artifact_digest: NonZeroDigestV0,
    expected_history_checksum: NonZeroDigestV0,
}

impl ReplaySourceHistoryReadRequestV0 {
    pub const fn source_validation_id_v0(self) -> ValidationIdV0 {
        self.source_validation_id
    }

    pub const fn artifact_digest_v0(self) -> NonZeroDigestV0 {
        self.artifact_digest
    }

    pub const fn expected_history_checksum_v0(self) -> NonZeroDigestV0 {
        self.expected_history_checksum
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntrustedReplaySourceHistoryReadbackV0 {
    source_validation_id: ValidationIdV0,
    artifact_digest: NonZeroDigestV0,
    history_checksum: NonZeroDigestV0,
}

impl UntrustedReplaySourceHistoryReadbackV0 {
    pub fn new(
        source_validation_id: ValidationIdV0,
        artifact_digest: NonZeroDigestV0,
        history_checksum: NonZeroDigestV0,
    ) -> Self {
        Self {
            source_validation_id,
            artifact_digest,
            history_checksum,
        }
    }
}

/// Node-TCB adapter for a fresh, owner-affined native application history-row
/// read. The returned scalar remains untrusted and is compared exactly.
pub trait ReplaySourceHistoryReadbackV0 {
    fn read_exact_replay_source_history_v0(
        &mut self,
        request: ReplaySourceHistoryReadRequestV0,
    ) -> ValidationStoreResultV0<UntrustedReplaySourceHistoryReadbackV0>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayCheckpointReadRequestV0 {
    session_id: [u8; 32],
    cursor: u64,
    target_validation_id: ValidationIdV0,
    alias_k_row_checksum: NonZeroDigestV0,
    previous_progress_checksum: NonZeroDigestV0,
    safety_revision: u64,
    expected_scope: NonZeroDigestV0,
    expected_profile_ref: NonZeroDigestV0,
    expected_predecessor_generation: u64,
    expected_predecessor_checksum: NonZeroDigestV0,
    application_history_digest: NonZeroDigestV0,
    signer_scope: NonZeroDigestV0,
    signer_journal_id: NonZeroDigestV0,
    signer_sequence: u64,
    signer_chain_checksum: NonZeroDigestV0,
    preimage_digest: NonZeroDigestV0,
}

impl ReplayCheckpointReadRequestV0 {
    pub const fn session_id_v0(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn cursor_v0(self) -> u64 {
        self.cursor
    }

    pub const fn target_validation_id_v0(self) -> ValidationIdV0 {
        self.target_validation_id
    }

    pub const fn preimage_digest_v0(self) -> NonZeroDigestV0 {
        self.preimage_digest
    }

    pub const fn expected_scope_v0(self) -> NonZeroDigestV0 {
        self.expected_scope
    }

    pub const fn expected_profile_ref_v0(self) -> NonZeroDigestV0 {
        self.expected_profile_ref
    }

    pub const fn expected_predecessor_generation_v0(self) -> u64 {
        self.expected_predecessor_generation
    }

    pub const fn expected_predecessor_checksum_v0(self) -> NonZeroDigestV0 {
        self.expected_predecessor_checksum
    }

    pub const fn alias_k_row_checksum_v0(self) -> NonZeroDigestV0 {
        self.alias_k_row_checksum
    }

    pub const fn previous_progress_checksum_v0(self) -> NonZeroDigestV0 {
        self.previous_progress_checksum
    }

    pub const fn safety_revision_v0(self) -> u64 {
        self.safety_revision
    }

    pub const fn application_history_digest_v0(self) -> NonZeroDigestV0 {
        self.application_history_digest
    }

    pub const fn signer_scope_v0(self) -> NonZeroDigestV0 {
        self.signer_scope
    }

    pub const fn signer_journal_id_v0(self) -> NonZeroDigestV0 {
        self.signer_journal_id
    }

    pub const fn signer_sequence_v0(self) -> u64 {
        self.signer_sequence
    }

    pub const fn signer_chain_checksum_v0(self) -> NonZeroDigestV0 {
        self.signer_chain_checksum
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntrustedReplayCheckpointReadbackV0 {
    preimage_digest: NonZeroDigestV0,
    scope: NonZeroDigestV0,
    profile_ref: NonZeroDigestV0,
    predecessor_checksum: NonZeroDigestV0,
    generation: u64,
    checkpoint_checksum: NonZeroDigestV0,
}

impl UntrustedReplayCheckpointReadbackV0 {
    pub fn new(
        preimage_digest: NonZeroDigestV0,
        scope: NonZeroDigestV0,
        profile_ref: NonZeroDigestV0,
        predecessor_checksum: NonZeroDigestV0,
        generation: u64,
        checkpoint_checksum: NonZeroDigestV0,
    ) -> ValidationStoreResultV0<Self> {
        if generation == 0 {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "replay_checkpoint.generation",
            ));
        }
        Ok(Self {
            preimage_digest,
            scope,
            profile_ref,
            predecessor_checksum,
            generation,
            checkpoint_checksum,
        })
    }
}

pub trait ReplayCheckpointReadbackV0 {
    fn read_or_advance_exact_replay_checkpoint_v0(
        &mut self,
        request: ReplayCheckpointReadRequestV0,
    ) -> ValidationStoreResultV0<UntrustedReplayCheckpointReadbackV0>;
}

/// Linear `P` capability proving that one exact binding and complete canonical
/// `NativeExecutedBlockV0` artifact were atomically persisted and freshly
/// read back from the exact store.
///
/// ```compile_fail
/// use trnm_native_application_sqlite::ReservedValidationV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ReservedValidationV0>();
/// ```
#[derive(Debug)]
pub struct ReservedValidationV0 {
    store_id: [u8; 32],
    validation_id: ValidationIdV0,
    owner_id: ProposalValidationOwnerIdV0,
    artifact_digest: NonZeroDigestV0,
    row_revision: u64,
}

impl ReservedValidationV0 {
    pub const fn validation_id(&self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn row_revision(&self) -> u64 {
        self.row_revision
    }

    pub const fn artifact_digest(&self) -> NonZeroDigestV0 {
        self.artifact_digest
    }
}

/// Linear proof that Core acceptance was durably delivered as `D`.
///
/// ```compile_fail
/// use trnm_native_application_sqlite::DeliveredValidationV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<DeliveredValidationV0>();
/// ```
#[derive(Debug)]
pub struct DeliveredValidationV0 {
    store_id: [u8; 32],
    validation_id: ValidationIdV0,
    owner_id: ProposalValidationOwnerIdV0,
    artifact_digest: NonZeroDigestV0,
    core_delivery: CoreDeliveryConfirmationV0,
    row_revision: u64,
}

impl DeliveredValidationV0 {
    pub const fn validation_id(&self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn core_delivery(&self) -> CoreDeliveryConfirmationV0 {
        self.core_delivery
    }

    pub const fn row_revision(&self) -> u64 {
        self.row_revision
    }
}

/// Terminal linear proof that exact request-bound, C-shaped readback closed `K`.
///
/// ```compile_fail
/// use trnm_native_application_sqlite::AckedValidationV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AckedValidationV0>();
/// ```
#[derive(Debug)]
pub struct AckedValidationV0 {
    store_id: [u8; 32],
    validation_id: ValidationIdV0,
    owner_id: ProposalValidationOwnerIdV0,
    safety_confirmation: RequestBoundSafetyConfirmationV0,
    row_revision: u64,
}

impl AckedValidationV0 {
    pub const fn validation_id(&self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn row_revision(&self) -> u64 {
        self.row_revision
    }

    pub const fn owner_id(&self) -> ProposalValidationOwnerIdV0 {
        self.owner_id
    }

    pub const fn store_id(&self) -> &[u8; 32] {
        &self.store_id
    }

    pub const fn request_bound_safety_confirmation(&self) -> RequestBoundSafetyConfirmationV0 {
        self.safety_confirmation
    }
}

#[derive(Debug)]
pub enum ReservationOutcomeV0 {
    Applied(ReservedValidationV0),
    NotApplied,
}

/// Linear authority for an independently durable replay link at `P`.
///
/// The link aliases one canonical terminal application `K`; it never creates
/// a second canonical validation job or copies the canonical artifact bytes.
#[derive(Debug)]
pub struct ReservedReplayLinkPV0 {
    store_id: [u8; 32],
    session_id: [u8; 32],
    cursor: u64,
    source_validation_id: ValidationIdV0,
    target_validation_id: ValidationIdV0,
    owner_id: ProposalValidationOwnerIdV0,
    artifact_digest: NonZeroDigestV0,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
}

impl ReservedReplayLinkPV0 {
    pub const fn session_id_v0(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn cursor_v0(&self) -> u64 {
        self.cursor
    }

    pub const fn source_validation_id_v0(&self) -> ValidationIdV0 {
        self.source_validation_id
    }

    pub const fn target_validation_id_v0(&self) -> ValidationIdV0 {
        self.target_validation_id
    }

    pub const fn artifact_digest_v0(&self) -> NonZeroDigestV0 {
        self.artifact_digest
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> NonZeroDigestV0 {
        self.row_checksum
    }
}

/// Linear authority for the same replay link after Core accepted Valid (`D`).
#[derive(Debug)]
pub struct CoreDeliveredReplayLinkDV0 {
    store_id: [u8; 32],
    session_id: [u8; 32],
    cursor: u64,
    source_validation_id: ValidationIdV0,
    target_validation_id: ValidationIdV0,
    owner_id: ProposalValidationOwnerIdV0,
    artifact_digest: NonZeroDigestV0,
    core_delivery: CoreDeliveryConfirmationV0,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
}

impl CoreDeliveredReplayLinkDV0 {
    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn session_id_v0(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn cursor_v0(&self) -> u64 {
        self.cursor
    }

    pub const fn source_validation_id_v0(&self) -> ValidationIdV0 {
        self.source_validation_id
    }

    pub const fn target_validation_id_v0(&self) -> ValidationIdV0 {
        self.target_validation_id
    }

    pub const fn core_delivery_v0(&self) -> CoreDeliveryConfirmationV0 {
        self.core_delivery
    }

    pub const fn owner_id_v0(&self) -> ProposalValidationOwnerIdV0 {
        self.owner_id
    }

    pub const fn artifact_digest_v0(&self) -> NonZeroDigestV0 {
        self.artifact_digest
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> NonZeroDigestV0 {
        self.row_checksum
    }
}

/// Linear authority for the same replay link after exact no-sign Safety
/// persistence was freshly confirmed (`C`).
#[derive(Debug)]
pub struct SafetyClosedReplayLinkCV0 {
    store_id: [u8; 32],
    session_id: [u8; 32],
    cursor: u64,
    source_validation_id: ValidationIdV0,
    target_validation_id: ValidationIdV0,
    owner_id: ProposalValidationOwnerIdV0,
    artifact_digest: NonZeroDigestV0,
    core_delivery: CoreDeliveryConfirmationV0,
    safety_revision: u64,
    safety_record_digest: NonZeroDigestV0,
    no_sign_closure_digest: NonZeroDigestV0,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
}

impl SafetyClosedReplayLinkCV0 {
    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn session_id_v0(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn cursor_v0(&self) -> u64 {
        self.cursor
    }

    pub const fn source_validation_id_v0(&self) -> ValidationIdV0 {
        self.source_validation_id
    }

    pub const fn target_validation_id_v0(&self) -> ValidationIdV0 {
        self.target_validation_id
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        self.safety_revision
    }

    pub const fn owner_id_v0(&self) -> ProposalValidationOwnerIdV0 {
        self.owner_id
    }

    pub const fn artifact_digest_v0(&self) -> NonZeroDigestV0 {
        self.artifact_digest
    }

    pub const fn core_delivery_v0(&self) -> CoreDeliveryConfirmationV0 {
        self.core_delivery
    }

    pub const fn safety_record_digest_v0(&self) -> NonZeroDigestV0 {
        self.safety_record_digest
    }

    pub const fn no_sign_closure_digest_v0(&self) -> NonZeroDigestV0 {
        self.no_sign_closure_digest
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> NonZeroDigestV0 {
        self.row_checksum
    }
}

/// Linear replay-link authority after the canonical source K and its exact
/// native application history row were freshly reconfirmed. This is the local
/// alias K and remains checkpoint-pending.
#[derive(Debug)]
pub struct AliasClosedReplayLinkKV0 {
    store_id: [u8; 32],
    session_id: [u8; 32],
    cursor: u64,
    source_validation_id: ValidationIdV0,
    target_validation_id: ValidationIdV0,
    owner_id: ProposalValidationOwnerIdV0,
    artifact_digest: NonZeroDigestV0,
    safety_revision: u64,
    alias_closure_checksum: NonZeroDigestV0,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
}

impl AliasClosedReplayLinkKV0 {
    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn session_id_v0(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn cursor_v0(&self) -> u64 {
        self.cursor
    }

    pub const fn source_validation_id_v0(&self) -> ValidationIdV0 {
        self.source_validation_id
    }

    pub const fn target_validation_id_v0(&self) -> ValidationIdV0 {
        self.target_validation_id
    }

    pub const fn alias_closure_checksum_v0(&self) -> NonZeroDigestV0 {
        self.alias_closure_checksum
    }

    pub const fn owner_id_v0(&self) -> ProposalValidationOwnerIdV0 {
        self.owner_id
    }

    pub const fn artifact_digest_v0(&self) -> NonZeroDigestV0 {
        self.artifact_digest
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        self.safety_revision
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> NonZeroDigestV0 {
        self.row_checksum
    }
}

/// Terminal cursor authority after the exact external checkpoint successor
/// was CASed, freshly read back, and atomically joined into the replay link and
/// session cursor.
#[derive(Debug)]
pub struct CheckpointedReplayLinkV0 {
    store_id: [u8; 32],
    session_id: [u8; 32],
    cursor: u64,
    source_validation_id: ValidationIdV0,
    target_validation_id: ValidationIdV0,
    owner_id: ProposalValidationOwnerIdV0,
    artifact_digest: NonZeroDigestV0,
    safety_revision: u64,
    checkpoint_scope: NonZeroDigestV0,
    checkpoint_profile_ref: NonZeroDigestV0,
    checkpoint_predecessor_checksum: NonZeroDigestV0,
    checkpoint_generation: u64,
    checkpoint_checksum: NonZeroDigestV0,
    row_revision: u64,
    row_checksum: NonZeroDigestV0,
}

impl CheckpointedReplayLinkV0 {
    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn session_id_v0(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn cursor_v0(&self) -> u64 {
        self.cursor
    }

    pub const fn source_validation_id_v0(&self) -> ValidationIdV0 {
        self.source_validation_id
    }

    pub const fn target_validation_id_v0(&self) -> ValidationIdV0 {
        self.target_validation_id
    }

    pub const fn owner_id_v0(&self) -> ProposalValidationOwnerIdV0 {
        self.owner_id
    }

    pub const fn artifact_digest_v0(&self) -> NonZeroDigestV0 {
        self.artifact_digest
    }

    pub const fn safety_revision_v0(&self) -> u64 {
        self.safety_revision
    }

    pub const fn checkpoint_scope_v0(&self) -> NonZeroDigestV0 {
        self.checkpoint_scope
    }

    pub const fn checkpoint_profile_ref_v0(&self) -> NonZeroDigestV0 {
        self.checkpoint_profile_ref
    }

    pub const fn checkpoint_predecessor_checksum_v0(&self) -> NonZeroDigestV0 {
        self.checkpoint_predecessor_checksum
    }

    pub const fn checkpoint_generation_v0(&self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn checkpoint_checksum_v0(&self) -> NonZeroDigestV0 {
        self.checkpoint_checksum
    }

    pub const fn row_revision_v0(&self) -> u64 {
        self.row_revision
    }

    pub const fn row_checksum_v0(&self) -> NonZeroDigestV0 {
        self.row_checksum
    }
}

#[derive(Debug)]
pub enum ReplayLinkReservationOutcomeV0 {
    Applied(ReservedReplayLinkPV0),
    Existing(ReservedReplayLinkPV0),
    NotApplied,
}

#[derive(Debug)]
pub enum ReplayLinkDeliveryOutcomeV0 {
    Applied(CoreDeliveredReplayLinkDV0),
    NotApplied(ReservedReplayLinkPV0),
}

#[derive(Debug)]
pub enum ReplayLinkSafetyOutcomeV0 {
    Applied(SafetyClosedReplayLinkCV0),
    NotApplied(CoreDeliveredReplayLinkDV0),
}

#[derive(Debug)]
pub enum ReplayLinkCheckpointOutcomeV0 {
    AppliedNext {
        link: CheckpointedReplayLinkV0,
        session: ActiveReplaySessionV0,
    },
    AppliedComplete {
        link: CheckpointedReplayLinkV0,
        session: DurableReplayCompleteV0,
    },
    NotApplied(AliasClosedReplayLinkKV0),
}

#[derive(Debug)]
pub enum ReplayLinkAliasCloseOutcomeV0 {
    Applied(AliasClosedReplayLinkKV0),
    NotApplied(SafetyClosedReplayLinkCV0),
}

#[derive(Debug)]
pub enum DeliverTransitionOutcomeV0 {
    Applied(DeliveredValidationV0),
    NotApplied(ReservedValidationV0),
}

#[derive(Debug)]
pub enum AckTransitionOutcomeV0 {
    Applied(AckedValidationV0),
    NotApplied(DeliveredValidationV0),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AccountingV0 {
    reserved: u64,
    delivered: u64,
    acked: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JobSnapshotV0 {
    binding: BindingRecordV0,
    owner_id: [u8; 32],
    artifact_digest: [u8; 32],
    artifact: Vec<u8>,
    stage: DurableValidationStageV0,
    confirmation: Option<ConfirmationRecordV0>,
    safety_confirmation: Option<SafetyConfirmationRecordV0>,
    row_revision: u64,
    row_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayMetadataV0 {
    sequence: u64,
    reserved: u64,
    core_delivered: u64,
    safety_closed: u64,
    alias_closed: u64,
    checkpointed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum DurableReplaySessionStateV0 {
    Active = 1,
    DurableReplayComplete = 2,
    ActivationReady = 3,
}

impl DurableReplaySessionStateV0 {
    fn from_i64(value: i64) -> ValidationStoreResultV0<Self> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::DurableReplayComplete),
            3 => Ok(Self::ActivationReady),
            _ => Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_session.state",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplaySessionSnapshotV0 {
    session_id: [u8; 32],
    core_config_ref: [u8; 32],
    validation_scope: [u8; 32],
    validation_store_id: [u8; 32],
    recovery_challenge_digest: [u8; 32],
    archive_context_digest: [u8; 32],
    archive_sequence: u64,
    archive_record_digest: [u8; 32],
    expected_count: u64,
    next_cursor: u64,
    canonical_store_sequence: u64,
    canonical_terminal_row_count: u64,
    canonical_terminal_audit_digest: [u8; 32],
    application_history_digest: [u8; 32],
    initial_safety_revision: u64,
    initial_safety_state_checksum: [u8; 32],
    initial_safety_chain_checksum: [u8; 32],
    initial_checkpoint_scope: [u8; 32],
    initial_checkpoint_profile_ref: [u8; 32],
    initial_checkpoint_generation: u64,
    initial_checkpoint_checksum: [u8; 32],
    signer_scope: [u8; 32],
    signer_journal_id: [u8; 32],
    signer_sequence: u64,
    signer_chain_checksum: [u8; 32],
    previous_progress_checksum: [u8; 32],
    state: DurableReplaySessionStateV0,
    activation_binding_digest: Option<[u8; 32]>,
    activation_source_row_revision: Option<u64>,
    activation_source_row_checksum: Option<[u8; 32]>,
    row_revision: u64,
    row_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplaySafetyClosureRecordV0 {
    core_delivery_digest: [u8; 32],
    safety_revision: u64,
    safety_record_digest: [u8; 32],
    no_sign_closure_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayCheckpointRecordV0 {
    scope: [u8; 32],
    profile_ref: [u8; 32],
    predecessor_checksum: [u8; 32],
    generation: u64,
    checksum: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayLinkSnapshotV0 {
    session_id: [u8; 32],
    cursor: u64,
    source_validation_id: ValidationIdV0,
    source_store_sequence: u64,
    source_application_history_checksum: [u8; 32],
    target_binding: BindingRecordV0,
    owner_id: [u8; 32],
    source_row_revision: u64,
    source_row_checksum: [u8; 32],
    artifact_digest: [u8; 32],
    previous_progress_checksum: [u8; 32],
    stage: DurableReplayLinkStageV0,
    confirmation: Option<ConfirmationRecordV0>,
    safety_closure: Option<ReplaySafetyClosureRecordV0>,
    alias_closure_checksum: Option<[u8; 32]>,
    checkpoint: Option<ReplayCheckpointRecordV0>,
    row_revision: u64,
    row_checksum: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableReplaySnapshotV0 {
    metadata: ReplayMetadataV0,
    session: Option<ReplaySessionSnapshotV0>,
    link: Option<ReplayLinkSnapshotV0>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfirmationRecordV0 {
    validation_id: [u8; 32],
    core_revision: u64,
    core_state_digest: [u8; 32],
    accepted_validation_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SafetyConfirmationRecordV0 {
    core_delivery_digest: [u8; 32],
    safety_revision: u64,
    safety_record_digest: [u8; 32],
    vote_intent_digest: [u8; 32],
}

impl From<RequestBoundSafetyConfirmationV0> for SafetyConfirmationRecordV0 {
    fn from(value: RequestBoundSafetyConfirmationV0) -> Self {
        Self {
            core_delivery_digest: *value.core_delivery_digest().as_bytes(),
            safety_revision: value.safety_revision(),
            safety_record_digest: *value.safety_record_digest().as_bytes(),
            vote_intent_digest: *value.vote_intent_digest().as_bytes(),
        }
    }
}

impl From<CoreDeliveryConfirmationV0> for ConfirmationRecordV0 {
    fn from(value: CoreDeliveryConfirmationV0) -> Self {
        Self {
            validation_id: *value.validation_id().as_bytes(),
            core_revision: value.core_revision(),
            core_state_digest: *value.core_state_digest().as_bytes(),
            accepted_validation_digest: *value.accepted_validation_digest().as_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableSnapshotV0 {
    sequence: u64,
    accounting: AccountingV0,
    job: Option<JobSnapshotV0>,
    outbox: Option<ConfirmationRecordV0>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolutionV0 {
    Source,
    Target,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestCommitFaultV0 {
    AppliedAckLost,
    #[cfg_attr(all(feature = "test-support", not(test)), allow(dead_code))]
    NotAppliedAckLost,
    #[cfg_attr(all(feature = "test-support", not(test)), allow(dead_code))]
    ThirdState,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentityV0 {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    mode: u32,
}

pub struct SqliteProposalValidationStoreV0 {
    path: PathBuf,
    scope: ProposalValidationStoreScopeV0,
    store_id: [u8; 32],
    connection: Option<Connection>,
    fenced: bool,
    owner_affinity: Arc<()>,
    #[cfg(unix)]
    file_identity: FileIdentityV0,
    #[cfg(any(test, feature = "test-support"))]
    next_commit_fault: Option<TestCommitFaultV0>,
}

impl SqliteProposalValidationStoreV0 {
    /// Canonical pinned database path for owner-affinity joins.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Inert namespace facts for a consuming Node-owner handoff.
    pub const fn scope_v0(&self) -> ProposalValidationStoreScopeV0 {
        self.scope
    }

    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub fn open(
        path: impl AsRef<Path>,
        scope: ProposalValidationStoreScopeV0,
        minimum_durable_sequence: u64,
    ) -> ValidationStoreResultV0<Self> {
        #[cfg(not(unix))]
        {
            let _ = (path.as_ref(), scope, minimum_durable_sequence);
            return Err(error(
                ValidationStoreErrorCodeV0::UnsupportedPlatform,
                "validation_store.platform",
            ));
        }

        #[cfg(unix)]
        {
            let (path, created) = prepare_store_file_v0(path.as_ref())?;
            let file_identity = read_file_identity_v0(&path)?;
            if !created {
                reject_existing_sqlite_sidecars_v0(&path)?;
                let read_only = open_read_only_connection_v0(&path)?;
                verify_schema_v0(&read_only)?;
                let store_id = initialize_or_load_metadata_v0(
                    &read_only,
                    &path,
                    scope,
                    false,
                    minimum_durable_sequence,
                )?;
                verify_metadata_v0(&read_only, scope, store_id, minimum_durable_sequence)?;
                audit_database_connection_v0(&read_only)?;
            }
            let connection = open_connection_v0(&path)?;
            if created {
                initialize_schema_v0(&connection)?;
            } else {
                verify_schema_v0(&connection)?;
            }
            let store_id = initialize_or_load_metadata_v0(
                &connection,
                &path,
                scope,
                created,
                minimum_durable_sequence,
            )?;
            let mut store = Self {
                path,
                scope,
                store_id,
                connection: Some(connection),
                fenced: false,
                owner_affinity: Arc::new(()),
                file_identity,
                #[cfg(any(test, feature = "test-support"))]
                next_commit_fault: None,
            };
            store.audit_database_v0()?;
            Ok(store)
        }
    }

    pub fn durable_sequence_v0(&mut self) -> ValidationStoreResultV0<u64> {
        self.ensure_ready_v0()?;
        load_sequence_v0(self.connection_v0()?)
    }

    pub fn replay_session_presence_v0(
        &mut self,
    ) -> ValidationStoreResultV0<ReplaySessionPresenceV0> {
        self.audit_database_v0()?;
        let Some(session) = load_replay_session_v0(self.connection_v0()?)? else {
            return Ok(ReplaySessionPresenceV0::None);
        };
        Ok(match session.state {
            DurableReplaySessionStateV0::Active => ReplaySessionPresenceV0::Active {
                session_id: session.session_id,
                next_cursor: session.next_cursor,
                expected_count: session.expected_count,
            },
            DurableReplaySessionStateV0::DurableReplayComplete => {
                ReplaySessionPresenceV0::DurableReplayComplete {
                    session_id: session.session_id,
                    expected_count: session.expected_count,
                }
            }
            DurableReplaySessionStateV0::ActivationReady => {
                ReplaySessionPresenceV0::ActivationReady {
                    session_id: session.session_id,
                    expected_count: session.expected_count,
                }
            }
        })
    }

    /// Re-audits the complete canonical and replay inventories, then returns
    /// one owner-affined readback of every immutable session field and every
    /// durable link stage.  It performs no transition and grants no cursor or
    /// activation authority.
    pub fn confirm_replay_inventory_v0(
        &mut self,
    ) -> ValidationStoreResultV0<ConfirmedReplayInventoryV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        let session = load_replay_session_v0(self.connection_v0()?)?.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "replay_inventory.session",
            )
        })?;
        let mut statement = self
            .connection_v0()?
            .prepare(
                "SELECT target_validation_id FROM proposal_validation_replay_links_v0
                 WHERE session_id = ?1 ORDER BY cursor",
            )
            .map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::Storage,
                    "replay_inventory.prepare",
                )
            })?;
        let rows = statement
            .query_map(params![session.session_id.as_slice()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::Storage,
                    "replay_inventory.query",
                )
            })?;
        let mut target_ids = Vec::new();
        for row in rows {
            target_ids.push(ValidationIdV0::from_bytes(vec_to_array_32_v0(
                row.map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "replay_inventory.target",
                    )
                })?,
                "replay_inventory.target",
            )?));
        }
        drop(statement);
        let mut links = Vec::with_capacity(target_ids.len());
        for target_id in target_ids {
            let link = load_replay_link_v0(self.connection_v0()?, target_id)?.ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_inventory.link",
                )
            })?;
            let confirmation = link.confirmation;
            let safety = link.safety_closure;
            let checkpoint = link.checkpoint;
            links.push(ReplayLinkFactsV0 {
                session_id: link.session_id,
                cursor: link.cursor,
                source_validation_id: link.source_validation_id,
                target_binding: ProposalValidationBindingV0::from_record(&link.target_binding)?,
                owner_id: ProposalValidationOwnerIdV0::new(link.owner_id)?,
                source_store_sequence: link.source_store_sequence,
                source_row_revision: link.source_row_revision,
                source_row_checksum: link.source_row_checksum,
                source_application_history_checksum: link.source_application_history_checksum,
                artifact_digest: link.artifact_digest,
                previous_progress_checksum: link.previous_progress_checksum,
                stage: link.stage,
                core_revision: confirmation.map(|value| value.core_revision),
                core_state_digest: confirmation.map(|value| value.core_state_digest),
                accepted_validation_digest: confirmation
                    .map(|value| value.accepted_validation_digest),
                safety_core_delivery_digest: safety.map(|value| value.core_delivery_digest),
                safety_revision: safety.map(|value| value.safety_revision),
                safety_record_digest: safety.map(|value| value.safety_record_digest),
                no_sign_closure_digest: safety.map(|value| value.no_sign_closure_digest),
                alias_closure_checksum: link.alias_closure_checksum,
                checkpoint_scope: checkpoint.map(|value| value.scope),
                checkpoint_profile_ref: checkpoint.map(|value| value.profile_ref),
                checkpoint_predecessor_checksum: checkpoint.map(|value| value.predecessor_checksum),
                checkpoint_generation: checkpoint.map(|value| value.generation),
                checkpoint_checksum: checkpoint.map(|value| value.checksum),
                progress_checksum: if link.stage == DurableReplayLinkStageV0::Checkpointed {
                    compute_replay_checkpoint_progress_v0(&link)
                } else {
                    None
                },
                row_revision: link.row_revision,
                row_checksum: link.row_checksum,
            });
        }
        let session_facts = ReplaySessionFactsV0 {
            session_id: session.session_id,
            core_config_ref: session.core_config_ref,
            validation_scope: session.validation_scope,
            validation_store_id: session.validation_store_id,
            recovery_challenge_digest: session.recovery_challenge_digest,
            archive_context_digest: session.archive_context_digest,
            archive_sequence: session.archive_sequence,
            archive_record_digest: session.archive_record_digest,
            expected_count: session.expected_count,
            next_cursor: session.next_cursor,
            canonical_store_sequence: session.canonical_store_sequence,
            canonical_terminal_row_count: session.canonical_terminal_row_count,
            canonical_terminal_audit_digest: session.canonical_terminal_audit_digest,
            application_history_digest: session.application_history_digest,
            initial_safety_revision: session.initial_safety_revision,
            initial_safety_state_checksum: session.initial_safety_state_checksum,
            initial_safety_chain_checksum: session.initial_safety_chain_checksum,
            initial_checkpoint_scope: session.initial_checkpoint_scope,
            initial_checkpoint_profile_ref: session.initial_checkpoint_profile_ref,
            initial_checkpoint_generation: session.initial_checkpoint_generation,
            initial_checkpoint_checksum: session.initial_checkpoint_checksum,
            signer_scope: session.signer_scope,
            signer_journal_id: session.signer_journal_id,
            signer_sequence: session.signer_sequence,
            signer_chain_checksum: session.signer_chain_checksum,
            previous_progress_checksum: session.previous_progress_checksum,
            durable_complete: session.state == DurableReplaySessionStateV0::DurableReplayComplete,
            activation_ready: session.state == DurableReplaySessionStateV0::ActivationReady,
            activation_binding_digest: session.activation_binding_digest,
            activation_source_row_revision: session.activation_source_row_revision,
            activation_source_row_checksum: session.activation_source_row_checksum,
            row_revision: session.row_revision,
            row_checksum: session.row_checksum,
        };
        Ok(ConfirmedReplayInventoryV0 {
            database_path: self.path.clone(),
            owner_affinity: Arc::clone(&self.owner_affinity),
            store_id: self.store_id,
            session: session_facts,
            links,
        })
    }

    /// Atomically advances one exact, fully checkpointed replay session from
    /// `DurableReplayComplete` to `ActivationReady`.
    ///
    /// The transition consumes an owner-affined complete inventory, freshly
    /// re-audits the same immutable session/link closure, and CASes the exact
    /// prior session revision/checksum in one SQLite transaction.  It does not
    /// activate Core or the signer and cannot arm the retained timer.
    pub fn confirm_replay_activation_ready_v0(
        &mut self,
        inventory: ConfirmedReplayInventoryV0,
        binding: ReplayActivationBindingV0,
    ) -> ValidationStoreResultV0<ConfirmedReplayActivationReadyV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        if !inventory.belongs_to_store_at_path_v0(self, &self.path) {
            return Err(error(
                ValidationStoreErrorCodeV0::ForeignToken,
                "replay_activation.inventory_owner",
            ));
        }
        let fresh = self.confirm_replay_inventory_v0()?;
        if fresh.session != inventory.session || fresh.links != inventory.links {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_activation.fresh_inventory",
            ));
        }
        let session = fresh.session;
        let last = fresh.links.last().ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "replay_activation.last_link",
            )
        })?;
        let expected_safety_revision = session
            .initial_safety_revision
            .checked_add(session.expected_count.checked_mul(2).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_activation.safety_span",
                )
            })?)
            .ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_activation.safety_revision",
                )
            })?;
        let expected_checkpoint_generation = session
            .initial_checkpoint_generation
            .checked_add(session.expected_count)
            .ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_activation.checkpoint_generation",
                )
            })?;
        if (!session.is_durable_complete_v0() && !session.is_activation_ready_v0())
            || session.next_cursor != session.expected_count
            || u64::try_from(fresh.links.len()).ok() != Some(session.expected_count)
            || fresh
                .links
                .iter()
                .any(|link| link.stage != DurableReplayLinkStageV0::Checkpointed)
            || binding.session_id_v0() != session.session_id
            || binding.application_history_digest_v0() != session.application_history_digest
            || binding.safety_revision_v0() != expected_safety_revision
            || binding.checkpoint_generation_v0() != expected_checkpoint_generation
            || binding.checkpoint_checksum_v0()
                != last.checkpoint_checksum.ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "replay_activation.last_checkpoint",
                    )
                })?
            || binding.signer_scope_v0() != session.signer_scope
            || binding.signer_journal_id_v0() != session.signer_journal_id
            || binding.signer_sequence_v0() != session.signer_sequence
            || binding.signer_chain_checksum_v0() != session.signer_chain_checksum
            || binding.application_parent_block_id_v0()
                != *last.target_binding.block_id().as_bytes()
            || binding.application_parent_height_v0() != last.target_binding.height().get()
            || binding.application_parent_state_root_v0()
                != *last
                    .target_binding
                    .commitments()
                    .post_state_root()
                    .as_bytes()
            || binding.binding_digest_v0() != compute_replay_activation_binding_v0(&binding)
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_activation.binding",
            ));
        }
        if session.is_activation_ready_v0() {
            if session.activation_binding_digest != Some(binding.binding_digest_v0())
                || session.activation_source_row_revision.is_none()
                || session.activation_source_row_checksum.is_none()
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::Duplicate,
                    "replay_activation.existing_conflict",
                ));
            }
            return replay_activation_ready_token_v0(
                self,
                binding,
                session.row_revision,
                session.row_checksum,
            );
        }

        let source = load_replay_session_v0(self.connection_v0()?)?.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "replay_activation.session",
            )
        })?;
        if source.row_revision != session.row_revision
            || source.row_checksum != session.row_checksum
            || source.state != DurableReplaySessionStateV0::DurableReplayComplete
            || source.activation_binding_digest.is_some()
            || source.activation_source_row_revision.is_some()
            || source.activation_source_row_checksum.is_some()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::InvalidTransition,
                "replay_activation.source",
            ));
        }
        let mut target = source.clone();
        target.state = DurableReplaySessionStateV0::ActivationReady;
        target.activation_binding_digest = Some(binding.binding_digest_v0());
        target.activation_source_row_revision = Some(source.row_revision);
        target.activation_source_row_checksum = Some(source.row_checksum);
        target.row_revision = target.row_revision.checked_add(1).ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::Overflow,
                "replay_activation.row_revision",
            )
        })?;
        target.row_checksum = compute_replay_session_checksum_v0(&target);

        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;
        let uncertain = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "replay_activation.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "replay_activation.begin",
                    )
                })?;
            let transactional_source = load_replay_session_v0(&transaction)?.ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "replay_activation.transaction_source",
                )
            })?;
            if transactional_source != source {
                return Err(error(
                    ValidationStoreErrorCodeV0::InvalidTransition,
                    "replay_activation.transaction_cas",
                ));
            }
            replace_replay_session_v0(&transaction, &source, &target)?;
            finish_transaction_v0(transaction, fault)?
        };
        if uncertain {
            self.discard_connection_v0();
            #[cfg(any(test, feature = "test-support"))]
            if matches!(fault, Some(TestCommitFaultV0::ThirdState)) {
                corrupt_replay_activation_target_for_test_v0(&self.path)?;
            }
            let observed = self.load_replay_session_fresh_v0().map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "replay_activation.readback",
                )
            })?;
            match observed {
                Some(observed) if observed == target => {}
                Some(observed) if observed == source => {
                    return Err(error(
                        ValidationStoreErrorCodeV0::CommitUncertain,
                        "replay_activation.not_applied",
                    ));
                }
                _ => {
                    return Err(error(
                        ValidationStoreErrorCodeV0::CommitUncertain,
                        "replay_activation.third_state",
                    ));
                }
            }
        }
        self.verify_replay_session_fresh_v0(&target)?;
        replay_activation_ready_token_v0(self, binding, target.row_revision, target.row_checksum)
    }

    /// Freshly re-audits one checkpointed replay link and reissues its exact
    /// durable Core-delivery fact.  The caller must retain the non-cloneable,
    /// owner-affined inventory minted by this same live store; public scalar
    /// replay facts cannot mint this carrier.
    pub fn confirm_checkpointed_replay_core_delivery_v0(
        &mut self,
        inventory: &ConfirmedReplayInventoryV0,
        cursor: u64,
        expected_target: &ProposalValidationBindingV0,
    ) -> ValidationStoreResultV0<CoreDeliveryConfirmationV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        #[cfg(not(unix))]
        {
            let _ = (inventory, cursor, expected_target);
            Err(error(
                ValidationStoreErrorCodeV0::UnsupportedPlatform,
                "replay_core_delivery.platform",
            ))
        }
        #[cfg(unix)]
        {
            if !Arc::ptr_eq(&inventory.owner_affinity, &self.owner_affinity)
                || inventory.database_path != self.path
                || inventory.store_id != self.store_id
                || read_file_identity_v0(&self.path)? != self.file_identity
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::ForeignToken,
                    "replay_core_delivery.owner_affinity",
                ));
            }
            let session = load_replay_session_v0(self.connection_v0()?)?.ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "replay_core_delivery.session",
                )
            })?;
            if session.session_id != inventory.session.session_id
                || session.validation_store_id != self.store_id
                || session.row_revision != inventory.session.row_revision
                || session.row_checksum != inventory.session.row_checksum
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_core_delivery.session_join",
                ));
            }
            let projected = inventory
                .links
                .iter()
                .find(|link| link.cursor == cursor)
                .ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::NotFound,
                        "replay_core_delivery.inventory_link",
                    )
                })?;
            if projected.stage != DurableReplayLinkStageV0::Checkpointed
                || &projected.target_binding != expected_target
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::InvalidTransition,
                    "replay_core_delivery.inventory_stage",
                ));
            }
            let fresh =
                load_replay_link_by_cursor_v0(self.connection_v0()?, session.session_id, cursor)?
                    .ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::NotFound,
                        "replay_core_delivery.fresh_link",
                    )
                })?;
            let fresh_target = ProposalValidationBindingV0::from_record(&fresh.target_binding)?;
            let confirmation = fresh.confirmation.ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_core_delivery.confirmation",
                )
            })?;
            if fresh.stage != DurableReplayLinkStageV0::Checkpointed
                || fresh.session_id != session.session_id
                || fresh.cursor != cursor
                || fresh_target != *expected_target
                || fresh.row_revision != projected.row_revision
                || fresh.row_checksum != projected.row_checksum
                || projected.core_revision != Some(confirmation.core_revision)
                || projected.core_state_digest != Some(confirmation.core_state_digest)
                || projected.accepted_validation_digest
                    != Some(confirmation.accepted_validation_digest)
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_core_delivery.fresh_join",
                ));
            }
            CoreDeliveryConfirmationV0::new(
                expected_target.validation_id(),
                confirmation.core_revision,
                NonZeroDigestV0::new(confirmation.core_state_digest)?,
                NonZeroDigestV0::new(confirmation.accepted_validation_digest)?,
            )
        }
    }

    /// Reopens the pinned database read-only and audits the complete terminal
    /// `K` population before returning its maximum persisted proposal height.
    /// A partial P/D transition, callback outbox, mixed owner, sequence/count
    /// mismatch, empty store, or concurrent/replaced-store observation is
    /// rejected rather than normalized into terminal evidence.
    pub fn confirm_terminal_k_audit_v0(
        &mut self,
    ) -> ValidationStoreResultV0<ConfirmedProposalValidationTerminalAuditV0> {
        self.ensure_ready_v0()?;
        #[cfg(not(unix))]
        {
            return Err(error(
                ValidationStoreErrorCodeV0::UnsupportedPlatform,
                "terminal_k_audit.platform",
            ));
        }
        #[cfg(unix)]
        {
            let identity_before = read_file_identity_v0(&self.path)?;
            if identity_before != self.file_identity {
                return Err(error(
                    ValidationStoreErrorCodeV0::ReplacedStore,
                    "terminal_k_audit.file_identity_before",
                ));
            }
            let connection = open_fresh_terminal_read_connection_v0(&self.path)?;
            verify_schema_v0(&connection)?;
            verify_metadata_v0(&connection, self.scope, self.store_id, 0)?;
            audit_database_connection_v0(&connection)?;

            let store_sequence = load_sequence_v0(&connection)?;
            let accounting = load_accounting_v0(&connection)?;
            let mut statement = connection
                .prepare(
                    "SELECT validation_id FROM proposal_validation_jobs_v0 ORDER BY validation_id",
                )
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "terminal_k_audit.prepare",
                    )
                })?;
            let ids = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "terminal_k_audit.query",
                    )
                })?;
            let mut owner_id = None;
            let mut terminal_row_count = 0u64;
            let mut maximum_terminal_height = 0u64;
            let mut terminal_bindings = Vec::new();
            for id in ids {
                let id = vec_to_array_32_v0(
                    id.map_err(|_| {
                        error(
                            ValidationStoreErrorCodeV0::Storage,
                            "terminal_k_audit.validation_id",
                        )
                    })?,
                    "terminal_k_audit.validation_id",
                )?;
                let snapshot =
                    load_durable_snapshot_v0(&connection, ValidationIdV0::from_bytes(id))?;
                let job = snapshot.job.ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "terminal_k_audit.missing_job",
                    )
                })?;
                if snapshot.sequence != store_sequence
                    || job.stage != DurableValidationStageV0::Acked
                    || snapshot.outbox.is_some()
                    || job.row_revision == 0
                    || job.row_revision > store_sequence
                {
                    return Err(error(
                        ValidationStoreErrorCodeV0::BindingMismatch,
                        "terminal_k_audit.nonterminal_job",
                    ));
                }
                let binding = ProposalValidationBindingV0::from_record(&job.binding)?;
                let observed_owner = ProposalValidationOwnerIdV0::new(job.owner_id)?;
                if owner_id.is_some_and(|expected| expected != observed_owner) {
                    return Err(error(
                        ValidationStoreErrorCodeV0::BindingMismatch,
                        "terminal_k_audit.mixed_owner",
                    ));
                }
                owner_id = Some(observed_owner);
                terminal_bindings.push(binding.clone());
                terminal_row_count = terminal_row_count.checked_add(1).ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::Overflow,
                        "terminal_k_audit.row_count",
                    )
                })?;
                maximum_terminal_height = maximum_terminal_height.max(binding.height().get());
            }
            drop(statement);

            let expected_sequence = terminal_row_count.checked_mul(3).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "terminal_k_audit.expected_sequence",
                )
            })?;
            if terminal_row_count == 0
                || maximum_terminal_height == 0
                || accounting.reserved != 0
                || accounting.delivered != 0
                || accounting.acked != terminal_row_count
                || store_sequence != expected_sequence
                || load_sequence_v0(&connection)? != store_sequence
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "terminal_k_audit.accounting",
                ));
            }
            let owner_id = owner_id.ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "terminal_k_audit.owner",
                )
            })?;
            let identity_after = read_file_identity_v0(&self.path)?;
            if identity_after != identity_before || identity_after != self.file_identity {
                return Err(error(
                    ValidationStoreErrorCodeV0::ReplacedStore,
                    "terminal_k_audit.file_identity_after",
                ));
            }
            let terminal_audit_digest = compute_terminal_audit_digest_v0(
                &connection,
                self.scope,
                self.store_id,
                store_sequence,
                terminal_row_count,
            )?;
            Ok(ConfirmedProposalValidationTerminalAuditV0 {
                database_path: self.path.clone(),
                owner_affinity: Arc::clone(&self.owner_affinity),
                scope: self.scope,
                store_id: self.store_id,
                owner_id,
                store_sequence,
                terminal_row_count,
                maximum_terminal_height,
                terminal_audit_digest,
                terminal_bindings,
            })
        }
    }

    /// Creates the durable `O` boundary for one exact authenticated process2
    /// replay. The source canonical inventory is freshly re-audited and bound
    /// into the session row; canonical jobs, outbox, accounting, and sequence
    /// are never modified.
    pub fn begin_replay_session_v0(
        &mut self,
        terminal_audit: ConfirmedProposalValidationTerminalAuditV0,
        plan: ReplaySessionPlanV0,
    ) -> ValidationStoreResultV0<ReplaySessionOpenOutcomeV0> {
        self.ensure_ready_v0()?;
        if !terminal_audit.belongs_to_store_at_path_v0(self, &self.path)
            || terminal_audit.scope != self.scope
            || terminal_audit.store_id != self.store_id
            || terminal_audit.terminal_row_count == 0
        {
            return Err(error(
                ValidationStoreErrorCodeV0::ForeignToken,
                "replay_session.open_audit",
            ));
        }
        let fresh_audit = self.confirm_terminal_k_audit_v0()?;
        if fresh_audit.store_sequence != terminal_audit.store_sequence
            || fresh_audit.terminal_row_count != terminal_audit.terminal_row_count
            || fresh_audit.terminal_audit_digest != terminal_audit.terminal_audit_digest
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_session.fresh_audit",
            ));
        }
        let mut target =
            replay_session_from_plan_v0(self.scope, self.store_id, &fresh_audit, plan)?;
        target.row_checksum = compute_replay_session_checksum_v0(&target);
        let store_id = self.store_id;
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;

        let (source, uncertain, existed) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "replay_session.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_session.begin"))?;
            let source = load_replay_session_v0(&transaction)?;
            if let Some(existing) = source.as_ref() {
                if existing != &target || existing.state != DurableReplaySessionStateV0::Active {
                    return Err(error(
                        ValidationStoreErrorCodeV0::Duplicate,
                        "replay_session.conflict",
                    ));
                }
                (source, false, true)
            } else {
                let metadata = load_replay_metadata_v0(&transaction)?;
                if metadata
                    != (ReplayMetadataV0 {
                        sequence: 0,
                        reserved: 0,
                        core_delivered: 0,
                        safety_closed: 0,
                        alias_closed: 0,
                        checkpointed: 0,
                    })
                    || count_replay_links_v0(&transaction)? != 0
                {
                    return Err(error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "replay_session.preexisting_links",
                    ));
                }
                insert_replay_session_v0(&transaction, &target)?;
                let uncertain = finish_transaction_v0(transaction, fault)?;
                (source, uncertain, false)
            }
        };

        if uncertain {
            self.discard_connection_v0();
            let observed = self.load_replay_session_fresh_v0()?;
            match (source, observed) {
                (None, None) => return Ok(ReplaySessionOpenOutcomeV0::NotApplied),
                (None, Some(observed)) if observed == target => {}
                _ => {
                    return Err(error(
                        ValidationStoreErrorCodeV0::CommitUncertain,
                        "replay_session.third_state",
                    ));
                }
            }
        }
        self.verify_replay_session_fresh_v0(&target)?;
        let token = active_replay_session_token_v0(store_id, &target)?;
        if existed {
            Ok(ReplaySessionOpenOutcomeV0::Existing(token))
        } else {
            Ok(ReplaySessionOpenOutcomeV0::Applied(token))
        }
    }

    /// Reopens an existing session from the immutable authenticated plan and
    /// complete canonical audit. It never re-runs `O` and returns the exact
    /// durable cursor frontier or a distinct all-links-complete carrier. A
    /// mid-link crash returns the exact non-cloneable stage authority rather
    /// than asking the caller to reconstruct P/D/C/alias-K from inert rows.
    pub fn resume_replay_session_v0(
        &mut self,
        terminal_audit: ConfirmedProposalValidationTerminalAuditV0,
        plan: ReplaySessionPlanV0,
    ) -> ValidationStoreResultV0<ReplaySessionResumeOutcomeV0> {
        self.ensure_ready_v0()?;
        if !terminal_audit.belongs_to_store_at_path_v0(self, &self.path) {
            return Err(error(
                ValidationStoreErrorCodeV0::ForeignToken,
                "replay_session_resume.audit",
            ));
        }
        self.audit_database_v0()?;
        let expected =
            replay_session_from_plan_v0(self.scope, self.store_id, &terminal_audit, plan)?;
        let observed = load_replay_session_v0(self.connection_v0()?)?.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "replay_session_resume.missing",
            )
        })?;
        if observed.session_id != expected.session_id
            || observed.canonical_store_sequence != terminal_audit.store_sequence
            || observed.canonical_terminal_row_count != terminal_audit.terminal_row_count
            || observed.canonical_terminal_audit_digest
                != *terminal_audit.terminal_audit_digest.as_bytes()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_session_resume.immutable_plan",
            ));
        }
        self.verify_replay_session_fresh_v0(&observed)?;
        match observed.state {
            DurableReplaySessionStateV0::Active => {
                let Some(frontier) = load_replay_link_by_cursor_v0(
                    self.connection_v0()?,
                    observed.session_id,
                    observed.next_cursor,
                )?
                else {
                    return Ok(ReplaySessionResumeOutcomeV0::Ready(
                        active_replay_session_token_v0(self.store_id, &observed)?,
                    ));
                };
                match frontier.stage {
                    DurableReplayLinkStageV0::Reserved => {
                        Ok(ReplaySessionResumeOutcomeV0::Reserved(
                            reserved_replay_token_v0(self.store_id, &frontier)?,
                        ))
                    }
                    DurableReplayLinkStageV0::CoreDelivered => {
                        Ok(ReplaySessionResumeOutcomeV0::CoreDelivered(
                            delivered_replay_token_v0(self.store_id, &frontier)?,
                        ))
                    }
                    DurableReplayLinkStageV0::SafetyClosed => {
                        Ok(ReplaySessionResumeOutcomeV0::SafetyClosed(
                            safety_closed_replay_token_v0(self.store_id, &frontier)?,
                        ))
                    }
                    DurableReplayLinkStageV0::AliasClosed => {
                        Ok(ReplaySessionResumeOutcomeV0::AliasClosed(
                            alias_closed_replay_token_v0(self.store_id, &frontier)?,
                        ))
                    }
                    DurableReplayLinkStageV0::Checkpointed => Err(error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "replay_session_resume.checkpointed_frontier",
                    )),
                }
            }
            DurableReplaySessionStateV0::DurableReplayComplete
            | DurableReplaySessionStateV0::ActivationReady => {
                Ok(ReplaySessionResumeOutcomeV0::DurableReplayComplete(
                    durable_replay_complete_token_v0(self.store_id, &observed)?,
                ))
            }
        }
    }

    pub fn reserve_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
        owner_id: ProposalValidationOwnerIdV0,
        executed: &NativeExecutedBlockV0,
    ) -> ValidationStoreResultV0<ReservationOutcomeV0> {
        self.ensure_ready_v0()?;
        require_artifact_matches_binding_v0(binding, executed)?;
        let artifact = encode_native_executed_block_artifact_v0(executed).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::InvalidBinding,
                "reserve.artifact_encode",
            )
        })?;
        let artifact_digest = artifact_digest_v0(&artifact)?;
        let validation_id = binding.validation_id();
        let store_id = self.store_id;
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;

        let (source, target, uncertain) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "reserve.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "reserve.begin"))?;
            let source = load_durable_snapshot_v0(&transaction, validation_id)?;
            if source.job.is_some() {
                return Err(error(
                    ValidationStoreErrorCodeV0::Duplicate,
                    "reserve.validation_id",
                ));
            }
            let next_sequence = source
                .sequence
                .checked_add(1)
                .ok_or_else(|| error(ValidationStoreErrorCodeV0::Overflow, "reserve.sequence"))?;
            let accounting = AccountingV0 {
                reserved: source.accounting.reserved.checked_add(1).ok_or_else(|| {
                    error(ValidationStoreErrorCodeV0::Overflow, "reserve.accounting")
                })?,
                ..source.accounting
            };
            let mut job = JobSnapshotV0 {
                binding: binding.to_record(),
                owner_id: *owner_id.as_bytes(),
                artifact_digest: *artifact_digest.as_bytes(),
                artifact,
                stage: DurableValidationStageV0::Reserved,
                confirmation: None,
                safety_confirmation: None,
                row_revision: next_sequence,
                row_checksum: [0; 32],
            };
            job.row_checksum = compute_row_checksum_v0(&job);
            insert_job_v0(&transaction, &job)?;
            update_sequence_v0(&transaction, source.sequence, next_sequence)?;
            update_accounting_v0(&transaction, source.accounting, accounting)?;
            let target = DurableSnapshotV0 {
                sequence: next_sequence,
                accounting,
                job: Some(job),
                outbox: None,
            };
            let uncertain = finish_transaction_v0(transaction, fault)?;
            (source, target, uncertain)
        };

        if uncertain {
            self.discard_connection_v0();
            #[cfg(any(test, feature = "test-support"))]
            if matches!(fault, Some(TestCommitFaultV0::ThirdState)) {
                corrupt_target_for_test_v0(&self.path, validation_id)?;
            }
            match self.resolve_uncertain_v0(&source, &target, validation_id)? {
                ResolutionV0::Source => return Ok(ReservationOutcomeV0::NotApplied),
                ResolutionV0::Target => {}
            }
        }

        let job = target
            .job
            .as_ref()
            .expect("reserve target must contain job");
        let token = ReservedValidationV0 {
            store_id,
            validation_id,
            owner_id,
            artifact_digest,
            row_revision: job.row_revision,
        };
        self.verify_durable_target_fresh_v0(&target, validation_id)?;
        Ok(ReservationOutcomeV0::Applied(token))
    }

    /// Atomically binds one canonical terminal application `K` to the exact
    /// live Core-issued Synced validation generation without creating another
    /// canonical validation job.
    ///
    /// The replay link retains the source validation id and terminal row
    /// checksum, exact target binding, source-owned artifact digest, and owner.
    /// A source-row mutation, a forked edge, a canonical target row, or a
    /// partial/conflicting retry fails closed. Canonical job accounting and
    /// terminal inventory are not mutated.
    pub fn reserve_synced_replay_link_v0(
        &mut self,
        session: ActiveReplaySessionV0,
        prior: ConfirmedProposalValidationCheckpointFactsV0,
        source_application_history_checksum: NonZeroDigestV0,
        binding: &ProposalValidationBindingV0,
        expected_owner: ProposalValidationOwnerIdV0,
    ) -> ValidationStoreResultV0<ReplayLinkReservationOutcomeV0> {
        self.ensure_ready_v0()?;
        if !prior.belongs_to_store_at_path_v0(self, &self.path) {
            return Err(error(
                ValidationStoreErrorCodeV0::ForeignToken,
                "replay_link_reserve.source_owner",
            ));
        }
        let fresh = self.reconfirm_proposal_validation_checkpoint_facts_exact_v0(&prior)?;
        let source_binding = fresh.binding.clone();
        if fresh.owner_id != expected_owner
            || !same_replay_edge_v0(&source_binding, binding)
            || source_binding.route() != ProposalRouteV0::Proposal
            || binding.route() != ProposalRouteV0::Synced
            || binding.generation() <= source_binding.generation()
            || binding.validation_id() == source_binding.validation_id()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_link_reserve.exact_edge",
            ));
        }

        let source_validation_id = source_binding.validation_id();
        let target_validation_id = binding.validation_id();
        if session.store_id != self.store_id || session.next_cursor >= session.expected_count {
            return Err(error(
                ValidationStoreErrorCodeV0::ForeignToken,
                "replay_link_reserve.session_token",
            ));
        }
        let source_row_revision = fresh.row_revision;
        let source_row_checksum = *fresh.row_checksum.as_bytes();
        let artifact_digest = *fresh.artifact_digest.as_bytes();
        let source_store_sequence = fresh.store_sequence;
        let source_application_history_checksum = *source_application_history_checksum.as_bytes();
        let store_id = self.store_id;
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;

        let (source, target, uncertain, existed) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "replay_link_reserve.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "replay_link_reserve.begin",
                    )
                })?;
            let durable_session = load_replay_session_v0(&transaction)?.ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "replay_link_reserve.session",
                )
            })?;
            require_active_replay_session_token_v0(&durable_session, &session)?;
            if durable_session.canonical_store_sequence != source_store_sequence {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_link_reserve.canonical_sequence",
                ));
            }
            let source_job = load_durable_snapshot_v0(&transaction, source_validation_id)?;
            require_exact_replay_source_k_v0(&source_job, &fresh, &source_binding, expected_owner)?;
            let canonical_target = load_durable_snapshot_v0(&transaction, target_validation_id)?;
            if canonical_target.job.is_some() || canonical_target.outbox.is_some() {
                return Err(error(
                    ValidationStoreErrorCodeV0::Duplicate,
                    "replay_link_reserve.canonical_target",
                ));
            }
            let source = load_durable_replay_snapshot_v0(&transaction, target_validation_id)?;
            if let Some(existing) = source.link.as_ref() {
                let expected = ReplayLinkSnapshotV0 {
                    session_id: session.session_id,
                    cursor: session.next_cursor,
                    source_validation_id,
                    source_store_sequence,
                    source_application_history_checksum,
                    target_binding: binding.to_record(),
                    owner_id: *expected_owner.as_bytes(),
                    source_row_revision,
                    source_row_checksum,
                    artifact_digest,
                    previous_progress_checksum: *session.previous_progress_checksum.as_bytes(),
                    stage: DurableReplayLinkStageV0::Reserved,
                    confirmation: None,
                    safety_closure: None,
                    alias_closure_checksum: None,
                    checkpoint: None,
                    row_revision: existing.row_revision,
                    row_checksum: existing.row_checksum,
                };
                if existing != &expected
                    || existing.row_checksum != compute_replay_link_checksum_v0(existing)
                {
                    return Err(error(
                        ValidationStoreErrorCodeV0::Duplicate,
                        "replay_link_reserve.target_conflict",
                    ));
                }
                (source.clone(), source, false, true)
            } else {
                let next_sequence = source.metadata.sequence.checked_add(1).ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::Overflow,
                        "replay_link_reserve.sequence",
                    )
                })?;
                let mut metadata = source.metadata;
                metadata.sequence = next_sequence;
                metadata.reserved = metadata.reserved.checked_add(1).ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::Overflow,
                        "replay_link_reserve.accounting",
                    )
                })?;
                let mut link = ReplayLinkSnapshotV0 {
                    session_id: session.session_id,
                    cursor: session.next_cursor,
                    source_validation_id,
                    source_store_sequence,
                    source_application_history_checksum,
                    target_binding: binding.to_record(),
                    owner_id: *expected_owner.as_bytes(),
                    source_row_revision,
                    source_row_checksum,
                    artifact_digest,
                    previous_progress_checksum: *session.previous_progress_checksum.as_bytes(),
                    stage: DurableReplayLinkStageV0::Reserved,
                    confirmation: None,
                    safety_closure: None,
                    alias_closure_checksum: None,
                    checkpoint: None,
                    row_revision: next_sequence,
                    row_checksum: [0; 32],
                };
                link.row_checksum = compute_replay_link_checksum_v0(&link);
                insert_replay_link_v0(&transaction, &link)?;
                update_replay_metadata_v0(&transaction, source.metadata, metadata)?;
                let target = DurableReplaySnapshotV0 {
                    metadata,
                    session: source.session.clone(),
                    link: Some(link),
                };
                let uncertain = finish_transaction_v0(transaction, fault)?;
                (source, target, uncertain, false)
            }
        };

        if uncertain {
            self.discard_connection_v0();
            match self.resolve_replay_uncertain_v0(&source, &target, target_validation_id)? {
                ResolutionV0::Source => {
                    return Ok(ReplayLinkReservationOutcomeV0::NotApplied);
                }
                ResolutionV0::Target => {}
            }
        }

        self.verify_replay_target_fresh_v0(&target, target_validation_id)?;
        let link = target
            .link
            .as_ref()
            .expect("replay-link reserve target must contain P");
        let token = reserved_replay_token_v0(store_id, link)?;
        if existed {
            Ok(ReplayLinkReservationOutcomeV0::Existing(token))
        } else {
            Ok(ReplayLinkReservationOutcomeV0::Applied(token))
        }
    }

    /// Reads the canonical source artifact through one exact replay-link P.
    /// No target canonical job exists and no artifact bytes are duplicated.
    pub fn read_replay_artifact_exact_v0(
        &mut self,
        reserved: &ReservedReplayLinkPV0,
        target_binding: &ProposalValidationBindingV0,
    ) -> ValidationStoreResultV0<NativeExecutedBlockV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        let link = load_replay_link_v0(self.connection_v0()?, reserved.target_validation_id)?
            .ok_or_else(|| error(ValidationStoreErrorCodeV0::NotFound, "replay_artifact.link"))?;
        require_reserved_replay_token_v0(self.store_id, &link, reserved)?;
        if link.target_binding != target_binding.to_record() {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_artifact.target_binding",
            ));
        }
        let source = load_durable_snapshot_v0(self.connection_v0()?, link.source_validation_id)?;
        let job = source.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "replay_artifact.source_k",
            )
        })?;
        if source.sequence != link.source_store_sequence
            || source.outbox.is_some()
            || job.stage != DurableValidationStageV0::Acked
            || job.row_revision != link.source_row_revision
            || job.row_checksum != link.source_row_checksum
            || job.artifact_digest != link.artifact_digest
            || job.owner_id != link.owner_id
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_artifact.source_freshness",
            ));
        }
        let executed =
            decode_checked_artifact_v0(&job.binding, &job.artifact, job.artifact_digest)?;
        require_artifact_matches_binding_v0(target_binding, &executed)?;
        Ok(executed)
    }

    /// Advances replay-link P to D from the exact non-forgeable Core accepted
    /// carrier without touching the canonical source K or callback outbox.
    pub fn deliver_replay_core_accepted_v0(
        &mut self,
        reserved: ReservedReplayLinkPV0,
        binding: &ProposalValidationBindingV0,
        accepted: &CoreAcceptedApplicationValidDV0,
    ) -> ValidationStoreResultV0<ReplayLinkDeliveryOutcomeV0> {
        self.ensure_ready_v0()?;
        let accepted_id = accepted.validation_id_v0();
        if binding.validation_id() != reserved.target_validation_id
            || binding.route() != ProposalRouteV0::Synced
            || accepted.route_v0() != PayloadValidationRouteV0::Synced
            || accepted_id.block_id().as_bytes() != binding.block_id().as_bytes()
            || accepted_id.view().get() != binding.view()
            || accepted_id.generation() != binding.generation()
            || accepted.completion_revision_v0() == 0
            || accepted.barrier_v0().get() != accepted.completion_revision_v0()
            || accepted.persistence_request_v0().state().revision()
                != accepted.completion_revision_v0()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_deliver.core_binding",
            ));
        }
        let core_delivery = CoreDeliveryConfirmationV0::new(
            binding.validation_id(),
            accepted.completion_revision_v0(),
            NonZeroDigestV0::new(accepted.delivery_digest_v0())?,
            NonZeroDigestV0::new(accepted.valid_result_checksum_v0())?,
        )?;
        let target_id = binding.validation_id();
        let store_id = self.store_id;
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;
        let (source, target, uncertain) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "replay_deliver.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_deliver.begin"))?;
            let source = load_durable_replay_snapshot_v0(&transaction, target_id)?;
            let source_link = source.link.as_ref().ok_or_else(|| {
                error(ValidationStoreErrorCodeV0::NotFound, "replay_deliver.link")
            })?;
            require_reserved_replay_token_v0(store_id, source_link, &reserved)?;
            let replay_session = source.session.as_ref().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "replay_deliver.session",
                )
            })?;
            if replay_session.state != DurableReplaySessionStateV0::Active
                || replay_session.session_id != source_link.session_id
                || replay_session.next_cursor != source_link.cursor
                || source_link.target_binding != binding.to_record()
                || core_delivery.core_revision()
                    != expected_replay_safety_closure_revision_v0(
                        replay_session,
                        source_link.cursor,
                    )?
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_deliver.target_binding",
                ));
            }
            let next_sequence = source.metadata.sequence.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_deliver.sequence",
                )
            })?;
            let mut metadata = source.metadata;
            metadata.sequence = next_sequence;
            metadata.core_delivered = metadata.core_delivered.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_deliver.accounting",
                )
            })?;
            let mut link = source_link.clone();
            link.stage = DurableReplayLinkStageV0::CoreDelivered;
            link.confirmation = Some(core_delivery.into());
            link.row_revision = next_sequence;
            link.row_checksum = compute_replay_link_checksum_v0(&link);
            replace_replay_link_v0(&transaction, source_link, &link)?;
            update_replay_metadata_v0(&transaction, source.metadata, metadata)?;
            let target = DurableReplaySnapshotV0 {
                metadata,
                session: source.session.clone(),
                link: Some(link),
            };
            let uncertain = finish_transaction_v0(transaction, fault)?;
            (source, target, uncertain)
        };
        if uncertain {
            self.discard_connection_v0();
            match self.resolve_replay_uncertain_v0(&source, &target, target_id)? {
                ResolutionV0::Source => {
                    return Ok(ReplayLinkDeliveryOutcomeV0::NotApplied(reserved));
                }
                ResolutionV0::Target => {}
            }
        }
        self.verify_replay_target_fresh_v0(&target, target_id)?;
        Ok(ReplayLinkDeliveryOutcomeV0::Applied(
            delivered_replay_token_v0(
                store_id,
                target.link.as_ref().expect("replay D target contains link"),
            )?,
        ))
    }

    /// Projects the exact tag-3 NativeValid transition context from replay D
    /// plus its still-retained live Core carrier.
    pub fn replay_native_valid_transition_context_exact_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
        delivered: &CoreDeliveredReplayLinkDV0,
        accepted: &CoreAcceptedApplicationValidDV0,
    ) -> ValidationStoreResultV0<SafetyTransitionContextV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        let link = load_replay_link_v0(self.connection_v0()?, delivered.target_validation_id)?
            .ok_or_else(|| error(ValidationStoreErrorCodeV0::NotFound, "replay_context.link"))?;
        require_delivered_replay_token_v0(self.store_id, &link, delivered)?;
        let confirmation = link.confirmation.expect("delivered replay link has D");
        if link.target_binding != binding.to_record()
            || accepted.route_v0() != PayloadValidationRouteV0::Synced
            || accepted.validation_id_v0().block_id().as_bytes() != binding.block_id().as_bytes()
            || accepted.validation_id_v0().view().get() != binding.view()
            || accepted.validation_id_v0().generation() != binding.generation()
            || accepted.completion_revision_v0() != confirmation.core_revision
            || accepted.delivery_digest_v0() != confirmation.core_state_digest
            || accepted.valid_result_checksum_v0() != confirmation.accepted_validation_digest
            || accepted
                .persistence_request_v0()
                .native_valid_post_ack_action_v0()
                != Some(NativeValidPostAckActionV0::None)
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_context.exact_d",
            ));
        }
        let source = load_durable_snapshot_v0(self.connection_v0()?, link.source_validation_id)?;
        let source_job = source.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "replay_context.source_k",
            )
        })?;
        if source.sequence != link.source_store_sequence
            || source_job.stage != DurableValidationStageV0::Acked
            || source_job.row_checksum != link.source_row_checksum
            || source_job.artifact_digest != link.artifact_digest
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_context.source_freshness",
            ));
        }
        let binding_bytes = encode_binding_record_v0(&link.target_binding)?;
        let request_fingerprint =
            domain_digest_v0(REQUEST_FINGERPRINT_DOMAIN_V0, &[binding_bytes.as_slice()]);
        let job_immutable_checksum = domain_digest_v0(
            JOB_IMMUTABLE_CHECKSUM_DOMAIN_V0,
            &[
                &link.session_id,
                &link.cursor.to_be_bytes(),
                link.source_validation_id.as_bytes(),
                &link.source_row_checksum,
                &link.source_application_history_checksum,
                binding_bytes.as_slice(),
                &link.owner_id,
                &link.artifact_digest,
            ],
        );
        let application_host_config_ref = domain_digest_v0(
            APPLICATION_HOST_CONFIG_REF_DOMAIN_V0,
            &[self.scope.as_bytes(), self.store_id.as_slice()],
        );
        let callback_payload_checksum = domain_digest_v0(
            CALLBACK_PAYLOAD_CHECKSUM_DOMAIN_V0,
            &[
                binding.validation_id().as_bytes(),
                &confirmation.core_state_digest,
                &confirmation.accepted_validation_digest,
                &link.artifact_digest,
                &link.row_checksum,
            ],
        );
        let idempotency_key = domain_digest_v0(
            IDEMPOTENCY_KEY_DOMAIN_V0,
            &[
                &link.session_id,
                &link.cursor.to_be_bytes(),
                binding.validation_id().as_bytes(),
                &callback_payload_checksum,
            ],
        );
        let delivery_checksum = domain_digest_v0(
            REPLAY_LINK_DELIVERY_CHECKSUM_DOMAIN_V0,
            &[&link.row_checksum, &confirmation.core_state_digest],
        );
        let transition = NativeValidTransitionV0::new(
            PayloadValidationRouteV0::Synced,
            accepted.validation_id_v0(),
            request_fingerprint,
            job_immutable_checksum,
            application_host_config_ref,
            accepted.valid_result_checksum_v0(),
            callback_payload_checksum,
            idempotency_key,
            1,
            link.row_checksum,
            delivery_checksum,
            NativeValidPostAckActionV0::None.code(),
            accepted.completion_revision_v0(),
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_context.transition",
            )
        })?;
        Ok(SafetyTransitionContextV0::native_valid(transition))
    }

    /// Records replay Safety C only after the exact owner-affined NativeValid
    /// head is freshly confirmed. The action is `None`; no Vote/Timeout intent
    /// or canonical application K is written.
    pub fn close_replay_safety_c_v0<V: SignatureVerifier>(
        &mut self,
        delivered: CoreDeliveredReplayLinkDV0,
        binding: &ProposalValidationBindingV0,
        accepted: &CoreAcceptedApplicationValidDV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
    ) -> ValidationStoreResultV0<ReplayLinkSafetyOutcomeV0> {
        let context =
            self.replay_native_valid_transition_context_exact_v0(binding, &delivered, accepted)?;
        let confirmed = safety_store
            .confirmed_native_valid_head_exact_v0(
                accepted.persistence_request_v0().state(),
                &context,
            )
            .map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_safety.exact_head",
                )
            })?;
        let state = confirmed.state();
        if !confirmed.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
            || confirmed.revision() != accepted.completion_revision_v0()
            || confirmed.transition().route() != PayloadValidationRouteV0::Synced
            || confirmed.transition().validation_id() != accepted.validation_id_v0()
            || confirmed.transition().valid_result_checksum() != accepted.valid_result_checksum_v0()
            || confirmed.transition().post_ack_action_code()
                != NativeValidPostAckActionV0::None.code()
            || state.state_sync_anchor().is_none()
            || state.pending_sign().is_some()
            || !state.payload_validation_obligations().is_empty()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_safety.authority",
            ));
        }
        let target_id = binding.validation_id();
        let store_id = self.store_id;
        let safety_record_digest = confirmed.state_record_checksum();
        let safety_revision = confirmed.revision();
        drop(confirmed);
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;
        let (source, target, uncertain) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "replay_safety.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_safety.begin"))?;
            let source = load_durable_replay_snapshot_v0(&transaction, target_id)?;
            let source_link = source
                .link
                .as_ref()
                .ok_or_else(|| error(ValidationStoreErrorCodeV0::NotFound, "replay_safety.link"))?;
            require_delivered_replay_token_v0(store_id, source_link, &delivered)?;
            let replay_session = source.session.as_ref().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "replay_safety.session",
                )
            })?;
            if replay_session.state != DurableReplaySessionStateV0::Active
                || replay_session.session_id != source_link.session_id
                || replay_session.next_cursor != source_link.cursor
                || source_link.target_binding != binding.to_record()
                || delivered.core_delivery.core_revision() != safety_revision
                || safety_revision
                    != expected_replay_safety_closure_revision_v0(
                        replay_session,
                        source_link.cursor,
                    )?
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_safety.link_binding",
                ));
            }
            let next_sequence = source.metadata.sequence.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_safety.sequence",
                )
            })?;
            let mut metadata = source.metadata;
            metadata.sequence = next_sequence;
            metadata.safety_closed = metadata.safety_closed.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_safety.accounting",
                )
            })?;
            let mut link = source_link.clone();
            link.stage = DurableReplayLinkStageV0::SafetyClosed;
            link.safety_closure = Some(ReplaySafetyClosureRecordV0 {
                core_delivery_digest: *delivered.core_delivery.digest().as_bytes(),
                safety_revision,
                safety_record_digest,
                no_sign_closure_digest: [0; 32],
            });
            let no_sign = compute_replay_no_sign_closure_v0(&link).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_safety.closure",
                )
            })?;
            link.safety_closure
                .as_mut()
                .expect("replay C closure exists")
                .no_sign_closure_digest = no_sign;
            link.row_revision = next_sequence;
            link.row_checksum = compute_replay_link_checksum_v0(&link);
            replace_replay_link_v0(&transaction, source_link, &link)?;
            update_replay_metadata_v0(&transaction, source.metadata, metadata)?;
            let target = DurableReplaySnapshotV0 {
                metadata,
                session: source.session.clone(),
                link: Some(link),
            };
            let uncertain = finish_transaction_v0(transaction, fault)?;
            (source, target, uncertain)
        };
        if uncertain {
            self.discard_connection_v0();
            match self.resolve_replay_uncertain_v0(&source, &target, target_id)? {
                ResolutionV0::Source => {
                    return Ok(ReplayLinkSafetyOutcomeV0::NotApplied(delivered));
                }
                ResolutionV0::Target => {}
            }
        }
        self.verify_replay_target_fresh_v0(&target, target_id)?;
        Ok(ReplayLinkSafetyOutcomeV0::Applied(
            safety_closed_replay_token_v0(
                store_id,
                target.link.as_ref().expect("replay C target contains link"),
            )?,
        ))
    }

    /// Closes replay alias K only after both the canonical source K and its
    /// exact native application history row are freshly reconfirmed. No
    /// execution, canonical application row, or signer state is mutated.
    pub fn close_replay_alias_k_v0<R: ReplaySourceHistoryReadbackV0>(
        &mut self,
        closed_c: SafetyClosedReplayLinkCV0,
        binding: &ProposalValidationBindingV0,
        history_readback: &mut R,
    ) -> ValidationStoreResultV0<ReplayLinkAliasCloseOutcomeV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        let initial = load_replay_link_v0(self.connection_v0()?, closed_c.target_validation_id)?
            .ok_or_else(|| error(ValidationStoreErrorCodeV0::NotFound, "replay_alias.link"))?;
        require_safety_closed_replay_token_v0(self.store_id, &initial, &closed_c)?;
        if initial.target_binding != binding.to_record() {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_alias.binding",
            ));
        }
        let request = ReplaySourceHistoryReadRequestV0 {
            source_validation_id: initial.source_validation_id,
            artifact_digest: NonZeroDigestV0::new(initial.artifact_digest)?,
            expected_history_checksum: NonZeroDigestV0::new(
                initial.source_application_history_checksum,
            )?,
        };
        let history = history_readback.read_exact_replay_source_history_v0(request)?;
        if history.source_validation_id != request.source_validation_id
            || history.artifact_digest != request.artifact_digest
            || history.history_checksum != request.expected_history_checksum
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_alias.history_readback",
            ));
        }
        let target_id = binding.validation_id();
        let store_id = self.store_id;
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;
        let (source, target, uncertain) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "replay_alias.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_alias.begin"))?;
            let source = load_durable_replay_snapshot_v0(&transaction, target_id)?;
            let source_link = source.link.as_ref().ok_or_else(|| {
                error(ValidationStoreErrorCodeV0::NotFound, "replay_alias.link_tx")
            })?;
            require_safety_closed_replay_token_v0(store_id, source_link, &closed_c)?;
            let source_k =
                load_durable_snapshot_v0(&transaction, source_link.source_validation_id)?;
            let source_job = source_k.job.as_ref().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "replay_alias.source_k",
                )
            })?;
            if source_k.sequence != source_link.source_store_sequence
                || source_k.outbox.is_some()
                || source_job.stage != DurableValidationStageV0::Acked
                || source_job.row_revision != source_link.source_row_revision
                || source_job.row_checksum != source_link.source_row_checksum
                || source_job.row_checksum != compute_row_checksum_v0(source_job)
                || source_job.artifact_digest != source_link.artifact_digest
                || source_job.owner_id != source_link.owner_id
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_alias.source_freshness",
                ));
            }
            let next_sequence = source.metadata.sequence.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_alias.sequence",
                )
            })?;
            let mut metadata = source.metadata;
            metadata.sequence = next_sequence;
            metadata.alias_closed = metadata.alias_closed.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_alias.accounting",
                )
            })?;
            let mut link = source_link.clone();
            link.stage = DurableReplayLinkStageV0::AliasClosed;
            link.alias_closure_checksum = compute_replay_alias_closure_v0(&link);
            if link.alias_closure_checksum.is_none() {
                return Err(error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_alias.closure",
                ));
            }
            link.row_revision = next_sequence;
            link.row_checksum = compute_replay_link_checksum_v0(&link);
            replace_replay_link_v0(&transaction, source_link, &link)?;
            update_replay_metadata_v0(&transaction, source.metadata, metadata)?;
            let target = DurableReplaySnapshotV0 {
                metadata,
                session: source.session.clone(),
                link: Some(link),
            };
            let uncertain = finish_transaction_v0(transaction, fault)?;
            (source, target, uncertain)
        };
        if uncertain {
            self.discard_connection_v0();
            match self.resolve_replay_uncertain_v0(&source, &target, target_id)? {
                ResolutionV0::Source => {
                    return Ok(ReplayLinkAliasCloseOutcomeV0::NotApplied(closed_c));
                }
                ResolutionV0::Target => {}
            }
        }
        self.verify_replay_target_fresh_v0(&target, target_id)?;
        Ok(ReplayLinkAliasCloseOutcomeV0::Applied(
            alias_closed_replay_token_v0(
                store_id,
                target.link.as_ref().expect("replay K target contains link"),
            )?,
        ))
    }

    /// Joins an exact fresh external checkpoint successor to alias K, then
    /// atomically advances the durable replay cursor and progress chain. If
    /// this is the final cursor, the same transaction seals the session as
    /// `DurableReplayComplete`.
    pub fn checkpoint_replay_alias_k_v0<R: ReplayCheckpointReadbackV0>(
        &mut self,
        alias_k: AliasClosedReplayLinkKV0,
        checkpoint_readback: &mut R,
    ) -> ValidationStoreResultV0<ReplayLinkCheckpointOutcomeV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        let initial_link =
            load_replay_link_v0(self.connection_v0()?, alias_k.target_validation_id)?.ok_or_else(
                || {
                    error(
                        ValidationStoreErrorCodeV0::NotFound,
                        "replay_checkpoint.link",
                    )
                },
            )?;
        require_alias_closed_replay_token_v0(self.store_id, &initial_link, &alias_k)?;
        let initial_session = load_replay_session_v0(self.connection_v0()?)?.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "replay_checkpoint.session",
            )
        })?;
        let request =
            replay_checkpoint_request_v0(self.connection_v0()?, &initial_session, &initial_link)?;
        let readback = checkpoint_readback.read_or_advance_exact_replay_checkpoint_v0(request)?;
        let expected_generation = request
            .expected_predecessor_generation
            .checked_add(1)
            .ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_checkpoint.generation",
                )
            })?;
        if readback.preimage_digest != request.preimage_digest
            || readback.scope != request.expected_scope
            || readback.profile_ref != request.expected_profile_ref
            || readback.predecessor_checksum != request.expected_predecessor_checksum
            || readback.generation != expected_generation
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_checkpoint.readback",
            ));
        }
        let target_id = alias_k.target_validation_id;
        let store_id = self.store_id;
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;
        let (source, target, uncertain) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "replay_checkpoint.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "replay_checkpoint.begin",
                    )
                })?;
            let source = load_durable_replay_snapshot_v0(&transaction, target_id)?;
            let source_link = source.link.as_ref().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "replay_checkpoint.link_tx",
                )
            })?;
            require_alias_closed_replay_token_v0(store_id, source_link, &alias_k)?;
            let source_session = source.session.as_ref().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::NotFound,
                    "replay_checkpoint.session_tx",
                )
            })?;
            let current_request =
                replay_checkpoint_request_v0(&transaction, source_session, source_link)?;
            if current_request != request {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_checkpoint.request_changed",
                ));
            }
            let next_sequence = source.metadata.sequence.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_checkpoint.sequence",
                )
            })?;
            let mut metadata = source.metadata;
            metadata.sequence = next_sequence;
            metadata.checkpointed = metadata.checkpointed.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_checkpoint.accounting",
                )
            })?;
            let mut link = source_link.clone();
            link.stage = DurableReplayLinkStageV0::Checkpointed;
            link.checkpoint = Some(ReplayCheckpointRecordV0 {
                scope: *readback.scope.as_bytes(),
                profile_ref: *readback.profile_ref.as_bytes(),
                predecessor_checksum: *readback.predecessor_checksum.as_bytes(),
                generation: readback.generation,
                checksum: *readback.checkpoint_checksum.as_bytes(),
            });
            link.row_revision = next_sequence;
            link.row_checksum = compute_replay_link_checksum_v0(&link);
            let progress = compute_replay_checkpoint_progress_v0(&link).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_checkpoint.progress",
                )
            })?;
            let mut session = source_session.clone();
            session.next_cursor = session.next_cursor.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_checkpoint.cursor",
                )
            })?;
            session.previous_progress_checksum = progress;
            session.state = if session.next_cursor == session.expected_count {
                DurableReplaySessionStateV0::DurableReplayComplete
            } else {
                DurableReplaySessionStateV0::Active
            };
            session.row_revision = session.row_revision.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_checkpoint.session_revision",
                )
            })?;
            session.row_checksum = compute_replay_session_checksum_v0(&session);
            replace_replay_link_v0(&transaction, source_link, &link)?;
            replace_replay_session_v0(&transaction, source_session, &session)?;
            update_replay_metadata_v0(&transaction, source.metadata, metadata)?;
            let target = DurableReplaySnapshotV0 {
                metadata,
                session: Some(session),
                link: Some(link),
            };
            let uncertain = finish_transaction_v0(transaction, fault)?;
            (source, target, uncertain)
        };
        if uncertain {
            self.discard_connection_v0();
            match self.resolve_replay_uncertain_v0(&source, &target, target_id)? {
                ResolutionV0::Source => {
                    return Ok(ReplayLinkCheckpointOutcomeV0::NotApplied(alias_k));
                }
                ResolutionV0::Target => {}
            }
        }
        self.verify_replay_target_fresh_v0(&target, target_id)?;
        let target_link = target
            .link
            .as_ref()
            .expect("replay checkpoint target contains link");
        let target_session = target
            .session
            .as_ref()
            .expect("replay checkpoint target contains session");
        let link = checkpointed_replay_token_v0(store_id, target_link)?;
        match target_session.state {
            DurableReplaySessionStateV0::Active => Ok(ReplayLinkCheckpointOutcomeV0::AppliedNext {
                link,
                session: active_replay_session_token_v0(store_id, target_session)?,
            }),
            DurableReplaySessionStateV0::DurableReplayComplete => {
                Ok(ReplayLinkCheckpointOutcomeV0::AppliedComplete {
                    link,
                    session: durable_replay_complete_token_v0(store_id, target_session)?,
                })
            }
            DurableReplaySessionStateV0::ActivationReady => Err(error(
                ValidationStoreErrorCodeV0::InvalidTransition,
                "replay_checkpoint.already_activation_ready",
            )),
        }
    }

    /// Reconstitutes only the linear store token for an exact crash-surviving
    /// durable `P` row.  The caller must still present Core's independently
    /// replayed request permit before any Valid callback can exist.
    pub fn recover_reserved_exact_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
        expected_owner: ProposalValidationOwnerIdV0,
    ) -> ValidationStoreResultV0<ReservedValidationV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        let snapshot = load_durable_snapshot_v0(self.connection_v0()?, binding.validation_id())?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "recover_reserved.validation_id",
            )
        })?;
        if job.binding != binding.to_record()
            || job.owner_id != *expected_owner.as_bytes()
            || job.stage != DurableValidationStageV0::Reserved
            || job.confirmation.is_some()
            || job.safety_confirmation.is_some()
            || snapshot.outbox.is_some()
            || job.row_checksum != compute_row_checksum_v0(&job)
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "recover_reserved.exact_p",
            ));
        }
        let artifact_digest = artifact_digest_v0(&job.artifact)?;
        if artifact_digest.as_bytes() != &job.artifact_digest {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "recover_reserved.artifact_digest",
            ));
        }
        decode_checked_artifact_v0(&job.binding, &job.artifact, *artifact_digest.as_bytes())?;
        Ok(ReservedValidationV0 {
            store_id: self.store_id,
            validation_id: binding.validation_id(),
            owner_id: expected_owner,
            artifact_digest,
            row_revision: job.row_revision,
        })
    }

    /// Persists the exact Core-accepted `D` fact for one reserved proposal.
    ///
    /// The caller cannot synthesize the accepted value: it is a non-cloneable
    /// process-local carrier with no public constructor, minted only after the
    /// live Core accepts an application-sealed Valid result. This method
    /// independently joins its route, BlockId, view, generation, revision,
    /// barrier, and durable state revision to the journal's exact binding
    /// before the private storage transition is entered.
    pub fn deliver_core_accepted_v0(
        &mut self,
        reserved: ReservedValidationV0,
        binding: &ProposalValidationBindingV0,
        accepted: &CoreAcceptedApplicationValidDV0,
    ) -> ValidationStoreResultV0<DeliverTransitionOutcomeV0> {
        let accepted_id = accepted.validation_id_v0();
        if binding.validation_id() != reserved.validation_id
            || accepted.route_v0() != payload_validation_route_v0(binding.route())
            || accepted_id.block_id().as_bytes() != binding.block_id().as_bytes()
            || accepted_id.view().get() != binding.view()
            || accepted_id.generation() != binding.generation()
            || accepted.completion_revision_v0() == 0
            || accepted.barrier_v0().get() != accepted.completion_revision_v0()
            || accepted.persistence_request_v0().state().revision()
                != accepted.completion_revision_v0()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "deliver_core_accepted.exact_binding",
            ));
        }
        let core_delivery = CoreDeliveryConfirmationV0::new(
            binding.validation_id(),
            accepted.completion_revision_v0(),
            NonZeroDigestV0::new(accepted.delivery_digest_v0())?,
            NonZeroDigestV0::new(accepted.valid_result_checksum_v0())?,
        )?;
        self.deliver_v0(reserved, core_delivery)
    }

    pub(crate) fn deliver_v0(
        &mut self,
        reserved: ReservedValidationV0,
        core_delivery: CoreDeliveryConfirmationV0,
    ) -> ValidationStoreResultV0<DeliverTransitionOutcomeV0> {
        self.ensure_ready_v0()?;
        self.require_reserved_token_v0(&reserved)?;
        if core_delivery.validation_id() != reserved.validation_id {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "deliver.core_delivery_validation_id",
            ));
        }
        let validation_id = reserved.validation_id;
        let store_id = self.store_id;
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;

        let (source, target, uncertain) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "deliver.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "deliver.begin"))?;
            let source = load_durable_snapshot_v0(&transaction, validation_id)?;
            require_source_job_v0(
                &source,
                DurableValidationStageV0::Reserved,
                reserved.owner_id,
                reserved.artifact_digest,
                reserved.row_revision,
            )?;
            let next_sequence = source
                .sequence
                .checked_add(1)
                .ok_or_else(|| error(ValidationStoreErrorCodeV0::Overflow, "deliver.sequence"))?;
            let accounting = AccountingV0 {
                reserved: source.accounting.reserved.checked_sub(1).ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "deliver.reserved_count",
                    )
                })?,
                delivered: source.accounting.delivered.checked_add(1).ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::Overflow,
                        "deliver.delivered_count",
                    )
                })?,
                acked: source.accounting.acked,
            };
            let mut job = source.job.clone().expect("source job checked above");
            job.stage = DurableValidationStageV0::Delivered;
            job.confirmation = Some(core_delivery.into());
            job.row_revision = next_sequence;
            job.row_checksum = compute_row_checksum_v0(&job);
            replace_job_v0(&transaction, &source.job, &job)?;
            insert_outbox_v0(&transaction, validation_id, core_delivery.into())?;
            update_sequence_v0(&transaction, source.sequence, next_sequence)?;
            update_accounting_v0(&transaction, source.accounting, accounting)?;
            let target = DurableSnapshotV0 {
                sequence: next_sequence,
                accounting,
                job: Some(job),
                outbox: Some(core_delivery.into()),
            };
            let uncertain = finish_transaction_v0(transaction, fault)?;
            (source, target, uncertain)
        };

        if uncertain {
            self.discard_connection_v0();
            #[cfg(any(test, feature = "test-support"))]
            if matches!(fault, Some(TestCommitFaultV0::ThirdState)) {
                corrupt_target_for_test_v0(&self.path, validation_id)?;
            }
            match self.resolve_uncertain_v0(&source, &target, validation_id)? {
                ResolutionV0::Source => {
                    return Ok(DeliverTransitionOutcomeV0::NotApplied(reserved));
                }
                ResolutionV0::Target => {}
            }
        }

        let job = target
            .job
            .as_ref()
            .expect("deliver target must contain job");
        let token = DeliveredValidationV0 {
            store_id,
            validation_id,
            owner_id: reserved.owner_id,
            artifact_digest: reserved.artifact_digest,
            core_delivery,
            row_revision: job.row_revision,
        };
        self.verify_durable_target_fresh_v0(&target, validation_id)?;
        Ok(DeliverTransitionOutcomeV0::Applied(token))
    }

    /// Projects the exact tag-3 NativeValid transition context from the live
    /// durable `D` row and Core's still-retained opaque authority.
    ///
    /// Every scalar is rederived from the canonical binding, artifact, row,
    /// outbox, store identity, and Core persistence request. The result is
    /// inert comparison material for SafetyStore; it is not Safety authority
    /// and cannot acknowledge `D` or release Core effects.
    pub fn native_valid_transition_context_exact_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
        delivered: &DeliveredValidationV0,
        accepted: &CoreAcceptedApplicationValidDV0,
    ) -> ValidationStoreResultV0<SafetyTransitionContextV0> {
        self.ensure_ready_v0()?;
        self.require_delivered_token_v0(delivered)?;
        let snapshot = load_durable_snapshot_v0(self.connection_v0()?, binding.validation_id())?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "native_valid_context.validation_id",
            )
        })?;
        let confirmation = job.confirmation.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "native_valid_context.core_delivery",
            )
        })?;
        if job.binding != binding.to_record()
            || job.stage != DurableValidationStageV0::Delivered
            || job.row_revision != delivered.row_revision
            || job.row_checksum != compute_row_checksum_v0(&job)
            || snapshot.outbox != Some(confirmation)
            || confirmation != delivered.core_delivery.into()
            || accepted.route_v0() != payload_validation_route_v0(binding.route())
            || accepted.validation_id_v0().block_id().as_bytes() != binding.block_id().as_bytes()
            || accepted.validation_id_v0().view().get() != binding.view()
            || accepted.validation_id_v0().generation() != binding.generation()
            || accepted.completion_revision_v0() != confirmation.core_revision
            || accepted.delivery_digest_v0() != confirmation.core_state_digest
            || accepted.valid_result_checksum_v0() != confirmation.accepted_validation_digest
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "native_valid_context.exact_d",
            ));
        }
        let action = accepted
            .persistence_request_v0()
            .native_valid_post_ack_action_v0()
            .ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "native_valid_context.post_ack_action",
                )
            })?;
        let binding_bytes = encode_binding_record_v0(&job.binding)?;
        let request_fingerprint =
            domain_digest_v0(REQUEST_FINGERPRINT_DOMAIN_V0, &[binding_bytes.as_slice()]);
        let job_immutable_checksum = domain_digest_v0(
            JOB_IMMUTABLE_CHECKSUM_DOMAIN_V0,
            &[
                binding_bytes.as_slice(),
                job.owner_id.as_slice(),
                job.artifact_digest.as_slice(),
                job.artifact.as_slice(),
            ],
        );
        let application_host_config_ref = domain_digest_v0(
            APPLICATION_HOST_CONFIG_REF_DOMAIN_V0,
            &[self.scope.as_bytes(), self.store_id.as_slice()],
        );
        let callback_payload_checksum = domain_digest_v0(
            CALLBACK_PAYLOAD_CHECKSUM_DOMAIN_V0,
            &[
                binding.validation_id().as_bytes(),
                confirmation.core_state_digest.as_slice(),
                confirmation.accepted_validation_digest.as_slice(),
                job.artifact_digest.as_slice(),
            ],
        );
        let idempotency_key = domain_digest_v0(
            IDEMPOTENCY_KEY_DOMAIN_V0,
            &[
                binding.validation_id().as_bytes(),
                callback_payload_checksum.as_slice(),
            ],
        );
        let outbox_checksum = outbox_checksum_v0(confirmation);
        for (field, value) in [
            ("request_fingerprint", request_fingerprint),
            ("job_immutable_checksum", job_immutable_checksum),
            ("application_host_config_ref", application_host_config_ref),
            ("callback_payload_checksum", callback_payload_checksum),
            ("idempotency_key", idempotency_key),
            ("delivered_job_row_checksum", job.row_checksum),
            ("outbox_checksum", outbox_checksum),
        ] {
            if value == [0; 32] {
                return Err(error(ValidationStoreErrorCodeV0::ZeroValue, field));
            }
        }
        let transition = NativeValidTransitionV0::new(
            accepted.route_v0(),
            accepted.validation_id_v0(),
            request_fingerprint,
            job_immutable_checksum,
            application_host_config_ref,
            accepted.valid_result_checksum_v0(),
            callback_payload_checksum,
            idempotency_key,
            1,
            job.row_checksum,
            outbox_checksum,
            action.code(),
            accepted.completion_revision_v0(),
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "native_valid_context.transition",
            )
        })?;
        Ok(SafetyTransitionContextV0::native_valid(transition))
    }

    /// Closes application `D -> K` only from a fresh, owner-affined,
    /// fully-authenticated SafetyStore NativeValid head.
    ///
    /// This is the real Safety-C boundary. The journal independently rederives
    /// the expected context from D, asks the exact live SafetyStore to fresh-
    /// confirm that state/context, and requires the durable Vote intent which
    /// Core's Proposal action will release only after a later StorageAck.
    /// No Core acknowledgement occurs here.
    pub fn acknowledge_confirmed_safety_v0<V: SignatureVerifier>(
        &mut self,
        delivered: DeliveredValidationV0,
        binding: &ProposalValidationBindingV0,
        accepted: &CoreAcceptedApplicationValidDV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
    ) -> ValidationStoreResultV0<AckTransitionOutcomeV0> {
        let context =
            self.native_valid_transition_context_exact_v0(binding, &delivered, accepted)?;
        let confirmed = safety_store
            .confirmed_native_valid_head_exact_v0(
                accepted.persistence_request_v0().state(),
                &context,
            )
            .map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "confirmed_safety.exact_head",
                )
            })?;
        if !confirmed.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
            || confirmed.revision() != accepted.completion_revision_v0()
            || confirmed.transition().route() != PayloadValidationRouteV0::Proposal
            || confirmed.transition().validation_id() != accepted.validation_id_v0()
            || confirmed.transition().valid_result_checksum() != accepted.valid_result_checksum_v0()
            || confirmed.transition().post_ack_action_code()
                != accepted
                    .persistence_request_v0()
                    .native_valid_post_ack_action_v0()
                    .expect("context derivation required the action")
                    .code()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "confirmed_safety.authority",
            ));
        }
        let pending_sign = confirmed.state().pending_sign().ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "confirmed_safety.vote_intent",
            )
        })?;
        if pending_sign.kind() != SignKind::Vote
            || pending_sign.authorizing_safety_revision() != confirmed.revision()
            || pending_sign.view() != accepted.validation_id_v0().view()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "confirmed_safety.vote_binding",
            ));
        }
        let safety_confirmation = RequestBoundSafetyConfirmationV0::from_confirmed_authority(
            binding.validation_id(),
            delivered.core_delivery.digest(),
            confirmed.revision(),
            NonZeroDigestV0::new(confirmed.state_record_checksum())?,
            NonZeroDigestV0::new(*pending_sign.signing_root().as_bytes())?,
        );
        self.acknowledge_with_confirmation_v0(delivered, safety_confirmation)
    }

    /// Closes an anchored-successor `D -> K` transition from the exact
    /// owner-affined NativeValid Safety head.
    ///
    /// Anchored h2/h3 replay deliberately has no Vote intent.  The legacy
    /// schema-v3 confirmation column therefore retains a domain-separated
    /// no-sign closure digest instead of a signing root.  This method admits
    /// only the `Synced` route, Core's `None` post-ack manifest, a state-sync
    /// anchor, revision two or four, and an absent pending signer intent.
    pub fn acknowledge_confirmed_anchor_successor_safety_v0<V: SignatureVerifier>(
        &mut self,
        delivered: DeliveredValidationV0,
        binding: &ProposalValidationBindingV0,
        accepted: &CoreAcceptedApplicationValidDV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &Path,
    ) -> ValidationStoreResultV0<AckTransitionOutcomeV0> {
        let context =
            self.native_valid_transition_context_exact_v0(binding, &delivered, accepted)?;
        let confirmed = safety_store
            .confirmed_native_valid_head_exact_v0(
                accepted.persistence_request_v0().state(),
                &context,
            )
            .map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "anchored_confirmed_safety.exact_head",
                )
            })?;
        let action = accepted
            .persistence_request_v0()
            .native_valid_post_ack_action_v0()
            .ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "anchored_confirmed_safety.action",
                )
            })?;
        let state = confirmed.state();
        if binding.route() != ProposalRouteV0::Synced
            || accepted.route_v0() != PayloadValidationRouteV0::Synced
            || action != NativeValidPostAckActionV0::None
            || !confirmed.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
            || confirmed.revision() != accepted.completion_revision_v0()
            || !matches!(confirmed.revision(), 2 | 4)
            || confirmed.transition().route() != PayloadValidationRouteV0::Synced
            || confirmed.transition().validation_id() != accepted.validation_id_v0()
            || confirmed.transition().valid_result_checksum() != accepted.valid_result_checksum_v0()
            || confirmed.transition().post_ack_action_code() != action.code()
            || state.state_sync_anchor().is_none()
            || state.pending_sign().is_some()
            || state.last_voted_view().is_some()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "anchored_confirmed_safety.authority",
            ));
        }
        let revision = confirmed.revision().to_be_bytes();
        let action_code = action.code().to_be_bytes();
        let no_sign_closure = domain_digest_v0(
            ANCHORED_SUCCESSOR_SAFETY_CLOSURE_DOMAIN_V0,
            &[
                binding.validation_id().as_bytes(),
                delivered.core_delivery.digest().as_bytes(),
                &revision,
                &confirmed.state_record_checksum(),
                &action_code,
            ],
        );
        let safety_confirmation = RequestBoundSafetyConfirmationV0::from_confirmed_authority(
            binding.validation_id(),
            delivered.core_delivery.digest(),
            confirmed.revision(),
            NonZeroDigestV0::new(confirmed.state_record_checksum())?,
            NonZeroDigestV0::new(no_sign_closure)?,
        );
        self.acknowledge_with_confirmation_v0(delivered, safety_confirmation)
    }

    pub fn acknowledge_v0<R: SafetyConfirmationReadbackV0>(
        &mut self,
        delivered: DeliveredValidationV0,
        safety_readback: &mut R,
    ) -> ValidationStoreResultV0<AckTransitionOutcomeV0> {
        self.ensure_ready_v0()?;
        self.require_delivered_token_v0(&delivered)?;
        let validation_id = delivered.validation_id;
        let safety_request = SafetyConfirmationReadRequestV0::new(
            validation_id,
            delivered.core_delivery.digest(),
            delivered.core_delivery.core_revision(),
        );
        let safety_confirmation = RequestBoundSafetyConfirmationV0::verify_readback(
            safety_request,
            safety_readback.read_exact_safety_confirmation_v0(safety_request)?,
        )?;
        self.acknowledge_with_confirmation_v0(delivered, safety_confirmation)
    }

    fn acknowledge_with_confirmation_v0(
        &mut self,
        delivered: DeliveredValidationV0,
        safety_confirmation: RequestBoundSafetyConfirmationV0,
    ) -> ValidationStoreResultV0<AckTransitionOutcomeV0> {
        let validation_id = delivered.validation_id;
        let store_id = self.store_id;
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.next_commit_fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault: Option<()> = None;

        let (source, target, uncertain) = {
            let connection = self.connection.as_mut().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "ack.connection",
                )
            })?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "ack.begin"))?;
            let source = load_durable_snapshot_v0(&transaction, validation_id)?;
            require_source_job_v0(
                &source,
                DurableValidationStageV0::Delivered,
                delivered.owner_id,
                delivered.artifact_digest,
                delivered.row_revision,
            )?;
            if source.job.as_ref().and_then(|job| job.confirmation)
                != Some(delivered.core_delivery.into())
                || source.outbox != Some(delivered.core_delivery.into())
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "ack.durable_confirmation",
                ));
            }
            let next_sequence = source
                .sequence
                .checked_add(1)
                .ok_or_else(|| error(ValidationStoreErrorCodeV0::Overflow, "ack.sequence"))?;
            let accounting = AccountingV0 {
                reserved: source.accounting.reserved,
                delivered: source.accounting.delivered.checked_sub(1).ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "ack.delivered_count",
                    )
                })?,
                acked: source.accounting.acked.checked_add(1).ok_or_else(|| {
                    error(ValidationStoreErrorCodeV0::Overflow, "ack.acked_count")
                })?,
            };
            let mut job = source.job.clone().expect("source job checked above");
            job.stage = DurableValidationStageV0::Acked;
            job.safety_confirmation = Some(safety_confirmation.into());
            job.row_revision = next_sequence;
            job.row_checksum = compute_row_checksum_v0(&job);
            replace_job_v0(&transaction, &source.job, &job)?;
            delete_outbox_v0(&transaction, validation_id, delivered.core_delivery.into())?;
            update_sequence_v0(&transaction, source.sequence, next_sequence)?;
            update_accounting_v0(&transaction, source.accounting, accounting)?;
            let target = DurableSnapshotV0 {
                sequence: next_sequence,
                accounting,
                job: Some(job),
                outbox: None,
            };
            let uncertain = finish_transaction_v0(transaction, fault)?;
            (source, target, uncertain)
        };

        if uncertain {
            self.discard_connection_v0();
            #[cfg(any(test, feature = "test-support"))]
            if matches!(fault, Some(TestCommitFaultV0::ThirdState)) {
                corrupt_target_for_test_v0(&self.path, validation_id)?;
            }
            match self.resolve_uncertain_v0(&source, &target, validation_id)? {
                ResolutionV0::Source => {
                    return Ok(AckTransitionOutcomeV0::NotApplied(delivered));
                }
                ResolutionV0::Target => {}
            }
        }

        let job = target.job.as_ref().expect("ack target must contain job");
        let token = AckedValidationV0 {
            store_id,
            validation_id,
            owner_id: delivered.owner_id,
            safety_confirmation,
            row_revision: job.row_revision,
        };
        self.verify_durable_target_fresh_v0(&target, validation_id)?;
        Ok(AckTransitionOutcomeV0::Applied(token))
    }

    pub fn inspect_exact_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
    ) -> ValidationStoreResultV0<ProposalValidationFactV0> {
        self.ensure_ready_v0()?;
        let snapshot = load_durable_snapshot_v0(self.connection_v0()?, binding.validation_id())?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "inspect.validation_id",
            )
        })?;
        if job.binding != binding.to_record() {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "inspect.binding",
            ));
        }
        Ok(ProposalValidationFactV0 {
            validation_id: binding.validation_id(),
            stage: job.stage,
            row_revision: job.row_revision,
            store_sequence: snapshot.sequence,
            outbox_present: snapshot.outbox.is_some(),
        })
    }

    /// Reconstruct one exact persisted execution artifact after all digest,
    /// canonical-codec, row-checksum, and binding checks have succeeded.
    pub fn read_artifact_exact_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
    ) -> ValidationStoreResultV0<NativeExecutedBlockV0> {
        self.ensure_ready_v0()?;
        let snapshot = load_durable_snapshot_v0(self.connection_v0()?, binding.validation_id())?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "artifact.validation_id",
            )
        })?;
        if job.binding != binding.to_record() {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "artifact.binding",
            ));
        }
        decode_checked_artifact_v0(&job.binding, &job.artifact, job.artifact_digest)
    }

    /// Read request-bound, C-shaped provenance retained by terminal `K`.
    ///
    /// The returned value is durable audit/recovery data, not a replacement
    /// for a fresh Safety-store authority read.
    pub fn inspect_request_bound_safety_closure_exact_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
    ) -> ValidationStoreResultV0<DurableRequestBoundSafetyClosureFactV0> {
        self.ensure_ready_v0()?;
        let snapshot = load_durable_snapshot_v0(self.connection_v0()?, binding.validation_id())?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "safety_closure.validation_id",
            )
        })?;
        if job.binding != binding.to_record() {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "safety_closure.binding",
            ));
        }
        if job.stage != DurableValidationStageV0::Acked {
            return Err(error(
                ValidationStoreErrorCodeV0::InvalidTransition,
                "safety_closure.stage",
            ));
        }
        let safety = job.safety_confirmation.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "safety_closure.missing",
            )
        })?;
        Ok(DurableRequestBoundSafetyClosureFactV0 {
            validation_id: binding.validation_id(),
            core_delivery_digest: NonZeroDigestV0::new(safety.core_delivery_digest)?,
            safety_revision: safety.safety_revision,
            safety_record_digest: NonZeroDigestV0::new(safety.safety_record_digest)?,
            vote_intent_digest: NonZeroDigestV0::new(safety.vote_intent_digest)?,
        })
    }

    /// Reconstructs the exact inert NativeValid transition retained by one
    /// terminal anchored-successor K row. This is recovery comparison data,
    /// not a callback, persistence request, or Safety authority.
    pub fn reconstruct_anchor_successor_native_valid_context_from_k_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
    ) -> ValidationStoreResultV0<SafetyTransitionContextV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        let snapshot = load_durable_snapshot_v0(self.connection_v0()?, binding.validation_id())?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "anchor_successor_recovery.validation_id",
            )
        })?;
        let confirmation = job.confirmation.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "anchor_successor_recovery.core_delivery",
            )
        })?;
        let safety = job.safety_confirmation.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "anchor_successor_recovery.safety_closure",
            )
        })?;
        if binding.route() != ProposalRouteV0::Synced
            || job.binding != binding.to_record()
            || job.stage != DurableValidationStageV0::Acked
            || job.row_checksum != compute_row_checksum_v0(&job)
            || snapshot.outbox.is_some()
            || confirmation.validation_id != *binding.validation_id().as_bytes()
            || !matches!(confirmation.core_revision, 2 | 4)
            || safety.safety_revision != confirmation.core_revision
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "anchor_successor_recovery.terminal_k",
            ));
        }
        let core_delivery = CoreDeliveryConfirmationV0::new(
            binding.validation_id(),
            confirmation.core_revision,
            NonZeroDigestV0::new(confirmation.core_state_digest)?,
            NonZeroDigestV0::new(confirmation.accepted_validation_digest)?,
        )?;
        if safety.core_delivery_digest != *core_delivery.digest().as_bytes()
            || safety.safety_record_digest == [0; 32]
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "anchor_successor_recovery.safety_binding",
            ));
        }

        let binding_bytes = encode_binding_record_v0(&job.binding)?;
        let request_fingerprint =
            domain_digest_v0(REQUEST_FINGERPRINT_DOMAIN_V0, &[binding_bytes.as_slice()]);
        let job_immutable_checksum = domain_digest_v0(
            JOB_IMMUTABLE_CHECKSUM_DOMAIN_V0,
            &[
                binding_bytes.as_slice(),
                job.owner_id.as_slice(),
                job.artifact_digest.as_slice(),
                job.artifact.as_slice(),
            ],
        );
        let application_host_config_ref = domain_digest_v0(
            APPLICATION_HOST_CONFIG_REF_DOMAIN_V0,
            &[self.scope.as_bytes(), self.store_id.as_slice()],
        );
        let callback_payload_checksum = domain_digest_v0(
            CALLBACK_PAYLOAD_CHECKSUM_DOMAIN_V0,
            &[
                binding.validation_id().as_bytes(),
                confirmation.core_state_digest.as_slice(),
                confirmation.accepted_validation_digest.as_slice(),
                job.artifact_digest.as_slice(),
            ],
        );
        let idempotency_key = domain_digest_v0(
            IDEMPOTENCY_KEY_DOMAIN_V0,
            &[
                binding.validation_id().as_bytes(),
                callback_payload_checksum.as_slice(),
            ],
        );
        let outbox_checksum = outbox_checksum_v0(confirmation);
        let validation_id = trnm_consensus_core::ValidationId::new(
            trnm_consensus_types::BlockId::new(*binding.block_id().as_bytes()),
            trnm_consensus_types::View::new(binding.view()),
            binding.generation(),
        );
        let transition = NativeValidTransitionV0::new(
            PayloadValidationRouteV0::Synced,
            validation_id,
            request_fingerprint,
            job_immutable_checksum,
            application_host_config_ref,
            confirmation.accepted_validation_digest,
            callback_payload_checksum,
            idempotency_key,
            1,
            job.row_checksum,
            outbox_checksum,
            NativeValidPostAckActionV0::None.code(),
            confirmation.core_revision,
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "anchor_successor_recovery.transition",
            )
        })?;
        let revision = safety.safety_revision.to_be_bytes();
        let action_code = NativeValidPostAckActionV0::None.code().to_be_bytes();
        let no_sign_closure = domain_digest_v0(
            ANCHORED_SUCCESSOR_SAFETY_CLOSURE_DOMAIN_V0,
            &[
                binding.validation_id().as_bytes(),
                core_delivery.digest().as_bytes(),
                &revision,
                &safety.safety_record_digest,
                &action_code,
            ],
        );
        if safety.vote_intent_digest != no_sign_closure {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "anchor_successor_recovery.no_sign_closure",
            ));
        }
        Ok(SafetyTransitionContextV0::native_valid(transition))
    }

    /// Freshly confirms the exact terminal `K` row and its durable P/D/C
    /// provenance for a later trusted whole-node checkpoint join.
    pub fn confirm_proposal_validation_checkpoint_facts_exact_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
    ) -> ValidationStoreResultV0<ConfirmedProposalValidationCheckpointFactsV0> {
        self.ensure_ready_v0()?;
        self.audit_database_v0()?;
        let snapshot = load_durable_snapshot_v0(self.connection_v0()?, binding.validation_id())?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::NotFound,
                "checkpoint_facts.validation_id",
            )
        })?;
        if job.binding != binding.to_record()
            || job.stage != DurableValidationStageV0::Acked
            || snapshot.outbox.is_some()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "checkpoint_facts.terminal_k",
            ));
        }
        let core_delivery = job.confirmation.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "checkpoint_facts.core_delivery",
            )
        })?;
        if core_delivery.validation_id != *binding.validation_id().as_bytes() {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "checkpoint_facts.core_delivery_validation_id",
            ));
        }
        let core_delivery = CoreDeliveryConfirmationV0::new(
            binding.validation_id(),
            core_delivery.core_revision,
            NonZeroDigestV0::new(core_delivery.core_state_digest)?,
            NonZeroDigestV0::new(core_delivery.accepted_validation_digest)?,
        )?;
        let safety = job.safety_confirmation.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "checkpoint_facts.safety_confirmation",
            )
        })?;
        let safety_closure = DurableRequestBoundSafetyClosureFactV0 {
            validation_id: binding.validation_id(),
            core_delivery_digest: NonZeroDigestV0::new(safety.core_delivery_digest)?,
            safety_revision: safety.safety_revision,
            safety_record_digest: NonZeroDigestV0::new(safety.safety_record_digest)?,
            vote_intent_digest: NonZeroDigestV0::new(safety.vote_intent_digest)?,
        };
        if safety_closure.core_delivery_digest() != core_delivery.digest() {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "checkpoint_facts.safety_core_delivery",
            ));
        }
        Ok(ConfirmedProposalValidationCheckpointFactsV0 {
            database_path: self.path.clone(),
            owner_affinity: Arc::clone(&self.owner_affinity),
            scope: self.scope,
            store_id: self.store_id,
            binding: binding.clone(),
            owner_id: ProposalValidationOwnerIdV0::new(job.owner_id)?,
            store_sequence: snapshot.sequence,
            row_revision: job.row_revision,
            row_checksum: NonZeroDigestV0::new(job.row_checksum)?,
            artifact_digest: NonZeroDigestV0::new(job.artifact_digest)?,
            core_delivery_digest: core_delivery.digest(),
            safety_closure,
        })
    }

    /// Reconfirms that a previously issued `K` capability is still the exact
    /// live head.  Success returns a newly issued capability so callers cannot
    /// mistake a stale owner-affinity token for a freshness proof.
    pub fn reconfirm_proposal_validation_checkpoint_facts_exact_v0(
        &mut self,
        prior: &ConfirmedProposalValidationCheckpointFactsV0,
    ) -> ValidationStoreResultV0<ConfirmedProposalValidationCheckpointFactsV0> {
        if !prior.belongs_to_store_at_path_v0(self, &self.path) {
            return Err(error(
                ValidationStoreErrorCodeV0::ForeignToken,
                "checkpoint_facts.owner",
            ));
        }
        let fresh = self.confirm_proposal_validation_checkpoint_facts_exact_v0(&prior.binding)?;
        if fresh.scope != prior.scope
            || fresh.store_id != prior.store_id
            || fresh.binding != prior.binding
            || fresh.owner_id != prior.owner_id
            || fresh.store_sequence != prior.store_sequence
            || fresh.row_revision != prior.row_revision
            || fresh.row_checksum != prior.row_checksum
            || fresh.artifact_digest != prior.artifact_digest
            || fresh.core_delivery_digest != prior.core_delivery_digest
            || fresh.safety_closure != prior.safety_closure
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "checkpoint_facts.freshness",
            ));
        }
        Ok(fresh)
    }

    fn require_reserved_token_v0(
        &self,
        token: &ReservedValidationV0,
    ) -> ValidationStoreResultV0<()> {
        if token.store_id != self.store_id {
            return Err(error(
                ValidationStoreErrorCodeV0::ForeignToken,
                "reserved.store_id",
            ));
        }
        Ok(())
    }

    fn require_delivered_token_v0(
        &self,
        token: &DeliveredValidationV0,
    ) -> ValidationStoreResultV0<()> {
        if token.store_id != self.store_id {
            return Err(error(
                ValidationStoreErrorCodeV0::ForeignToken,
                "delivered.store_id",
            ));
        }
        Ok(())
    }

    fn ensure_ready_v0(&self) -> ValidationStoreResultV0<()> {
        if self.fenced || self.connection.is_none() {
            return Err(error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "validation_store.fenced",
            ));
        }
        #[cfg(unix)]
        {
            let current = read_file_identity_v0(&self.path)?;
            if current != self.file_identity {
                return Err(error(
                    ValidationStoreErrorCodeV0::ReplacedStore,
                    "validation_store.file_identity",
                ));
            }
        }
        Ok(())
    }

    fn connection_v0(&self) -> ValidationStoreResultV0<&Connection> {
        self.connection.as_ref().ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "validation_store.connection",
            )
        })
    }

    fn discard_connection_v0(&mut self) {
        self.fenced = true;
        self.connection.take();
    }

    fn resolve_uncertain_v0(
        &mut self,
        source: &DurableSnapshotV0,
        target: &DurableSnapshotV0,
        validation_id: ValidationIdV0,
    ) -> ValidationStoreResultV0<ResolutionV0> {
        let connection = open_connection_v0(&self.path).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "uncertain.reopen",
            )
        })?;
        #[cfg(unix)]
        if read_file_identity_v0(&self.path)? != self.file_identity {
            return Err(error(
                ValidationStoreErrorCodeV0::ReplacedStore,
                "uncertain.file_identity",
            ));
        }
        verify_metadata_v0(&connection, self.scope, self.store_id, 0).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "uncertain.metadata",
            )
        })?;
        let current = load_durable_snapshot_v0(&connection, validation_id).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "uncertain.readback",
            )
        })?;
        let resolution = if current == *target {
            ResolutionV0::Target
        } else if current == *source {
            ResolutionV0::Source
        } else {
            return Err(error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "uncertain.third_state",
            ));
        };
        audit_database_connection_v0(&connection).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "uncertain.audit",
            )
        })?;
        self.connection = Some(connection);
        self.fenced = false;
        Ok(resolution)
    }

    /// A successful SQLite COMMIT is not enough to release a linear token.
    /// Reopen the exact file and compare the entire durable target using a
    /// different connection, then discard that verification connection.
    fn verify_durable_target_fresh_v0(
        &self,
        target: &DurableSnapshotV0,
        validation_id: ValidationIdV0,
    ) -> ValidationStoreResultV0<()> {
        let connection = open_connection_v0(&self.path).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "target_readback.reopen",
            )
        })?;
        #[cfg(unix)]
        if read_file_identity_v0(&self.path)? != self.file_identity {
            return Err(error(
                ValidationStoreErrorCodeV0::ReplacedStore,
                "target_readback.file_identity",
            ));
        }
        verify_schema_v0(&connection).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "target_readback.schema",
            )
        })?;
        verify_metadata_v0(&connection, self.scope, self.store_id, target.sequence).map_err(
            |_| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "target_readback.metadata",
                )
            },
        )?;
        let current = load_durable_snapshot_v0(&connection, validation_id).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "target_readback.snapshot",
            )
        })?;
        if current != *target {
            return Err(error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "target_readback.mismatch",
            ));
        }
        audit_database_connection_v0(&connection).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "target_readback.audit",
            )
        })
    }

    fn load_replay_session_fresh_v0(
        &self,
    ) -> ValidationStoreResultV0<Option<ReplaySessionSnapshotV0>> {
        let connection = open_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        verify_metadata_v0(&connection, self.scope, self.store_id, 0)?;
        audit_database_connection_v0(&connection)?;
        load_replay_session_v0(&connection)
    }

    fn verify_replay_session_fresh_v0(
        &self,
        target: &ReplaySessionSnapshotV0,
    ) -> ValidationStoreResultV0<()> {
        if self.load_replay_session_fresh_v0()?.as_ref() != Some(target) {
            return Err(error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "replay_session.fresh_mismatch",
            ));
        }
        Ok(())
    }

    fn resolve_replay_uncertain_v0(
        &mut self,
        source: &DurableReplaySnapshotV0,
        target: &DurableReplaySnapshotV0,
        target_validation_id: ValidationIdV0,
    ) -> ValidationStoreResultV0<ResolutionV0> {
        let connection = open_connection_v0(&self.path).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "replay_uncertain.reopen",
            )
        })?;
        verify_schema_v0(&connection)?;
        verify_metadata_v0(&connection, self.scope, self.store_id, 0)?;
        let current = load_durable_replay_snapshot_v0(&connection, target_validation_id)?;
        let resolution = if current == *target {
            ResolutionV0::Target
        } else if current == *source {
            ResolutionV0::Source
        } else {
            return Err(error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "replay_uncertain.third_state",
            ));
        };
        audit_database_connection_v0(&connection)?;
        self.connection = Some(connection);
        self.fenced = false;
        Ok(resolution)
    }

    fn verify_replay_target_fresh_v0(
        &self,
        target: &DurableReplaySnapshotV0,
        target_validation_id: ValidationIdV0,
    ) -> ValidationStoreResultV0<()> {
        let connection = open_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        verify_metadata_v0(&connection, self.scope, self.store_id, 0)?;
        let current = load_durable_replay_snapshot_v0(&connection, target_validation_id)?;
        if current != *target {
            return Err(error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "replay_target.fresh_mismatch",
            ));
        }
        audit_database_connection_v0(&connection)
    }

    fn audit_database_v0(&mut self) -> ValidationStoreResultV0<()> {
        self.ensure_ready_v0()?;
        verify_schema_v0(self.connection_v0()?)?;
        verify_metadata_v0(self.connection_v0()?, self.scope, self.store_id, 0)?;
        audit_database_connection_v0(self.connection_v0()?)
    }

    #[cfg(test)]
    pub(crate) fn inject_next_commit_fault_v0(&mut self, fault: TestCommitFaultV0) {
        self.next_commit_fault = Some(fault);
    }

    /// Test-support-only process-loss injection immediately after the
    /// ActivationReady transaction commits but before its caller observes the
    /// acknowledgement.  Normal builds do not contain this hook.
    #[cfg(feature = "test-support")]
    pub fn inject_replay_activation_applied_ack_loss_for_test_v0(&mut self) {
        self.next_commit_fault = Some(TestCommitFaultV0::AppliedAckLost);
    }
}

#[cfg(test)]
pub(crate) fn duplicate_reserved_for_test_v0(token: &ReservedValidationV0) -> ReservedValidationV0 {
    ReservedValidationV0 {
        store_id: token.store_id,
        validation_id: token.validation_id,
        owner_id: token.owner_id,
        artifact_digest: token.artifact_digest,
        row_revision: token.row_revision,
    }
}

/// Test-only adversarial rewrite which keeps the artifact digest and row
/// checksum internally consistent. Reopen must still reject malformed codec
/// bytes or a canonical artifact substituted under a different binding.
#[cfg(test)]
pub(crate) fn rewrite_artifact_self_consistent_for_test_v0(
    path: &Path,
    validation_id: ValidationIdV0,
    artifact: Vec<u8>,
) -> ValidationStoreResultV0<()> {
    let connection = open_connection_v0(path)?;
    let mut job = load_job_v0(&connection, validation_id)?
        .ok_or_else(|| error(ValidationStoreErrorCodeV0::NotFound, "test.artifact_job"))?;
    job.artifact_digest = *artifact_digest_v0(&artifact)?.as_bytes();
    job.artifact = artifact;
    job.row_checksum = compute_row_checksum_v0(&job);
    let changed = connection
        .execute(
            "UPDATE proposal_validation_jobs_v0
             SET artifact_digest = ?1, artifact = ?2, row_checksum = ?3
             WHERE validation_id = ?4",
            params![
                job.artifact_digest.as_slice(),
                job.artifact.as_slice(),
                job.row_checksum.as_slice(),
                validation_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "test.artifact_rewrite"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::NotFound,
            "test.artifact_rewrite_target",
        ));
    }
    Ok(())
}

/// Test-only adversarial rewrite that updates both the persisted C field and
/// row checksum. Reopen must still reject C provenance that no longer equals
/// the digest of the row's exact durable Core-D record.
#[cfg(test)]
pub(crate) fn rewrite_safety_core_delivery_self_consistent_for_test_v0(
    path: &Path,
    validation_id: ValidationIdV0,
    core_delivery_digest: [u8; 32],
) -> ValidationStoreResultV0<()> {
    let connection = open_connection_v0(path)?;
    let mut job = load_job_v0(&connection, validation_id)?
        .ok_or_else(|| error(ValidationStoreErrorCodeV0::NotFound, "test.safety_job"))?;
    let safety = job.safety_confirmation.as_mut().ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "test.safety_missing",
        )
    })?;
    safety.core_delivery_digest = core_delivery_digest;
    job.row_checksum = compute_row_checksum_v0(&job);
    let changed = connection
        .execute(
            "UPDATE proposal_validation_jobs_v0
             SET safety_core_delivery_digest = ?1, row_checksum = ?2
             WHERE validation_id = ?3",
            params![
                core_delivery_digest.as_slice(),
                job.row_checksum.as_slice(),
                validation_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "test.safety_rewrite"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::NotFound,
            "test.safety_rewrite_target",
        ));
    }
    Ok(())
}

/// Test-only conversion of a generic terminal K fixture into the exact
/// domain-separated no-sign closure written by the anchored-successor path.
/// All production decoding and transition reconstruction remains unchanged.
#[cfg(test)]
pub(crate) fn rewrite_anchor_successor_no_sign_closure_for_test_v0(
    path: &Path,
    binding: &ProposalValidationBindingV0,
) -> ValidationStoreResultV0<()> {
    let connection = open_connection_v0(path)?;
    let mut job = load_job_v0(&connection, binding.validation_id())?
        .ok_or_else(|| error(ValidationStoreErrorCodeV0::NotFound, "test.anchor_k_job"))?;
    let confirmation = job.confirmation.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "test.anchor_k_delivery",
        )
    })?;
    let safety = job.safety_confirmation.as_mut().ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "test.anchor_k_safety",
        )
    })?;
    let core_delivery = CoreDeliveryConfirmationV0::new(
        binding.validation_id(),
        confirmation.core_revision,
        NonZeroDigestV0::new(confirmation.core_state_digest)?,
        NonZeroDigestV0::new(confirmation.accepted_validation_digest)?,
    )?;
    if binding.route() != ProposalRouteV0::Synced
        || job.binding != binding.to_record()
        || job.stage != DurableValidationStageV0::Acked
        || !matches!(safety.safety_revision, 2 | 4)
        || safety.safety_revision != confirmation.core_revision
        || safety.core_delivery_digest != *core_delivery.digest().as_bytes()
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "test.anchor_k_binding",
        ));
    }
    let revision = safety.safety_revision.to_be_bytes();
    let action_code = NativeValidPostAckActionV0::None.code().to_be_bytes();
    let vote_intent_digest = domain_digest_v0(
        ANCHORED_SUCCESSOR_SAFETY_CLOSURE_DOMAIN_V0,
        &[
            binding.validation_id().as_bytes(),
            core_delivery.digest().as_bytes(),
            &revision,
            &safety.safety_record_digest,
            &action_code,
        ],
    );
    safety.vote_intent_digest = vote_intent_digest;
    job.row_checksum = compute_row_checksum_v0(&job);
    let changed = connection
        .execute(
            "UPDATE proposal_validation_jobs_v0
             SET vote_intent_digest = ?1, row_checksum = ?2
             WHERE validation_id = ?3",
            params![
                vote_intent_digest.as_slice(),
                job.row_checksum.as_slice(),
                binding.validation_id().as_bytes().as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "test.anchor_k_rewrite"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::NotFound,
            "test.anchor_k_rewrite_target",
        ));
    }
    Ok(())
}

/// Test-only construction of the smallest internally audited replay closure
/// needed to exercise the `DurableReplayComplete -> ActivationReady` CAS in
/// isolation.  The caller must first create one canonical terminal K, open a
/// one-link replay session, and reserve that exact replay link.
#[cfg(test)]
pub(crate) fn complete_single_replay_link_for_activation_test_v0(
    store: &mut SqliteProposalValidationStoreV0,
    target_validation_id: ValidationIdV0,
) -> ValidationStoreResultV0<()> {
    store.ensure_ready_v0()?;
    store.audit_database_v0()?;
    let source = load_durable_replay_snapshot_v0(store.connection_v0()?, target_validation_id)?;
    let source_session = source.session.as_ref().ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::NotFound,
            "test.activation_session",
        )
    })?;
    let source_link = source
        .link
        .as_ref()
        .ok_or_else(|| error(ValidationStoreErrorCodeV0::NotFound, "test.activation_link"))?;
    if source_session.state != DurableReplaySessionStateV0::Active
        || source_session.expected_count != 1
        || source_session.next_cursor != 0
        || source_link.stage != DurableReplayLinkStageV0::Reserved
        || source_link.cursor != 0
        || source_link.session_id != source_session.session_id
        || source.metadata.reserved != 1
        || source.metadata.core_delivered != 0
        || source.metadata.safety_closed != 0
        || source.metadata.alias_closed != 0
        || source.metadata.checkpointed != 0
    {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "test.activation_frontier",
        ));
    }

    let safety_revision =
        expected_replay_safety_closure_revision_v0(source_session, source_link.cursor)?;
    let confirmation = ConfirmationRecordV0 {
        validation_id: *target_validation_id.as_bytes(),
        core_revision: safety_revision,
        core_state_digest: [0xC1; 32],
        accepted_validation_digest: [0xC2; 32],
    };
    let core_delivery = CoreDeliveryConfirmationV0::new(
        target_validation_id,
        confirmation.core_revision,
        NonZeroDigestV0::new(confirmation.core_state_digest)?,
        NonZeroDigestV0::new(confirmation.accepted_validation_digest)?,
    )?;

    let mut link = source_link.clone();
    link.confirmation = Some(confirmation);
    link.safety_closure = Some(ReplaySafetyClosureRecordV0 {
        core_delivery_digest: *core_delivery.digest().as_bytes(),
        safety_revision,
        safety_record_digest: [0xC3; 32],
        no_sign_closure_digest: [0; 32],
    });
    link.safety_closure
        .as_mut()
        .expect("test replay safety closure exists")
        .no_sign_closure_digest = compute_replay_no_sign_closure_v0(&link).ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "test.activation_no_sign",
        )
    })?;
    link.alias_closure_checksum = compute_replay_alias_closure_v0(&link);
    link.checkpoint = Some(ReplayCheckpointRecordV0 {
        scope: source_session.initial_checkpoint_scope,
        profile_ref: source_session.initial_checkpoint_profile_ref,
        predecessor_checksum: source_session.initial_checkpoint_checksum,
        generation: source_session
            .initial_checkpoint_generation
            .checked_add(1)
            .ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "test.activation_checkpoint_generation",
                )
            })?,
        checksum: [0xC4; 32],
    });
    link.stage = DurableReplayLinkStageV0::Checkpointed;

    let mut metadata = source.metadata;
    metadata.sequence = metadata.sequence.checked_add(4).ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::Overflow,
            "test.activation_sequence",
        )
    })?;
    metadata.core_delivered = 1;
    metadata.safety_closed = 1;
    metadata.alias_closed = 1;
    metadata.checkpointed = 1;
    link.row_revision = metadata.sequence;
    link.row_checksum = compute_replay_link_checksum_v0(&link);

    let progress = compute_replay_checkpoint_progress_v0(&link).ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "test.activation_progress",
        )
    })?;
    let mut session = source_session.clone();
    session.next_cursor = 1;
    session.previous_progress_checksum = progress;
    session.state = DurableReplaySessionStateV0::DurableReplayComplete;
    session.row_revision = session.row_revision.checked_add(1).ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::Overflow,
            "test.activation_session_revision",
        )
    })?;
    session.row_checksum = compute_replay_session_checksum_v0(&session);

    let transaction = store
        .connection
        .as_mut()
        .ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CommitUncertain,
                "test.activation_connection",
            )
        })?
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "test.activation_begin"))?;
    replace_replay_link_v0(&transaction, source_link, &link)?;
    replace_replay_session_v0(&transaction, source_session, &session)?;
    update_replay_metadata_v0(&transaction, source.metadata, metadata)?;
    transaction.commit().map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::Storage,
            "test.activation_commit",
        )
    })?;

    let target = DurableReplaySnapshotV0 {
        metadata,
        session: Some(session),
        link: Some(link),
    };
    store.verify_replay_target_fresh_v0(&target, target_validation_id)
}

/// Test-only third durable state for the activation CAS.  The transaction's
/// target was committed, then one binding field is durably changed without
/// its row checksum; neither source nor target may be released and normal
/// reopen must reject the torn row.
#[cfg(any(test, feature = "test-support"))]
fn corrupt_replay_activation_target_for_test_v0(path: &Path) -> ValidationStoreResultV0<()> {
    let connection = open_connection_v0(path)?;
    let mut binding: Vec<u8> = connection
        .query_row(
            "SELECT activation_binding_digest
             FROM proposal_validation_replay_session_v0
             WHERE singleton = 1 AND state = 3",
            [],
            |row| row.get(0),
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "test.activation_third_read",
            )
        })?;
    if binding.len() != 32 {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "test.activation_third_shape",
        ));
    }
    binding[0] ^= 0xFF;
    let changed = connection
        .execute(
            "UPDATE proposal_validation_replay_session_v0
             SET activation_binding_digest = ?1
             WHERE singleton = 1 AND state = 3",
            params![binding],
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "test.activation_third_write",
            )
        })?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::NotFound,
            "test.activation_third_target",
        ));
    }
    Ok(())
}

fn initialize_schema_v0(connection: &Connection) -> ValidationStoreResultV0<()> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS validation_store_metadata_v0 (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               schema_version INTEGER NOT NULL,
               scope BLOB NOT NULL CHECK (length(scope) = 32),
               store_id BLOB NOT NULL CHECK (length(store_id) = 32),
               sequence BLOB NOT NULL CHECK (length(sequence) = 8)
             );
             CREATE TABLE IF NOT EXISTS validation_store_accounting_v0 (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               reserved BLOB NOT NULL CHECK (length(reserved) = 8),
               delivered BLOB NOT NULL CHECK (length(delivered) = 8),
               acked BLOB NOT NULL CHECK (length(acked) = 8)
             );
             CREATE TABLE IF NOT EXISTS proposal_validation_jobs_v0 (
               validation_id BLOB PRIMARY KEY CHECK (length(validation_id) = 32),
               binding BLOB NOT NULL,
               owner_id BLOB NOT NULL CHECK (length(owner_id) = 32),
               artifact_digest BLOB NOT NULL CHECK (length(artifact_digest) = 32),
               artifact BLOB NOT NULL
                 CHECK (typeof(artifact) = 'blob' AND length(artifact) > 0
                        AND length(artifact) <= 16777216),
               stage INTEGER NOT NULL CHECK (stage IN (1, 2, 3)),
               core_revision BLOB,
               core_state_digest BLOB,
               accepted_validation_digest BLOB,
               safety_core_delivery_digest BLOB,
               safety_revision BLOB,
               safety_record_digest BLOB,
               vote_intent_digest BLOB,
               row_revision BLOB NOT NULL CHECK (length(row_revision) = 8),
               row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32),
               CHECK ((stage = 1 AND core_revision IS NULL
                       AND core_state_digest IS NULL AND accepted_validation_digest IS NULL
                       AND safety_core_delivery_digest IS NULL AND safety_revision IS NULL
                       AND safety_record_digest IS NULL AND vote_intent_digest IS NULL)
                      OR (stage = 2 AND length(core_revision) = 8
                          AND length(core_state_digest) = 32
                          AND length(accepted_validation_digest) = 32
                          AND safety_core_delivery_digest IS NULL AND safety_revision IS NULL
                          AND safety_record_digest IS NULL AND vote_intent_digest IS NULL)
                      OR (stage = 3 AND length(core_revision) = 8
                          AND length(core_state_digest) = 32
                          AND length(accepted_validation_digest) = 32
                          AND length(safety_core_delivery_digest) = 32
                          AND length(safety_revision) = 8
                          AND length(safety_record_digest) = 32
                          AND length(vote_intent_digest) = 32))
             );
             CREATE TABLE IF NOT EXISTS proposal_validation_outbox_v0 (
               validation_id BLOB PRIMARY KEY
                 REFERENCES proposal_validation_jobs_v0(validation_id),
               core_revision BLOB NOT NULL CHECK (length(core_revision) = 8),
               core_state_digest BLOB NOT NULL CHECK (length(core_state_digest) = 32),
               accepted_validation_digest BLOB NOT NULL
                 CHECK (length(accepted_validation_digest) = 32)
             );
             CREATE TABLE IF NOT EXISTS proposal_validation_replay_session_v0 (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               session_id BLOB NOT NULL UNIQUE CHECK (length(session_id) = 32),
               core_config_ref BLOB NOT NULL CHECK (length(core_config_ref) = 32),
               validation_scope BLOB NOT NULL CHECK (length(validation_scope) = 32),
               validation_store_id BLOB NOT NULL CHECK (length(validation_store_id) = 32),
               recovery_challenge_digest BLOB NOT NULL
                 CHECK (length(recovery_challenge_digest) = 32),
               archive_context_digest BLOB NOT NULL CHECK (length(archive_context_digest) = 32),
               archive_sequence BLOB NOT NULL CHECK (length(archive_sequence) = 8),
               archive_record_digest BLOB NOT NULL CHECK (length(archive_record_digest) = 32),
               expected_count BLOB NOT NULL CHECK (length(expected_count) = 8),
               next_cursor BLOB NOT NULL CHECK (length(next_cursor) = 8),
               canonical_store_sequence BLOB NOT NULL
                 CHECK (length(canonical_store_sequence) = 8),
               canonical_terminal_row_count BLOB NOT NULL
                 CHECK (length(canonical_terminal_row_count) = 8),
               canonical_terminal_audit_digest BLOB NOT NULL
                 CHECK (length(canonical_terminal_audit_digest) = 32),
               application_history_digest BLOB NOT NULL
                 CHECK (length(application_history_digest) = 32),
               initial_safety_revision BLOB NOT NULL
                 CHECK (length(initial_safety_revision) = 8),
               initial_safety_state_checksum BLOB NOT NULL
                 CHECK (length(initial_safety_state_checksum) = 32),
               initial_safety_chain_checksum BLOB NOT NULL
                 CHECK (length(initial_safety_chain_checksum) = 32),
               initial_checkpoint_scope BLOB NOT NULL
                 CHECK (length(initial_checkpoint_scope) = 32),
               initial_checkpoint_profile_ref BLOB NOT NULL
                 CHECK (length(initial_checkpoint_profile_ref) = 32),
               initial_checkpoint_generation BLOB NOT NULL
                 CHECK (length(initial_checkpoint_generation) = 8),
               initial_checkpoint_checksum BLOB NOT NULL
                 CHECK (length(initial_checkpoint_checksum) = 32),
               signer_scope BLOB NOT NULL CHECK (length(signer_scope) = 32),
               signer_journal_id BLOB NOT NULL CHECK (length(signer_journal_id) = 32),
               signer_sequence BLOB NOT NULL CHECK (length(signer_sequence) = 8),
               signer_chain_checksum BLOB NOT NULL CHECK (length(signer_chain_checksum) = 32),
               previous_progress_checksum BLOB NOT NULL
                 CHECK (length(previous_progress_checksum) = 32),
               state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
               activation_binding_digest BLOB,
               activation_source_row_revision BLOB,
               activation_source_row_checksum BLOB,
               row_revision BLOB NOT NULL CHECK (length(row_revision) = 8),
               row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32),
               CHECK (next_cursor <= expected_count),
               CHECK ((state = 1 AND next_cursor < expected_count
                        AND activation_binding_digest IS NULL
                        AND activation_source_row_revision IS NULL
                        AND activation_source_row_checksum IS NULL)
                      OR (state = 2 AND next_cursor = expected_count
                          AND activation_binding_digest IS NULL
                          AND activation_source_row_revision IS NULL
                          AND activation_source_row_checksum IS NULL)
                      OR (state = 3 AND next_cursor = expected_count
                          AND length(activation_binding_digest) = 32
                          AND length(activation_source_row_revision) = 8
                          AND length(activation_source_row_checksum) = 32))
             );
             CREATE TABLE IF NOT EXISTS proposal_validation_replay_links_v0 (
               target_validation_id BLOB PRIMARY KEY
                 CHECK (length(target_validation_id) = 32),
               session_id BLOB NOT NULL
                 REFERENCES proposal_validation_replay_session_v0(session_id)
                 CHECK (length(session_id) = 32),
               cursor BLOB NOT NULL CHECK (length(cursor) = 8),
               source_validation_id BLOB NOT NULL
                 REFERENCES proposal_validation_jobs_v0(validation_id)
                 CHECK (length(source_validation_id) = 32),
               source_store_sequence BLOB NOT NULL CHECK (length(source_store_sequence) = 8),
               source_row_revision BLOB NOT NULL CHECK (length(source_row_revision) = 8),
               source_row_checksum BLOB NOT NULL CHECK (length(source_row_checksum) = 32),
               source_application_history_checksum BLOB NOT NULL
                 CHECK (length(source_application_history_checksum) = 32),
               target_binding BLOB NOT NULL,
               owner_id BLOB NOT NULL CHECK (length(owner_id) = 32),
               artifact_digest BLOB NOT NULL CHECK (length(artifact_digest) = 32),
               previous_progress_checksum BLOB NOT NULL
                 CHECK (length(previous_progress_checksum) = 32),
               stage INTEGER NOT NULL CHECK (stage IN (1, 2, 3, 4, 5)),
               core_revision BLOB,
               core_state_digest BLOB,
               accepted_validation_digest BLOB,
               safety_core_delivery_digest BLOB,
               safety_revision BLOB,
               safety_record_digest BLOB,
               no_sign_closure_digest BLOB,
               alias_closure_checksum BLOB,
               checkpoint_scope BLOB,
               checkpoint_profile_ref BLOB,
               checkpoint_predecessor_checksum BLOB,
               checkpoint_generation BLOB,
               checkpoint_checksum BLOB,
               row_revision BLOB NOT NULL CHECK (length(row_revision) = 8),
               row_checksum BLOB NOT NULL CHECK (length(row_checksum) = 32),
               UNIQUE (session_id, cursor),
               UNIQUE (session_id, source_validation_id),
               CHECK ((stage = 1 AND core_revision IS NULL
                       AND core_state_digest IS NULL AND accepted_validation_digest IS NULL
                       AND safety_core_delivery_digest IS NULL AND safety_revision IS NULL
                       AND safety_record_digest IS NULL AND no_sign_closure_digest IS NULL
                       AND alias_closure_checksum IS NULL AND checkpoint_scope IS NULL
                       AND checkpoint_profile_ref IS NULL
                       AND checkpoint_predecessor_checksum IS NULL
                       AND checkpoint_generation IS NULL AND checkpoint_checksum IS NULL)
                      OR (stage = 2 AND length(core_revision) = 8
                          AND length(core_state_digest) = 32
                          AND length(accepted_validation_digest) = 32
                          AND safety_core_delivery_digest IS NULL AND safety_revision IS NULL
                          AND safety_record_digest IS NULL AND no_sign_closure_digest IS NULL
                          AND alias_closure_checksum IS NULL AND checkpoint_scope IS NULL
                          AND checkpoint_profile_ref IS NULL
                          AND checkpoint_predecessor_checksum IS NULL
                          AND checkpoint_generation IS NULL AND checkpoint_checksum IS NULL)
                      OR (stage = 3 AND length(core_revision) = 8
                          AND length(core_state_digest) = 32
                          AND length(accepted_validation_digest) = 32
                          AND length(safety_core_delivery_digest) = 32
                          AND length(safety_revision) = 8
                          AND length(safety_record_digest) = 32
                          AND length(no_sign_closure_digest) = 32
                          AND alias_closure_checksum IS NULL AND checkpoint_scope IS NULL
                          AND checkpoint_profile_ref IS NULL
                          AND checkpoint_predecessor_checksum IS NULL
                          AND checkpoint_generation IS NULL AND checkpoint_checksum IS NULL)
                      OR (stage = 4 AND length(core_revision) = 8
                          AND length(core_state_digest) = 32
                          AND length(accepted_validation_digest) = 32
                          AND length(safety_core_delivery_digest) = 32
                          AND length(safety_revision) = 8
                          AND length(safety_record_digest) = 32
                          AND length(no_sign_closure_digest) = 32
                          AND length(alias_closure_checksum) = 32
                          AND checkpoint_scope IS NULL AND checkpoint_profile_ref IS NULL
                          AND checkpoint_predecessor_checksum IS NULL
                          AND checkpoint_generation IS NULL AND checkpoint_checksum IS NULL)
                      OR (stage = 5 AND length(core_revision) = 8
                          AND length(core_state_digest) = 32
                          AND length(accepted_validation_digest) = 32
                          AND length(safety_core_delivery_digest) = 32
                          AND length(safety_revision) = 8
                          AND length(safety_record_digest) = 32
                          AND length(no_sign_closure_digest) = 32
                          AND length(alias_closure_checksum) = 32
                          AND length(checkpoint_scope) = 32
                          AND length(checkpoint_profile_ref) = 32
                          AND length(checkpoint_predecessor_checksum) = 32
                          AND length(checkpoint_generation) = 8
                          AND length(checkpoint_checksum) = 32))
             );
             CREATE TABLE IF NOT EXISTS proposal_validation_replay_metadata_v0 (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               sequence BLOB NOT NULL CHECK (length(sequence) = 8),
               reserved BLOB NOT NULL CHECK (length(reserved) = 8),
               core_delivered BLOB NOT NULL CHECK (length(core_delivered) = 8),
               safety_closed BLOB NOT NULL CHECK (length(safety_closed) = 8),
               alias_closed BLOB NOT NULL CHECK (length(alias_closed) = 8),
               checkpointed BLOB NOT NULL CHECK (length(checkpointed) = 8)
             );",
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "schema"))?;
    Ok(())
}

fn verify_schema_v0(connection: &Connection) -> ValidationStoreResultV0<()> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "schema.verify_prepare"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "schema.verify_query"))?;
    let mut actual = Vec::new();
    for row in rows {
        let (kind, name, sql) =
            row.map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "schema.verify_row"))?;
        if kind == "trigger" {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "schema.trigger",
            ));
        }
        if kind != "table" {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "schema.object_type",
            ));
        }
        let sql = sql.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "schema.missing_sql",
            )
        })?;
        actual.push((name, normalize_sql_v0(&sql)));
    }
    let expected = EXPECTED_SCHEMA_V0
        .iter()
        .map(|(name, sql)| ((*name).to_owned(), normalize_sql_v0(sql)))
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "schema.exact",
        ));
    }
    Ok(())
}

fn normalize_sql_v0(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn initialize_or_load_metadata_v0(
    connection: &Connection,
    path: &Path,
    scope: ProposalValidationStoreScopeV0,
    created: bool,
    minimum_durable_sequence: u64,
) -> ValidationStoreResultV0<[u8; 32]> {
    let existing: Option<MetadataRowV0> = connection
        .query_row(
            "SELECT schema_version, scope, store_id, sequence
             FROM validation_store_metadata_v0 WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "metadata.load"))?;

    if let Some((schema_version, stored_scope, stored_id, stored_sequence)) = existing {
        if created {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "metadata.created_with_row",
            ));
        }
        if schema_version != SCHEMA_VERSION_V0
            || stored_scope.as_slice() != scope.as_bytes()
            || stored_id.len() != 32
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "metadata.identity",
            ));
        }
        let sequence = decode_u64_v0(&stored_sequence, "metadata.sequence")?;
        if sequence < minimum_durable_sequence {
            return Err(error(
                ValidationStoreErrorCodeV0::RollbackDetected,
                "metadata.sequence_floor",
            ));
        }
        return vec_to_array_32_v0(stored_id, "metadata.store_id");
    }

    if !created || minimum_durable_sequence != 0 {
        return Err(error(
            ValidationStoreErrorCodeV0::RollbackDetected,
            "metadata.missing",
        ));
    }
    let store_id = derive_store_id_v0(path, scope)?;
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "metadata.begin"))?;
    transaction
        .execute(
            "INSERT INTO validation_store_metadata_v0
             (singleton, schema_version, scope, store_id, sequence)
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                SCHEMA_VERSION_V0,
                scope.as_bytes().as_slice(),
                store_id.as_slice(),
                encode_u64_v0(0).as_slice()
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "metadata.insert"))?;
    transaction
        .execute(
            "INSERT INTO validation_store_accounting_v0
             (singleton, reserved, delivered, acked) VALUES (1, ?1, ?1, ?1)",
            params![encode_u64_v0(0).as_slice()],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "accounting.insert"))?;
    transaction
        .execute(
            "INSERT INTO proposal_validation_replay_metadata_v0
             (singleton, sequence, reserved, core_delivered, safety_closed,
              alias_closed, checkpointed)
             VALUES (1, ?1, ?1, ?1, ?1, ?1, ?1)",
            params![encode_u64_v0(0).as_slice()],
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "replay_metadata.insert",
            )
        })?;
    transaction.commit().map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CommitUncertain,
            "metadata.commit",
        )
    })?;
    Ok(store_id)
}

fn verify_metadata_v0(
    connection: &Connection,
    scope: ProposalValidationStoreScopeV0,
    store_id: [u8; 32],
    minimum_sequence: u64,
) -> ValidationStoreResultV0<()> {
    let (schema_version, stored_scope, stored_id, sequence): (i64, Vec<u8>, Vec<u8>, Vec<u8>) =
        connection
            .query_row(
                "SELECT schema_version, scope, store_id, sequence
                 FROM validation_store_metadata_v0 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, "metadata.verify"))?;
    if schema_version != SCHEMA_VERSION_V0
        || stored_scope.as_slice() != scope.as_bytes()
        || stored_id.as_slice() != store_id
        || decode_u64_v0(&sequence, "metadata.verify_sequence")? < minimum_sequence
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "metadata.verify_identity",
        ));
    }
    Ok(())
}

fn audit_database_connection_v0(connection: &Connection) -> ValidationStoreResultV0<()> {
    let accounting = load_accounting_v0(connection)?;
    let mut statement = connection
        .prepare("SELECT validation_id FROM proposal_validation_jobs_v0 ORDER BY validation_id")
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "audit.prepare"))?;
    let ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "audit.query"))?;
    let mut counted = AccountingV0 {
        reserved: 0,
        delivered: 0,
        acked: 0,
    };
    for id in ids {
        let id = vec_to_array_32_v0(
            id.map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "audit.id"))?,
            "audit.validation_id",
        )?;
        let validation_id = ValidationIdV0::from_bytes(id);
        let snapshot = load_durable_snapshot_v0(connection, validation_id)?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "audit.missing_job",
            )
        })?;
        match job.stage {
            DurableValidationStageV0::Reserved => {
                counted.reserved = counted
                    .reserved
                    .checked_add(1)
                    .ok_or_else(|| error(ValidationStoreErrorCodeV0::Overflow, "audit.reserved"))?;
                if snapshot.outbox.is_some()
                    || job.confirmation.is_some()
                    || job.safety_confirmation.is_some()
                {
                    return Err(error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "audit.reserved_outbox",
                    ));
                }
            }
            DurableValidationStageV0::Delivered => {
                counted.delivered = counted.delivered.checked_add(1).ok_or_else(|| {
                    error(ValidationStoreErrorCodeV0::Overflow, "audit.delivered")
                })?;
                if snapshot.outbox != job.confirmation || job.safety_confirmation.is_some() {
                    return Err(error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "audit.delivered_outbox",
                    ));
                }
            }
            DurableValidationStageV0::Acked => {
                counted.acked = counted
                    .acked
                    .checked_add(1)
                    .ok_or_else(|| error(ValidationStoreErrorCodeV0::Overflow, "audit.acked"))?;
                if snapshot.outbox.is_some()
                    || job.confirmation.is_none()
                    || job.safety_confirmation.is_none()
                {
                    return Err(error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "audit.acked_outbox",
                    ));
                }
            }
        }
    }
    if counted != accounting {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "audit.accounting",
        ));
    }
    audit_replay_links_v0(connection)?;
    Ok(())
}

fn load_durable_snapshot_v0(
    connection: &Connection,
    validation_id: ValidationIdV0,
) -> ValidationStoreResultV0<DurableSnapshotV0> {
    Ok(DurableSnapshotV0 {
        sequence: load_sequence_v0(connection)?,
        accounting: load_accounting_v0(connection)?,
        job: load_job_v0(connection, validation_id)?,
        outbox: load_outbox_v0(connection, validation_id)?,
    })
}

fn load_sequence_v0(connection: &Connection) -> ValidationStoreResultV0<u64> {
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT sequence FROM validation_store_metadata_v0 WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, "sequence.load"))?;
    decode_u64_v0(&bytes, "sequence.decode")
}

fn load_accounting_v0(connection: &Connection) -> ValidationStoreResultV0<AccountingV0> {
    let (reserved, delivered, acked): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT reserved, delivered, acked
             FROM validation_store_accounting_v0 WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, "accounting.load"))?;
    Ok(AccountingV0 {
        reserved: decode_u64_v0(&reserved, "accounting.reserved")?,
        delivered: decode_u64_v0(&delivered, "accounting.delivered")?,
        acked: decode_u64_v0(&acked, "accounting.acked")?,
    })
}

fn load_replay_metadata_v0(connection: &Connection) -> ValidationStoreResultV0<ReplayMetadataV0> {
    let (sequence, reserved, core_delivered, safety_closed, alias_closed, checkpointed):
        ReplayMetadataRowV0 = connection
        .query_row(
            "SELECT sequence, reserved, core_delivered, safety_closed, alias_closed, checkpointed
             FROM proposal_validation_replay_metadata_v0 WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_metadata.load",
            )
        })?;
    Ok(ReplayMetadataV0 {
        sequence: decode_u64_v0(&sequence, "replay_metadata.sequence")?,
        reserved: decode_u64_v0(&reserved, "replay_metadata.reserved")?,
        core_delivered: decode_u64_v0(&core_delivered, "replay_metadata.core_delivered")?,
        safety_closed: decode_u64_v0(&safety_closed, "replay_metadata.safety_closed")?,
        alias_closed: decode_u64_v0(&alias_closed, "replay_metadata.alias_closed")?,
        checkpointed: decode_u64_v0(&checkpointed, "replay_metadata.checkpointed")?,
    })
}

fn load_replay_session_v0(
    connection: &Connection,
) -> ValidationStoreResultV0<Option<ReplaySessionSnapshotV0>> {
    type RawReplaySessionV0 = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
    );
    let raw: Option<RawReplaySessionV0> = connection
        .query_row(
            "SELECT session_id, core_config_ref, validation_scope, validation_store_id,
                    recovery_challenge_digest,
                    archive_context_digest, archive_sequence, archive_record_digest,
                    expected_count, next_cursor, canonical_store_sequence,
                    canonical_terminal_row_count, canonical_terminal_audit_digest,
                    application_history_digest, initial_safety_revision,
                    initial_safety_state_checksum, initial_safety_chain_checksum,
                    initial_checkpoint_scope, initial_checkpoint_profile_ref,
                    initial_checkpoint_generation,
                    initial_checkpoint_checksum, signer_scope, signer_journal_id,
                    signer_sequence, signer_chain_checksum, previous_progress_checksum,
                    state, activation_binding_digest, activation_source_row_revision,
                    activation_source_row_checksum, row_revision, row_checksum
             FROM proposal_validation_replay_session_v0 WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                    row.get(21)?,
                    row.get(22)?,
                    row.get(23)?,
                    row.get(24)?,
                    row.get(25)?,
                    row.get(26)?,
                    row.get(27)?,
                    row.get(28)?,
                    row.get(29)?,
                    row.get(30)?,
                    row.get(31)?,
                ))
            },
        )
        .optional()
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_session.load"))?;
    let Some(raw) = raw else { return Ok(None) };
    let session = ReplaySessionSnapshotV0 {
        session_id: vec_to_array_32_v0(raw.0, "replay_session.session_id")?,
        core_config_ref: vec_to_array_32_v0(raw.1, "replay_session.core_config_ref")?,
        validation_scope: vec_to_array_32_v0(raw.2, "replay_session.validation_scope")?,
        validation_store_id: vec_to_array_32_v0(raw.3, "replay_session.validation_store")?,
        recovery_challenge_digest: vec_to_array_32_v0(raw.4, "replay_session.challenge")?,
        archive_context_digest: vec_to_array_32_v0(raw.5, "replay_session.archive_context")?,
        archive_sequence: decode_u64_v0(&raw.6, "replay_session.archive_sequence")?,
        archive_record_digest: vec_to_array_32_v0(raw.7, "replay_session.archive_record")?,
        expected_count: decode_u64_v0(&raw.8, "replay_session.expected_count")?,
        next_cursor: decode_u64_v0(&raw.9, "replay_session.next_cursor")?,
        canonical_store_sequence: decode_u64_v0(&raw.10, "replay_session.canonical_sequence")?,
        canonical_terminal_row_count: decode_u64_v0(&raw.11, "replay_session.canonical_count")?,
        canonical_terminal_audit_digest: vec_to_array_32_v0(
            raw.12,
            "replay_session.canonical_audit",
        )?,
        application_history_digest: vec_to_array_32_v0(raw.13, "replay_session.app_history")?,
        initial_safety_revision: decode_u64_v0(&raw.14, "replay_session.safety_revision")?,
        initial_safety_state_checksum: vec_to_array_32_v0(raw.15, "replay_session.safety_state")?,
        initial_safety_chain_checksum: vec_to_array_32_v0(raw.16, "replay_session.safety_chain")?,
        initial_checkpoint_scope: vec_to_array_32_v0(raw.17, "replay_session.checkpoint_scope")?,
        initial_checkpoint_profile_ref: vec_to_array_32_v0(
            raw.18,
            "replay_session.checkpoint_profile",
        )?,
        initial_checkpoint_generation: decode_u64_v0(
            &raw.19,
            "replay_session.checkpoint_generation",
        )?,
        initial_checkpoint_checksum: vec_to_array_32_v0(raw.20, "replay_session.checkpoint")?,
        signer_scope: vec_to_array_32_v0(raw.21, "replay_session.signer_scope")?,
        signer_journal_id: vec_to_array_32_v0(raw.22, "replay_session.signer_journal")?,
        signer_sequence: decode_u64_v0(&raw.23, "replay_session.signer_sequence")?,
        signer_chain_checksum: vec_to_array_32_v0(raw.24, "replay_session.signer_chain")?,
        previous_progress_checksum: vec_to_array_32_v0(raw.25, "replay_session.progress")?,
        state: DurableReplaySessionStateV0::from_i64(raw.26)?,
        activation_binding_digest: raw
            .27
            .map(|value| vec_to_array_32_v0(value, "replay_session.activation_binding"))
            .transpose()?,
        activation_source_row_revision: raw
            .28
            .map(|value| decode_u64_v0(&value, "replay_session.activation_source_revision"))
            .transpose()?,
        activation_source_row_checksum: raw
            .29
            .map(|value| vec_to_array_32_v0(value, "replay_session.activation_source_checksum"))
            .transpose()?,
        row_revision: decode_u64_v0(&raw.30, "replay_session.row_revision")?,
        row_checksum: vec_to_array_32_v0(raw.31, "replay_session.row_checksum")?,
    };
    if session.session_id == [0; 32]
        || session.expected_count == 0
        || session.initial_safety_revision == 0
        || session.next_cursor > session.expected_count
        || session.row_revision == 0
        || compute_replay_session_id_v0(&session) != session.session_id
        || compute_replay_session_checksum_v0(&session) != session.row_checksum
        || ((session.state == DurableReplaySessionStateV0::Active)
            != (session.next_cursor < session.expected_count))
        || match session.state {
            DurableReplaySessionStateV0::Active
            | DurableReplaySessionStateV0::DurableReplayComplete => {
                session.activation_binding_digest.is_some()
                    || session.activation_source_row_revision.is_some()
                    || session.activation_source_row_checksum.is_some()
            }
            DurableReplaySessionStateV0::ActivationReady => {
                session
                    .activation_binding_digest
                    .is_none_or(|digest| digest == [0; 32])
                    || session
                        .activation_source_row_revision
                        .is_none_or(|revision| {
                            revision == 0 || revision.checked_add(1) != Some(session.row_revision)
                        })
                    || session
                        .activation_source_row_checksum
                        .is_none_or(|checksum| checksum == [0; 32])
            }
        }
    {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_session.integrity",
        ));
    }
    Ok(Some(session))
}

fn load_replay_link_v0(
    connection: &Connection,
    target_validation_id: ValidationIdV0,
) -> ValidationStoreResultV0<Option<ReplayLinkSnapshotV0>> {
    type RawReplayLinkV0 = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );
    let raw: Option<RawReplayLinkV0> = connection
        .query_row(
            "SELECT session_id, cursor, source_validation_id, source_store_sequence,
                    source_row_revision, source_row_checksum,
                    source_application_history_checksum, target_binding, owner_id,
                    artifact_digest, stage, core_revision, core_state_digest,
                    accepted_validation_digest, safety_core_delivery_digest,
                    safety_revision, safety_record_digest, no_sign_closure_digest,
                    alias_closure_checksum, checkpoint_scope, checkpoint_profile_ref,
                    checkpoint_predecessor_checksum, checkpoint_generation,
                    checkpoint_checksum, previous_progress_checksum,
                    row_revision, row_checksum
             FROM proposal_validation_replay_links_v0 WHERE target_validation_id = ?1",
            params![target_validation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                    row.get(21)?,
                    row.get(22)?,
                    row.get(23)?,
                    row.get(24)?,
                    row.get(25)?,
                    row.get(26)?,
                ))
            },
        )
        .optional()
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_link.load"))?;
    let Some(raw) = raw else { return Ok(None) };
    let stage = DurableReplayLinkStageV0::from_i64(raw.10)?;
    let confirmation = match (raw.11, raw.12, raw.13) {
        (None, None, None) if stage == DurableReplayLinkStageV0::Reserved => None,
        (Some(revision), Some(state), Some(accepted))
            if stage != DurableReplayLinkStageV0::Reserved =>
        {
            Some(ConfirmationRecordV0 {
                validation_id: *target_validation_id.as_bytes(),
                core_revision: decode_u64_v0(&revision, "replay_link.core_revision")?,
                core_state_digest: vec_to_array_32_v0(state, "replay_link.core_state")?,
                accepted_validation_digest: vec_to_array_32_v0(accepted, "replay_link.accepted")?,
            })
        }
        _ => {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_link.delivery_shape",
            ))
        }
    };
    let safety_closure = match (raw.14, raw.15, raw.16, raw.17) {
        (None, None, None, None)
            if (stage as u8) < (DurableReplayLinkStageV0::SafetyClosed as u8) =>
        {
            None
        }
        (Some(delivery), Some(revision), Some(record), Some(no_sign))
            if (stage as u8) >= (DurableReplayLinkStageV0::SafetyClosed as u8) =>
        {
            Some(ReplaySafetyClosureRecordV0 {
                core_delivery_digest: vec_to_array_32_v0(delivery, "replay_link.safety_delivery")?,
                safety_revision: decode_u64_v0(&revision, "replay_link.safety_revision")?,
                safety_record_digest: vec_to_array_32_v0(record, "replay_link.safety_record")?,
                no_sign_closure_digest: vec_to_array_32_v0(no_sign, "replay_link.no_sign")?,
            })
        }
        _ => {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_link.safety_shape",
            ))
        }
    };
    let alias_closure_checksum = match raw.18 {
        None if (stage as u8) < (DurableReplayLinkStageV0::AliasClosed as u8) => None,
        Some(value) if (stage as u8) >= (DurableReplayLinkStageV0::AliasClosed as u8) => {
            Some(vec_to_array_32_v0(value, "replay_link.alias_closure")?)
        }
        _ => {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_link.alias_shape",
            ))
        }
    };
    let checkpoint = match (raw.19, raw.20, raw.21, raw.22, raw.23) {
        (None, None, None, None, None) if stage != DurableReplayLinkStageV0::Checkpointed => None,
        (Some(scope), Some(profile), Some(predecessor), Some(generation), Some(checksum))
            if stage == DurableReplayLinkStageV0::Checkpointed =>
        {
            Some(ReplayCheckpointRecordV0 {
                scope: vec_to_array_32_v0(scope, "replay_link.checkpoint_scope")?,
                profile_ref: vec_to_array_32_v0(profile, "replay_link.checkpoint_profile")?,
                predecessor_checksum: vec_to_array_32_v0(
                    predecessor,
                    "replay_link.checkpoint_predecessor",
                )?,
                generation: decode_u64_v0(&generation, "replay_link.checkpoint_generation")?,
                checksum: vec_to_array_32_v0(checksum, "replay_link.checkpoint_checksum")?,
            })
        }
        _ => {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_link.checkpoint_shape",
            ))
        }
    };
    let link = ReplayLinkSnapshotV0 {
        session_id: vec_to_array_32_v0(raw.0, "replay_link.session_id")?,
        cursor: decode_u64_v0(&raw.1, "replay_link.cursor")?,
        source_validation_id: ValidationIdV0::from_bytes(vec_to_array_32_v0(
            raw.2,
            "replay_link.source_id",
        )?),
        source_store_sequence: decode_u64_v0(&raw.3, "replay_link.source_sequence")?,
        source_row_revision: decode_u64_v0(&raw.4, "replay_link.source_revision")?,
        source_row_checksum: vec_to_array_32_v0(raw.5, "replay_link.source_checksum")?,
        source_application_history_checksum: vec_to_array_32_v0(
            raw.6,
            "replay_link.source_history",
        )?,
        target_binding: decode_binding_record_v0(&raw.7)?,
        owner_id: vec_to_array_32_v0(raw.8, "replay_link.owner")?,
        artifact_digest: vec_to_array_32_v0(raw.9, "replay_link.artifact")?,
        previous_progress_checksum: vec_to_array_32_v0(raw.24, "replay_link.previous_progress")?,
        stage,
        confirmation,
        safety_closure,
        alias_closure_checksum,
        checkpoint,
        row_revision: decode_u64_v0(&raw.25, "replay_link.row_revision")?,
        row_checksum: vec_to_array_32_v0(raw.26, "replay_link.row_checksum")?,
    };
    if link.target_binding.validation_id != *target_validation_id.as_bytes()
        || link.owner_id == [0; 32]
        || link.artifact_digest == [0; 32]
        || link.previous_progress_checksum == [0; 32]
        || link.source_application_history_checksum == [0; 32]
        || link.row_revision == 0
        || compute_replay_link_checksum_v0(&link) != link.row_checksum
    {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_link.integrity",
        ));
    }
    Ok(Some(link))
}

fn load_durable_replay_snapshot_v0(
    connection: &Connection,
    target_validation_id: ValidationIdV0,
) -> ValidationStoreResultV0<DurableReplaySnapshotV0> {
    Ok(DurableReplaySnapshotV0 {
        metadata: load_replay_metadata_v0(connection)?,
        session: load_replay_session_v0(connection)?,
        link: load_replay_link_v0(connection, target_validation_id)?,
    })
}

fn load_replay_link_by_cursor_v0(
    connection: &Connection,
    session_id: [u8; 32],
    cursor: u64,
) -> ValidationStoreResultV0<Option<ReplayLinkSnapshotV0>> {
    let target: Option<Vec<u8>> = connection
        .query_row(
            "SELECT target_validation_id FROM proposal_validation_replay_links_v0
             WHERE session_id = ?1 AND cursor = ?2",
            params![session_id.as_slice(), encode_u64_v0(cursor).as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_link.cursor"))?;
    target
        .map(|value| {
            load_replay_link_v0(
                connection,
                ValidationIdV0::from_bytes(vec_to_array_32_v0(value, "replay_link.cursor_id")?),
            )?
            .ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_link.cursor_missing",
                )
            })
        })
        .transpose()
}

fn count_replay_links_v0(connection: &Connection) -> ValidationStoreResultV0<u64> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM proposal_validation_replay_links_v0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_link.count"))?;
    u64::try_from(count).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_link.count_range",
        )
    })
}

fn audit_replay_links_v0(connection: &Connection) -> ValidationStoreResultV0<()> {
    let metadata = load_replay_metadata_v0(connection)?;
    let session = load_replay_session_v0(connection)?;
    let link_count = count_replay_links_v0(connection)?;
    let Some(session) = session else {
        if link_count != 0
            || metadata
                != (ReplayMetadataV0 {
                    sequence: 0,
                    reserved: 0,
                    core_delivered: 0,
                    safety_closed: 0,
                    alias_closed: 0,
                    checkpointed: 0,
                })
        {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_audit.orphan_inventory",
            ));
        }
        return Ok(());
    };
    let canonical_sequence = load_sequence_v0(connection)?;
    if session.validation_store_id == [0; 32]
        || session.validation_scope == [0; 32]
        || session.canonical_store_sequence != canonical_sequence
        || session.canonical_terminal_row_count == 0
        || session.expected_count > session.canonical_terminal_row_count
        || link_count > session.expected_count
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "replay_audit.session_inventory",
        ));
    }
    let canonical_digest = compute_terminal_audit_digest_v0(
        connection,
        ProposalValidationStoreScopeV0::new(session.validation_scope)?,
        session.validation_store_id,
        canonical_sequence,
        session.canonical_terminal_row_count,
    )?;
    if canonical_digest.as_bytes() != &session.canonical_terminal_audit_digest {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "replay_audit.canonical_digest",
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT target_validation_id FROM proposal_validation_replay_links_v0
             WHERE session_id = ?1 ORDER BY cursor",
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_audit.prepare"))?;
    let rows = statement
        .query_map(params![session.session_id.as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_audit.query"))?;
    let mut counted = ReplayMetadataV0 {
        sequence: 0,
        reserved: 0,
        core_delivered: 0,
        safety_closed: 0,
        alias_closed: 0,
        checkpointed: 0,
    };
    let mut progress = compute_initial_replay_progress_v0(&session);
    let mut observed = 0_u64;
    for row in rows {
        let target_id = ValidationIdV0::from_bytes(vec_to_array_32_v0(
            row.map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_audit.target"))?,
            "replay_audit.target",
        )?);
        let link = load_replay_link_v0(connection, target_id)?.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_audit.missing_link",
            )
        })?;
        if link.session_id != session.session_id
            || link.cursor != observed
            || link.previous_progress_checksum != progress
            || link.source_store_sequence != canonical_sequence
            || link.target_binding.route != ProposalRouteV0::Synced.tag()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_audit.link_order",
            ));
        }
        let source_snapshot = load_durable_snapshot_v0(connection, link.source_validation_id)?;
        let source_job = source_snapshot.job.as_ref().ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "replay_audit.source_job",
            )
        })?;
        let source_binding = ProposalValidationBindingV0::from_record(&source_job.binding)?;
        let target_binding = ProposalValidationBindingV0::from_record(&link.target_binding)?;
        if source_snapshot.sequence != canonical_sequence
            || source_snapshot.outbox.is_some()
            || source_job.stage != DurableValidationStageV0::Acked
            || source_job.row_revision != link.source_row_revision
            || source_job.row_checksum != link.source_row_checksum
            || source_job.row_checksum != compute_row_checksum_v0(source_job)
            || source_job.owner_id != link.owner_id
            || source_job.artifact_digest != link.artifact_digest
            || source_binding.route() != ProposalRouteV0::Proposal
            || !same_replay_edge_v0(&source_binding, &target_binding)
            || target_binding.generation() <= source_binding.generation()
            || load_durable_snapshot_v0(connection, target_id)?
                .job
                .is_some()
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_audit.source_alias",
            ));
        }
        if let Some(delivery) = link.confirmation {
            if delivery.core_revision
                != expected_replay_safety_closure_revision_v0(&session, link.cursor)?
            {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_audit.safety_revision",
                ));
            }
            let core_delivery = CoreDeliveryConfirmationV0::new(
                target_id,
                delivery.core_revision,
                NonZeroDigestV0::new(delivery.core_state_digest)?,
                NonZeroDigestV0::new(delivery.accepted_validation_digest)?,
            )?;
            if let Some(safety) = link.safety_closure {
                if safety.core_delivery_digest != *core_delivery.digest().as_bytes()
                    || safety.safety_revision != delivery.core_revision
                    || compute_replay_no_sign_closure_v0(&link)
                        != Some(safety.no_sign_closure_digest)
                {
                    return Err(error(
                        ValidationStoreErrorCodeV0::BindingMismatch,
                        "replay_audit.safety_closure",
                    ));
                }
            }
        }
        if (link.stage as u8) >= (DurableReplayLinkStageV0::AliasClosed as u8)
            && link.alias_closure_checksum != compute_replay_alias_closure_v0(&link)
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_audit.alias_closure",
            ));
        }
        if link.stage == DurableReplayLinkStageV0::Checkpointed {
            progress = compute_replay_checkpoint_progress_v0(&link).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_audit.checkpoint_progress",
                )
            })?;
        } else if link.cursor != session.next_cursor {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "replay_audit.multiple_frontier",
            ));
        }
        counted.reserved = counted.reserved.checked_add(1).ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::Overflow,
                "replay_audit.reserved",
            )
        })?;
        if (link.stage as u8) >= (DurableReplayLinkStageV0::CoreDelivered as u8) {
            counted.core_delivered = counted.core_delivered.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_audit.delivered",
                )
            })?;
        }
        if (link.stage as u8) >= (DurableReplayLinkStageV0::SafetyClosed as u8) {
            counted.safety_closed = counted.safety_closed.checked_add(1).ok_or_else(|| {
                error(ValidationStoreErrorCodeV0::Overflow, "replay_audit.safety")
            })?;
        }
        if (link.stage as u8) >= (DurableReplayLinkStageV0::AliasClosed as u8) {
            counted.alias_closed = counted
                .alias_closed
                .checked_add(1)
                .ok_or_else(|| error(ValidationStoreErrorCodeV0::Overflow, "replay_audit.alias"))?;
        }
        if link.stage == DurableReplayLinkStageV0::Checkpointed {
            counted.checkpointed = counted.checkpointed.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "replay_audit.checkpointed",
                )
            })?;
        }
        observed = observed.checked_add(1).ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::Overflow,
                "replay_audit.observed",
            )
        })?;
    }
    drop(statement);
    counted.sequence = counted
        .reserved
        .checked_add(counted.core_delivered)
        .and_then(|value| value.checked_add(counted.safety_closed))
        .and_then(|value| value.checked_add(counted.alias_closed))
        .and_then(|value| value.checked_add(counted.checkpointed))
        .ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::Overflow,
                "replay_audit.sequence",
            )
        })?;
    if counted != metadata
        || counted.checkpointed != session.next_cursor
        || observed != link_count
        || observed > session.next_cursor.saturating_add(1)
        || session.previous_progress_checksum != progress
        || (session.state == DurableReplaySessionStateV0::Active
            && session.next_cursor >= session.expected_count)
        || (session.state != DurableReplaySessionStateV0::Active
            && (session.next_cursor != session.expected_count
                || observed != session.expected_count
                || counted.checkpointed != session.expected_count))
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "replay_audit.frontier",
        ));
    }
    Ok(())
}

fn load_job_v0(
    connection: &Connection,
    validation_id: ValidationIdV0,
) -> ValidationStoreResultV0<Option<JobSnapshotV0>> {
    let raw = connection
        .query_row(
            "SELECT binding, owner_id, artifact_digest, artifact, stage, core_revision,
                    core_state_digest, accepted_validation_digest,
                    safety_core_delivery_digest, safety_revision, safety_record_digest,
                    vote_intent_digest, row_revision, row_checksum
             FROM proposal_validation_jobs_v0 WHERE validation_id = ?1",
            params![validation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                ))
            },
        )
        .optional()
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "job.load"))?;
    let Some((
        binding,
        owner,
        artifact,
        artifact_bytes,
        stage,
        revision,
        core_state,
        accepted_validation,
        safety_core_delivery,
        safety_revision,
        safety_record,
        vote_intent,
        row_revision,
        checksum,
    )) = raw
    else {
        return Ok(None);
    };
    let stage = DurableValidationStageV0::from_i64(stage)?;
    let confirmation = match (revision, core_state, accepted_validation) {
        (None, None, None) if stage == DurableValidationStageV0::Reserved => None,
        (Some(revision), Some(core_state), Some(accepted_validation))
            if stage != DurableValidationStageV0::Reserved =>
        {
            Some(ConfirmationRecordV0 {
                validation_id: *validation_id.as_bytes(),
                core_revision: decode_u64_v0(&revision, "job.core_revision")?,
                core_state_digest: vec_to_array_32_v0(core_state, "job.core_state")?,
                accepted_validation_digest: vec_to_array_32_v0(
                    accepted_validation,
                    "job.accepted_validation",
                )?,
            })
        }
        _ => {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "job.confirmation_shape",
            ));
        }
    };
    let safety_confirmation = match (
        safety_core_delivery,
        safety_revision,
        safety_record,
        vote_intent,
    ) {
        (None, None, None, None) if stage != DurableValidationStageV0::Acked => None,
        (Some(core_delivery), Some(revision), Some(record), Some(vote_intent))
            if stage == DurableValidationStageV0::Acked =>
        {
            Some(SafetyConfirmationRecordV0 {
                core_delivery_digest: vec_to_array_32_v0(
                    core_delivery,
                    "job.safety_core_delivery",
                )?,
                safety_revision: decode_u64_v0(&revision, "job.safety_revision")?,
                safety_record_digest: vec_to_array_32_v0(record, "job.safety_record")?,
                vote_intent_digest: vec_to_array_32_v0(vote_intent, "job.vote_intent")?,
            })
        }
        _ => {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "job.safety_confirmation_shape",
            ));
        }
    };
    let job = JobSnapshotV0 {
        binding: decode_binding_record_v0(&binding)?,
        owner_id: vec_to_array_32_v0(owner, "job.owner_id")?,
        artifact_digest: vec_to_array_32_v0(artifact, "job.artifact_digest")?,
        artifact: artifact_bytes,
        stage,
        confirmation,
        safety_confirmation,
        row_revision: decode_u64_v0(&row_revision, "job.row_revision")?,
        row_checksum: vec_to_array_32_v0(checksum, "job.row_checksum")?,
    };
    ProposalValidationBindingV0::from_record(&job.binding)?;
    if job.binding.validation_id != *validation_id.as_bytes()
        || job.owner_id == [0; 32]
        || job.artifact_digest == [0; 32]
        || job.artifact.is_empty()
        || job.artifact.len() > MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0
        || job.confirmation.is_some_and(|value| {
            value.validation_id != job.binding.validation_id
                || value.core_revision == 0
                || value.core_state_digest == [0; 32]
                || value.accepted_validation_digest == [0; 32]
        })
        || job.safety_confirmation.is_some_and(|value| {
            value.core_delivery_digest == [0; 32]
                || value.safety_revision == 0
                || value.safety_record_digest == [0; 32]
                || value.vote_intent_digest == [0; 32]
                || job
                    .confirmation
                    .and_then(core_delivery_digest_from_record_v0)
                    != Some(value.core_delivery_digest)
                || job.confirmation.map(|delivery| delivery.core_revision)
                    != Some(value.safety_revision)
        })
        || compute_row_checksum_v0(&job) != job.row_checksum
    {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "job.integrity",
        ));
    }
    decode_checked_artifact_v0(&job.binding, &job.artifact, job.artifact_digest)?;
    Ok(Some(job))
}

fn load_outbox_v0(
    connection: &Connection,
    validation_id: ValidationIdV0,
) -> ValidationStoreResultV0<Option<ConfirmationRecordV0>> {
    let raw: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT core_revision, core_state_digest, accepted_validation_digest
             FROM proposal_validation_outbox_v0 WHERE validation_id = ?1",
            params![validation_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "outbox.load"))?;
    raw.map(|(revision, core_state, accepted_validation)| {
        let record = ConfirmationRecordV0 {
            validation_id: *validation_id.as_bytes(),
            core_revision: decode_u64_v0(&revision, "outbox.core_revision")?,
            core_state_digest: vec_to_array_32_v0(core_state, "outbox.core_state")?,
            accepted_validation_digest: vec_to_array_32_v0(
                accepted_validation,
                "outbox.accepted_validation",
            )?,
        };
        if record.core_revision == 0
            || record.core_state_digest == [0; 32]
            || record.accepted_validation_digest == [0; 32]
        {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "outbox.integrity",
            ));
        }
        Ok(record)
    })
    .transpose()
}

fn insert_replay_session_v0(
    connection: &Connection,
    session: &ReplaySessionSnapshotV0,
) -> ValidationStoreResultV0<()> {
    connection
        .execute(
            "INSERT INTO proposal_validation_replay_session_v0
             (singleton, session_id, core_config_ref, validation_scope, validation_store_id,
              recovery_challenge_digest, archive_context_digest, archive_sequence,
              archive_record_digest, expected_count, next_cursor, canonical_store_sequence,
              canonical_terminal_row_count, canonical_terminal_audit_digest,
              application_history_digest, initial_safety_revision,
              initial_safety_state_checksum, initial_safety_chain_checksum,
              initial_checkpoint_scope, initial_checkpoint_profile_ref,
              initial_checkpoint_generation,
              initial_checkpoint_checksum, signer_scope, signer_journal_id, signer_sequence,
              signer_chain_checksum, previous_progress_checksum, state,
              activation_binding_digest, activation_source_row_revision,
              activation_source_row_checksum, row_revision, row_checksum)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                     ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25,
                     ?26, ?27, ?28, ?29, ?30, ?31, ?32)",
            params![
                session.session_id.as_slice(),
                session.core_config_ref.as_slice(),
                session.validation_scope.as_slice(),
                session.validation_store_id.as_slice(),
                session.recovery_challenge_digest.as_slice(),
                session.archive_context_digest.as_slice(),
                encode_u64_v0(session.archive_sequence).as_slice(),
                session.archive_record_digest.as_slice(),
                encode_u64_v0(session.expected_count).as_slice(),
                encode_u64_v0(session.next_cursor).as_slice(),
                encode_u64_v0(session.canonical_store_sequence).as_slice(),
                encode_u64_v0(session.canonical_terminal_row_count).as_slice(),
                session.canonical_terminal_audit_digest.as_slice(),
                session.application_history_digest.as_slice(),
                encode_u64_v0(session.initial_safety_revision).as_slice(),
                session.initial_safety_state_checksum.as_slice(),
                session.initial_safety_chain_checksum.as_slice(),
                session.initial_checkpoint_scope.as_slice(),
                session.initial_checkpoint_profile_ref.as_slice(),
                encode_u64_v0(session.initial_checkpoint_generation).as_slice(),
                session.initial_checkpoint_checksum.as_slice(),
                session.signer_scope.as_slice(),
                session.signer_journal_id.as_slice(),
                encode_u64_v0(session.signer_sequence).as_slice(),
                session.signer_chain_checksum.as_slice(),
                session.previous_progress_checksum.as_slice(),
                session.state as u8,
                session
                    .activation_binding_digest
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                session
                    .activation_source_row_revision
                    .map(|revision| encode_u64_v0(revision).to_vec()),
                session
                    .activation_source_row_checksum
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                encode_u64_v0(session.row_revision).as_slice(),
                session.row_checksum.as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_session.insert"))?;
    Ok(())
}

fn replace_replay_session_v0(
    connection: &Connection,
    source: &ReplaySessionSnapshotV0,
    target: &ReplaySessionSnapshotV0,
) -> ValidationStoreResultV0<()> {
    let changed = connection
        .execute(
            "UPDATE proposal_validation_replay_session_v0
             SET next_cursor = ?1, previous_progress_checksum = ?2, state = ?3,
                 activation_binding_digest = ?4, activation_source_row_revision = ?5,
                 activation_source_row_checksum = ?6, row_revision = ?7, row_checksum = ?8
             WHERE singleton = 1 AND session_id = ?9 AND row_revision = ?10 AND row_checksum = ?11",
            params![
                encode_u64_v0(target.next_cursor).as_slice(),
                target.previous_progress_checksum.as_slice(),
                target.state as u8,
                target
                    .activation_binding_digest
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                target
                    .activation_source_row_revision
                    .map(|revision| encode_u64_v0(revision).to_vec()),
                target
                    .activation_source_row_checksum
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                encode_u64_v0(target.row_revision).as_slice(),
                target.row_checksum.as_slice(),
                source.session_id.as_slice(),
                encode_u64_v0(source.row_revision).as_slice(),
                source.row_checksum.as_slice(),
            ],
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "replay_session.replace",
            )
        })?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_session.replace_cas",
        ));
    }
    Ok(())
}

fn insert_replay_link_v0(
    connection: &Connection,
    link: &ReplayLinkSnapshotV0,
) -> ValidationStoreResultV0<()> {
    let target_binding = encode_binding_record_v0(&link.target_binding)?;
    let (core_revision, core_state, accepted) = encode_confirmation_v0(link.confirmation);
    let (safety_delivery, safety_revision, safety_record, no_sign) =
        link.safety_closure
            .map_or((None, None, None, None), |value| {
                (
                    Some(value.core_delivery_digest.to_vec()),
                    Some(encode_u64_v0(value.safety_revision).to_vec()),
                    Some(value.safety_record_digest.to_vec()),
                    Some(value.no_sign_closure_digest.to_vec()),
                )
            });
    let (
        checkpoint_scope,
        checkpoint_profile,
        checkpoint_predecessor,
        checkpoint_generation,
        checkpoint_checksum,
    ) = link
        .checkpoint
        .map_or((None, None, None, None, None), |value| {
            (
                Some(value.scope.to_vec()),
                Some(value.profile_ref.to_vec()),
                Some(value.predecessor_checksum.to_vec()),
                Some(encode_u64_v0(value.generation).to_vec()),
                Some(value.checksum.to_vec()),
            )
        });
    connection
        .execute(
            "INSERT INTO proposal_validation_replay_links_v0
             (target_validation_id, session_id, cursor, source_validation_id,
              source_store_sequence, source_row_revision, source_row_checksum,
              source_application_history_checksum, target_binding, owner_id, artifact_digest,
              previous_progress_checksum, stage, core_revision, core_state_digest,
              accepted_validation_digest, safety_core_delivery_digest, safety_revision,
              safety_record_digest, no_sign_closure_digest, alias_closure_checksum,
              checkpoint_scope, checkpoint_profile_ref, checkpoint_predecessor_checksum,
              checkpoint_generation, checkpoint_checksum, row_revision, row_checksum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                     ?27, ?28)",
            params![
                link.target_binding.validation_id.as_slice(),
                link.session_id.as_slice(),
                encode_u64_v0(link.cursor).as_slice(),
                link.source_validation_id.as_bytes().as_slice(),
                encode_u64_v0(link.source_store_sequence).as_slice(),
                encode_u64_v0(link.source_row_revision).as_slice(),
                link.source_row_checksum.as_slice(),
                link.source_application_history_checksum.as_slice(),
                target_binding,
                link.owner_id.as_slice(),
                link.artifact_digest.as_slice(),
                link.previous_progress_checksum.as_slice(),
                link.stage as u8,
                core_revision,
                core_state,
                accepted,
                safety_delivery,
                safety_revision,
                safety_record,
                no_sign,
                link.alias_closure_checksum.map(|value| value.to_vec()),
                checkpoint_scope,
                checkpoint_profile,
                checkpoint_predecessor,
                checkpoint_generation,
                checkpoint_checksum,
                encode_u64_v0(link.row_revision).as_slice(),
                link.row_checksum.as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_link.insert"))?;
    Ok(())
}

fn replace_replay_link_v0(
    connection: &Connection,
    source: &ReplayLinkSnapshotV0,
    target: &ReplayLinkSnapshotV0,
) -> ValidationStoreResultV0<()> {
    let (core_revision, core_state, accepted) = encode_confirmation_v0(target.confirmation);
    let (safety_delivery, safety_revision, safety_record, no_sign) =
        target
            .safety_closure
            .map_or((None, None, None, None), |value| {
                (
                    Some(value.core_delivery_digest.to_vec()),
                    Some(encode_u64_v0(value.safety_revision).to_vec()),
                    Some(value.safety_record_digest.to_vec()),
                    Some(value.no_sign_closure_digest.to_vec()),
                )
            });
    let (
        checkpoint_scope,
        checkpoint_profile,
        checkpoint_predecessor,
        checkpoint_generation,
        checkpoint_checksum,
    ) = target
        .checkpoint
        .map_or((None, None, None, None, None), |value| {
            (
                Some(value.scope.to_vec()),
                Some(value.profile_ref.to_vec()),
                Some(value.predecessor_checksum.to_vec()),
                Some(encode_u64_v0(value.generation).to_vec()),
                Some(value.checksum.to_vec()),
            )
        });
    let changed = connection
        .execute(
            "UPDATE proposal_validation_replay_links_v0
             SET stage = ?1, core_revision = ?2, core_state_digest = ?3,
                 accepted_validation_digest = ?4, safety_core_delivery_digest = ?5,
                 safety_revision = ?6, safety_record_digest = ?7,
                 no_sign_closure_digest = ?8, alias_closure_checksum = ?9,
                 checkpoint_scope = ?10, checkpoint_profile_ref = ?11,
                 checkpoint_predecessor_checksum = ?12, checkpoint_generation = ?13,
                 checkpoint_checksum = ?14, row_revision = ?15, row_checksum = ?16
             WHERE target_validation_id = ?17 AND stage = ?18
                   AND row_revision = ?19 AND row_checksum = ?20",
            params![
                target.stage as u8,
                core_revision,
                core_state,
                accepted,
                safety_delivery,
                safety_revision,
                safety_record,
                no_sign,
                target.alias_closure_checksum.map(|value| value.to_vec()),
                checkpoint_scope,
                checkpoint_profile,
                checkpoint_predecessor,
                checkpoint_generation,
                checkpoint_checksum,
                encode_u64_v0(target.row_revision).as_slice(),
                target.row_checksum.as_slice(),
                target.target_binding.validation_id.as_slice(),
                source.stage as u8,
                encode_u64_v0(source.row_revision).as_slice(),
                source.row_checksum.as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "replay_link.replace"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_link.replace_cas",
        ));
    }
    Ok(())
}

fn update_replay_metadata_v0(
    connection: &Connection,
    source: ReplayMetadataV0,
    target: ReplayMetadataV0,
) -> ValidationStoreResultV0<()> {
    let changed = connection
        .execute(
            "UPDATE proposal_validation_replay_metadata_v0
             SET sequence = ?1, reserved = ?2, core_delivered = ?3,
                 safety_closed = ?4, alias_closed = ?5, checkpointed = ?6
             WHERE singleton = 1 AND sequence = ?7 AND reserved = ?8
                   AND core_delivered = ?9 AND safety_closed = ?10
                   AND alias_closed = ?11 AND checkpointed = ?12",
            params![
                encode_u64_v0(target.sequence).as_slice(),
                encode_u64_v0(target.reserved).as_slice(),
                encode_u64_v0(target.core_delivered).as_slice(),
                encode_u64_v0(target.safety_closed).as_slice(),
                encode_u64_v0(target.alias_closed).as_slice(),
                encode_u64_v0(target.checkpointed).as_slice(),
                encode_u64_v0(source.sequence).as_slice(),
                encode_u64_v0(source.reserved).as_slice(),
                encode_u64_v0(source.core_delivered).as_slice(),
                encode_u64_v0(source.safety_closed).as_slice(),
                encode_u64_v0(source.alias_closed).as_slice(),
                encode_u64_v0(source.checkpointed).as_slice(),
            ],
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "replay_metadata.update",
            )
        })?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_metadata.update_cas",
        ));
    }
    Ok(())
}

fn insert_job_v0(connection: &Connection, job: &JobSnapshotV0) -> ValidationStoreResultV0<()> {
    let binding = encode_binding_record_v0(&job.binding)?;
    let (revision, core_state, accepted_validation) = encode_confirmation_v0(job.confirmation);
    let (safety_core_delivery, safety_revision, safety_record, vote_intent) =
        encode_safety_confirmation_v0(job.safety_confirmation);
    connection
        .execute(
            "INSERT INTO proposal_validation_jobs_v0
             (validation_id, binding, owner_id, artifact_digest, artifact, stage,
              core_revision, core_state_digest, accepted_validation_digest,
              safety_core_delivery_digest, safety_revision, safety_record_digest,
              vote_intent_digest, row_revision, row_checksum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                job.binding.validation_id.as_slice(),
                binding,
                job.owner_id.as_slice(),
                job.artifact_digest.as_slice(),
                job.artifact.as_slice(),
                job.stage as u8,
                revision,
                core_state,
                accepted_validation,
                safety_core_delivery,
                safety_revision,
                safety_record,
                vote_intent,
                encode_u64_v0(job.row_revision).as_slice(),
                job.row_checksum.as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "job.insert"))?;
    Ok(())
}

fn replace_job_v0(
    connection: &Connection,
    source: &Option<JobSnapshotV0>,
    target: &JobSnapshotV0,
) -> ValidationStoreResultV0<()> {
    let source = source.as_ref().ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "job.replace_missing_source",
        )
    })?;
    let (revision, core_state, accepted_validation) = encode_confirmation_v0(target.confirmation);
    let (safety_core_delivery, safety_revision, safety_record, vote_intent) =
        encode_safety_confirmation_v0(target.safety_confirmation);
    let changed = connection
        .execute(
            "UPDATE proposal_validation_jobs_v0
             SET stage = ?1, core_revision = ?2, core_state_digest = ?3,
                 accepted_validation_digest = ?4, safety_core_delivery_digest = ?5,
                 safety_revision = ?6, safety_record_digest = ?7, vote_intent_digest = ?8,
                 row_revision = ?9, row_checksum = ?10
             WHERE validation_id = ?11 AND stage = ?12 AND row_revision = ?13
                   AND row_checksum = ?14",
            params![
                target.stage as u8,
                revision,
                core_state,
                accepted_validation,
                safety_core_delivery,
                safety_revision,
                safety_record,
                vote_intent,
                encode_u64_v0(target.row_revision).as_slice(),
                target.row_checksum.as_slice(),
                target.binding.validation_id.as_slice(),
                source.stage as u8,
                encode_u64_v0(source.row_revision).as_slice(),
                source.row_checksum.as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "job.replace"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "job.replace_cas",
        ));
    }
    Ok(())
}

fn insert_outbox_v0(
    connection: &Connection,
    validation_id: ValidationIdV0,
    confirmation: ConfirmationRecordV0,
) -> ValidationStoreResultV0<()> {
    if confirmation.validation_id != *validation_id.as_bytes() {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "outbox.insert_validation_id",
        ));
    }
    connection
        .execute(
            "INSERT INTO proposal_validation_outbox_v0
             (validation_id, core_revision, core_state_digest, accepted_validation_digest)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                validation_id.as_bytes().as_slice(),
                encode_u64_v0(confirmation.core_revision).as_slice(),
                confirmation.core_state_digest.as_slice(),
                confirmation.accepted_validation_digest.as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "outbox.insert"))?;
    Ok(())
}

fn delete_outbox_v0(
    connection: &Connection,
    validation_id: ValidationIdV0,
    confirmation: ConfirmationRecordV0,
) -> ValidationStoreResultV0<()> {
    if confirmation.validation_id != *validation_id.as_bytes() {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "outbox.delete_validation_id",
        ));
    }
    let changed = connection
        .execute(
            "DELETE FROM proposal_validation_outbox_v0
             WHERE validation_id = ?1 AND core_revision = ?2
                   AND core_state_digest = ?3 AND accepted_validation_digest = ?4",
            params![
                validation_id.as_bytes().as_slice(),
                encode_u64_v0(confirmation.core_revision).as_slice(),
                confirmation.core_state_digest.as_slice(),
                confirmation.accepted_validation_digest.as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "outbox.delete"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "outbox.delete_cas",
        ));
    }
    Ok(())
}

fn require_source_job_v0(
    source: &DurableSnapshotV0,
    stage: DurableValidationStageV0,
    owner_id: ProposalValidationOwnerIdV0,
    artifact_digest: NonZeroDigestV0,
    row_revision: u64,
) -> ValidationStoreResultV0<()> {
    let job = source.job.as_ref().ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::NotFound,
            "transition.source_job",
        )
    })?;
    if job.stage != stage || job.row_revision != row_revision {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "transition.source_stage",
        ));
    }
    if job.owner_id.as_slice() != owner_id.as_bytes()
        || job.artifact_digest.as_slice() != artifact_digest.as_bytes()
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ForeignToken,
            "transition.source_owner",
        ));
    }
    Ok(())
}

fn update_sequence_v0(
    connection: &Connection,
    source: u64,
    target: u64,
) -> ValidationStoreResultV0<()> {
    let changed = connection
        .execute(
            "UPDATE validation_store_metadata_v0 SET sequence = ?1
             WHERE singleton = 1 AND sequence = ?2",
            params![
                encode_u64_v0(target).as_slice(),
                encode_u64_v0(source).as_slice()
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "sequence.update"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "sequence.cas",
        ));
    }
    Ok(())
}

fn update_accounting_v0(
    connection: &Connection,
    source: AccountingV0,
    target: AccountingV0,
) -> ValidationStoreResultV0<()> {
    let changed = connection
        .execute(
            "UPDATE validation_store_accounting_v0
             SET reserved = ?1, delivered = ?2, acked = ?3
             WHERE singleton = 1 AND reserved = ?4 AND delivered = ?5 AND acked = ?6",
            params![
                encode_u64_v0(target.reserved).as_slice(),
                encode_u64_v0(target.delivered).as_slice(),
                encode_u64_v0(target.acked).as_slice(),
                encode_u64_v0(source.reserved).as_slice(),
                encode_u64_v0(source.delivered).as_slice(),
                encode_u64_v0(source.acked).as_slice(),
            ],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "accounting.update"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "accounting.cas",
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
fn finish_transaction_v0(
    transaction: rusqlite::Transaction<'_>,
    fault: Option<TestCommitFaultV0>,
) -> ValidationStoreResultV0<bool> {
    match fault {
        Some(TestCommitFaultV0::NotAppliedAckLost) => {
            transaction.rollback().map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "transaction.rollback",
                )
            })?;
            Ok(true)
        }
        Some(TestCommitFaultV0::AppliedAckLost | TestCommitFaultV0::ThirdState) => {
            transaction.commit().map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "transaction.commit",
                )
            })?;
            Ok(true)
        }
        None => match transaction.commit() {
            Ok(()) => Ok(false),
            Err(_) => Ok(true),
        },
    }
}

#[cfg(not(any(test, feature = "test-support")))]
fn finish_transaction_v0(
    transaction: rusqlite::Transaction<'_>,
    _fault: Option<()>,
) -> ValidationStoreResultV0<bool> {
    match transaction.commit() {
        Ok(()) => Ok(false),
        Err(_) => Ok(true),
    }
}

fn compute_row_checksum_v0(job: &JobSnapshotV0) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROW_CHECKSUM_DOMAIN_V0);
    if let Ok(binding) = encode_binding_record_v0(&job.binding) {
        hasher.update((binding.len() as u32).to_be_bytes());
        hasher.update(binding);
    } else {
        hasher.update(u32::MAX.to_be_bytes());
    }
    hasher.update(job.owner_id);
    hasher.update(job.artifact_digest);
    hasher.update((job.artifact.len() as u64).to_be_bytes());
    hasher.update(&job.artifact);
    hasher.update([job.stage as u8]);
    match job.confirmation {
        Some(confirmation) => {
            hasher.update([1]);
            hasher.update(confirmation.validation_id);
            hasher.update(confirmation.core_revision.to_be_bytes());
            hasher.update(confirmation.core_state_digest);
            hasher.update(confirmation.accepted_validation_digest);
        }
        None => hasher.update([0]),
    }
    match job.safety_confirmation {
        Some(confirmation) => {
            hasher.update([1]);
            hasher.update(confirmation.core_delivery_digest);
            hasher.update(confirmation.safety_revision.to_be_bytes());
            hasher.update(confirmation.safety_record_digest);
            hasher.update(confirmation.vote_intent_digest);
        }
        None => hasher.update([0]),
    }
    hasher.update(job.row_revision.to_be_bytes());
    hasher.finalize().into()
}

fn replay_session_from_plan_v0(
    scope: ProposalValidationStoreScopeV0,
    store_id: [u8; 32],
    audit: &ConfirmedProposalValidationTerminalAuditV0,
    plan: ReplaySessionPlanV0,
) -> ValidationStoreResultV0<ReplaySessionSnapshotV0> {
    if audit.scope != scope
        || audit.store_id != store_id
        || audit.store_sequence == 0
        || audit.terminal_row_count == 0
        || plan.expected_count > audit.terminal_row_count
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "replay_session_plan.audit",
        ));
    }
    let mut session = ReplaySessionSnapshotV0 {
        session_id: [0; 32],
        core_config_ref: *plan.core_config_ref.as_bytes(),
        validation_scope: *scope.as_bytes(),
        validation_store_id: store_id,
        recovery_challenge_digest: *plan.recovery_challenge_digest.as_bytes(),
        archive_context_digest: *plan.archive_context_digest.as_bytes(),
        archive_sequence: plan.archive_sequence,
        archive_record_digest: *plan.archive_record_digest.as_bytes(),
        expected_count: plan.expected_count,
        next_cursor: 0,
        canonical_store_sequence: audit.store_sequence,
        canonical_terminal_row_count: audit.terminal_row_count,
        canonical_terminal_audit_digest: *audit.terminal_audit_digest.as_bytes(),
        application_history_digest: *plan.application_history_digest.as_bytes(),
        initial_safety_revision: plan.initial_safety_revision,
        initial_safety_state_checksum: *plan.initial_safety_state_checksum.as_bytes(),
        initial_safety_chain_checksum: *plan.initial_safety_chain_checksum.as_bytes(),
        initial_checkpoint_scope: *plan.initial_checkpoint_scope.as_bytes(),
        initial_checkpoint_profile_ref: *plan.initial_checkpoint_profile_ref.as_bytes(),
        initial_checkpoint_generation: plan.initial_checkpoint_generation,
        initial_checkpoint_checksum: *plan.initial_checkpoint_checksum.as_bytes(),
        signer_scope: *plan.signer_scope.as_bytes(),
        signer_journal_id: *plan.signer_journal_id.as_bytes(),
        signer_sequence: plan.signer_sequence,
        signer_chain_checksum: *plan.signer_chain_checksum.as_bytes(),
        previous_progress_checksum: [0; 32],
        state: DurableReplaySessionStateV0::Active,
        activation_binding_digest: None,
        activation_source_row_revision: None,
        activation_source_row_checksum: None,
        row_revision: 1,
        row_checksum: [0; 32],
    };
    session.session_id = compute_replay_session_id_v0(&session);
    session.previous_progress_checksum = compute_initial_replay_progress_v0(&session);
    if session.session_id == [0; 32] || session.previous_progress_checksum == [0; 32] {
        return Err(error(
            ValidationStoreErrorCodeV0::ZeroValue,
            "replay_session_plan.digest",
        ));
    }
    Ok(session)
}

fn active_replay_session_token_v0(
    store_id: [u8; 32],
    session: &ReplaySessionSnapshotV0,
) -> ValidationStoreResultV0<ActiveReplaySessionV0> {
    if session.state != DurableReplaySessionStateV0::Active
        || session.next_cursor >= session.expected_count
    {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_session.not_active",
        ));
    }
    Ok(ActiveReplaySessionV0 {
        store_id,
        session_id: session.session_id,
        next_cursor: session.next_cursor,
        expected_count: session.expected_count,
        previous_progress_checksum: NonZeroDigestV0::new(session.previous_progress_checksum)?,
        row_revision: session.row_revision,
        row_checksum: NonZeroDigestV0::new(session.row_checksum)?,
    })
}

fn durable_replay_complete_token_v0(
    store_id: [u8; 32],
    session: &ReplaySessionSnapshotV0,
) -> ValidationStoreResultV0<DurableReplayCompleteV0> {
    if !matches!(
        session.state,
        DurableReplaySessionStateV0::DurableReplayComplete
            | DurableReplaySessionStateV0::ActivationReady
    ) || session.next_cursor != session.expected_count
    {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_session.not_complete",
        ));
    }
    Ok(DurableReplayCompleteV0 {
        store_id,
        session_id: session.session_id,
        expected_count: session.expected_count,
        final_progress_checksum: NonZeroDigestV0::new(session.previous_progress_checksum)?,
        row_revision: session.row_revision,
        row_checksum: NonZeroDigestV0::new(session.row_checksum)?,
    })
}

fn require_active_replay_session_token_v0(
    session: &ReplaySessionSnapshotV0,
    token: &ActiveReplaySessionV0,
) -> ValidationStoreResultV0<()> {
    if session.state != DurableReplaySessionStateV0::Active
        || session.session_id != token.session_id
        || session.validation_store_id != token.store_id
        || session.next_cursor != token.next_cursor
        || session.expected_count != token.expected_count
        || session.previous_progress_checksum != *token.previous_progress_checksum.as_bytes()
        || session.row_revision != token.row_revision
        || session.row_checksum != *token.row_checksum.as_bytes()
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ForeignToken,
            "replay_session.token",
        ));
    }
    Ok(())
}

fn expected_replay_safety_closure_revision_v0(
    session: &ReplaySessionSnapshotV0,
    cursor: u64,
) -> ValidationStoreResultV0<u64> {
    cursor
        .checked_mul(2)
        .and_then(|offset| session.initial_safety_revision.checked_add(offset))
        .and_then(|revision| revision.checked_add(2))
        .ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::Overflow,
                "replay_safety.expected_revision",
            )
        })
}

fn require_exact_replay_source_k_v0(
    snapshot: &DurableSnapshotV0,
    fresh: &ConfirmedProposalValidationCheckpointFactsV0,
    binding: &ProposalValidationBindingV0,
    owner: ProposalValidationOwnerIdV0,
) -> ValidationStoreResultV0<()> {
    let job = snapshot.job.as_ref().ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::NotFound,
            "replay_source_k.missing",
        )
    })?;
    let confirmation = job.confirmation.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_source_k.delivery",
        )
    })?;
    let safety = job.safety_confirmation.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_source_k.safety",
        )
    })?;
    if snapshot.sequence != fresh.store_sequence
        || snapshot.outbox.is_some()
        || job.binding != binding.to_record()
        || job.owner_id != *owner.as_bytes()
        || job.stage != DurableValidationStageV0::Acked
        || job.row_revision != fresh.row_revision
        || job.row_checksum != *fresh.row_checksum.as_bytes()
        || job.row_checksum != compute_row_checksum_v0(job)
        || job.artifact_digest != *fresh.artifact_digest.as_bytes()
        || confirmation.validation_id != *binding.validation_id().as_bytes()
        || core_delivery_digest_from_record_v0(confirmation)
            != Some(*fresh.core_delivery_digest.as_bytes())
        || safety.core_delivery_digest != *fresh.safety_closure.core_delivery_digest().as_bytes()
        || safety.safety_revision != fresh.safety_closure.safety_revision()
        || safety.safety_record_digest != *fresh.safety_closure.safety_record_digest().as_bytes()
        || safety.vote_intent_digest != *fresh.safety_closure.vote_intent_digest().as_bytes()
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "replay_source_k.freshness",
        ));
    }
    decode_checked_artifact_v0(&job.binding, &job.artifact, job.artifact_digest)?;
    Ok(())
}

fn reserved_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
) -> ValidationStoreResultV0<ReservedReplayLinkPV0> {
    if link.stage != DurableReplayLinkStageV0::Reserved {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_link.reserved_token",
        ));
    }
    Ok(ReservedReplayLinkPV0 {
        store_id,
        session_id: link.session_id,
        cursor: link.cursor,
        source_validation_id: link.source_validation_id,
        target_validation_id: ValidationIdV0::from_bytes(link.target_binding.validation_id),
        owner_id: ProposalValidationOwnerIdV0::new(link.owner_id)?,
        artifact_digest: NonZeroDigestV0::new(link.artifact_digest)?,
        row_revision: link.row_revision,
        row_checksum: NonZeroDigestV0::new(link.row_checksum)?,
    })
}

fn require_reserved_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
    token: &ReservedReplayLinkPV0,
) -> ValidationStoreResultV0<()> {
    if token.store_id != store_id
        || link.stage != DurableReplayLinkStageV0::Reserved
        || link.session_id != token.session_id
        || link.cursor != token.cursor
        || link.source_validation_id != token.source_validation_id
        || link.target_binding.validation_id != *token.target_validation_id.as_bytes()
        || link.owner_id != *token.owner_id.as_bytes()
        || link.artifact_digest != *token.artifact_digest.as_bytes()
        || link.row_revision != token.row_revision
        || link.row_checksum != *token.row_checksum.as_bytes()
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ForeignToken,
            "replay_link.reserved_authority",
        ));
    }
    Ok(())
}

fn delivered_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
) -> ValidationStoreResultV0<CoreDeliveredReplayLinkDV0> {
    let confirmation = link.confirmation.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_link.delivered_token",
        )
    })?;
    if link.stage != DurableReplayLinkStageV0::CoreDelivered {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_link.delivered_stage",
        ));
    }
    Ok(CoreDeliveredReplayLinkDV0 {
        store_id,
        session_id: link.session_id,
        cursor: link.cursor,
        source_validation_id: link.source_validation_id,
        target_validation_id: ValidationIdV0::from_bytes(link.target_binding.validation_id),
        owner_id: ProposalValidationOwnerIdV0::new(link.owner_id)?,
        artifact_digest: NonZeroDigestV0::new(link.artifact_digest)?,
        core_delivery: CoreDeliveryConfirmationV0::new(
            ValidationIdV0::from_bytes(link.target_binding.validation_id),
            confirmation.core_revision,
            NonZeroDigestV0::new(confirmation.core_state_digest)?,
            NonZeroDigestV0::new(confirmation.accepted_validation_digest)?,
        )?,
        row_revision: link.row_revision,
        row_checksum: NonZeroDigestV0::new(link.row_checksum)?,
    })
}

fn require_delivered_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
    token: &CoreDeliveredReplayLinkDV0,
) -> ValidationStoreResultV0<()> {
    let expected = delivered_replay_token_v0(store_id, link)?;
    if expected.store_id != token.store_id
        || expected.session_id != token.session_id
        || expected.cursor != token.cursor
        || expected.source_validation_id != token.source_validation_id
        || expected.target_validation_id != token.target_validation_id
        || expected.owner_id != token.owner_id
        || expected.artifact_digest != token.artifact_digest
        || expected.core_delivery != token.core_delivery
        || expected.row_revision != token.row_revision
        || expected.row_checksum != token.row_checksum
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ForeignToken,
            "replay_link.delivered_authority",
        ));
    }
    Ok(())
}

fn safety_closed_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
) -> ValidationStoreResultV0<SafetyClosedReplayLinkCV0> {
    if link.stage != DurableReplayLinkStageV0::SafetyClosed {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_link.safety_stage",
        ));
    }
    let confirmation = link.confirmation.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_link.safety_delivery",
        )
    })?;
    let safety = link.safety_closure.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_link.safety_closure",
        )
    })?;
    Ok(SafetyClosedReplayLinkCV0 {
        store_id,
        session_id: link.session_id,
        cursor: link.cursor,
        source_validation_id: link.source_validation_id,
        target_validation_id: ValidationIdV0::from_bytes(link.target_binding.validation_id),
        owner_id: ProposalValidationOwnerIdV0::new(link.owner_id)?,
        artifact_digest: NonZeroDigestV0::new(link.artifact_digest)?,
        core_delivery: CoreDeliveryConfirmationV0::new(
            ValidationIdV0::from_bytes(link.target_binding.validation_id),
            confirmation.core_revision,
            NonZeroDigestV0::new(confirmation.core_state_digest)?,
            NonZeroDigestV0::new(confirmation.accepted_validation_digest)?,
        )?,
        safety_revision: safety.safety_revision,
        safety_record_digest: NonZeroDigestV0::new(safety.safety_record_digest)?,
        no_sign_closure_digest: NonZeroDigestV0::new(safety.no_sign_closure_digest)?,
        row_revision: link.row_revision,
        row_checksum: NonZeroDigestV0::new(link.row_checksum)?,
    })
}

fn require_safety_closed_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
    token: &SafetyClosedReplayLinkCV0,
) -> ValidationStoreResultV0<()> {
    let expected = safety_closed_replay_token_v0(store_id, link)?;
    if expected.store_id != token.store_id
        || expected.session_id != token.session_id
        || expected.cursor != token.cursor
        || expected.source_validation_id != token.source_validation_id
        || expected.target_validation_id != token.target_validation_id
        || expected.owner_id != token.owner_id
        || expected.artifact_digest != token.artifact_digest
        || expected.core_delivery != token.core_delivery
        || expected.safety_revision != token.safety_revision
        || expected.safety_record_digest != token.safety_record_digest
        || expected.no_sign_closure_digest != token.no_sign_closure_digest
        || expected.row_revision != token.row_revision
        || expected.row_checksum != token.row_checksum
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ForeignToken,
            "replay_link.safety_authority",
        ));
    }
    Ok(())
}

fn alias_closed_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
) -> ValidationStoreResultV0<AliasClosedReplayLinkKV0> {
    if link.stage != DurableReplayLinkStageV0::AliasClosed {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_link.alias_stage",
        ));
    }
    let safety = link.safety_closure.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_link.alias_safety",
        )
    })?;
    Ok(AliasClosedReplayLinkKV0 {
        store_id,
        session_id: link.session_id,
        cursor: link.cursor,
        source_validation_id: link.source_validation_id,
        target_validation_id: ValidationIdV0::from_bytes(link.target_binding.validation_id),
        owner_id: ProposalValidationOwnerIdV0::new(link.owner_id)?,
        artifact_digest: NonZeroDigestV0::new(link.artifact_digest)?,
        safety_revision: safety.safety_revision,
        alias_closure_checksum: NonZeroDigestV0::new(link.alias_closure_checksum.ok_or_else(
            || {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_link.alias_checksum",
                )
            },
        )?)?,
        row_revision: link.row_revision,
        row_checksum: NonZeroDigestV0::new(link.row_checksum)?,
    })
}

fn require_alias_closed_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
    token: &AliasClosedReplayLinkKV0,
) -> ValidationStoreResultV0<()> {
    let expected = alias_closed_replay_token_v0(store_id, link)?;
    if expected.store_id != token.store_id
        || expected.session_id != token.session_id
        || expected.cursor != token.cursor
        || expected.source_validation_id != token.source_validation_id
        || expected.target_validation_id != token.target_validation_id
        || expected.owner_id != token.owner_id
        || expected.artifact_digest != token.artifact_digest
        || expected.safety_revision != token.safety_revision
        || expected.alias_closure_checksum != token.alias_closure_checksum
        || expected.row_revision != token.row_revision
        || expected.row_checksum != token.row_checksum
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ForeignToken,
            "replay_link.alias_authority",
        ));
    }
    Ok(())
}

fn checkpointed_replay_token_v0(
    store_id: [u8; 32],
    link: &ReplayLinkSnapshotV0,
) -> ValidationStoreResultV0<CheckpointedReplayLinkV0> {
    if link.stage != DurableReplayLinkStageV0::Checkpointed {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidTransition,
            "replay_link.checkpoint_stage",
        ));
    }
    let safety = link.safety_closure.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_link.checkpoint_safety",
        )
    })?;
    let checkpoint = link.checkpoint.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_link.checkpoint_record",
        )
    })?;
    Ok(CheckpointedReplayLinkV0 {
        store_id,
        session_id: link.session_id,
        cursor: link.cursor,
        source_validation_id: link.source_validation_id,
        target_validation_id: ValidationIdV0::from_bytes(link.target_binding.validation_id),
        owner_id: ProposalValidationOwnerIdV0::new(link.owner_id)?,
        artifact_digest: NonZeroDigestV0::new(link.artifact_digest)?,
        safety_revision: safety.safety_revision,
        checkpoint_scope: NonZeroDigestV0::new(checkpoint.scope)?,
        checkpoint_profile_ref: NonZeroDigestV0::new(checkpoint.profile_ref)?,
        checkpoint_predecessor_checksum: NonZeroDigestV0::new(checkpoint.predecessor_checksum)?,
        checkpoint_generation: checkpoint.generation,
        checkpoint_checksum: NonZeroDigestV0::new(checkpoint.checksum)?,
        row_revision: link.row_revision,
        row_checksum: NonZeroDigestV0::new(link.row_checksum)?,
    })
}

fn replay_activation_ready_token_v0(
    store: &SqliteProposalValidationStoreV0,
    binding: ReplayActivationBindingV0,
    row_revision: u64,
    row_checksum: [u8; 32],
) -> ValidationStoreResultV0<ConfirmedReplayActivationReadyV0> {
    if row_revision == 0 || row_checksum == [0; 32] {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_activation.token",
        ));
    }
    Ok(ConfirmedReplayActivationReadyV0 {
        database_path: store.path.clone(),
        owner_affinity: Arc::clone(&store.owner_affinity),
        store_id: store.store_id,
        binding,
        row_revision,
        row_checksum: NonZeroDigestV0::new(row_checksum)?,
    })
}

fn compute_replay_session_id_v0(session: &ReplaySessionSnapshotV0) -> [u8; 32] {
    domain_digest_v0(
        REPLAY_SESSION_ID_DOMAIN_V0,
        &[
            &session.core_config_ref,
            &session.validation_scope,
            &session.validation_store_id,
            &session.recovery_challenge_digest,
            &session.archive_context_digest,
            &session.archive_sequence.to_be_bytes(),
            &session.archive_record_digest,
            &session.expected_count.to_be_bytes(),
            &session.canonical_store_sequence.to_be_bytes(),
            &session.canonical_terminal_row_count.to_be_bytes(),
            &session.canonical_terminal_audit_digest,
            &session.application_history_digest,
            &session.initial_safety_revision.to_be_bytes(),
            &session.initial_safety_state_checksum,
            &session.initial_safety_chain_checksum,
            &session.initial_checkpoint_scope,
            &session.initial_checkpoint_profile_ref,
            &session.initial_checkpoint_generation.to_be_bytes(),
            &session.initial_checkpoint_checksum,
            &session.signer_scope,
            &session.signer_journal_id,
            &session.signer_sequence.to_be_bytes(),
            &session.signer_chain_checksum,
        ],
    )
}

fn compute_initial_replay_progress_v0(session: &ReplaySessionSnapshotV0) -> [u8; 32] {
    domain_digest_v0(
        REPLAY_INITIAL_PROGRESS_DOMAIN_V0,
        &[
            &session.session_id,
            &session.initial_safety_revision.to_be_bytes(),
            &session.initial_safety_state_checksum,
            &session.initial_safety_chain_checksum,
            &session.initial_checkpoint_scope,
            &session.initial_checkpoint_profile_ref,
            &session.initial_checkpoint_generation.to_be_bytes(),
            &session.initial_checkpoint_checksum,
            &session.signer_scope,
            &session.signer_journal_id,
            &session.signer_sequence.to_be_bytes(),
            &session.signer_chain_checksum,
        ],
    )
}

fn compute_replay_session_checksum_v0(session: &ReplaySessionSnapshotV0) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REPLAY_SESSION_ROW_CHECKSUM_DOMAIN_V0);
    hasher.update(session.session_id);
    hasher.update(session.next_cursor.to_be_bytes());
    hasher.update(session.previous_progress_checksum);
    hasher.update([session.state as u8]);
    match session.activation_binding_digest {
        Some(digest) => {
            hasher.update([1]);
            hasher.update(digest);
        }
        None => hasher.update([0]),
    }
    match session.activation_source_row_revision {
        Some(revision) => {
            hasher.update([1]);
            hasher.update(revision.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    match session.activation_source_row_checksum {
        Some(checksum) => {
            hasher.update([1]);
            hasher.update(checksum);
        }
        None => hasher.update([0]),
    }
    hasher.update(session.row_revision.to_be_bytes());
    hasher.update(compute_replay_session_id_v0(session));
    hasher.finalize().into()
}

fn compute_replay_activation_binding_v0(binding: &ReplayActivationBindingV0) -> [u8; 32] {
    domain_digest_v0(
        REPLAY_ACTIVATION_BINDING_DOMAIN_V0,
        &[
            binding.session_id.as_bytes(),
            binding.core_rehydrate_digest.as_bytes(),
            &binding.safety_revision.to_be_bytes(),
            binding.safety_chain_checksum.as_bytes(),
            binding.application_history_digest.as_bytes(),
            &binding.application_parent_height.to_be_bytes(),
            binding.application_parent_block_id.as_bytes(),
            binding.application_parent_state_root.as_bytes(),
            binding.application_parent_commit_id.as_bytes(),
            &binding.checkpoint_generation.to_be_bytes(),
            binding.checkpoint_checksum.as_bytes(),
            binding.signer_scope.as_bytes(),
            binding.signer_journal_id.as_bytes(),
            &binding.signer_sequence.to_be_bytes(),
            binding.signer_chain_checksum.as_bytes(),
            binding.signer_inventory_digest.as_bytes(),
            binding.selected_replay_digest.as_bytes(),
        ],
    )
}

fn compute_replay_link_checksum_v0(link: &ReplayLinkSnapshotV0) -> [u8; 32] {
    let binding = encode_binding_record_v0(&link.target_binding).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(REPLAY_LINK_ROW_CHECKSUM_DOMAIN_V0);
    hasher.update(link.session_id);
    hasher.update(link.cursor.to_be_bytes());
    hasher.update(link.source_validation_id.as_bytes());
    hasher.update(link.source_store_sequence.to_be_bytes());
    hasher.update(link.source_row_revision.to_be_bytes());
    hasher.update(link.source_row_checksum);
    hasher.update(link.source_application_history_checksum);
    hasher.update((binding.len() as u64).to_be_bytes());
    hasher.update(binding);
    hasher.update(link.owner_id);
    hasher.update(link.artifact_digest);
    hasher.update(link.previous_progress_checksum);
    hasher.update([link.stage as u8]);
    match link.confirmation {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.validation_id);
            hasher.update(value.core_revision.to_be_bytes());
            hasher.update(value.core_state_digest);
            hasher.update(value.accepted_validation_digest);
        }
        None => hasher.update([0]),
    }
    match link.safety_closure {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.core_delivery_digest);
            hasher.update(value.safety_revision.to_be_bytes());
            hasher.update(value.safety_record_digest);
            hasher.update(value.no_sign_closure_digest);
        }
        None => hasher.update([0]),
    }
    match link.alias_closure_checksum {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value);
        }
        None => hasher.update([0]),
    }
    match link.checkpoint {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.scope);
            hasher.update(value.profile_ref);
            hasher.update(value.predecessor_checksum);
            hasher.update(value.generation.to_be_bytes());
            hasher.update(value.checksum);
        }
        None => hasher.update([0]),
    }
    hasher.update(link.row_revision.to_be_bytes());
    hasher.finalize().into()
}

fn compute_replay_no_sign_closure_v0(link: &ReplayLinkSnapshotV0) -> Option<[u8; 32]> {
    let delivery = link.confirmation?;
    let safety = link.safety_closure?;
    let action_code = NativeValidPostAckActionV0::None.code().to_be_bytes();
    Some(domain_digest_v0(
        ORDINARY_REPLAY_SAFETY_CLOSURE_DOMAIN_V0,
        &[
            &link.session_id,
            &link.cursor.to_be_bytes(),
            &link.previous_progress_checksum,
            link.source_validation_id.as_bytes(),
            &link.source_row_checksum,
            &link.target_binding.validation_id,
            &delivery.core_revision.to_be_bytes(),
            &delivery.core_state_digest,
            &delivery.accepted_validation_digest,
            &safety.safety_revision.to_be_bytes(),
            &safety.safety_record_digest,
            &action_code,
        ],
    ))
}

fn compute_replay_alias_closure_v0(link: &ReplayLinkSnapshotV0) -> Option<[u8; 32]> {
    let safety = link.safety_closure?;
    Some(domain_digest_v0(
        REPLAY_ALIAS_CLOSURE_DOMAIN_V0,
        &[
            &link.session_id,
            &link.cursor.to_be_bytes(),
            link.source_validation_id.as_bytes(),
            &link.source_store_sequence.to_be_bytes(),
            &link.source_row_revision.to_be_bytes(),
            &link.source_row_checksum,
            &link.source_application_history_checksum,
            &link.target_binding.validation_id,
            &link.artifact_digest,
            &safety.core_delivery_digest,
            &safety.safety_revision.to_be_bytes(),
            &safety.safety_record_digest,
            &safety.no_sign_closure_digest,
        ],
    ))
}

fn compute_replay_checkpoint_progress_v0(link: &ReplayLinkSnapshotV0) -> Option<[u8; 32]> {
    let alias = link.alias_closure_checksum?;
    let checkpoint = link.checkpoint?;
    Some(domain_digest_v0(
        REPLAY_CHECKPOINT_PROGRESS_DOMAIN_V0,
        &[
            &link.previous_progress_checksum,
            &link.session_id,
            &link.cursor.to_be_bytes(),
            &link.target_binding.validation_id,
            &alias,
            &checkpoint.scope,
            &checkpoint.profile_ref,
            &checkpoint.predecessor_checksum,
            &checkpoint.generation.to_be_bytes(),
            &checkpoint.checksum,
        ],
    ))
}

fn replay_checkpoint_request_v0(
    connection: &Connection,
    session: &ReplaySessionSnapshotV0,
    link: &ReplayLinkSnapshotV0,
) -> ValidationStoreResultV0<ReplayCheckpointReadRequestV0> {
    if session.state != DurableReplaySessionStateV0::Active
        || link.stage != DurableReplayLinkStageV0::AliasClosed
        || link.session_id != session.session_id
        || link.cursor != session.next_cursor
        || link.previous_progress_checksum != session.previous_progress_checksum
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "replay_checkpoint.frontier",
        ));
    }
    let (predecessor_generation, predecessor_checksum, predecessor_scope, predecessor_profile) =
        if link.cursor == 0 {
            (
                session.initial_checkpoint_generation,
                session.initial_checkpoint_checksum,
                session.initial_checkpoint_scope,
                session.initial_checkpoint_profile_ref,
            )
        } else {
            let predecessor =
                load_replay_link_by_cursor_v0(connection, session.session_id, link.cursor - 1)?
                    .ok_or_else(|| {
                        error(
                            ValidationStoreErrorCodeV0::NotFound,
                            "replay_checkpoint.predecessor_link",
                        )
                    })?;
            if predecessor.stage != DurableReplayLinkStageV0::Checkpointed {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "replay_checkpoint.predecessor_stage",
                ));
            }
            let checkpoint = predecessor.checkpoint.ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "replay_checkpoint.predecessor_record",
                )
            })?;
            (
                checkpoint.generation,
                checkpoint.checksum,
                checkpoint.scope,
                checkpoint.profile_ref,
            )
        };
    if predecessor_scope != session.initial_checkpoint_scope
        || predecessor_profile != session.initial_checkpoint_profile_ref
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "replay_checkpoint.profile_chain",
        ));
    }
    let safety = link.safety_closure.ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "replay_checkpoint.safety",
        )
    })?;
    let preimage = domain_digest_v0(
        REPLAY_CHECKPOINT_PREIMAGE_DOMAIN_V0,
        &[
            &session.session_id,
            &link.cursor.to_be_bytes(),
            &link.target_binding.validation_id,
            &link.row_checksum,
            &link.previous_progress_checksum,
            &safety.safety_revision.to_be_bytes(),
            &safety.safety_record_digest,
            &session.application_history_digest,
            &session.signer_scope,
            &session.signer_journal_id,
            &session.signer_sequence.to_be_bytes(),
            &session.signer_chain_checksum,
            &predecessor_scope,
            &predecessor_profile,
            &predecessor_generation.to_be_bytes(),
            &predecessor_checksum,
        ],
    );
    Ok(ReplayCheckpointReadRequestV0 {
        session_id: session.session_id,
        cursor: link.cursor,
        target_validation_id: ValidationIdV0::from_bytes(link.target_binding.validation_id),
        alias_k_row_checksum: NonZeroDigestV0::new(link.row_checksum)?,
        previous_progress_checksum: NonZeroDigestV0::new(link.previous_progress_checksum)?,
        safety_revision: safety.safety_revision,
        expected_scope: NonZeroDigestV0::new(predecessor_scope)?,
        expected_profile_ref: NonZeroDigestV0::new(predecessor_profile)?,
        expected_predecessor_generation: predecessor_generation,
        expected_predecessor_checksum: NonZeroDigestV0::new(predecessor_checksum)?,
        application_history_digest: NonZeroDigestV0::new(session.application_history_digest)?,
        signer_scope: NonZeroDigestV0::new(session.signer_scope)?,
        signer_journal_id: NonZeroDigestV0::new(session.signer_journal_id)?,
        signer_sequence: session.signer_sequence,
        signer_chain_checksum: NonZeroDigestV0::new(session.signer_chain_checksum)?,
        preimage_digest: NonZeroDigestV0::new(preimage)?,
    })
}

fn compute_terminal_audit_digest_v0(
    connection: &Connection,
    scope: ProposalValidationStoreScopeV0,
    store_id: [u8; 32],
    store_sequence: u64,
    terminal_row_count: u64,
) -> ValidationStoreResultV0<NonZeroDigestV0> {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_AUDIT_DIGEST_DOMAIN_V0);
    hasher.update(scope.as_bytes());
    hasher.update(store_id);
    hasher.update(store_sequence.to_be_bytes());
    hasher.update(terminal_row_count.to_be_bytes());
    let mut statement = connection
        .prepare("SELECT validation_id FROM proposal_validation_jobs_v0 ORDER BY validation_id")
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "terminal_digest.prepare",
            )
        })?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "terminal_digest.query"))?;
    let mut observed = 0_u64;
    for row in rows {
        let id = ValidationIdV0::from_bytes(vec_to_array_32_v0(
            row.map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "terminal_digest.id"))?,
            "terminal_digest.id",
        )?);
        let snapshot = load_durable_snapshot_v0(connection, id)?;
        let job = snapshot.job.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "terminal_digest.job",
            )
        })?;
        if job.stage != DurableValidationStageV0::Acked || snapshot.outbox.is_some() {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "terminal_digest.nonterminal",
            ));
        }
        hasher.update(id.as_bytes());
        hasher.update(job.row_revision.to_be_bytes());
        hasher.update(job.row_checksum);
        hasher.update(job.artifact_digest);
        observed = observed.checked_add(1).ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::Overflow,
                "terminal_digest.count",
            )
        })?;
    }
    if observed != terminal_row_count {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "terminal_digest.inventory",
        ));
    }
    NonZeroDigestV0::new(hasher.finalize().into())
}

fn domain_digest_v0(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn outbox_checksum_v0(confirmation: ConfirmationRecordV0) -> [u8; 32] {
    domain_digest_v0(
        OUTBOX_CHECKSUM_DOMAIN_V0,
        &[
            confirmation.validation_id.as_slice(),
            confirmation.core_revision.to_be_bytes().as_slice(),
            confirmation.core_state_digest.as_slice(),
            confirmation.accepted_validation_digest.as_slice(),
        ],
    )
}

fn artifact_digest_v0(bytes: &[u8]) -> ValidationStoreResultV0<NonZeroDigestV0> {
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_DIGEST_DOMAIN_V0);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    NonZeroDigestV0::new(hasher.finalize().into())
}

fn require_artifact_matches_binding_v0(
    binding: &ProposalValidationBindingV0,
    executed: &NativeExecutedBlockV0,
) -> ValidationStoreResultV0<()> {
    let request = executed.request();
    let expected = request.expected();
    if request.chain_id() != binding.chain_id()
        || request.genesis_hash() != binding.genesis_hash()
        || request.parent() != binding.parent()
        || request.block_id() != binding.block_id()
        || request.height() != binding.height()
        || request.timestamp_ms() != binding.timestamp_ms()
        || request.active_validator_set_id() != binding.active_validator_set_id()
        || expected != binding.commitments()
    {
        return Err(error(
            ValidationStoreErrorCodeV0::BindingMismatch,
            "artifact.binding",
        ));
    }
    Ok(())
}

fn same_replay_edge_v0(
    source: &ProposalValidationBindingV0,
    target: &ProposalValidationBindingV0,
) -> bool {
    source.chain_id() == target.chain_id()
        && source.genesis_hash() == target.genesis_hash()
        && source.parent() == target.parent()
        && source.block_id() == target.block_id()
        && source.height() == target.height()
        && source.timestamp_ms() == target.timestamp_ms()
        && source.active_validator_set_id() == target.active_validator_set_id()
        && source.view() == target.view()
        && source.commitments() == target.commitments()
}

fn decode_checked_artifact_v0(
    binding: &BindingRecordV0,
    bytes: &[u8],
    expected_digest: [u8; 32],
) -> ValidationStoreResultV0<NativeExecutedBlockV0> {
    let digest = artifact_digest_v0(bytes)?;
    if digest.as_bytes() != &expected_digest {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "artifact.digest",
        ));
    }
    let executed = decode_native_executed_block_artifact_v0(bytes)
        .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, "artifact.decode"))?;
    let canonical = encode_native_executed_block_artifact_v0(&executed).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "artifact.reencode",
        )
    })?;
    if canonical != bytes {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "artifact.noncanonical",
        ));
    }
    let reconstructed_binding = ProposalValidationBindingV0::from_record(binding)?;
    require_artifact_matches_binding_v0(&reconstructed_binding, &executed).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "artifact.persisted_binding",
        )
    })?;
    Ok(executed)
}

fn encode_confirmation_v0(confirmation: Option<ConfirmationRecordV0>) -> EncodedConfirmationV0 {
    confirmation.map_or((None, None, None), |value| {
        (
            Some(encode_u64_v0(value.core_revision).to_vec()),
            Some(value.core_state_digest.to_vec()),
            Some(value.accepted_validation_digest.to_vec()),
        )
    })
}

fn encode_safety_confirmation_v0(
    confirmation: Option<SafetyConfirmationRecordV0>,
) -> EncodedSafetyConfirmationV0 {
    confirmation.map_or((None, None, None, None), |value| {
        (
            Some(value.core_delivery_digest.to_vec()),
            Some(encode_u64_v0(value.safety_revision).to_vec()),
            Some(value.safety_record_digest.to_vec()),
            Some(value.vote_intent_digest.to_vec()),
        )
    })
}

fn core_delivery_digest_from_record_v0(record: ConfirmationRecordV0) -> Option<[u8; 32]> {
    let delivery = CoreDeliveryConfirmationV0::new(
        ValidationIdV0::from_bytes(record.validation_id),
        record.core_revision,
        NonZeroDigestV0::new(record.core_state_digest).ok()?,
        NonZeroDigestV0::new(record.accepted_validation_digest).ok()?,
    )
    .ok()?;
    Some(*delivery.digest().as_bytes())
}

fn encode_binding_record_v0(record: &BindingRecordV0) -> ValidationStoreResultV0<Vec<u8>> {
    let chain = record.chain_id.as_bytes();
    let chain_len = u32::try_from(chain.len())
        .map_err(|_| error(ValidationStoreErrorCodeV0::Overflow, "binding.chain_len"))?;
    let mut bytes = Vec::with_capacity(4 + chain.len() + 32 * 11 + 8 * 4 + 1);
    bytes.extend_from_slice(&chain_len.to_be_bytes());
    bytes.extend_from_slice(chain);
    bytes.extend_from_slice(&record.validation_id);
    bytes.extend_from_slice(&record.genesis_hash);
    bytes.extend_from_slice(&record.parent_height.to_be_bytes());
    bytes.extend_from_slice(&record.parent_block_id);
    bytes.extend_from_slice(&record.parent_state_root);
    bytes.extend_from_slice(&record.parent_commit_id);
    bytes.extend_from_slice(&record.block_id);
    bytes.extend_from_slice(&record.height.to_be_bytes());
    bytes.extend_from_slice(&record.timestamp_ms.to_be_bytes());
    bytes.extend_from_slice(&record.active_validator_set_id);
    bytes.extend_from_slice(&record.view.to_be_bytes());
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    bytes.push(record.route);
    bytes.extend_from_slice(&record.payload_root);
    bytes.extend_from_slice(&record.post_state_root);
    bytes.extend_from_slice(&record.receipts_root);
    bytes.extend_from_slice(&record.evidence_root);
    Ok(bytes)
}

fn decode_binding_record_v0(bytes: &[u8]) -> ValidationStoreResultV0<BindingRecordV0> {
    let mut decoder = DecoderV0::new(bytes);
    let chain_len = decoder.read_u32()? as usize;
    let chain_bytes = decoder.read_exact(chain_len)?;
    let chain_id = String::from_utf8(chain_bytes.to_vec()).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "binding.chain_utf8",
        )
    })?;
    let record = BindingRecordV0 {
        chain_id,
        validation_id: decoder.read_array_32()?,
        genesis_hash: decoder.read_array_32()?,
        parent_height: decoder.read_u64()?,
        parent_block_id: decoder.read_array_32()?,
        parent_state_root: decoder.read_array_32()?,
        parent_commit_id: decoder.read_array_32()?,
        block_id: decoder.read_array_32()?,
        height: decoder.read_u64()?,
        timestamp_ms: decoder.read_u64()?,
        active_validator_set_id: decoder.read_array_32()?,
        view: decoder.read_u64()?,
        generation: decoder.read_u64()?,
        route: decoder.read_u8()?,
        payload_root: decoder.read_array_32()?,
        post_state_root: decoder.read_array_32()?,
        receipts_root: decoder.read_array_32()?,
        evidence_root: decoder.read_array_32()?,
    };
    if !decoder.is_finished() {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "binding.trailing_bytes",
        ));
    }
    Ok(record)
}

struct DecoderV0<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DecoderV0<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> ValidationStoreResultV0<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| error(ValidationStoreErrorCodeV0::Overflow, "decoder.offset"))?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "decoder.truncated",
            )
        })?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> ValidationStoreResultV0<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u32(&mut self) -> ValidationStoreResultV0<u32> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, "decoder.u32"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> ValidationStoreResultV0<u64> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, "decoder.u64"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_array_32(&mut self) -> ValidationStoreResultV0<[u8; 32]> {
        self.read_exact(32)?
            .try_into()
            .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, "decoder.array32"))
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn encode_u64_v0(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64_v0(bytes: &[u8], context: &'static str) -> ValidationStoreResultV0<u64> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, context))?;
    Ok(u64::from_be_bytes(bytes))
}

fn vec_to_array_32_v0(bytes: Vec<u8>, context: &'static str) -> ValidationStoreResultV0<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, context))
}

fn derive_store_id_v0(
    path: &Path,
    scope: ProposalValidationStoreScopeV0,
) -> ValidationStoreResultV0<[u8; 32]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "store_id.clock"))?;
    let mut hasher = Sha256::new();
    hasher.update(STORE_ID_DOMAIN_V0);
    hasher.update(scope.as_bytes());
    hasher.update(path.as_os_str().to_string_lossy().as_bytes());
    hasher.update(now.as_nanos().to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    #[cfg(unix)]
    {
        let identity = read_file_identity_v0(path)?;
        hasher.update(identity.device.to_be_bytes());
        hasher.update(identity.inode.to_be_bytes());
    }
    let value: [u8; 32] = hasher.finalize().into();
    if value == [0; 32] {
        return Err(error(ValidationStoreErrorCodeV0::ZeroValue, "store_id"));
    }
    Ok(value)
}

fn open_connection_v0(path: &Path) -> ValidationStoreResultV0<Connection> {
    let connection = Connection::open(path)
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "connection.open"))?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "connection.busy_timeout",
            )
        })?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "connection.journal_mode",
            )
        })?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "connection.synchronous",
            )
        })?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "connection.foreign_keys",
            )
        })?;
    Ok(connection)
}

/// Opens a second read-only connection to a live WAL-backed owner. Unlike the
/// immutable pre-open auditor below, this connection must observe committed
/// WAL pages written during the current process lifetime.
#[cfg(unix)]
fn open_fresh_terminal_read_connection_v0(path: &Path) -> ValidationStoreResultV0<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::Storage,
            "connection.terminal_read_open",
        )
    })?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "connection.terminal_read_busy_timeout",
            )
        })?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "connection.terminal_read_foreign_keys",
            )
        })?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "connection.terminal_read_query_only",
            )
        })?;
    Ok(connection)
}

/// Existing stores are authenticated through SQLite's immutable URI before
/// any writable connection, WAL transition, schema initialization, or
/// migration attempt is permitted. Existing WAL/SHM/rollback-journal files are
/// rejected before SQLite is called because immutable mode intentionally
/// ignores them.
#[cfg(unix)]
fn open_read_only_connection_v0(path: &Path) -> ValidationStoreResultV0<Connection> {
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'.' | b'_' | b'~' => {
                uri.push(char::from(*byte))
            }
            value => {
                use std::fmt::Write as _;
                write!(&mut uri, "%{value:02X}").expect("writing to String cannot fail");
            }
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    let connection = Connection::open_with_flags(
        Path::new(&uri),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::Storage,
            "connection.read_only_open",
        )
    })?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "connection.read_only_busy_timeout",
            )
        })?;
    Ok(connection)
}

#[cfg(unix)]
fn reject_existing_sqlite_sidecars_v0(path: &Path) -> ValidationStoreResultV0<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => {
                return Err(error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "existing_store.sqlite_sidecar",
                ));
            }
            Err(value) if value.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(error(
                    ValidationStoreErrorCodeV0::Storage,
                    "existing_store.sqlite_sidecar_metadata",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_store_file_v0(path: &Path) -> ValidationStoreResultV0<(PathBuf, bool)> {
    let file_name = path.file_name().ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::Empty,
            "validation_store.file_name",
        )
    })?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::Storage,
            "validation_store.parent",
        )
    })?;
    let path = canonical_parent.join(file_name);
    let existed = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(error(
                    ValidationStoreErrorCodeV0::ReplacedStore,
                    "validation_store.file_type",
                ));
            }
            true
        }
        Err(value) if value.kind() == std::io::ErrorKind::NotFound => {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "validation_store.create",
                    )
                })?;
            false
        }
        Err(_) => {
            return Err(error(
                ValidationStoreErrorCodeV0::Storage,
                "validation_store.metadata",
            ));
        }
    };
    let identity = read_file_identity_v0(&path)?;
    if identity.links != 1 || identity.mode != 0o600 {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidPermissions,
            "validation_store.identity",
        ));
    }
    Ok((path, !existed))
}

#[cfg(unix)]
fn read_file_identity_v0(path: &Path) -> ValidationStoreResultV0<FileIdentityV0> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "validation_store.identity_read",
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "validation_store.identity_type",
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if metadata.nlink() != 1 || mode != 0o600 {
        return Err(error(
            ValidationStoreErrorCodeV0::InvalidPermissions,
            "validation_store.identity_permissions",
        ));
    }
    Ok(FileIdentityV0 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        mode,
    })
}

#[cfg(any(test, feature = "test-support"))]
fn corrupt_target_for_test_v0(
    path: &Path,
    validation_id: ValidationIdV0,
) -> ValidationStoreResultV0<()> {
    let connection = open_connection_v0(path)?;
    let changed = connection
        .execute(
            "UPDATE proposal_validation_jobs_v0 SET artifact_digest = ?1
             WHERE validation_id = ?2",
            params![[0xabu8; 32].as_slice(), validation_id.as_bytes().as_slice()],
        )
        .map_err(|_| error(ValidationStoreErrorCodeV0::Storage, "test.corrupt"))?;
    if changed != 1 {
        return Err(error(
            ValidationStoreErrorCodeV0::NotFound,
            "test.corrupt_target",
        ));
    }
    Ok(())
}
