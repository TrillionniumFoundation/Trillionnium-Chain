use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, TryLockError,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Context, Result};
use fs2::FileExt;
use jmt::{
    storage::{HasPreimage, LeafNode, NibblePath, Node, NodeKey, TreeReader},
    JellyfishMerkleIterator, KeyHash, RootHash, Version,
};
use rusqlite::{
    backup::Backup, ffi::ErrorCode, params, Connection, DatabaseName, OpenFlags, OptionalExtension,
    Transaction, TransactionBehavior,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use trnm_consensus_core::{PayloadValidationParentV0, PayloadValidationRouteV0, ValidationId};
use trnm_consensus_types::{decode_block_header_v0_exact, Block, BlockId, BlockKind, View};
use trnm_finality_types::hash_domain;

// The raw Delivered/Acked journal transitions are private to this parent
// module.  Nesting the callback driver here lets it consume those hooks while
// preventing sibling modules from bypassing the real-Core and exact-sink
// capability chain.
#[allow(dead_code)]
#[path = "native_validation_callback_driver.rs"]
pub(crate) mod native_validation_callback_driver;

// The recovery facade is a child of the authoritative store module so it can
// revalidate and advance the journal without publishing `ApplicationStore`
// or any of its general mutation surface.  Its public owners remain opaque
// and store-affine.
#[path = "native_validation_recovery.rs"]
pub(crate) mod native_validation_recovery;

use super::{
    auth_tree::{
        authenticated_key_hash, plan_put_value_set, poco_snapshot_key_components,
        prove_with_reader, stored_object_key, stored_object_key_preimage, validator_state_key,
        verify_ics23_membership, verify_ics23_non_membership, AuthProof, AuthWrite,
        AuthenticatedObjectRecord, InMemoryAuthTree, PlannedAuthUpdate, PruneStats,
        MAX_AUTH_KEY_PREIMAGE_BYTES,
    },
    native_payload_validation::PreparedDurableInvalidV0,
    native_validation_artifact::{
        durable_deterministic_invalid_result_kind_v0, durable_invalid_callback_outbox_checksum_v0,
        durable_invalid_callback_payload_checksum_for_identity_v0,
        prepare_durable_invalid_artifact_v0, prepare_durable_invalid_callback_v0,
        verify_durable_invalid_artifact_v0, verify_durable_invalid_callback_v0,
        DurableDeterministicInvalidReasonV0, DurableNativeValidationRecordErrorV0,
        NativeValidationArtifactIdentityV0, RevalidatedDurableInvalidArtifactV0,
        RevalidatedDurableInvalidCallbackV0, DURABLE_INVALID_ARTIFACT_BYTES_V0,
        DURABLE_INVALID_ARTIFACT_CODEC_V0, DURABLE_INVALID_CALLBACK_BYTES_V0,
        DURABLE_INVALID_CALLBACK_CODEC_V0,
    },
    persist_state_bytes,
    poco_transition::{
        take_and_validate_production_poco_projection_v0, ProductionPocoProjectionV0,
    },
    validate_in_memory_authenticated_domain_projection, AppState, PendingBlock, StoredObject,
    ValidatorLifecycleStateV1, APP_VERSION, VALIDATOR_LIFECYCLE_SCHEMA_V1,
};

const STORE_SCHEMA_VERSION_V8: &str = "8";
const STORE_SCHEMA_VERSION: &str = STORE_SCHEMA_VERSION_V8;
const STORE_SCHEMA_VERSION_V7: &str = "7";
const STORE_SCHEMA_VERSION_V6: &str = "6";
const STORE_SCHEMA_VERSION_V5: &str = "5";
const STORE_SCHEMA_VERSION_V4: &str = "4";
const LEGACY_STORE_SCHEMA_VERSION: &str = "3";
const STATUS_SCHEMA_V2: &str = "trnm_cometbft_app_status_v2";
const AUTH_QUERY_FLOOR_KEY: &str = "auth_query_floor";
const AUTH_PRUNE_TARGET_KEY: &str = "auth_prune_target";
const AUTH_PRUNE_BATCH_MAX_DURATION: Duration = Duration::from_millis(10);
const MAX_SNAPSHOT_AUTH_NODE_BYTES: u64 = 64 * 1024;
const MAX_SNAPSHOT_AUTH_VALUE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_KEY_PREIMAGE_BYTES: u64 = MAX_AUTH_KEY_PREIMAGE_BYTES as u64;
const MAX_SNAPSHOT_OBJECT_VALUE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_LIFECYCLE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SNAPSHOT_IDENTIFIER_BYTES: u64 = 4096;
const MAX_NATIVE_VALIDATION_RESERVATIONS: u64 = 65_536;
const MAX_NATIVE_VALIDATION_HEADER_BYTES: usize = 64 * 1024;
pub(super) const MAX_NATIVE_VALIDATION_BODY_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_NATIVE_VALIDATION_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_NATIVE_VALIDATION_CALLBACK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_NATIVE_VALIDATION_REQUEST_JOURNAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_NATIVE_VALIDATION_ARTIFACT_JOURNAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_NATIVE_VALIDATION_CALLBACK_OUTBOX_BYTES: u64 = 128 * 1024 * 1024;
const NATIVE_VALIDATION_BODY_RECORD_CODEC_V0: u16 = 0;
const NATIVE_VALIDATION_RESERVATION_FINGERPRINT_CODEC_V0: u16 = 0;
const NATIVE_VALIDATION_RESERVATION_FINGERPRINT_HASH_PREFIX_V0: &[u8] =
    b"trnm.native-validation-reservation.hash.v0";
const NATIVE_VALIDATION_RESERVATION_FINGERPRINT_DOMAIN_V0: &[u8] =
    b"trnm.consensus-app.native-validation-reservation.v0";
const NATIVE_VALIDATION_JOB_IMMUTABLE_CODEC_V0: u16 = 0;
const NATIVE_VALIDATION_JOB_ROW_CODEC_V0: u16 = 0;
const NATIVE_VALIDATION_JOB_IMMUTABLE_DOMAIN_V0: &str =
    "trnm.consensus-app.validation-job-immutable.v0";
const NATIVE_VALIDATION_JOB_ROW_DOMAIN_V0: &str = "trnm.consensus-app.validation-job-row.v0";
const NATIVE_VALIDATION_JOB_DELIVERY_ROW_DOMAIN_V0: &str =
    "trnm.consensus-app.validation-job-delivery-row.v0";
const NATIVE_VALIDATION_BODY_DOMAIN_V0: &str = "trnm.consensus-app.validation-body.v0";
const NATIVE_VALIDATION_RUNTIME_PROFILE_DOMAIN_V0: &str =
    "trnm.consensus-app.validation-runtime-profile.v0";
const NATIVE_VALIDATION_HOST_CONFIG_DOMAIN_V0: &str =
    "trnm.consensus-app.validation-host-config.v0";
const LEGACY_NATIVE_VALIDATION_RESERVATIONS_SCHEMA_V5_SQL: &str = "
    CREATE TABLE IF NOT EXISTS native_validation_reservations (
        route INTEGER NOT NULL CHECK(route IN (0,1)),
        block_id BLOB NOT NULL CHECK(length(block_id)=32),
        view_be BLOB NOT NULL CHECK(length(view_be)=8),
        generation_be BLOB NOT NULL CHECK(length(generation_be)=8),
        target_height_be BLOB NOT NULL CHECK(length(target_height_be)=8),
        parent_block_id BLOB NOT NULL CHECK(length(parent_block_id)=32),
        request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
        PRIMARY KEY(route, block_id, view_be, generation_be),
        UNIQUE(block_id, view_be, generation_be)
    ) STRICT;
";
const NATIVE_VALIDATION_JOURNAL_SCHEMA_V0_SQL: &str = "
    CREATE TABLE IF NOT EXISTS validation_journal_accounting_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        job_count_be BLOB NOT NULL CHECK(length(job_count_be)=8),
        request_bytes_be BLOB NOT NULL CHECK(length(request_bytes_be)=8),
        artifact_bytes_be BLOB NOT NULL CHECK(length(artifact_bytes_be)=8),
        outbox_count_be BLOB NOT NULL CHECK(length(outbox_count_be)=8),
        outbox_bytes_be BLOB NOT NULL CHECK(length(outbox_bytes_be)=8)
    ) STRICT;
    INSERT OR IGNORE INTO validation_journal_accounting_v0(
        singleton, job_count_be, request_bytes_be, artifact_bytes_be,
        outbox_count_be, outbox_bytes_be
    ) VALUES (1, zeroblob(8), zeroblob(8), zeroblob(8), zeroblob(8), zeroblob(8));
    CREATE TABLE IF NOT EXISTS validation_jobs_v0 (
        route INTEGER NOT NULL CHECK(route IN (0,1)),
        block_id BLOB NOT NULL CHECK(length(block_id)=32),
        view_be BLOB NOT NULL CHECK(length(view_be)=8),
        generation_be BLOB NOT NULL CHECK(length(generation_be)=8),
        target_height_be BLOB NOT NULL CHECK(length(target_height_be)=8),
        target_header_cev0 BLOB NOT NULL
            CHECK(length(target_header_cev0)>0 AND length(target_header_cev0)<=65536),
        body_record_codec INTEGER NOT NULL CHECK(body_record_codec=0),
        body_record BLOB NOT NULL
            CHECK(length(body_record)>0 AND length(body_record)<=16777216),
        body_checksum BLOB NOT NULL CHECK(length(body_checksum)=32),
        parent_height_be BLOB NOT NULL CHECK(length(parent_height_be)=8),
        parent_view_be BLOB NOT NULL CHECK(length(parent_view_be)=8),
        parent_block_id BLOB NOT NULL CHECK(length(parent_block_id)=32),
        parent_timestamp_ms_be BLOB NOT NULL CHECK(length(parent_timestamp_ms_be)=8),
        parent_header_cev0 BLOB
            CHECK(parent_header_cev0 IS NULL OR
                  (length(parent_header_cev0)>0 AND length(parent_header_cev0)<=65536)),
        parent_state_version_be BLOB
            CHECK(parent_state_version_be IS NULL OR length(parent_state_version_be)=8),
        parent_state_root BLOB
            CHECK(parent_state_root IS NULL OR length(parent_state_root)=32),
        validator_set_id BLOB NOT NULL CHECK(length(validator_set_id)=32),
        parameters_hash BLOB NOT NULL CHECK(length(parameters_hash)=32),
        protocol_version_be BLOB NOT NULL CHECK(length(protocol_version_be)=4),
        runtime_profile_ref BLOB NOT NULL CHECK(length(runtime_profile_ref)=32),
        host_config_ref BLOB NOT NULL CHECK(length(host_config_ref)=32),
        creation_revision_be BLOB NOT NULL CHECK(length(creation_revision_be)=8),
        request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
        immutable_checksum BLOB NOT NULL CHECK(length(immutable_checksum)=32),
        state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 5),
        result_kind INTEGER CHECK(result_kind IS NULL OR result_kind IN (0,1)),
        invalid_reason_code_be BLOB
            CHECK(invalid_reason_code_be IS NULL OR length(invalid_reason_code_be)=4),
        artifact_codec TEXT
            CHECK(artifact_codec IS NULL OR
                  (length(artifact_codec)>0 AND length(CAST(artifact_codec AS BLOB))<=64)),
        artifact_bytes BLOB
            CHECK(artifact_bytes IS NULL OR length(artifact_bytes)<=67108864),
        artifact_checksum BLOB
            CHECK(artifact_checksum IS NULL OR length(artifact_checksum)=32),
        accepted_core_revision_be BLOB
            CHECK(accepted_core_revision_be IS NULL OR length(accepted_core_revision_be)=8),
        accepted_core_payload_checksum BLOB
            CHECK(accepted_core_payload_checksum IS NULL OR
                  length(accepted_core_payload_checksum)=32),
        row_codec INTEGER NOT NULL CHECK(row_codec=0),
        row_checksum BLOB NOT NULL CHECK(length(row_checksum)=32),
        PRIMARY KEY(route, block_id, view_be, generation_be),
        UNIQUE(block_id, view_be, generation_be),
        CHECK(creation_revision_be=generation_be),
        CHECK(
            (parent_header_cev0 IS NULL AND parent_state_version_be IS NULL AND
             parent_state_root IS NULL) OR
            (parent_header_cev0 IS NOT NULL AND parent_state_version_be IS NOT NULL AND
             parent_state_root IS NOT NULL)
        ),
        CHECK(
            (state=0 AND result_kind IS NULL AND invalid_reason_code_be IS NULL AND
             artifact_codec IS NULL AND artifact_bytes IS NULL AND
             artifact_checksum IS NULL) OR
            (state BETWEEN 1 AND 5 AND result_kind IS NOT NULL AND
             artifact_codec IS NOT NULL AND artifact_bytes IS NOT NULL AND
             artifact_checksum IS NOT NULL)
        ),
        CHECK(
            (result_kind IS NULL AND invalid_reason_code_be IS NULL) OR
            (result_kind=0 AND invalid_reason_code_be IS NULL) OR
            (result_kind=1 AND invalid_reason_code_be IS NOT NULL)
        ),
        CHECK(
            (state<4 AND accepted_core_revision_be IS NULL AND
             accepted_core_payload_checksum IS NULL) OR
            (state>=4 AND accepted_core_revision_be IS NOT NULL AND
             accepted_core_payload_checksum IS NOT NULL)
        )
    ) STRICT;
    CREATE INDEX IF NOT EXISTS validation_jobs_non_reserved_v0
        ON validation_jobs_v0(state) WHERE state<>0;
    CREATE TABLE IF NOT EXISTS validation_callback_outbox_v0 (
        route INTEGER NOT NULL CHECK(route IN (0,1)),
        block_id BLOB NOT NULL CHECK(length(block_id)=32),
        view_be BLOB NOT NULL CHECK(length(view_be)=8),
        generation_be BLOB NOT NULL CHECK(length(generation_be)=8),
        result_kind INTEGER NOT NULL CHECK(result_kind IN (0,1)),
        artifact_checksum BLOB NOT NULL CHECK(length(artifact_checksum)=32),
        payload_codec TEXT NOT NULL
            CHECK(length(payload_codec)>0 AND length(CAST(payload_codec AS BLOB))<=64),
        payload_bytes BLOB NOT NULL CHECK(length(payload_bytes)<=16777216),
        payload_checksum BLOB NOT NULL CHECK(length(payload_checksum)=32),
        idempotency_key BLOB NOT NULL CHECK(length(idempotency_key)=32),
        delivery_attempt_be BLOB NOT NULL CHECK(length(delivery_attempt_be)=8),
        outbox_checksum BLOB NOT NULL CHECK(length(outbox_checksum)=32),
        PRIMARY KEY(route, block_id, view_be, generation_be),
        UNIQUE(idempotency_key),
        FOREIGN KEY(route, block_id, view_be, generation_be)
            REFERENCES validation_jobs_v0(route, block_id, view_be, generation_be)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    ) STRICT;
";
const STORE_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS objects (
        object_key_hex TEXT PRIMARY KEY NOT NULL,
        object_type TEXT NOT NULL,
        version TEXT NOT NULL,
        value_hash_hex TEXT NOT NULL,
        value_bytes BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS command_ids (
        command_id TEXT PRIMARY KEY NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS signer_nonces (
        signer_id TEXT NOT NULL,
        nonce BLOB NOT NULL CHECK(length(nonce)=8),
        PRIMARY KEY (signer_id, nonce)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS validator_lifecycle (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        state_json BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_nodes (
        node_key BLOB PRIMARY KEY NOT NULL,
        node BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_values (
        key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
        version_be BLOB NOT NULL CHECK(length(version_be)=8),
        value BLOB,
        is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0,1)),
        PRIMARY KEY (key_hash, version_be)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_preimages (
        key_hash BLOB PRIMARY KEY NOT NULL CHECK(length(key_hash)=32),
        key_preimage BLOB NOT NULL CHECK(length(key_preimage)>0)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_stale_nodes (
        stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
        node_key BLOB NOT NULL,
        PRIMARY KEY (stale_since_version_be, node_key)
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS auth_stale_nodes_by_node_key
        ON auth_stale_nodes(node_key);
    CREATE TABLE IF NOT EXISTS auth_stale_values (
        stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
        key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
        version_be BLOB NOT NULL CHECK(length(version_be)=8),
        PRIMARY KEY (stale_since_version_be, key_hash, version_be),
        UNIQUE (key_hash, version_be)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_roots (
        version_be BLOB PRIMARY KEY NOT NULL CHECK(length(version_be)=8),
        root_hash BLOB NOT NULL CHECK(length(root_hash)=32)
    ) STRICT;
";

/// The exact authenticated-read boundary which observed a storage failure.
///
/// This is deliberately a closed, data-free stage marker. Consensus callers
/// may use it for diagnostics, but must classify retryability from
/// [`AuthenticatedRuntimeReadFailureV0`] rather than from error strings.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthenticatedRuntimeReadStageV0 {
    OpenDatabase,
    ConfigureDatabase,
    ValidateBindings,
    BeginSnapshot,
    ReadHead,
    ReadQueryFloor,
    ReadRoot,
    ReadObject,
    DeriveObjectKey,
    BuildProof,
    VerifyObject,
    VerifyPocoProjection,
    PlanPostState,
    EndSnapshot,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TypedSqliteReadCodeV0 {
    pub(super) code: ErrorCode,
    pub(super) extended_code: i32,
}

/// Typed source taxonomy for authenticated runtime object reads.
///
/// SQLite failures are classified only from `ErrorCode` and the numeric
/// extended code. Persisted-content and proof failures are fail-stop facts;
/// they never become retryable merely because their diagnostic text happens
/// to resemble an I/O error.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AuthenticatedRuntimeReadFailureV0 {
    DatabaseUnavailable {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: TypedSqliteReadCodeV0,
    },
    StorageUnavailable {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: TypedSqliteReadCodeV0,
    },
    HostResourceUnavailable {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
        reason: &'static str,
    },
    Pruned {
        requested: Version,
        floor: Version,
    },
    /// The Core-authenticated parent is not the committed source represented
    /// by this store. This remains retryable source unavailability rather than
    /// a negative fact about the signed target block.
    SourceMismatch {
        stage: AuthenticatedRuntimeReadStageV0,
        reason: &'static str,
    },
    AuthenticatedStateInvariant {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
        reason: &'static str,
    },
    HostInvariant {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
        reason: &'static str,
    },
}

impl fmt::Display for AuthenticatedRuntimeReadFailureV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseUnavailable { stage, sqlite } => write!(
                formatter,
                "authenticated runtime read database unavailable at {stage:?} ({:?}/{})",
                sqlite.code, sqlite.extended_code
            ),
            Self::StorageUnavailable { stage, sqlite } => write!(
                formatter,
                "authenticated runtime read storage unavailable at {stage:?} ({:?}/{})",
                sqlite.code, sqlite.extended_code
            ),
            Self::HostResourceUnavailable {
                stage,
                sqlite,
                reason,
            } => write!(
                formatter,
                "authenticated runtime read host resource unavailable at {stage:?} ({sqlite:?}): {reason}"
            ),
            Self::Pruned { requested, floor } => write!(
                formatter,
                "authenticated runtime read version {requested} is below durable query floor {floor}"
            ),
            Self::SourceMismatch { stage, reason } => write!(
                formatter,
                "authenticated runtime source mismatch at {stage:?}: {reason}"
            ),
            Self::AuthenticatedStateInvariant {
                stage,
                sqlite,
                reason,
            } => write!(
                formatter,
                "authenticated runtime state invariant at {stage:?} ({sqlite:?}): {reason}"
            ),
            Self::HostInvariant {
                stage,
                sqlite,
                reason,
            } => write!(
                formatter,
                "authenticated runtime read host invariant at {stage:?} ({sqlite:?}): {reason}"
            ),
        }
    }
}

impl std::error::Error for AuthenticatedRuntimeReadFailureV0 {}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeValidationRequestRecordFailureV0 {
    ValidationIdentityMismatch,
    TargetHeaderEncoding,
    ParentHeaderEncoding,
    ApplicationPayloadTooLarge,
    EvidenceCountOverflow,
    EvidenceObjectTooLarge,
    BodyRecordTooLarge,
    FingerprintFrameLengthOverflow,
    RequestFingerprintMismatch,
}

fn hash_native_validation_reservation_frame_v0(
    hasher: &mut Sha256,
    frame: &[u8],
) -> std::result::Result<(), NativeValidationRequestRecordFailureV0> {
    let length = u32::try_from(frame.len())
        .map_err(|_| NativeValidationRequestRecordFailureV0::FingerprintFrameLengthOverflow)?;
    hasher.update(length.to_be_bytes());
    hasher.update(frame);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn begin_native_validation_reservation_fingerprint_v0(
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    target_header_cev0: &[u8],
    application_payload: &[u8],
    evidence_count: u32,
) -> std::result::Result<Sha256, NativeValidationRequestRecordFailureV0> {
    let route = [match route {
        PayloadValidationRouteV0::Proposal => 0,
        PayloadValidationRouteV0::Synced => 1,
    }];
    let codec = NATIVE_VALIDATION_RESERVATION_FINGERPRINT_CODEC_V0.to_be_bytes();
    let validation_view = validation_id.view().get().to_be_bytes();
    let validation_generation = validation_id.generation().to_be_bytes();
    let evidence_count = evidence_count.to_be_bytes();
    let mut hasher = Sha256::new();
    for frame in [
        NATIVE_VALIDATION_RESERVATION_FINGERPRINT_HASH_PREFIX_V0,
        NATIVE_VALIDATION_RESERVATION_FINGERPRINT_DOMAIN_V0,
        codec.as_slice(),
        route.as_slice(),
        validation_id.block_id().as_bytes(),
        validation_view.as_slice(),
        validation_generation.as_slice(),
        target_header_cev0,
        application_payload,
        evidence_count.as_slice(),
    ] {
        hash_native_validation_reservation_frame_v0(&mut hasher, frame)?;
    }
    Ok(hasher)
}

#[allow(clippy::too_many_arguments)]
fn finish_native_validation_reservation_fingerprint_v0(
    mut hasher: Sha256,
    parent_height: u64,
    parent_view: u64,
    parent_block_id: &[u8; 32],
    parent_timestamp_ms: u64,
    parent_header_cev0: Option<&[u8]>,
) -> std::result::Result<[u8; 32], NativeValidationRequestRecordFailureV0> {
    let parent_height = parent_height.to_be_bytes();
    let parent_view = parent_view.to_be_bytes();
    let parent_timestamp_ms = parent_timestamp_ms.to_be_bytes();
    let parent_header_presence = [u8::from(parent_header_cev0.is_some())];
    for frame in [
        parent_height.as_slice(),
        parent_view.as_slice(),
        parent_block_id.as_slice(),
        parent_timestamp_ms.as_slice(),
        parent_header_presence.as_slice(),
    ] {
        hash_native_validation_reservation_frame_v0(&mut hasher, frame)?;
    }
    if let Some(parent_header_cev0) = parent_header_cev0 {
        hash_native_validation_reservation_frame_v0(&mut hasher, parent_header_cev0)?;
    }
    Ok(hasher.finalize().into())
}

pub(super) fn native_validation_request_fingerprint_v0(
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    block: &Block,
    parent: &PayloadValidationParentV0,
) -> std::result::Result<[u8; 32], NativeValidationRequestRecordFailureV0> {
    let target_header_cev0 = block
        .header()
        .try_cev0_bytes()
        .map_err(|_| NativeValidationRequestRecordFailureV0::TargetHeaderEncoding)?;
    let evidence_count = u32::try_from(block.evidence_objects().len())
        .map_err(|_| NativeValidationRequestRecordFailureV0::EvidenceCountOverflow)?;
    let mut hasher = begin_native_validation_reservation_fingerprint_v0(
        route,
        validation_id,
        &target_header_cev0,
        block.application_payload(),
        evidence_count,
    )?;
    for evidence in block.evidence_objects() {
        hash_native_validation_reservation_frame_v0(&mut hasher, evidence)?;
    }
    let parent_tip = parent.tip();
    let parent_header_cev0 = parent
        .exact_header()
        .map(|header| {
            header
                .try_cev0_bytes()
                .map_err(|_| NativeValidationRequestRecordFailureV0::ParentHeaderEncoding)
        })
        .transpose()?;
    finish_native_validation_reservation_fingerprint_v0(
        hasher,
        parent_tip.height().get(),
        parent_tip.view().get(),
        parent_tip.block_id().as_bytes(),
        parent_tip.timestamp_ms(),
        parent_header_cev0.as_deref(),
    )
}

struct NativeValidationRequestBodyRecordV0 {
    bytes: Vec<u8>,
    checksum: [u8; 32],
}

impl NativeValidationRequestBodyRecordV0 {
    fn from_block(
        block: &Block,
    ) -> std::result::Result<Self, NativeValidationRequestRecordFailureV0> {
        let payload = block.application_payload();
        let payload_length = u32::try_from(payload.len())
            .map_err(|_| NativeValidationRequestRecordFailureV0::ApplicationPayloadTooLarge)?;
        let evidence_count = u32::try_from(block.evidence_objects().len())
            .map_err(|_| NativeValidationRequestRecordFailureV0::EvidenceCountOverflow)?;
        let mut bytes = Vec::with_capacity(block.logical_block_size());
        bytes.extend_from_slice(&NATIVE_VALIDATION_BODY_RECORD_CODEC_V0.to_be_bytes());
        bytes.extend_from_slice(&payload_length.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&evidence_count.to_be_bytes());
        for evidence in block.evidence_objects() {
            let evidence_length = u32::try_from(evidence.len())
                .map_err(|_| NativeValidationRequestRecordFailureV0::EvidenceObjectTooLarge)?;
            bytes.extend_from_slice(&evidence_length.to_be_bytes());
            bytes.extend_from_slice(evidence);
        }
        if bytes.len() > MAX_NATIVE_VALIDATION_BODY_RECORD_BYTES {
            return Err(NativeValidationRequestRecordFailureV0::BodyRecordTooLarge);
        }
        let checksum = hash_domain(NATIVE_VALIDATION_BODY_DOMAIN_V0, &[&bytes]);
        Ok(Self { bytes, checksum })
    }
}

/// Process-local inputs for one revalidatable native raw-request job fact.
///
/// The constructor accepts only one exact Core-issued block/parent graph and
/// freezes the target header, canonical raw body record, parent state
/// reference and execution-configuration references before SQLite is
/// opened. The value is deliberately neither cloneable nor serializable. Its
/// checksums are congruence and recovery facts, never payload-validity or Core
/// callback authority.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct NativeValidationReservationFactsV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    target_height: u64,
    target_header_cev0: Vec<u8>,
    body_record: Vec<u8>,
    body_checksum: [u8; 32],
    parent_height: u64,
    parent_view: u64,
    parent_block_id: [u8; 32],
    parent_timestamp_ms: u64,
    parent_header_cev0: Option<Vec<u8>>,
    parent_state_version: Option<u64>,
    parent_state_root: Option<[u8; 32]>,
    validator_set_id: [u8; 32],
    parameters_hash: [u8; 32],
    protocol_version: u32,
    creation_revision: u64,
    request_fingerprint: [u8; 32],
}

#[cfg_attr(not(test), allow(dead_code))]
impl NativeValidationReservationFactsV0 {
    pub(super) fn from_core_request_v0(
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        block: &Block,
        parent: &PayloadValidationParentV0,
        request_fingerprint: [u8; 32],
    ) -> std::result::Result<Self, NativeValidationRequestRecordFailureV0> {
        let header = block.header();
        if validation_id.block_id() != block.id() || validation_id.view() != header.view() {
            return Err(NativeValidationRequestRecordFailureV0::ValidationIdentityMismatch);
        }
        let target_header_cev0 = header
            .try_cev0_bytes()
            .map_err(|_| NativeValidationRequestRecordFailureV0::TargetHeaderEncoding)?;
        if target_header_cev0.is_empty()
            || target_header_cev0.len() > MAX_NATIVE_VALIDATION_HEADER_BYTES
        {
            return Err(NativeValidationRequestRecordFailureV0::TargetHeaderEncoding);
        }
        let body = NativeValidationRequestBodyRecordV0::from_block(block)?;
        if native_validation_request_fingerprint_v0(route, validation_id, block, parent)?
            != request_fingerprint
        {
            return Err(NativeValidationRequestRecordFailureV0::RequestFingerprintMismatch);
        }
        let parent_tip = parent.tip();
        let (parent_header_cev0, parent_state_version, parent_state_root) = parent
            .exact_header()
            .map(|header| {
                let encoded = header
                    .try_cev0_bytes()
                    .map_err(|_| NativeValidationRequestRecordFailureV0::ParentHeaderEncoding)?;
                if encoded.is_empty() || encoded.len() > MAX_NATIVE_VALIDATION_HEADER_BYTES {
                    return Err(NativeValidationRequestRecordFailureV0::ParentHeaderEncoding);
                }
                Ok((
                    encoded,
                    header.height().get(),
                    *header.state_root().as_bytes(),
                ))
            })
            .transpose()?
            .map_or((None, None, None), |(header, version, root)| {
                (Some(header), Some(version), Some(root))
            });
        Ok(Self {
            route,
            validation_id,
            target_height: header.height().get(),
            target_header_cev0,
            body_record: body.bytes,
            body_checksum: body.checksum,
            parent_height: parent_tip.height().get(),
            parent_view: parent_tip.view().get(),
            parent_block_id: *parent_tip.block_id().as_bytes(),
            parent_timestamp_ms: parent_tip.timestamp_ms(),
            parent_header_cev0,
            parent_state_version,
            parent_state_root,
            validator_set_id: *header.validator_set_id().as_bytes(),
            parameters_hash: *header.consensus_parameters_hash().as_bytes(),
            protocol_version: header.protocol_version().get(),
            creation_revision: validation_id.generation(),
            request_fingerprint,
        })
    }

    #[cfg(test)]
    pub(super) fn new_for_test_v0(
        route: PayloadValidationRouteV0,
        generation: u64,
        chain_id: &str,
    ) -> Self {
        use trnm_consensus_types::{
            BlockHeader, BlockKind, ChainId, ConsensusParametersHash, Epoch, EvidenceRoot,
            GenesisHash, Height, PayloadDigest, ProtocolVersion, ReceiptsRoot, StateRoot,
            ValidatorId, ValidatorSetId,
        };

        let test_chain = ChainId::new(chain_id).expect("valid validation-job test chain ID");
        let parent_header = BlockHeader::new(
            GenesisHash::new([1; 32]),
            test_chain,
            ProtocolVersion::V0,
            Epoch::new(1),
            View::new(8),
            Height::new(11),
            trnm_consensus_types::BlockKind::Regular,
            BlockId::new([2; 32]),
            ValidatorId::new([3; 32]),
            ValidatorSetId::new([4; 32]),
            ConsensusParametersHash::new([5; 32]),
            PayloadDigest::new([6; 32]),
            StateRoot::new([3; 32]),
            ReceiptsRoot::new([8; 32]),
            EvidenceRoot::new([9; 32]),
            10,
            None,
        )
        .expect("construct validation-job test parent header");
        let target_header = BlockHeader::new(
            GenesisHash::new([1; 32]),
            test_chain,
            ProtocolVersion::V0,
            Epoch::new(1),
            View::new(9),
            Height::new(12),
            BlockKind::Regular,
            parent_header.id(),
            ValidatorId::new([3; 32]),
            ValidatorSetId::new([4; 32]),
            ConsensusParametersHash::new([5; 32]),
            PayloadDigest::new([6; 32]),
            StateRoot::new([7; 32]),
            ReceiptsRoot::new([8; 32]),
            EvidenceRoot::new([9; 32]),
            11,
            None,
        )
        .expect("construct validation-job test target header");
        let validation_id = ValidationId::new(target_header.id(), target_header.view(), generation);
        let body_record = vec![0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0];
        let body_checksum = hash_domain(NATIVE_VALIDATION_BODY_DOMAIN_V0, &[&body_record]);
        let mut facts = Self {
            route,
            validation_id,
            target_height: target_header.height().get(),
            target_header_cev0: target_header
                .try_cev0_bytes()
                .expect("encode validation-job test target header"),
            body_record,
            body_checksum,
            parent_height: parent_header.height().get(),
            parent_view: parent_header.view().get(),
            parent_block_id: *parent_header.id().as_bytes(),
            parent_timestamp_ms: parent_header.timestamp_ms(),
            parent_header_cev0: Some(
                parent_header
                    .try_cev0_bytes()
                    .expect("encode validation-job test parent header"),
            ),
            parent_state_version: Some(parent_header.height().get()),
            parent_state_root: Some([3; 32]),
            validator_set_id: [4; 32],
            parameters_hash: [5; 32],
            protocol_version: ProtocolVersion::V0.get(),
            creation_revision: validation_id.generation(),
            request_fingerprint: [0; 32],
        };
        facts.request_fingerprint =
            native_validation_reservation_fingerprint_from_record_v0(&facts)
                .expect("derive validation-job test request fingerprint");
        facts
    }
}

/// Opaque proof that the exact route/full-ValidationId request family has a
/// congruent durable reservation in the authoritative application database.
/// This token does not authorize evaluation, persistence, a Core callback, or
/// ABCI output.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a durable native validation reservation is not terminal authority"]
pub(super) struct NativeValidationReservationTokenV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    request_fingerprint: [u8; 32],
    immutable_checksum: [u8; 32],
    issuing_writer_gate: Arc<Mutex<()>>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl NativeValidationReservationTokenV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.validation_id
    }

    pub(super) const fn request_fingerprint(&self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub(super) const fn immutable_checksum(&self) -> [u8; 32] {
        self.immutable_checksum
    }

    pub(super) fn is_bound_to_store_v0(&self, store: &ApplicationStore) -> bool {
        Arc::ptr_eq(&self.issuing_writer_gate, &store.writer_gate)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum NativeValidationJobStateV0 {
    Reserved,
    Evaluated,
    CallbackPending,
    Delivered,
    Acked,
    Applied,
}

impl NativeValidationJobStateV0 {
    const fn code(self) -> i64 {
        match self {
            Self::Reserved => 0,
            Self::Evaluated => 1,
            Self::CallbackPending => 2,
            Self::Delivered => 3,
            Self::Acked => 4,
            Self::Applied => 5,
        }
    }

    const fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::Reserved),
            1 => Some(Self::Evaluated),
            2 => Some(Self::CallbackPending),
            3 => Some(Self::Delivered),
            4 => Some(Self::Acked),
            5 => Some(Self::Applied),
            _ => None,
        }
    }
}

/// Checksum-verified durable state returned when an exact job already exists
/// or when restart recovery enumerates local work. It exposes no conversion
/// into the unique first-reservation evaluation token and is not Core
/// callback authority.
#[allow(dead_code)]
#[must_use = "an existing durable job must be routed by its verified recovery state"]
pub(super) struct DurableNativeValidationJobV0 {
    facts: NativeValidationReservationFactsV0,
    runtime_profile_ref: [u8; 32],
    host_config_ref: [u8; 32],
    immutable_checksum: [u8; 32],
    state: NativeValidationJobStateV0,
    result_kind: Option<i64>,
    invalid_reason_code_be: Option<Vec<u8>>,
    artifact_codec: Option<String>,
    artifact_bytes: Option<Vec<u8>>,
    artifact_checksum: Option<[u8; 32]>,
    accepted_core_revision_be: Option<Vec<u8>>,
    accepted_core_payload_checksum: Option<[u8; 32]>,
    row_checksum: [u8; 32],
}

#[allow(dead_code)]
impl DurableNativeValidationJobV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.facts.route
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.facts.validation_id
    }

    pub(super) const fn target_height(&self) -> u64 {
        self.facts.target_height
    }

    pub(super) const fn parent_block_id(&self) -> [u8; 32] {
        self.facts.parent_block_id
    }

    pub(super) const fn request_fingerprint(&self) -> [u8; 32] {
        self.facts.request_fingerprint
    }

    pub(super) const fn immutable_checksum(&self) -> [u8; 32] {
        self.immutable_checksum
    }

    pub(super) const fn creation_revision(&self) -> u64 {
        self.facts.creation_revision
    }

    pub(super) const fn state(&self) -> NativeValidationJobStateV0 {
        self.state
    }
}

/// Deeply revalidated join of one deterministic-invalid job, its canonical
/// artifact and its exact callback outbox row. This remains an inert durable
/// fact until it is joined to the unique process-local preparation lineage.
struct RevalidatedNativeValidationInvalidOutboxV0 {
    artifact: RevalidatedDurableInvalidArtifactV0,
    callback: RevalidatedDurableInvalidCallbackV0,
    delivery_attempt: u64,
}

#[must_use = "a verified callback record is still not live Core delivery authority"]
struct VerifiedNativeValidationInvalidCallbackV0 {
    job: Box<DurableNativeValidationJobV0>,
    artifact: RevalidatedDurableInvalidArtifactV0,
    callback: RevalidatedDurableInvalidCallbackV0,
    delivery_attempt: u64,
}

impl VerifiedNativeValidationInvalidCallbackV0 {
    fn new_v0(
        job: DurableNativeValidationJobV0,
        outbox: RevalidatedNativeValidationInvalidOutboxV0,
    ) -> Self {
        Self {
            job: Box::new(job),
            artifact: outbox.artifact,
            callback: outbox.callback,
            delivery_attempt: outbox.delivery_attempt,
        }
    }

    const fn route(&self) -> PayloadValidationRouteV0 {
        self.job.route()
    }

    const fn validation_id(&self) -> ValidationId {
        self.job.validation_id()
    }

    const fn reason(&self) -> DurableDeterministicInvalidReasonV0 {
        self.artifact.reason()
    }

    const fn request_fingerprint(&self) -> [u8; 32] {
        self.job.request_fingerprint()
    }

    const fn immutable_checksum(&self) -> [u8; 32] {
        self.job.immutable_checksum()
    }

    const fn artifact_checksum(&self) -> [u8; 32] {
        self.artifact.checksum()
    }

    const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.callback.payload_checksum()
    }

    const fn idempotency_key(&self) -> [u8; 32] {
        self.callback.idempotency_key()
    }

    const fn outbox_checksum(&self) -> [u8; 32] {
        self.callback.outbox_checksum()
    }

    const fn delivery_attempt(&self) -> u64 {
        self.delivery_attempt
    }
}

/// Distinguishes first durable creation from exact owner-preserving replay.
/// Both retain the same live process capability; generic database recovery
/// never constructs this disposition or its owner.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeValidationInvalidSealDispositionV0 {
    NewlyCommitted,
    ExactExisting,
    CommitConfirmedExisting,
}

/// Live callback-delivery owner produced only while consuming the unique
/// complete-body deterministic-invalid preparation. The database artifact is
/// retained merely as a verified fact and cannot mint this type on reopen.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a live deterministic-invalid callback owner must be delivered or retained"]
pub(super) struct LiveNativeValidationInvalidCallbackV0 {
    prepared: PreparedDurableInvalidV0,
    verified: VerifiedNativeValidationInvalidCallbackV0,
    disposition: NativeValidationInvalidSealDispositionV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl LiveNativeValidationInvalidCallbackV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.verified.route()
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.verified.validation_id()
    }

    pub(super) const fn reason(&self) -> DurableDeterministicInvalidReasonV0 {
        self.verified.reason()
    }

    pub(super) const fn request_fingerprint(&self) -> [u8; 32] {
        self.verified.request_fingerprint()
    }

    pub(super) const fn immutable_checksum(&self) -> [u8; 32] {
        self.verified.immutable_checksum()
    }

    pub(super) const fn artifact_checksum(&self) -> [u8; 32] {
        self.verified.artifact_checksum()
    }

    pub(super) const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.verified.callback_payload_checksum()
    }

    pub(super) const fn idempotency_key(&self) -> [u8; 32] {
        self.verified.idempotency_key()
    }

    pub(super) const fn delivery_attempt(&self) -> u64 {
        self.verified.delivery_attempt()
    }

    pub(super) const fn disposition(&self) -> NativeValidationInvalidSealDispositionV0 {
        self.disposition
    }

    pub(super) const fn state(&self) -> NativeValidationJobStateV0 {
        self.verified.job.state()
    }

    pub(super) fn is_bound_to_store_v0(&self, store: &ApplicationStore) -> bool {
        self.prepared.is_bound_to_store_v0(store)
    }
}

/// Owner retained after the Core callback has been accepted and the exact
/// application outbox has atomically entered `Delivered`.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a delivered callback must reach exact safety persistence and acknowledgement"]
pub(super) struct DeliveredNativeValidationInvalidCallbackV0 {
    prepared: PreparedDurableInvalidV0,
    verified: VerifiedNativeValidationInvalidCallbackV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl DeliveredNativeValidationInvalidCallbackV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.verified.route()
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.verified.validation_id()
    }

    pub(super) const fn reason(&self) -> DurableDeterministicInvalidReasonV0 {
        self.verified.reason()
    }

    pub(super) const fn request_fingerprint(&self) -> [u8; 32] {
        self.verified.request_fingerprint()
    }

    pub(super) const fn immutable_checksum(&self) -> [u8; 32] {
        self.verified.immutable_checksum()
    }

    pub(super) const fn artifact_checksum(&self) -> [u8; 32] {
        self.verified.artifact_checksum()
    }

    pub(super) const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.verified.callback_payload_checksum()
    }

    pub(super) const fn idempotency_key(&self) -> [u8; 32] {
        self.verified.idempotency_key()
    }

    pub(super) const fn delivery_attempt(&self) -> u64 {
        self.verified.delivery_attempt()
    }

    pub(super) fn is_bound_to_store_v0(&self, store: &ApplicationStore) -> bool {
        self.prepared.is_bound_to_store_v0(store)
    }

    /// Binds a driver-verified exact Core safety revision to this delivered
    /// owner. The callback payload checksum is derived from the retained
    /// canonical outbox rather than accepted as a detached argument.
    fn bind_confirmed_core_completion_v0(
        self: Box<Self>,
        accepted_core_revision: u64,
    ) -> std::result::Result<
        Box<ConfirmedCoreInvalidCompletionV0>,
        Box<FailedBindConfirmedCoreInvalidCompletionV0>,
    > {
        if accepted_core_revision <= self.verified.job.creation_revision() {
            return Err(Box::new(FailedBindConfirmedCoreInvalidCompletionV0 {
                owner: self,
                cause: BindConfirmedCoreInvalidCompletionFailureCauseV0::RevisionNotAdvanced,
            }));
        }
        Ok(Box::new(ConfirmedCoreInvalidCompletionV0 {
            delivered: self,
            accepted_core_revision,
        }))
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BindConfirmedCoreInvalidCompletionFailureCauseV0 {
    RevisionNotAdvanced,
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed completion binding retains the delivered callback owner"]
pub(super) struct FailedBindConfirmedCoreInvalidCompletionV0 {
    #[allow(dead_code)]
    owner: Box<DeliveredNativeValidationInvalidCallbackV0>,
    cause: BindConfirmedCoreInvalidCompletionFailureCauseV0,
}

impl fmt::Debug for FailedBindConfirmedCoreInvalidCompletionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedBindConfirmedCoreInvalidCompletionV0")
            .field("cause", &self.cause)
            .field("retains_delivered_owner", &true)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedBindConfirmedCoreInvalidCompletionV0 {
    #[allow(dead_code)]
    pub(super) const fn cause(&self) -> BindConfirmedCoreInvalidCompletionFailureCauseV0 {
        self.cause
    }
}

/// Driver-attested exact safety-state persistence joined to the delivered
/// callback lineage. Only the callback driver should construct this after its
/// durable sink confirms the exact Core state.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a confirmed Core completion must be atomically acknowledged"]
pub(super) struct ConfirmedCoreInvalidCompletionV0 {
    delivered: Box<DeliveredNativeValidationInvalidCallbackV0>,
    accepted_core_revision: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ConfirmedCoreInvalidCompletionV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.delivered.route()
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.delivered.validation_id()
    }

    pub(super) const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.delivered.callback_payload_checksum()
    }

    pub(super) const fn accepted_core_revision(&self) -> u64 {
        self.accepted_core_revision
    }
}

/// Durable application acknowledgement retained through the subsequent Core
/// `StorageAck` release. Its outbox has been retired exactly once.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "an acknowledged callback still owns the pending Core barrier release"]
pub(super) struct AckedNativeValidationInvalidCallbackV0 {
    prepared: PreparedDurableInvalidV0,
    durable: Box<DurableNativeValidationJobV0>,
    accepted_core_revision: u64,
    callback_payload_checksum: [u8; 32],
}

#[cfg_attr(not(test), allow(dead_code))]
impl AckedNativeValidationInvalidCallbackV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.durable.route()
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.durable.validation_id()
    }

    pub(super) fn reason(&self) -> DurableDeterministicInvalidReasonV0 {
        match native_validation_job_invalid_reason_v0(&self.durable) {
            Some(reason) => reason,
            None => unreachable!(),
        }
    }

    pub(super) const fn request_fingerprint(&self) -> [u8; 32] {
        self.durable.request_fingerprint()
    }

    pub(super) const fn artifact_checksum(&self) -> [u8; 32] {
        match self.durable.artifact_checksum {
            Some(checksum) => checksum,
            None => unreachable!(),
        }
    }

    pub(super) const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.callback_payload_checksum
    }

    pub(super) const fn accepted_core_revision(&self) -> u64 {
        self.accepted_core_revision
    }

    pub(super) fn is_bound_to_store_v0(&self, store: &ApplicationStore) -> bool {
        self.prepared.is_bound_to_store_v0(store)
    }
}

/// Whether this call created the durable row or joined the already-identical
/// job. Only `Reserved` retains first-evaluation admission. `Existing`
/// returns the checksum-verified durable state for explicit recovery/takeover
/// routing without recreating that token. Neither variant is a result or
/// callback authority.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a reservation decision must remain attached to its opaque token"]
pub(super) enum NativeValidationReservationDecisionV0 {
    Reserved(NativeValidationReservationTokenV0),
    Existing(Box<DurableNativeValidationJobV0>),
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a durable invalid seal decision must remain attached to verified journal state"]
pub(super) enum NativeValidationInvalidSealDecisionV0 {
    CallbackPending(Box<LiveNativeValidationInvalidCallbackV0>),
    Existing(Box<LiveNativeValidationInvalidCallbackV0>),
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NativeValidationInvalidSealFailureCauseV0 {
    Storage(NativeValidationReservationFailureCauseV0),
    HostInvariant {
        stage: NativeValidationReservationStageV0,
    },
    ArtifactByteCapacity {
        maximum: u64,
    },
    CallbackByteCapacity {
        maximum: u64,
    },
    Invariant(NativeValidationReservationInvariantV0),
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed durable invalid seal retains its unique prepared owner"]
pub(super) struct FailedNativeValidationInvalidSealV0 {
    prepared: PreparedDurableInvalidV0,
    cause: NativeValidationInvalidSealFailureCauseV0,
}

impl fmt::Debug for FailedNativeValidationInvalidSealV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedNativeValidationInvalidSealV0")
            .field("cause", &self.cause)
            .field("retains_prepared_owner", &true)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedNativeValidationInvalidSealV0 {
    pub(super) const fn cause(&self) -> &NativeValidationInvalidSealFailureCauseV0 {
        &self.cause
    }

    pub(super) const fn prepared(&self) -> &PreparedDurableInvalidV0 {
        &self.prepared
    }

    pub(super) fn into_prepared_v0(self) -> PreparedDurableInvalidV0 {
        self.prepared
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NativeValidationInvalidJournalTransitionFailureCauseV0 {
    Storage(NativeValidationReservationFailureCauseV0),
    HostInvariant {
        stage: NativeValidationReservationStageV0,
    },
    DeliveryAttemptOverflow,
    AccountingUnderflow,
    Invariant(NativeValidationReservationInvariantV0),
}

fn native_validation_invalid_transition_failure_v0(
    cause: NativeValidationReservationFailureCauseV0,
) -> NativeValidationInvalidJournalTransitionFailureCauseV0 {
    match cause {
        NativeValidationReservationFailureCauseV0::Invariant { kind, .. } => {
            NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(kind)
        }
        NativeValidationReservationFailureCauseV0::HostInvariant { stage, .. } => {
            NativeValidationInvalidJournalTransitionFailureCauseV0::HostInvariant { stage }
        }
        other => NativeValidationInvalidJournalTransitionFailureCauseV0::Storage(other),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed delivery transition retains its live callback owner"]
pub(super) struct FailedNativeValidationInvalidDeliveryV0 {
    owner: Box<LiveNativeValidationInvalidCallbackV0>,
    cause: NativeValidationInvalidJournalTransitionFailureCauseV0,
}

impl fmt::Debug for FailedNativeValidationInvalidDeliveryV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedNativeValidationInvalidDeliveryV0")
            .field("cause", &self.cause)
            .field("retains_live_owner", &true)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedNativeValidationInvalidDeliveryV0 {
    pub(super) const fn cause(&self) -> &NativeValidationInvalidJournalTransitionFailureCauseV0 {
        &self.cause
    }

    pub(super) fn into_owner_v0(self) -> Box<LiveNativeValidationInvalidCallbackV0> {
        self.owner
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed acknowledgement retains its confirmed completion owner"]
pub(super) struct FailedNativeValidationInvalidAcknowledgementV0 {
    owner: Box<ConfirmedCoreInvalidCompletionV0>,
    cause: NativeValidationInvalidJournalTransitionFailureCauseV0,
}

impl fmt::Debug for FailedNativeValidationInvalidAcknowledgementV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedNativeValidationInvalidAcknowledgementV0")
            .field("cause", &self.cause)
            .field("retains_confirmed_completion_owner", &true)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedNativeValidationInvalidAcknowledgementV0 {
    pub(super) const fn cause(&self) -> &NativeValidationInvalidJournalTransitionFailureCauseV0 {
        &self.cause
    }

    pub(super) fn into_owner_v0(self) -> Box<ConfirmedCoreInvalidCompletionV0> {
        self.owner
    }
}

fn native_validation_invalid_seal_failure_v0(
    cause: NativeValidationReservationFailureCauseV0,
) -> NativeValidationInvalidSealFailureCauseV0 {
    match cause {
        NativeValidationReservationFailureCauseV0::Invariant { kind, .. } => {
            NativeValidationInvalidSealFailureCauseV0::Invariant(kind)
        }
        NativeValidationReservationFailureCauseV0::HostInvariant { stage, .. } => {
            NativeValidationInvalidSealFailureCauseV0::HostInvariant { stage }
        }
        other => NativeValidationInvalidSealFailureCauseV0::Storage(other),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeValidationReservationStageV0 {
    LockWriter,
    OpenDatabase,
    ConfigureDatabase,
    BeginTransaction,
    ValidateBindings,
    ReadExisting,
    ReadCapacity,
    Insert,
    Commit,
    ConfirmCommit,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeValidationReservationInvariantV0 {
    IssuingStoreMismatch,
    RouteMismatch,
    TargetHeightMismatch,
    ParentBlockIdMismatch,
    RequestFingerprintMismatch,
    TargetHeaderMismatch,
    BodyRecordMismatch,
    ParentContextMismatch,
    ConfigurationReferenceMismatch,
    CreationRevisionMismatch,
    ChecksumMismatch,
    StateMismatch,
    PersistedRepresentationMalformed,
    CommitReadbackConflict,
}

/// Typed durable-reservation failure taxonomy. Callers must retain their
/// claimed Core owner alongside this cause; no bare cause can be retried or
/// promoted on its own.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NativeValidationReservationFailureCauseV0 {
    DatabaseUnavailable {
        stage: NativeValidationReservationStageV0,
        sqlite: TypedSqliteReadCodeV0,
    },
    StorageUnavailable {
        stage: NativeValidationReservationStageV0,
        sqlite: TypedSqliteReadCodeV0,
    },
    HostResourceUnavailable {
        stage: NativeValidationReservationStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
    },
    Capacity {
        maximum: u64,
    },
    ByteCapacity {
        maximum: u64,
    },
    Invariant {
        stage: NativeValidationReservationStageV0,
        kind: NativeValidationReservationInvariantV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
    },
    HostInvariant {
        stage: NativeValidationReservationStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
    },
}

/// Owning failure returned only after the reservation transaction has ended.
/// It retains the exact facts so a future explicit retry path cannot splice a
/// different route, generation, source, parent, or fingerprint into the same
/// claimed Core owner.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed durable reservation retains exact facts for an explicit retry"]
pub(super) struct FailedNativeValidationReservationV0 {
    facts: NativeValidationReservationFactsV0,
    cause: NativeValidationReservationFailureCauseV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedNativeValidationReservationV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.facts.route
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.facts.validation_id
    }

    pub(super) const fn cause(&self) -> &NativeValidationReservationFailureCauseV0 {
        &self.cause
    }
}

struct NativeValidationReservationExistingV0 {
    route: i64,
    block_id: Vec<u8>,
    view_be: Vec<u8>,
    generation_be: Vec<u8>,
    target_height_be: Vec<u8>,
    target_header_cev0: Vec<u8>,
    body_record_codec: i64,
    body_record: Vec<u8>,
    body_checksum: Vec<u8>,
    parent_height_be: Vec<u8>,
    parent_view_be: Vec<u8>,
    parent_block_id: Vec<u8>,
    parent_timestamp_ms_be: Vec<u8>,
    parent_header_cev0: Option<Vec<u8>>,
    parent_state_version_be: Option<Vec<u8>>,
    parent_state_root: Option<Vec<u8>>,
    validator_set_id: Vec<u8>,
    parameters_hash: Vec<u8>,
    protocol_version_be: Vec<u8>,
    runtime_profile_ref: Vec<u8>,
    host_config_ref: Vec<u8>,
    creation_revision_be: Vec<u8>,
    request_fingerprint: Vec<u8>,
    immutable_checksum: Vec<u8>,
    state: i64,
    result_kind: Option<i64>,
    invalid_reason_code_be: Option<Vec<u8>>,
    artifact_codec: Option<String>,
    artifact_bytes: Option<Vec<u8>>,
    artifact_checksum: Option<Vec<u8>>,
    accepted_core_revision_be: Option<Vec<u8>>,
    accepted_core_payload_checksum: Option<Vec<u8>>,
    row_codec: i64,
    row_checksum: Vec<u8>,
}

struct NativeValidationCallbackOutboxExistingV0 {
    route: i64,
    block_id: Vec<u8>,
    view_be: Vec<u8>,
    generation_be: Vec<u8>,
    result_kind: i64,
    artifact_checksum: Vec<u8>,
    payload_codec: String,
    payload_bytes: Vec<u8>,
    payload_checksum: Vec<u8>,
    idempotency_key: Vec<u8>,
    delivery_attempt_be: Vec<u8>,
    outbox_checksum: Vec<u8>,
}

enum NativeValidationReservationInnerDecisionV0 {
    Reserved,
    Existing(DurableNativeValidationJobV0),
    CommitUncertainExisting(DurableNativeValidationJobV0),
}

enum NativeValidationInvalidSealInnerDecisionV0 {
    CallbackPending(VerifiedNativeValidationInvalidCallbackV0),
    Existing(VerifiedNativeValidationInvalidCallbackV0),
    CommitUncertainExisting(VerifiedNativeValidationInvalidCallbackV0),
}

enum NativeValidationInvalidCommitReadbackV0 {
    Reserved,
    CallbackPending(Box<VerifiedNativeValidationInvalidCallbackV0>),
}

enum NativeValidationInvalidDeliveryInnerDecisionV0 {
    Delivered(VerifiedNativeValidationInvalidCallbackV0),
    CommitUncertainDelivered(VerifiedNativeValidationInvalidCallbackV0),
}

enum NativeValidationInvalidDeliveryCommitReadbackV0 {
    CallbackPending,
    Delivered(Box<VerifiedNativeValidationInvalidCallbackV0>),
}

enum NativeValidationInvalidAcknowledgementInnerDecisionV0 {
    Acked(DurableNativeValidationJobV0),
    CommitUncertainAcked(DurableNativeValidationJobV0),
}

enum NativeValidationInvalidAcknowledgementCommitReadbackV0 {
    Delivered,
    Acked(Box<DurableNativeValidationJobV0>),
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoreFailpoint {
    BeforeSqlCommit,
    AfterSqlCommitBeforeStatus,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeValidationInvalidSealFailpointV0 {
    AfterOutboxInsert,
    AfterJobUpdate,
    AfterAccountingUpdate,
    BeforeCommit,
    #[cfg(test)]
    AfterCommitBeforeReturn,
}

#[derive(Debug, Clone)]
pub(super) struct ApplicationStore {
    status_path: PathBuf,
    database_path: PathBuf,
    chain_id: String,
    signer_policy_hash_hex: String,
    writer_gate: Arc<Mutex<()>>,
    writer_waiters: Arc<AtomicUsize>,
    maintenance_gate: Arc<Mutex<()>>,
    active_snapshot_pins: Arc<AtomicUsize>,
    namespace_owner: Arc<ApplicationStoreNamespaceOwnerV0>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApplicationStoreFileIdentityV0 {
    device: u64,
    inode: u64,
}

impl ApplicationStoreFileIdentityV0 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplicationStoreOwnerModeV0 {
    OrdinaryShared,
    RecoveryExclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ApplicationStoreNamespaceOpenFailureV0 {
    InvalidPath,
    ParentUnavailable,
    MissingDatabase,
    DatabaseIsNotRegularFile,
    Locked,
    UnsafeNamespace,
    NamespaceChanged,
    ProcessChanged,
    Io,
}

impl fmt::Display for ApplicationStoreNamespaceOpenFailureV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "application store namespace path is invalid",
            Self::ParentUnavailable => "application store namespace parent is unavailable",
            Self::MissingDatabase => "application store database is missing",
            Self::DatabaseIsNotRegularFile => {
                "application store database is not a regular non-symlink file"
            }
            Self::Locked => "application store namespace is owned by another lifetime",
            Self::UnsafeNamespace => {
                "application store recovery namespace ownership or mode is unsafe"
            }
            Self::NamespaceChanged => "application store namespace identity changed",
            Self::ProcessChanged => "application store owner crossed a process boundary",
            Self::Io => "application store namespace I/O failed",
        })
    }
}

impl std::error::Error for ApplicationStoreNamespaceOpenFailureV0 {}

#[derive(Debug)]
struct ApplicationStoreNamespaceOwnerV0 {
    owner_pid: u32,
    mode: ApplicationStoreOwnerModeV0,
    canonical_parent: PathBuf,
    parent_handle: File,
    parent_identity: ApplicationStoreFileIdentityV0,
    parent_uid: u32,
    database_path: PathBuf,
    lock_path: PathBuf,
    lock_handle: File,
    lock_identity: ApplicationStoreFileIdentityV0,
    #[cfg(test)]
    test_lock_released: std::sync::atomic::AtomicBool,
}

impl ApplicationStoreNamespaceOwnerV0 {
    fn acquire(
        status_path: &Path,
        mode: ApplicationStoreOwnerModeV0,
    ) -> std::result::Result<(Self, PathBuf, PathBuf), ApplicationStoreNamespaceOpenFailureV0> {
        let file_name = status_path
            .file_name()
            .ok_or(ApplicationStoreNamespaceOpenFailureV0::InvalidPath)?;
        let requested_parent = status_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if mode == ApplicationStoreOwnerModeV0::OrdinaryShared {
            fs::create_dir_all(requested_parent)
                .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::ParentUnavailable)?;
        }
        let canonical_parent = fs::canonicalize(requested_parent)
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::ParentUnavailable)?;
        let parent_handle = open_application_store_parent_v0(&canonical_parent)?;
        let parent_metadata = parent_handle
            .metadata()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::Io)?;
        let parent_path_metadata = canonical_parent
            .symlink_metadata()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::ParentUnavailable)?;
        if !parent_metadata.is_dir()
            || !parent_path_metadata.file_type().is_dir()
            || parent_path_metadata.file_type().is_symlink()
            || ApplicationStoreFileIdentityV0::from_metadata(&parent_metadata)
                != ApplicationStoreFileIdentityV0::from_metadata(&parent_path_metadata)
        {
            return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
        }
        let parent_identity = ApplicationStoreFileIdentityV0::from_metadata(&parent_metadata);
        let parent_uid = parent_metadata.uid();
        if mode == ApplicationStoreOwnerModeV0::RecoveryExclusive {
            validate_application_store_recovery_parent_v0(
                &parent_metadata,
                &parent_path_metadata,
                parent_uid,
            )?;
        }
        let status_path = canonical_parent.join(file_name);
        let database_path = application_store_database_path_v0(&status_path);
        if mode == ApplicationStoreOwnerModeV0::RecoveryExclusive {
            validate_existing_application_store_database_path_v0(&database_path, Some(parent_uid))?;
        }
        let lock_path = application_store_lock_path_v0(&database_path)?;
        let lock_handle = open_application_store_lock_v0(&lock_path, mode)?;
        lock_handle
            .sync_all()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::Io)?;
        parent_handle
            .sync_all()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::Io)?;
        match mode {
            ApplicationStoreOwnerModeV0::OrdinaryShared => {
                FileExt::try_lock_shared(&lock_handle).map_err(classify_owner_lock_error_v0)?;
            }
            ApplicationStoreOwnerModeV0::RecoveryExclusive => {
                FileExt::try_lock_exclusive(&lock_handle).map_err(classify_owner_lock_error_v0)?;
            }
        }
        let lock_metadata =
            validate_application_store_lock_v0(&lock_path, &lock_handle, parent_uid)?;
        let owner = Self {
            owner_pid: std::process::id(),
            mode,
            canonical_parent,
            parent_handle,
            parent_identity,
            parent_uid,
            database_path: database_path.clone(),
            lock_path,
            lock_handle,
            lock_identity: ApplicationStoreFileIdentityV0::from_metadata(&lock_metadata),
            #[cfg(test)]
            test_lock_released: std::sync::atomic::AtomicBool::new(false),
        };
        owner.validate()?;
        Ok((owner, status_path, database_path))
    }

    fn validate(&self) -> std::result::Result<(), ApplicationStoreNamespaceOpenFailureV0> {
        if std::process::id() != self.owner_pid {
            return Err(ApplicationStoreNamespaceOpenFailureV0::ProcessChanged);
        }
        #[cfg(test)]
        if self
            .test_lock_released
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(ApplicationStoreNamespaceOpenFailureV0::Locked);
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
        {
            return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
        }
        if self.mode == ApplicationStoreOwnerModeV0::RecoveryExclusive {
            validate_application_store_recovery_parent_v0(
                &parent_handle_metadata,
                &parent_path_metadata,
                self.parent_uid,
            )?;
            validate_existing_application_store_database_path_v0(
                &self.database_path,
                Some(self.parent_uid),
            )?;
        }
        let lock_metadata = validate_application_store_lock_v0(
            &self.lock_path,
            &self.lock_handle,
            self.parent_uid,
        )?;
        if ApplicationStoreFileIdentityV0::from_metadata(&lock_metadata) != self.lock_identity {
            return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
        }
        Ok(())
    }

    #[cfg(test)]
    fn release_for_recovery_test_v0(
        &self,
    ) -> std::result::Result<(), ApplicationStoreNamespaceOpenFailureV0> {
        if self.mode != ApplicationStoreOwnerModeV0::OrdinaryShared {
            return Err(ApplicationStoreNamespaceOpenFailureV0::Locked);
        }
        if !self
            .test_lock_released
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            FileExt::unlock(&self.lock_handle)
                .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::Io)?;
        }
        Ok(())
    }
}

pub(super) fn application_store_database_path_v0(status_path: &Path) -> PathBuf {
    let extension = status_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.sqlite3"))
        .unwrap_or_else(|| "sqlite3".to_string());
    status_path.with_extension(extension)
}

fn application_store_lock_path_v0(
    database_path: &Path,
) -> std::result::Result<PathBuf, ApplicationStoreNamespaceOpenFailureV0> {
    let mut file_name = database_path
        .file_name()
        .ok_or(ApplicationStoreNamespaceOpenFailureV0::InvalidPath)?
        .to_os_string();
    file_name.push(".owner.lock");
    Ok(database_path.with_file_name(file_name))
}

fn open_application_store_parent_v0(
    canonical_parent: &Path,
) -> std::result::Result<File, ApplicationStoreNamespaceOpenFailureV0> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(canonical_parent)
        .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::ParentUnavailable)
}

fn open_application_store_lock_v0(
    lock_path: &Path,
    mode: ApplicationStoreOwnerModeV0,
) -> std::result::Result<File, ApplicationStoreNamespaceOpenFailureV0> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if mode == ApplicationStoreOwnerModeV0::OrdinaryShared {
        options.create(true).mode(0o600);
    }
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(lock_path)
        .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::Io)?;
    if mode == ApplicationStoreOwnerModeV0::OrdinaryShared {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::Io)?;
    }
    Ok(file)
}

fn classify_owner_lock_error_v0(error: std::io::Error) -> ApplicationStoreNamespaceOpenFailureV0 {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied
    ) {
        ApplicationStoreNamespaceOpenFailureV0::Locked
    } else {
        ApplicationStoreNamespaceOpenFailureV0::Io
    }
}

fn validate_application_store_lock_v0(
    lock_path: &Path,
    lock_handle: &File,
    expected_owner_uid: u32,
) -> std::result::Result<fs::Metadata, ApplicationStoreNamespaceOpenFailureV0> {
    let handle_metadata = lock_handle
        .metadata()
        .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
    let path_metadata = lock_path
        .symlink_metadata()
        .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
    if !handle_metadata.is_file()
        || !path_metadata.file_type().is_file()
        || path_metadata.file_type().is_symlink()
        || handle_metadata.nlink() != 1
        || path_metadata.nlink() != 1
        || handle_metadata.uid() != expected_owner_uid
        || path_metadata.uid() != expected_owner_uid
        || handle_metadata.mode() & 0o077 != 0
        || path_metadata.mode() & 0o077 != 0
        || ApplicationStoreFileIdentityV0::from_metadata(&handle_metadata)
            != ApplicationStoreFileIdentityV0::from_metadata(&path_metadata)
    {
        return Err(ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged);
    }
    Ok(handle_metadata)
}

fn validate_existing_application_store_database_path_v0(
    database_path: &Path,
    expected_owner_uid: Option<u32>,
) -> std::result::Result<fs::Metadata, ApplicationStoreNamespaceOpenFailureV0> {
    let metadata = database_path.symlink_metadata().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ApplicationStoreNamespaceOpenFailureV0::MissingDatabase
        } else {
            ApplicationStoreNamespaceOpenFailureV0::Io
        }
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ApplicationStoreNamespaceOpenFailureV0::DatabaseIsNotRegularFile);
    }
    if metadata.nlink() != 1
        || expected_owner_uid.is_some_and(|uid| metadata.uid() != uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err(ApplicationStoreNamespaceOpenFailureV0::UnsafeNamespace);
    }
    Ok(metadata)
}

fn validate_application_store_recovery_auxiliary_v0(
    database_path: &Path,
    suffix: &str,
    expected_owner_uid: u32,
) -> std::result::Result<(), ApplicationStoreNamespaceOpenFailureV0> {
    let mut auxiliary = database_path.as_os_str().to_os_string();
    auxiliary.push(suffix);
    let auxiliary = PathBuf::from(auxiliary);
    let metadata = match auxiliary.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ApplicationStoreNamespaceOpenFailureV0::Io),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(ApplicationStoreNamespaceOpenFailureV0::UnsafeNamespace);
    }
    Ok(())
}

fn validate_application_store_recovery_parent_v0(
    handle_metadata: &fs::Metadata,
    path_metadata: &fs::Metadata,
    expected_owner_uid: u32,
) -> std::result::Result<(), ApplicationStoreNamespaceOpenFailureV0> {
    if handle_metadata.uid() != expected_owner_uid
        || path_metadata.uid() != expected_owner_uid
        || handle_metadata.mode() & 0o022 != 0
        || path_metadata.mode() & 0o022 != 0
    {
        return Err(ApplicationStoreNamespaceOpenFailureV0::UnsafeNamespace);
    }
    Ok(())
}

pub(super) struct PinnedSnapshot {
    source: Option<Connection>,
    active_snapshot_pins: Arc<AtomicUsize>,
}

/// Opaque, transaction-owned authenticated runtime read snapshot.
///
/// The connection owns the SQLite read transaction directly; no self-
/// referential `Transaction<'_>` is stored. Production can open this snapshot
/// only by consuming the Core-retained exact-parent capability and matching
/// the committed head height/root; the snapshot is still not terminal outcome
/// or persistence authority.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "an authenticated runtime snapshot must be explicitly finished before promoting an execution result"]
pub(super) struct AuthenticatedRuntimeReadSnapshotV0 {
    source: Option<Connection>,
    height: Version,
    root_hash: RootHash,
    active_snapshot_pins: Arc<AtomicUsize>,
    #[cfg(test)]
    fail_finish_for_test_v0: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthenticatedRuntimeExpectedParentV0 {
    height: Version,
    root_hash: RootHash,
}

impl PinnedSnapshot {
    fn source(&self) -> Result<&Connection> {
        self.source
            .as_ref()
            .context("pinned snapshot source was already released")
    }

    fn release(&mut self) -> Result<()> {
        let Some(source) = self.source.take() else {
            return Ok(());
        };
        let rollback = source.execute_batch("ROLLBACK");
        drop(source);
        self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        rollback?;
        Ok(())
    }
}

impl Drop for PinnedSnapshot {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            let _ = source.execute_batch("ROLLBACK");
            drop(source);
            self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl AuthenticatedRuntimeReadSnapshotV0 {
    pub(super) fn load(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StoredObject>, AuthenticatedRuntimeReadFailureV0> {
        let source =
            self.source
                .as_ref()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        load_authenticated_runtime_object_at_v0(source, self.height, self.root_hash, object_key_hex)
    }

    /// Reads the validator lifecycle from this snapshot's already-fixed
    /// parent root and proves that the physical singleton is the same value
    /// committed by the authenticated tree.
    ///
    /// The snapshot itself can now be opened from a Core-issued exact-parent
    /// capability. This method deliberately does not open a second connection
    /// or read a later committed head.
    pub(super) fn load_authenticated_validator_lifecycle_v0(
        &self,
    ) -> std::result::Result<ValidatorLifecycleStateV1, AuthenticatedRuntimeReadFailureV0> {
        let source =
            self.source
                .as_ref()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        load_authenticated_validator_lifecycle_at_v0(source, self.height, self.root_hash)
    }

    /// Loads the complete namespace-8 production projection from this same
    /// already-open transaction and proves every physical leaf against the
    /// snapshot's fixed root. No cache, second connection, version argument,
    /// or independently-read root participates.
    pub(super) fn load_authenticated_production_poco_projection_v0(
        &self,
    ) -> std::result::Result<ProductionPocoProjectionV0, AuthenticatedRuntimeReadFailureV0> {
        let stage = AuthenticatedRuntimeReadStageV0::VerifyPocoProjection;
        let source =
            self.source
                .as_ref()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        load_production_poco_projection_from_connection_v0(source, self.height, self.root_hash)
            .map_err(|error| {
                classify_authenticated_read_anyhow_v0(
                    stage,
                    &error,
                    "authenticated parent PoCO projection failed exact verification",
                )
            })?
            .ok_or(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage,
                    sqlite: None,
                    reason: "authenticated parent lacks the active PoCO configuration namespace",
                },
            )
    }

    /// Plans the exact next authenticated state on this snapshot's existing
    /// SQLite connection and read transaction.
    ///
    /// The snapshot itself already owns the Core-authenticated exact-parent
    /// authority used to open this connection. No target version or expected
    /// root is caller supplied here. The only legal target is the fixed parent
    /// version plus one, and the complete persisted state is revalidated before
    /// the JMT planner reads from this same transaction. The returned plan is
    /// inert and is never applied or persisted by this method.
    pub(super) fn plan_exact_next_auth_update_v0(
        &self,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> std::result::Result<PlannedAuthUpdate, AuthenticatedRuntimeReadFailureV0> {
        let stage = AuthenticatedRuntimeReadStageV0::PlanPostState;
        let source =
            self.source
                .as_ref()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        let target_version =
            self.height
                .checked_add(1)
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage,
                    sqlite: None,
                    reason: "authenticated parent height cannot advance",
                })?;
        let state = load_sqlite_state(source).map_err(|error| {
            classify_authenticated_read_anyhow_v0(
                stage,
                &error,
                "complete authenticated parent state failed post-state planning validation",
            )
        })?;
        if state.height != self.height || RootHash(state.app_hash) != self.root_hash {
            return Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage,
                    sqlite: None,
                    reason: "post-state planner parent differs from the fixed runtime snapshot",
                },
            );
        }
        let reader = SqliteAuthReader { connection: source };
        // `plan_put_value_set` takes `(expected_next_version, version)`. Both
        // are the unique target derived above; the retained parent version is
        // represented by the reader's fixed SQLite snapshot, not either
        // numeric argument.
        let plan = plan_put_value_set(&reader, target_version, target_version, writes).map_err(
            |error| {
                classify_authenticated_read_anyhow_v0(
                    stage,
                    &error,
                    "authenticated post-state JMT planning failed",
                )
            },
        )?;
        if plan.version != target_version {
            return Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage,
                sqlite: None,
                reason: "authenticated post-state planner returned a foreign target version",
            });
        }
        Ok(plan)
    }

    pub(super) fn finish(mut self) -> std::result::Result<(), AuthenticatedRuntimeReadFailureV0> {
        let source =
            self.source
                .take()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        let rollback = source.execute_batch("ROLLBACK").map_err(|error| {
            classify_sqlite_authenticated_read_failure_v0(
                AuthenticatedRuntimeReadStageV0::EndSnapshot,
                &error,
            )
        });
        drop(source);
        self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        #[cfg(test)]
        if self.fail_finish_for_test_v0 && rollback.is_ok() {
            return Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
                sqlite: None,
                reason: "injected authenticated runtime snapshot finish failure",
            });
        }
        rollback
    }

    /// Test-only failure injection after the real rollback has released the
    /// SQLite snapshot and pin. This proves callers cannot promote an inert
    /// traversal when the explicit finish boundary reports failure.
    #[cfg(test)]
    pub(super) fn inject_finish_failure_for_test_v0(&mut self) {
        self.fail_finish_for_test_v0 = true;
    }
}

impl Drop for AuthenticatedRuntimeReadSnapshotV0 {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            let _ = source.execute_batch("ROLLBACK");
            drop(source);
            self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PruneBatchOutcome {
    pub(super) stats: PruneStats,
    pub(super) query_floor: Version,
    pub(super) target: Version,
    pub(super) complete: bool,
    pub(super) rows_examined: usize,
    pub(super) logical_bytes_examined: u64,
    pub(super) elapsed: Duration,
}

#[cfg(any(test, feature = "scale-gate"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AuthPruneStatus {
    pub(super) query_floor: Version,
    pub(super) target: Option<Version>,
}

#[derive(Serialize)]
struct PersistedStatusV2 {
    schema: &'static str,
    app_version: u64,
    height: u64,
    app_hash_hex: String,
}

struct SqliteAuthReader<'a> {
    connection: &'a Connection,
}

impl TreeReader for SqliteAuthReader<'_> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let encoded_key = borsh::to_vec(node_key).context("encode JMT node key")?;
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT node FROM auth_nodes WHERE node_key=?1",
                params![encoded_key],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|bytes| borsh::from_slice(&bytes).context("decode persisted JMT node"))
            .transpose()
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        let row: Option<(Option<Vec<u8>>, i64)> = self
            .connection
            .query_row(
                "SELECT value, is_deleted
                 FROM auth_values
                 WHERE key_hash=?1 AND version_be<=?2
                 ORDER BY version_be DESC
                 LIMIT 1",
                params![key_hash.0.as_slice(), max_version.to_be_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            None | Some((None, 1)) => Ok(None),
            Some((Some(value), 0)) => Ok(Some(value)),
            Some(_) => Err(anyhow!("persisted JMT value tombstone mismatch")),
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut statement = self
            .connection
            .prepare("SELECT node_key, node FROM auth_nodes")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut rightmost: Option<(NodeKey, LeafNode)> = None;
        for row in rows {
            let (node_key, node) = row?;
            let node_key: NodeKey =
                borsh::from_slice(&node_key).context("decode persisted JMT node key")?;
            let node: Node = borsh::from_slice(&node).context("decode persisted JMT node")?;
            let Node::Leaf(leaf) = node else {
                continue;
            };
            if rightmost.as_ref().is_none_or(|(best_key, best_leaf)| {
                (leaf.key_hash(), node_key.version()) > (best_leaf.key_hash(), best_key.version())
            }) {
                rightmost = Some((node_key, leaf));
            }
        }
        Ok(rightmost)
    }
}

impl HasPreimage for SqliteAuthReader<'_> {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .connection
            .query_row(
                "SELECT key_preimage FROM auth_preimages WHERE key_hash=?1",
                params![key_hash.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?)
    }
}

impl ApplicationStore {
    fn require_namespace_owner_v0(&self) -> Result<()> {
        self.validate_namespace_owner_v0()
            .map_err(|failure| anyhow!(failure))
    }

    fn require_native_validation_namespace_owner_v0(
        &self,
        stage: NativeValidationReservationStageV0,
    ) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
        self.validate_namespace_owner_v0().map_err(|_| {
            NativeValidationReservationFailureCauseV0::HostInvariant {
                stage,
                sqlite: None,
            }
        })
    }

    fn lock_writer(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.writer_waiters.fetch_add(1, Ordering::AcqRel);
        let locked = self.writer_gate.lock();
        self.writer_waiters.fetch_sub(1, Ordering::AcqRel);
        locked.map_err(|_| anyhow!("application store writer gate poisoned"))
    }

    /// Durably reserves or checksum-verifies one Core-issued native
    /// payload-validation job.
    ///
    /// The complete identity is globally unique in this SQLite store even
    /// though route is also part of the primary key. An exactly congruent row
    /// coalesces before the capacity check; any reuse of the full identity with
    /// different route, raw request record, parent, configuration reference,
    /// target height, or fingerprint is fail-stop. An exact reopen returns the
    /// durable state for recovery routing; it never remints the unique first
    /// evaluation token. This method does not evaluate the block or create
    /// terminal/callback authority.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn reserve_or_reopen_native_validation_job_v0(
        &self,
        facts: NativeValidationReservationFactsV0,
    ) -> std::result::Result<
        NativeValidationReservationDecisionV0,
        Box<FailedNativeValidationReservationV0>,
    > {
        let route = facts.route;
        let validation_id = facts.validation_id;
        let request_fingerprint = facts.request_fingerprint;
        let immutable_checksum = native_validation_job_immutable_checksum_v0(
            &facts,
            &native_validation_runtime_profile_ref_v0(facts.protocol_version),
            &native_validation_host_config_ref_v0(self),
        );
        match self.reserve_or_reopen_native_validation_job_inner_v0(&facts) {
            Ok(NativeValidationReservationInnerDecisionV0::Reserved) => {
                Ok(NativeValidationReservationDecisionV0::Reserved(
                    NativeValidationReservationTokenV0 {
                        route,
                        validation_id,
                        request_fingerprint,
                        immutable_checksum,
                        issuing_writer_gate: Arc::clone(&self.writer_gate),
                    },
                ))
            }
            Ok(
                NativeValidationReservationInnerDecisionV0::Existing(existing)
                | NativeValidationReservationInnerDecisionV0::CommitUncertainExisting(existing),
            ) => Ok(NativeValidationReservationDecisionV0::Existing(Box::new(
                existing,
            ))),
            Err(cause) => Err(Box::new(FailedNativeValidationReservationV0 {
                facts,
                cause,
            })),
        }
    }

    /// Atomically consumes one owning deterministic-invalid preparation into
    /// the v7-compatible callback-pending state of the active v8 journal. No
    /// Core callback is invoked here.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn seal_durable_invalid_and_enqueue_callback_v0(
        &self,
        prepared: PreparedDurableInvalidV0,
    ) -> std::result::Result<
        NativeValidationInvalidSealDecisionV0,
        Box<FailedNativeValidationInvalidSealV0>,
    > {
        self.seal_durable_invalid_and_enqueue_callback_with_failpoint_v0(prepared, None)
    }

    #[cfg(test)]
    pub(super) fn seal_durable_invalid_and_enqueue_callback_with_test_failpoint_v0(
        &self,
        prepared: PreparedDurableInvalidV0,
        failpoint: NativeValidationInvalidSealFailpointV0,
    ) -> std::result::Result<
        NativeValidationInvalidSealDecisionV0,
        Box<FailedNativeValidationInvalidSealV0>,
    > {
        self.seal_durable_invalid_and_enqueue_callback_with_failpoint_v0(prepared, Some(failpoint))
    }

    fn seal_durable_invalid_and_enqueue_callback_with_failpoint_v0(
        &self,
        prepared: PreparedDurableInvalidV0,
        failpoint: Option<NativeValidationInvalidSealFailpointV0>,
    ) -> std::result::Result<
        NativeValidationInvalidSealDecisionV0,
        Box<FailedNativeValidationInvalidSealV0>,
    > {
        match self.seal_durable_invalid_and_enqueue_callback_inner_v0(&prepared, failpoint) {
            Ok(NativeValidationInvalidSealInnerDecisionV0::CallbackPending(verified)) => {
                Ok(NativeValidationInvalidSealDecisionV0::CallbackPending(
                    Box::new(LiveNativeValidationInvalidCallbackV0 {
                        prepared,
                        verified,
                        disposition: NativeValidationInvalidSealDispositionV0::NewlyCommitted,
                    }),
                ))
            }
            Ok(NativeValidationInvalidSealInnerDecisionV0::Existing(verified)) => {
                Ok(NativeValidationInvalidSealDecisionV0::Existing(Box::new(
                    LiveNativeValidationInvalidCallbackV0 {
                        prepared,
                        verified,
                        disposition: NativeValidationInvalidSealDispositionV0::ExactExisting,
                    },
                )))
            }
            Ok(NativeValidationInvalidSealInnerDecisionV0::CommitUncertainExisting(verified)) => {
                Ok(NativeValidationInvalidSealDecisionV0::Existing(Box::new(
                    LiveNativeValidationInvalidCallbackV0 {
                        prepared,
                        verified,
                        disposition:
                            NativeValidationInvalidSealDispositionV0::CommitConfirmedExisting,
                    },
                )))
            }
            Err(cause) => Err(Box::new(FailedNativeValidationInvalidSealV0 {
                prepared,
                cause,
            })),
        }
    }

    fn seal_durable_invalid_and_enqueue_callback_inner_v0(
        &self,
        prepared: &PreparedDurableInvalidV0,
        failpoint: Option<NativeValidationInvalidSealFailpointV0>,
    ) -> std::result::Result<
        NativeValidationInvalidSealInnerDecisionV0,
        NativeValidationInvalidSealFailureCauseV0,
    > {
        if !prepared.is_bound_to_store_v0(self) {
            return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::IssuingStoreMismatch,
            ));
        }
        self.writer_waiters.fetch_add(1, Ordering::AcqRel);
        let writer = self.writer_gate.lock();
        self.writer_waiters.fetch_sub(1, Ordering::AcqRel);
        let _writer =
            writer.map_err(
                |_| NativeValidationInvalidSealFailureCauseV0::HostInvariant {
                    stage: NativeValidationReservationStageV0::LockWriter,
                },
            )?;
        let mut connection = self
            .connect_native_validation_job_v0()
            .map_err(native_validation_invalid_seal_failure_v0)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                native_validation_invalid_seal_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::BeginTransaction,
                        &error,
                    ),
                )
            })?;
        validate_native_validation_job_bindings_v0(&transaction, self)
            .map_err(native_validation_invalid_seal_failure_v0)?;
        let accounting = read_bounded_native_validation_journal_accounting_v0(
            &transaction,
            NativeValidationReservationStageV0::ReadCapacity,
        )
        .map_err(native_validation_invalid_seal_failure_v0)?;
        let existing = load_native_validation_job_v0(&transaction, prepared.validation_id())
            .map_err(native_validation_invalid_seal_failure_v0)?
            .ok_or(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            ))?;
        let existing = durable_native_validation_job_from_existing_v0(existing, self)
            .map_err(NativeValidationInvalidSealFailureCauseV0::Invariant)?;
        let verified_outbox = revalidate_native_validation_job_outbox_v0(
            &transaction,
            &existing,
            NativeValidationReservationStageV0::ReadExisting,
        )
        .map_err(native_validation_invalid_seal_failure_v0)?;
        if existing.route() != prepared.route()
            || existing.validation_id() != prepared.validation_id()
            || existing.request_fingerprint() != prepared.request_fingerprint()
            || existing.immutable_checksum() != prepared.immutable_checksum()
        {
            return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::RouteMismatch,
            ));
        }
        if existing.state == NativeValidationJobStateV0::CallbackPending {
            if native_validation_job_invalid_reason_v0(&existing) != Some(prepared.reason()) {
                return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ));
            }
            transaction.commit().map_err(|error| {
                native_validation_invalid_seal_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Commit,
                        &error,
                    ),
                )
            })?;
            return Ok(NativeValidationInvalidSealInnerDecisionV0::Existing(
                VerifiedNativeValidationInvalidCallbackV0::new_v0(
                    existing,
                    verified_outbox.ok_or(NativeValidationInvalidSealFailureCauseV0::Invariant(
                        NativeValidationReservationInvariantV0::StateMismatch,
                    ))?,
                ),
            ));
        }
        if verified_outbox.is_some() {
            return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::StateMismatch,
            ));
        }
        if existing.state != NativeValidationJobStateV0::Reserved {
            return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::StateMismatch,
            ));
        }

        let identity = native_validation_artifact_identity_v0(&existing);
        let artifact = prepare_durable_invalid_artifact_v0(identity, prepared.reason());
        let callback = prepare_durable_invalid_callback_v0(&artifact);
        let artifact_bytes = u64::try_from(artifact.encoded().len()).map_err(|_| {
            NativeValidationInvalidSealFailureCauseV0::ArtifactByteCapacity {
                maximum: MAX_NATIVE_VALIDATION_ARTIFACT_JOURNAL_BYTES,
            }
        })?;
        let callback_bytes = u64::try_from(callback.payload().len()).map_err(|_| {
            NativeValidationInvalidSealFailureCauseV0::CallbackByteCapacity {
                maximum: MAX_NATIVE_VALIDATION_CALLBACK_OUTBOX_BYTES,
            }
        })?;
        let next_artifact_bytes = accounting
            .artifact_bytes
            .checked_add(artifact_bytes)
            .filter(|total| *total <= MAX_NATIVE_VALIDATION_ARTIFACT_JOURNAL_BYTES)
            .ok_or(
                NativeValidationInvalidSealFailureCauseV0::ArtifactByteCapacity {
                    maximum: MAX_NATIVE_VALIDATION_ARTIFACT_JOURNAL_BYTES,
                },
            )?;
        let next_outbox_count = accounting
            .outbox_count
            .checked_add(1)
            .filter(|count| {
                *count <= accounting.job_count && *count <= MAX_NATIVE_VALIDATION_RESERVATIONS
            })
            .ok_or(
                NativeValidationInvalidSealFailureCauseV0::CallbackByteCapacity {
                    maximum: MAX_NATIVE_VALIDATION_RESERVATIONS,
                },
            )?;
        let next_outbox_bytes = accounting
            .outbox_bytes
            .checked_add(callback_bytes)
            .filter(|total| *total <= MAX_NATIVE_VALIDATION_CALLBACK_OUTBOX_BYTES)
            .ok_or(
                NativeValidationInvalidSealFailureCauseV0::CallbackByteCapacity {
                    maximum: MAX_NATIVE_VALIDATION_CALLBACK_OUTBOX_BYTES,
                },
            )?;
        let result_kind = i64::from(durable_deterministic_invalid_result_kind_v0());
        let reason_be = prepared.reason().code_v0().to_be_bytes();
        let row_checksum = native_validation_job_row_checksum_v0(
            &existing.immutable_checksum,
            NativeValidationJobStateV0::CallbackPending,
            Some(result_kind),
            Some(&reason_be),
            Some(artifact.artifact_codec()),
            Some(&artifact.checksum()),
            None,
            None,
        );
        transaction
            .execute(
                "INSERT INTO validation_callback_outbox_v0(
                     route, block_id, view_be, generation_be, result_kind,
                     artifact_checksum, payload_codec, payload_bytes,
                     payload_checksum, idempotency_key, delivery_attempt_be,
                     outbox_checksum
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    native_validation_route_code_v0(prepared.route()),
                    prepared.validation_id().block_id().as_bytes().as_slice(),
                    prepared
                        .validation_id()
                        .view()
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                    prepared
                        .validation_id()
                        .generation()
                        .to_be_bytes()
                        .as_slice(),
                    result_kind,
                    callback.artifact_checksum().as_slice(),
                    callback.payload_codec(),
                    callback.payload().as_slice(),
                    callback.payload_checksum().as_slice(),
                    callback.idempotency_key().as_slice(),
                    callback.delivery_attempt().to_be_bytes().as_slice(),
                    callback.outbox_checksum().as_slice(),
                ],
            )
            .map_err(|error| {
                native_validation_invalid_seal_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Insert,
                        &error,
                    ),
                )
            })?;
        if failpoint == Some(NativeValidationInvalidSealFailpointV0::AfterOutboxInsert) {
            return Err(NativeValidationInvalidSealFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::Insert,
            });
        }
        let updated = transaction
            .execute(
                "UPDATE validation_jobs_v0
                 SET state=2, result_kind=?1, invalid_reason_code_be=?2,
                     artifact_codec=?3, artifact_bytes=?4, artifact_checksum=?5,
                     row_checksum=?6
                 WHERE route=?7 AND block_id=?8 AND view_be=?9 AND generation_be=?10
                   AND state=0 AND row_checksum=?11",
                params![
                    result_kind,
                    reason_be.as_slice(),
                    artifact.artifact_codec(),
                    artifact.encoded().as_slice(),
                    artifact.checksum().as_slice(),
                    row_checksum.as_slice(),
                    native_validation_route_code_v0(prepared.route()),
                    prepared.validation_id().block_id().as_bytes().as_slice(),
                    prepared
                        .validation_id()
                        .view()
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                    prepared
                        .validation_id()
                        .generation()
                        .to_be_bytes()
                        .as_slice(),
                    existing.row_checksum.as_slice(),
                ],
            )
            .map_err(|error| {
                native_validation_invalid_seal_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Insert,
                        &error,
                    ),
                )
            })?;
        if updated != 1 {
            return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::StateMismatch,
            ));
        }
        if failpoint == Some(NativeValidationInvalidSealFailpointV0::AfterJobUpdate) {
            return Err(NativeValidationInvalidSealFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::Insert,
            });
        }
        let accounting_updated = transaction
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET artifact_bytes_be=?1, outbox_count_be=?2, outbox_bytes_be=?3
                 WHERE singleton=1 AND artifact_bytes_be=?4
                   AND outbox_count_be=?5 AND outbox_bytes_be=?6",
                params![
                    next_artifact_bytes.to_be_bytes().as_slice(),
                    next_outbox_count.to_be_bytes().as_slice(),
                    next_outbox_bytes.to_be_bytes().as_slice(),
                    accounting.artifact_bytes.to_be_bytes().as_slice(),
                    accounting.outbox_count.to_be_bytes().as_slice(),
                    accounting.outbox_bytes.to_be_bytes().as_slice(),
                ],
            )
            .map_err(|error| {
                native_validation_invalid_seal_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Insert,
                        &error,
                    ),
                )
            })?;
        if accounting_updated != 1 {
            return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
            ));
        }
        if failpoint == Some(NativeValidationInvalidSealFailpointV0::AfterAccountingUpdate) {
            return Err(NativeValidationInvalidSealFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::Insert,
            });
        }
        let sealed = load_native_validation_job_v0(&transaction, prepared.validation_id())
            .map_err(native_validation_invalid_seal_failure_v0)?
            .ok_or(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            ))?;
        let sealed = durable_native_validation_job_from_existing_v0(sealed, self)
            .map_err(NativeValidationInvalidSealFailureCauseV0::Invariant)?;
        let verified_outbox = revalidate_native_validation_job_outbox_v0(
            &transaction,
            &sealed,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(native_validation_invalid_seal_failure_v0)?;
        if sealed.state != NativeValidationJobStateV0::CallbackPending
            || native_validation_job_invalid_reason_v0(&sealed) != Some(prepared.reason())
        {
            return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            ));
        }
        let sealed = VerifiedNativeValidationInvalidCallbackV0::new_v0(
            sealed,
            verified_outbox.ok_or(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            ))?,
        );
        if failpoint == Some(NativeValidationInvalidSealFailpointV0::BeforeCommit) {
            return Err(NativeValidationInvalidSealFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::Commit,
            });
        }
        if let Err(error) = transaction.commit() {
            return match self.confirm_durable_invalid_callback_v0(prepared) {
                Ok(NativeValidationInvalidCommitReadbackV0::CallbackPending(job)) => {
                    Ok(NativeValidationInvalidSealInnerDecisionV0::CommitUncertainExisting(*job))
                }
                Ok(NativeValidationInvalidCommitReadbackV0::Reserved) => {
                    Err(native_validation_invalid_seal_failure_v0(
                        classify_native_validation_reservation_sqlite_failure_v0(
                            NativeValidationReservationStageV0::Commit,
                            &error,
                        ),
                    ))
                }
                Err(NativeValidationInvalidSealFailureCauseV0::Invariant(kind)) => {
                    Err(NativeValidationInvalidSealFailureCauseV0::Invariant(kind))
                }
                Err(NativeValidationInvalidSealFailureCauseV0::HostInvariant { stage }) => {
                    Err(NativeValidationInvalidSealFailureCauseV0::HostInvariant { stage })
                }
                Err(_) => Err(native_validation_invalid_seal_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Commit,
                        &error,
                    ),
                )),
            };
        }
        #[cfg(test)]
        if failpoint == Some(NativeValidationInvalidSealFailpointV0::AfterCommitBeforeReturn) {
            return Err(NativeValidationInvalidSealFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::ConfirmCommit,
            });
        }
        Ok(NativeValidationInvalidSealInnerDecisionV0::CallbackPending(
            sealed,
        ))
    }

    fn confirm_durable_invalid_callback_v0(
        &self,
        prepared: &PreparedDurableInvalidV0,
    ) -> std::result::Result<
        NativeValidationInvalidCommitReadbackV0,
        NativeValidationInvalidSealFailureCauseV0,
    > {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| {
            native_validation_invalid_seal_failure_v0(
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfirmCommit,
                    &error,
                ),
            )
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| {
                native_validation_invalid_seal_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::ConfirmCommit,
                        &error,
                    ),
                )
            })?;
        validate_native_validation_job_bindings_v0(&connection, self)
            .map_err(native_validation_invalid_seal_failure_v0)?;
        let job = load_native_validation_job_v0(&connection, prepared.validation_id())
            .map_err(native_validation_invalid_seal_failure_v0)?
            .ok_or(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            ))?;
        let job = durable_native_validation_job_from_existing_v0(job, self)
            .map_err(NativeValidationInvalidSealFailureCauseV0::Invariant)?;
        let verified_outbox = revalidate_native_validation_job_outbox_v0(
            &connection,
            &job,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(native_validation_invalid_seal_failure_v0)?;
        if job.route() != prepared.route()
            || job.validation_id() != prepared.validation_id()
            || job.request_fingerprint() != prepared.request_fingerprint()
            || job.immutable_checksum() != prepared.immutable_checksum()
        {
            return Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            ));
        }
        match job.state {
            NativeValidationJobStateV0::Reserved => {
                Ok(NativeValidationInvalidCommitReadbackV0::Reserved)
            }
            NativeValidationJobStateV0::CallbackPending
                if native_validation_job_invalid_reason_v0(&job) == Some(prepared.reason()) =>
            {
                Ok(NativeValidationInvalidCommitReadbackV0::CallbackPending(
                    Box::new(VerifiedNativeValidationInvalidCallbackV0::new_v0(
                        job,
                        verified_outbox.ok_or(
                            NativeValidationInvalidSealFailureCauseV0::Invariant(
                                NativeValidationReservationInvariantV0::CommitReadbackConflict,
                            ),
                        )?,
                    )),
                ))
            }
            _ => Err(NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            )),
        }
    }

    /// Atomically records that the exact live callback was accepted by the
    /// current Core instance. The outbox remains durable and its attempt is
    /// advanced exactly once; journal byte accounting is unchanged.
    #[cfg_attr(not(test), allow(dead_code))]
    fn mark_native_validation_invalid_callback_delivered_v0(
        &self,
        owner: Box<LiveNativeValidationInvalidCallbackV0>,
    ) -> std::result::Result<
        Box<DeliveredNativeValidationInvalidCallbackV0>,
        Box<FailedNativeValidationInvalidDeliveryV0>,
    > {
        match self.mark_native_validation_invalid_callback_delivered_inner_v0(&owner) {
            Ok(
                NativeValidationInvalidDeliveryInnerDecisionV0::Delivered(verified)
                | NativeValidationInvalidDeliveryInnerDecisionV0::CommitUncertainDelivered(verified),
            ) => {
                let LiveNativeValidationInvalidCallbackV0 { prepared, .. } = *owner;
                Ok(Box::new(DeliveredNativeValidationInvalidCallbackV0 {
                    prepared,
                    verified,
                }))
            }
            Err(cause) => Err(Box::new(FailedNativeValidationInvalidDeliveryV0 {
                owner,
                cause,
            })),
        }
    }

    fn mark_native_validation_invalid_callback_delivered_inner_v0(
        &self,
        owner: &LiveNativeValidationInvalidCallbackV0,
    ) -> std::result::Result<
        NativeValidationInvalidDeliveryInnerDecisionV0,
        NativeValidationInvalidJournalTransitionFailureCauseV0,
    > {
        if !owner.is_bound_to_store_v0(self) {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::IssuingStoreMismatch,
                ),
            );
        }
        self.writer_waiters.fetch_add(1, Ordering::AcqRel);
        let writer = self.writer_gate.lock();
        self.writer_waiters.fetch_sub(1, Ordering::AcqRel);
        let _writer = writer.map_err(|_| {
            NativeValidationInvalidJournalTransitionFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::LockWriter,
            }
        })?;
        let mut connection = self
            .connect_native_validation_job_v0()
            .map_err(native_validation_invalid_transition_failure_v0)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::BeginTransaction,
                        &error,
                    ),
                )
            })?;
        validate_native_validation_job_bindings_v0(&transaction, self)
            .map_err(native_validation_invalid_transition_failure_v0)?;
        read_bounded_native_validation_journal_accounting_v0(
            &transaction,
            NativeValidationReservationStageV0::ReadCapacity,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?;
        let existing = load_native_validation_job_v0(&transaction, owner.validation_id())
            .map_err(native_validation_invalid_transition_failure_v0)?
            .ok_or(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            )?;
        let existing = durable_native_validation_job_from_existing_v0(existing, self)
            .map_err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant)?;
        let existing_outbox = revalidate_native_validation_job_outbox_v0(
            &transaction,
            &existing,
            NativeValidationReservationStageV0::ReadExisting,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?
        .ok_or(
            NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::StateMismatch,
            ),
        )?;
        let existing = VerifiedNativeValidationInvalidCallbackV0::new_v0(existing, existing_outbox);
        if !native_validation_invalid_callback_lineage_matches_v0(&existing, owner) {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::RouteMismatch,
                ),
            );
        }
        if existing.job.state == NativeValidationJobStateV0::Delivered {
            if existing.delivery_attempt
                != owner.delivery_attempt().checked_add(1).ok_or(
                    NativeValidationInvalidJournalTransitionFailureCauseV0::DeliveryAttemptOverflow,
                )?
            {
                return Err(
                    NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                        NativeValidationReservationInvariantV0::StateMismatch,
                    ),
                );
            }
            transaction.commit().map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Commit,
                        &error,
                    ),
                )
            })?;
            return Ok(NativeValidationInvalidDeliveryInnerDecisionV0::Delivered(
                existing,
            ));
        }
        if existing.job.state != NativeValidationJobStateV0::CallbackPending
            || existing.delivery_attempt() != owner.delivery_attempt()
        {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ),
            );
        }
        let next_attempt = existing.delivery_attempt().checked_add(1).ok_or(
            NativeValidationInvalidJournalTransitionFailureCauseV0::DeliveryAttemptOverflow,
        )?;
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
            .map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Insert,
                        &error,
                    ),
                )
            })?;
        if outbox_updated != 1 {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ),
            );
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
            .map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Insert,
                        &error,
                    ),
                )
            })?;
        if job_updated != 1 {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ),
            );
        }
        let delivered = load_native_validation_job_v0(&transaction, owner.validation_id())
            .map_err(native_validation_invalid_transition_failure_v0)?
            .ok_or(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            )?;
        let delivered = durable_native_validation_job_from_existing_v0(delivered, self)
            .map_err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant)?;
        let delivered_outbox = revalidate_native_validation_job_outbox_v0(
            &transaction,
            &delivered,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?
        .ok_or(
            NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            ),
        )?;
        let delivered =
            VerifiedNativeValidationInvalidCallbackV0::new_v0(delivered, delivered_outbox);
        if delivered.job.state != NativeValidationJobStateV0::Delivered
            || delivered.delivery_attempt() != next_attempt
            || !native_validation_invalid_callback_lineage_matches_v0(&delivered, owner)
        {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            );
        }
        if let Err(error) = transaction.commit() {
            return match self.confirm_native_validation_invalid_delivery_v0(owner) {
                Ok(NativeValidationInvalidDeliveryCommitReadbackV0::Delivered(verified)) => Ok(
                    NativeValidationInvalidDeliveryInnerDecisionV0::CommitUncertainDelivered(
                        *verified,
                    ),
                ),
                Ok(NativeValidationInvalidDeliveryCommitReadbackV0::CallbackPending) => {
                    Err(native_validation_invalid_transition_failure_v0(
                        classify_native_validation_reservation_sqlite_failure_v0(
                            NativeValidationReservationStageV0::Commit,
                            &error,
                        ),
                    ))
                }
                Err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(kind)) => {
                    Err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(kind))
                }
                Err(NativeValidationInvalidJournalTransitionFailureCauseV0::HostInvariant {
                    stage,
                }) => Err(
                    NativeValidationInvalidJournalTransitionFailureCauseV0::HostInvariant { stage },
                ),
                Err(_) => Err(native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Commit,
                        &error,
                    ),
                )),
            };
        }
        Ok(NativeValidationInvalidDeliveryInnerDecisionV0::Delivered(
            delivered,
        ))
    }

    fn confirm_native_validation_invalid_delivery_v0(
        &self,
        owner: &LiveNativeValidationInvalidCallbackV0,
    ) -> std::result::Result<
        NativeValidationInvalidDeliveryCommitReadbackV0,
        NativeValidationInvalidJournalTransitionFailureCauseV0,
    > {
        let connection = self
            .open_native_validation_confirmation_connection_v0()
            .map_err(native_validation_invalid_transition_failure_v0)?;
        read_bounded_native_validation_journal_accounting_v0(
            &connection,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?;
        let job = load_native_validation_job_v0(&connection, owner.validation_id())
            .map_err(native_validation_invalid_transition_failure_v0)?
            .ok_or(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            )?;
        let job = durable_native_validation_job_from_existing_v0(job, self)
            .map_err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant)?;
        let outbox = revalidate_native_validation_job_outbox_v0(
            &connection,
            &job,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?
        .ok_or(
            NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::CommitReadbackConflict,
            ),
        )?;
        let verified = VerifiedNativeValidationInvalidCallbackV0::new_v0(job, outbox);
        if !native_validation_invalid_callback_lineage_matches_v0(&verified, owner) {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            );
        }
        match verified.job.state {
            NativeValidationJobStateV0::CallbackPending
                if verified.delivery_attempt() == owner.delivery_attempt() =>
            {
                Ok(NativeValidationInvalidDeliveryCommitReadbackV0::CallbackPending)
            }
            NativeValidationJobStateV0::Delivered
                if verified.delivery_attempt()
                    == owner.delivery_attempt().checked_add(1).ok_or(
                        NativeValidationInvalidJournalTransitionFailureCauseV0::DeliveryAttemptOverflow,
                    )? =>
            {
                Ok(NativeValidationInvalidDeliveryCommitReadbackV0::Delivered(
                    Box::new(verified),
                ))
            }
            _ => Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            ),
        }
    }

    /// Atomically retires the delivered outbox after the callback driver has
    /// confirmed exact Core safety-state persistence.
    #[cfg_attr(not(test), allow(dead_code))]
    fn acknowledge_native_validation_invalid_callback_v0(
        &self,
        owner: Box<ConfirmedCoreInvalidCompletionV0>,
    ) -> std::result::Result<
        Box<AckedNativeValidationInvalidCallbackV0>,
        Box<FailedNativeValidationInvalidAcknowledgementV0>,
    > {
        match self.acknowledge_native_validation_invalid_callback_inner_v0(&owner) {
            Ok(
                NativeValidationInvalidAcknowledgementInnerDecisionV0::Acked(durable)
                | NativeValidationInvalidAcknowledgementInnerDecisionV0::CommitUncertainAcked(
                    durable,
                ),
            ) => {
                let ConfirmedCoreInvalidCompletionV0 {
                    delivered,
                    accepted_core_revision,
                } = *owner;
                let DeliveredNativeValidationInvalidCallbackV0 { prepared, verified } = *delivered;
                Ok(Box::new(AckedNativeValidationInvalidCallbackV0 {
                    prepared,
                    durable: Box::new(durable),
                    accepted_core_revision,
                    callback_payload_checksum: verified.callback_payload_checksum(),
                }))
            }
            Err(cause) => Err(Box::new(FailedNativeValidationInvalidAcknowledgementV0 {
                owner,
                cause,
            })),
        }
    }

    fn acknowledge_native_validation_invalid_callback_inner_v0(
        &self,
        owner: &ConfirmedCoreInvalidCompletionV0,
    ) -> std::result::Result<
        NativeValidationInvalidAcknowledgementInnerDecisionV0,
        NativeValidationInvalidJournalTransitionFailureCauseV0,
    > {
        let delivered_owner = &owner.delivered;
        if !delivered_owner.is_bound_to_store_v0(self) {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::IssuingStoreMismatch,
                ),
            );
        }
        self.writer_waiters.fetch_add(1, Ordering::AcqRel);
        let writer = self.writer_gate.lock();
        self.writer_waiters.fetch_sub(1, Ordering::AcqRel);
        let _writer = writer.map_err(|_| {
            NativeValidationInvalidJournalTransitionFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::LockWriter,
            }
        })?;
        let mut connection = self
            .connect_native_validation_job_v0()
            .map_err(native_validation_invalid_transition_failure_v0)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::BeginTransaction,
                        &error,
                    ),
                )
            })?;
        validate_native_validation_job_bindings_v0(&transaction, self)
            .map_err(native_validation_invalid_transition_failure_v0)?;
        let accounting = read_bounded_native_validation_journal_accounting_v0(
            &transaction,
            NativeValidationReservationStageV0::ReadCapacity,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?;
        let existing = load_native_validation_job_v0(&transaction, owner.validation_id())
            .map_err(native_validation_invalid_transition_failure_v0)?
            .ok_or(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            )?;
        let existing = durable_native_validation_job_from_existing_v0(existing, self)
            .map_err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant)?;
        if existing.state == NativeValidationJobStateV0::Acked {
            verify_native_validation_job_outbox_v0(
                &transaction,
                &existing,
                NativeValidationReservationStageV0::ReadExisting,
            )
            .map_err(native_validation_invalid_transition_failure_v0)?;
            if !native_validation_invalid_acked_job_matches_confirmation_v0(&existing, owner) {
                return Err(
                    NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                        NativeValidationReservationInvariantV0::StateMismatch,
                    ),
                );
            }
            transaction.commit().map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Commit,
                        &error,
                    ),
                )
            })?;
            return Ok(NativeValidationInvalidAcknowledgementInnerDecisionV0::Acked(existing));
        }
        let existing_outbox = revalidate_native_validation_job_outbox_v0(
            &transaction,
            &existing,
            NativeValidationReservationStageV0::ReadExisting,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?
        .ok_or(
            NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::StateMismatch,
            ),
        )?;
        let existing = VerifiedNativeValidationInvalidCallbackV0::new_v0(existing, existing_outbox);
        if existing.job.state != NativeValidationJobStateV0::Delivered
            || !native_validation_invalid_delivered_lineage_matches_v0(&existing, delivered_owner)
        {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ),
            );
        }
        let callback_bytes = u64::try_from(DURABLE_INVALID_CALLBACK_BYTES_V0).map_err(|_| {
            NativeValidationInvalidJournalTransitionFailureCauseV0::AccountingUnderflow
        })?;
        let next_outbox_count = accounting
            .outbox_count
            .checked_sub(1)
            .ok_or(NativeValidationInvalidJournalTransitionFailureCauseV0::AccountingUnderflow)?;
        let next_outbox_bytes = accounting
            .outbox_bytes
            .checked_sub(callback_bytes)
            .ok_or(NativeValidationInvalidJournalTransitionFailureCauseV0::AccountingUnderflow)?;
        let accepted_core_revision_be = owner.accepted_core_revision().to_be_bytes();
        let callback_payload_checksum = owner.callback_payload_checksum();
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
            .map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Insert,
                        &error,
                    ),
                )
            })?;
        if deleted != 1 {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ),
            );
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
            .map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Insert,
                        &error,
                    ),
                )
            })?;
        if job_updated != 1 {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ),
            );
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
            .map_err(|error| {
                native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Insert,
                        &error,
                    ),
                )
            })?;
        if accounting_updated != 1 {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                ),
            );
        }
        let expected_accounting = NativeValidationJournalAccountingV0 {
            job_count: accounting.job_count,
            request_bytes: accounting.request_bytes,
            artifact_bytes: accounting.artifact_bytes,
            outbox_count: next_outbox_count,
            outbox_bytes: next_outbox_bytes,
        };
        let readback_accounting = read_bounded_native_validation_journal_accounting_v0(
            &transaction,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?;
        if readback_accounting != expected_accounting {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            );
        }
        let acked = load_native_validation_job_v0(&transaction, owner.validation_id())
            .map_err(native_validation_invalid_transition_failure_v0)?
            .ok_or(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            )?;
        let acked = durable_native_validation_job_from_existing_v0(acked, self)
            .map_err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant)?;
        verify_native_validation_job_outbox_v0(
            &transaction,
            &acked,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?;
        if !native_validation_invalid_acked_job_matches_confirmation_v0(&acked, owner) {
            return Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            );
        }
        if let Err(error) = transaction.commit() {
            return match self.confirm_native_validation_invalid_acknowledgement_v0(owner) {
                Ok(NativeValidationInvalidAcknowledgementCommitReadbackV0::Acked(durable)) => Ok(
                    NativeValidationInvalidAcknowledgementInnerDecisionV0::CommitUncertainAcked(
                        *durable,
                    ),
                ),
                Ok(NativeValidationInvalidAcknowledgementCommitReadbackV0::Delivered) => {
                    Err(native_validation_invalid_transition_failure_v0(
                        classify_native_validation_reservation_sqlite_failure_v0(
                            NativeValidationReservationStageV0::Commit,
                            &error,
                        ),
                    ))
                }
                Err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(kind)) => {
                    Err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(kind))
                }
                Err(NativeValidationInvalidJournalTransitionFailureCauseV0::HostInvariant {
                    stage,
                }) => Err(
                    NativeValidationInvalidJournalTransitionFailureCauseV0::HostInvariant { stage },
                ),
                Err(_) => Err(native_validation_invalid_transition_failure_v0(
                    classify_native_validation_reservation_sqlite_failure_v0(
                        NativeValidationReservationStageV0::Commit,
                        &error,
                    ),
                )),
            };
        }
        Ok(NativeValidationInvalidAcknowledgementInnerDecisionV0::Acked(acked))
    }

    fn confirm_native_validation_invalid_acknowledgement_v0(
        &self,
        owner: &ConfirmedCoreInvalidCompletionV0,
    ) -> std::result::Result<
        NativeValidationInvalidAcknowledgementCommitReadbackV0,
        NativeValidationInvalidJournalTransitionFailureCauseV0,
    > {
        let connection = self
            .open_native_validation_confirmation_connection_v0()
            .map_err(native_validation_invalid_transition_failure_v0)?;
        read_bounded_native_validation_journal_accounting_v0(
            &connection,
            NativeValidationReservationStageV0::ConfirmCommit,
        )
        .map_err(native_validation_invalid_transition_failure_v0)?;
        let job = load_native_validation_job_v0(&connection, owner.validation_id())
            .map_err(native_validation_invalid_transition_failure_v0)?
            .ok_or(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            )?;
        let job = durable_native_validation_job_from_existing_v0(job, self)
            .map_err(NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant)?;
        match job.state {
            NativeValidationJobStateV0::Delivered => {
                let outbox = revalidate_native_validation_job_outbox_v0(
                    &connection,
                    &job,
                    NativeValidationReservationStageV0::ConfirmCommit,
                )
                .map_err(native_validation_invalid_transition_failure_v0)?
                .ok_or(
                    NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                        NativeValidationReservationInvariantV0::CommitReadbackConflict,
                    ),
                )?;
                let verified = VerifiedNativeValidationInvalidCallbackV0::new_v0(job, outbox);
                if native_validation_invalid_delivered_lineage_matches_v0(
                    &verified,
                    &owner.delivered,
                ) {
                    Ok(NativeValidationInvalidAcknowledgementCommitReadbackV0::Delivered)
                } else {
                    Err(
                        NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                            NativeValidationReservationInvariantV0::CommitReadbackConflict,
                        ),
                    )
                }
            }
            NativeValidationJobStateV0::Acked => {
                verify_native_validation_job_outbox_v0(
                    &connection,
                    &job,
                    NativeValidationReservationStageV0::ConfirmCommit,
                )
                .map_err(native_validation_invalid_transition_failure_v0)?;
                if native_validation_invalid_acked_job_matches_confirmation_v0(&job, owner) {
                    Ok(
                        NativeValidationInvalidAcknowledgementCommitReadbackV0::Acked(Box::new(
                            job,
                        )),
                    )
                } else {
                    Err(
                        NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                            NativeValidationReservationInvariantV0::CommitReadbackConflict,
                        ),
                    )
                }
            }
            _ => Err(
                NativeValidationInvalidJournalTransitionFailureCauseV0::Invariant(
                    NativeValidationReservationInvariantV0::CommitReadbackConflict,
                ),
            ),
        }
    }

    fn open_native_validation_confirmation_connection_v0(
        &self,
    ) -> std::result::Result<Connection, NativeValidationReservationFailureCauseV0> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::ConfirmCommit,
                &error,
            )
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfirmCommit,
                    &error,
                )
            })?;
        validate_native_validation_job_bindings_v0(&connection, self)?;
        Ok(connection)
    }

    fn reserve_or_reopen_native_validation_job_inner_v0(
        &self,
        facts: &NativeValidationReservationFactsV0,
    ) -> std::result::Result<
        NativeValidationReservationInnerDecisionV0,
        NativeValidationReservationFailureCauseV0,
    > {
        let stage = NativeValidationReservationStageV0::LockWriter;
        self.writer_waiters.fetch_add(1, Ordering::AcqRel);
        let writer = self.writer_gate.lock();
        self.writer_waiters.fetch_sub(1, Ordering::AcqRel);
        let _writer =
            writer.map_err(
                |_| NativeValidationReservationFailureCauseV0::HostInvariant {
                    stage,
                    sqlite: None,
                },
            )?;

        let mut connection = self.connect_native_validation_job_v0()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::BeginTransaction,
                    &error,
                )
            })?;
        validate_native_validation_job_bindings_v0(&transaction, self)?;
        let decision = match load_native_validation_job_v0(&transaction, facts.validation_id)? {
            Some(existing) => {
                let existing = durable_native_validation_job_from_existing_v0(existing, self)
                    .map_err(
                        |kind| NativeValidationReservationFailureCauseV0::Invariant {
                            stage: NativeValidationReservationStageV0::ReadExisting,
                            kind,
                            sqlite: None,
                        },
                    )?;
                verify_native_validation_job_outbox_v0(
                    &transaction,
                    &existing,
                    NativeValidationReservationStageV0::ReadExisting,
                )?;
                validate_native_validation_job_congruence_v0(facts, &existing, self)?;
                read_bounded_native_validation_journal_accounting_v0(
                    &transaction,
                    NativeValidationReservationStageV0::ReadExisting,
                )?;
                NativeValidationReservationInnerDecisionV0::Existing(existing)
            }
            None => {
                let accounting = read_bounded_native_validation_journal_accounting_v0(
                    &transaction,
                    NativeValidationReservationStageV0::ReadCapacity,
                )?;
                if accounting.job_count >= MAX_NATIVE_VALIDATION_RESERVATIONS {
                    return Err(NativeValidationReservationFailureCauseV0::Capacity {
                        maximum: MAX_NATIVE_VALIDATION_RESERVATIONS,
                    });
                }
                let incoming_request_bytes = facts
                    .target_header_cev0
                    .len()
                    .checked_add(facts.body_record.len())
                    .and_then(|length| {
                        length.checked_add(facts.parent_header_cev0.as_ref().map_or(0, Vec::len))
                    })
                    .and_then(|length| u64::try_from(length).ok())
                    .ok_or(NativeValidationReservationFailureCauseV0::HostInvariant {
                        stage: NativeValidationReservationStageV0::ReadCapacity,
                        sqlite: None,
                    })?;
                let next_request_bytes = accounting
                    .request_bytes
                    .checked_add(incoming_request_bytes)
                    .filter(|total| *total <= MAX_NATIVE_VALIDATION_REQUEST_JOURNAL_BYTES)
                    .ok_or(NativeValidationReservationFailureCauseV0::ByteCapacity {
                        maximum: MAX_NATIVE_VALIDATION_REQUEST_JOURNAL_BYTES,
                    })?;
                let next_job_count = accounting.job_count.checked_add(1).ok_or(
                    NativeValidationReservationFailureCauseV0::Capacity {
                        maximum: MAX_NATIVE_VALIDATION_RESERVATIONS,
                    },
                )?;
                if next_job_count > MAX_NATIVE_VALIDATION_RESERVATIONS {
                    return Err(NativeValidationReservationFailureCauseV0::Capacity {
                        maximum: MAX_NATIVE_VALIDATION_RESERVATIONS,
                    });
                }
                insert_native_validation_job_v0(&transaction, facts, self)?;
                let updated = transaction
                    .execute(
                        "UPDATE validation_journal_accounting_v0
                         SET job_count_be=?1, request_bytes_be=?2
                         WHERE singleton=1 AND job_count_be=?3 AND request_bytes_be=?4",
                        params![
                            next_job_count.to_be_bytes().as_slice(),
                            next_request_bytes.to_be_bytes().as_slice(),
                            accounting.job_count.to_be_bytes().as_slice(),
                            accounting.request_bytes.to_be_bytes().as_slice(),
                        ],
                    )
                    .map_err(|error| {
                        classify_native_validation_reservation_sqlite_failure_v0(
                            NativeValidationReservationStageV0::Insert,
                            &error,
                        )
                    })?;
                if updated != 1 {
                    return Err(NativeValidationReservationFailureCauseV0::Invariant {
                        stage: NativeValidationReservationStageV0::Insert,
                        kind:
                            NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                        sqlite: None,
                    });
                }
                NativeValidationReservationInnerDecisionV0::Reserved
            }
        };

        if let Err(commit_error) = transaction.commit() {
            // A failed SQLite commit can leave the caller uncertain about
            // whether the WAL record became durable. Reopen read-only and
            // accept an exact row only as suppression: another process may
            // have inserted it after this transaction released its lock, so
            // readback alone can never mint the unique evaluation token.
            return match self.confirm_native_validation_job_v0(facts) {
                Ok(existing) => Ok(
                    NativeValidationReservationInnerDecisionV0::CommitUncertainExisting(existing),
                ),
                Err(invariant @ NativeValidationReservationFailureCauseV0::Invariant { .. }) => {
                    Err(invariant)
                }
                Err(_) => Err(classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::Commit,
                    &commit_error,
                )),
            };
        }

        Ok(decision)
    }

    fn connect_native_validation_job_v0(
        &self,
    ) -> std::result::Result<Connection, NativeValidationReservationFailureCauseV0> {
        self.require_native_validation_namespace_owner_v0(
            NativeValidationReservationStageV0::OpenDatabase,
        )?;
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::OpenDatabase,
                &error,
            )
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        connection
            .execute_batch(
                "
                PRAGMA synchronous=FULL;
                PRAGMA foreign_keys=ON;
                ",
            )
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        let schema_version = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        if schema_version != STORE_SCHEMA_VERSION {
            return Err(NativeValidationReservationFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::ConfigureDatabase,
                sqlite: None,
            });
        }
        self.require_native_validation_namespace_owner_v0(
            NativeValidationReservationStageV0::ConfigureDatabase,
        )?;
        Ok(connection)
    }

    fn confirm_native_validation_job_v0(
        &self,
        facts: &NativeValidationReservationFactsV0,
    ) -> std::result::Result<DurableNativeValidationJobV0, NativeValidationReservationFailureCauseV0>
    {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::ConfirmCommit,
                &error,
            )
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfirmCommit,
                    &error,
                )
            })?;
        validate_native_validation_job_bindings_v0(&connection, self)?;
        let existing = load_native_validation_job_v0(&connection, facts.validation_id)?.ok_or(
            NativeValidationReservationFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::ConfirmCommit,
                sqlite: None,
            },
        )?;
        let existing =
            durable_native_validation_job_from_existing_v0(existing, self).map_err(|kind| {
                NativeValidationReservationFailureCauseV0::Invariant {
                    stage: NativeValidationReservationStageV0::ConfirmCommit,
                    kind,
                    sqlite: None,
                }
            })?;
        verify_native_validation_job_outbox_v0(
            &connection,
            &existing,
            NativeValidationReservationStageV0::ConfirmCommit,
        )?;
        validate_native_validation_job_congruence_v0(facts, &existing, self).map_err(
            |failure| match failure {
                NativeValidationReservationFailureCauseV0::Invariant { kind, sqlite, .. } => {
                    NativeValidationReservationFailureCauseV0::Invariant {
                        stage: NativeValidationReservationStageV0::ConfirmCommit,
                        kind: if kind
                            == NativeValidationReservationInvariantV0::PersistedRepresentationMalformed
                        {
                            kind
                        } else {
                            NativeValidationReservationInvariantV0::CommitReadbackConflict
                        },
                        sqlite,
                    }
                }
                other => other,
            },
        )?;
        Ok(existing)
    }

    /// Loads every checksum-verified local validation job in canonical state
    /// and identity order. Returned values are recovery facts only: they do
    /// not recreate the first-reservation token, the claimed Core request, an
    /// evaluated artifact, or callback authority.
    #[cfg_attr(not(test), allow(dead_code))]
    #[cfg(test)]
    pub(super) fn load_native_validation_recovery_work_v0(
        &self,
    ) -> Result<Vec<DurableNativeValidationJobV0>> {
        let connection = self.connect_read()?;
        let mut work = Vec::new();
        self.visit_native_validation_recovery_work_v0(&connection, |job| {
            work.push(job);
            Ok(())
        })?;
        Ok(work)
    }

    fn visit_native_validation_recovery_work_v0(
        &self,
        connection: &Connection,
        mut visit: impl FnMut(DurableNativeValidationJobV0) -> Result<()>,
    ) -> Result<()> {
        validate_foreign_key_integrity(connection)?;
        validate_storage_resource_bounds(connection)?;
        let schema_version = metadata(connection, "schema_version")?;
        ensure!(
            schema_version == STORE_SCHEMA_VERSION
                || schema_version == STORE_SCHEMA_VERSION_V7
                || schema_version == STORE_SCHEMA_VERSION_V6,
            "native validation recovery requires schema v6, v7, or v8"
        );
        let reserved_only = schema_version == STORE_SCHEMA_VERSION_V6;
        let mut statement = connection.prepare(
            "SELECT route, block_id, view_be, generation_be, target_height_be,
                    target_header_cev0, body_record_codec, body_record, body_checksum,
                    parent_height_be, parent_view_be, parent_block_id,
                    parent_timestamp_ms_be, parent_header_cev0,
                    parent_state_version_be, parent_state_root, validator_set_id,
                    parameters_hash, protocol_version_be, runtime_profile_ref,
                    host_config_ref, creation_revision_be, request_fingerprint,
                    immutable_checksum, state, result_kind, invalid_reason_code_be,
                    artifact_codec, artifact_bytes, artifact_checksum,
                    accepted_core_revision_be, accepted_core_payload_checksum,
                    row_codec, row_checksum
             FROM validation_jobs_v0
             ORDER BY state, route, block_id, view_be, generation_be",
        )?;
        let rows = statement.query_map([], native_validation_existing_from_row_v0)?;
        let expected_host_config_ref = native_validation_host_config_ref_v0(self);
        for row in rows {
            let job =
                durable_native_validation_job_from_existing_v0(row?, self).map_err(|kind| {
                    anyhow!("native validation recovery row invariant failed: {kind:?}")
                })?;
            verify_native_validation_job_outbox_v0(
                connection,
                &job,
                NativeValidationReservationStageV0::ReadExisting,
            )
            .map_err(|cause| anyhow!("native validation recovery outbox failed: {cause:?}"))?;
            ensure!(
                job.runtime_profile_ref
                    == native_validation_runtime_profile_ref_v0(job.facts.protocol_version)
                    && job.host_config_ref == expected_host_config_ref,
                "native validation recovery row configuration reference differs from this host"
            );
            if reserved_only {
                ensure!(
                    job.state == NativeValidationJobStateV0::Reserved,
                    "application-store schema v6 contains an active validation result"
                );
            } else if schema_version == STORE_SCHEMA_VERSION_V7 {
                ensure!(
                    matches!(
                        job.state,
                        NativeValidationJobStateV0::Reserved
                            | NativeValidationJobStateV0::CallbackPending
                    ),
                    "application-store schema v7 contains an inactive validation state"
                );
            } else {
                ensure!(
                    matches!(
                        job.state,
                        NativeValidationJobStateV0::Reserved
                            | NativeValidationJobStateV0::CallbackPending
                            | NativeValidationJobStateV0::Delivered
                            | NativeValidationJobStateV0::Acked
                    ),
                    "application-store schema v8 contains an inactive validation state"
                );
            }
            visit(job)?;
        }
        Ok(())
    }

    pub(super) fn open(
        status_path: &Path,
        chain_id: &str,
        signer_policy_hash_hex: &str,
    ) -> Result<Self> {
        Self::open_with_namespace_owner_v0(
            status_path,
            chain_id,
            signer_policy_hash_hex,
            ApplicationStoreOwnerModeV0::OrdinaryShared,
        )
        .map_err(|failure| anyhow!(failure))
    }

    pub(super) fn open_existing_recovery_v0(
        status_path: &Path,
        chain_id: &str,
        signer_policy_hash_hex: &str,
    ) -> std::result::Result<Self, ApplicationStoreNamespaceOpenFailureV0> {
        Self::open_with_namespace_owner_v0(
            status_path,
            chain_id,
            signer_policy_hash_hex,
            ApplicationStoreOwnerModeV0::RecoveryExclusive,
        )
    }

    fn open_with_namespace_owner_v0(
        status_path: &Path,
        chain_id: &str,
        signer_policy_hash_hex: &str,
        mode: ApplicationStoreOwnerModeV0,
    ) -> std::result::Result<Self, ApplicationStoreNamespaceOpenFailureV0> {
        let (namespace_owner, status_path, database_path) =
            ApplicationStoreNamespaceOwnerV0::acquire(status_path, mode)?;
        let store = Self {
            status_path,
            database_path,
            chain_id: chain_id.to_string(),
            signer_policy_hash_hex: signer_policy_hash_hex.to_string(),
            writer_gate: Arc::new(Mutex::new(())),
            writer_waiters: Arc::new(AtomicUsize::new(0)),
            maintenance_gate: Arc::new(Mutex::new(())),
            active_snapshot_pins: Arc::new(AtomicUsize::new(0)),
            namespace_owner: Arc::new(namespace_owner),
        };
        store.validate_namespace_owner_v0()?;
        if mode == ApplicationStoreOwnerModeV0::RecoveryExclusive {
            validate_existing_application_store_database_path_v0(
                &store.database_path,
                Some(store.namespace_owner.parent_uid),
            )?;
        }
        Ok(store)
    }

    fn validate_namespace_owner_v0(
        &self,
    ) -> std::result::Result<(), ApplicationStoreNamespaceOpenFailureV0> {
        self.namespace_owner.validate()
    }

    /// Verifies the minimum filesystem boundary required before the recovery
    /// facade may reopen SQLite by pathname. This excludes non-owner and
    /// group/world-writable namespace components; it does not claim to defend
    /// against a hostile process running under the same effective UID.
    pub(super) fn validate_secure_native_validation_recovery_namespace_v0(
        &self,
    ) -> std::result::Result<(), ApplicationStoreNamespaceOpenFailureV0> {
        self.validate_namespace_owner_v0()?;
        let parent_handle_metadata = self
            .namespace_owner
            .parent_handle
            .metadata()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        let parent_path_metadata = self
            .namespace_owner
            .canonical_parent
            .symlink_metadata()
            .map_err(|_| ApplicationStoreNamespaceOpenFailureV0::NamespaceChanged)?;
        validate_application_store_recovery_parent_v0(
            &parent_handle_metadata,
            &parent_path_metadata,
            self.namespace_owner.parent_uid,
        )?;
        validate_existing_application_store_database_path_v0(
            &self.database_path,
            Some(self.namespace_owner.parent_uid),
        )?;
        validate_application_store_recovery_auxiliary_v0(
            &self.database_path,
            "-wal",
            self.namespace_owner.parent_uid,
        )?;
        validate_application_store_recovery_auxiliary_v0(
            &self.database_path,
            "-shm",
            self.namespace_owner.parent_uid,
        )?;
        validate_application_store_lock_v0(
            &self.namespace_owner.lock_path,
            &self.namespace_owner.lock_handle,
            self.namespace_owner.parent_uid,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn release_namespace_owner_for_recovery_test_v0(
        &self,
    ) -> std::result::Result<(), ApplicationStoreNamespaceOpenFailureV0> {
        self.namespace_owner.release_for_recovery_test_v0()
    }

    pub(super) fn load_or_migrate(&self) -> Result<AppState> {
        if !self.database_path.exists() && self.status_path.exists() {
            return Err(anyhow!(
                "existing pre-v4 state requires the explicit export/new-genesis migration tool"
            ));
        }
        if self.database_path.exists() {
            self.probe_existing_database()?;
        }
        let connection = self.connect()?;
        // Startup must authenticate every local validation fact before the
        // application resumes from the committed head. Recovery execution is
        // still a later tranche; this scan is a fail-closed integrity gate.
        self.visit_native_validation_recovery_work_v0(&connection, |job| {
            drop(job);
            Ok(())
        })?;
        if self.has_committed_state(&connection)? {
            let state = load_sqlite_state(&connection)?;
            self.refresh_status_best_effort(&state);
            return Ok(state);
        }
        drop(connection);

        if !self.status_path.exists() {
            return Ok(AppState::default());
        }
        Err(anyhow!(
            "existing pre-v4 state requires the explicit export/new-genesis migration tool"
        ))
    }

    pub(super) fn load_object(&self, object_key_hex: &str) -> Result<Option<StoredObject>> {
        let connection = self.connect_read()?;
        load_object(&connection, object_key_hex)
    }

    /// Loads one object from the committed head while independently proving
    /// that the physical object row agrees with the authenticated JMT.
    ///
    /// This is a legacy self-head read, not host parent authority. It validates
    /// bindings, head metadata, app hash, query floor, root, row, and proof in
    /// one temporary read transaction, while leaving the existing `anyhow`
    /// wrapper in place for old callers. New execution adapters must instead
    /// begin from a separately authenticated expected-parent capability.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn load_authenticated_runtime_object_v0(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StoredObject>, AuthenticatedRuntimeReadFailureV0> {
        let snapshot = self.begin_authenticated_runtime_read_snapshot_v0(None)?;
        let result = snapshot.load(object_key_hex);
        let rollback = snapshot.finish();
        merge_authenticated_runtime_read_and_rollback_v0(result, rollback)
    }

    #[cfg(test)]
    pub(super) fn begin_authenticated_runtime_read_snapshot_for_test_v0(
        &self,
        expected_height: Version,
        expected_root: [u8; 32],
    ) -> std::result::Result<AuthenticatedRuntimeReadSnapshotV0, AuthenticatedRuntimeReadFailureV0>
    {
        self.begin_authenticated_runtime_read_snapshot_v0(Some(
            AuthenticatedRuntimeExpectedParentV0 {
                height: expected_height,
                root_hash: RootHash(expected_root),
            },
        ))
    }

    /// Opens the committed head only when it is exactly the positive-height
    /// parent frozen inside a Core-issued payload-validation capability.
    /// Synthetic genesis deliberately has no native header/state root and is
    /// therefore reported as source-unavailable rather than guessed.
    pub(super) fn begin_authenticated_runtime_read_snapshot_for_core_parent_v0(
        &self,
        parent: &PayloadValidationParentV0,
    ) -> std::result::Result<AuthenticatedRuntimeReadSnapshotV0, AuthenticatedRuntimeReadFailureV0>
    {
        let header =
            parent
                .exact_header()
                .ok_or(AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    reason: "trusted genesis parent has no canonical native state-root header",
                })?;
        self.begin_authenticated_runtime_read_snapshot_v0(Some(
            AuthenticatedRuntimeExpectedParentV0 {
                height: header.height().get(),
                root_hash: RootHash(*header.state_root().as_bytes()),
            },
        ))
    }

    #[cfg(test)]
    pub(super) fn active_runtime_snapshot_pins_for_test_v0(&self) -> usize {
        self.active_snapshot_pins.load(Ordering::Acquire)
    }

    pub(super) fn configured_signer_policy_commitment_v0(
        &self,
    ) -> std::result::Result<[u8; 32], AuthenticatedRuntimeReadFailureV0> {
        trnm_finality_types::decode_hash32(
            "authenticated runtime configured signer policy",
            &self.signer_policy_hash_hex,
        )
        .map_err(|_| AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
            sqlite: None,
            reason: "configured signer-policy commitment is not canonical hash32",
        })
    }

    pub(super) fn configured_chain_id_v0(&self) -> &str {
        &self.chain_id
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn begin_authenticated_runtime_read_snapshot_v0(
        &self,
        expected_parent: Option<AuthenticatedRuntimeExpectedParentV0>,
    ) -> std::result::Result<AuthenticatedRuntimeReadSnapshotV0, AuthenticatedRuntimeReadFailureV0>
    {
        let _maintenance = match self.maintenance_gate.try_lock() {
            Ok(maintenance) => maintenance,
            Err(TryLockError::WouldBlock) => {
                return Err(AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                    stage: AuthenticatedRuntimeReadStageV0::BeginSnapshot,
                    sqlite: None,
                    reason: "application store maintenance is busy",
                });
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::BeginSnapshot,
                    sqlite: None,
                    reason: "application store maintenance gate is poisoned",
                });
            }
        };
        let connection = self.connect_authenticated_runtime_read_v0()?;
        connection
            .execute_batch("BEGIN DEFERRED")
            .map_err(|error| {
                classify_sqlite_authenticated_read_failure_v0(
                    AuthenticatedRuntimeReadStageV0::BeginSnapshot,
                    &error,
                )
            })?;

        let validated = (|| {
            let (height, root_hash) =
                self.validate_authenticated_runtime_snapshot_head_v0(&connection)?;
            if let Some(expected_parent) = expected_parent {
                if (height, root_hash) != (expected_parent.height, expected_parent.root_hash) {
                    return Err(AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                        stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                        reason: "authenticated runtime snapshot differs from expected parent",
                    });
                }
            }
            Ok((height, root_hash))
        })();
        match validated {
            Ok((height, root_hash)) => {
                self.active_snapshot_pins.fetch_add(1, Ordering::AcqRel);
                Ok(AuthenticatedRuntimeReadSnapshotV0 {
                    source: Some(connection),
                    height,
                    root_hash,
                    active_snapshot_pins: Arc::clone(&self.active_snapshot_pins),
                    #[cfg(test)]
                    fail_finish_for_test_v0: false,
                })
            }
            Err(error) => {
                let rollback = connection.execute_batch("ROLLBACK").map_err(|rollback| {
                    classify_sqlite_authenticated_read_failure_v0(
                        AuthenticatedRuntimeReadStageV0::EndSnapshot,
                        &rollback,
                    )
                });
                merge_authenticated_runtime_read_and_rollback_v0(Err(error), rollback)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn contains_command_id(&self, command_id: &str) -> Result<bool> {
        let connection = self.connect_read()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM command_ids WHERE command_id=?1",
                params![command_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    #[cfg(test)]
    pub(super) fn contains_signer_nonce(&self, signer_id: &str, nonce: u64) -> Result<bool> {
        let connection = self.connect_read()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM signer_nonces WHERE signer_id=?1 AND nonce=?2",
                params![signer_id, nonce.to_be_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub(super) fn plan_auth_update(
        &self,
        version: Version,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> Result<PlannedAuthUpdate> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let expected_next_version = latest_auth_version(&connection)?.map_or(0, |value| value + 1);
        let reader = SqliteAuthReader {
            connection: &connection,
        };
        let update = plan_put_value_set(&reader, expected_next_version, version, writes)?;
        connection.execute_batch("ROLLBACK")?;
        Ok(update)
    }

    pub(super) fn prove(&self, version: Version, key: Vec<u8>) -> Result<AuthProof> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let query_floor = optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
            .or(oldest_auth_version(&connection)?)
            .unwrap_or(0);
        ensure!(
            version >= query_floor,
            "authenticated version {version} was pruned; retained query floor is {query_floor}"
        );
        let root_hash = auth_root(&connection, version)?
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let reader = SqliteAuthReader {
            connection: &connection,
        };
        let proof = prove_with_reader(&reader, version, root_hash, key)?;
        let valid = match proof.value.as_deref() {
            Some(value) => verify_ics23_membership(&proof, value),
            None => verify_ics23_non_membership(&proof),
        };
        ensure!(valid, "persisted authenticated proof failed verification");
        connection.execute_batch("ROLLBACK")?;
        Ok(proof)
    }

    pub(super) fn production_poco_projection(
        &self,
        version: Version,
    ) -> Result<(RootHash, Option<ProductionPocoProjectionV0>)> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let query_floor = optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
            .or(oldest_auth_version(&connection)?)
            .unwrap_or(0);
        ensure!(
            version >= query_floor,
            "authenticated version {version} was pruned; retained query floor is {query_floor}"
        );
        let root_hash = auth_root(&connection, version)?
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let projection =
            load_production_poco_projection_from_connection_v0(&connection, version, root_hash)?;
        connection.execute_batch("ROLLBACK")?;
        Ok((root_hash, projection))
    }

    pub(super) fn authenticated_root_at(&self, version: Version) -> Result<RootHash> {
        let connection = self.connect_read()?;
        let query_floor = optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
            .or(oldest_auth_version(&connection)?)
            .unwrap_or(0);
        ensure!(
            version >= query_floor,
            "authenticated version {version} was pruned; retained query floor is {query_floor}"
        );
        auth_root(&connection, version)?
            .with_context(|| format!("missing authenticated root at version {version}"))
    }

    /// Removes authenticated roots, stale nodes, and superseded values below
    /// the durable query floor using one writer-budgeted transaction.
    ///
    /// A `None` result means the consensus writer currently owns the shared
    /// gate. Callers must yield and retry; they must never wait in front of a
    /// Commit. Preimages remain one-per-distinct-key in the live database;
    /// latest-only snapshot compaction removes dead-key preimages.
    pub(super) fn try_prune_auth_batch(
        &self,
        max_rows: usize,
        max_logical_bytes: u64,
    ) -> Result<Option<PruneBatchOutcome>> {
        ensure!(max_rows > 0, "authenticated prune batch must allow a row");
        ensure!(
            max_logical_bytes > 0,
            "authenticated prune batch must allow logical bytes"
        );
        let _maintenance = match self.maintenance_gate.try_lock() {
            Ok(maintenance) => maintenance,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store maintenance gate poisoned"));
            }
        };
        if self.active_snapshot_pins.load(Ordering::Acquire) > 0 {
            return Ok(None);
        }
        if self.writer_waiters.load(Ordering::Acquire) > 0 {
            return Ok(None);
        }
        let _writer = match self.writer_gate.try_lock() {
            Ok(writer) => writer,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store writer gate poisoned"));
            }
        };
        let started = Instant::now();
        let mut connection = self.connect_maintenance()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let query_floor = optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
            .context("application store is missing authenticated query floor")?;
        let Some(target) = optional_metadata_version(&transaction, AUTH_PRUNE_TARGET_KEY)? else {
            transaction.rollback()?;
            return Ok(Some(PruneBatchOutcome {
                stats: PruneStats::default(),
                query_floor,
                target: query_floor,
                complete: true,
                rows_examined: 0,
                logical_bytes_examined: 0,
                elapsed: started.elapsed(),
            }));
        };
        let height = metadata(&transaction, "height")?
            .parse::<u64>()
            .context("parse application store height during authenticated pruning")?;
        let app_hash = trnm_finality_types::decode_hash32(
            "application store app_hash",
            &metadata(&transaction, "app_hash_hex")?,
        )?;
        ensure!(
            target <= query_floor && query_floor <= height,
            "authenticated prune control exceeds the committed head"
        );
        ensure!(
            auth_root(&transaction, target)?.is_some(),
            "authenticated prune boundary root is absent"
        );

        let target_be = target.to_be_bytes();
        let mut stats = PruneStats::default();
        let mut rows_examined = 0_usize;
        let mut logical_bytes_examined = 0_u64;
        let mut budget_expired = false;

        let root_versions = {
            let mut statement = transaction.prepare(
                "SELECT version_be
                 FROM auth_roots
                 WHERE version_be<?1
                 ORDER BY version_be
                 LIMIT ?2",
            )?;
            let rows = statement.query_map(
                params![target_be.as_slice(), i64::try_from(max_rows)?],
                |row| row.get::<_, Vec<u8>>(0),
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for encoded_version in root_versions {
            let version = decode_version_be(&encoded_version)?;
            let root_path: NibblePath = std::iter::empty().collect();
            let encoded_key = borsh::to_vec(&NodeKey::new(version, root_path))
                .context("encode authenticated root node key during pruning")?;
            let node_bytes = transaction
                .query_row(
                    "SELECT length(node) FROM auth_nodes WHERE node_key=?1",
                    params![encoded_key.as_slice()],
                    |row| row.get::<_, u64>(0),
                )
                .optional()?
                .unwrap_or(0)
                .saturating_add(u64::try_from(encoded_key.len())?);
            if rows_examined > 0
                && (logical_bytes_examined.saturating_add(node_bytes) > max_logical_bytes
                    || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
            {
                budget_expired = true;
                break;
            }
            rows_examined = rows_examined.saturating_add(1);
            logical_bytes_examined = logical_bytes_examined.saturating_add(node_bytes);
            stats.nodes_removed = stats.nodes_removed.saturating_add(transaction.execute(
                "DELETE FROM auth_nodes WHERE node_key=?1",
                params![encoded_key.as_slice()],
            )?);
            stats.roots_removed = stats.roots_removed.saturating_add(transaction.execute(
                "DELETE FROM auth_roots WHERE version_be=?1",
                params![encoded_version],
            )?);
        }

        let old_roots_remain = transaction
            .query_row(
                "SELECT 1 FROM auth_roots WHERE version_be<?1 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !old_roots_remain && !budget_expired && rows_examined < max_rows {
            let remaining = max_rows.saturating_sub(rows_examined);
            let stale_rows = {
                let mut statement = transaction.prepare(
                    "SELECT stale.stale_since_version_be,
                            stale.node_key,
                            COALESCE(length(nodes.node), 0)
                     FROM auth_stale_nodes AS stale
                     LEFT JOIN auth_nodes AS nodes ON nodes.node_key=stale.node_key
                     WHERE stale.stale_since_version_be<=?1
                     ORDER BY stale.stale_since_version_be, stale.node_key
                     LIMIT ?2",
                )?;
                let rows = statement.query_map(
                    params![target_be.as_slice(), i64::try_from(remaining)?],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, u64>(2)?,
                        ))
                    },
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (stale_since, node_key, node_length) in stale_rows {
                let logical_bytes = node_length.saturating_add(u64::try_from(node_key.len())?);
                if rows_examined > 0
                    && (logical_bytes_examined.saturating_add(logical_bytes) > max_logical_bytes
                        || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
                {
                    break;
                }
                rows_examined = rows_examined.saturating_add(1);
                logical_bytes_examined = logical_bytes_examined.saturating_add(logical_bytes);
                stats.nodes_removed = stats.nodes_removed.saturating_add(transaction.execute(
                    "DELETE FROM auth_nodes WHERE node_key=?1",
                    params![node_key.as_slice()],
                )?);
                stats.stale_indices_removed =
                    stats
                        .stale_indices_removed
                        .saturating_add(transaction.execute(
                            "DELETE FROM auth_stale_nodes
                             WHERE stale_since_version_be=?1 AND node_key=?2",
                            params![stale_since, node_key],
                        )?);
            }
        }

        let stale_nodes_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !old_roots_remain
            && !stale_nodes_remain
            && rows_examined < max_rows
            && started.elapsed() < AUTH_PRUNE_BATCH_MAX_DURATION
        {
            let remaining = max_rows.saturating_sub(rows_examined);
            let stale_values = {
                let mut statement = transaction.prepare(
                    "SELECT stale.stale_since_version_be,
                            stale.key_hash,
                            stale.version_be,
                            history.key_hash IS NOT NULL,
                            COALESCE(length(history.value), 0)
                     FROM auth_stale_values AS stale
                     LEFT JOIN auth_values AS history
                       ON history.key_hash=stale.key_hash
                      AND history.version_be=stale.version_be
                     WHERE stale.stale_since_version_be<=?1
                     ORDER BY stale.stale_since_version_be,
                              stale.key_hash,
                              stale.version_be
                     LIMIT ?2",
                )?;
                let rows = statement.query_map(
                    params![target_be.as_slice(), i64::try_from(remaining)?],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, bool>(3)?,
                            row.get::<_, u64>(4)?,
                        ))
                    },
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (stale_since, key_hash, version_be, value_exists, value_length) in stale_values {
                ensure!(
                    value_exists,
                    "authenticated stale-value index points to an absent value"
                );
                let logical_bytes = value_length
                    .saturating_add(u64::try_from(key_hash.len())?)
                    .saturating_add(u64::try_from(version_be.len())?);
                if rows_examined > 0
                    && (logical_bytes_examined.saturating_add(logical_bytes) > max_logical_bytes
                        || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
                {
                    break;
                }
                rows_examined = rows_examined.saturating_add(1);
                logical_bytes_examined = logical_bytes_examined.saturating_add(logical_bytes);
                let removed = transaction.execute(
                    "DELETE FROM auth_values
                     WHERE key_hash=?1 AND version_be=?2",
                    params![key_hash.as_slice(), version_be.as_slice()],
                )?;
                ensure!(
                    removed == 1,
                    "authenticated stale value disappeared during pruning"
                );
                stats.value_versions_removed = stats.value_versions_removed.saturating_add(removed);
                let index_removed = transaction.execute(
                    "DELETE FROM auth_stale_values
                     WHERE stale_since_version_be=?1
                       AND key_hash=?2
                       AND version_be=?3",
                    params![
                        stale_since.as_slice(),
                        key_hash.as_slice(),
                        version_be.as_slice(),
                    ],
                )?;
                ensure!(
                    index_removed == 1,
                    "authenticated stale-value index disappeared during pruning"
                );
                stats.stale_indices_removed =
                    stats.stale_indices_removed.saturating_add(index_removed);
            }
        }

        let old_roots_remain = transaction
            .query_row(
                "SELECT 1 FROM auth_roots WHERE version_be<?1 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let stale_nodes_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let stale_values_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_values
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let complete = !old_roots_remain && !stale_nodes_remain && !stale_values_remain;
        if complete {
            verify_retained_lifecycle_proofs(&transaction, height, app_hash, target)?;
            transaction.execute(
                "DELETE FROM metadata WHERE key=?1",
                params![AUTH_PRUNE_TARGET_KEY],
            )?;
        }
        transaction.commit()?;
        Ok(Some(PruneBatchOutcome {
            stats,
            query_floor,
            target,
            complete,
            rows_examined,
            logical_bytes_examined,
            elapsed: started.elapsed(),
        }))
    }

    #[cfg(any(test, feature = "scale-gate"))]
    pub(super) fn request_auth_prune(
        &self,
        retain_from_version: Version,
    ) -> Result<AuthPruneStatus> {
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let height = metadata(&transaction, "height")?
            .parse::<u64>()
            .context("parse application store height during prune request")?;
        ensure!(
            retain_from_version <= height,
            "cannot request a future authenticated query floor"
        );
        ensure!(
            auth_root(&transaction, retain_from_version)?.is_some(),
            "requested authenticated query floor has no root"
        );
        advance_auth_query_floor(&transaction, retain_from_version)?;
        let status = AuthPruneStatus {
            query_floor: optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
                .context("application store is missing authenticated query floor")?,
            target: optional_metadata_version(&transaction, AUTH_PRUNE_TARGET_KEY)?,
        };
        transaction.commit()?;
        Ok(status)
    }

    #[cfg(any(test, feature = "scale-gate"))]
    pub(super) fn auth_prune_status(&self) -> Result<AuthPruneStatus> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let status = AuthPruneStatus {
            query_floor: optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
                .context("application store is missing authenticated query floor")?,
            target: optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?,
        };
        connection.execute_batch("ROLLBACK")?;
        Ok(status)
    }

    pub(super) fn has_pending_auth_prune(&self) -> Result<bool> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let pending = optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?.is_some();
        connection.execute_batch("ROLLBACK")?;
        Ok(pending)
    }

    pub(super) fn prune_auth_versions_before(
        &self,
        state: &AppState,
        retain_from_version: Version,
    ) -> Result<PruneStats> {
        ensure!(
            state.pending.is_none(),
            "cannot prune authenticated history while a block is pending"
        );
        ensure!(
            retain_from_version <= state.height,
            "cannot retain a future authenticated version"
        );
        let _maintenance = self
            .maintenance_gate
            .lock()
            .map_err(|_| anyhow!("application store maintenance gate poisoned"))?;
        ensure!(
            self.active_snapshot_pins.load(Ordering::Acquire) == 0,
            "cannot run full authenticated pruning while a snapshot is pinned"
        );
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, state)?;
        ensure!(
            latest_auth_version(&transaction)? == Some(state.height),
            "authenticated tree head differs from application height"
        );
        let current_query_floor = optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
            .context("application store is missing authenticated query floor")?;
        ensure!(
            retain_from_version >= current_query_floor,
            "authenticated query floor cannot move backwards"
        );

        transaction.execute_batch(
            "
            CREATE TEMP TABLE trnm_prune_nodes (
                node_key BLOB PRIMARY KEY NOT NULL
            ) WITHOUT ROWID;
            CREATE TEMP TABLE trnm_live_preimages (
                key_hash BLOB PRIMARY KEY NOT NULL CHECK(length(key_hash)=32)
            ) WITHOUT ROWID;
            ",
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO trnm_prune_nodes(node_key)
             SELECT node_key
             FROM auth_stale_nodes
             WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;

        {
            let mut statement = transaction.prepare(
                "SELECT version_be
                 FROM auth_roots
                 WHERE version_be<?1
                 ORDER BY version_be",
            )?;
            let rows = statement.query_map(
                params![retain_from_version.to_be_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )?;
            for row in rows {
                let version = decode_version_be(&row?)?;
                let root_path: NibblePath = std::iter::empty().collect();
                let encoded_key = borsh::to_vec(&NodeKey::new(version, root_path))
                    .context("encode historical JMT root node key during pruning")?;
                transaction.execute(
                    "INSERT OR IGNORE INTO trnm_prune_nodes(node_key) VALUES (?1)",
                    params![encoded_key],
                )?;
            }
        }

        let nodes_removed = transaction.execute(
            "DELETE FROM auth_nodes
             WHERE node_key IN (SELECT node_key FROM trnm_prune_nodes)",
            [],
        )?;
        let stale_node_indices_removed = transaction.execute(
            "DELETE FROM auth_stale_nodes WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        let roots_removed = transaction.execute(
            "DELETE FROM auth_roots WHERE version_be<?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        {
            let mut statement = transaction.prepare("SELECT node FROM auth_nodes")?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                let node: Node =
                    borsh::from_slice(&row?).context("decode retained JMT node during pruning")?;
                if let Node::Leaf(leaf) = node {
                    transaction.execute(
                        "INSERT OR IGNORE INTO trnm_live_preimages(key_hash) VALUES (?1)",
                        params![leaf.key_hash().0.as_slice()],
                    )?;
                }
            }
        }
        let value_versions_removed = transaction.execute(
            "DELETE FROM auth_values AS candidate
             WHERE EXISTS (
                 SELECT 1
                 FROM auth_stale_values AS stale
                 WHERE stale.stale_since_version_be<=?1
                   AND stale.key_hash=candidate.key_hash
                   AND stale.version_be=candidate.version_be
             )",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        let stale_value_indices_removed = transaction.execute(
            "DELETE FROM auth_stale_values WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        ensure!(
            value_versions_removed == stale_value_indices_removed,
            "authenticated stale-value index differs from value history"
        );
        let dead_value_versions_removed = if retain_from_version == state.height {
            transaction.execute(
                "DELETE FROM auth_values
                 WHERE key_hash NOT IN (SELECT key_hash FROM trnm_live_preimages)",
                [],
            )?
        } else {
            0
        };
        let preimages_removed = transaction.execute(
            "DELETE FROM auth_preimages
             WHERE key_hash NOT IN (SELECT key_hash FROM trnm_live_preimages)",
            [],
        )?;
        write_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY, retain_from_version)?;
        transaction.execute(
            "DELETE FROM metadata WHERE key=?1",
            params![AUTH_PRUNE_TARGET_KEY],
        )?;

        let retained_root = auth_root(&transaction, state.height)?
            .context("pruning removed the committed authenticated root")?;
        ensure!(
            <[u8; 32]>::from(retained_root) == state.app_hash,
            "authenticated pruning changed the committed AppHash"
        );
        let lifecycle_bytes: Vec<u8> = transaction.query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let reader = SqliteAuthReader {
            connection: &transaction,
        };
        let latest_proof =
            prove_with_reader(&reader, state.height, retained_root, validator_state_key()?)?;
        let latest_value = latest_proof
            .value
            .as_deref()
            .context("latest validator lifecycle proof is absent")?;
        let lifecycle_record = AuthenticatedObjectRecord::decode(latest_value)?;
        ensure!(
            lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
                && lifecycle_record.object_version <= state.height
                && lifecycle_record.value == lifecycle_bytes
                && verify_ics23_membership(&latest_proof, latest_value),
            "authenticated pruning damaged the latest validator lifecycle proof"
        );
        if retain_from_version < state.height {
            let boundary_root = auth_root(&transaction, retain_from_version)?
                .context("pruning removed the retention-boundary root")?;
            let boundary_proof = prove_with_reader(
                &reader,
                retain_from_version,
                boundary_root,
                validator_state_key()?,
            )?;
            let boundary_value = boundary_proof
                .value
                .as_deref()
                .context("retention-boundary lifecycle proof is absent")?;
            ensure!(
                verify_ics23_membership(&boundary_proof, boundary_value),
                "authenticated pruning damaged the retention-boundary proof"
            );
        }
        transaction.commit()?;
        Ok(PruneStats {
            nodes_removed,
            value_versions_removed: value_versions_removed
                .saturating_add(dead_value_versions_removed),
            preimages_removed,
            stale_indices_removed: stale_node_indices_removed
                .saturating_add(stale_value_indices_removed),
            roots_removed,
        })
    }

    pub(super) fn build_snapshot_database(
        &self,
        state: &AppState,
        destination: &Path,
        mut pinned: PinnedSnapshot,
    ) -> Result<AppState> {
        ensure!(
            state.height > 0 && state.pending.is_none(),
            "snapshot database requires committed non-genesis state"
        );
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create snapshot directory {}", parent.display()))?;
        }
        let temporary = destination.with_extension("snapshot.tmp");
        remove_file_if_exists(&temporary)?;
        remove_sqlite_sidecars(&temporary)?;

        let mut target = Connection::open_with_flags(
            &temporary,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("create SQLite snapshot {}", temporary.display()))?;
        {
            let backup = Backup::new(pinned.source()?, &mut target)?;
            backup.run_to_completion(256, Duration::from_millis(2), None)?;
        }
        drop(target);
        pinned.release()?;

        // Validation jobs and callback delivery records are node-local,
        // monotonic work journal rows, not consensus state. Scrub only the
        // temporary copy, child outbox first, before pruning/VACUUM; the
        // authoritative source database remains intact.
        {
            let mut connection = Connection::open_with_flags(
                &temporary,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute("DELETE FROM validation_callback_outbox_v0", [])?;
            transaction.execute("DELETE FROM validation_jobs_v0", [])?;
            transaction.execute(
                "UPDATE validation_journal_accounting_v0
                 SET job_count_be=zeroblob(8), request_bytes_be=zeroblob(8),
                     artifact_bytes_be=zeroblob(8), outbox_count_be=zeroblob(8),
                     outbox_bytes_be=zeroblob(8)
                 WHERE singleton=1",
                [],
            )?;
            transaction.commit()?;
        }

        let snapshot_store = self.with_database_path(temporary.clone());
        snapshot_store.prune_auth_versions_before(state, state.height)?;
        {
            let connection = Connection::open_with_flags(
                &temporary,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?;
            connection.execute_batch(
                "
                PRAGMA wal_checkpoint(TRUNCATE);
                PRAGMA journal_mode=DELETE;
                VACUUM;
                ",
            )?;
        }
        remove_sqlite_sidecars(&temporary)?;
        let validated =
            snapshot_store.validate_snapshot_database(&temporary, state.height, state.app_hash)?;
        fs::File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, destination).with_context(|| {
            format!(
                "install completed snapshot {} from {}",
                destination.display(),
                temporary.display()
            )
        })?;
        sync_parent(destination)?;
        Ok(validated)
    }

    pub(super) fn pin_snapshot(&self, state: &AppState) -> Result<PinnedSnapshot> {
        ensure!(
            state.height > 0 && state.pending.is_none(),
            "snapshot pin requires committed non-genesis state"
        );
        let _maintenance = match self.maintenance_gate.try_lock() {
            Ok(maintenance) => maintenance,
            Err(TryLockError::WouldBlock) => {
                return Err(anyhow!(
                    "application store maintenance is busy; defer optional snapshot pin"
                ));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store maintenance gate poisoned"));
            }
        };
        let source = self.connect_read()?;
        source.execute_batch("BEGIN DEFERRED")?;
        let pinned_height = metadata(&source, "height")?
            .parse::<u64>()
            .context("parse pinned snapshot height")?;
        let pinned_hash = trnm_finality_types::decode_hash32(
            "pinned snapshot app_hash",
            &metadata(&source, "app_hash_hex")?,
        )?;
        ensure!(
            (pinned_height, pinned_hash) == (state.height, state.app_hash),
            "application store head differs from requested snapshot"
        );
        self.active_snapshot_pins.fetch_add(1, Ordering::AcqRel);
        Ok(PinnedSnapshot {
            source: Some(source),
            active_snapshot_pins: Arc::clone(&self.active_snapshot_pins),
        })
    }

    pub(super) fn install_snapshot_database(
        &self,
        expected: &AppState,
        source_path: &Path,
        expected_height: u64,
        expected_app_hash: [u8; 32],
    ) -> Result<AppState> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "snapshot install requires empty application state"
        );
        let restored =
            self.validate_snapshot_database(source_path, expected_height, expected_app_hash)?;

        let _maintenance = self
            .maintenance_gate
            .lock()
            .map_err(|_| anyhow!("application store maintenance gate poisoned"))?;
        ensure!(
            self.active_snapshot_pins.load(Ordering::Acquire) == 0,
            "cannot install a snapshot while a live snapshot read is pinned"
        );
        let _writer = self.lock_writer()?;
        let mut destination = self.connect()?;
        {
            let transaction =
                destination.transaction_with_behavior(TransactionBehavior::Immediate)?;
            verify_database_head(&transaction, expected)?;
            let accounting = decode_native_validation_journal_accounting_v0(
                native_validation_journal_accounting_raw_v0(&transaction)?,
            )
            .context("decode snapshot-install validation journal accounting")?;
            let local_jobs =
                transaction.query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
                    row.get::<_, u64>(0)
                })?;
            let local_outbox = transaction.query_row(
                "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                local_jobs == 0
                    && local_outbox == 0
                    && accounting.job_count == 0
                    && accounting.request_bytes == 0
                    && accounting.artifact_bytes == 0
                    && accounting.outbox_count == 0
                    && accounting.outbox_bytes == 0,
                "snapshot install refuses to discard local native validation journal work"
            );
            transaction.rollback()?;
        }
        destination.restore(
            DatabaseName::Main,
            source_path,
            None::<fn(rusqlite::backup::Progress)>,
        )?;
        let post_install = (|| -> Result<AppState> {
            let mut installed_schema = metadata(&destination, "schema_version")?;
            if installed_schema == LEGACY_STORE_SCHEMA_VERSION {
                migrate_store_schema_v3_to_v4(&mut destination)?;
                installed_schema = metadata(&destination, "schema_version")?;
            }
            if installed_schema == STORE_SCHEMA_VERSION_V4 {
                migrate_store_schema_v4_to_v5(&mut destination)?;
                installed_schema = metadata(&destination, "schema_version")?;
            }
            if installed_schema == STORE_SCHEMA_VERSION_V5 {
                migrate_store_schema_v5_to_v6(&mut destination)?;
                installed_schema = metadata(&destination, "schema_version")?;
            }
            if installed_schema == STORE_SCHEMA_VERSION_V6 {
                migrate_store_schema_v6_to_v7(&mut destination, self)?;
                installed_schema = metadata(&destination, "schema_version")?;
            }
            if installed_schema == STORE_SCHEMA_VERSION_V7 {
                migrate_store_schema_v7_to_v8(&mut destination, self)?;
                installed_schema = metadata(&destination, "schema_version")?;
            }
            ensure!(
                installed_schema == STORE_SCHEMA_VERSION,
                "installed snapshot store schema is unsupported"
            );
            validate_auth_prune_metadata(&destination)?;
            let checkpoint =
                destination.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })?;
            ensure!(
                checkpoint.0 == 0,
                "installed snapshot WAL checkpoint was blocked by an active reader"
            );
            drop(destination);
            fs::File::open(&self.database_path)?.sync_all()?;
            let wal = sqlite_sidecar(&self.database_path, "-wal");
            if wal.exists() {
                fs::File::open(&wal)?.sync_all()?;
            }
            sync_parent(&self.database_path)?;

            let installed = self.validate_snapshot_database(
                &self.database_path,
                expected_height,
                expected_app_hash,
            )?;
            ensure!(
                (installed.height, installed.app_hash) == (restored.height, restored.app_hash),
                "installed snapshot differs from its prevalidated source"
            );
            Ok(installed)
        })();
        match post_install {
            Ok(installed) => {
                self.refresh_status_best_effort(&installed);
                Ok(installed)
            }
            Err(error) => fail_stop_after_snapshot_install(error),
        }
    }

    pub(super) fn validate_snapshot_database(
        &self,
        path: &Path,
        expected_height: u64,
        expected_app_hash: [u8; 32],
    ) -> Result<AppState> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("open untrusted SQLite snapshot {}", path.display()))?;
        connection.execute_batch(
            "
            PRAGMA trusted_schema=OFF;
            PRAGMA query_only=ON;
            ",
        )?;
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        ensure!(integrity == "ok", "SQLite snapshot quick_check failed");
        validate_snapshot_schema(&connection)?;
        validate_foreign_key_integrity(&connection)?;
        validate_storage_resource_bounds(&connection)?;
        let store_schema = self.verify_compatible_database_bindings(&connection)?;
        ensure!(
            metadata(&connection, "height")? == expected_height.to_string()
                && metadata(&connection, "app_hash_hex")? == hex::encode(expected_app_hash),
            "SQLite snapshot trusted head mismatch"
        );
        let root_count = connection.query_row("SELECT COUNT(*) FROM auth_roots", [], |row| {
            row.get::<_, u64>(0)
        })?;
        let stale_count =
            connection.query_row("SELECT COUNT(*) FROM auth_stale_nodes", [], |row| {
                row.get::<_, u64>(0)
            })?;
        let stale_value_count = if store_schema != LEGACY_STORE_SCHEMA_VERSION {
            connection.query_row("SELECT COUNT(*) FROM auth_stale_values", [], |row| {
                row.get::<_, u64>(0)
            })?
        } else {
            0
        };
        ensure!(
            root_count == 1 && stale_count == 0 && stale_value_count == 0,
            "SQLite snapshot must contain latest-only authenticated history"
        );
        if store_schema != LEGACY_STORE_SCHEMA_VERSION {
            ensure!(
                optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
                    == Some(expected_height),
                "SQLite snapshot authenticated query floor is not latest-only"
            );
            ensure!(
                optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?.is_none(),
                "SQLite snapshot contains unfinished authenticated maintenance"
            );
        }
        if store_schema == STORE_SCHEMA_VERSION
            || store_schema == STORE_SCHEMA_VERSION_V7
            || store_schema == STORE_SCHEMA_VERSION_V6
        {
            let jobs =
                connection.query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
                    row.get::<_, u64>(0)
                })?;
            let outbox = connection.query_row(
                "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                jobs == 0 && outbox == 0,
                "SQLite snapshot contains node-local native validation jobs or callbacks"
            );
        } else if store_schema == STORE_SCHEMA_VERSION_V5 {
            let reservations = connection.query_row(
                "SELECT COUNT(*) FROM native_validation_reservations",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                reservations == 0,
                "SQLite schema-v5 snapshot contains unreplayable native validation reservations"
            );
        }
        Self::validate_latest_only_auth_storage(&connection, expected_height)?;
        let restored = load_sqlite_state(&connection)?;
        ensure!(
            (restored.height, restored.app_hash) == (expected_height, expected_app_hash),
            "validated SQLite snapshot state differs from trusted head"
        );
        Ok(restored)
    }

    pub(super) fn load_snapshot_object(
        &self,
        path: &Path,
        object_key_hex: &str,
    ) -> Result<Option<StoredObject>> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("open validated SQLite snapshot {}", path.display()))?;
        connection.execute_batch(
            "
            PRAGMA trusted_schema=OFF;
            PRAGMA query_only=ON;
            ",
        )?;
        load_object(&connection, object_key_hex)
    }

    fn validate_latest_only_auth_storage(connection: &Connection, height: u64) -> Result<()> {
        let reader = SqliteAuthReader { connection };
        let root_path: NibblePath = std::iter::empty().collect();
        let mut stack = vec![NodeKey::new(height, root_path)];
        let mut reachable_nodes = 0_u64;
        let mut reachable_leaves = 0_u64;
        while let Some(node_key) = stack.pop() {
            ensure!(
                node_key.version() <= height,
                "SQLite snapshot contains a future-version reachable node"
            );
            let node = reader
                .get_node_option(&node_key)?
                .context("SQLite snapshot is missing a reachable JMT node")?;
            reachable_nodes = reachable_nodes
                .checked_add(1)
                .context("reachable JMT node count overflow")?;
            match node {
                Node::Null => {}
                Node::Leaf(leaf) => {
                    reachable_leaves = reachable_leaves
                        .checked_add(1)
                        .context("reachable JMT leaf count overflow")?;
                    let preimage = reader
                        .preimage(leaf.key_hash())?
                        .context("reachable JMT leaf is missing its preimage")?;
                    ensure!(
                        authenticated_key_hash(&preimage)? == leaf.key_hash(),
                        "reachable JMT leaf preimage hash mismatch"
                    );
                }
                Node::Internal(internal) => {
                    for (nibble, child) in internal.children_sorted() {
                        ensure!(
                            child.version <= height,
                            "SQLite snapshot contains a future-version JMT child"
                        );
                        let path = node_key
                            .nibble_path()
                            .nibbles()
                            .chain(std::iter::once(nibble))
                            .collect();
                        stack.push(NodeKey::new(child.version, path));
                    }
                }
            }
        }
        let stored_nodes = connection.query_row("SELECT COUNT(*) FROM auth_nodes", [], |row| {
            row.get::<_, u64>(0)
        })?;
        let stored_preimages =
            connection.query_row("SELECT COUNT(*) FROM auth_preimages", [], |row| {
                row.get::<_, u64>(0)
            })?;
        let stored_values =
            connection.query_row("SELECT COUNT(*) FROM auth_values", [], |row| {
                row.get::<_, u64>(0)
            })?;
        ensure!(
            stored_nodes == reachable_nodes
                && stored_preimages == reachable_leaves
                && stored_values == reachable_leaves,
            "SQLite snapshot contains unreachable authenticated rows"
        );

        let mut statement = connection
            .prepare("SELECT key_hash, version_be, value, is_deleted FROM auth_values")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (key_hash, version, value, is_deleted) = row?;
            ensure!(
                key_hash.len() == 32
                    && decode_version_be(&version)? <= height
                    && value.is_some()
                    && is_deleted == 0,
                "SQLite snapshot contains a non-canonical latest value"
            );
            let preimage_exists = connection
                .query_row(
                    "SELECT 1 FROM auth_preimages WHERE key_hash=?1",
                    params![key_hash],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            ensure!(
                preimage_exists,
                "SQLite snapshot value has no reachable preimage"
            );
        }
        Ok(())
    }

    fn with_database_path(&self, database_path: PathBuf) -> Self {
        Self {
            status_path: database_path.with_extension("status-cache-unused"),
            database_path,
            chain_id: self.chain_id.clone(),
            signer_policy_hash_hex: self.signer_policy_hash_hex.clone(),
            writer_gate: Arc::new(Mutex::new(())),
            writer_waiters: Arc::new(AtomicUsize::new(0)),
            maintenance_gate: Arc::new(Mutex::new(())),
            active_snapshot_pins: Arc::new(AtomicUsize::new(0)),
            namespace_owner: Arc::clone(&self.namespace_owner),
        }
    }

    pub(super) fn persist_transition(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        query_floor: Version,
    ) -> Result<()> {
        self.persist_transition_inner(current, pending, query_floor, None)
    }

    #[cfg(test)]
    pub(super) fn persist_transition_with_failpoint(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        failpoint: StoreFailpoint,
    ) -> Result<()> {
        self.persist_transition_inner(current, pending, 0, Some(failpoint))
    }

    fn persist_transition_inner(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        query_floor: Version,
        #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<StoreFailpoint>,
    ) -> Result<()> {
        ensure!(
            pending.height == current.height.saturating_add(1),
            "application store height transition is not contiguous"
        );
        ensure!(
            pending.auth_update.version == pending.height,
            "authenticated update version differs from pending height"
        );
        ensure!(
            query_floor <= pending.height,
            "authenticated query floor exceeds pending height"
        );

        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, current)?;
        ensure!(
            latest_auth_version(&transaction)? == Some(current.height)
                && auth_root(&transaction, current.height)?.map(Into::<[u8; 32]>::into)
                    == Some(current.app_hash),
            "authenticated tree head differs from committed application head"
        );
        validate_planned_production_poco_projection(
            &transaction,
            Some(current.height),
            &pending.auth_update,
        )?;
        for object in pending.delta.objects.values() {
            upsert_object(&transaction, object)?;
        }
        for command_id in &pending.delta.command_ids {
            ensure!(
                !current.command_ids.contains(command_id),
                "pending command ID already exists in committed state"
            );
            transaction.execute(
                "INSERT INTO command_ids(command_id) VALUES (?1)",
                params![command_id],
            )?;
        }
        for (signer_id, nonce) in &pending.delta.signer_nonces {
            ensure!(
                !current.signer_nonces.contains(&(signer_id.clone(), *nonce)),
                "pending signer nonce already exists in committed state"
            );
            transaction.execute(
                "INSERT INTO signer_nonces(signer_id, nonce) VALUES (?1, ?2)",
                params![signer_id, nonce.to_be_bytes().as_slice()],
            )?;
        }
        let lifecycle = pending
            .delta
            .validator_lifecycle
            .as_ref()
            .or(current.validator_lifecycle.as_ref())
            .context("cannot persist state before validator lifecycle initialization")?;
        write_validator_lifecycle(&transaction, lifecycle)?;
        ensure!(
            <[u8; 32]>::from(pending.auth_update.root_hash) == pending.app_hash,
            "pending AppHash differs from authenticated tree root"
        );
        persist_auth_update(&transaction, &pending.auth_update)?;
        write_head_values(&transaction, pending.height, pending.app_hash)?;
        advance_auth_query_floor(&transaction, query_floor)?;
        #[cfg(test)]
        if failpoint == Some(StoreFailpoint::BeforeSqlCommit) {
            return Err(anyhow!("injected failure before SQLite COMMIT"));
        }
        transaction.commit()?;
        #[cfg(test)]
        if failpoint == Some(StoreFailpoint::AfterSqlCommitBeforeStatus) {
            return Err(anyhow!(
                "injected failure after SQLite COMMIT before status refresh"
            ));
        }
        self.refresh_status_values_best_effort(pending.height, pending.app_hash);
        Ok(())
    }

    pub(super) fn replace_empty_state(
        &self,
        expected: &AppState,
        state: &AppState,
        auth_update: &PlannedAuthUpdate,
    ) -> Result<()> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "replacement expected state must be empty"
        );
        ensure!(state.pending.is_none(), "cannot persist pending state");
        ensure!(
            auth_update.version == state.height
                && <[u8; 32]>::from(auth_update.root_hash) == state.app_hash,
            "replacement authenticated update does not match app head"
        );
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, expected)?;
        validate_planned_production_poco_projection(
            &transaction,
            latest_auth_version(&transaction)?,
            auth_update,
        )?;
        replace_domain_state(&transaction, state)?;
        clear_auth_tree(&transaction)?;
        persist_auth_update(&transaction, auth_update)?;
        write_head_values(&transaction, state.height, state.app_hash)?;
        transaction.commit()?;
        self.refresh_status_best_effort(state);
        Ok(())
    }

    pub(super) fn replace_empty_state_from_tree(
        &self,
        expected: &AppState,
        state: &AppState,
        auth_tree: &InMemoryAuthTree,
    ) -> Result<()> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "snapshot replacement expected state must be empty"
        );
        ensure!(state.pending.is_none(), "cannot persist pending state");
        ensure!(
            auth_tree.latest_version() == Some(state.height)
                && auth_tree
                    .root_hash(state.height)
                    .map(Into::<[u8; 32]>::into)
                    == Some(state.app_hash),
            "replacement authenticated state does not match app head"
        );
        validate_in_memory_authenticated_domain_projection(state, auth_tree)?;
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, expected)?;
        replace_domain_state(&transaction, state)?;
        clear_auth_tree(&transaction)?;
        persist_full_auth_tree(&transaction, auth_tree)?;
        write_head_values(&transaction, state.height, state.app_hash)?;
        transaction.commit()?;
        self.refresh_status_best_effort(state);
        Ok(())
    }

    fn connect(&self) -> Result<Connection> {
        self.require_namespace_owner_v0()?;
        if let Some(parent) = self.database_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create application store directory {}", parent.display())
            })?;
        }
        let initialize = !self.database_path.exists();
        let mut connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("open application store {}", self.database_path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        if initialize {
            connection.execute_batch("PRAGMA journal_mode=WAL;")?;
        }
        connection.execute_batch(
            "
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            ",
        )?;
        if initialize {
            connection.execute_batch(STORE_SCHEMA_SQL)?;
            connection.execute_batch(NATIVE_VALIDATION_JOURNAL_SCHEMA_V0_SQL)?;
        }
        let schema: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match schema.as_deref() {
            Some(schema) => ensure!(
                schema == STORE_SCHEMA_VERSION
                    || schema == STORE_SCHEMA_VERSION_V7
                    || schema == STORE_SCHEMA_VERSION_V6
                    || schema == STORE_SCHEMA_VERSION_V5
                    || schema == STORE_SCHEMA_VERSION_V4
                    || schema == LEGACY_STORE_SCHEMA_VERSION,
                "unsupported application store schema version"
            ),
            None => {
                ensure!(
                    initialize,
                    "existing application store is missing schema_version"
                );
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?1)",
                    params![STORE_SCHEMA_VERSION],
                )?;
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES (?1, '0')",
                    params![AUTH_QUERY_FLOOR_KEY],
                )?;
            }
        }
        if schema.as_deref() == Some(LEGACY_STORE_SCHEMA_VERSION) {
            migrate_store_schema_v3_to_v4(&mut connection)?;
        }
        if metadata(&connection, "schema_version")? == STORE_SCHEMA_VERSION_V4 {
            migrate_store_schema_v4_to_v5(&mut connection)?;
        }
        if metadata(&connection, "schema_version")? == STORE_SCHEMA_VERSION_V5 {
            migrate_store_schema_v5_to_v6(&mut connection)?;
        }
        if metadata(&connection, "schema_version")? == STORE_SCHEMA_VERSION_V6 {
            migrate_store_schema_v6_to_v7(&mut connection, self)?;
        }
        if metadata(&connection, "schema_version")? == STORE_SCHEMA_VERSION_V7 {
            migrate_store_schema_v7_to_v8(&mut connection, self)?;
        }
        if initialize {
            ensure_metadata_binding(&connection, "chain_id", &self.chain_id)?;
            ensure_metadata_binding(&connection, "app_version", &APP_VERSION.to_string())?;
            ensure_metadata_binding(
                &connection,
                "authorized_signers_hash_hex",
                &self.signer_policy_hash_hex,
            )?;
            ensure_metadata_binding(&connection, "auth_tree", "jmt-sha256-v0.12.0")?;
            ensure_metadata_binding(&connection, "auth_codec", "borsh-v1")?;
        } else {
            self.verify_database_bindings(&connection)?;
        }
        validate_auth_prune_metadata(&connection)?;
        self.require_namespace_owner_v0()?;
        Ok(connection)
    }

    fn connect_read(&self) -> Result<Connection> {
        self.require_namespace_owner_v0()?;
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| {
            format!(
                "open application store read-only {}",
                self.database_path.display()
            )
        })?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "
            PRAGMA trusted_schema=OFF;
            PRAGMA query_only=ON;
            ",
        )?;
        self.verify_database_bindings(&connection)?;
        self.require_namespace_owner_v0()?;
        Ok(connection)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn connect_authenticated_runtime_read_v0(
        &self,
    ) -> std::result::Result<Connection, AuthenticatedRuntimeReadFailureV0> {
        self.validate_namespace_owner_v0().map_err(|_| {
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage: AuthenticatedRuntimeReadStageV0::OpenDatabase,
                sqlite: None,
                reason: "application store namespace owner changed",
            }
        })?;
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| {
            classify_sqlite_authenticated_read_failure_v0(
                AuthenticatedRuntimeReadStageV0::OpenDatabase,
                &error,
            )
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| {
                classify_sqlite_authenticated_read_failure_v0(
                    AuthenticatedRuntimeReadStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        connection
            .execute_batch(
                "
                PRAGMA trusted_schema=OFF;
                PRAGMA query_only=ON;
                ",
            )
            .map_err(|error| {
                classify_sqlite_authenticated_read_failure_v0(
                    AuthenticatedRuntimeReadStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        self.validate_namespace_owner_v0().map_err(|_| {
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage: AuthenticatedRuntimeReadStageV0::ConfigureDatabase,
                sqlite: None,
                reason: "application store namespace owner changed",
            }
        })?;
        Ok(connection)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn validate_authenticated_runtime_snapshot_head_v0(
        &self,
        connection: &Connection,
    ) -> std::result::Result<(Version, RootHash), AuthenticatedRuntimeReadFailureV0> {
        self.verify_authenticated_runtime_database_bindings_v0(connection)?;
        let height = authenticated_runtime_head_v0(connection)?;
        let latest_version = latest_auth_version(connection).map_err(|error| {
            classify_authenticated_read_anyhow_v0(
                AuthenticatedRuntimeReadStageV0::ReadRoot,
                &error,
                "persisted authenticated root version is invalid",
            )
        })?;
        if latest_version != Some(height) {
            return Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    sqlite: None,
                    reason: "latest authenticated root version differs from committed height",
                },
            );
        }
        let app_hash_hex = authenticated_runtime_required_metadata_v0(
            connection,
            "app_hash_hex",
            AuthenticatedRuntimeReadStageV0::ReadHead,
            "application store is missing committed app hash",
        )?;
        let app_hash = trnm_finality_types::decode_hash32(
            "authenticated runtime snapshot app_hash",
            &app_hash_hex,
        )
        .map_err(
            |_| AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::ReadHead,
                sqlite: None,
                reason: "application store committed app hash is not canonical lowercase hash32",
            },
        )?;
        require_authenticated_query_floor_v0(connection, height, height)?;
        let root_hash = authenticated_runtime_root_v0(connection, height)?.ok_or(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                sqlite: None,
                reason: "committed head is missing its authenticated root",
            },
        )?;
        if root_hash != RootHash(app_hash) {
            return Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    sqlite: None,
                    reason: "committed app hash differs from authenticated head root",
                },
            );
        }
        Ok((height, root_hash))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn verify_authenticated_runtime_database_bindings_v0(
        &self,
        connection: &Connection,
    ) -> std::result::Result<(), AuthenticatedRuntimeReadFailureV0> {
        let stage = AuthenticatedRuntimeReadStageV0::ValidateBindings;
        let schema_version = authenticated_runtime_required_metadata_v0(
            connection,
            "schema_version",
            stage,
            "application store is missing schema_version",
        )?;
        if schema_version != STORE_SCHEMA_VERSION {
            return Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage,
                    sqlite: None,
                    reason: "application store schema is not the active runtime schema",
                },
            );
        }
        let app_version = APP_VERSION.to_string();
        let bindings = [
            ("chain_id", self.chain_id.as_str()),
            ("app_version", app_version.as_str()),
            (
                "authorized_signers_hash_hex",
                self.signer_policy_hash_hex.as_str(),
            ),
            ("auth_tree", "jmt-sha256-v0.12.0"),
            ("auth_codec", "borsh-v1"),
        ];
        for (key, expected) in bindings {
            let actual = authenticated_runtime_required_metadata_v0(
                connection,
                key,
                stage,
                "application store is missing a required runtime binding",
            )?;
            if actual != expected {
                return Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage,
                        sqlite: None,
                        reason: "application store runtime binding differs from configuration",
                    },
                );
            }
        }
        Ok(())
    }

    fn connect_maintenance(&self) -> Result<Connection> {
        self.require_namespace_owner_v0()?;
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| {
            format!(
                "open application store maintenance connection {}",
                self.database_path.display()
            )
        })?;
        connection.busy_timeout(Duration::ZERO)?;
        connection.execute_batch(
            "
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            ",
        )?;
        self.verify_database_bindings(&connection)?;
        validate_auth_prune_metadata(&connection)?;
        self.require_namespace_owner_v0()?;
        Ok(connection)
    }

    fn probe_existing_database(&self) -> Result<()> {
        self.require_namespace_owner_v0()?;
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| {
            format!(
                "open existing application store read-only {}",
                self.database_path.display()
            )
        })?;
        validate_snapshot_schema(&connection)?;
        validate_foreign_key_integrity(&connection)?;
        validate_storage_resource_bounds(&connection)?;
        self.verify_compatible_database_bindings(&connection)?;
        self.require_namespace_owner_v0()?;
        Ok(())
    }

    fn verify_database_bindings(&self, connection: &Connection) -> Result<()> {
        ensure!(
            self.verify_compatible_database_bindings(connection)? == STORE_SCHEMA_VERSION,
            "existing application store requires schema migration"
        );
        Ok(())
    }

    fn verify_compatible_database_bindings(&self, connection: &Connection) -> Result<String> {
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .context("existing application store is missing or cannot read schema_version")?;
        ensure!(
            schema_version == STORE_SCHEMA_VERSION
                || schema_version == STORE_SCHEMA_VERSION_V7
                || schema_version == STORE_SCHEMA_VERSION_V6
                || schema_version == STORE_SCHEMA_VERSION_V5
                || schema_version == STORE_SCHEMA_VERSION_V4
                || schema_version == LEGACY_STORE_SCHEMA_VERSION,
            "existing application store schema version is unsupported"
        );
        let app_version = APP_VERSION.to_string();
        let bindings = [
            ("chain_id", self.chain_id.as_str()),
            ("app_version", app_version.as_str()),
            (
                "authorized_signers_hash_hex",
                self.signer_policy_hash_hex.as_str(),
            ),
            ("auth_tree", "jmt-sha256-v0.12.0"),
            ("auth_codec", "borsh-v1"),
        ];
        for (key, expected) in bindings {
            let actual: String = connection
                .query_row(
                    "SELECT value FROM metadata WHERE key=?1",
                    params![key],
                    |row| row.get(0),
                )
                .with_context(|| {
                    format!("existing application store is missing or cannot read {key}")
                })?;
            ensure!(
                actual == expected,
                "existing application store {key} differs from configured value"
            );
        }
        Ok(schema_version)
    }

    fn has_committed_state(&self, connection: &Connection) -> Result<bool> {
        Ok(connection
            .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .is_some())
    }

    fn refresh_status_best_effort(&self, state: &AppState) {
        self.refresh_status_values_best_effort(state.height, state.app_hash);
    }

    fn refresh_status_values_best_effort(&self, height: u64, app_hash: [u8; 32]) {
        if let Err(error) = self.write_status_values(height, app_hash) {
            eprintln!(
                "[trnm-cometbft-app] SQLite commit is authoritative; failed to refresh status cache: {error:#}"
            );
        }
    }

    fn write_status_values(&self, height: u64, app_hash: [u8; 32]) -> Result<()> {
        let status = PersistedStatusV2 {
            schema: STATUS_SCHEMA_V2,
            app_version: APP_VERSION,
            height,
            app_hash_hex: hex::encode(app_hash),
        };
        persist_state_bytes(&self.status_path, &serde_json::to_vec(&status)?)
    }
}

fn verify_database_head(transaction: &Transaction<'_>, current: &AppState) -> Result<()> {
    let stored_height: Option<String> = transaction
        .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
            row.get(0)
        })
        .optional()?;
    if current.height == 0 && stored_height.is_none() {
        return Ok(());
    }
    let stored_height = stored_height
        .ok_or_else(|| anyhow!("application store is missing committed height"))?
        .parse::<u64>()
        .context("parse application store height")?;
    let stored_hash: String = transaction
        .query_row(
            "SELECT value FROM metadata WHERE key='app_hash_hex'",
            [],
            |row| row.get(0),
        )
        .context("application store is missing committed app hash")?;
    ensure!(
        stored_height == current.height && stored_hash == hex::encode(current.app_hash),
        "application store head differs from in-memory committed state"
    );
    Ok(())
}

fn validate_planned_production_poco_projection(
    transaction: &Transaction<'_>,
    source_version: Option<Version>,
    update: &PlannedAuthUpdate,
) -> Result<()> {
    let expected_version = source_version.map_or(0, |version| version.saturating_add(1));
    ensure!(
        update.version == expected_version,
        "planned PoCO validation version is not exact-next"
    );
    let mut touches_poco = false;
    for preimage in update.preimages().values() {
        if poco_snapshot_key_components(preimage)?.is_some() {
            touches_poco = true;
        }
    }
    if !touches_poco {
        return Ok(());
    }

    let reader = SqliteAuthReader {
        connection: transaction,
    };
    let mut live = BTreeMap::new();
    if let Some(version) = source_version {
        let root_hash = auth_root(transaction, version)?
            .with_context(|| format!("missing source root for PoCO plan at version {version}"))?;
        // The iterator requires Arc even though this transaction-bound reader
        // never escapes the current thread.
        #[allow(clippy::arc_with_non_send_sync)]
        let iterator_reader = Arc::new(SqliteAuthReader {
            connection: transaction,
        });
        let iterator =
            JellyfishMerkleIterator::new(Arc::clone(&iterator_reader), version, KeyHash([0; 32]))
                .with_context(|| format!("open source PoCO iterator at version {version}"))?;
        for item in iterator {
            let (hash, value) =
                item.with_context(|| format!("iterate source PoCO state at version {version}"))?;
            let preimage = iterator_reader
                .preimage(hash)?
                .with_context(|| format!("missing PoCO source key preimage {hash:?}"))?;
            if poco_snapshot_key_components(&preimage)?.is_none() {
                continue;
            }
            let proof = prove_with_reader(
                iterator_reader.as_ref(),
                version,
                root_hash,
                preimage.clone(),
            )?;
            ensure!(
                proof.value.as_deref() == Some(value.as_slice())
                    && verify_ics23_membership(&proof, &value),
                "source PoCO leaf failed authenticated verification"
            );
            ensure!(
                live.insert(preimage, value).is_none(),
                "source PoCO namespace contains a duplicate physical key"
            );
        }
    }

    for ((version, hash), value) in update.tree_update_batch.node_batch.values() {
        ensure!(
            *version == update.version,
            "planned update contains a value at the wrong version"
        );
        let preimage = match update.preimages().get(hash) {
            Some(preimage) => preimage.clone(),
            None => reader
                .preimage(*hash)?
                .with_context(|| format!("missing planned authenticated key preimage {hash:?}"))?,
        };
        if poco_snapshot_key_components(&preimage)?.is_none() {
            continue;
        }
        match value {
            Some(value) => {
                live.insert(preimage, value.clone());
            }
            None => {
                live.remove(&preimage);
            }
        }
    }
    take_and_validate_production_poco_projection_v0(update.version, &mut live)?;
    ensure!(
        live.is_empty(),
        "planned PoCO projection left unclassified leaves"
    );
    Ok(())
}

/// Verifies the complete physical PoCO namespace at one already-authenticated
/// version/root using the caller's existing SQLite transaction.
///
/// Keeping this connection-bound primitive separate prevents native payload
/// validation from accidentally reopening the latest head or consulting the
/// projection cache after its exact parent snapshot has been fixed.
fn load_production_poco_projection_from_connection_v0(
    connection: &Connection,
    version: Version,
    root_hash: RootHash,
) -> Result<Option<ProductionPocoProjectionV0>> {
    #[allow(clippy::arc_with_non_send_sync)]
    let reader = Arc::new(SqliteAuthReader { connection });
    let iterator = JellyfishMerkleIterator::new(Arc::clone(&reader), version, KeyHash([0; 32]))
        .with_context(|| format!("open PoCO projection iterator at version {version}"))?;
    let mut live = BTreeMap::new();
    for item in iterator {
        let (hash, value) =
            item.with_context(|| format!("iterate PoCO projection at version {version}"))?;
        let preimage = reader
            .preimage(hash)?
            .with_context(|| format!("missing PoCO key preimage {hash:?}"))?;
        if poco_snapshot_key_components(&preimage)?.is_none() {
            continue;
        }
        let proof = prove_with_reader(reader.as_ref(), version, root_hash, preimage.clone())?;
        ensure!(
            proof.value.as_deref() == Some(value.as_slice())
                && verify_ics23_membership(&proof, &value),
            "PoCO projection leaf failed authenticated verification"
        );
        ensure!(
            live.insert(preimage, value).is_none(),
            "duplicate PoCO physical key"
        );
    }
    let projection = take_and_validate_production_poco_projection_v0(version, &mut live)?;
    ensure!(live.is_empty(), "unclassified PoCO physical leaves");
    Ok(projection)
}

fn write_head_values(transaction: &Transaction<'_>, height: u64, app_hash: [u8; 32]) -> Result<()> {
    for (key, value) in [
        ("height", height.to_string()),
        ("app_hash_hex", hex::encode(app_hash)),
    ] {
        transaction.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}

fn advance_auth_query_floor(transaction: &Transaction<'_>, requested: Version) -> Result<()> {
    let current = optional_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY)?
        .context("application store is missing authenticated query floor")?;
    if requested <= current {
        return Ok(());
    }
    write_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY, requested)?;
    write_metadata_version(transaction, AUTH_PRUNE_TARGET_KEY, requested)
}

fn clear_auth_tree(transaction: &Transaction<'_>) -> Result<()> {
    transaction.execute("DELETE FROM auth_nodes", [])?;
    transaction.execute("DELETE FROM auth_values", [])?;
    transaction.execute("DELETE FROM auth_preimages", [])?;
    transaction.execute("DELETE FROM auth_stale_nodes", [])?;
    transaction.execute("DELETE FROM auth_stale_values", [])?;
    transaction.execute("DELETE FROM auth_roots", [])?;
    write_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY, 0)?;
    transaction.execute(
        "DELETE FROM metadata WHERE key=?1",
        params![AUTH_PRUNE_TARGET_KEY],
    )?;
    Ok(())
}

fn replace_domain_state(transaction: &Transaction<'_>, state: &AppState) -> Result<()> {
    transaction.execute("DELETE FROM objects", [])?;
    transaction.execute("DELETE FROM command_ids", [])?;
    transaction.execute("DELETE FROM signer_nonces", [])?;
    transaction.execute("DELETE FROM validator_lifecycle", [])?;
    for object in state.objects.values() {
        upsert_object(transaction, object)?;
    }
    for command_id in &state.command_ids {
        transaction.execute(
            "INSERT INTO command_ids(command_id) VALUES (?1)",
            params![command_id],
        )?;
    }
    for (signer_id, nonce) in &state.signer_nonces {
        transaction.execute(
            "INSERT INTO signer_nonces(signer_id, nonce) VALUES (?1, ?2)",
            params![signer_id, nonce.to_be_bytes().as_slice()],
        )?;
    }
    if let Some(lifecycle) = &state.validator_lifecycle {
        write_validator_lifecycle(transaction, lifecycle)?;
    }
    Ok(())
}

fn persist_full_auth_tree(
    transaction: &Transaction<'_>,
    auth_tree: &InMemoryAuthTree,
) -> Result<()> {
    for (node_key, node) in auth_tree.nodes() {
        transaction.execute(
            "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
            params![
                borsh::to_vec(node_key).context("encode JMT node key")?,
                borsh::to_vec(node).context("encode JMT node")?,
            ],
        )?;
    }
    for ((key_hash, version), value) in auth_tree.values() {
        transaction.execute(
            "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key_hash.0.as_slice(),
                version.to_be_bytes().as_slice(),
                value.as_deref(),
                i64::from(value.is_none()),
            ],
        )?;
    }
    rebuild_auth_stale_values(transaction)?;
    for (key_hash, preimage) in auth_tree.preimages() {
        transaction.execute(
            "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (?1, ?2)",
            params![key_hash.0.as_slice(), preimage],
        )?;
    }
    for stale in auth_tree.stale_nodes() {
        transaction.execute(
            "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key)
             VALUES (?1, ?2)",
            params![
                stale.stale_since_version.to_be_bytes().as_slice(),
                borsh::to_vec(&stale.node_key).context("encode stale JMT node key")?,
            ],
        )?;
    }
    for (version, root) in auth_tree.roots() {
        transaction.execute(
            "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
            params![version.to_be_bytes().as_slice(), root.0.as_slice(),],
        )?;
    }
    Ok(())
}

fn persist_auth_update(transaction: &Transaction<'_>, update: &PlannedAuthUpdate) -> Result<()> {
    for (node_key, node) in update.tree_update_batch.node_batch.nodes() {
        transaction.execute(
            "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
            params![
                borsh::to_vec(node_key).context("encode JMT node key")?,
                borsh::to_vec(node).context("encode JMT node")?,
            ],
        )?;
    }
    for ((version, key_hash), value) in update.tree_update_batch.node_batch.values() {
        let previous_version: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT version_be
                 FROM auth_values
                 WHERE key_hash=?1 AND version_be<?2
                 ORDER BY version_be DESC
                 LIMIT 1",
                params![key_hash.0.as_slice(), version.to_be_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(previous_version) = previous_version {
            transaction.execute(
                "INSERT INTO auth_stale_values(
                    stale_since_version_be,
                    key_hash,
                    version_be
                 ) VALUES (?1, ?2, ?3)",
                params![
                    version.to_be_bytes().as_slice(),
                    key_hash.0.as_slice(),
                    previous_version,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key_hash.0.as_slice(),
                version.to_be_bytes().as_slice(),
                value.as_deref(),
                i64::from(value.is_none()),
            ],
        )?;
    }
    for (key_hash, preimage) in update.preimages() {
        transaction.execute(
            "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (?1, ?2)
             ON CONFLICT(key_hash) DO NOTHING",
            params![key_hash.0.as_slice(), preimage],
        )?;
        let stored: Vec<u8> = transaction.query_row(
            "SELECT key_preimage FROM auth_preimages WHERE key_hash=?1",
            params![key_hash.0.as_slice()],
            |row| row.get(0),
        )?;
        ensure!(
            stored == *preimage,
            "authenticated key hash collision in persistent preimage store"
        );
    }
    for stale in &update.tree_update_batch.stale_node_index_batch {
        transaction.execute(
            "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key)
             VALUES (?1, ?2)",
            params![
                stale.stale_since_version.to_be_bytes().as_slice(),
                borsh::to_vec(&stale.node_key).context("encode stale JMT node key")?,
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
        params![
            update.version.to_be_bytes().as_slice(),
            update.root_hash.0.as_slice(),
        ],
    )?;
    Ok(())
}

fn decode_version_be(bytes: &[u8]) -> Result<Version> {
    Ok(u64::from_be_bytes(<[u8; 8]>::try_from(bytes).map_err(
        |_| anyhow!("persisted JMT version is not 8 bytes"),
    )?))
}

fn rebuild_auth_stale_values(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM auth_stale_values", [])?;
    connection.execute(
        "INSERT INTO auth_stale_values(
            stale_since_version_be,
            key_hash,
            version_be
         )
         SELECT next_version_be, key_hash, version_be
         FROM (
             SELECT key_hash,
                    version_be,
                    LEAD(version_be) OVER (
                        PARTITION BY key_hash
                        ORDER BY version_be
                    ) AS next_version_be
             FROM auth_values
         )
         WHERE next_version_be IS NOT NULL",
        [],
    )?;
    Ok(())
}

fn upsert_object(transaction: &Transaction<'_>, object: &StoredObject) -> Result<()> {
    transaction.execute(
        "INSERT INTO objects(
            object_key_hex, object_type, version, value_hash_hex, value_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(object_key_hex) DO UPDATE SET
            object_type=excluded.object_type,
            version=excluded.version,
            value_hash_hex=excluded.value_hash_hex,
            value_bytes=excluded.value_bytes",
        params![
            object.object_key_hex,
            object.object_type,
            object.version.to_string(),
            object.value_hash_hex,
            object.value_bytes,
        ],
    )?;
    Ok(())
}

fn write_validator_lifecycle(
    transaction: &Transaction<'_>,
    lifecycle: &ValidatorLifecycleStateV1,
) -> Result<()> {
    lifecycle.validate()?;
    transaction.execute(
        "INSERT INTO validator_lifecycle(singleton, state_json) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET state_json=excluded.state_json",
        params![serde_json::to_vec(lifecycle)?],
    )?;
    Ok(())
}

fn verify_retained_lifecycle_proofs(
    connection: &Connection,
    height: Version,
    app_hash: [u8; 32],
    boundary: Version,
) -> Result<()> {
    ensure!(
        boundary <= height,
        "authenticated proof boundary exceeds the committed head"
    );
    let retained_root = auth_root(connection, height)?
        .context("authenticated maintenance removed the committed root")?;
    ensure!(
        <[u8; 32]>::from(retained_root) == app_hash,
        "authenticated maintenance changed the committed AppHash"
    );
    let lifecycle_bytes: Vec<u8> = connection.query_row(
        "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let reader = SqliteAuthReader { connection };
    let latest_proof = prove_with_reader(&reader, height, retained_root, validator_state_key()?)?;
    let latest_value = latest_proof
        .value
        .as_deref()
        .context("latest validator lifecycle proof is absent")?;
    let lifecycle_record = AuthenticatedObjectRecord::decode(latest_value)?;
    ensure!(
        lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
            && lifecycle_record.object_version <= height
            && lifecycle_record.value == lifecycle_bytes
            && verify_ics23_membership(&latest_proof, latest_value),
        "authenticated maintenance damaged the latest validator lifecycle proof"
    );
    if boundary < height {
        let boundary_root = auth_root(connection, boundary)?
            .context("authenticated maintenance removed the retention-boundary root")?;
        let boundary_proof =
            prove_with_reader(&reader, boundary, boundary_root, validator_state_key()?)?;
        let boundary_value = boundary_proof
            .value
            .as_deref()
            .context("retention-boundary lifecycle proof is absent")?;
        ensure!(
            verify_ics23_membership(&boundary_proof, boundary_value),
            "authenticated maintenance damaged the retention-boundary proof"
        );
    }
    Ok(())
}

fn load_sqlite_state(connection: &Connection) -> Result<AppState> {
    let height = metadata(connection, "height")?
        .parse::<u64>()
        .context("parse application store height")?;
    let app_hash = trnm_finality_types::decode_hash32(
        "application store app_hash",
        &metadata(connection, "app_hash_hex")?,
    )?;
    if let Some(query_floor) = optional_metadata_version(connection, AUTH_QUERY_FLOOR_KEY)? {
        ensure!(
            query_floor <= height && auth_root(connection, query_floor)?.is_some(),
            "application store authenticated query floor is invalid"
        );
        if let Some(target) = optional_metadata_version(connection, AUTH_PRUNE_TARGET_KEY)? {
            ensure!(
                target == query_floor,
                "application store authenticated prune target differs from its query floor"
            );
        }
    }
    validate_no_future_auth_rows(connection, height)?;
    if metadata(connection, "schema_version")? != LEGACY_STORE_SCHEMA_VERSION {
        validate_auth_stale_value_index(connection)?;
    }

    let lifecycle_bytes: Vec<u8> = connection
        .query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .context("application store is missing committed validator lifecycle")?;
    let validator_lifecycle: ValidatorLifecycleStateV1 =
        serde_json::from_slice(&lifecycle_bytes)
            .context("decode application store validator lifecycle")?;
    validator_lifecycle.validate()?;

    ensure!(
        latest_auth_version(connection)? == Some(height),
        "authenticated tree version differs from application height"
    );
    let root_hash = auth_root(connection, height)?
        .context("application store is missing authenticated root")?;
    ensure!(
        <[u8; 32]>::from(root_hash) == app_hash,
        "application store content does not match committed app hash"
    );

    let object_count = connection.query_row("SELECT COUNT(*) FROM objects", [], |row| {
        row.get::<_, u64>(0)
    })?;
    // JellyfishMerkleIterator's public API requires Arc even though this
    // connection-bound reader never leaves the current thread.
    #[allow(clippy::arc_with_non_send_sync)]
    let reader = Arc::new(SqliteAuthReader { connection });
    let iterator = JellyfishMerkleIterator::new(Arc::clone(&reader), height, KeyHash([0; 32]))
        .with_context(|| format!("open authenticated tree iterator at version {height}"))?;
    let lifecycle_key = validator_state_key()?;
    let mut object_leaves = 0_u64;
    let mut lifecycle_seen = false;
    let mut poco_leaves = BTreeMap::new();
    for entry in iterator {
        let (hash, value) =
            entry.with_context(|| format!("iterate authenticated tree at version {height}"))?;
        let preimage = reader
            .preimage(hash)?
            .with_context(|| format!("missing authenticated key preimage {hash:?}"))?;
        ensure!(
            authenticated_key_hash(&preimage)? == hash,
            "authenticated key preimage hash mismatch"
        );
        let proof = prove_with_reader(reader.as_ref(), height, root_hash, preimage.clone())?;
        ensure!(
            proof.value.as_deref() == Some(value.as_slice())
                && verify_ics23_membership(&proof, &value),
            "authenticated tree leaf failed root verification"
        );
        if preimage == lifecycle_key {
            ensure!(
                !lifecycle_seen,
                "authenticated state contains duplicate validator lifecycle"
            );
            let lifecycle_record = AuthenticatedObjectRecord::decode(&value)?;
            ensure!(
                lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
                    && lifecycle_record.object_version <= height
                    && lifecycle_record.value == lifecycle_bytes,
                "application store validator lifecycle differs from authenticated state"
            );
            lifecycle_seen = true;
            continue;
        }

        if poco_snapshot_key_components(&preimage)?.is_some() {
            ensure!(
                poco_leaves.insert(preimage, value).is_none(),
                "authenticated state contains duplicate PoCO physical key"
            );
            continue;
        }

        let object_key_hex = stored_object_key_preimage(&preimage)?;
        let object = load_object(connection, &object_key_hex)?.with_context(|| {
            format!("authenticated object {object_key_hex} is absent from the application store")
        })?;
        validate_object(&object)?;
        let expected =
            AuthenticatedObjectRecord::new(object.object_type, object.version, object.value_bytes)?
                .encode()?;
        ensure!(
            value == expected,
            "application store object {object_key_hex} differs from authenticated state"
        );
        object_leaves = object_leaves.saturating_add(1);
    }
    ensure!(
        lifecycle_seen,
        "authenticated state is missing validator lifecycle"
    );
    ensure!(
        object_leaves == object_count,
        "application store contains objects absent from authenticated state"
    );
    take_and_validate_production_poco_projection_v0(height, &mut poco_leaves)?;
    ensure!(
        poco_leaves.is_empty(),
        "application store contains unclassified PoCO leaves"
    );

    Ok(AppState {
        height,
        app_hash,
        objects: std::collections::BTreeMap::new(),
        command_ids: std::collections::BTreeSet::new(),
        signer_nonces: std::collections::BTreeSet::new(),
        validator_lifecycle: Some(validator_lifecycle),
        pending: None,
    })
}

fn validate_no_future_auth_rows(connection: &Connection, height: u64) -> Result<()> {
    {
        let mut statement = connection.prepare("SELECT node_key FROM auth_nodes")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let node_key: NodeKey =
                borsh::from_slice(&row?).context("decode persisted JMT node key")?;
            ensure!(
                node_key.version() <= height,
                "application store contains a future-version JMT node"
            );
        }
    }
    let mut version_columns = vec![
        ("auth_values", "version_be"),
        ("auth_roots", "version_be"),
        ("auth_stale_nodes", "stale_since_version_be"),
    ];
    if metadata(connection, "schema_version")? != LEGACY_STORE_SCHEMA_VERSION {
        version_columns.extend([
            ("auth_stale_values", "stale_since_version_be"),
            ("auth_stale_values", "version_be"),
        ]);
    }
    for (table, column) in version_columns {
        let query = format!("SELECT {column} FROM {table}");
        let mut statement = connection.prepare(&query)?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            ensure!(
                decode_version_be(&row?)? <= height,
                "application store contains a future-version row in {table}"
            );
        }
    }
    Ok(())
}

fn validate_auth_stale_value_index(connection: &Connection) -> Result<()> {
    let missing_or_wrong = connection
        .query_row(
            "WITH ordered AS (
                 SELECT key_hash,
                        version_be,
                        LEAD(version_be) OVER (
                            PARTITION BY key_hash
                            ORDER BY version_be
                        ) AS next_version_be
                 FROM auth_values
             )
             SELECT 1
             FROM ordered
             LEFT JOIN auth_stale_values AS stale
               ON stale.key_hash=ordered.key_hash
              AND stale.version_be=ordered.version_be
             WHERE ordered.next_version_be IS NOT NULL
               AND (
                   stale.stale_since_version_be IS NULL
                   OR stale.stale_since_version_be<>ordered.next_version_be
               )
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    ensure!(
        !missing_or_wrong,
        "application store authenticated stale-value index is incomplete"
    );
    let unexpected = connection
        .query_row(
            "WITH ordered AS (
                 SELECT key_hash,
                        version_be,
                        LEAD(version_be) OVER (
                            PARTITION BY key_hash
                            ORDER BY version_be
                        ) AS next_version_be
                 FROM auth_values
             )
             SELECT 1
             FROM auth_stale_values AS stale
             LEFT JOIN ordered
               ON ordered.key_hash=stale.key_hash
              AND ordered.version_be=stale.version_be
             WHERE ordered.next_version_be IS NULL
                OR ordered.next_version_be<>stale.stale_since_version_be
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    ensure!(
        !unexpected,
        "application store authenticated stale-value index contains an invalid row"
    );
    Ok(())
}

fn take_native_validation_record_bytes_v0<'a>(
    cursor: &mut &'a [u8],
    length: usize,
) -> Option<&'a [u8]> {
    if cursor.len() < length {
        return None;
    }
    let (taken, remaining) = cursor.split_at(length);
    *cursor = remaining;
    Some(taken)
}

fn read_native_validation_record_u16_v0(cursor: &mut &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = take_native_validation_record_bytes_v0(cursor, 2)?
        .try_into()
        .ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_native_validation_record_u32_v0(cursor: &mut &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = take_native_validation_record_bytes_v0(cursor, 4)?
        .try_into()
        .ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn validate_native_validation_body_record_v0(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_VALIDATION_BODY_RECORD_BYTES {
        return false;
    }
    let mut cursor = bytes;
    if read_native_validation_record_u16_v0(&mut cursor)
        != Some(NATIVE_VALIDATION_BODY_RECORD_CODEC_V0)
    {
        return false;
    }
    let Some(payload_length) = read_native_validation_record_u32_v0(&mut cursor)
        .and_then(|length| usize::try_from(length).ok())
    else {
        return false;
    };
    if payload_length == 0
        || take_native_validation_record_bytes_v0(&mut cursor, payload_length).is_none()
    {
        return false;
    }
    let Some(evidence_count) = read_native_validation_record_u32_v0(&mut cursor)
        .and_then(|count| usize::try_from(count).ok())
    else {
        return false;
    };
    for _ in 0..evidence_count {
        let Some(evidence_length) = read_native_validation_record_u32_v0(&mut cursor)
            .and_then(|length| usize::try_from(length).ok())
        else {
            return false;
        };
        if evidence_length == 0
            || take_native_validation_record_bytes_v0(&mut cursor, evidence_length).is_none()
        {
            return false;
        }
    }
    cursor.is_empty()
}

fn native_validation_reservation_fingerprint_from_record_v0(
    facts: &NativeValidationReservationFactsV0,
) -> std::result::Result<[u8; 32], NativeValidationReservationInvariantV0> {
    let mut cursor = facts.body_record.as_slice();
    if read_native_validation_record_u16_v0(&mut cursor)
        != Some(NATIVE_VALIDATION_BODY_RECORD_CODEC_V0)
    {
        return Err(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed);
    }
    let payload_length = read_native_validation_record_u32_v0(&mut cursor)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let application_payload = take_native_validation_record_bytes_v0(&mut cursor, payload_length)
        .filter(|payload| !payload.is_empty())
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let evidence_count = read_native_validation_record_u32_v0(&mut cursor)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let mut hasher = begin_native_validation_reservation_fingerprint_v0(
        facts.route,
        facts.validation_id,
        &facts.target_header_cev0,
        application_payload,
        evidence_count,
    )
    .map_err(|_| NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    for _ in 0..evidence_count {
        let evidence_length = read_native_validation_record_u32_v0(&mut cursor)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
        let evidence = take_native_validation_record_bytes_v0(&mut cursor, evidence_length)
            .filter(|evidence| !evidence.is_empty())
            .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
        hash_native_validation_reservation_frame_v0(&mut hasher, evidence).map_err(|_| {
            NativeValidationReservationInvariantV0::PersistedRepresentationMalformed
        })?;
    }
    if !cursor.is_empty() {
        return Err(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed);
    }
    finish_native_validation_reservation_fingerprint_v0(
        hasher,
        facts.parent_height,
        facts.parent_view,
        &facts.parent_block_id,
        facts.parent_timestamp_ms,
        facts.parent_header_cev0.as_deref(),
    )
    .map_err(|_| NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)
}

fn validate_native_validation_request_record_semantics_v0(
    facts: &NativeValidationReservationFactsV0,
    store: &ApplicationStore,
) -> std::result::Result<(), NativeValidationReservationInvariantV0> {
    let malformed = || NativeValidationReservationInvariantV0::PersistedRepresentationMalformed;
    let target_header =
        decode_block_header_v0_exact(&facts.target_header_cev0).map_err(|_| malformed())?;
    if target_header.try_cev0_bytes().map_err(|_| malformed())? != facts.target_header_cev0 {
        return Err(malformed());
    }
    if target_header.id() != facts.validation_id.block_id()
        || target_header.view() != facts.validation_id.view()
        || target_header.height().get() != facts.target_height
        || target_header.parent_id().as_bytes() != &facts.parent_block_id
        || facts.parent_height.checked_add(1) != Some(facts.target_height)
        || facts.parent_timestamp_ms >= target_header.timestamp_ms()
    {
        return Err(NativeValidationReservationInvariantV0::TargetHeaderMismatch);
    }
    if target_header.validator_set_id().as_bytes() != &facts.validator_set_id
        || target_header.consensus_parameters_hash().as_bytes() != &facts.parameters_hash
        || target_header.protocol_version().get() != facts.protocol_version
        || target_header.chain_id().as_str() != store.chain_id
    {
        return Err(NativeValidationReservationInvariantV0::ConfigurationReferenceMismatch);
    }
    match (
        facts.parent_header_cev0.as_deref(),
        facts.parent_state_version,
        facts.parent_state_root,
    ) {
        (None, None, None)
            if facts.parent_height == 0
                && facts.parent_view == 0
                && facts.parent_block_id == *target_header.genesis_hash().as_bytes()
                && target_header.block_kind() == BlockKind::Regular
                && target_header.epoch().get() == 0 => {}
        (Some(encoded), Some(state_version), Some(state_root)) => {
            let parent_header = decode_block_header_v0_exact(encoded).map_err(|_| malformed())?;
            if parent_header.try_cev0_bytes().map_err(|_| malformed())? != encoded {
                return Err(malformed());
            }
            if facts.parent_height == 0
                || parent_header.id().as_bytes() != &facts.parent_block_id
                || parent_header.height().get() != facts.parent_height
                || parent_header.view().get() != facts.parent_view
                || parent_header.timestamp_ms() != facts.parent_timestamp_ms
                || parent_header.height().get() != state_version
                || parent_header.state_root().as_bytes() != &state_root
                || parent_header.chain_id() != target_header.chain_id()
                || parent_header.genesis_hash() != target_header.genesis_hash()
            {
                return Err(NativeValidationReservationInvariantV0::ParentContextMismatch);
            }
            let context_matches = if target_header.block_kind() == BlockKind::EpochHandoff {
                parent_header.block_kind() == BlockKind::EpochSeal2
                    && parent_header.epoch().get().checked_add(1)
                        == Some(target_header.epoch().get())
            } else {
                parent_header.protocol_version() == target_header.protocol_version()
                    && parent_header.epoch() == target_header.epoch()
                    && parent_header.validator_set_id() == target_header.validator_set_id()
                    && parent_header.consensus_parameters_hash()
                        == target_header.consensus_parameters_hash()
            };
            if !context_matches {
                return Err(NativeValidationReservationInvariantV0::ParentContextMismatch);
            }
        }
        _ => return Err(NativeValidationReservationInvariantV0::ParentContextMismatch),
    }
    if native_validation_reservation_fingerprint_from_record_v0(facts)? != facts.request_fingerprint
    {
        return Err(NativeValidationReservationInvariantV0::RequestFingerprintMismatch);
    }
    Ok(())
}

fn native_validation_route_code_v0(route: PayloadValidationRouteV0) -> i64 {
    match route {
        PayloadValidationRouteV0::Proposal => 0,
        PayloadValidationRouteV0::Synced => 1,
    }
}

fn native_validation_route_from_code_v0(code: i64) -> Option<PayloadValidationRouteV0> {
    match code {
        0 => Some(PayloadValidationRouteV0::Proposal),
        1 => Some(PayloadValidationRouteV0::Synced),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeValidationJournalAccountingV0 {
    job_count: u64,
    request_bytes: u64,
    artifact_bytes: u64,
    outbox_count: u64,
    outbox_bytes: u64,
}

type NativeValidationJournalAccountingRawV0 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn native_validation_journal_accounting_raw_v0(
    connection: &Connection,
) -> rusqlite::Result<NativeValidationJournalAccountingRawV0> {
    connection.query_row(
        "SELECT job_count_be, request_bytes_be, artifact_bytes_be,
                outbox_count_be, outbox_bytes_be
         FROM validation_journal_accounting_v0
         WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )
}

fn decode_native_validation_journal_accounting_v0(
    raw: NativeValidationJournalAccountingRawV0,
) -> Option<NativeValidationJournalAccountingV0> {
    Some(NativeValidationJournalAccountingV0 {
        job_count: native_validation_u64_v0(&raw.0)?,
        request_bytes: native_validation_u64_v0(&raw.1)?,
        artifact_bytes: native_validation_u64_v0(&raw.2)?,
        outbox_count: native_validation_u64_v0(&raw.3)?,
        outbox_bytes: native_validation_u64_v0(&raw.4)?,
    })
}

fn read_reserved_only_native_validation_journal_accounting_v0(
    connection: &Connection,
    stage: NativeValidationReservationStageV0,
) -> std::result::Result<
    NativeValidationJournalAccountingV0,
    NativeValidationReservationFailureCauseV0,
> {
    let accounting = read_bounded_native_validation_journal_accounting_v0(connection, stage)?;
    let outbox_exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM validation_callback_outbox_v0 LIMIT 1)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let non_reserved_job_exists = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM validation_jobs_v0 WHERE state<>0 LIMIT 1
             )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    if accounting.artifact_bytes != 0
        || accounting.outbox_count != 0
        || accounting.outbox_bytes != 0
        || outbox_exists
        || non_reserved_job_exists
    {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::StateMismatch,
            sqlite: None,
        });
    }
    Ok(accounting)
}

fn read_active_native_validation_journal_accounting_v0(
    connection: &Connection,
    stage: NativeValidationReservationStageV0,
) -> std::result::Result<
    NativeValidationJournalAccountingV0,
    NativeValidationReservationFailureCauseV0,
> {
    let accounting = read_bounded_native_validation_journal_accounting_v0(connection, stage)?;
    let result_kind = i64::from(durable_deterministic_invalid_result_kind_v0());
    let invalid_job_exists = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM validation_jobs_v0 AS job
                 LEFT JOIN validation_callback_outbox_v0 AS outbox
                   ON outbox.route=job.route AND outbox.block_id=job.block_id
                  AND outbox.view_be=job.view_be AND outbox.generation_be=job.generation_be
                 WHERE job.state NOT IN (0,2)
                    OR (job.state=0 AND outbox.block_id IS NOT NULL)
                    OR (job.state=2 AND (
                        job.result_kind<>?1 OR
                        job.invalid_reason_code_be NOT IN (X'00000001',X'00000002') OR
                        job.artifact_codec<>?2 OR outbox.block_id IS NULL OR
                        outbox.result_kind<>job.result_kind OR
                        outbox.artifact_checksum<>job.artifact_checksum OR
                        outbox.payload_codec<>?3 OR outbox.delivery_attempt_be<>zeroblob(8)
                    ))
                 LIMIT 1
             )",
            params![
                result_kind,
                DURABLE_INVALID_ARTIFACT_CODEC_V0,
                DURABLE_INVALID_CALLBACK_CODEC_V0,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let invalid_outbox_exists = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM validation_callback_outbox_v0 AS outbox
                 LEFT JOIN validation_jobs_v0 AS job
                   ON job.route=outbox.route AND job.block_id=outbox.block_id
                  AND job.view_be=outbox.view_be AND job.generation_be=outbox.generation_be
                 WHERE job.block_id IS NULL OR job.state<>2 OR
                       outbox.result_kind<>?1 OR
                       outbox.result_kind<>job.result_kind OR
                       outbox.artifact_checksum<>job.artifact_checksum OR
                       outbox.payload_codec<>?2 OR
                       outbox.delivery_attempt_be<>zeroblob(8)
                 LIMIT 1
             )",
            params![result_kind, DURABLE_INVALID_CALLBACK_CODEC_V0],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let callback_pending_exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM validation_jobs_v0 WHERE state=2 LIMIT 1)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let outbox_exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM validation_callback_outbox_v0 LIMIT 1)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    if invalid_job_exists
        || invalid_outbox_exists
        || callback_pending_exists != outbox_exists
        || (accounting.artifact_bytes == 0) == callback_pending_exists
        || (accounting.outbox_count == 0) == outbox_exists
        || (accounting.outbox_bytes == 0) == outbox_exists
        || accounting.artifact_bytes > MAX_NATIVE_VALIDATION_ARTIFACT_JOURNAL_BYTES
        || accounting.artifact_bytes
            != accounting
                .outbox_count
                .saturating_mul(DURABLE_INVALID_ARTIFACT_BYTES_V0 as u64)
        || accounting.outbox_count > accounting.job_count
        || accounting.outbox_bytes > MAX_NATIVE_VALIDATION_CALLBACK_OUTBOX_BYTES
    {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::StateMismatch,
            sqlite: None,
        });
    }
    Ok(accounting)
}

fn read_delivery_native_validation_journal_accounting_v0(
    connection: &Connection,
    stage: NativeValidationReservationStageV0,
) -> std::result::Result<
    NativeValidationJournalAccountingV0,
    NativeValidationReservationFailureCauseV0,
> {
    let accounting = read_bounded_native_validation_journal_accounting_v0(connection, stage)?;
    let result_kind = i64::from(durable_deterministic_invalid_result_kind_v0());
    let invalid_job_exists = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM validation_jobs_v0 AS job
                 LEFT JOIN validation_callback_outbox_v0 AS outbox
                   ON outbox.route=job.route AND outbox.block_id=job.block_id
                  AND outbox.view_be=job.view_be AND outbox.generation_be=job.generation_be
                 WHERE job.state NOT IN (0,2,3,4)
                    OR (job.state=0 AND outbox.block_id IS NOT NULL)
                    OR (job.state IN (2,3,4) AND (
                        job.result_kind<>?1 OR
                        job.invalid_reason_code_be NOT IN (X'00000001',X'00000002') OR
                        job.artifact_codec<>?2
                    ))
                    OR (job.state=2 AND (
                        outbox.block_id IS NULL OR outbox.result_kind<>job.result_kind OR
                        outbox.artifact_checksum<>job.artifact_checksum OR
                        outbox.payload_codec<>?3 OR outbox.delivery_attempt_be<>zeroblob(8)
                    ))
                    OR (job.state=3 AND (
                        outbox.block_id IS NULL OR outbox.result_kind<>job.result_kind OR
                        outbox.artifact_checksum<>job.artifact_checksum OR
                        outbox.payload_codec<>?3 OR outbox.delivery_attempt_be=zeroblob(8)
                    ))
                    OR (job.state=4 AND outbox.block_id IS NOT NULL)
                 LIMIT 1
             )",
            params![
                result_kind,
                DURABLE_INVALID_ARTIFACT_CODEC_V0,
                DURABLE_INVALID_CALLBACK_CODEC_V0,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let invalid_outbox_exists = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM validation_callback_outbox_v0 AS outbox
                 LEFT JOIN validation_jobs_v0 AS job
                   ON job.route=outbox.route AND job.block_id=outbox.block_id
                  AND job.view_be=outbox.view_be AND job.generation_be=outbox.generation_be
                 WHERE job.block_id IS NULL OR job.state NOT IN (2,3) OR
                       outbox.result_kind<>?1 OR
                       outbox.result_kind<>job.result_kind OR
                       outbox.artifact_checksum<>job.artifact_checksum OR
                       outbox.payload_codec<>?2 OR
                       (job.state=2 AND outbox.delivery_attempt_be<>zeroblob(8)) OR
                       (job.state=3 AND outbox.delivery_attempt_be=zeroblob(8))
                 LIMIT 1
             )",
            params![result_kind, DURABLE_INVALID_CALLBACK_CODEC_V0],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let artifact_count = connection
        .query_row(
            "SELECT COUNT(*) FROM validation_jobs_v0 WHERE state IN (2,3,4)",
            [],
            |row| row.get::<_, u64>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let active_outbox_jobs = connection
        .query_row(
            "SELECT COUNT(*) FROM validation_jobs_v0 WHERE state IN (2,3)",
            [],
            |row| row.get::<_, u64>(0),
        )
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let expected_artifact_bytes =
        artifact_count.checked_mul(DURABLE_INVALID_ARTIFACT_BYTES_V0 as u64);
    let expected_outbox_bytes =
        active_outbox_jobs.checked_mul(DURABLE_INVALID_CALLBACK_BYTES_V0 as u64);
    if invalid_job_exists
        || invalid_outbox_exists
        || accounting.outbox_count != active_outbox_jobs
        || expected_artifact_bytes != Some(accounting.artifact_bytes)
        || expected_outbox_bytes != Some(accounting.outbox_bytes)
    {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::StateMismatch,
            sqlite: None,
        });
    }
    Ok(accounting)
}

/// Reads only the singleton accounting row and validates its scalar bounds.
/// Admission and seal transactions use this O(1) gate; the full table/join
/// congruence audit remains a startup, migration, and snapshot responsibility.
fn read_bounded_native_validation_journal_accounting_v0(
    connection: &Connection,
    stage: NativeValidationReservationStageV0,
) -> std::result::Result<
    NativeValidationJournalAccountingV0,
    NativeValidationReservationFailureCauseV0,
> {
    let raw = native_validation_journal_accounting_raw_v0(connection)
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;
    let accounting = decode_native_validation_journal_accounting_v0(raw).ok_or(
        NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
            sqlite: None,
        },
    )?;
    let exact_outbox_bytes = accounting
        .outbox_count
        .checked_mul(DURABLE_INVALID_CALLBACK_BYTES_V0 as u64);
    let artifact_count = accounting.artifact_bytes / DURABLE_INVALID_ARTIFACT_BYTES_V0 as u64;
    if accounting.job_count > MAX_NATIVE_VALIDATION_RESERVATIONS
        || accounting.request_bytes > MAX_NATIVE_VALIDATION_REQUEST_JOURNAL_BYTES
        || accounting.artifact_bytes > MAX_NATIVE_VALIDATION_ARTIFACT_JOURNAL_BYTES
        || accounting.outbox_count > accounting.job_count
        || accounting.outbox_count > MAX_NATIVE_VALIDATION_RESERVATIONS
        || accounting.outbox_bytes > MAX_NATIVE_VALIDATION_CALLBACK_OUTBOX_BYTES
        || !accounting
            .artifact_bytes
            .is_multiple_of(DURABLE_INVALID_ARTIFACT_BYTES_V0 as u64)
        || artifact_count > accounting.job_count
        || accounting.outbox_count > artifact_count
        || exact_outbox_bytes != Some(accounting.outbox_bytes)
    {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::StateMismatch,
            sqlite: None,
        });
    }
    Ok(accounting)
}

fn native_validation_runtime_profile_ref_v0(protocol_version: u32) -> [u8; 32] {
    hash_domain(
        NATIVE_VALIDATION_RUNTIME_PROFILE_DOMAIN_V0,
        &[
            &APP_VERSION.to_be_bytes(),
            &protocol_version.to_be_bytes(),
            b"native-runtime-v0",
        ],
    )
}

fn native_validation_host_config_ref_v0(store: &ApplicationStore) -> [u8; 32] {
    hash_domain(
        NATIVE_VALIDATION_HOST_CONFIG_DOMAIN_V0,
        &[
            store.chain_id.as_bytes(),
            &APP_VERSION.to_be_bytes(),
            store.signer_policy_hash_hex.as_bytes(),
            b"jmt-sha256-v0.12.0",
            b"borsh-v1",
        ],
    )
}

fn native_validation_job_immutable_checksum_v0(
    facts: &NativeValidationReservationFactsV0,
    runtime_profile_ref: &[u8; 32],
    host_config_ref: &[u8; 32],
) -> [u8; 32] {
    let route = [u8::try_from(native_validation_route_code_v0(facts.route))
        .expect("native validation route code is one byte")];
    let validation_id = facts.validation_id;
    let immutable_codec = NATIVE_VALIDATION_JOB_IMMUTABLE_CODEC_V0.to_be_bytes();
    let body_record_codec = NATIVE_VALIDATION_BODY_RECORD_CODEC_V0.to_be_bytes();
    let parent_header_presence = [u8::from(facts.parent_header_cev0.is_some())];
    let empty = [];
    let parent_header = facts.parent_header_cev0.as_deref().unwrap_or(&empty);
    let parent_state_version = facts
        .parent_state_version
        .map(u64::to_be_bytes)
        .unwrap_or_default();
    let parent_state_root = facts.parent_state_root.unwrap_or_default();
    hash_domain(
        NATIVE_VALIDATION_JOB_IMMUTABLE_DOMAIN_V0,
        &[
            &immutable_codec,
            &route,
            validation_id.block_id().as_bytes(),
            &validation_id.view().get().to_be_bytes(),
            &validation_id.generation().to_be_bytes(),
            &facts.target_height.to_be_bytes(),
            &facts.target_header_cev0,
            &body_record_codec,
            &facts.body_checksum,
            &facts.parent_height.to_be_bytes(),
            &facts.parent_view.to_be_bytes(),
            &facts.parent_block_id,
            &facts.parent_timestamp_ms.to_be_bytes(),
            &parent_header_presence,
            parent_header,
            &parent_state_version,
            &parent_state_root,
            &facts.validator_set_id,
            &facts.parameters_hash,
            &facts.protocol_version.to_be_bytes(),
            runtime_profile_ref,
            host_config_ref,
            &facts.creation_revision.to_be_bytes(),
            &facts.request_fingerprint,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn native_validation_job_row_checksum_v0(
    immutable_checksum: &[u8; 32],
    state: NativeValidationJobStateV0,
    result_kind: Option<i64>,
    invalid_reason_code_be: Option<&[u8]>,
    artifact_codec: Option<&str>,
    artifact_checksum: Option<&[u8; 32]>,
    accepted_core_revision_be: Option<&[u8]>,
    accepted_core_payload_checksum: Option<&[u8; 32]>,
) -> [u8; 32] {
    let codec = NATIVE_VALIDATION_JOB_ROW_CODEC_V0.to_be_bytes();
    let state = [u8::try_from(state.code()).expect("native validation state code is one byte")];
    let result_kind_presence = [u8::from(result_kind.is_some())];
    let result_kind = result_kind
        .and_then(|value| u8::try_from(value).ok())
        .map_or(Vec::new(), |value| vec![value]);
    let invalid_reason_presence = [u8::from(invalid_reason_code_be.is_some())];
    let artifact_presence = [u8::from(artifact_checksum.is_some())];
    let accepted_revision_presence = [u8::from(accepted_core_revision_be.is_some())];
    let accepted_payload_presence = [u8::from(accepted_core_payload_checksum.is_some())];
    hash_domain(
        NATIVE_VALIDATION_JOB_ROW_DOMAIN_V0,
        &[
            &codec,
            immutable_checksum,
            &state,
            &result_kind_presence,
            &result_kind,
            &invalid_reason_presence,
            invalid_reason_code_be.unwrap_or(&[]),
            &artifact_presence,
            artifact_codec.map(str::as_bytes).unwrap_or(&[]),
            artifact_checksum.map(<[u8; 32]>::as_slice).unwrap_or(&[]),
            &accepted_revision_presence,
            accepted_core_revision_be.unwrap_or(&[]),
            &accepted_payload_presence,
            accepted_core_payload_checksum
                .map(<[u8; 32]>::as_slice)
                .unwrap_or(&[]),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn native_validation_job_delivery_row_checksum_v0(
    immutable_checksum: &[u8; 32],
    state: NativeValidationJobStateV0,
    result_kind: Option<i64>,
    invalid_reason_code_be: Option<&[u8]>,
    artifact_codec: Option<&str>,
    artifact_checksum: Option<&[u8; 32]>,
    accepted_core_revision_be: Option<&[u8]>,
    accepted_core_payload_checksum: Option<&[u8; 32]>,
    outbox_checksum: Option<&[u8; 32]>,
) -> [u8; 32] {
    let codec = NATIVE_VALIDATION_JOB_ROW_CODEC_V0.to_be_bytes();
    let base = native_validation_job_row_checksum_v0(
        immutable_checksum,
        state,
        result_kind,
        invalid_reason_code_be,
        artifact_codec,
        artifact_checksum,
        accepted_core_revision_be,
        accepted_core_payload_checksum,
    );
    let outbox_presence = [u8::from(outbox_checksum.is_some())];
    hash_domain(
        NATIVE_VALIDATION_JOB_DELIVERY_ROW_DOMAIN_V0,
        &[
            &codec,
            &base,
            &outbox_presence,
            outbox_checksum.map(<[u8; 32]>::as_slice).unwrap_or(&[]),
        ],
    )
}

fn native_validation_array_v0<const LENGTH: usize>(bytes: &[u8]) -> Option<[u8; LENGTH]> {
    bytes.try_into().ok()
}

fn native_validation_u64_v0(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(native_validation_array_v0(bytes)?))
}

fn native_validation_u32_v0(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(native_validation_array_v0(bytes)?))
}

fn durable_native_validation_job_from_existing_v0(
    existing: NativeValidationReservationExistingV0,
    store: &ApplicationStore,
) -> std::result::Result<DurableNativeValidationJobV0, NativeValidationReservationInvariantV0> {
    let route = native_validation_route_from_code_v0(existing.route)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let block_id = native_validation_array_v0::<32>(&existing.block_id)
        .map(BlockId::new)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let view = native_validation_u64_v0(&existing.view_be)
        .map(View::new)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let generation = native_validation_u64_v0(&existing.generation_be)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let target_height = native_validation_u64_v0(&existing.target_height_be)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let parent_height = native_validation_u64_v0(&existing.parent_height_be)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let parent_view = native_validation_u64_v0(&existing.parent_view_be)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let parent_block_id = native_validation_array_v0(&existing.parent_block_id)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let parent_timestamp_ms = native_validation_u64_v0(&existing.parent_timestamp_ms_be)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let parent_state_version = existing
        .parent_state_version_be
        .as_deref()
        .map(native_validation_u64_v0)
        .transpose_option()
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let parent_state_root = existing
        .parent_state_root
        .as_deref()
        .map(native_validation_array_v0::<32>)
        .transpose_option()
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    if existing.body_record_codec != i64::from(NATIVE_VALIDATION_BODY_RECORD_CODEC_V0)
        || existing.row_codec != i64::from(NATIVE_VALIDATION_JOB_ROW_CODEC_V0)
        || existing.target_header_cev0.is_empty()
        || existing.target_header_cev0.len() > MAX_NATIVE_VALIDATION_HEADER_BYTES
        || !validate_native_validation_body_record_v0(&existing.body_record)
        || existing.parent_header_cev0.as_ref().is_some_and(|header| {
            header.is_empty() || header.len() > MAX_NATIVE_VALIDATION_HEADER_BYTES
        })
        || !matches!(
            (
                existing.parent_header_cev0.is_some(),
                parent_state_version.is_some(),
                parent_state_root.is_some(),
            ),
            (false, false, false) | (true, true, true)
        )
    {
        return Err(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed);
    }
    let body_checksum = native_validation_array_v0(&existing.body_checksum)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    if hash_domain(NATIVE_VALIDATION_BODY_DOMAIN_V0, &[&existing.body_record]) != body_checksum {
        return Err(NativeValidationReservationInvariantV0::ChecksumMismatch);
    }
    let validator_set_id = native_validation_array_v0(&existing.validator_set_id)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let parameters_hash = native_validation_array_v0(&existing.parameters_hash)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let protocol_version = native_validation_u32_v0(&existing.protocol_version_be)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let runtime_profile_ref = native_validation_array_v0(&existing.runtime_profile_ref)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let host_config_ref = native_validation_array_v0(&existing.host_config_ref)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let creation_revision = native_validation_u64_v0(&existing.creation_revision_be)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    if creation_revision != generation {
        return Err(NativeValidationReservationInvariantV0::CreationRevisionMismatch);
    }
    let request_fingerprint = native_validation_array_v0(&existing.request_fingerprint)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let immutable_checksum = native_validation_array_v0(&existing.immutable_checksum)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let state = NativeValidationJobStateV0::from_code(existing.state)
        .ok_or(NativeValidationReservationInvariantV0::StateMismatch)?;
    let artifact_checksum = existing
        .artifact_checksum
        .as_deref()
        .map(native_validation_array_v0::<32>)
        .transpose_option()
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let accepted_core_payload_checksum = existing
        .accepted_core_payload_checksum
        .as_deref()
        .map(native_validation_array_v0::<32>)
        .transpose_option()
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let accepted_core_revision = existing
        .accepted_core_revision_be
        .as_deref()
        .map(native_validation_u64_v0)
        .transpose_option()
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let active_invalid_shape = existing.result_kind
        == Some(i64::from(durable_deterministic_invalid_result_kind_v0()))
        && existing
            .invalid_reason_code_be
            .as_deref()
            .and_then(native_validation_u32_v0)
            .and_then(DurableDeterministicInvalidReasonV0::from_code_v0)
            .is_some()
        && existing.artifact_codec.as_deref() == Some(DURABLE_INVALID_ARTIFACT_CODEC_V0)
        && existing.artifact_bytes.is_some()
        && artifact_checksum.is_some();
    match state {
        NativeValidationJobStateV0::Reserved
            if existing.result_kind.is_none()
                && existing.invalid_reason_code_be.is_none()
                && existing.artifact_codec.is_none()
                && existing.artifact_bytes.is_none()
                && artifact_checksum.is_none()
                && existing.accepted_core_revision_be.is_none()
                && accepted_core_payload_checksum.is_none() => {}
        NativeValidationJobStateV0::CallbackPending | NativeValidationJobStateV0::Delivered
            if active_invalid_shape
                && accepted_core_revision.is_none()
                && accepted_core_payload_checksum.is_none() => {}
        NativeValidationJobStateV0::Acked
            if active_invalid_shape
                && accepted_core_revision.is_some_and(|revision| revision > creation_revision)
                && accepted_core_payload_checksum.is_some() => {}
        _ => return Err(NativeValidationReservationInvariantV0::StateMismatch),
    }
    let row_checksum = native_validation_array_v0(&existing.row_checksum)
        .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
    let facts = NativeValidationReservationFactsV0 {
        route,
        validation_id: ValidationId::new(block_id, view, generation),
        target_height,
        target_header_cev0: existing.target_header_cev0,
        body_record: existing.body_record,
        body_checksum,
        parent_height,
        parent_view,
        parent_block_id,
        parent_timestamp_ms,
        parent_header_cev0: existing.parent_header_cev0,
        parent_state_version,
        parent_state_root,
        validator_set_id,
        parameters_hash,
        protocol_version,
        creation_revision,
        request_fingerprint,
    };
    validate_native_validation_request_record_semantics_v0(&facts, store)?;
    if native_validation_job_immutable_checksum_v0(&facts, &runtime_profile_ref, &host_config_ref)
        != immutable_checksum
    {
        return Err(NativeValidationReservationInvariantV0::ChecksumMismatch);
    }
    if state != NativeValidationJobStateV0::Reserved {
        let identity = NativeValidationArtifactIdentityV0::new_v0(
            facts.route,
            facts.validation_id,
            facts.request_fingerprint,
            immutable_checksum,
        );
        let result_kind = u8::try_from(
            existing
                .result_kind
                .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?,
        )
        .map_err(|_| NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
        let reason = existing
            .invalid_reason_code_be
            .as_deref()
            .and_then(native_validation_u32_v0)
            .and_then(DurableDeterministicInvalidReasonV0::from_code_v0)
            .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?;
        verify_durable_invalid_artifact_v0(
            existing
                .artifact_codec
                .as_deref()
                .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?,
            existing
                .artifact_bytes
                .as_deref()
                .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?,
            artifact_checksum
                .ok_or(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)?,
            result_kind,
            reason,
            identity,
        )
        .map_err(native_validation_record_invariant_v0)?;
        if state == NativeValidationJobStateV0::Acked
            && accepted_core_payload_checksum
                != Some(durable_invalid_callback_payload_checksum_for_identity_v0(
                    identity,
                    artifact_checksum.ok_or(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )?,
                ))
        {
            return Err(NativeValidationReservationInvariantV0::ChecksumMismatch);
        }
    }
    let expected_row_checksum = match state {
        NativeValidationJobStateV0::Delivered => None,
        NativeValidationJobStateV0::Acked => Some(native_validation_job_delivery_row_checksum_v0(
            &immutable_checksum,
            state,
            existing.result_kind,
            existing.invalid_reason_code_be.as_deref(),
            existing.artifact_codec.as_deref(),
            artifact_checksum.as_ref(),
            existing.accepted_core_revision_be.as_deref(),
            accepted_core_payload_checksum.as_ref(),
            None,
        )),
        NativeValidationJobStateV0::Reserved | NativeValidationJobStateV0::CallbackPending => {
            Some(native_validation_job_row_checksum_v0(
                &immutable_checksum,
                state,
                existing.result_kind,
                existing.invalid_reason_code_be.as_deref(),
                existing.artifact_codec.as_deref(),
                artifact_checksum.as_ref(),
                existing.accepted_core_revision_be.as_deref(),
                accepted_core_payload_checksum.as_ref(),
            ))
        }
        NativeValidationJobStateV0::Evaluated | NativeValidationJobStateV0::Applied => {
            unreachable!("inactive native validation state was rejected above")
        }
    };
    if expected_row_checksum.is_some_and(|expected| expected != row_checksum) {
        return Err(NativeValidationReservationInvariantV0::ChecksumMismatch);
    }
    Ok(DurableNativeValidationJobV0 {
        facts,
        runtime_profile_ref,
        host_config_ref,
        immutable_checksum,
        state,
        result_kind: existing.result_kind,
        invalid_reason_code_be: existing.invalid_reason_code_be,
        artifact_codec: existing.artifact_codec,
        artifact_bytes: existing.artifact_bytes,
        artifact_checksum,
        accepted_core_revision_be: existing.accepted_core_revision_be,
        accepted_core_payload_checksum,
        row_checksum,
    })
}

fn native_validation_artifact_identity_v0(
    job: &DurableNativeValidationJobV0,
) -> NativeValidationArtifactIdentityV0 {
    NativeValidationArtifactIdentityV0::new_v0(
        job.facts.route,
        job.facts.validation_id,
        job.facts.request_fingerprint,
        job.immutable_checksum,
    )
}

fn native_validation_job_invalid_reason_v0(
    job: &DurableNativeValidationJobV0,
) -> Option<DurableDeterministicInvalidReasonV0> {
    job.invalid_reason_code_be
        .as_deref()
        .and_then(native_validation_u32_v0)
        .and_then(DurableDeterministicInvalidReasonV0::from_code_v0)
}

fn native_validation_invalid_callback_lineage_matches_v0(
    verified: &VerifiedNativeValidationInvalidCallbackV0,
    owner: &LiveNativeValidationInvalidCallbackV0,
) -> bool {
    verified.route() == owner.route()
        && verified.validation_id() == owner.validation_id()
        && verified.reason() == owner.reason()
        && verified.request_fingerprint() == owner.request_fingerprint()
        && verified.immutable_checksum() == owner.immutable_checksum()
        && verified.artifact_checksum() == owner.artifact_checksum()
        && verified.callback_payload_checksum() == owner.callback_payload_checksum()
        && verified.idempotency_key() == owner.idempotency_key()
}

fn native_validation_invalid_delivered_lineage_matches_v0(
    verified: &VerifiedNativeValidationInvalidCallbackV0,
    owner: &DeliveredNativeValidationInvalidCallbackV0,
) -> bool {
    verified.route() == owner.route()
        && verified.validation_id() == owner.validation_id()
        && verified.reason() == owner.reason()
        && verified.request_fingerprint() == owner.request_fingerprint()
        && verified.immutable_checksum() == owner.immutable_checksum()
        && verified.artifact_checksum() == owner.artifact_checksum()
        && verified.callback_payload_checksum() == owner.callback_payload_checksum()
        && verified.idempotency_key() == owner.idempotency_key()
        && verified.delivery_attempt() == owner.delivery_attempt()
        && verified.outbox_checksum() == owner.verified.outbox_checksum()
}

fn native_validation_invalid_acked_job_matches_confirmation_v0(
    job: &DurableNativeValidationJobV0,
    owner: &ConfirmedCoreInvalidCompletionV0,
) -> bool {
    job.state == NativeValidationJobStateV0::Acked
        && job.route() == owner.route()
        && job.validation_id() == owner.validation_id()
        && job.request_fingerprint() == owner.delivered.request_fingerprint()
        && job.immutable_checksum() == owner.delivered.immutable_checksum()
        && native_validation_job_invalid_reason_v0(job) == Some(owner.delivered.reason())
        && job.artifact_checksum == Some(owner.delivered.artifact_checksum())
        && job
            .accepted_core_revision_be
            .as_deref()
            .and_then(native_validation_u64_v0)
            == Some(owner.accepted_core_revision())
        && job.accepted_core_payload_checksum == Some(owner.callback_payload_checksum())
}

fn native_validation_record_invariant_v0(
    error: DurableNativeValidationRecordErrorV0,
) -> NativeValidationReservationInvariantV0 {
    match error {
        DurableNativeValidationRecordErrorV0::Codec(_) => {
            NativeValidationReservationInvariantV0::PersistedRepresentationMalformed
        }
        DurableNativeValidationRecordErrorV0::Binding(_) => {
            NativeValidationReservationInvariantV0::ChecksumMismatch
        }
    }
}

fn native_validation_outbox_from_row_v0(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<NativeValidationCallbackOutboxExistingV0> {
    Ok(NativeValidationCallbackOutboxExistingV0 {
        route: row.get(0)?,
        block_id: row.get(1)?,
        view_be: row.get(2)?,
        generation_be: row.get(3)?,
        result_kind: row.get(4)?,
        artifact_checksum: row.get(5)?,
        payload_codec: row.get(6)?,
        payload_bytes: row.get(7)?,
        payload_checksum: row.get(8)?,
        idempotency_key: row.get(9)?,
        delivery_attempt_be: row.get(10)?,
        outbox_checksum: row.get(11)?,
    })
}

fn revalidate_native_validation_job_outbox_v0(
    connection: &Connection,
    job: &DurableNativeValidationJobV0,
    stage: NativeValidationReservationStageV0,
) -> std::result::Result<
    Option<RevalidatedNativeValidationInvalidOutboxV0>,
    NativeValidationReservationFailureCauseV0,
> {
    let validation_id = job.validation_id();
    let outbox = connection
        .query_row(
            "SELECT route, block_id, view_be, generation_be, result_kind,
                    artifact_checksum, payload_codec, payload_bytes,
                    payload_checksum, idempotency_key, delivery_attempt_be,
                    outbox_checksum
             FROM validation_callback_outbox_v0
             WHERE route=?1 AND block_id=?2 AND view_be=?3 AND generation_be=?4",
            params![
                native_validation_route_code_v0(job.route()),
                validation_id.block_id().as_bytes().as_slice(),
                validation_id.view().get().to_be_bytes().as_slice(),
                validation_id.generation().to_be_bytes().as_slice(),
            ],
            native_validation_outbox_from_row_v0,
        )
        .optional()
        .map_err(|error| classify_native_validation_reservation_sqlite_failure_v0(stage, &error))?;

    let invariant = |kind| NativeValidationReservationFailureCauseV0::Invariant {
        stage,
        kind,
        sqlite: None,
    };
    match job.state {
        NativeValidationJobStateV0::Reserved | NativeValidationJobStateV0::Acked => {
            if outbox.is_some() {
                return Err(invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ));
            }
            Ok(None)
        }
        NativeValidationJobStateV0::CallbackPending | NativeValidationJobStateV0::Delivered => {
            let outbox = outbox
                .ok_or_else(|| invariant(NativeValidationReservationInvariantV0::StateMismatch))?;
            let route = native_validation_route_from_code_v0(outbox.route).ok_or_else(|| {
                invariant(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)
            })?;
            let block_id = native_validation_array_v0::<32>(&outbox.block_id)
                .map(BlockId::new)
                .ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?;
            let view = native_validation_u64_v0(&outbox.view_be)
                .map(View::new)
                .ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?;
            let generation = native_validation_u64_v0(&outbox.generation_be).ok_or_else(|| {
                invariant(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)
            })?;
            if route != job.route()
                || ValidationId::new(block_id, view, generation) != validation_id
            {
                return Err(invariant(
                    NativeValidationReservationInvariantV0::RouteMismatch,
                ));
            }
            let result_kind = u8::try_from(outbox.result_kind).map_err(|_| {
                invariant(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)
            })?;
            let artifact_checksum = native_validation_array_v0(&outbox.artifact_checksum)
                .ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?;
            let payload_checksum = native_validation_array_v0(&outbox.payload_checksum)
                .ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?;
            let idempotency_key =
                native_validation_array_v0(&outbox.idempotency_key).ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?;
            let delivery_attempt = native_validation_u64_v0(&outbox.delivery_attempt_be)
                .ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?;
            let expected_delivery_attempt = match job.state {
                NativeValidationJobStateV0::CallbackPending if delivery_attempt == 0 => 0,
                NativeValidationJobStateV0::Delivered if delivery_attempt > 0 => delivery_attempt,
                _ => {
                    return Err(invariant(
                        NativeValidationReservationInvariantV0::StateMismatch,
                    ));
                }
            };
            let outbox_checksum =
                native_validation_array_v0(&outbox.outbox_checksum).ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?;
            if job.result_kind != Some(outbox.result_kind)
                || job.artifact_checksum != Some(artifact_checksum)
            {
                return Err(invariant(
                    NativeValidationReservationInvariantV0::StateMismatch,
                ));
            }
            let stored_reason = native_validation_job_invalid_reason_v0(job).ok_or_else(|| {
                invariant(NativeValidationReservationInvariantV0::PersistedRepresentationMalformed)
            })?;
            let artifact = verify_durable_invalid_artifact_v0(
                job.artifact_codec.as_deref().ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?,
                job.artifact_bytes.as_deref().ok_or_else(|| {
                    invariant(
                        NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                    )
                })?,
                artifact_checksum,
                result_kind,
                stored_reason,
                native_validation_artifact_identity_v0(job),
            )
            .map_err(|error| invariant(native_validation_record_invariant_v0(error)))?;
            let callback = verify_durable_invalid_callback_v0(
                &outbox.payload_codec,
                &outbox.payload_bytes,
                payload_checksum,
                idempotency_key,
                delivery_attempt,
                expected_delivery_attempt,
                outbox_checksum,
                result_kind,
                artifact_checksum,
                native_validation_artifact_identity_v0(job),
            )
            .map_err(|error| invariant(native_validation_record_invariant_v0(error)))?;
            if job.state == NativeValidationJobStateV0::Delivered
                && native_validation_job_delivery_row_checksum_v0(
                    &job.immutable_checksum,
                    job.state,
                    job.result_kind,
                    job.invalid_reason_code_be.as_deref(),
                    job.artifact_codec.as_deref(),
                    job.artifact_checksum.as_ref(),
                    job.accepted_core_revision_be.as_deref(),
                    job.accepted_core_payload_checksum.as_ref(),
                    Some(&outbox_checksum),
                ) != job.row_checksum
            {
                return Err(invariant(
                    NativeValidationReservationInvariantV0::ChecksumMismatch,
                ));
            }
            Ok(Some(RevalidatedNativeValidationInvalidOutboxV0 {
                artifact,
                callback,
                delivery_attempt,
            }))
        }
        _ => Err(invariant(
            NativeValidationReservationInvariantV0::StateMismatch,
        )),
    }
}

fn verify_native_validation_job_outbox_v0(
    connection: &Connection,
    job: &DurableNativeValidationJobV0,
    stage: NativeValidationReservationStageV0,
) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
    revalidate_native_validation_job_outbox_v0(connection, job, stage).map(|_| ())
}

trait TransposeOptionV0<T> {
    fn transpose_option(self) -> Option<Option<T>>;
}

impl<T> TransposeOptionV0<T> for Option<Option<T>> {
    fn transpose_option(self) -> Option<Option<T>> {
        match self {
            Some(Some(value)) => Some(Some(value)),
            Some(None) => None,
            None => Some(None),
        }
    }
}

fn validate_native_validation_job_bindings_v0(
    connection: &Connection,
    store: &ApplicationStore,
) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
    let stage = NativeValidationReservationStageV0::ValidateBindings;
    let app_version = APP_VERSION.to_string();
    let bindings = [
        ("schema_version", STORE_SCHEMA_VERSION),
        ("chain_id", store.chain_id.as_str()),
        ("app_version", app_version.as_str()),
        (
            "authorized_signers_hash_hex",
            store.signer_policy_hash_hex.as_str(),
        ),
        ("auth_tree", "jmt-sha256-v0.12.0"),
        ("auth_codec", "borsh-v1"),
    ];
    for (key, expected) in bindings {
        let actual = connection
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(stage, &error)
            })?;
        if actual != expected {
            return Err(NativeValidationReservationFailureCauseV0::HostInvariant {
                stage,
                sqlite: None,
            });
        }
    }
    Ok(())
}

fn native_validation_existing_from_row_v0(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<NativeValidationReservationExistingV0> {
    Ok(NativeValidationReservationExistingV0 {
        route: row.get(0)?,
        block_id: row.get(1)?,
        view_be: row.get(2)?,
        generation_be: row.get(3)?,
        target_height_be: row.get(4)?,
        target_header_cev0: row.get(5)?,
        body_record_codec: row.get(6)?,
        body_record: row.get(7)?,
        body_checksum: row.get(8)?,
        parent_height_be: row.get(9)?,
        parent_view_be: row.get(10)?,
        parent_block_id: row.get(11)?,
        parent_timestamp_ms_be: row.get(12)?,
        parent_header_cev0: row.get(13)?,
        parent_state_version_be: row.get(14)?,
        parent_state_root: row.get(15)?,
        validator_set_id: row.get(16)?,
        parameters_hash: row.get(17)?,
        protocol_version_be: row.get(18)?,
        runtime_profile_ref: row.get(19)?,
        host_config_ref: row.get(20)?,
        creation_revision_be: row.get(21)?,
        request_fingerprint: row.get(22)?,
        immutable_checksum: row.get(23)?,
        state: row.get(24)?,
        result_kind: row.get(25)?,
        invalid_reason_code_be: row.get(26)?,
        artifact_codec: row.get(27)?,
        artifact_bytes: row.get(28)?,
        artifact_checksum: row.get(29)?,
        accepted_core_revision_be: row.get(30)?,
        accepted_core_payload_checksum: row.get(31)?,
        row_codec: row.get(32)?,
        row_checksum: row.get(33)?,
    })
}

fn load_native_validation_job_v0(
    connection: &Connection,
    validation_id: ValidationId,
) -> std::result::Result<
    Option<NativeValidationReservationExistingV0>,
    NativeValidationReservationFailureCauseV0,
> {
    connection
        .query_row(
            "SELECT route, block_id, view_be, generation_be, target_height_be,
                    target_header_cev0, body_record_codec, body_record, body_checksum,
                    parent_height_be, parent_view_be, parent_block_id,
                    parent_timestamp_ms_be, parent_header_cev0,
                    parent_state_version_be, parent_state_root, validator_set_id,
                    parameters_hash, protocol_version_be, runtime_profile_ref,
                    host_config_ref, creation_revision_be, request_fingerprint,
                    immutable_checksum, state, result_kind, invalid_reason_code_be,
                    artifact_codec, artifact_bytes, artifact_checksum,
                    accepted_core_revision_be, accepted_core_payload_checksum,
                    row_codec, row_checksum
             FROM validation_jobs_v0
             WHERE block_id=?1 AND view_be=?2 AND generation_be=?3",
            params![
                validation_id.block_id().as_bytes().as_slice(),
                validation_id.view().get().to_be_bytes().as_slice(),
                validation_id.generation().to_be_bytes().as_slice(),
            ],
            native_validation_existing_from_row_v0,
        )
        .optional()
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::ReadExisting,
                &error,
            )
        })
}

fn validate_native_validation_job_congruence_v0(
    facts: &NativeValidationReservationFactsV0,
    existing: &DurableNativeValidationJobV0,
    store: &ApplicationStore,
) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
    let stage = NativeValidationReservationStageV0::ReadExisting;
    if existing.facts.validation_id != facts.validation_id {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
            sqlite: None,
        });
    }
    if existing.facts.route != facts.route {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::RouteMismatch,
            sqlite: None,
        });
    }
    if existing.facts.target_height != facts.target_height {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::TargetHeightMismatch,
            sqlite: None,
        });
    }
    if existing.facts.parent_block_id != facts.parent_block_id {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::ParentBlockIdMismatch,
            sqlite: None,
        });
    }
    if existing.facts.request_fingerprint != facts.request_fingerprint {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::RequestFingerprintMismatch,
            sqlite: None,
        });
    }
    if existing.facts.target_header_cev0 != facts.target_header_cev0 {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::TargetHeaderMismatch,
            sqlite: None,
        });
    }
    if existing.facts.body_record != facts.body_record
        || existing.facts.body_checksum != facts.body_checksum
    {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::BodyRecordMismatch,
            sqlite: None,
        });
    }
    if existing.facts.parent_height != facts.parent_height
        || existing.facts.parent_view != facts.parent_view
        || existing.facts.parent_timestamp_ms != facts.parent_timestamp_ms
        || existing.facts.parent_header_cev0 != facts.parent_header_cev0
        || existing.facts.parent_state_version != facts.parent_state_version
        || existing.facts.parent_state_root != facts.parent_state_root
    {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::ParentContextMismatch,
            sqlite: None,
        });
    }
    if existing.facts.validator_set_id != facts.validator_set_id
        || existing.facts.parameters_hash != facts.parameters_hash
        || existing.facts.protocol_version != facts.protocol_version
        || existing.runtime_profile_ref
            != native_validation_runtime_profile_ref_v0(facts.protocol_version)
        || existing.host_config_ref != native_validation_host_config_ref_v0(store)
    {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::ConfigurationReferenceMismatch,
            sqlite: None,
        });
    }
    if existing.facts.creation_revision != facts.creation_revision {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::CreationRevisionMismatch,
            sqlite: None,
        });
    }
    Ok(())
}

fn insert_native_validation_job_v0(
    connection: &Connection,
    facts: &NativeValidationReservationFactsV0,
    store: &ApplicationStore,
) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
    validate_native_validation_request_record_semantics_v0(facts, store).map_err(|kind| {
        NativeValidationReservationFailureCauseV0::Invariant {
            stage: NativeValidationReservationStageV0::Insert,
            kind,
            sqlite: None,
        }
    })?;
    if !validate_native_validation_body_record_v0(&facts.body_record)
        || hash_domain(NATIVE_VALIDATION_BODY_DOMAIN_V0, &[&facts.body_record])
            != facts.body_checksum
    {
        return Err(NativeValidationReservationFailureCauseV0::HostInvariant {
            stage: NativeValidationReservationStageV0::Insert,
            sqlite: None,
        });
    }
    let validation_id = facts.validation_id;
    let runtime_profile_ref = native_validation_runtime_profile_ref_v0(facts.protocol_version);
    let host_config_ref = native_validation_host_config_ref_v0(store);
    let immutable_checksum =
        native_validation_job_immutable_checksum_v0(facts, &runtime_profile_ref, &host_config_ref);
    let state = NativeValidationJobStateV0::Reserved;
    let row_checksum = native_validation_job_row_checksum_v0(
        &immutable_checksum,
        state,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let parent_state_version_be = facts.parent_state_version.map(u64::to_be_bytes);
    connection
        .execute(
            "INSERT INTO validation_jobs_v0(
                 route, block_id, view_be, generation_be, target_height_be,
                 target_header_cev0, body_record_codec, body_record, body_checksum,
                 parent_height_be, parent_view_be, parent_block_id,
                 parent_timestamp_ms_be, parent_header_cev0,
                 parent_state_version_be, parent_state_root, validator_set_id,
                 parameters_hash, protocol_version_be, runtime_profile_ref,
                 host_config_ref, creation_revision_be, request_fingerprint,
                 immutable_checksum, state, result_kind, invalid_reason_code_be,
                 artifact_codec, artifact_bytes, artifact_checksum,
                 accepted_core_revision_be, accepted_core_payload_checksum,
                 row_codec, row_checksum
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, ?24
             )",
            params![
                native_validation_route_code_v0(facts.route),
                validation_id.block_id().as_bytes().as_slice(),
                validation_id.view().get().to_be_bytes().as_slice(),
                validation_id.generation().to_be_bytes().as_slice(),
                facts.target_height.to_be_bytes().as_slice(),
                facts.target_header_cev0.as_slice(),
                facts.body_record.as_slice(),
                facts.body_checksum.as_slice(),
                facts.parent_height.to_be_bytes().as_slice(),
                facts.parent_view.to_be_bytes().as_slice(),
                facts.parent_block_id.as_slice(),
                facts.parent_timestamp_ms.to_be_bytes().as_slice(),
                facts.parent_header_cev0.as_deref(),
                parent_state_version_be.as_ref().map(<[u8; 8]>::as_slice),
                facts.parent_state_root.as_ref().map(<[u8; 32]>::as_slice),
                facts.validator_set_id.as_slice(),
                facts.parameters_hash.as_slice(),
                facts.protocol_version.to_be_bytes().as_slice(),
                runtime_profile_ref.as_slice(),
                host_config_ref.as_slice(),
                facts.creation_revision.to_be_bytes().as_slice(),
                facts.request_fingerprint.as_slice(),
                immutable_checksum.as_slice(),
                row_checksum.as_slice(),
            ],
        )
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::Insert,
                &error,
            )
        })?;
    Ok(())
}

fn classify_native_validation_reservation_sqlite_failure_v0(
    stage: NativeValidationReservationStageV0,
    error: &rusqlite::Error,
) -> NativeValidationReservationFailureCauseV0 {
    match classify_sqlite_authenticated_read_failure_v0(
        AuthenticatedRuntimeReadStageV0::ValidateBindings,
        error,
    ) {
        AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::DatabaseUnavailable { stage, sqlite }
        }
        AuthenticatedRuntimeReadFailureV0::StorageUnavailable { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::StorageUnavailable { stage, sqlite }
        }
        AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::HostResourceUnavailable { stage, sqlite }
        }
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::Invariant {
                stage,
                kind: NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                sqlite,
            }
        }
        AuthenticatedRuntimeReadFailureV0::HostInvariant { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::HostInvariant { stage, sqlite }
        }
        AuthenticatedRuntimeReadFailureV0::SourceMismatch { .. }
        | AuthenticatedRuntimeReadFailureV0::Pruned { .. } => {
            NativeValidationReservationFailureCauseV0::HostInvariant {
                stage,
                sqlite: None,
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn classify_sqlite_authenticated_read_failure_v0(
    stage: AuthenticatedRuntimeReadStageV0,
    error: &rusqlite::Error,
) -> AuthenticatedRuntimeReadFailureV0 {
    let rusqlite::Error::SqliteFailure(error, _) = error else {
        return match error {
            rusqlite::Error::FromSqlConversionFailure(_, _, _)
            | rusqlite::Error::IntegralValueOutOfRange(_, _)
            | rusqlite::Error::Utf8Error(_)
            | rusqlite::Error::InvalidColumnType(_, _, _)
            | rusqlite::Error::QueryReturnedNoRows => {
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage,
                    sqlite: None,
                    reason: "persisted SQLite value does not match the authenticated schema",
                }
            }
            _ => AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage,
                sqlite: None,
                reason: "non-SQLite host API failure at an authenticated read boundary",
            },
        };
    };
    let sqlite = TypedSqliteReadCodeV0 {
        code: error.code,
        extended_code: error.extended_code,
    };
    match error.code {
        ErrorCode::DatabaseBusy
        | ErrorCode::DatabaseLocked
        | ErrorCode::OperationInterrupted
        | ErrorCode::FileLockingProtocolFailed => {
            AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable { stage, sqlite }
        }
        ErrorCode::PermissionDenied
        | ErrorCode::ReadOnly
        | ErrorCode::DiskFull
        | ErrorCode::CannotOpen
        | ErrorCode::NoLargeFileSupport => {
            AuthenticatedRuntimeReadFailureV0::StorageUnavailable { stage, sqlite }
        }
        ErrorCode::SystemIoFailure => classify_sqlite_system_io_failure_v0(stage, sqlite),
        ErrorCode::OutOfMemory => AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
            stage,
            sqlite: Some(sqlite),
            reason: "SQLite host resource limit prevented an authenticated read",
        },
        ErrorCode::DatabaseCorrupt
        | ErrorCode::NotADatabase
        | ErrorCode::TooBig
        | ErrorCode::TypeMismatch => {
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: Some(sqlite),
                reason: "SQLite authenticated-state representation is corrupt",
            }
        }
        ErrorCode::InternalMalfunction
        | ErrorCode::OperationAborted
        | ErrorCode::NotFound
        | ErrorCode::SchemaChanged
        | ErrorCode::ConstraintViolation
        | ErrorCode::ApiMisuse
        | ErrorCode::AuthorizationForStatementDenied
        | ErrorCode::ParameterOutOfRange
        | ErrorCode::Unknown => AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage,
            sqlite: Some(sqlite),
            reason: "SQLite returned a fail-stop host or unknown error code",
        },
        // `ErrorCode` is non-exhaustive. Future codes remain fail-stop until
        // they receive an explicit protocol-safe classification here.
        _ => AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage,
            sqlite: Some(sqlite),
            reason: "unclassified future SQLite error code",
        },
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn classify_sqlite_system_io_failure_v0(
    stage: AuthenticatedRuntimeReadStageV0,
    sqlite: TypedSqliteReadCodeV0,
) -> AuthenticatedRuntimeReadFailureV0 {
    match sqlite.extended_code {
        // Only these named VFS operation failures are retryable storage
        // dependencies. The primary SQLITE_IOERR code and future extended
        // codes are intentionally absent from this allowlist.
        rusqlite::ffi::SQLITE_IOERR_READ
        | rusqlite::ffi::SQLITE_IOERR_SHORT_READ
        | rusqlite::ffi::SQLITE_IOERR_WRITE
        | rusqlite::ffi::SQLITE_IOERR_FSYNC
        | rusqlite::ffi::SQLITE_IOERR_DIR_FSYNC
        | rusqlite::ffi::SQLITE_IOERR_TRUNCATE
        | rusqlite::ffi::SQLITE_IOERR_FSTAT
        | rusqlite::ffi::SQLITE_IOERR_UNLOCK
        | rusqlite::ffi::SQLITE_IOERR_RDLOCK
        | rusqlite::ffi::SQLITE_IOERR_DELETE
        | rusqlite::ffi::SQLITE_IOERR_BLOCKED
        | rusqlite::ffi::SQLITE_IOERR_ACCESS
        | rusqlite::ffi::SQLITE_IOERR_CHECKRESERVEDLOCK
        | rusqlite::ffi::SQLITE_IOERR_LOCK
        | rusqlite::ffi::SQLITE_IOERR_CLOSE
        | rusqlite::ffi::SQLITE_IOERR_DIR_CLOSE
        | rusqlite::ffi::SQLITE_IOERR_SHMOPEN
        | rusqlite::ffi::SQLITE_IOERR_SHMSIZE
        | rusqlite::ffi::SQLITE_IOERR_SHMLOCK
        | rusqlite::ffi::SQLITE_IOERR_SHMMAP
        | rusqlite::ffi::SQLITE_IOERR_SEEK
        | rusqlite::ffi::SQLITE_IOERR_DELETE_NOENT
        | rusqlite::ffi::SQLITE_IOERR_MMAP
        | rusqlite::ffi::SQLITE_IOERR_GETTEMPPATH
        | rusqlite::ffi::SQLITE_IOERR_BEGIN_ATOMIC
        | rusqlite::ffi::SQLITE_IOERR_COMMIT_ATOMIC
        | rusqlite::ffi::SQLITE_IOERR_ROLLBACK_ATOMIC => {
            AuthenticatedRuntimeReadFailureV0::StorageUnavailable { stage, sqlite }
        }
        rusqlite::ffi::SQLITE_IOERR_NOMEM => {
            AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                stage,
                sqlite: Some(sqlite),
                reason: "SQLite VFS memory exhaustion prevented an authenticated read",
            }
        }
        // DATA and IN_PAGE mean the persisted database page cannot be trusted,
        // so they are authenticated-state corruption rather than retryable I/O.
        rusqlite::ffi::SQLITE_IOERR_DATA | rusqlite::ffi::SQLITE_IOERR_IN_PAGE => {
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: Some(sqlite),
                reason: "SQLite reported untrustworthy authenticated database page data",
            }
        }
        // CORRUPTFS and VFS/path authorization failures describe the host
        // storage environment, not authenticated application state.
        rusqlite::ffi::SQLITE_IOERR_CORRUPTFS
        | rusqlite::ffi::SQLITE_IOERR_CONVPATH
        | rusqlite::ffi::SQLITE_IOERR_VNODE
        | rusqlite::ffi::SQLITE_IOERR_AUTH => AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage,
            sqlite: Some(sqlite),
            reason: "SQLite reported a fail-stop VFS or filesystem invariant",
        },
        _ => AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage,
            sqlite: Some(sqlite),
            reason: "unclassified SQLite system I/O extended code",
        },
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_read_failure_is_fail_stop_v0(
    failure: &AuthenticatedRuntimeReadFailureV0,
) -> bool {
    matches!(
        failure,
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. }
            | AuthenticatedRuntimeReadFailureV0::HostInvariant { .. }
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn merge_authenticated_runtime_read_and_rollback_v0<T>(
    result: std::result::Result<T, AuthenticatedRuntimeReadFailureV0>,
    rollback: std::result::Result<(), AuthenticatedRuntimeReadFailureV0>,
) -> std::result::Result<T, AuthenticatedRuntimeReadFailureV0> {
    match (result, rollback) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(rollback_error)) => Err(rollback_error),
        (Err(read_error), Ok(())) => Err(read_error),
        (Err(read_error), Err(rollback_error)) => {
            if authenticated_runtime_read_failure_is_fail_stop_v0(&rollback_error)
                && !authenticated_runtime_read_failure_is_fail_stop_v0(&read_error)
            {
                Err(rollback_error)
            } else {
                Err(read_error)
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn classify_authenticated_read_anyhow_v0(
    stage: AuthenticatedRuntimeReadStageV0,
    error: &anyhow::Error,
    invariant_reason: &'static str,
) -> AuthenticatedRuntimeReadFailureV0 {
    if let Some(sqlite) = error
        .chain()
        .find_map(|source| source.downcast_ref::<rusqlite::Error>())
    {
        return classify_sqlite_authenticated_read_failure_v0(stage, sqlite);
    }
    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
        stage,
        sqlite: None,
        reason: invariant_reason,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_required_metadata_v0(
    connection: &Connection,
    key: &str,
    stage: AuthenticatedRuntimeReadStageV0,
    missing_reason: &'static str,
) -> std::result::Result<String, AuthenticatedRuntimeReadFailureV0> {
    match connection.query_row(
        "SELECT value FROM metadata WHERE key=?1",
        params![key],
        |row| row.get(0),
    ) {
        Ok(value) => Ok(value),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: missing_reason,
            },
        ),
        Err(error) => Err(classify_sqlite_authenticated_read_failure_v0(stage, &error)),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_optional_metadata_v0(
    connection: &Connection,
    key: &str,
    stage: AuthenticatedRuntimeReadStageV0,
) -> std::result::Result<Option<String>, AuthenticatedRuntimeReadFailureV0> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| classify_sqlite_authenticated_read_failure_v0(stage, &error))
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_canonical_decimal_version_v0(
    value: &str,
    stage: AuthenticatedRuntimeReadStageV0,
    reason: &'static str,
) -> std::result::Result<Version, AuthenticatedRuntimeReadFailureV0> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason,
            },
        );
    }
    value.parse::<Version>().map_err(|_| {
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
            stage,
            sqlite: None,
            reason,
        }
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_head_v0(
    connection: &Connection,
) -> std::result::Result<Version, AuthenticatedRuntimeReadFailureV0> {
    let stage = AuthenticatedRuntimeReadStageV0::ReadHead;
    let value = authenticated_runtime_required_metadata_v0(
        connection,
        "height",
        stage,
        "application store is missing committed height",
    )?;
    parse_canonical_decimal_version_v0(
        &value,
        stage,
        "application store committed height is not canonical u64",
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn require_authenticated_query_floor_v0(
    connection: &Connection,
    requested: Version,
    committed_height: Version,
) -> std::result::Result<Version, AuthenticatedRuntimeReadFailureV0> {
    let stage = AuthenticatedRuntimeReadStageV0::ReadQueryFloor;
    let floor_value = authenticated_runtime_required_metadata_v0(
        connection,
        AUTH_QUERY_FLOOR_KEY,
        stage,
        "application store is missing durable authenticated query floor",
    )?;
    let floor = parse_canonical_decimal_version_v0(
        &floor_value,
        stage,
        "durable authenticated query floor is not canonical u64",
    )?;
    let target =
        authenticated_runtime_optional_metadata_v0(connection, AUTH_PRUNE_TARGET_KEY, stage)?
            .map(|value| {
                parse_canonical_decimal_version_v0(
                    &value,
                    stage,
                    "authenticated prune target is not canonical u64",
                )
            })
            .transpose()?;
    if floor > committed_height {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "durable authenticated query floor exceeds committed height",
            },
        );
    }
    if target.is_some_and(|target| target != floor) {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "authenticated prune target differs from durable query floor",
            },
        );
    }
    if authenticated_runtime_root_v0(connection, floor)?.is_none() {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "durable authenticated query floor has no retained root",
            },
        );
    }
    if requested < floor {
        return Err(AuthenticatedRuntimeReadFailureV0::Pruned { requested, floor });
    }
    if requested > committed_height {
        return Err(AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
            stage,
            sqlite: None,
            reason: "requested authenticated version is not committed locally",
        });
    }
    Ok(floor)
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_root_v0(
    connection: &Connection,
    version: Version,
) -> std::result::Result<Option<RootHash>, AuthenticatedRuntimeReadFailureV0> {
    let stage = AuthenticatedRuntimeReadStageV0::ReadRoot;
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT root_hash FROM auth_roots WHERE version_be=?1",
            params![version.to_be_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| classify_sqlite_authenticated_read_failure_v0(stage, &error))?;
    encoded
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map(RootHash)
                .map_err(
                    |_| AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage,
                        sqlite: None,
                        reason: "persisted authenticated root is not 32 bytes",
                    },
                )
        })
        .transpose()
}

#[cfg_attr(not(test), allow(dead_code))]
fn load_authenticated_runtime_object_at_v0(
    connection: &Connection,
    height: Version,
    root_hash: RootHash,
    object_key_hex: &str,
) -> std::result::Result<Option<StoredObject>, AuthenticatedRuntimeReadFailureV0> {
    let key = stored_object_key(object_key_hex).map_err(|_| {
        AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::DeriveObjectKey,
            sqlite: None,
            reason: "runtime object key is not canonical",
        }
    })?;
    let object = load_authenticated_runtime_object_row_v0(connection, object_key_hex)?;
    let reader = SqliteAuthReader { connection };
    let proof = prove_with_reader(&reader, height, root_hash, key).map_err(|error| {
        classify_authenticated_read_anyhow_v0(
            AuthenticatedRuntimeReadStageV0::BuildProof,
            &error,
            "persisted authenticated proof reconstruction failed",
        )
    })?;
    match &object {
        Some(object) => {
            let expected = AuthenticatedObjectRecord::new(
                object.object_type.clone(),
                object.version,
                object.value_bytes.clone(),
            )
            .and_then(|record| record.encode())
            .map_err(|error| {
                classify_authenticated_read_anyhow_v0(
                    AuthenticatedRuntimeReadStageV0::VerifyObject,
                    &error,
                    "persisted object cannot form its authenticated record",
                )
            })?;
            if proof.value.as_deref() != Some(expected.as_slice())
                || !verify_ics23_membership(&proof, &expected)
            {
                return Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                        sqlite: None,
                        reason: "physical object differs from authenticated state",
                    },
                );
            }
        }
        None => {
            if proof.value.is_some() || !verify_ics23_non_membership(&proof) {
                return Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                        sqlite: None,
                        reason: "physical object absence differs from authenticated state",
                    },
                );
            }
        }
    }
    Ok(object)
}

fn load_authenticated_validator_lifecycle_at_v0(
    connection: &Connection,
    height: Version,
    root_hash: RootHash,
) -> std::result::Result<ValidatorLifecycleStateV1, AuthenticatedRuntimeReadFailureV0> {
    let lifecycle_key =
        validator_state_key().map_err(|_| AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::DeriveObjectKey,
            sqlite: None,
            reason: "validator lifecycle authenticated key cannot be derived",
        })?;
    let reader = SqliteAuthReader { connection };
    let proof = prove_with_reader(&reader, height, root_hash, lifecycle_key).map_err(|error| {
        classify_authenticated_read_anyhow_v0(
            AuthenticatedRuntimeReadStageV0::BuildProof,
            &error,
            "validator lifecycle authenticated proof reconstruction failed",
        )
    })?;
    let authenticated_value = proof.value.as_deref().ok_or(
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
            stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
            sqlite: None,
            reason: "authenticated parent state lacks validator lifecycle",
        },
    )?;
    if !verify_ics23_membership(&proof, authenticated_value) {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "validator lifecycle membership does not verify against parent root",
            },
        );
    }
    let record = AuthenticatedObjectRecord::decode(authenticated_value).map_err(|error| {
        classify_authenticated_read_anyhow_v0(
            AuthenticatedRuntimeReadStageV0::VerifyObject,
            &error,
            "authenticated validator lifecycle record is malformed",
        )
    })?;
    if record.object_type != VALIDATOR_LIFECYCLE_SCHEMA_V1 || record.object_version > height {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "authenticated validator lifecycle record metadata is invalid",
            },
        );
    }
    let physical_value: Vec<u8> = connection
        .query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            classify_sqlite_authenticated_read_failure_v0(
                AuthenticatedRuntimeReadStageV0::ReadObject,
                &error,
            )
        })?;
    if physical_value != record.value {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "physical validator lifecycle differs from authenticated parent state",
            },
        );
    }
    let lifecycle: ValidatorLifecycleStateV1 =
        serde_json::from_slice(&record.value).map_err(|_| {
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "authenticated validator lifecycle JSON is malformed",
            }
        })?;
    lifecycle.validate().map_err(|_| {
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
            stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
            sqlite: None,
            reason: "authenticated validator lifecycle is not canonical",
        }
    })?;
    let expected_chain_id = authenticated_runtime_required_metadata_v0(
        connection,
        "chain_id",
        AuthenticatedRuntimeReadStageV0::ValidateBindings,
        "application store is missing chain binding",
    )?;
    let expected_signer_policy = authenticated_runtime_required_metadata_v0(
        connection,
        "authorized_signers_hash_hex",
        AuthenticatedRuntimeReadStageV0::ValidateBindings,
        "application store is missing signer-policy binding",
    )?;
    if lifecycle.chain_id != expected_chain_id
        || lifecycle.app_version != APP_VERSION
        || lifecycle.authorized_signers_hash_hex != expected_signer_policy
    {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                sqlite: None,
                reason: "authenticated validator lifecycle differs from store bindings",
            },
        );
    }
    Ok(lifecycle)
}

#[cfg_attr(not(test), allow(dead_code))]
fn load_authenticated_runtime_object_row_v0(
    connection: &Connection,
    object_key_hex: &str,
) -> std::result::Result<Option<StoredObject>, AuthenticatedRuntimeReadFailureV0> {
    let stage = AuthenticatedRuntimeReadStageV0::ReadObject;
    let raw_object = connection
        .query_row(
            "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
             FROM objects
             WHERE object_key_hex=?1",
            params![object_key_hex],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|error| classify_sqlite_authenticated_read_failure_v0(stage, &error))?;
    let Some((object_key_hex_value, object_type, version, value_hash_hex, value_bytes)) =
        raw_object
    else {
        return Ok(None);
    };
    let object = StoredObject {
        object_key_hex: object_key_hex_value,
        object_type,
        version: parse_canonical_decimal_version_v0(
            &version,
            stage,
            "persisted runtime object version is not canonical u64",
        )?,
        value_hash_hex,
        value_bytes,
    };
    if object.object_key_hex != object_key_hex {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "persisted object key differs from its physical lookup key",
            },
        );
    }
    if object.value_hash_hex
        != hex::encode(trnm_finality_types::hash_domain(
            "trnm.state.object.value.v1",
            &[&object.value_bytes],
        ))
    {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "persisted object value hash does not match its bytes",
            },
        );
    }
    Ok(Some(object))
}

fn load_object(connection: &Connection, object_key_hex: &str) -> Result<Option<StoredObject>> {
    let object = connection
        .query_row(
            "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
             FROM objects
             WHERE object_key_hex=?1",
            params![object_key_hex],
            |row| {
                Ok(StoredObject {
                    object_key_hex: row.get(0)?,
                    object_type: row.get(1)?,
                    version: row.get::<_, String>(2)?.parse::<u64>().map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    value_hash_hex: row.get(3)?,
                    value_bytes: row.get(4)?,
                })
            },
        )
        .optional()?;
    object
        .map(|object| validate_object(&object).map(|()| object))
        .transpose()
}

fn validate_object(object: &StoredObject) -> Result<()> {
    ensure!(
        object.value_hash_hex
            == hex::encode(trnm_finality_types::hash_domain(
                "trnm.state.object.value.v1",
                &[&object.value_bytes],
            )),
        "application store object value hash mismatch"
    );
    Ok(())
}

fn latest_auth_version(connection: &Connection) -> Result<Option<Version>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    encoded.map(|bytes| decode_version_be(&bytes)).transpose()
}

fn oldest_auth_version(connection: &Connection) -> Result<Option<Version>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    encoded.map(|bytes| decode_version_be(&bytes)).transpose()
}

fn auth_root(connection: &Connection, version: Version) -> Result<Option<RootHash>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT root_hash FROM auth_roots WHERE version_be=?1",
            params![version.to_be_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    encoded
        .map(|bytes| {
            Ok(RootHash(<[u8; 32]>::try_from(bytes.as_slice()).map_err(
                |_| anyhow!("persisted JMT root hash is not 32 bytes"),
            )?))
        })
        .transpose()
}

fn physical_prune_candidates_remain(connection: &Connection, target: Version) -> Result<bool> {
    let target_be = target.to_be_bytes();
    Ok(connection.query_row(
        "SELECT
             EXISTS(
                 SELECT 1 FROM auth_roots
                 WHERE version_be<?1
             )
             OR EXISTS(
                 SELECT 1 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
             )
             OR EXISTS(
                 SELECT 1 FROM auth_stale_values
                 WHERE stale_since_version_be<=?1
             )",
        params![target_be.as_slice()],
        |row| row.get::<_, bool>(0),
    )?)
}

fn metadata(connection: &Connection, key: &str) -> Result<String> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .with_context(|| format!("application store is missing {key}"))
}

fn optional_metadata_version(connection: &Connection, key: &str) -> Result<Option<Version>> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| {
            value
                .parse::<Version>()
                .with_context(|| format!("parse application store {key}"))
        })
        .transpose()
}

fn write_metadata_version(transaction: &Transaction<'_>, key: &str, value: Version) -> Result<()> {
    transaction.execute(
        "INSERT INTO metadata(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn validate_auth_prune_metadata(connection: &Connection) -> Result<()> {
    let floor = optional_metadata_version(connection, AUTH_QUERY_FLOOR_KEY)?
        .context("application store is missing authenticated query floor")?;
    let target = optional_metadata_version(connection, AUTH_PRUNE_TARGET_KEY)?;
    if let Some(target) = target {
        ensure!(
            target == floor,
            "authenticated prune target differs from the query floor"
        );
    }
    let height = connection
        .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()?
        .map(|value| {
            value
                .parse::<Version>()
                .context("parse application store height during prune metadata validation")
        })
        .transpose()?;
    match height {
        Some(height) => {
            ensure!(
                floor <= height && auth_root(connection, floor)?.is_some(),
                "application store authenticated query floor is invalid"
            );
            if target.is_none() {
                ensure!(
                    oldest_auth_version(connection)? == Some(floor),
                    "completed authenticated maintenance differs from its query floor"
                );
                ensure!(
                    !physical_prune_candidates_remain(connection, floor)?,
                    "completed authenticated maintenance still has prune candidates"
                );
            }
        }
        None => ensure!(
            floor == 0 && target.is_none(),
            "empty application store contains authenticated maintenance state"
        ),
    }
    Ok(())
}

fn migrate_store_schema_v3_to_v4(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        metadata(&transaction, "schema_version")? == LEGACY_STORE_SCHEMA_VERSION,
        "application store schema changed before v3 to v4 migration"
    );
    transaction.execute_batch(
        "
        CREATE UNIQUE INDEX IF NOT EXISTS auth_stale_nodes_by_node_key
            ON auth_stale_nodes(node_key);
        CREATE TABLE IF NOT EXISTS auth_stale_values (
            stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
            key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
            version_be BLOB NOT NULL CHECK(length(version_be)=8),
            PRIMARY KEY (stale_since_version_be, key_hash, version_be),
            UNIQUE (key_hash, version_be)
        ) STRICT;
        ",
    )?;
    let encoded: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let inferred_floor = encoded
        .map(|bytes| decode_version_be(&bytes))
        .transpose()?
        .unwrap_or(0);
    rebuild_auth_stale_values(&transaction)?;
    write_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY, inferred_floor)?;
    transaction.execute(
        "DELETE FROM metadata WHERE key=?1",
        params![AUTH_PRUNE_TARGET_KEY],
    )?;
    transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='schema_version'",
        params![STORE_SCHEMA_VERSION_V4],
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_store_schema_v4_to_v5(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        metadata(&transaction, "schema_version")? == STORE_SCHEMA_VERSION_V4,
        "application store schema changed before v4 to v5 migration"
    );
    transaction.execute_batch(LEGACY_NATIVE_VALIDATION_RESERVATIONS_SCHEMA_V5_SQL)?;
    transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='schema_version'",
        params![STORE_SCHEMA_VERSION_V5],
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_store_schema_v5_to_v6(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        metadata(&transaction, "schema_version")? == STORE_SCHEMA_VERSION_V5,
        "application store schema changed before v5 to v6 migration"
    );
    let legacy_reservations = transaction.query_row(
        "SELECT COUNT(*) FROM native_validation_reservations",
        [],
        |row| row.get::<_, u64>(0),
    )?;
    ensure!(
        legacy_reservations == 0,
        "application store schema v5 contains unreplayable native validation reservations"
    );
    transaction.execute_batch(NATIVE_VALIDATION_JOURNAL_SCHEMA_V0_SQL)?;
    transaction.execute_batch("DROP TABLE native_validation_reservations;")?;
    transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='schema_version'",
        params![STORE_SCHEMA_VERSION_V6],
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_store_schema_v6_to_v7(
    connection: &mut Connection,
    store: &ApplicationStore,
) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        metadata(&transaction, "schema_version")? == STORE_SCHEMA_VERSION_V6,
        "application store schema changed before v6 to v7 migration"
    );
    ensure!(
        store.verify_compatible_database_bindings(&transaction)? == STORE_SCHEMA_VERSION_V6,
        "application store bindings changed before v6 to v7 migration"
    );
    // Schema v6 deliberately activated only revalidatable Reserved jobs. Before
    // changing the version marker, authenticate every row and the journal-wide
    // accounting/FK/resource invariants inside the same writer transaction.
    // This makes the metadata-only activation atomic: a malformed row, future
    // state, callback child, or accounting drift leaves the database at v6.
    read_reserved_only_native_validation_journal_accounting_v0(
        &transaction,
        NativeValidationReservationStageV0::ReadExisting,
    )
    .map_err(|cause| anyhow!("schema-v6 reserved-only journal invariant: {cause:?}"))?;
    store
        .visit_native_validation_recovery_work_v0(&transaction, |job| {
            drop(job);
            Ok(())
        })
        .context("validate schema-v6 reserved-only native validation journal")?;
    transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='schema_version'",
        params![STORE_SCHEMA_VERSION_V7],
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_store_schema_v7_to_v8(
    connection: &mut Connection,
    store: &ApplicationStore,
) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        metadata(&transaction, "schema_version")? == STORE_SCHEMA_VERSION_V7,
        "application store schema changed before v7 to v8 migration"
    );
    ensure!(
        store.verify_compatible_database_bindings(&transaction)? == STORE_SCHEMA_VERSION_V7,
        "application store bindings changed before v7 to v8 migration"
    );
    // V7 admits only Reserved and callback-pending deterministic-invalid
    // records with their initial attempt-zero outbox. Authenticate that exact
    // semantic set before enabling the delivery/acknowledgement recovery
    // states; the physical schema is deliberately unchanged.
    read_active_native_validation_journal_accounting_v0(
        &transaction,
        NativeValidationReservationStageV0::ReadExisting,
    )
    .map_err(|cause| anyhow!("schema-v7 callback-pending journal invariant: {cause:?}"))?;
    store
        .visit_native_validation_recovery_work_v0(&transaction, |job| {
            drop(job);
            Ok(())
        })
        .context("validate schema-v7 native validation journal before v8 activation")?;
    transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='schema_version'",
        params![STORE_SCHEMA_VERSION_V8],
    )?;
    transaction.commit()?;
    Ok(())
}

fn ensure_metadata_binding(connection: &Connection, key: &str, expected: &str) -> Result<()> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    match actual {
        Some(actual) => ensure!(
            actual == expected,
            "application store {key} differs from configured value"
        ),
        None => {
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES (?1, ?2)",
                params![key, expected],
            )?;
        }
    }
    Ok(())
}

fn validate_snapshot_schema(connection: &Connection) -> Result<()> {
    let schema_version = metadata(connection, "schema_version")?;
    ensure!(
        schema_version == STORE_SCHEMA_VERSION
            || schema_version == STORE_SCHEMA_VERSION_V7
            || schema_version == STORE_SCHEMA_VERSION_V6
            || schema_version == STORE_SCHEMA_VERSION_V5
            || schema_version == STORE_SCHEMA_VERSION_V4
            || schema_version == LEGACY_STORE_SCHEMA_VERSION,
        "SQLite snapshot store schema is unsupported"
    );
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(STORE_SCHEMA_SQL)?;
    canonical.execute_batch(NATIVE_VALIDATION_JOURNAL_SCHEMA_V0_SQL)?;
    if schema_version != STORE_SCHEMA_VERSION
        && schema_version != STORE_SCHEMA_VERSION_V7
        && schema_version != STORE_SCHEMA_VERSION_V6
    {
        canonical.execute_batch(
            "DROP TABLE validation_callback_outbox_v0;
             DROP TABLE validation_jobs_v0;
             DROP TABLE validation_journal_accounting_v0;",
        )?;
    }
    if schema_version == STORE_SCHEMA_VERSION_V5 {
        canonical.execute_batch(LEGACY_NATIVE_VALIDATION_RESERVATIONS_SCHEMA_V5_SQL)?;
    }
    if schema_version == LEGACY_STORE_SCHEMA_VERSION {
        canonical.execute_batch(
            "
            DROP INDEX auth_stale_nodes_by_node_key;
            DROP TABLE auth_stale_values;
            ",
        )?;
    }
    let expected = schema_objects(&canonical)?;
    let actual = schema_objects(connection)?;
    ensure!(
        actual == expected,
        "SQLite snapshot schema differs from the canonical store schema"
    );
    Ok(())
}

fn validate_foreign_key_integrity(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    ensure!(
        rows.next()?.is_none(),
        "SQLite store contains a foreign-key violation"
    );
    Ok(())
}

fn validate_storage_resource_bounds(connection: &Connection) -> Result<()> {
    for (table, column, maximum) in [
        ("metadata", "key", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("metadata", "value", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "object_key_hex", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "object_type", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "version", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "value_hash_hex", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "value_bytes", MAX_SNAPSHOT_OBJECT_VALUE_BYTES),
        ("command_ids", "command_id", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("signer_nonces", "signer_id", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        (
            "validator_lifecycle",
            "state_json",
            MAX_SNAPSHOT_LIFECYCLE_BYTES,
        ),
        ("auth_nodes", "node_key", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("auth_nodes", "node", MAX_SNAPSHOT_AUTH_NODE_BYTES),
        ("auth_values", "value", MAX_SNAPSHOT_AUTH_VALUE_BYTES),
        (
            "auth_preimages",
            "key_preimage",
            MAX_SNAPSHOT_KEY_PREIMAGE_BYTES,
        ),
        (
            "auth_stale_nodes",
            "node_key",
            MAX_SNAPSHOT_IDENTIFIER_BYTES,
        ),
    ] {
        let query = format!("SELECT COALESCE(MAX(length(CAST({column} AS BLOB))), 0) FROM {table}");
        let observed = connection.query_row(&query, [], |row| row.get::<_, u64>(0))?;
        ensure!(
            observed <= maximum,
            "SQLite store {table}.{column} exceeds the {maximum}-byte resource limit"
        );
    }
    let schema_version = metadata(connection, "schema_version")?;
    match schema_version.as_str() {
        STORE_SCHEMA_VERSION | STORE_SCHEMA_VERSION_V7 | STORE_SCHEMA_VERSION_V6 => {
            let jobs =
                connection.query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
                    row.get::<_, u64>(0)
                })?;
            ensure!(
                jobs <= MAX_NATIVE_VALIDATION_RESERVATIONS,
                "SQLite store native validation jobs exceed the {MAX_NATIVE_VALIDATION_RESERVATIONS}-row resource limit"
            );
            let outbox = connection.query_row(
                "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                outbox <= jobs,
                "SQLite store native validation callback outbox exceeds its job count"
            );
            let request_bytes = connection.query_row(
                "SELECT COALESCE(SUM(
                     length(target_header_cev0) + length(body_record) +
                     COALESCE(length(parent_header_cev0), 0)
                 ), 0)
                 FROM validation_jobs_v0",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                request_bytes <= MAX_NATIVE_VALIDATION_REQUEST_JOURNAL_BYTES,
                "SQLite store native validation request journal exceeds the {MAX_NATIVE_VALIDATION_REQUEST_JOURNAL_BYTES}-byte resource limit"
            );
            let maximum_artifact_bytes = connection.query_row(
                "SELECT COALESCE(MAX(length(artifact_bytes)), 0) FROM validation_jobs_v0",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                maximum_artifact_bytes <= MAX_NATIVE_VALIDATION_ARTIFACT_BYTES,
                "SQLite store native validation artifact exceeds the {MAX_NATIVE_VALIDATION_ARTIFACT_BYTES}-byte resource limit"
            );
            let artifact_journal_bytes = connection.query_row(
                "SELECT COALESCE(SUM(COALESCE(length(artifact_bytes), 0)), 0)
                 FROM validation_jobs_v0",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                artifact_journal_bytes <= MAX_NATIVE_VALIDATION_ARTIFACT_JOURNAL_BYTES,
                "SQLite store native validation artifact journal exceeds the {MAX_NATIVE_VALIDATION_ARTIFACT_JOURNAL_BYTES}-byte aggregate resource limit"
            );
            let maximum_callback_bytes = connection.query_row(
                "SELECT COALESCE(MAX(length(payload_bytes)), 0)
                 FROM validation_callback_outbox_v0",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                maximum_callback_bytes <= MAX_NATIVE_VALIDATION_CALLBACK_BYTES,
                "SQLite store native validation callback exceeds the {MAX_NATIVE_VALIDATION_CALLBACK_BYTES}-byte resource limit"
            );
            let callback_outbox_bytes = connection.query_row(
                "SELECT COALESCE(SUM(length(payload_bytes)), 0)
                 FROM validation_callback_outbox_v0",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                callback_outbox_bytes <= MAX_NATIVE_VALIDATION_CALLBACK_OUTBOX_BYTES,
                "SQLite store native validation callback outbox exceeds the {MAX_NATIVE_VALIDATION_CALLBACK_OUTBOX_BYTES}-byte aggregate resource limit"
            );
            let accounting = decode_native_validation_journal_accounting_v0(
                native_validation_journal_accounting_raw_v0(connection)?,
            )
            .context("SQLite store native validation accounting row is malformed")?;
            ensure!(
                accounting
                    == (NativeValidationJournalAccountingV0 {
                        job_count: jobs,
                        request_bytes,
                        artifact_bytes: artifact_journal_bytes,
                        outbox_count: outbox,
                        outbox_bytes: callback_outbox_bytes,
                    }),
                "SQLite store native validation accounting differs from journal contents"
            );
            if schema_version == STORE_SCHEMA_VERSION_V6 {
                read_reserved_only_native_validation_journal_accounting_v0(
                    connection,
                    NativeValidationReservationStageV0::ReadExisting,
                )
                .map_err(|cause| {
                    anyhow!("application-store schema-v6 validation journal invariant: {cause:?}")
                })?;
            } else if schema_version == STORE_SCHEMA_VERSION_V7 {
                read_active_native_validation_journal_accounting_v0(
                    connection,
                    NativeValidationReservationStageV0::ReadExisting,
                )
                .map_err(|cause| {
                    anyhow!("application-store schema-v7 validation journal invariant: {cause:?}")
                })?;
            } else {
                read_delivery_native_validation_journal_accounting_v0(
                    connection,
                    NativeValidationReservationStageV0::ReadExisting,
                )
                .map_err(|cause| {
                    anyhow!("application-store schema-v8 validation journal invariant: {cause:?}")
                })?;
            }
        }
        STORE_SCHEMA_VERSION_V5 => {
            let reservations = connection.query_row(
                "SELECT COUNT(*) FROM native_validation_reservations",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                reservations <= MAX_NATIVE_VALIDATION_RESERVATIONS,
                "SQLite store native validation reservations exceed the {MAX_NATIVE_VALIDATION_RESERVATIONS}-row resource limit"
            );
        }
        STORE_SCHEMA_VERSION_V4 | LEGACY_STORE_SCHEMA_VERSION => {}
        _ => unreachable!("schema version was validated before resource bounds"),
    }
    Ok(())
}

fn schema_objects(
    connection: &Connection,
) -> Result<std::collections::BTreeMap<(String, String), String>> {
    let mut objects = std::collections::BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT type, name, sql
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        let (kind, name, sql) = row?;
        let sql = sql
            .context("SQLite snapshot table is missing CREATE statement")?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        ensure!(
            objects.insert((kind, name), sql).is_none(),
            "SQLite snapshot contains duplicate schema object"
        );
    }
    Ok(objects)
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove stale temporary file {}", path.display()))
        }
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn remove_sqlite_sidecars(path: &Path) -> Result<()> {
    remove_file_if_exists(&sqlite_sidecar(path, "-wal"))?;
    remove_file_if_exists(&sqlite_sidecar(path, "-shm"))
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cold]
fn fail_stop_after_snapshot_install(error: anyhow::Error) -> ! {
    eprintln!(
        "[trnm-cometbft-app] fatal error after authoritative snapshot installation; \
         restart is required before serving ABCI: {error:#}"
    );
    #[cfg(not(test))]
    std::process::abort();
    #[cfg(test)]
    panic!("fatal post-install snapshot error: {error:#}");
}

#[cfg(test)]
mod authenticated_runtime_read_taxonomy_tests {
    use super::*;

    fn sqlite_failure(code: i32) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
    }

    #[test]
    fn sqlite_error_codes_have_closed_retry_or_fail_stop_classes() {
        let stage = AuthenticatedRuntimeReadStageV0::ReadObject;
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_BUSY_RECOVERY),
            ),
            AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable {
                sqlite: TypedSqliteReadCodeV0 {
                    code: ErrorCode::DatabaseBusy,
                    extended_code: rusqlite::ffi::SQLITE_BUSY_RECOVERY,
                },
                ..
            }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_IOERR_READ),
            ),
            AuthenticatedRuntimeReadFailureV0::StorageUnavailable {
                sqlite: TypedSqliteReadCodeV0 {
                    code: ErrorCode::SystemIoFailure,
                    extended_code: rusqlite::ffi::SQLITE_IOERR_READ,
                },
                ..
            }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_IOERR_NOMEM),
            ),
            AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { .. }
        ));
        for code in [
            rusqlite::ffi::SQLITE_IOERR_DATA,
            rusqlite::ffi::SQLITE_IOERR_IN_PAGE,
        ] {
            assert!(matches!(
                classify_sqlite_authenticated_read_failure_v0(stage, &sqlite_failure(code)),
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    sqlite: Some(TypedSqliteReadCodeV0 {
                        code: ErrorCode::SystemIoFailure,
                        extended_code,
                    }),
                    ..
                } if extended_code == code
            ));
        }
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_IOERR_CORRUPTFS),
            ),
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                sqlite: Some(TypedSqliteReadCodeV0 {
                    code: ErrorCode::SystemIoFailure,
                    extended_code: rusqlite::ffi::SQLITE_IOERR_CORRUPTFS,
                }),
                ..
            }
        ));
        let unknown_ioerr = rusqlite::ffi::SQLITE_IOERR | (63 << 8);
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(unknown_ioerr),
            ),
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                sqlite: Some(TypedSqliteReadCodeV0 {
                    code: ErrorCode::SystemIoFailure,
                    extended_code,
                }),
                ..
            } if extended_code == unknown_ioerr
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_NOMEM),
            ),
            AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_CORRUPT),
            ),
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_TOOBIG),
            ),
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_SCHEMA),
            ),
            AuthenticatedRuntimeReadFailureV0::HostInvariant { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_CONSTRAINT),
            ),
            AuthenticatedRuntimeReadFailureV0::HostInvariant { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(stage, &sqlite_failure(0x7f)),
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                sqlite: Some(TypedSqliteReadCodeV0 {
                    code: ErrorCode::Unknown,
                    extended_code: 0x7f,
                }),
                ..
            }
        ));
    }

    #[test]
    fn fail_stop_rollback_error_outranks_retryable_or_pruned_read_failure() {
        let rollback_fail_stop = AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
            stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
            sqlite: None,
            reason: "rollback exposed an authenticated-state invariant",
        };
        assert_eq!(
            merge_authenticated_runtime_read_and_rollback_v0::<()>(
                Err(AuthenticatedRuntimeReadFailureV0::Pruned {
                    requested: 4,
                    floor: 5,
                }),
                Err(rollback_fail_stop.clone()),
            ),
            Err(rollback_fail_stop.clone())
        );
        assert_eq!(
            merge_authenticated_runtime_read_and_rollback_v0::<()>(
                Err(AuthenticatedRuntimeReadFailureV0::StorageUnavailable {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    sqlite: TypedSqliteReadCodeV0 {
                        code: ErrorCode::SystemIoFailure,
                        extended_code: rusqlite::ffi::SQLITE_IOERR_READ,
                    },
                }),
                Err(rollback_fail_stop.clone()),
            ),
            Err(rollback_fail_stop)
        );

        let rollback_fail_stop = AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
            sqlite: None,
            reason: "rollback exposed a host invariant",
        };
        assert_eq!(
            merge_authenticated_runtime_read_and_rollback_v0::<()>(
                Err(AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    reason: "requested parent is not the committed source",
                }),
                Err(rollback_fail_stop.clone()),
            ),
            Err(rollback_fail_stop)
        );

        let read_fail_stop = AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::BuildProof,
            sqlite: None,
            reason: "primary read exposed a host invariant",
        };
        assert_eq!(
            merge_authenticated_runtime_read_and_rollback_v0::<()>(
                Err(read_fail_stop.clone()),
                Err(AuthenticatedRuntimeReadFailureV0::StorageUnavailable {
                    stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    sqlite: TypedSqliteReadCodeV0 {
                        code: ErrorCode::SystemIoFailure,
                        extended_code: rusqlite::ffi::SQLITE_IOERR_FSYNC,
                    },
                }),
            ),
            Err(read_fail_stop)
        );
    }

    #[test]
    fn typed_runtime_object_api_preserves_cannot_open_as_storage_unavailable() {
        let root = std::env::temp_dir().join(format!(
            "trnm-authenticated-runtime-read-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create typed-read test directory");
        let path = root.join("state.json");
        let store = ApplicationStore::open(&path, "typed-read-test", &"00".repeat(32))
            .expect("construct store path");
        assert!(matches!(
            store.load_authenticated_runtime_object_v0("00"),
            Err(AuthenticatedRuntimeReadFailureV0::StorageUnavailable {
                stage: AuthenticatedRuntimeReadStageV0::OpenDatabase,
                sqlite: TypedSqliteReadCodeV0 {
                    code: ErrorCode::CannotOpen,
                    ..
                },
            })
        ));
        drop(store);
        fs::remove_dir_all(root).expect("remove typed-read test directory");
    }

    fn floor_test_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("open in-memory SQLite");
        connection
            .execute_batch(
                "
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE auth_roots (
                    version_be BLOB PRIMARY KEY NOT NULL CHECK(length(version_be)=8),
                    root_hash BLOB NOT NULL
                ) STRICT;
                ",
            )
            .expect("create floor-test schema");
        connection
    }

    fn authenticated_runtime_snapshot_store() -> (
        PathBuf,
        PathBuf,
        ApplicationStore,
        [u8; 32],
        BTreeMap<String, StoredObject>,
    ) {
        let root = std::env::temp_dir().join(format!(
            "trnm-authenticated-runtime-snapshot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create snapshot test directory");
        let status_path = root.join("state.json");
        let signer_policy_hash_hex = "11".repeat(32);
        let store = ApplicationStore::open(
            &status_path,
            "authenticated-runtime-snapshot-test",
            &signer_policy_hash_hex,
        )
        .expect("construct snapshot test store");
        let expected = store
            .load_or_migrate()
            .expect("initialize snapshot test store");
        let objects = [
            ("snapshot-object-a", "alpha", b"alpha-value".as_slice()),
            ("snapshot-object-b", "beta", b"beta-value".as_slice()),
        ]
        .into_iter()
        .map(|(object_key_hex, object_type, value_bytes)| {
            let value_bytes = value_bytes.to_vec();
            let object = StoredObject {
                object_key_hex: object_key_hex.to_string(),
                object_type: object_type.to_string(),
                version: 1,
                value_hash_hex: hex::encode(trnm_finality_types::hash_domain(
                    "trnm.state.object.value.v1",
                    &[&value_bytes],
                )),
                value_bytes,
            };
            (object.object_key_hex.clone(), object)
        })
        .collect::<BTreeMap<_, _>>();
        let writes = objects
            .values()
            .map(|object| {
                let record = AuthenticatedObjectRecord::new(
                    object.object_type.clone(),
                    object.version,
                    object.value_bytes.clone(),
                )
                .and_then(|record| record.encode())
                .expect("encode snapshot test object record");
                AuthWrite::put(
                    stored_object_key(&object.object_key_hex)
                        .expect("derive snapshot test object key"),
                    record,
                )
                .expect("construct snapshot test authenticated write")
            })
            .collect::<Vec<_>>();
        let update = store
            .plan_auth_update(0, writes)
            .expect("plan snapshot test authenticated update");
        let app_hash = <[u8; 32]>::from(update.root_hash);
        let state = AppState {
            objects: objects.clone(),
            app_hash,
            ..AppState::default()
        };
        store
            .replace_empty_state(&expected, &state, &update)
            .expect("persist snapshot test state");
        (root, status_path, store, app_hash, objects)
    }

    #[test]
    fn authenticated_runtime_snapshot_binds_expected_parent_and_same_transaction_bindings() {
        let (root, status_path, store, app_hash, _) = authenticated_runtime_snapshot_store();

        for (height, expected_root) in [(1, app_hash), (0, [9_u8; 32])] {
            assert!(matches!(
                store.begin_authenticated_runtime_read_snapshot_for_test_v0(height, expected_root,),
                Err(AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    ..
                })
            ));
        }

        let wrong_chain = ApplicationStore::open(
            &status_path,
            "wrong-authenticated-runtime-snapshot-chain",
            &"11".repeat(32),
        )
        .expect("construct wrong-chain snapshot store handle");
        assert!(matches!(
            wrong_chain.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    ..
                }
            )
        ));

        {
            let _maintenance = store
                .maintenance_gate
                .lock()
                .expect("lock snapshot test maintenance gate");
            assert!(matches!(
                store.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
                Err(AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                    stage: AuthenticatedRuntimeReadStageV0::BeginSnapshot,
                    ..
                })
            ));
        }

        let connection = store.connect().expect("open future-root writer");
        connection
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                params![1_u64.to_be_bytes().as_slice(), [7_u8; 32].as_slice()],
            )
            .expect("insert orphan future authenticated root");
        drop(connection);
        assert!(matches!(
            store.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    ..
                }
            )
        ));
        let connection = store.connect().expect("open future-root cleanup writer");
        connection
            .execute(
                "DELETE FROM auth_roots WHERE version_be=?1",
                params![1_u64.to_be_bytes().as_slice()],
            )
            .expect("remove orphan future authenticated root");
        drop(connection);

        let connection = store.connect().expect("open snapshot test writer");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='app_hash_hex'",
                params![hex::encode([8_u8; 32])],
            )
            .expect("corrupt committed app hash");
        drop(connection);
        assert!(matches!(
            store.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    ..
                }
            )
        ));

        let connection = store.connect().expect("open noncanonical app-hash writer");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='app_hash_hex'",
                params![hex::encode(app_hash).to_uppercase()],
            )
            .expect("write noncanonical committed app hash");
        drop(connection);
        assert!(matches!(
            store.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadHead,
                    ..
                }
            )
        ));

        let connection = store.connect().expect("open snapshot test repair writer");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='app_hash_hex'",
                params![hex::encode(app_hash)],
            )
            .expect("repair committed app hash");
        drop(connection);
        let snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash)
            .expect("begin correctly bound authenticated runtime snapshot");
        snapshot.finish().expect("finish bound snapshot");

        drop(wrong_chain);
        drop(store);
        fs::remove_dir_all(root).expect("remove snapshot test directory");
    }

    #[test]
    fn authenticated_runtime_snapshot_reuses_one_pin_and_preserves_typed_failures() {
        let (root, _, store, app_hash, objects) = authenticated_runtime_snapshot_store();
        let snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash)
            .expect("begin authenticated runtime snapshot");
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 1);
        for (key, expected) in &objects {
            assert_eq!(
                snapshot
                    .load(key)
                    .expect("load authenticated snapshot object"),
                Some(expected.clone())
            );
        }
        assert_eq!(
            snapshot
                .load("snapshot-object-missing")
                .expect("verify authenticated non-membership"),
            None
        );
        snapshot
            .finish()
            .expect("finish authenticated runtime snapshot");
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 0);
        let dropped_snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash)
            .expect("begin snapshot for best-effort drop");
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 1);
        drop(dropped_snapshot);
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 0);

        let connection = store.connect().expect("open snapshot corruption writer");
        connection
            .execute(
                "UPDATE objects SET value_hash_hex=?1 WHERE object_key_hex='snapshot-object-a'",
                params!["00".repeat(32)],
            )
            .expect("corrupt physical object hash");
        drop(connection);
        let snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash)
            .expect("begin snapshot over checksum-consistent head metadata");
        assert!(matches!(
            snapshot.load("snapshot-object-a"),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    ..
                }
            )
        ));
        snapshot.finish().expect("finish corrupted-object snapshot");
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 0);

        drop(store);
        fs::remove_dir_all(root).expect("remove snapshot test directory");
    }

    #[test]
    fn required_query_floor_never_falls_back_and_pruned_is_typed() {
        let connection = floor_test_connection();
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 7, 7),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                    ..
                }
            )
        ));

        connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES (?1, 'seven')",
                rusqlite::params![AUTH_QUERY_FLOOR_KEY],
            )
            .expect("insert malformed floor");
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 7, 7),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                    ..
                }
            )
        ));

        connection
            .execute(
                "UPDATE metadata SET value='5' WHERE key=?1",
                rusqlite::params![AUTH_QUERY_FLOOR_KEY],
            )
            .expect("repair floor");
        connection
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                rusqlite::params![5_u64.to_be_bytes().as_slice(), [9_u8; 32].as_slice()],
            )
            .expect("insert floor root");
        assert_eq!(
            require_authenticated_query_floor_v0(&connection, 4, 7),
            Err(AuthenticatedRuntimeReadFailureV0::Pruned {
                requested: 4,
                floor: 5,
            })
        );
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 8, 7),
            Err(AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                ..
            })
        ));
    }

    #[test]
    fn typed_runtime_versions_require_canonical_decimal_u64() {
        let stage = AuthenticatedRuntimeReadStageV0::ReadHead;
        assert_eq!(
            parse_canonical_decimal_version_v0("0", stage, "invalid"),
            Ok(0)
        );
        assert_eq!(
            parse_canonical_decimal_version_v0(&u64::MAX.to_string(), stage, "invalid",),
            Ok(u64::MAX)
        );
        for value in [
            "",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "00",
            "18446744073709551616",
        ] {
            assert!(matches!(
                parse_canonical_decimal_version_v0(value, stage, "invalid"),
                Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage: AuthenticatedRuntimeReadStageV0::ReadHead,
                        ..
                    }
                )
            ));
        }

        let connection = floor_test_connection();
        connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES ('height', '01')",
                [],
            )
            .expect("insert noncanonical head");
        assert!(matches!(
            authenticated_runtime_head_v0(&connection),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadHead,
                    ..
                }
            )
        ));
        connection
            .execute("UPDATE metadata SET value='1' WHERE key='height'", [])
            .expect("repair head");
        connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES (?1, '01')",
                rusqlite::params![AUTH_QUERY_FLOOR_KEY],
            )
            .expect("insert noncanonical floor");
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 1, 1),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                    ..
                }
            )
        ));
        connection
            .execute(
                "UPDATE metadata SET value='1' WHERE key=?1",
                rusqlite::params![AUTH_QUERY_FLOOR_KEY],
            )
            .expect("repair floor");
        connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES (?1, '+1')",
                rusqlite::params![AUTH_PRUNE_TARGET_KEY],
            )
            .expect("insert noncanonical prune target");
        connection
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                rusqlite::params![1_u64.to_be_bytes().as_slice(), [7_u8; 32].as_slice()],
            )
            .expect("insert floor root");
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 1, 1),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                    ..
                }
            )
        ));

        connection
            .execute_batch(
                "
                CREATE TABLE objects (
                    object_key_hex TEXT PRIMARY KEY NOT NULL,
                    object_type TEXT NOT NULL,
                    version TEXT NOT NULL,
                    value_hash_hex TEXT NOT NULL,
                    value_bytes BLOB NOT NULL
                ) STRICT;
                ",
            )
            .expect("create object table");
        let value_bytes = [1_u8, 2];
        let value_hash_hex = hex::encode(trnm_finality_types::hash_domain(
            "trnm.state.object.value.v1",
            &[&value_bytes],
        ));
        connection
            .execute(
                "INSERT INTO objects(
                    object_key_hex, object_type, version, value_hash_hex, value_bytes
                 ) VALUES ('aa', 'test-v0', '01', ?1, ?2)",
                rusqlite::params![value_hash_hex, value_bytes.as_slice()],
            )
            .expect("insert noncanonical object version");
        assert!(matches!(
            load_authenticated_runtime_object_row_v0(&connection, "aa"),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    ..
                }
            )
        ));
    }

    #[test]
    fn checksum_consistent_root_and_object_corruption_remain_fail_stop() {
        let connection = floor_test_connection();
        connection
            .execute_batch(
                "
                CREATE TABLE objects (
                    object_key_hex TEXT PRIMARY KEY NOT NULL,
                    object_type TEXT NOT NULL,
                    version TEXT NOT NULL,
                    value_hash_hex TEXT NOT NULL,
                    value_bytes BLOB NOT NULL
                ) STRICT;
                ",
            )
            .expect("create object table");
        connection
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                rusqlite::params![3_u64.to_be_bytes().as_slice(), [1_u8; 31].as_slice()],
            )
            .expect("insert malformed root");
        assert!(matches!(
            authenticated_runtime_root_v0(&connection, 3),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    ..
                }
            )
        ));

        connection
            .execute(
                "INSERT INTO objects(
                    object_key_hex, object_type, version, value_hash_hex, value_bytes
                 ) VALUES ('aa', 'test-v0', '1', ?1, X'0102')",
                rusqlite::params!["00".repeat(32)],
            )
            .expect("insert inconsistent object");
        assert!(matches!(
            load_authenticated_runtime_object_row_v0(&connection, "aa"),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    ..
                }
            )
        ));
    }
}

#[cfg(test)]
mod native_validation_reservation_tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Barrier},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rusqlite::OptionalExtension;
    use trnm_consensus_core::{PayloadValidationRouteV0, ValidationId};
    use trnm_consensus_types::{
        decode_block_header_v0_exact, BlockHeader, BlockId, BlockKind, Epoch, Height,
    };

    use super::{
        metadata, migrate_store_schema_v4_to_v5, migrate_store_schema_v5_to_v6,
        migrate_store_schema_v6_to_v7, migrate_store_schema_v7_to_v8,
        native_validation_invalid_seal_failure_v0, schema_objects, validate_snapshot_schema,
        ApplicationStore, NativeValidationInvalidSealFailureCauseV0,
        NativeValidationReservationDecisionV0, NativeValidationReservationFactsV0,
        NativeValidationReservationFailureCauseV0, NativeValidationReservationInvariantV0,
        NativeValidationReservationStageV0, LEGACY_NATIVE_VALIDATION_RESERVATIONS_SCHEMA_V5_SQL,
        STORE_SCHEMA_VERSION, STORE_SCHEMA_VERSION_V4, STORE_SCHEMA_VERSION_V5,
        STORE_SCHEMA_VERSION_V6, STORE_SCHEMA_VERSION_V7,
    };

    #[test]
    fn invalid_seal_preserves_fail_stop_reservation_causes() {
        let invariant = native_validation_invalid_seal_failure_v0(
            NativeValidationReservationFailureCauseV0::Invariant {
                stage: NativeValidationReservationStageV0::Insert,
                kind: NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                sqlite: None,
            },
        );
        assert_eq!(
            invariant,
            NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
            )
        );

        let host_invariant = native_validation_invalid_seal_failure_v0(
            NativeValidationReservationFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::Commit,
                sqlite: None,
            },
        );
        assert_eq!(
            host_invariant,
            NativeValidationInvalidSealFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::Commit,
            }
        );

        let unavailable = NativeValidationReservationFailureCauseV0::HostResourceUnavailable {
            stage: NativeValidationReservationStageV0::OpenDatabase,
            sqlite: None,
        };
        assert!(matches!(
            native_validation_invalid_seal_failure_v0(unavailable),
            NativeValidationInvalidSealFailureCauseV0::Storage(
                NativeValidationReservationFailureCauseV0::HostResourceUnavailable {
                    stage: NativeValidationReservationStageV0::OpenDatabase,
                    sqlite: None,
                }
            )
        ));
    }

    fn test_store(label: &str) -> (PathBuf, ApplicationStore) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "trnm-native-validation-reservation-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create reservation test directory");
        let store = ApplicationStore::open(
            &root.join("app.status"),
            "reservation-test-chain",
            &"11".repeat(32),
        )
        .expect("construct reservation test store");
        store
            .load_or_migrate()
            .expect("initialize reservation test store");
        (root, store)
    }

    fn facts(
        route: PayloadValidationRouteV0,
        generation: u64,
        parent: u8,
        fingerprint: u8,
    ) -> NativeValidationReservationFactsV0 {
        let mut facts = NativeValidationReservationFactsV0::new_for_test_v0(
            route,
            generation,
            "reservation-test-chain",
        );
        if parent != 8 {
            facts.parent_block_id = [parent; 32];
        }
        if fingerprint != 9 {
            facts.request_fingerprint = [fingerprint; 32];
        }
        facts
    }

    fn headerless_genesis_facts(
        route: PayloadValidationRouteV0,
        generation: u64,
    ) -> NativeValidationReservationFactsV0 {
        let mut facts = facts(route, generation, 8, 9);
        let previous = decode_block_header_v0_exact(&facts.target_header_cev0)
            .expect("decode validation-job target fixture");
        let genesis_block_id = BlockId::new(*previous.genesis_hash().as_bytes());
        let target = BlockHeader::new(
            previous.genesis_hash(),
            previous.chain_id(),
            previous.protocol_version(),
            Epoch::new(0),
            previous.view(),
            Height::new(1),
            BlockKind::Regular,
            genesis_block_id,
            previous.proposer_id(),
            previous.validator_set_id(),
            previous.consensus_parameters_hash(),
            previous.payload_digest(),
            previous.state_root(),
            previous.receipts_root(),
            previous.evidence_root(),
            previous.timestamp_ms(),
            None,
        )
        .expect("construct headerless-genesis target fixture");
        facts.validation_id = ValidationId::new(target.id(), target.view(), generation);
        facts.target_height = 1;
        facts.target_header_cev0 = target
            .try_cev0_bytes()
            .expect("encode headerless-genesis target fixture");
        facts.parent_height = 0;
        facts.parent_view = 0;
        facts.parent_block_id = *genesis_block_id.as_bytes();
        facts.parent_timestamp_ms = target.timestamp_ms() - 1;
        facts.parent_header_cev0 = None;
        facts.parent_state_version = None;
        facts.parent_state_root = None;
        facts.request_fingerprint =
            super::native_validation_reservation_fingerprint_from_record_v0(&facts)
                .expect("derive headerless-genesis request fingerprint");
        facts
    }

    fn table_exists(connection: &rusqlite::Connection, name: &str) -> bool {
        connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1",
                rusqlite::params![name],
                |_| Ok(()),
            )
            .optional()
            .expect("query table existence")
            .is_some()
    }

    fn downgrade_fresh_store_to_schema_v5(connection: &rusqlite::Connection) {
        connection
            .execute_batch(
                "DROP TABLE validation_callback_outbox_v0;
                 DROP TABLE validation_jobs_v0;
                 DROP TABLE validation_journal_accounting_v0;",
            )
            .expect("drop schema v6/v7 validation journal");
        connection
            .execute_batch(LEGACY_NATIVE_VALIDATION_RESERVATIONS_SCHEMA_V5_SQL)
            .expect("create schema v5 reservation table");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='schema_version'",
                rusqlite::params![STORE_SCHEMA_VERSION_V5],
            )
            .expect("set schema v5 fixture version");
    }

    fn downgrade_fresh_store_to_schema_v6(connection: &rusqlite::Connection) {
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='schema_version'",
                rusqlite::params![STORE_SCHEMA_VERSION_V6],
            )
            .expect("set schema v6 fixture version");
    }

    fn downgrade_fresh_store_to_schema_v7(connection: &rusqlite::Connection) {
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='schema_version'",
                rusqlite::params![STORE_SCHEMA_VERSION_V7],
            )
            .expect("set schema v7 fixture version");
    }

    fn install_callback_pending_invalid_fixture_v0(
        store: &ApplicationStore,
        route: PayloadValidationRouteV0,
        generation: u64,
    ) -> ValidationId {
        let reserved = facts(route, generation, 8, 9);
        let validation_id = reserved.validation_id;
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(reserved),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let mut connection = store.connect().expect("open callback-pending fixture");
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("begin callback-pending fixture transaction");
        let existing = super::load_native_validation_job_v0(&transaction, validation_id)
            .expect("load callback-pending fixture job")
            .expect("callback-pending fixture job exists");
        let durable = super::durable_native_validation_job_from_existing_v0(existing, store)
            .expect("verify callback-pending fixture reservation");
        let identity = super::native_validation_artifact_identity_v0(&durable);
        let reason = super::DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch;
        let artifact = super::prepare_durable_invalid_artifact_v0(identity, reason);
        let callback = super::prepare_durable_invalid_callback_v0(&artifact);
        let reason_code = reason.code_v0().to_be_bytes();
        let row_checksum = super::native_validation_job_row_checksum_v0(
            &durable.immutable_checksum,
            super::NativeValidationJobStateV0::CallbackPending,
            Some(i64::from(
                super::durable_deterministic_invalid_result_kind_v0(),
            )),
            Some(&reason_code),
            Some(artifact.artifact_codec()),
            Some(&artifact.checksum()),
            None,
            None,
        );
        assert_eq!(
            transaction
                .execute(
                    "UPDATE validation_jobs_v0
                     SET state=2, result_kind=?1, invalid_reason_code_be=?2,
                         artifact_codec=?3, artifact_bytes=?4, artifact_checksum=?5,
                         row_checksum=?6
                     WHERE route=?7 AND block_id=?8 AND view_be=?9 AND generation_be=?10
                       AND state=0 AND row_checksum=?11",
                    rusqlite::params![
                        i64::from(super::durable_deterministic_invalid_result_kind_v0()),
                        reason_code.as_slice(),
                        artifact.artifact_codec(),
                        artifact.encoded().as_slice(),
                        artifact.checksum().as_slice(),
                        row_checksum.as_slice(),
                        super::native_validation_route_code_v0(route),
                        validation_id.block_id().as_bytes().as_slice(),
                        validation_id.view().get().to_be_bytes().as_slice(),
                        validation_id.generation().to_be_bytes().as_slice(),
                        durable.row_checksum.as_slice(),
                    ],
                )
                .expect("write callback-pending fixture job"),
            1
        );
        transaction
            .execute(
                "INSERT INTO validation_callback_outbox_v0(
                     route, block_id, view_be, generation_be, result_kind,
                     artifact_checksum, payload_codec, payload_bytes,
                     payload_checksum, idempotency_key, delivery_attempt_be,
                     outbox_checksum
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                rusqlite::params![
                    super::native_validation_route_code_v0(route),
                    validation_id.block_id().as_bytes().as_slice(),
                    validation_id.view().get().to_be_bytes().as_slice(),
                    validation_id.generation().to_be_bytes().as_slice(),
                    i64::from(callback.result_kind()),
                    callback.artifact_checksum().as_slice(),
                    callback.payload_codec(),
                    callback.payload().as_slice(),
                    callback.payload_checksum().as_slice(),
                    callback.idempotency_key().as_slice(),
                    callback.delivery_attempt().to_be_bytes().as_slice(),
                    callback.outbox_checksum().as_slice(),
                ],
            )
            .expect("insert callback-pending fixture outbox");
        let accounting = super::read_bounded_native_validation_journal_accounting_v0(
            &transaction,
            NativeValidationReservationStageV0::ReadCapacity,
        )
        .expect("read callback-pending fixture accounting");
        transaction
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET artifact_bytes_be=?1, outbox_count_be=?2, outbox_bytes_be=?3
                 WHERE singleton=1",
                rusqlite::params![
                    accounting
                        .artifact_bytes
                        .checked_add(super::DURABLE_INVALID_ARTIFACT_BYTES_V0 as u64)
                        .expect("add fixture artifact bytes")
                        .to_be_bytes()
                        .as_slice(),
                    accounting
                        .outbox_count
                        .checked_add(1)
                        .expect("add fixture outbox count")
                        .to_be_bytes()
                        .as_slice(),
                    accounting
                        .outbox_bytes
                        .checked_add(super::DURABLE_INVALID_CALLBACK_BYTES_V0 as u64)
                        .expect("add fixture outbox bytes")
                        .to_be_bytes()
                        .as_slice(),
                ],
            )
            .expect("update callback-pending fixture accounting");
        transaction
            .commit()
            .expect("commit callback-pending fixture");
        validation_id
    }

    fn promote_invalid_fixture_to_delivered_v0(
        store: &ApplicationStore,
        validation_id: ValidationId,
        delivery_attempt: u64,
    ) {
        assert!(delivery_attempt > 0);
        let mut connection = store.connect().expect("open delivered fixture");
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("begin delivered fixture transaction");
        let existing = super::load_native_validation_job_v0(&transaction, validation_id)
            .expect("load delivered fixture job")
            .expect("delivered fixture job exists");
        let durable = super::durable_native_validation_job_from_existing_v0(existing, store)
            .expect("verify delivered fixture callback-pending job");
        super::verify_native_validation_job_outbox_v0(
            &transaction,
            &durable,
            NativeValidationReservationStageV0::ReadExisting,
        )
        .expect("verify delivered fixture initial outbox");
        let (payload_codec, payload_checksum, idempotency_key, old_outbox_checksum) = transaction
            .query_row(
                "SELECT payload_codec, payload_checksum, idempotency_key, outbox_checksum
                 FROM validation_callback_outbox_v0
                 WHERE route=?1 AND block_id=?2 AND view_be=?3 AND generation_be=?4",
                rusqlite::params![
                    super::native_validation_route_code_v0(durable.route()),
                    validation_id.block_id().as_bytes().as_slice(),
                    validation_id.view().get().to_be_bytes().as_slice(),
                    validation_id.generation().to_be_bytes().as_slice(),
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .expect("read delivered fixture outbox");
        let payload_checksum: [u8; 32] = payload_checksum
            .try_into()
            .expect("delivered fixture payload checksum length");
        let idempotency_key: [u8; 32] = idempotency_key
            .try_into()
            .expect("delivered fixture idempotency length");
        let old_outbox_checksum: [u8; 32] = old_outbox_checksum
            .try_into()
            .expect("delivered fixture outbox checksum length");
        let identity = super::native_validation_artifact_identity_v0(&durable);
        let artifact_checksum = durable
            .artifact_checksum
            .expect("delivered fixture artifact checksum");
        let outbox_checksum =
            crate::native_validation_artifact::durable_invalid_callback_outbox_checksum_v0(
                identity,
                artifact_checksum,
                &payload_codec,
                payload_checksum,
                idempotency_key,
                delivery_attempt,
            );
        let row_checksum = super::native_validation_job_delivery_row_checksum_v0(
            &durable.immutable_checksum,
            super::NativeValidationJobStateV0::Delivered,
            durable.result_kind,
            durable.invalid_reason_code_be.as_deref(),
            durable.artifact_codec.as_deref(),
            durable.artifact_checksum.as_ref(),
            None,
            None,
            Some(&outbox_checksum),
        );
        assert_eq!(
            transaction
                .execute(
                    "UPDATE validation_callback_outbox_v0
                     SET delivery_attempt_be=?1, outbox_checksum=?2
                     WHERE route=?3 AND block_id=?4 AND view_be=?5 AND generation_be=?6
                       AND outbox_checksum=?7",
                    rusqlite::params![
                        delivery_attempt.to_be_bytes().as_slice(),
                        outbox_checksum.as_slice(),
                        super::native_validation_route_code_v0(durable.route()),
                        validation_id.block_id().as_bytes().as_slice(),
                        validation_id.view().get().to_be_bytes().as_slice(),
                        validation_id.generation().to_be_bytes().as_slice(),
                        old_outbox_checksum.as_slice(),
                    ],
                )
                .expect("update delivered fixture outbox"),
            1
        );
        assert_eq!(
            transaction
                .execute(
                    "UPDATE validation_jobs_v0 SET state=3, row_checksum=?1
                     WHERE route=?2 AND block_id=?3 AND view_be=?4 AND generation_be=?5
                       AND state=2 AND row_checksum=?6",
                    rusqlite::params![
                        row_checksum.as_slice(),
                        super::native_validation_route_code_v0(durable.route()),
                        validation_id.block_id().as_bytes().as_slice(),
                        validation_id.view().get().to_be_bytes().as_slice(),
                        validation_id.generation().to_be_bytes().as_slice(),
                        durable.row_checksum.as_slice(),
                    ],
                )
                .expect("update delivered fixture job"),
            1
        );
        transaction.commit().expect("commit delivered fixture");
    }

    fn promote_invalid_fixture_to_acked_v0(store: &ApplicationStore, validation_id: ValidationId) {
        let mut connection = store.connect().expect("open acked fixture");
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("begin acked fixture transaction");
        let existing = super::load_native_validation_job_v0(&transaction, validation_id)
            .expect("load acked fixture job")
            .expect("acked fixture job exists");
        let durable = super::durable_native_validation_job_from_existing_v0(existing, store)
            .expect("decode delivered fixture job");
        super::verify_native_validation_job_outbox_v0(
            &transaction,
            &durable,
            NativeValidationReservationStageV0::ReadExisting,
        )
        .expect("verify delivered fixture before acknowledgement");
        let (payload_checksum, outbox_checksum) = transaction
            .query_row(
                "SELECT payload_checksum, outbox_checksum
                 FROM validation_callback_outbox_v0
                 WHERE route=?1 AND block_id=?2 AND view_be=?3 AND generation_be=?4",
                rusqlite::params![
                    super::native_validation_route_code_v0(durable.route()),
                    validation_id.block_id().as_bytes().as_slice(),
                    validation_id.view().get().to_be_bytes().as_slice(),
                    validation_id.generation().to_be_bytes().as_slice(),
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .expect("read acked fixture outbox");
        let payload_checksum: [u8; 32] = payload_checksum
            .try_into()
            .expect("acked fixture payload checksum length");
        let accepted_revision = validation_id
            .generation()
            .checked_add(1)
            .expect("advance acked fixture Core revision");
        let accepted_revision_be = accepted_revision.to_be_bytes();
        let row_checksum = super::native_validation_job_delivery_row_checksum_v0(
            &durable.immutable_checksum,
            super::NativeValidationJobStateV0::Acked,
            durable.result_kind,
            durable.invalid_reason_code_be.as_deref(),
            durable.artifact_codec.as_deref(),
            durable.artifact_checksum.as_ref(),
            Some(&accepted_revision_be),
            Some(&payload_checksum),
            None,
        );
        assert_eq!(
            transaction
                .execute(
                    "DELETE FROM validation_callback_outbox_v0
                     WHERE route=?1 AND block_id=?2 AND view_be=?3 AND generation_be=?4
                       AND outbox_checksum=?5",
                    rusqlite::params![
                        super::native_validation_route_code_v0(durable.route()),
                        validation_id.block_id().as_bytes().as_slice(),
                        validation_id.view().get().to_be_bytes().as_slice(),
                        validation_id.generation().to_be_bytes().as_slice(),
                        outbox_checksum,
                    ],
                )
                .expect("retire acked fixture outbox"),
            1
        );
        assert_eq!(
            transaction
                .execute(
                    "UPDATE validation_jobs_v0
                     SET state=4, accepted_core_revision_be=?1,
                         accepted_core_payload_checksum=?2, row_checksum=?3
                     WHERE route=?4 AND block_id=?5 AND view_be=?6 AND generation_be=?7
                       AND state=3 AND row_checksum=?8",
                    rusqlite::params![
                        accepted_revision_be.as_slice(),
                        payload_checksum.as_slice(),
                        row_checksum.as_slice(),
                        super::native_validation_route_code_v0(durable.route()),
                        validation_id.block_id().as_bytes().as_slice(),
                        validation_id.view().get().to_be_bytes().as_slice(),
                        validation_id.generation().to_be_bytes().as_slice(),
                        durable.row_checksum.as_slice(),
                    ],
                )
                .expect("update acked fixture job"),
            1
        );
        let accounting = super::read_bounded_native_validation_journal_accounting_v0(
            &transaction,
            NativeValidationReservationStageV0::ReadCapacity,
        )
        .expect("read acked fixture accounting");
        transaction
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET outbox_count_be=?1, outbox_bytes_be=?2 WHERE singleton=1",
                rusqlite::params![
                    accounting
                        .outbox_count
                        .checked_sub(1)
                        .expect("retire fixture outbox count")
                        .to_be_bytes()
                        .as_slice(),
                    accounting
                        .outbox_bytes
                        .checked_sub(super::DURABLE_INVALID_CALLBACK_BYTES_V0 as u64)
                        .expect("retire fixture outbox bytes")
                        .to_be_bytes()
                        .as_slice(),
                ],
            )
            .expect("update acked fixture accounting");
        transaction.commit().expect("commit acked fixture");
    }

    #[test]
    fn native_validation_body_record_codec_is_stable_bounded_and_strict_eof() {
        let facts = facts(PayloadValidationRouteV0::Proposal, 1, 8, 9);
        assert_eq!(facts.body_record, vec![0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0]);
        assert!(super::validate_native_validation_body_record_v0(
            &facts.body_record
        ));

        let mut unknown_version = facts.body_record.clone();
        unknown_version[1] = 1;
        assert!(!super::validate_native_validation_body_record_v0(
            &unknown_version
        ));
        let mut truncated = facts.body_record.clone();
        truncated.pop();
        assert!(!super::validate_native_validation_body_record_v0(
            &truncated
        ));
        let mut trailing = facts.body_record.clone();
        trailing.push(0);
        assert!(!super::validate_native_validation_body_record_v0(&trailing));
        let mut zero_payload = facts.body_record.clone();
        zero_payload[2..6].copy_from_slice(&0_u32.to_be_bytes());
        assert!(!super::validate_native_validation_body_record_v0(
            &zero_payload
        ));
        assert!(!super::validate_native_validation_body_record_v0(
            &vec![0; super::MAX_NATIVE_VALIDATION_BODY_RECORD_BYTES + 1]
        ));
    }

    #[test]
    fn validation_job_immutable_and_row_checksums_have_frozen_vectors() {
        let (root, store) = test_store("checksum-vectors");
        let mut facts = facts(PayloadValidationRouteV0::Proposal, 1, 8, 9);
        let runtime = super::native_validation_runtime_profile_ref_v0(facts.protocol_version);
        let host = super::native_validation_host_config_ref_v0(&store);
        let immutable = super::native_validation_job_immutable_checksum_v0(&facts, &runtime, &host);
        let row = super::native_validation_job_row_checksum_v0(
            &immutable,
            super::NativeValidationJobStateV0::Reserved,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            hex::encode(immutable),
            "df663ad6b773454c5c2c3043a4429865a9f23f4aa96c5e255d5533a48c666c41"
        );
        assert_eq!(
            hex::encode(row),
            "fd9dc8caa07ce08fec93a624b8afbea08759a8d51ab914bbc91f5656cf911a75"
        );

        let reason = 1_u32.to_be_bytes();
        let artifact_checksum = [0x44; 32];
        let outbox_checksum = [0x55; 32];
        let delivered = super::native_validation_job_delivery_row_checksum_v0(
            &immutable,
            super::NativeValidationJobStateV0::Delivered,
            Some(i64::from(
                super::durable_deterministic_invalid_result_kind_v0(),
            )),
            Some(&reason),
            Some(super::DURABLE_INVALID_ARTIFACT_CODEC_V0),
            Some(&artifact_checksum),
            None,
            None,
            Some(&outbox_checksum),
        );
        assert_eq!(
            hex::encode(delivered),
            "350fd1c3e134da9b1506e41c1938d67dd2c56837dc5b2a22ac098e6d7936b7fe"
        );
        let accepted_revision = 2_u64.to_be_bytes();
        let accepted_payload_checksum = [0x66; 32];
        let acked = super::native_validation_job_delivery_row_checksum_v0(
            &immutable,
            super::NativeValidationJobStateV0::Acked,
            Some(i64::from(
                super::durable_deterministic_invalid_result_kind_v0(),
            )),
            Some(&reason),
            Some(super::DURABLE_INVALID_ARTIFACT_CODEC_V0),
            Some(&artifact_checksum),
            Some(&accepted_revision),
            Some(&accepted_payload_checksum),
            None,
        );
        assert_eq!(
            hex::encode(acked),
            "7027088ece1a60a9798f7fd0d0aff18ac56abf9710b3f18c6d9f9e65438709e6"
        );
        assert_ne!(
            delivered,
            super::native_validation_job_delivery_row_checksum_v0(
                &immutable,
                super::NativeValidationJobStateV0::Delivered,
                Some(i64::from(
                    super::durable_deterministic_invalid_result_kind_v0(),
                )),
                Some(&reason),
                Some(super::DURABLE_INVALID_ARTIFACT_CODEC_V0),
                Some(&artifact_checksum),
                None,
                None,
                Some(&[0x56; 32]),
            )
        );

        facts.parent_timestamp_ms += 1;
        assert_ne!(
            super::native_validation_job_immutable_checksum_v0(&facts, &runtime, &host),
            immutable
        );
        drop(store);
        fs::remove_dir_all(root).expect("remove checksum-vector test directory");
    }

    #[test]
    fn durable_job_is_unique_and_exact_reopen_returns_existing_state() {
        let (root, store) = test_store("coalesce");
        let expected_facts = facts(PayloadValidationRouteV0::Proposal, 3, 8, 9);
        let expected_id = expected_facts.validation_id;
        let expected_parent = expected_facts.parent_block_id;
        let expected_fingerprint = expected_facts.request_fingerprint;
        let first = match store.reserve_or_reopen_native_validation_job_v0(expected_facts) {
            Ok(decision) => decision,
            Err(_) => panic!("reserve exact validation identity"),
        };
        let NativeValidationReservationDecisionV0::Reserved(token) = first else {
            panic!("first reservation must own evaluation admission");
        };
        assert_eq!(token.route(), PayloadValidationRouteV0::Proposal);
        assert_eq!(token.validation_id(), expected_id);

        let duplicate = match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            3,
            8,
            9,
        )) {
            Ok(decision) => decision,
            Err(_) => panic!("coalesce exact duplicate"),
        };
        let NativeValidationReservationDecisionV0::Existing(existing) = duplicate else {
            panic!("exact duplicate must return its durable state");
        };
        assert_eq!(existing.route(), PayloadValidationRouteV0::Proposal);
        assert_eq!(existing.validation_id(), expected_id);
        assert_eq!(existing.target_height(), 12);
        assert_eq!(existing.parent_block_id(), expected_parent);
        assert_eq!(existing.request_fingerprint(), expected_fingerprint);
        assert_eq!(existing.creation_revision(), 3);
        assert_eq!(
            existing.state(),
            super::NativeValidationJobStateV0::Reserved
        );

        let connection = store.connect().expect("open reservation test database");
        let count = connection
            .query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("count durable reservations");
        assert_eq!(count, 1);
        drop(connection);
        fs::remove_dir_all(root).expect("remove reservation test directory");
    }

    #[test]
    fn durable_reservation_is_unique_across_independent_stores_and_reopen() {
        const WORKER_COUNT: usize = 8;

        let (root, initialized_store) = test_store("independent-stores");
        let status_path = root.join("app.status");
        drop(initialized_store);

        let stores = (0..WORKER_COUNT)
            .map(|_| {
                let store = ApplicationStore::open(
                    &status_path,
                    "reservation-test-chain",
                    &"11".repeat(32),
                )
                .expect("open independent reservation test store");
                store
                    .load_or_migrate()
                    .expect("load independent reservation test store");
                store
            })
            .collect::<Vec<_>>();
        let barrier = Arc::new(Barrier::new(WORKER_COUNT));
        let workers =
            stores
                .into_iter()
                .map(|store| {
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        let reserved = match store.reserve_or_reopen_native_validation_job_v0(
                            facts(PayloadValidationRouteV0::Proposal, 5, 8, 9),
                        ) {
                            Ok(NativeValidationReservationDecisionV0::Reserved(_)) => true,
                            Ok(NativeValidationReservationDecisionV0::Existing(_)) => false,
                            Err(_) => panic!("reserve from independent application store"),
                        };
                        drop(store);
                        reserved
                    })
                })
                .collect::<Vec<_>>();

        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().expect("join reservation worker"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes.iter().filter(|reserved| **reserved).count(),
            1,
            "exactly one independent ApplicationStore must own evaluation admission"
        );
        assert_eq!(
            outcomes.iter().filter(|reserved| !**reserved).count(),
            WORKER_COUNT - 1,
            "all other independent ApplicationStore instances must coalesce"
        );

        let reopened =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen reservation test store");
        reopened
            .load_or_migrate()
            .expect("load reopened reservation test store");
        let repeated = match reopened.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            5,
            8,
            9,
        )) {
            Ok(decision) => decision,
            Err(_) => panic!("coalesce reservation after store reopen"),
        };
        let NativeValidationReservationDecisionV0::Existing(existing) = repeated else {
            panic!("reopening the store must return durable state without fresh admission");
        };
        assert_eq!(existing.route(), PayloadValidationRouteV0::Proposal);
        assert_eq!(
            existing.validation_id(),
            facts(PayloadValidationRouteV0::Proposal, 5, 8, 9).validation_id
        );
        assert_eq!(
            existing.state(),
            super::NativeValidationJobStateV0::Reserved
        );

        let connection = reopened
            .connect()
            .expect("open reopened reservation test database");
        let count = connection
            .query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("count durable reservations after reopen");
        assert_eq!(count, 1);
        drop(connection);
        drop(reopened);
        fs::remove_dir_all(root).expect("remove independent reservation test directory");
    }

    #[test]
    fn durable_job_exact_reopen_precedes_row_capacity() {
        let (root, store) = test_store("capacity-coalesce");
        match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            3,
            8,
            9,
        )) {
            Ok(NativeValidationReservationDecisionV0::Reserved(_)) => {}
            _ => panic!("reserve baseline capacity job"),
        }
        let mut connection = store.connect().expect("open capacity test database");
        let transaction = connection.transaction().expect("begin capacity fixture");
        {
            let mut insert = transaction
                .prepare(
                    "INSERT INTO validation_jobs_v0(
                         route, block_id, view_be, generation_be, target_height_be,
                         target_header_cev0, body_record_codec, body_record, body_checksum,
                         parent_height_be, parent_view_be, parent_block_id,
                         parent_timestamp_ms_be, parent_header_cev0,
                         parent_state_version_be, parent_state_root, validator_set_id,
                         parameters_hash, protocol_version_be, runtime_profile_ref,
                         host_config_ref, creation_revision_be, request_fingerprint,
                         immutable_checksum, state, result_kind, invalid_reason_code_be,
                         artifact_codec, artifact_bytes, artifact_checksum,
                         accepted_core_revision_be, accepted_core_payload_checksum,
                         row_codec, row_checksum
                     ) VALUES (
                         0, ?1, ?2, ?3, ?4, X'00', 0,
                         X'0000000000010100000000', zeroblob(32), ?5, ?6, ?7, ?8,
                         X'00', ?5, zeroblob(32), zeroblob(32), zeroblob(32), ?9,
                         zeroblob(32), zeroblob(32), ?3, zeroblob(32), zeroblob(32),
                         0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, zeroblob(32)
                     )",
                )
                .expect("prepare capacity fixture insert");
            for generation in 0..super::MAX_NATIVE_VALIDATION_RESERVATIONS {
                if generation == 3 {
                    continue;
                }
                insert
                    .execute(rusqlite::params![
                        [7_u8; 32].as_slice(),
                        9_u64.to_be_bytes().as_slice(),
                        generation.to_be_bytes().as_slice(),
                        12_u64.to_be_bytes().as_slice(),
                        11_u64.to_be_bytes().as_slice(),
                        8_u64.to_be_bytes().as_slice(),
                        [8_u8; 32].as_slice(),
                        1_u64.to_be_bytes().as_slice(),
                        1_u32.to_be_bytes().as_slice(),
                    ])
                    .expect("insert capacity fixture row");
            }
        }
        let fixture_count = transaction
            .query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("count capacity fixture jobs");
        let fixture_request_bytes = transaction
            .query_row(
                "SELECT COALESCE(SUM(
                     length(target_header_cev0) + length(body_record) +
                     COALESCE(length(parent_header_cev0), 0)
                 ), 0)
                 FROM validation_jobs_v0",
                [],
                |row| row.get::<_, u64>(0),
            )
            .expect("sum capacity fixture request bytes");
        transaction
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET job_count_be=?1, request_bytes_be=?2
                 WHERE singleton=1",
                rusqlite::params![
                    fixture_count.to_be_bytes().as_slice(),
                    fixture_request_bytes.to_be_bytes().as_slice(),
                ],
            )
            .expect("update capacity fixture accounting");
        transaction.commit().expect("commit capacity fixture");
        drop(connection);

        let duplicate = match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            3,
            8,
            9,
        )) {
            Ok(decision) => decision,
            Err(_) => panic!("exact duplicate at capacity must coalesce"),
        };
        assert!(matches!(
            duplicate,
            NativeValidationReservationDecisionV0::Existing(_)
        ));

        let failure = match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            super::MAX_NATIVE_VALIDATION_RESERVATIONS,
            8,
            9,
        )) {
            Ok(_) => panic!("new reservation above capacity unexpectedly succeeded"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.cause(),
            NativeValidationReservationFailureCauseV0::Capacity { maximum }
                if *maximum == super::MAX_NATIVE_VALIDATION_RESERVATIONS
        ));

        drop(store);
        fs::remove_dir_all(root).expect("remove capacity test directory");
    }

    #[test]
    fn durable_reservation_rejects_route_parent_and_fingerprint_splices() {
        let (root, store) = test_store("splices");
        match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            4,
            8,
            9,
        )) {
            Ok(NativeValidationReservationDecisionV0::Reserved(_)) => {}
            Ok(NativeValidationReservationDecisionV0::Existing(_)) | Err(_) => {
                panic!("reserve baseline validation identity")
            }
        }

        let mut target_header_splice = facts(PayloadValidationRouteV0::Proposal, 4, 8, 9);
        target_header_splice.target_header_cev0[0] ^= 1;
        let mut body_splice = facts(PayloadValidationRouteV0::Proposal, 4, 8, 9);
        body_splice.body_record[6] ^= 1;
        body_splice.body_checksum = super::hash_domain(
            super::NATIVE_VALIDATION_BODY_DOMAIN_V0,
            &[&body_splice.body_record],
        );
        let mut parent_context_splice = facts(PayloadValidationRouteV0::Proposal, 4, 8, 9);
        parent_context_splice.parent_timestamp_ms += 1;
        let mut configuration_splice = facts(PayloadValidationRouteV0::Proposal, 4, 8, 9);
        configuration_splice.protocol_version += 1;
        let mut creation_revision_splice = facts(PayloadValidationRouteV0::Proposal, 4, 8, 9);
        creation_revision_splice.creation_revision += 1;

        for (candidate, expected) in [
            (
                facts(PayloadValidationRouteV0::Synced, 4, 8, 9),
                NativeValidationReservationInvariantV0::RouteMismatch,
            ),
            (
                facts(PayloadValidationRouteV0::Proposal, 4, 10, 9),
                NativeValidationReservationInvariantV0::ParentBlockIdMismatch,
            ),
            (
                facts(PayloadValidationRouteV0::Proposal, 4, 8, 11),
                NativeValidationReservationInvariantV0::RequestFingerprintMismatch,
            ),
            (
                target_header_splice,
                NativeValidationReservationInvariantV0::TargetHeaderMismatch,
            ),
            (
                body_splice,
                NativeValidationReservationInvariantV0::BodyRecordMismatch,
            ),
            (
                parent_context_splice,
                NativeValidationReservationInvariantV0::ParentContextMismatch,
            ),
            (
                configuration_splice,
                NativeValidationReservationInvariantV0::ConfigurationReferenceMismatch,
            ),
            (
                creation_revision_splice,
                NativeValidationReservationInvariantV0::CreationRevisionMismatch,
            ),
        ] {
            let failure = match store.reserve_or_reopen_native_validation_job_v0(candidate) {
                Ok(_) => panic!("spliced reservation unexpectedly succeeded"),
                Err(failure) => failure,
            };
            assert!(matches!(
                failure.cause(),
                NativeValidationReservationFailureCauseV0::Invariant { kind, .. }
                    if *kind == expected
            ));
        }
        fs::remove_dir_all(root).expect("remove reservation splice test directory");
    }

    #[test]
    fn durable_reservation_binding_failure_is_zero_write() {
        let (root, store) = test_store("binding-zero-write");
        let connection = store.connect().expect("open binding test database");
        connection
            .execute(
                "UPDATE metadata SET value='foreign-chain' WHERE key='chain_id'",
                [],
            )
            .expect("corrupt reservation binding fixture");
        drop(connection);

        let failure = match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            6,
            8,
            9,
        )) {
            Ok(_) => panic!("binding-mismatched reservation unexpectedly succeeded"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.cause(),
            NativeValidationReservationFailureCauseV0::HostInvariant {
                stage: super::NativeValidationReservationStageV0::ValidateBindings,
                ..
            }
        ));
        let connection = rusqlite::Connection::open(&store.database_path)
            .expect("reopen binding test database without revalidating the corrupted fixture");
        let count = connection
            .query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("count reservations after binding failure");
        assert_eq!(count, 0);
        drop(connection);
        drop(store);
        fs::remove_dir_all(root).expect("remove binding test directory");
    }

    #[test]
    fn fresh_store_uses_schema_v8_and_empty_validation_journal() {
        let (root, store) = test_store("fresh-v8");
        let connection = store.connect().expect("open fresh schema v8 store");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read fresh schema version"),
            STORE_SCHEMA_VERSION
        );
        validate_snapshot_schema(&connection).expect("validate fresh schema v8");
        assert!(table_exists(&connection, "validation_jobs_v0"));
        assert!(table_exists(&connection, "validation_callback_outbox_v0"));
        assert!(!table_exists(&connection, "native_validation_reservations"));
        drop(connection);
        assert!(store
            .load_native_validation_recovery_work_v0()
            .expect("scan empty recovery journal")
            .is_empty());
        drop(store);
        fs::remove_dir_all(root).expect("remove fresh schema v8 test directory");
    }

    #[test]
    fn schema_v7_reserved_and_callback_pending_rows_migrate_byte_exactly_to_v8() {
        let (root, store) = test_store("migration-v7-active");
        let reserved_facts = facts(PayloadValidationRouteV0::Synced, 31, 8, 9);
        let reserved_id = reserved_facts.validation_id;
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(reserved_facts),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let callback_id = install_callback_pending_invalid_fixture_v0(
            &store,
            PayloadValidationRouteV0::Proposal,
            32,
        );
        let connection = store.connect().expect("open schema v7 active fixture");
        let row_checksums_before = {
            let mut statement = connection
                .prepare(
                    "SELECT row_checksum FROM validation_jobs_v0
                     ORDER BY state, route, block_id, view_be, generation_be",
                )
                .expect("prepare schema v7 row checksum query");
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .expect("query schema v7 row checksums")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect schema v7 row checksums")
        };
        let outbox_checksum_before = connection
            .query_row(
                "SELECT outbox_checksum FROM validation_callback_outbox_v0",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("read schema v7 outbox checksum");
        downgrade_fresh_store_to_schema_v7(&connection);
        validate_snapshot_schema(&connection).expect("validate schema v7 physical fixture");
        drop(connection);

        store
            .load_or_migrate()
            .expect("activate schema v8 over exact schema v7 rows");
        let connection = store.connect().expect("open migrated schema v8 store");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read schema v8 version"),
            STORE_SCHEMA_VERSION
        );
        let row_checksums_after = {
            let mut statement = connection
                .prepare(
                    "SELECT row_checksum FROM validation_jobs_v0
                     ORDER BY state, route, block_id, view_be, generation_be",
                )
                .expect("prepare migrated row checksum query");
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .expect("query migrated row checksums")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect migrated row checksums")
        };
        assert_eq!(row_checksums_after, row_checksums_before);
        assert_eq!(
            connection
                .query_row(
                    "SELECT outbox_checksum FROM validation_callback_outbox_v0",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .expect("read migrated outbox checksum"),
            outbox_checksum_before
        );
        drop(connection);
        let recovery = store
            .load_native_validation_recovery_work_v0()
            .expect("recover migrated schema v8 rows");
        assert_eq!(recovery.len(), 2);
        assert_eq!(recovery[0].validation_id(), reserved_id);
        assert_eq!(
            recovery[0].state(),
            super::NativeValidationJobStateV0::Reserved
        );
        assert_eq!(recovery[1].validation_id(), callback_id);
        assert_eq!(
            recovery[1].state(),
            super::NativeValidationJobStateV0::CallbackPending
        );
        drop(recovery);
        drop(store);
        fs::remove_dir_all(root).expect("remove schema v7 active migration directory");
    }

    #[test]
    fn schema_v7_delivery_state_activation_fails_closed_and_preserves_rows() {
        let (root, store) = test_store("migration-v7-delivered-reject");
        let validation_id = install_callback_pending_invalid_fixture_v0(
            &store,
            PayloadValidationRouteV0::Proposal,
            33,
        );
        promote_invalid_fixture_to_delivered_v0(&store, validation_id, 1);
        let mut connection = store.connect().expect("open pre-v8 delivered fixture");
        downgrade_fresh_store_to_schema_v7(&connection);
        let row_before = connection
            .query_row(
                "SELECT state, row_checksum FROM validation_jobs_v0",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .expect("read rejected schema v7 delivered row");
        let outbox_before = connection
            .query_row(
                "SELECT delivery_attempt_be, outbox_checksum
                 FROM validation_callback_outbox_v0",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .expect("read rejected schema v7 delivered outbox");
        migrate_store_schema_v7_to_v8(&mut connection, &store)
            .expect_err("schema v7 must reject delivered state before v8 activation");
        drop(connection);

        let connection = rusqlite::Connection::open(&store.database_path)
            .expect("reopen rejected schema v7 delivery fixture directly");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read preserved schema v7 version"),
            STORE_SCHEMA_VERSION_V7
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT state, row_checksum FROM validation_jobs_v0",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .expect("read preserved delivered row"),
            row_before
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT delivery_attempt_be, outbox_checksum
                     FROM validation_callback_outbox_v0",
                    [],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .expect("read preserved delivered outbox"),
            outbox_before
        );
        drop(connection);
        drop(store);
        fs::remove_dir_all(root).expect("remove rejected schema v7 delivery directory");
    }

    #[test]
    fn schema_v8_recovers_delivered_and_acked_with_retired_outbox_accounting() {
        let (root, store) = test_store("recovery-v8-delivered-acked");
        let delivered_id = install_callback_pending_invalid_fixture_v0(
            &store,
            PayloadValidationRouteV0::Proposal,
            34,
        );
        promote_invalid_fixture_to_delivered_v0(&store, delivered_id, 2);
        let acked_id = install_callback_pending_invalid_fixture_v0(
            &store,
            PayloadValidationRouteV0::Synced,
            35,
        );
        promote_invalid_fixture_to_delivered_v0(&store, acked_id, 1);
        promote_invalid_fixture_to_acked_v0(&store, acked_id);

        let connection = store
            .connect()
            .expect("open schema v8 delivery recovery fixture");
        let accounting = connection
            .query_row(
                "SELECT artifact_bytes_be, outbox_count_be, outbox_bytes_be
                 FROM validation_journal_accounting_v0 WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .expect("read schema v8 delivery accounting");
        assert_eq!(accounting.0, 240_u64.to_be_bytes());
        assert_eq!(accounting.1, 1_u64.to_be_bytes());
        assert_eq!(accounting.2, 84_u64.to_be_bytes());
        drop(connection);

        let status_path = root.join("app.status");
        drop(store);
        let reopened =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen schema v8 delivery fixture");
        reopened
            .load_or_migrate()
            .expect("restart authenticates delivered and acked rows");
        let recovery = reopened
            .load_native_validation_recovery_work_v0()
            .expect("enumerate schema v8 delivery recovery rows");
        assert_eq!(recovery.len(), 2);
        assert_eq!(recovery[0].validation_id(), delivered_id);
        assert_eq!(
            recovery[0].state(),
            super::NativeValidationJobStateV0::Delivered
        );
        assert_eq!(recovery[1].validation_id(), acked_id);
        assert_eq!(
            recovery[1].state(),
            super::NativeValidationJobStateV0::Acked
        );
        drop(recovery);
        drop(reopened);
        fs::remove_dir_all(root).expect("remove schema v8 delivery recovery directory");
    }

    #[test]
    fn schema_v8_restart_rejects_evaluated_applied_and_valid_rows() {
        for (case, generation) in [
            ("evaluated", 36_u64),
            ("applied", 37_u64),
            ("valid", 38_u64),
        ] {
            let (root, store) = test_store(&format!("v8-inactive-{case}"));
            let validation_id = install_callback_pending_invalid_fixture_v0(
                &store,
                PayloadValidationRouteV0::Proposal,
                generation,
            );
            if case == "applied" {
                promote_invalid_fixture_to_delivered_v0(&store, validation_id, 1);
                promote_invalid_fixture_to_acked_v0(&store, validation_id);
            }
            let connection = store.connect().expect("open inactive schema v8 fixture");
            let existing = super::load_native_validation_job_v0(&connection, validation_id)
                .expect("load inactive schema v8 row")
                .expect("inactive schema v8 row exists");
            let durable = super::durable_native_validation_job_from_existing_v0(existing, &store)
                .expect("decode inactive schema v8 baseline row");
            super::verify_native_validation_job_outbox_v0(
                &connection,
                &durable,
                NativeValidationReservationStageV0::ReadExisting,
            )
            .expect("verify inactive schema v8 baseline row");
            match case {
                "evaluated" => {
                    let row_checksum = super::native_validation_job_row_checksum_v0(
                        &durable.immutable_checksum,
                        super::NativeValidationJobStateV0::Evaluated,
                        durable.result_kind,
                        durable.invalid_reason_code_be.as_deref(),
                        durable.artifact_codec.as_deref(),
                        durable.artifact_checksum.as_ref(),
                        None,
                        None,
                    );
                    connection
                        .execute(
                            "UPDATE validation_jobs_v0 SET state=1, row_checksum=?1",
                            rusqlite::params![row_checksum.as_slice()],
                        )
                        .expect("write evaluated schema v8 row");
                }
                "applied" => {
                    let row_checksum = super::native_validation_job_delivery_row_checksum_v0(
                        &durable.immutable_checksum,
                        super::NativeValidationJobStateV0::Applied,
                        durable.result_kind,
                        durable.invalid_reason_code_be.as_deref(),
                        durable.artifact_codec.as_deref(),
                        durable.artifact_checksum.as_ref(),
                        durable.accepted_core_revision_be.as_deref(),
                        durable.accepted_core_payload_checksum.as_ref(),
                        None,
                    );
                    connection
                        .execute(
                            "UPDATE validation_jobs_v0 SET state=5, row_checksum=?1",
                            rusqlite::params![row_checksum.as_slice()],
                        )
                        .expect("write applied schema v8 row");
                }
                "valid" => {
                    let row_checksum = super::native_validation_job_row_checksum_v0(
                        &durable.immutable_checksum,
                        super::NativeValidationJobStateV0::CallbackPending,
                        Some(0),
                        None,
                        durable.artifact_codec.as_deref(),
                        durable.artifact_checksum.as_ref(),
                        None,
                        None,
                    );
                    connection
                        .execute(
                            "UPDATE validation_jobs_v0
                             SET result_kind=0, invalid_reason_code_be=NULL, row_checksum=?1",
                            rusqlite::params![row_checksum.as_slice()],
                        )
                        .expect("write valid schema v8 job row");
                    connection
                        .execute("UPDATE validation_callback_outbox_v0 SET result_kind=0", [])
                        .expect("write valid schema v8 outbox row");
                }
                _ => unreachable!("closed inactive schema v8 case"),
            }
            drop(connection);
            let status_path = root.join("app.status");
            drop(store);
            let reopened =
                ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                    .expect("reopen inactive schema v8 store");
            reopened
                .load_or_migrate()
                .expect_err("schema v8 accepted an inactive validation state/result");
            drop(reopened);
            fs::remove_dir_all(root).expect("remove inactive schema v8 directory");
        }
    }

    #[test]
    fn headerless_genesis_recovery_fact_is_structurally_revalidated() {
        let (root, store) = test_store("headerless-genesis");
        let facts = headerless_genesis_facts(PayloadValidationRouteV0::Proposal, 12);
        let validation_id = facts.validation_id;
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(facts),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let status_path = root.join("app.status");
        drop(store);

        let reopened =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen headerless-genesis store");
        reopened
            .load_or_migrate()
            .expect("revalidate structurally bound headerless-genesis fact");
        let work = reopened
            .load_native_validation_recovery_work_v0()
            .expect("load headerless-genesis recovery fact");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].validation_id(), validation_id);
        drop(work);
        drop(reopened);
        fs::remove_dir_all(root).expect("remove headerless-genesis test directory");
    }

    #[test]
    fn schema_v6_reserved_jobs_migrate_atomically_through_v7_to_v8() {
        let (root, store) = test_store("migration-v6-reserved");
        for (route, generation) in [
            (PayloadValidationRouteV0::Proposal, 21),
            (PayloadValidationRouteV0::Synced, 22),
        ] {
            assert!(matches!(
                store.reserve_or_reopen_native_validation_job_v0(facts(route, generation, 8, 9,)),
                Ok(NativeValidationReservationDecisionV0::Reserved(_))
            ));
        }
        let connection = store.connect().expect("open schema v6 migration fixture");
        let row_checksums_before = {
            let mut statement = connection
                .prepare(
                    "SELECT row_checksum FROM validation_jobs_v0
                     ORDER BY route, block_id, view_be, generation_be",
                )
                .expect("prepare schema v6 checksum query");
            let checksums = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .expect("query schema v6 row checksums")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect schema v6 row checksums");
            checksums
        };
        downgrade_fresh_store_to_schema_v6(&connection);
        validate_snapshot_schema(&connection).expect("validate canonical schema v6 fixture");
        drop(connection);

        store
            .load_or_migrate()
            .expect("migrate checksum-verified schema v6 jobs to v7");
        let connection = store.connect().expect("open migrated schema v7 store");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read migrated schema version"),
            STORE_SCHEMA_VERSION
        );
        let row_checksums_after = {
            let mut statement = connection
                .prepare(
                    "SELECT row_checksum FROM validation_jobs_v0
                     ORDER BY route, block_id, view_be, generation_be",
                )
                .expect("prepare migrated checksum query");
            let checksums = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .expect("query migrated row checksums")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect migrated row checksums");
            checksums
        };
        assert_eq!(row_checksums_after, row_checksums_before);
        drop(connection);
        assert_eq!(
            store
                .load_native_validation_recovery_work_v0()
                .expect("scan migrated schema v7 jobs")
                .len(),
            2
        );
        drop(store);
        fs::remove_dir_all(root).expect("remove schema v6 migration directory");
    }

    #[test]
    fn schema_v6_checksum_drift_migration_fails_closed_and_preserves_version() {
        let (root, store) = test_store("migration-v6-checksum-drift");
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(facts(
                PayloadValidationRouteV0::Proposal,
                23,
                8,
                9,
            )),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let connection = store.connect().expect("open corrupt schema v6 fixture");
        downgrade_fresh_store_to_schema_v6(&connection);
        connection
            .execute(
                "UPDATE validation_jobs_v0 SET immutable_checksum=zeroblob(32)",
                [],
            )
            .expect("corrupt schema v6 immutable checksum");
        let schema_before = schema_objects(&connection).expect("capture schema v6 objects");
        drop(connection);

        let error = store
            .load_or_migrate()
            .expect_err("checksum-drifted schema v6 migration must fail closed");
        assert!(error
            .to_string()
            .contains("validate schema-v6 reserved-only native validation journal"));
        let connection = rusqlite::Connection::open(&store.database_path)
            .expect("reopen rejected schema v6 database directly");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read preserved schema v6 version"),
            STORE_SCHEMA_VERSION_V6
        );
        assert_eq!(
            schema_objects(&connection).expect("read preserved schema v6 objects"),
            schema_before
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT immutable_checksum FROM validation_jobs_v0",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .expect("read preserved corrupt immutable checksum"),
            vec![0; 32]
        );
        assert_eq!(
            connection
                .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                .expect("quick-check rejected schema v6 database"),
            "ok"
        );
        drop(connection);
        drop(store);
        fs::remove_dir_all(root).expect("remove rejected schema v6 migration directory");
    }

    #[test]
    fn schema_v6_active_state_outbox_and_accounting_drift_migrations_roll_back() {
        for (case, generation) in [
            ("active-state", 24_u64),
            ("outbox", 25_u64),
            ("accounting", 26_u64),
        ] {
            let (root, store) = test_store(&format!("migration-v6-{case}"));
            let reserved_facts = facts(PayloadValidationRouteV0::Proposal, generation, 8, 9);
            let validation_id = reserved_facts.validation_id;
            assert!(matches!(
                store.reserve_or_reopen_native_validation_job_v0(reserved_facts),
                Ok(NativeValidationReservationDecisionV0::Reserved(_))
            ));
            let connection = store.connect().expect("open schema v6 rejection fixture");
            let existing = super::load_native_validation_job_v0(&connection, validation_id)
                .expect("load schema v6 rejection row")
                .expect("schema v6 rejection row exists");
            let durable = super::durable_native_validation_job_from_existing_v0(existing, &store)
                .expect("baseline schema v6 reserved row validates");
            downgrade_fresh_store_to_schema_v6(&connection);
            match case {
                "active-state" => {
                    let artifact_codec = "inactive-v6-artifact-v0";
                    let artifact_checksum = [0x91_u8; 32];
                    let row_checksum = super::native_validation_job_row_checksum_v0(
                        &durable.immutable_checksum,
                        super::NativeValidationJobStateV0::Evaluated,
                        Some(0),
                        None,
                        Some(artifact_codec),
                        Some(&artifact_checksum),
                        None,
                        None,
                    );
                    connection
                        .execute(
                            "UPDATE validation_jobs_v0
                             SET state=1, result_kind=0, artifact_codec=?1,
                                 artifact_bytes=X'', artifact_checksum=?2,
                                 row_checksum=?3",
                            rusqlite::params![
                                artifact_codec,
                                artifact_checksum.as_slice(),
                                row_checksum.as_slice(),
                            ],
                        )
                        .expect("write inactive schema v6 job state");
                }
                "outbox" => {
                    connection
                        .execute(
                            "INSERT INTO validation_callback_outbox_v0(
                                 route, block_id, view_be, generation_be, result_kind,
                                 artifact_checksum, payload_codec, payload_bytes,
                                 payload_checksum, idempotency_key, delivery_attempt_be,
                                 outbox_checksum
                             ) VALUES (?1,?2,?3,?4,1,?5,'inactive-v6-callback-v0',X'',?6,?7,zeroblob(8),?8)",
                            rusqlite::params![
                                super::native_validation_route_code_v0(
                                    PayloadValidationRouteV0::Proposal
                                ),
                                validation_id.block_id().as_bytes().as_slice(),
                                validation_id.view().get().to_be_bytes().as_slice(),
                                validation_id.generation().to_be_bytes().as_slice(),
                                [0x92_u8; 32].as_slice(),
                                [0x93_u8; 32].as_slice(),
                                [0x94_u8; 32].as_slice(),
                                [0x95_u8; 32].as_slice(),
                            ],
                        )
                        .expect("write inactive schema v6 outbox row");
                }
                "accounting" => {
                    connection
                        .execute(
                            "UPDATE validation_journal_accounting_v0
                             SET artifact_bytes_be=?1 WHERE singleton=1",
                            rusqlite::params![120_u64.to_be_bytes().as_slice()],
                        )
                        .expect("drift schema v6 journal accounting");
                }
                _ => unreachable!("closed schema v6 rejection case"),
            }
            let before_state = connection
                .query_row("SELECT state FROM validation_jobs_v0", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("read pre-migration schema v6 state");
            let before_outbox = connection
                .query_row(
                    "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .expect("read pre-migration schema v6 outbox count");
            let before_accounting = connection
                .query_row(
                    "SELECT artifact_bytes_be, outbox_count_be, outbox_bytes_be
                     FROM validation_journal_accounting_v0 WHERE singleton=1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .expect("read pre-migration schema v6 accounting");
            drop(connection);

            assert!(
                store.connect().is_err(),
                "schema v6 {case} migration unexpectedly succeeded"
            );
            let connection = rusqlite::Connection::open(&store.database_path)
                .expect("reopen rejected schema v6 migration directly");
            assert_eq!(
                metadata(&connection, "schema_version")
                    .expect("read rolled-back schema v6 version"),
                STORE_SCHEMA_VERSION_V6
            );
            assert_eq!(
                connection
                    .query_row("SELECT state FROM validation_jobs_v0", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("read rolled-back schema v6 state"),
                before_state
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                        [],
                        |row| row.get::<_, u64>(0),
                    )
                    .expect("read rolled-back schema v6 outbox count"),
                before_outbox
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT artifact_bytes_be, outbox_count_be, outbox_bytes_be
                         FROM validation_journal_accounting_v0 WHERE singleton=1",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, Vec<u8>>(0)?,
                                row.get::<_, Vec<u8>>(1)?,
                                row.get::<_, Vec<u8>>(2)?,
                            ))
                        },
                    )
                    .expect("read rolled-back schema v6 accounting"),
                before_accounting
            );
            assert_eq!(
                connection
                    .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                    .expect("quick-check rejected schema v6 migration"),
                "ok"
            );
            drop(connection);
            drop(store);
            fs::remove_dir_all(root).expect("remove rejected schema v6 migration case");
        }
    }

    #[test]
    fn schema_v5_empty_migrates_atomically_through_v6_v7_to_v8() {
        let (root, store) = test_store("migration-v5-empty");
        let connection = store.connect().expect("open schema v5 migration fixture");
        downgrade_fresh_store_to_schema_v5(&connection);
        validate_snapshot_schema(&connection).expect("validate canonical schema v5 fixture");
        drop(connection);

        store
            .load_or_migrate()
            .expect("migrate empty schema v5 store through v6 to v7");
        let connection = store.connect().expect("open migrated schema v7 store");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read migrated schema version"),
            STORE_SCHEMA_VERSION
        );
        assert!(!table_exists(&connection, "native_validation_reservations"));
        assert!(table_exists(&connection, "validation_jobs_v0"));
        assert!(table_exists(&connection, "validation_callback_outbox_v0"));
        validate_snapshot_schema(&connection).expect("validate migrated schema v7");
        drop(connection);
        drop(store);
        fs::remove_dir_all(root).expect("remove empty schema v5 migration directory");
    }

    #[test]
    fn schema_v5_nonempty_migration_fails_closed_and_preserves_rows() {
        let (root, store) = test_store("migration-v5-nonempty");
        let connection = store
            .connect()
            .expect("open nonempty schema v5 migration fixture");
        downgrade_fresh_store_to_schema_v5(&connection);
        connection
            .execute(
                "INSERT INTO native_validation_reservations(
                     route, block_id, view_be, generation_be, target_height_be,
                     parent_block_id, request_fingerprint
                 ) VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    [7_u8; 32].as_slice(),
                    9_u64.to_be_bytes().as_slice(),
                    3_u64.to_be_bytes().as_slice(),
                    12_u64.to_be_bytes().as_slice(),
                    [8_u8; 32].as_slice(),
                    [9_u8; 32].as_slice(),
                ],
            )
            .expect("insert unreplayable schema v5 reservation");
        let schema_before = schema_objects(&connection).expect("capture schema v5 objects");
        let row_before = connection
            .query_row(
                "SELECT route, block_id, view_be, generation_be, target_height_be,
                        parent_block_id, request_fingerprint
                 FROM native_validation_reservations",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .expect("capture schema v5 reservation row");
        drop(connection);

        let error = store
            .load_or_migrate()
            .expect_err("nonempty schema v5 migration must fail closed");
        assert!(error
            .to_string()
            .contains("unreplayable native validation reservations"));
        let connection = rusqlite::Connection::open(&store.database_path)
            .expect("reopen rejected schema v5 database directly");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read preserved schema version"),
            STORE_SCHEMA_VERSION_V5
        );
        assert_eq!(
            schema_objects(&connection).expect("read preserved schema objects"),
            schema_before
        );
        let row_after = connection
            .query_row(
                "SELECT route, block_id, view_be, generation_be, target_height_be,
                        parent_block_id, request_fingerprint
                 FROM native_validation_reservations",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .expect("read preserved schema v5 reservation row");
        assert_eq!(row_after, row_before);
        assert!(!table_exists(&connection, "validation_jobs_v0"));
        assert!(!table_exists(&connection, "validation_callback_outbox_v0"));
        let integrity = connection
            .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .expect("quick-check rejected schema v5 database");
        assert_eq!(integrity, "ok");
        drop(connection);
        drop(store);
        fs::remove_dir_all(root).expect("remove rejected schema v5 migration directory");
    }

    #[test]
    fn schema_v4_migrates_serially_through_v5_v6_and_v7_to_v8() {
        let (root, store) = test_store("migration-v4-v8");
        let mut connection = store.connect().expect("open schema v4 migration fixture");
        downgrade_fresh_store_to_schema_v5(&connection);
        connection
            .execute_batch("DROP TABLE native_validation_reservations;")
            .expect("remove schema v5 reservation table for v4 fixture");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='schema_version'",
                rusqlite::params![STORE_SCHEMA_VERSION_V4],
            )
            .expect("set schema v4 fixture version");
        validate_snapshot_schema(&connection).expect("validate canonical schema v4 fixture");

        migrate_store_schema_v4_to_v5(&mut connection).expect("migrate schema v4 to v5");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read intermediate schema version"),
            STORE_SCHEMA_VERSION_V5
        );
        assert!(table_exists(&connection, "native_validation_reservations"));
        validate_snapshot_schema(&connection).expect("validate intermediate schema v5");

        migrate_store_schema_v5_to_v6(&mut connection).expect("migrate schema v5 to v6");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read schema v6 version"),
            STORE_SCHEMA_VERSION_V6
        );
        assert!(!table_exists(&connection, "native_validation_reservations"));
        assert!(table_exists(&connection, "validation_jobs_v0"));
        assert!(table_exists(&connection, "validation_callback_outbox_v0"));
        validate_snapshot_schema(&connection).expect("validate intermediate schema v6");

        migrate_store_schema_v6_to_v7(&mut connection, &store).expect("migrate schema v6 to v7");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read schema v7 version"),
            STORE_SCHEMA_VERSION_V7
        );
        validate_snapshot_schema(&connection).expect("validate intermediate schema v7");

        migrate_store_schema_v7_to_v8(&mut connection, &store).expect("migrate schema v7 to v8");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read final schema version"),
            STORE_SCHEMA_VERSION
        );
        validate_snapshot_schema(&connection).expect("validate final schema v8");
        drop(connection);
        drop(store);
        fs::remove_dir_all(root).expect("remove serial schema migration directory");
    }

    #[test]
    fn recovery_scanner_orders_reserved_jobs_and_fails_closed_on_checksum_drift() {
        let (root, store) = test_store("recovery-scan");
        for (route, generation) in [
            (PayloadValidationRouteV0::Synced, 3),
            (PayloadValidationRouteV0::Proposal, 5),
            (PayloadValidationRouteV0::Proposal, 2),
        ] {
            assert!(matches!(
                store.reserve_or_reopen_native_validation_job_v0(facts(route, generation, 8, 9,)),
                Ok(NativeValidationReservationDecisionV0::Reserved(_))
            ));
        }
        let status_path = root.join("app.status");
        drop(store);
        let reopened =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen recovery scan store");
        reopened
            .load_or_migrate()
            .expect("load recovery scan store");
        let work = reopened
            .load_native_validation_recovery_work_v0()
            .expect("scan checksum-verified recovery work");
        assert_eq!(work.len(), 3);
        assert_eq!(
            work.iter()
                .map(|job| (job.route(), job.validation_id().generation(), job.state()))
                .collect::<Vec<_>>(),
            vec![
                (
                    PayloadValidationRouteV0::Proposal,
                    2,
                    super::NativeValidationJobStateV0::Reserved,
                ),
                (
                    PayloadValidationRouteV0::Proposal,
                    5,
                    super::NativeValidationJobStateV0::Reserved,
                ),
                (
                    PayloadValidationRouteV0::Synced,
                    3,
                    super::NativeValidationJobStateV0::Reserved,
                ),
            ]
        );
        drop(work);
        let connection = reopened
            .connect()
            .expect("open recovery corruption fixture");
        connection
            .execute(
                "UPDATE validation_jobs_v0
                 SET immutable_checksum=zeroblob(32)
                 WHERE generation_be=?1",
                rusqlite::params![2_u64.to_be_bytes().as_slice()],
            )
            .expect("tamper one recovery row checksum");
        drop(connection);
        drop(reopened);
        let corrupted =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen checksum-corrupted recovery store");
        assert!(corrupted.load_or_migrate().is_err());
        drop(corrupted);
        fs::remove_dir_all(root).expect("remove recovery scan test directory");
    }

    #[test]
    fn restart_rejects_checksum_consistent_canonical_header_splice() {
        let (root, store) = test_store("semantic-splice");
        let facts = facts(PayloadValidationRouteV0::Proposal, 7, 8, 9);
        let validation_id = facts.validation_id;
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(facts),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let connection = store.connect().expect("open semantic splice fixture");
        let encoded: Vec<u8> = connection
            .query_row(
                "SELECT target_header_cev0 FROM validation_jobs_v0
                 WHERE block_id=?1 AND view_be=?2 AND generation_be=?3",
                rusqlite::params![
                    validation_id.block_id().as_bytes().as_slice(),
                    validation_id.view().get().to_be_bytes().as_slice(),
                    validation_id.generation().to_be_bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .expect("load semantic splice target header");
        let header = decode_block_header_v0_exact(&encoded).expect("decode fixture target header");
        let spliced = BlockHeader::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.view(),
            header.height(),
            header.block_kind(),
            header.parent_id(),
            header.proposer_id(),
            header.validator_set_id(),
            header.consensus_parameters_hash(),
            header.payload_digest(),
            header.state_root(),
            header.receipts_root(),
            header.evidence_root(),
            header.timestamp_ms() + 1,
            header.next_epoch_commitment_hash(),
        )
        .expect("construct canonical spliced target header")
        .try_cev0_bytes()
        .expect("encode canonical spliced target header");
        let existing = super::load_native_validation_job_v0(&connection, validation_id)
            .expect("load semantic splice row")
            .expect("semantic splice row exists");
        let mut durable = super::durable_native_validation_job_from_existing_v0(existing, &store)
            .expect("baseline semantic row validates");
        durable.facts.target_header_cev0 = spliced.clone();
        let immutable = super::native_validation_job_immutable_checksum_v0(
            &durable.facts,
            &durable.runtime_profile_ref,
            &durable.host_config_ref,
        );
        let row = super::native_validation_job_row_checksum_v0(
            &immutable,
            super::NativeValidationJobStateV0::Reserved,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        connection
            .execute(
                "UPDATE validation_jobs_v0
                 SET target_header_cev0=?1, immutable_checksum=?2, row_checksum=?3
                 WHERE block_id=?4 AND view_be=?5 AND generation_be=?6",
                rusqlite::params![
                    spliced,
                    immutable.as_slice(),
                    row.as_slice(),
                    validation_id.block_id().as_bytes().as_slice(),
                    validation_id.view().get().to_be_bytes().as_slice(),
                    validation_id.generation().to_be_bytes().as_slice(),
                ],
            )
            .expect("write checksum-consistent semantic splice");
        drop(connection);
        drop(store);

        let status_path = root.join("app.status");
        let corrupted =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen semantic splice store");
        assert!(corrupted.load_or_migrate().is_err());
        drop(corrupted);
        fs::remove_dir_all(root).expect("remove semantic splice test directory");
    }

    #[test]
    fn restart_rejects_checksum_consistent_positive_parent_downgrade() {
        let (root, store) = test_store("parent-downgrade");
        let original = facts(PayloadValidationRouteV0::Proposal, 10, 8, 9);
        let validation_id = original.validation_id;
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(original),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let connection = store.connect().expect("open parent downgrade fixture");
        let existing = super::load_native_validation_job_v0(&connection, validation_id)
            .expect("load parent downgrade row")
            .expect("parent downgrade row exists");
        let mut durable = super::durable_native_validation_job_from_existing_v0(existing, &store)
            .expect("baseline parent row validates");
        durable.facts.parent_height = 0;
        durable.facts.parent_view = 0;
        durable.facts.parent_timestamp_ms = 0;
        durable.facts.parent_header_cev0 = None;
        durable.facts.parent_state_version = None;
        durable.facts.parent_state_root = None;
        durable.facts.request_fingerprint =
            super::native_validation_reservation_fingerprint_from_record_v0(&durable.facts)
                .expect("recompute checksum-consistent downgraded-parent fingerprint");
        let immutable = super::native_validation_job_immutable_checksum_v0(
            &durable.facts,
            &durable.runtime_profile_ref,
            &durable.host_config_ref,
        );
        let row = super::native_validation_job_row_checksum_v0(
            &immutable,
            super::NativeValidationJobStateV0::Reserved,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        connection
            .execute(
                "UPDATE validation_jobs_v0
                 SET parent_height_be=?1, parent_view_be=?1,
                     parent_timestamp_ms_be=?1, parent_header_cev0=NULL,
                     parent_state_version_be=NULL, parent_state_root=NULL,
                     request_fingerprint=?2, immutable_checksum=?3, row_checksum=?4
                 WHERE block_id=?5 AND view_be=?6 AND generation_be=?7",
                rusqlite::params![
                    0_u64.to_be_bytes().as_slice(),
                    durable.facts.request_fingerprint.as_slice(),
                    immutable.as_slice(),
                    row.as_slice(),
                    validation_id.block_id().as_bytes().as_slice(),
                    validation_id.view().get().to_be_bytes().as_slice(),
                    validation_id.generation().to_be_bytes().as_slice(),
                ],
            )
            .expect("write checksum-consistent positive-parent downgrade");
        drop(connection);
        drop(store);

        let status_path = root.join("app.status");
        let corrupted =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen parent downgrade store");
        assert!(corrupted.load_or_migrate().is_err());
        drop(corrupted);
        fs::remove_dir_all(root).expect("remove parent downgrade test directory");
    }

    #[test]
    fn exact_reopen_rejects_checksum_consistent_inactive_future_state() {
        let (root, store) = test_store("inactive-future-state");
        let original = facts(PayloadValidationRouteV0::Proposal, 8, 8, 9);
        let validation_id = original.validation_id;
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(original),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let connection = store.connect().expect("open inactive-state fixture");
        let existing = super::load_native_validation_job_v0(&connection, validation_id)
            .expect("load inactive-state row")
            .expect("inactive-state row exists");
        let durable = super::durable_native_validation_job_from_existing_v0(existing, &store)
            .expect("baseline reserved row validates");
        let artifact_codec = "future-fixture-v0";
        let artifact_bytes = [1_u8];
        let artifact_checksum = [0x88_u8; 32];
        let row_checksum = super::native_validation_job_row_checksum_v0(
            &durable.immutable_checksum,
            super::NativeValidationJobStateV0::Evaluated,
            Some(0),
            None,
            Some(artifact_codec),
            Some(&artifact_checksum),
            None,
            None,
        );
        connection
            .execute(
                "UPDATE validation_jobs_v0
                 SET state=1, result_kind=0, artifact_codec=?1,
                     artifact_bytes=?2, artifact_checksum=?3, row_checksum=?4
                 WHERE block_id=?5 AND view_be=?6 AND generation_be=?7",
                rusqlite::params![
                    artifact_codec,
                    artifact_bytes.as_slice(),
                    artifact_checksum.as_slice(),
                    row_checksum.as_slice(),
                    validation_id.block_id().as_bytes().as_slice(),
                    validation_id.view().get().to_be_bytes().as_slice(),
                    validation_id.generation().to_be_bytes().as_slice(),
                ],
            )
            .expect("write checksum-consistent inactive state");
        connection
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET artifact_bytes_be=?1 WHERE singleton=1",
                rusqlite::params![1_u64.to_be_bytes().as_slice()],
            )
            .expect("update inactive-state accounting");
        drop(connection);

        let failure = match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            8,
            8,
            9,
        )) {
            Ok(_) => panic!("inactive future state unexpectedly reopened"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.cause(),
            NativeValidationReservationFailureCauseV0::Invariant {
                kind: NativeValidationReservationInvariantV0::StateMismatch,
                ..
            }
        ));
        drop(store);
        let status_path = root.join("app.status");
        let corrupted =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen inactive-state store");
        assert!(corrupted.load_or_migrate().is_err());
        drop(corrupted);
        fs::remove_dir_all(root).expect("remove inactive-state test directory");
    }

    #[test]
    fn exact_reopen_stays_inert_but_restart_rejects_a_different_non_reserved_job() {
        let (root, store) = test_store("foreign-inactive-state");
        let first = facts(PayloadValidationRouteV0::Proposal, 13, 8, 9);
        let first_id = first.validation_id;
        let second = facts(PayloadValidationRouteV0::Proposal, 14, 8, 9);
        let second_id = second.validation_id;
        for candidate in [first, second] {
            assert!(matches!(
                store.reserve_or_reopen_native_validation_job_v0(candidate),
                Ok(NativeValidationReservationDecisionV0::Reserved(_))
            ));
        }
        let connection = store
            .connect()
            .expect("open foreign inactive-state fixture");
        let existing = super::load_native_validation_job_v0(&connection, second_id)
            .expect("load foreign inactive-state row")
            .expect("foreign inactive-state row exists");
        let durable = super::durable_native_validation_job_from_existing_v0(existing, &store)
            .expect("baseline foreign reserved row validates");
        let artifact_codec = "future-empty-fixture-v0";
        let artifact_checksum = [0x98_u8; 32];
        let row_checksum = super::native_validation_job_row_checksum_v0(
            &durable.immutable_checksum,
            super::NativeValidationJobStateV0::Evaluated,
            Some(0),
            None,
            Some(artifact_codec),
            Some(&artifact_checksum),
            None,
            None,
        );
        connection
            .execute(
                "UPDATE validation_jobs_v0
                 SET state=1, result_kind=0, artifact_codec=?1,
                     artifact_bytes=X'', artifact_checksum=?2, row_checksum=?3
                 WHERE block_id=?4 AND view_be=?5 AND generation_be=?6",
                rusqlite::params![
                    artifact_codec,
                    artifact_checksum.as_slice(),
                    row_checksum.as_slice(),
                    second_id.block_id().as_bytes().as_slice(),
                    second_id.view().get().to_be_bytes().as_slice(),
                    second_id.generation().to_be_bytes().as_slice(),
                ],
            )
            .expect("write checksum-consistent foreign inactive state");
        drop(connection);

        let reopened = match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            13,
            8,
            9,
        )) {
            Ok(NativeValidationReservationDecisionV0::Existing(existing)) => existing,
            Ok(NativeValidationReservationDecisionV0::Reserved(_)) => {
                panic!("exact reopen reminted first-evaluation authority")
            }
            Err(failure) => panic!("exact inert reopen failed: {:?}", failure.cause()),
        };
        assert_eq!(reopened.validation_id(), first_id);
        assert_eq!(
            reopened.state(),
            super::NativeValidationJobStateV0::Reserved
        );
        drop(store);
        let corrupted = ApplicationStore::open(
            &root.join("app.status"),
            "reservation-test-chain",
            &"11".repeat(32),
        )
        .expect("reopen foreign inactive-state store");
        assert!(corrupted.load_or_migrate().is_err());
        drop(corrupted);
        fs::remove_dir_all(root).expect("remove foreign inactive-state test directory");
    }

    #[test]
    fn exact_reopen_and_restart_reject_nonempty_inactive_outbox() {
        let (root, store) = test_store("inactive-outbox");
        let original = facts(PayloadValidationRouteV0::Proposal, 11, 8, 9);
        let validation_id = original.validation_id;
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(original),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let connection = store.connect().expect("open inactive-outbox fixture");
        connection
            .execute(
                "INSERT INTO validation_callback_outbox_v0(
                     route, block_id, view_be, generation_be, result_kind,
                     artifact_checksum, payload_codec, payload_bytes,
                     payload_checksum, idempotency_key, delivery_attempt_be,
                     outbox_checksum
                 ) VALUES (0, ?1, ?2, ?3, 0, ?4, 'future-fixture-v0', X'01',
                           ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    validation_id.block_id().as_bytes().as_slice(),
                    validation_id.view().get().to_be_bytes().as_slice(),
                    validation_id.generation().to_be_bytes().as_slice(),
                    [0x84_u8; 32].as_slice(),
                    [0x85_u8; 32].as_slice(),
                    [0x86_u8; 32].as_slice(),
                    0_u64.to_be_bytes().as_slice(),
                    [0x87_u8; 32].as_slice(),
                ],
            )
            .expect("insert inactive outbox child");
        connection
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET outbox_count_be=?1, outbox_bytes_be=?1 WHERE singleton=1",
                rusqlite::params![1_u64.to_be_bytes().as_slice()],
            )
            .expect("update inactive-outbox accounting");
        drop(connection);

        let failure = match store.reserve_or_reopen_native_validation_job_v0(facts(
            PayloadValidationRouteV0::Proposal,
            11,
            8,
            9,
        )) {
            Ok(_) => panic!("nonempty inactive outbox unexpectedly reopened"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.cause(),
            NativeValidationReservationFailureCauseV0::Invariant {
                stage: super::NativeValidationReservationStageV0::ReadExisting,
                kind: NativeValidationReservationInvariantV0::StateMismatch,
                ..
            }
        ));
        drop(store);

        let status_path = root.join("app.status");
        let corrupted =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen inactive-outbox store");
        assert!(corrupted.load_or_migrate().is_err());
        drop(corrupted);
        fs::remove_dir_all(root).expect("remove inactive-outbox test directory");
    }

    #[test]
    fn restart_rejects_validation_journal_accounting_drift() {
        let (root, store) = test_store("accounting-drift");
        assert!(matches!(
            store.reserve_or_reopen_native_validation_job_v0(facts(
                PayloadValidationRouteV0::Proposal,
                9,
                8,
                9,
            )),
            Ok(NativeValidationReservationDecisionV0::Reserved(_))
        ));
        let connection = store.connect().expect("open accounting drift fixture");
        connection
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET job_count_be=?1 WHERE singleton=1",
                rusqlite::params![2_u64.to_be_bytes().as_slice()],
            )
            .expect("tamper validation journal accounting");
        drop(connection);
        drop(store);

        let status_path = root.join("app.status");
        let corrupted =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen accounting-drift store");
        assert!(corrupted.load_or_migrate().is_err());
        drop(corrupted);
        fs::remove_dir_all(root).expect("remove accounting-drift test directory");
    }
}
