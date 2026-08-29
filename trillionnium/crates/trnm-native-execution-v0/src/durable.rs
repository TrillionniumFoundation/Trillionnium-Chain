//! Durable frozen-v0 application owner.
//!
//! The owner joins one exact pinned parent snapshot to deterministic complete
//! execution, persists canonical execution artifact P and the complete target
//! JMT snapshot in one SQLite transaction, and requires a fresh-connection
//! readback before returning `Valid`.  Commit is a second exact transition
//! from that P.  This module deliberately has no Core Valid permit, Safety
//! authority, signing key, network, or broadcast surface.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{ensure, Context};
use borsh::{BorshDeserialize, BorshSerialize};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    ApplicationPayloadV0, BlockHeader, ConsensusParametersV0, ExecutionEventAttributeV0,
    ExecutionEventV0, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, FinalityProofV0,
    GenesisHash, ValidatorId, ValidatorSet,
};
use trnm_finality_types::hash_domain;
use trnm_native_application::{
    decode_native_executed_block_artifact_v0, encode_native_executed_block_artifact_v0,
    ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, Hash32V0, HeightV0,
    NativeApplicationCommitRequestV0, NativeApplicationCommitResultV0,
    NativeApplicationGenesisRequestV0, NativeApplicationGenesisResultV0,
    NativeApplicationRecoveryRequestV0, NativeApplicationRecoveryResultV0, NativeApplicationV0,
    NativeBlockExecutionRequestV0, NativeBlockExecutionResultV0, NativeDeterministicInvalidV0,
    NativeExecutedBlockV0, NativeRecoveryDispositionV0, NativeRecoveryWatermarksV0,
    NativeSnapshotChunkV0, NativeSnapshotManifestV0, NativeSnapshotRequestV0,
    NativeStateProofRequestV0, NativeStateProofSchemeV0, NativeStateProofV0, NativeValidatorSetV0,
    NativeUnavailableReasonV0, NativeValidatorV0, StateRootV0, ValidatorSetIdV0,
};

use crate::{
    canonical_lab_bootstrap::{
        derive_canonical_lab_native_chain_genesis_material_v0,
        CanonicalLabNativeChainGenesisFactsV0, CanonicalLabNativeChainGenesisInputsV0,
    },
    complete::{
        execute_complete_native_block_v0, load_validator_lifecycle_from_live_v0,
        preview_complete_native_block_v0, validate_application_validator_projection_v0,
        validator_lifecycle_seed_write_v0, CompleteNativeExecutionFailureV0,
        NativeBlockPreviewRequestV0, NativeBlockPreviewV0,
    },
    store::{InMemoryNativeExecutionStoreV0, NativeExecutionStoreV0},
    AuthorizedSignerV0, NativeStateWriteV0,
};

const APPLICATION_SCHEMA_VERSION_V0: u64 = 3;
const P_STATUS_PREPARED: u64 = 1;
const P_STATUS_COMMITTED: u64 = 2;
const P_DIGEST_DOMAIN_V0: &str = "trnm.native-application.durable-p.v0";
const COMMIT_ID_DOMAIN_V0: &str = "trnm.native-application.commit-id.v0";
const H1_STATE_SYNC_IMPORT_DIGEST_DOMAIN_V0: &str =
    "trnm.native-application.h1-state-sync-import.v0";
const H1_STATE_SYNC_COMMIT_ID_DOMAIN_V0: &str =
    "trnm.native-application.h1-state-sync-commit-id.v0";
const SNAPSHOT_CHUNK_DOMAIN_V0: &str = "trnm.native-application.snapshot-chunk.v0";
const SNAPSHOT_MANIFEST_DOMAIN_V0: &str = "trnm.native-application.snapshot-manifest.v0";
const LAB_STORE_ID_DOMAIN_V0: &str = "trnm.native-application.canonical-lab-store-id.v0";
const NATIVE_RECEIPT_COMMITMENT_DOMAIN_V0: &str = "trnm.native-application.execution-receipt.v0";

const EXPECTED_SCHEMA_V0: &[(&str, &str)] = &[
    (
        "native_application_metadata_v0",
        "CREATE TABLE native_application_metadata_v0 (
           singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
           schema_version BLOB NOT NULL CHECK (length(schema_version) = 8),
           store_id BLOB NOT NULL CHECK (length(store_id) = 32),
           chain_id TEXT NOT NULL,
           genesis_hash BLOB NOT NULL CHECK (length(genesis_hash) = 32),
           chain_descriptor_hash BLOB NOT NULL CHECK (length(chain_descriptor_hash) = 32),
           signer_policy_commitment BLOB NOT NULL CHECK (length(signer_policy_commitment) = 32),
           validator_set_id BLOB NOT NULL CHECK (length(validator_set_id) = 32),
           parameters_hash BLOB NOT NULL CHECK (length(parameters_hash) = 32),
           durable_sequence BLOB NOT NULL CHECK (length(durable_sequence) = 8),
           head_height BLOB NOT NULL CHECK (length(head_height) = 8),
           head_block_id BLOB NOT NULL CHECK (length(head_block_id) = 32),
           head_state_root BLOB NOT NULL CHECK (length(head_state_root) = 32),
           head_commit_id BLOB NOT NULL CHECK (length(head_commit_id) = 32),
           authenticated_snapshot BLOB NOT NULL,
           authenticated_snapshot_digest BLOB NOT NULL CHECK (length(authenticated_snapshot_digest) = 32),
           replay_command_ids BLOB NOT NULL,
           replay_signer_nonces BLOB NOT NULL
         )",
    ),
    (
        "native_durable_execution_p_v0",
        "CREATE TABLE native_durable_execution_p_v0 (
           block_id BLOB PRIMARY KEY CHECK (length(block_id) = 32),
           target_height BLOB NOT NULL CHECK (length(target_height) = 8),
           store_id BLOB NOT NULL CHECK (length(store_id) = 32),
           p_sequence BLOB NOT NULL CHECK (length(p_sequence) = 8),
           status BLOB NOT NULL CHECK (length(status) = 8),
           parent_height BLOB NOT NULL CHECK (length(parent_height) = 8),
           parent_block_id BLOB NOT NULL CHECK (length(parent_block_id) = 32),
           parent_state_root BLOB NOT NULL CHECK (length(parent_state_root) = 32),
           parent_commit_id BLOB NOT NULL CHECK (length(parent_commit_id) = 32),
           artifact BLOB NOT NULL,
           artifact_digest BLOB NOT NULL CHECK (length(artifact_digest) = 32),
           target_snapshot BLOB NOT NULL,
           target_snapshot_digest BLOB NOT NULL CHECK (length(target_snapshot_digest) = 32),
           target_replay_command_ids BLOB NOT NULL,
           target_replay_signer_nonces BLOB NOT NULL,
           target_lifecycle_json BLOB NOT NULL,
           p_digest BLOB NOT NULL CHECK (length(p_digest) = 32),
           commit_sequence BLOB,
           commit_id BLOB,
           CHECK ((status = x'0000000000000001' AND commit_sequence IS NULL AND commit_id IS NULL)
             OR (status = x'0000000000000002' AND length(commit_sequence) = 8 AND length(commit_id) = 32))
         )",
    ),
    (
        "native_h1_state_sync_trusted_base_v0",
        "CREATE TABLE native_h1_state_sync_trusted_base_v0 (
           singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
           store_id BLOB NOT NULL CHECK (length(store_id) = 32),
           install_sequence BLOB NOT NULL CHECK (length(install_sequence) = 8),
           proof_id BLOB NOT NULL CHECK (length(proof_id) = 32),
           artifact BLOB NOT NULL,
           artifact_digest BLOB NOT NULL CHECK (length(artifact_digest) = 32),
           target_snapshot_digest BLOB NOT NULL CHECK (length(target_snapshot_digest) = 32),
           target_commit_id BLOB NOT NULL CHECK (length(target_commit_id) = 32),
           import_digest BLOB NOT NULL CHECK (length(import_digest) = 32)
         )",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeApplicationExecutionErrorCodeV0 {
    InvalidConfiguration,
    Storage,
    CorruptStore,
    ReplacedStore,
    BindingMismatch,
    NonContiguous,
    CommitUncertain,
    DeterministicallyInvalid,
    Busy,
}

#[derive(Debug)]
pub struct NativeApplicationExecutionErrorV0 {
    code: NativeApplicationExecutionErrorCodeV0,
    field: &'static str,
}

impl NativeApplicationExecutionErrorV0 {
    const fn new(code: NativeApplicationExecutionErrorCodeV0, field: &'static str) -> Self {
        Self { code, field }
    }

    pub const fn code(&self) -> NativeApplicationExecutionErrorCodeV0 {
        self.code
    }

    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl std::fmt::Display for NativeApplicationExecutionErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}:{}", self.code, self.field)
    }
}

impl std::error::Error for NativeApplicationExecutionErrorV0 {}

type DurableResult<T> = Result<T, NativeApplicationExecutionErrorV0>;

type MetadataSqlRowV0 = (
    Vec<u8>,
    Vec<u8>,
    String,
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
);

fn error(
    code: NativeApplicationExecutionErrorCodeV0,
    field: &'static str,
) -> NativeApplicationExecutionErrorV0 {
    NativeApplicationExecutionErrorV0::new(code, field)
}

/// Reconstructs the canonical payload and every receipt commitment at the
/// finalization boundary instead of trusting the shape-only native carrier.
///
/// `NativeExecutedBlockV0` deliberately permits host-neutral construction and
/// therefore proves only count/index shape plus caller-supplied root equality.
/// A finalization owner must additionally bind transaction bytes to payload
/// leaves, native receipt digests to those leaves, native commitment hashes to
/// the exact canonical receipt fields, and the reconstructed list to the
/// finalized receipts root.
pub fn validate_native_finalized_execution_receipts_v0(
    executed: &NativeExecutedBlockV0,
) -> Result<(), NativeApplicationExecutionErrorV0> {
    let execution = executed.request();
    let payload = ApplicationPayloadV0::new(execution.transactions().to_vec()).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.payload",
        )
    })?;
    let payload_root = payload.payload_root().map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.payload_root",
        )
    })?;
    if payload_root.as_bytes() != execution.expected().payload_root().as_bytes() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.payload_root",
        ));
    }
    if executed.receipts().len() != payload.transactions().len() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.receipt_count",
        ));
    }

    let mut commitments = Vec::with_capacity(executed.receipts().len());
    for (expected_index, receipt) in executed.receipts().iter().enumerate() {
        let expected_index = u32::try_from(expected_index).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "finalized_commit.receipt_index",
            )
        })?;
        if receipt.transaction_index() != expected_index {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "finalized_commit.receipt_index",
            ));
        }
        let events = receipt
            .events()
            .iter()
            .map(|event| {
                let attributes = event
                    .attributes()
                    .iter()
                    .map(|attribute| {
                        ExecutionEventAttributeV0::new(
                            attribute.key().as_bytes().to_vec(),
                            attribute.value().as_bytes().to_vec(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                ExecutionEventV0::new(event.kind().as_bytes().to_vec(), attributes)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "finalized_commit.receipt_events",
                )
            })?;
        let commitment = ExecutionReceiptCommitmentV0::for_transaction(
            &payload,
            expected_index,
            receipt.gas_used(),
            receipt.fee_charged(),
            events,
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "finalized_commit.receipt_payload_leaf",
            )
        })?;
        if receipt.transaction_digest().as_bytes() != commitment.payload_leaf_hash() {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "finalized_commit.receipt_transaction_digest",
            ));
        }
        let encoded = commitment.try_cev0_bytes().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "finalized_commit.receipt_encoding",
            )
        })?;
        let expected_commitment = hash_domain(NATIVE_RECEIPT_COMMITMENT_DOMAIN_V0, &[&encoded]);
        if receipt.commitment().as_bytes() != &expected_commitment {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "finalized_commit.receipt_commitment",
            ));
        }
        commitments.push(commitment);
    }
    let receipts = ExecutionReceiptsV0::new(&payload, commitments).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.receipts",
        )
    })?;
    let receipts_root = receipts.receipts_root().map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.receipts_root",
        )
    })?;
    if receipts_root.as_bytes() != execution.expected().receipts_root().as_bytes() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.receipts_root",
        ));
    }
    Ok(())
}

fn ensure_finalized_header_binding_v0(
    header: &BlockHeader,
    execution: &NativeBlockExecutionRequestV0,
) -> DurableResult<()> {
    let expected = execution.expected();
    if header.id().as_bytes() != execution.block_id().as_bytes() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.block_id",
        ));
    }
    if header.height().get() != execution.height().get()
        || header.parent_id().as_bytes() != execution.parent().block_id().as_bytes()
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.height_or_parent",
        ));
    }
    if header.state_root().as_bytes() != expected.post_state_root().as_bytes() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.state_root",
        ));
    }
    if header.payload_root().as_bytes() != expected.payload_root().as_bytes()
        || header.receipts_root().as_bytes() != expected.receipts_root().as_bytes()
        || header.evidence_root().as_bytes() != expected.evidence_root().as_bytes()
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.other_roots",
        ));
    }
    if header.chain_id().as_str() != execution.chain_id().as_str()
        || header.genesis_hash().as_bytes() != execution.genesis_hash().as_bytes()
        || header.timestamp_ms() != execution.timestamp_ms()
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "finalized_commit.header_context",
        ));
    }
    Ok(())
}

/// Closed, secret-free inputs for one deterministic G3 laboratory
/// application configuration.
///
/// Chain identity is derived only from the frozen consensus context and the
/// independent application signer/lifecycle policy. Deployment facts bind the
/// per-validator store identity, but deliberately do not alter the chain
/// descriptor, initial block, initial application commit, or state root.
/// Local paths, process IDs, clocks, binaries, and secret key material are not
/// accepted by this type.
#[derive(Debug, Clone)]
pub struct CanonicalLabNativeApplicationConfigInputsV0 {
    run_id: String,
    coordinator_manifest_sha256: [u8; 32],
    topology_sha256: [u8; 32],
    validator_set_manifest_sha256: [u8; 32],
    candidate_source_sha256: [u8; 32],
    local_validator: ValidatorId,
    chain_genesis_inputs: CanonicalLabNativeChainGenesisInputsV0,
}

impl CanonicalLabNativeApplicationConfigInputsV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: impl Into<String>,
        coordinator_manifest_sha256: [u8; 32],
        topology_sha256: [u8; 32],
        validator_set_manifest_sha256: [u8; 32],
        candidate_source_sha256: [u8; 32],
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        application_signers: Vec<AuthorizedSignerV0>,
        governance_signer_id: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let run_id = run_id.into();
        ensure!(
            !run_id.is_empty()
                && run_id.len() <= 96
                && run_id.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'T' | b'Z')
                }),
            "lab run id is not canonical"
        );
        ensure!(
            coordinator_manifest_sha256 != [0; 32]
                && topology_sha256 != [0; 32]
                && validator_set_manifest_sha256 != [0; 32]
                && candidate_source_sha256 != [0; 32],
            "lab deployment commitments must be nonzero"
        );
        ensure!(
            validator_set.validator(local_validator).is_some(),
            "local validator is absent from the committed validator set"
        );
        let chain_genesis_inputs = CanonicalLabNativeChainGenesisInputsV0::new(
            validator_set,
            consensus_parameters,
            application_signers,
            governance_signer_id,
        )?;
        Ok(Self {
            run_id,
            coordinator_manifest_sha256,
            topology_sha256,
            validator_set_manifest_sha256,
            candidate_source_sha256,
            local_validator,
            chain_genesis_inputs,
        })
    }
}

/// Immutable trust inputs used to create or reopen one application store.
#[derive(Debug)]
pub struct NativeApplicationConfigV0 {
    chain_id: String,
    genesis_hash: [u8; 32],
    chain_descriptor_hash: [u8; 32],
    store_id: [u8; 32],
    initial_block_id: [u8; 32],
    initial_commit_id: [u8; 32],
    validator_set: ValidatorSet,
    native_validator_set: NativeValidatorSetV0,
    parameters: ConsensusParametersV0,
    signers: Vec<AuthorizedSignerV0>,
    signer_policy_commitment: [u8; 32],
    initial_snapshot: Vec<u8>,
    initial_state_root: [u8; 32],
}

impl NativeApplicationConfigV0 {
    /// Derives one laboratory application configuration from a closed set of
    /// public deployment facts without opening or initializing a store.
    ///
    /// Application command keys must be independent from every consensus key.
    /// This prevents a consensus signing key from silently acquiring the
    /// `operator` role. Signer order is canonicalized before both the policy
    /// commitment and lifecycle JSON are derived.
    pub fn from_canonical_lab_inputs_v0(
        inputs: CanonicalLabNativeApplicationConfigInputsV0,
    ) -> anyhow::Result<Self> {
        let CanonicalLabNativeApplicationConfigInputsV0 {
            run_id,
            coordinator_manifest_sha256,
            topology_sha256,
            validator_set_manifest_sha256,
            candidate_source_sha256,
            local_validator,
            chain_genesis_inputs,
        } = inputs;
        let material = derive_canonical_lab_native_chain_genesis_material_v0(chain_genesis_inputs)?;
        let store_id = hash_domain(
            LAB_STORE_ID_DOMAIN_V0,
            &[
                &material.facts.chain_descriptor_hash_v0(),
                run_id.as_bytes(),
                &coordinator_manifest_sha256,
                &topology_sha256,
                &validator_set_manifest_sha256,
                &candidate_source_sha256,
                local_validator.as_bytes(),
            ],
        );
        ensure!(store_id != [0; 32], "canonical lab store id is zero");
        let native_validator_set = native_validator_set_v0(&material.validator_set)?;
        Ok(Self {
            chain_id: material.validator_set.chain_id().as_str().to_owned(),
            genesis_hash: *material.validator_set.genesis_hash().as_bytes(),
            chain_descriptor_hash: material.facts.chain_descriptor_hash_v0(),
            store_id,
            initial_block_id: material.facts.initial_block_id_v0(),
            initial_commit_id: material.facts.initial_commit_id_v0(),
            validator_set: material.validator_set,
            native_validator_set,
            parameters: material.consensus_parameters,
            signers: material.application_signers,
            signer_policy_commitment: material.facts.signer_policy_commitment_v0(),
            initial_snapshot: material.initial_snapshot,
            initial_state_root: material.facts.initial_state_root_v0(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: impl Into<String>,
        genesis_hash: [u8; 32],
        chain_descriptor_hash: [u8; 32],
        store_id: [u8; 32],
        initial_block_id: [u8; 32],
        initial_commit_id: [u8; 32],
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
        lifecycle_json: Vec<u8>,
        signers: Vec<AuthorizedSignerV0>,
        mut initial_writes: Vec<NativeStateWriteV0>,
    ) -> anyhow::Result<Self> {
        let chain_id = chain_id.into();
        ensure!(!chain_id.is_empty(), "chain id must not be empty");
        ensure!(genesis_hash != [0; 32], "genesis hash must not be zero");
        ensure!(
            chain_descriptor_hash != [0; 32],
            "chain descriptor hash must not be zero"
        );
        ensure!(store_id != [0; 32], "store id must not be zero");
        ensure!(
            initial_block_id != [0; 32],
            "initial block id must not be zero"
        );
        ensure!(
            initial_commit_id != [0; 32],
            "initial commit id must not be zero"
        );
        parameters
            .validate_safety_invariants()
            .map_err(crate::consensus_error)?;
        validator_set
            .validate_against_parameters(&parameters)
            .map_err(crate::consensus_error)?;
        ensure!(
            validator_set.chain_id().as_str() == chain_id,
            "validator-set chain mismatch"
        );
        ensure!(
            validator_set.genesis_hash().as_bytes() == &genesis_hash,
            "validator-set genesis mismatch"
        );
        let signer_policy_commitment = crate::signer_policy_commitment_v0(&signers)?;
        let lifecycle: crate::validator_lifecycle::ValidatorLifecycleStateV1 =
            serde_json::from_slice(&lifecycle_json).context("decode bootstrap lifecycle")?;
        ensure!(
            serde_json::to_vec(&lifecycle)? == lifecycle_json,
            "bootstrap lifecycle is not canonical JSON"
        );
        lifecycle.validate()?;
        ensure!(
            lifecycle.chain_id == chain_id,
            "bootstrap lifecycle chain mismatch"
        );
        ensure!(
            lifecycle.authorized_signers_hash_hex == hex::encode(signer_policy_commitment),
            "bootstrap lifecycle signer-policy mismatch"
        );
        validate_application_validator_projection_v0(&validator_set, &lifecycle.active_validators)?;
        initial_writes.push(validator_lifecycle_seed_write_v0(0, &lifecycle)?);
        let mut initial_store =
            InMemoryNativeExecutionStoreV0::new(chain_id.clone(), signers.clone(), parameters)?;
        let root = initial_store.apply_seed_v0(0, initial_writes)?;
        let initial_snapshot = initial_store.encode_authenticated_snapshot_v0()?;
        let native_validator_set = native_validator_set_v0(&validator_set)?;
        Ok(Self {
            chain_id,
            genesis_hash,
            chain_descriptor_hash,
            store_id,
            initial_block_id,
            initial_commit_id,
            validator_set,
            native_validator_set,
            parameters,
            signers,
            signer_policy_commitment,
            initial_snapshot,
            initial_state_root: root.0,
        })
    }

    pub const fn initial_state_root(&self) -> [u8; 32] {
        self.initial_state_root
    }

    pub const fn store_id(&self) -> [u8; 32] {
        self.store_id
    }

    /// Inert configuration readbacks used by a trusted Node join.  They do
    /// not grant store ownership or execution/commit authority.
    pub fn chain_id_v0(&self) -> &str {
        self.chain_id.as_str()
    }

    pub const fn genesis_hash_v0(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub const fn chain_descriptor_hash_v0(&self) -> [u8; 32] {
        self.chain_descriptor_hash
    }

    pub const fn signer_policy_commitment_v0(&self) -> [u8; 32] {
        self.signer_policy_commitment
    }

    pub const fn initial_block_id_v0(&self) -> [u8; 32] {
        self.initial_block_id
    }

    pub const fn initial_commit_id_v0(&self) -> [u8; 32] {
        self.initial_commit_id
    }

    pub const fn chain_genesis_facts_v0(&self) -> CanonicalLabNativeChainGenesisFactsV0 {
        CanonicalLabNativeChainGenesisFactsV0::new_for_config_v0(
            self.chain_descriptor_hash,
            self.signer_policy_commitment,
            self.initial_block_id,
            self.initial_state_root,
            self.initial_commit_id,
        )
    }

    pub const fn validator_set_v0(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn consensus_parameters_v0(&self) -> &ConsensusParametersV0 {
        &self.parameters
    }

    pub fn initial_validator_set(&self) -> &NativeValidatorSetV0 {
        &self.native_validator_set
    }
}

/// Single-process owner of one exact durable application store.
pub struct DurableNativeApplicationV0 {
    path: PathBuf,
    _lock_file: File,
    operation_lock: Mutex<()>,
    config: NativeApplicationConfigV0,
    owner_affinity: Arc<()>,
}

/// Exact application transition carried by a proof-derived h1 state-sync
/// import.
///
/// Construction validates only the local shape.  Possessing this value does
/// not prove finality and cannot activate Core, Safety, a signer, or a node.
/// The trusted Node host must keep Core's independently verified finality
/// carrier live while consuming this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeH1StateSyncTrustedBaseRequestV0 {
    proof_id: [u8; 32],
    execution: NativeBlockExecutionRequestV0,
}

/// Explicit adapter request for committing one already executed block whose
/// finalized header is independently carried by `FinalityProofV0`.
///
/// This request is deliberately narrower than a Core callback: it verifies
/// the proof against the store's authenticated validator/parameter set, binds
/// the proof's finalized header to the exact `NativeExecutedBlockV0`, and then
/// delegates to the existing atomic application commit. It does not interpret
/// a bare QC as an application commit, mint a Core/Safety permit, activate a
/// validator, or enable any production flag.
#[derive(Debug, Clone)]
pub struct FinalizedNativeApplicationCommitRequestV0 {
    executed: NativeExecutedBlockV0,
    finality_proof: FinalityProofV0,
    authenticated_parent_timestamp_ms: u64,
}

impl FinalizedNativeApplicationCommitRequestV0 {
    pub fn new(
        executed: NativeExecutedBlockV0,
        finality_proof: FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Self {
        Self {
            executed,
            finality_proof,
            authenticated_parent_timestamp_ms,
        }
    }

    pub const fn executed(&self) -> &NativeExecutedBlockV0 {
        &self.executed
    }

    pub const fn finality_proof(&self) -> &FinalityProofV0 {
        &self.finality_proof
    }

    pub const fn authenticated_parent_timestamp_ms(&self) -> u64 {
        self.authenticated_parent_timestamp_ms
    }
}

impl NativeH1StateSyncTrustedBaseRequestV0 {
    pub fn new(
        proof_id: [u8; 32],
        execution: NativeBlockExecutionRequestV0,
    ) -> anyhow::Result<Self> {
        ensure!(
            proof_id != [0; 32],
            "h1 state-sync proof id must not be zero"
        );
        ensure!(
            execution.height().get() == 1 && execution.parent().height().get() == 0,
            "h1 state-sync application import must be the exact genesis successor"
        );
        Ok(Self {
            proof_id,
            execution,
        })
    }

    pub const fn proof_id_v0(&self) -> [u8; 32] {
        self.proof_id
    }

    pub const fn execution_v0(&self) -> &NativeBlockExecutionRequestV0 {
        &self.execution
    }
}

/// Freshly revalidated ownership proof for one exact proof-derived h1
/// ApplicationStore TrustedBase.
///
/// The carrier is deliberately non-Clone and has no public constructor.  It
/// is still not consensus/finality authority: a Node commissioning join must
/// bind it to the exact Core-prepared Safety tag-4 head and a virgin signer.
///
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedNativeH1StateSyncTrustedBaseV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedNativeH1StateSyncTrustedBaseV0>();
/// ```
#[derive(Debug)]
#[must_use = "confirmed h1 trusted base must remain joined to Core, Safety, and signer facts"]
pub struct ConfirmedNativeH1StateSyncTrustedBaseV0 {
    store_id: [u8; 32],
    install_sequence: u64,
    proof_id: [u8; 32],
    head: ApplicationHeadV0,
    artifact_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    import_digest: [u8; 32],
    owner_affinity: Arc<()>,
}

impl ConfirmedNativeH1StateSyncTrustedBaseV0 {
    pub fn belongs_to_application_at_path_v0(
        &self,
        application: &DurableNativeApplicationV0,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &application.owner_affinity)
            && application.path() == expected_path
            && fresh_validate_v0(&application.path, &application.config).is_ok()
    }

    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn install_sequence_v0(&self) -> u64 {
        self.install_sequence
    }

    pub const fn proof_id_v0(&self) -> [u8; 32] {
        self.proof_id
    }

    pub const fn head_v0(&self) -> &ApplicationHeadV0 {
        &self.head
    }

    pub const fn artifact_digest_v0(&self) -> [u8; 32] {
        self.artifact_digest
    }

    pub const fn snapshot_digest_v0(&self) -> [u8; 32] {
        self.snapshot_digest
    }

    pub const fn import_digest_v0(&self) -> [u8; 32] {
        self.import_digest
    }
}

/// Freshly revalidated authority that one exact complete execution artifact
/// and its complete target overlay are the prepared durable `P` owned by this
/// application store.
///
/// The carrier is process-local, non-`Clone`, non-serializable, and has no
/// public constructor. Its digest accessors are inert comparison material;
/// only consuming the carrier together with Core's live request permit and
/// application-seal authority can advance toward a Valid callback.
///
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedDurableExecutionPV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedDurableExecutionPV0>();
/// ```
#[must_use = "confirmed durable P must remain joined to the Core callback owner"]
pub struct ConfirmedDurableExecutionPV0 {
    owner_affinity: Arc<()>,
    store_id: [u8; 32],
    p_sequence: u64,
    parent_block_id: [u8; 32],
    block_id: [u8; 32],
    target_height: u64,
    target_state_root: [u8; 32],
    application_commit_id: [u8; 32],
    artifact_digest: [u8; 32],
    overlay_digest: [u8; 32],
    p_digest: [u8; 32],
}

/// Durable lifecycle state of one fully audited execution-history row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableExecutionHistoryStatusV0 {
    Prepared,
    Committed,
}

/// Inert, non-cloneable fresh readback of one exact durable execution row.
///
/// Unlike [`ConfirmedDurableExecutionPV0`], this carrier grants no callback or
/// commit authority and may describe either a prepared or already-committed
/// row. It exists solely for restart coordinators which must join a complete
/// terminal validation inventory to the independently authenticated
/// application history before issuing a network replay challenge.
///
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedDurableExecutionHistoryRowV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ConfirmedDurableExecutionHistoryRowV0>();
/// ```
#[derive(Debug)]
#[must_use = "the confirmed history row must remain joined to its application owner"]
pub struct ConfirmedDurableExecutionHistoryRowV0 {
    owner_affinity: Arc<()>,
    store_id: [u8; 32],
    p_sequence: u64,
    status: DurableExecutionHistoryStatusV0,
    parent_height: u64,
    parent_block_id: [u8; 32],
    parent_state_root: [u8; 32],
    parent_commit_id: [u8; 32],
    target_height: u64,
    block_id: [u8; 32],
    target_state_root: [u8; 32],
    application_commit_id: [u8; 32],
    artifact_digest: [u8; 32],
    overlay_digest: [u8; 32],
    p_digest: [u8; 32],
    commit_sequence: Option<u64>,
}

impl ConfirmedDurableExecutionHistoryRowV0 {
    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn p_sequence_v0(&self) -> u64 {
        self.p_sequence
    }

    pub const fn status_v0(&self) -> DurableExecutionHistoryStatusV0 {
        self.status
    }

    pub const fn artifact_digest_v0(&self) -> [u8; 32] {
        self.artifact_digest
    }

    pub const fn overlay_digest_v0(&self) -> [u8; 32] {
        self.overlay_digest
    }

    pub const fn p_digest_v0(&self) -> [u8; 32] {
        self.p_digest
    }

    pub const fn commit_sequence_v0(&self) -> Option<u64> {
        self.commit_sequence
    }

    pub fn parent_head_v0(&self) -> DurableResult<ApplicationHeadV0> {
        Ok(ApplicationHeadV0::new(
            HeightV0::new(self.parent_height),
            BlockIdV0::new(self.parent_block_id).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_history.parent_block_id",
                )
            })?,
            StateRootV0::new(self.parent_state_root).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_history.parent_state_root",
                )
            })?,
            ApplicationCommitIdV0::new(self.parent_commit_id).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_history.parent_commit_id",
                )
            })?,
        ))
    }

    pub fn target_head_v0(&self) -> DurableResult<ApplicationHeadV0> {
        Ok(ApplicationHeadV0::new(
            HeightV0::new(self.target_height),
            BlockIdV0::new(self.block_id).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_history.block_id",
                )
            })?,
            StateRootV0::new(self.target_state_root).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_history.state_root",
                )
            })?,
            ApplicationCommitIdV0::new(self.application_commit_id).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_history.commit_id",
                )
            })?,
        ))
    }

    pub fn belongs_to_application_at_path_v0(
        &self,
        application: &DurableNativeApplicationV0,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &application.owner_affinity)
            && application.path == expected_path
            && fresh_validate_v0(&application.path, &application.config).is_ok()
    }
}

/// Fresh, authenticated readback of one application-finalized block.
///
/// The read is intentionally narrower than a network RPC response: it is
/// backed by the application's fully validated committed-chain inventory and
/// carries the exact durable-P history row plus the decoded execution artifact
/// (including receipt commitments).  A prepared row can never be returned.
/// The carrier is inert and does not mint a Core/Safety permit or a consensus
/// finality proof; a Node/RPC host must still join `confirmed_head_v0()` to its
/// independently authenticated Core finalized head before serving it.
#[derive(Debug)]
#[must_use = "the finalized application read must remain joined to its owner"]
pub struct FinalizedNativeApplicationReadV0 {
    confirmed_head: ApplicationHeadV0,
    row: ConfirmedDurableExecutionHistoryRowV0,
    executed: NativeExecutedBlockV0,
    receipt_commitments: Vec<Hash32V0>,
}

impl FinalizedNativeApplicationReadV0 {
    /// The freshly validated application head observed in the same read.
    pub const fn confirmed_head_v0(&self) -> &ApplicationHeadV0 {
        &self.confirmed_head
    }

    /// The exact durable-P row, including its committed status and digests.
    pub const fn durable_row_v0(&self) -> &ConfirmedDurableExecutionHistoryRowV0 {
        &self.row
    }

    /// The exact target head represented by the committed durable-P row.
    pub fn finalized_head_v0(&self) -> DurableResult<ApplicationHeadV0> {
        self.row.target_head_v0()
    }

    /// The canonical execution artifact freshly decoded from durable P.
    pub const fn executed_v0(&self) -> &NativeExecutedBlockV0 {
        &self.executed
    }

    /// Per-transaction receipt commitments in canonical transaction order.
    pub fn receipt_commitments_v0(&self) -> &[Hash32V0] {
        &self.receipt_commitments
    }

    /// The receipt root bound by the finalized execution header.
    pub const fn receipts_root_v0(&self) -> trnm_native_application::ReceiptsRootV0 {
        self.executed.request().expected().receipts_root()
    }
}

impl std::fmt::Debug for ConfirmedDurableExecutionPV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfirmedDurableExecutionPV0")
            .field("store_id", &hex::encode(self.store_id))
            .field("p_sequence", &self.p_sequence)
            .field("target_height", &self.target_height)
            .field("block_id", &hex::encode(self.block_id))
            .field("p_digest", &hex::encode(self.p_digest))
            .finish_non_exhaustive()
    }
}

impl ConfirmedDurableExecutionPV0 {
    /// Confirms that this prepared-P authority was issued by the same live,
    /// freshly validated application owner at the exact pinned path.
    pub fn belongs_to_application_at_path_v0(
        &self,
        application: &DurableNativeApplicationV0,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &application.owner_affinity)
            && application.path == expected_path
            && fresh_validate_v0(&application.path, &application.config).is_ok()
    }

    pub const fn store_id_v0(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn p_sequence_v0(&self) -> u64 {
        self.p_sequence
    }

    pub const fn parent_block_id_v0(&self) -> [u8; 32] {
        self.parent_block_id
    }

    pub const fn block_id_v0(&self) -> [u8; 32] {
        self.block_id
    }

    pub const fn target_height_v0(&self) -> u64 {
        self.target_height
    }

    /// Stable speculative parent head for pipelined descendants. The commit
    /// ID is derived when P is created and remains identical if this block is
    /// later finalized; it is not a QC or finality signal.
    pub fn overlay_parent_head_v0(&self) -> DurableResult<ApplicationHeadV0> {
        Ok(ApplicationHeadV0::new(
            HeightV0::new(self.target_height),
            BlockIdV0::new(self.block_id).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_p.block_id",
                )
            })?,
            StateRootV0::new(self.target_state_root).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_p.state_root",
                )
            })?,
            ApplicationCommitIdV0::new(self.application_commit_id).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirmed_p.commit_id",
                )
            })?,
        ))
    }

    pub const fn source_artifact_checksum_v0(&self) -> [u8; 32] {
        self.artifact_digest
    }

    /// SHA-256 of the complete canonical target JMT snapshot. This is the
    /// stable BlockId-keyed speculative-overlay checksum consumed by Core.
    pub const fn overlay_checksum_v0(&self) -> [u8; 32] {
        self.overlay_digest
    }

    pub const fn p_digest_v0(&self) -> [u8; 32] {
        self.p_digest
    }
}

impl std::fmt::Debug for DurableNativeApplicationV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableNativeApplicationV0")
            .field("path", &self.path)
            .field("store_id", &hex::encode(self.config.store_id))
            .finish_non_exhaustive()
    }
}

impl DurableNativeApplicationV0 {
    pub fn open(path: impl AsRef<Path>, config: NativeApplicationConfigV0) -> DurableResult<Self> {
        let (path, created) = prepare_store_file_v0(path.as_ref())?;
        let lock_path = lock_path_v0(&path)?;
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::Storage, "lock.open"))?;
        lock_file.try_lock_exclusive().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Busy,
                "lock.exclusive",
            )
        })?;
        if created {
            let connection = open_writable_connection_v0(&path)?;
            initialize_schema_v0(&connection)?;
            verify_schema_v0(&connection)?;
        } else {
            if sqlite_sidecars_present_v0(&path)? {
                recover_sqlite_rollback_journal_v0(&path)?;
            }
            reject_sqlite_sidecars_v0(&path)?;
            let connection = open_immutable_connection_v0(&path)?;
            verify_schema_v0(&connection)?;
            if metadata_exists_v0(&connection)? {
                let metadata = load_metadata_v0(&connection, &config)?;
                validate_metadata_v0(&connection, &config, &metadata)?;
            } else {
                validate_virgin_inventory_v0(&connection)?;
            }
        }
        Ok(Self {
            path,
            _lock_file: lock_file,
            operation_lock: Mutex::new(()),
            config,
            owner_affinity: Arc::new(()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Immutable trust inputs for cross-store commissioning comparisons.
    pub const fn config_v0(&self) -> &NativeApplicationConfigV0 {
        &self.config
    }

    /// Revalidates and returns the exact committed application head.
    ///
    /// This is an inert readback, not finality or Core authority.  A process
    /// host must still join it to the authenticated Safety/Core finalized tip
    /// before accepting it as a proposal parent.  The method performs the
    /// same complete immutable-store validation used by recovery and does not
    /// create a prepared execution artifact or advance the durable sequence.
    pub fn confirmed_committed_head_v0(&self) -> DurableResult<ApplicationHeadV0> {
        let _guard = self.lock_operation()?;
        let metadata = fresh_validate_v0(&self.path, &self.config)?;
        Ok(metadata.head)
    }

    /// Reads one exact committed application block by `BlockId`.
    ///
    /// This is a local authenticated read seam, not a network RPC or a
    /// replacement for Core's finality proof. The complete SQLite store is
    /// freshly validated before and after the row read; the row must be a
    /// committed member of the contiguous authenticated application chain,
    /// and its artifact/receipt commitments must decode and bind exactly.
    pub fn read_finalized_by_block_id_v0(
        &self,
        block_id: BlockIdV0,
    ) -> DurableResult<FinalizedNativeApplicationReadV0> {
        let _guard = self.lock_operation()?;
        self.read_finalized_v0(*block_id.as_bytes(), None)
    }

    /// Reads one exact committed application block by target height.
    ///
    /// Genesis has no durable-P row and therefore is rejected. A prepared
    /// future row, missing height, or any key/height mismatch fails closed.
    pub fn read_finalized_by_height_v0(
        &self,
        height: HeightV0,
    ) -> DurableResult<FinalizedNativeApplicationReadV0> {
        let _guard = self.lock_operation()?;
        self.read_finalized_by_height_locked_v0(height.get())
    }

    /// Reads a block and additionally joins it to an independently
    /// authenticated PoCO `FinalityProofV0`.
    ///
    /// Unlike the local committed-read seam, this method rejects a row that
    /// cannot be bound to the supplied three-chain proof, including any
    /// BlockId/height/parent/root/timestamp mismatch. The proof is verified
    /// against this store's committed validator set and parameters before the
    /// read is returned.
    pub fn read_finalized_by_block_id_with_proof_v0(
        &self,
        block_id: BlockIdV0,
        finality_proof: &FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> DurableResult<FinalizedNativeApplicationReadV0> {
        let read = self.read_finalized_by_block_id_v0(block_id)?;
        self.bind_finality_proof_to_read_v0(read, finality_proof, authenticated_parent_timestamp_ms)
    }

    /// Height-keyed counterpart to
    /// [`Self::read_finalized_by_block_id_with_proof_v0`].
    pub fn read_finalized_by_height_with_proof_v0(
        &self,
        height: HeightV0,
        finality_proof: &FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> DurableResult<FinalizedNativeApplicationReadV0> {
        let read = self.read_finalized_by_height_v0(height)?;
        self.bind_finality_proof_to_read_v0(read, finality_proof, authenticated_parent_timestamp_ms)
    }

    fn bind_finality_proof_to_read_v0(
        &self,
        read: FinalizedNativeApplicationReadV0,
        finality_proof: &FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> DurableResult<FinalizedNativeApplicationReadV0> {
        finality_proof
            .verify(
                &self.config.validator_set,
                None,
                &self.config.parameters,
                authenticated_parent_timestamp_ms,
                &StrictEd25519Verifier,
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "read_finalized.finality_proof",
                )
            })?;
        ensure_finalized_header_binding_v0(
            finality_proof.finalized_block().header(),
            read.executed.request(),
        )?;
        Ok(read)
    }

    fn read_finalized_by_height_locked_v0(
        &self,
        height: u64,
    ) -> DurableResult<FinalizedNativeApplicationReadV0> {
        if height == 0 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::NonContiguous,
                "read_finalized.genesis",
            ));
        }
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let p = load_p_by_height_v0(&connection, height)?.ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::NonContiguous,
                "read_finalized.missing_height",
            )
        })?;
        self.finish_finalized_read_v0(metadata, p, Some(height))
    }

    fn read_finalized_v0(
        &self,
        block_id: [u8; 32],
        expected_height: Option<u64>,
    ) -> DurableResult<FinalizedNativeApplicationReadV0> {
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let p = load_p_by_block_v0(&connection, block_id)?.ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::NonContiguous,
                "read_finalized.missing_block",
            )
        })?;
        self.finish_finalized_read_v0(metadata, p, expected_height)
    }

    fn finish_finalized_read_v0(
        &self,
        metadata: MetadataV0,
        p: DurablePV0,
        expected_height: Option<u64>,
    ) -> DurableResult<FinalizedNativeApplicationReadV0> {
        validate_p_v0(&self.config, &p)?;
        validate_target_snapshot_v0(&self.config, &p)?;
        if expected_height.is_some_and(|height| height != p.target_height) {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "read_finalized.height_block_mismatch",
            ));
        }
        if p.status != P_STATUS_COMMITTED
            || p.commit_sequence.is_none()
            || p.commit_id.is_none()
            || p.commit_id != Some(application_commit_id_v0(&p))
            || p.target_height > metadata.head.height().get()
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::NonContiguous,
                "read_finalized.not_committed",
            ));
        }
        let executed = decode_native_executed_block_artifact_v0(&p.artifact).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "read_finalized.artifact",
            )
        })?;
        let receipt_commitments = executed
            .receipts()
            .iter()
            .map(|receipt| Hash32V0::new(*receipt.commitment().as_bytes()))
            .collect::<Vec<_>>();
        let row = ConfirmedDurableExecutionHistoryRowV0 {
            owner_affinity: Arc::clone(&self.owner_affinity),
            store_id: p.store_id,
            p_sequence: p.p_sequence,
            status: DurableExecutionHistoryStatusV0::Committed,
            parent_height: p.parent_height,
            parent_block_id: p.parent_block_id,
            parent_state_root: p.parent_state_root,
            parent_commit_id: p.parent_commit_id,
            target_height: p.target_height,
            block_id: p.block_id,
            target_state_root: *executed.request().expected().post_state_root().as_bytes(),
            application_commit_id: application_commit_id_v0(&p),
            artifact_digest: p.artifact_digest,
            overlay_digest: p.target_snapshot_digest,
            p_digest: p.p_digest,
            commit_sequence: p.commit_sequence,
        };
        // A second immutable validation closes the read's TOCTOU window. Any
        // head/sequence change means this response is not a coherent read.
        let after = fresh_validate_v0(&self.path, &self.config)?;
        if after != metadata {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "read_finalized.concurrent_mutation",
            ));
        }
        Ok(FinalizedNativeApplicationReadV0 {
            confirmed_head: metadata.head,
            row,
            executed,
            receipt_commitments,
        })
    }

    /// Reopens and fully revalidates one exact prepared durable-P row without
    /// mutating the store, then returns its unique process-local authority.
    pub fn confirm_durable_p_v0(
        &self,
        executed: &NativeExecutedBlockV0,
    ) -> DurableResult<ConfirmedDurableExecutionPV0> {
        let _guard = self.lock_operation()?;
        let metadata = fresh_validate_v0(&self.path, &self.config)?;
        let exact_artifact = encode_native_executed_block_artifact_v0(executed).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "confirm_p.artifact_encode",
            )
        })?;
        let p = fresh_load_p_by_block_v0(&self.path, *executed.request().block_id().as_bytes())?;
        validate_p_v0(&self.config, &p)?;
        validate_target_snapshot_v0(&self.config, &p)?;
        if p.status != P_STATUS_PREPARED
            || p.artifact != exact_artifact
            || p.artifact_digest != sha256_v0(&exact_artifact)
            || p.block_id != *executed.request().block_id().as_bytes()
            || p.parent_block_id != *executed.request().parent().block_id().as_bytes()
            || p.parent_height != executed.request().parent().height().get()
            || p.target_height != executed.request().height().get()
            || p.p_sequence > metadata.durable_sequence
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "confirm_p.exact_binding",
            ));
        }
        Ok(ConfirmedDurableExecutionPV0 {
            owner_affinity: Arc::clone(&self.owner_affinity),
            store_id: p.store_id,
            p_sequence: p.p_sequence,
            parent_block_id: p.parent_block_id,
            block_id: p.block_id,
            target_height: p.target_height,
            target_state_root: *executed.request().expected().post_state_root().as_bytes(),
            application_commit_id: application_commit_id_v0(&p),
            artifact_digest: p.artifact_digest,
            overlay_digest: p.target_snapshot_digest,
            p_digest: p.p_digest,
        })
    }

    /// Reopens one exact prepared-or-committed execution row as inert history.
    ///
    /// The complete application database is freshly validated first. The
    /// supplied execution artifact must then equal the durable bytes named by
    /// the row, including its parent, target commitments, target snapshot, and
    /// lifecycle status. The returned carrier cannot validate payloads, commit
    /// a row, mint a Core callback, or release any runtime authority.
    pub fn confirm_durable_execution_history_row_v0(
        &self,
        executed: &NativeExecutedBlockV0,
    ) -> DurableResult<ConfirmedDurableExecutionHistoryRowV0> {
        let _guard = self.lock_operation()?;
        let metadata = fresh_validate_v0(&self.path, &self.config)?;
        let exact_artifact = encode_native_executed_block_artifact_v0(executed).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "confirm_history.artifact_encode",
            )
        })?;
        let p = fresh_load_p_by_block_v0(&self.path, *executed.request().block_id().as_bytes())?;
        validate_p_v0(&self.config, &p)?;
        validate_target_snapshot_v0(&self.config, &p)?;
        if p.artifact != exact_artifact
            || p.artifact_digest != sha256_v0(&exact_artifact)
            || p.block_id != *executed.request().block_id().as_bytes()
            || p.parent_block_id != *executed.request().parent().block_id().as_bytes()
            || p.parent_height != executed.request().parent().height().get()
            || p.target_height != executed.request().height().get()
            || p.p_sequence > metadata.durable_sequence
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "confirm_history.exact_binding",
            ));
        }
        let status = match p.status {
            P_STATUS_PREPARED if p.commit_sequence.is_none() && p.commit_id.is_none() => {
                DurableExecutionHistoryStatusV0::Prepared
            }
            P_STATUS_COMMITTED if p.commit_sequence.is_some() && p.commit_id.is_some() => {
                DurableExecutionHistoryStatusV0::Committed
            }
            _ => {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "confirm_history.status",
                ))
            }
        };
        Ok(ConfirmedDurableExecutionHistoryRowV0 {
            owner_affinity: Arc::clone(&self.owner_affinity),
            store_id: p.store_id,
            p_sequence: p.p_sequence,
            status,
            parent_height: p.parent_height,
            parent_block_id: p.parent_block_id,
            parent_state_root: p.parent_state_root,
            parent_commit_id: p.parent_commit_id,
            target_height: p.target_height,
            block_id: p.block_id,
            target_state_root: *executed.request().expected().post_state_root().as_bytes(),
            application_commit_id: application_commit_id_v0(&p),
            artifact_digest: p.artifact_digest,
            overlay_digest: p.target_snapshot_digest,
            p_digest: p.p_digest,
            commit_sequence: p.commit_sequence,
        })
    }

    /// Computes all frozen-v0 application commitments through an immutable,
    /// read-only connection without creating P or advancing any sequence.
    ///
    /// The returned preview is inert input for proposal construction. Final
    /// execution recomputes the transition from the pinned parent and still
    /// checks the final block ID and all four committed roots.
    pub fn preview_block_v0(
        &self,
        request: &NativeBlockPreviewRequestV0,
    ) -> DurableResult<NativeBlockPreviewV0> {
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let before = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &before)?;
        let store = resolve_parent_store_v0(&connection, &self.config, &before, request.parent())?;
        drop(connection);
        let preview = preview_complete_native_block_v0(
            &store,
            &self.config.validator_set,
            GenesisHash::new(self.config.genesis_hash),
            request,
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::DeterministicallyInvalid,
                "preview.execution",
            )
        })?;
        let after = fresh_validate_v0(&self.path, &self.config)?;
        if after.durable_sequence != before.durable_sequence
            || after.head != before.head
            || after.snapshot_digest != before.snapshot_digest
            || after.command_ids != before.command_ids
            || after.signer_nonces != before.signer_nonces
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "preview.read_only",
            ));
        }
        Ok(preview)
    }

    /// Atomically installs one proof-derived h1 application TrustedBase
    /// without creating a local durable-P row or validation history.
    ///
    /// The transition is accepted only from the exact initialized genesis
    /// head, with an empty P inventory.  Execution is recomputed locally from
    /// the pinned genesis snapshot, and the complete target snapshot plus an
    /// audit artifact are committed in one transaction.  A retry succeeds
    /// only for the byte-identical proof/request.  This method does not verify
    /// consensus finality; the Node host must consume Core's proof-carrying
    /// promotion candidate in the same commissioning join.
    pub fn install_h1_state_sync_trusted_base_v0(
        &self,
        request: &NativeH1StateSyncTrustedBaseRequestV0,
    ) -> DurableResult<ConfirmedNativeH1StateSyncTrustedBaseV0> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;

        if load_h1_state_sync_trusted_base_v0(&connection)?.is_some() {
            drop(connection);
            // A prior install may have returned CommitUncertain after its
            // SQLite transaction committed but before the host sync.  An
            // idempotent retry must re-establish the same durability fence
            // before returning the exact existing TrustedBase.
            sync_store_commit_boundary_named_v0(
                &self.path,
                "h1_state_sync.fsync",
                "h1_state_sync.directory_fsync",
            )?;
            return fresh_confirm_h1_state_sync_trusted_base_v0(
                &self.path,
                &self.config,
                request,
                Arc::clone(&self.owner_affinity),
            );
        }

        if metadata.head.height().get() != 0
            || metadata.head.block_id().as_bytes() != &self.config.initial_block_id
            || metadata.head.state_root().as_bytes() != &self.config.initial_state_root
            || metadata.head.commit_id().as_bytes() != &self.config.initial_commit_id
            || metadata.durable_sequence != 1
            || !load_all_p_v0(&connection)?.is_empty()
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::NonContiguous,
                "h1_state_sync.genesis_precondition",
            ));
        }

        let computed = compute_h1_state_sync_import_v0(&self.config, request)?;
        let install_sequence = metadata.durable_sequence.checked_add(1).ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "h1_state_sync.sequence_overflow",
            )
        })?;
        if install_sequence != 2 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "h1_state_sync.sequence",
            ));
        }
        let target_commit_id = h1_state_sync_commit_id_v0(
            self.config.store_id,
            request.proof_id,
            computed.artifact_digest,
            computed.snapshot_digest,
            *request.execution.block_id().as_bytes(),
        );
        let import_digest = h1_state_sync_import_digest_v0(
            self.config.store_id,
            install_sequence,
            request.proof_id,
            computed.artifact_digest,
            computed.snapshot_digest,
            target_commit_id,
        );
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::Storage,
                    "h1_state_sync.transaction",
                )
            })?;
        transaction
            .execute(
                "INSERT INTO native_h1_state_sync_trusted_base_v0 (
                   singleton,store_id,install_sequence,proof_id,artifact,artifact_digest,
                   target_snapshot_digest,target_commit_id,import_digest
                 ) VALUES (1,?,?,?,?,?,?,?,?)",
                params![
                    self.config.store_id.as_slice(),
                    u64_bytes_v0(install_sequence).as_slice(),
                    request.proof_id.as_slice(),
                    computed.artifact,
                    computed.artifact_digest.as_slice(),
                    computed.snapshot_digest.as_slice(),
                    target_commit_id.as_slice(),
                    import_digest.as_slice(),
                ],
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                    "h1_state_sync.insert",
                )
            })?;
        let changed = transaction
            .execute(
                "UPDATE native_application_metadata_v0 SET
                   durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,
                   head_commit_id=?,authenticated_snapshot=?,authenticated_snapshot_digest=?,
                   replay_command_ids=?,replay_signer_nonces=?
                 WHERE singleton=1 AND durable_sequence=? AND head_height=? AND head_block_id=?
                   AND head_state_root=? AND head_commit_id=?",
                params![
                    u64_bytes_v0(install_sequence).as_slice(),
                    u64_bytes_v0(1).as_slice(),
                    request.execution.block_id().as_bytes().as_slice(),
                    request
                        .execution
                        .expected()
                        .post_state_root()
                        .as_bytes()
                        .as_slice(),
                    target_commit_id.as_slice(),
                    computed.snapshot,
                    computed.snapshot_digest.as_slice(),
                    computed.command_bytes,
                    computed.nonce_bytes,
                    u64_bytes_v0(metadata.durable_sequence).as_slice(),
                    u64_bytes_v0(0).as_slice(),
                    self.config.initial_block_id.as_slice(),
                    self.config.initial_state_root.as_slice(),
                    self.config.initial_commit_id.as_slice(),
                ],
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                    "h1_state_sync.metadata_update",
                )
            })?;
        if changed != 1 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "h1_state_sync.metadata_cas",
            ));
        }
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("h1_before_commit");
        transaction.commit().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "h1_state_sync.commit",
            )
        })?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("h1_before_fsync");
        sync_store_commit_boundary_named_v0(
            &self.path,
            "h1_state_sync.fsync",
            "h1_state_sync.directory_fsync",
        )?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("h1_after_fsync");
        fresh_confirm_h1_state_sync_trusted_base_v0(
            &self.path,
            &self.config,
            request,
            Arc::clone(&self.owner_affinity),
        )
    }

    /// Revalidates one already-installed h1 TrustedBase through a fresh
    /// immutable connection and exact request comparison.
    pub fn confirm_h1_state_sync_trusted_base_exact_v0(
        &self,
        request: &NativeH1StateSyncTrustedBaseRequestV0,
    ) -> DurableResult<ConfirmedNativeH1StateSyncTrustedBaseV0> {
        let _guard = self.lock_operation()?;
        fresh_confirm_h1_state_sync_trusted_base_v0(
            &self.path,
            &self.config,
            request,
            Arc::clone(&self.owner_affinity),
        )
    }

    /// Verifies one complete PoCO finality proof, binds its finalized header
    /// to the exact executed block, and delegates to the existing atomic
    /// application commit path.
    ///
    /// This is an explicit adapter seam for a future Core host. It does not
    /// turn QC/finality into a standalone application authority, and it does
    /// not change `qc_as_application_commit`, Core/Safety, signer, or
    /// production activation flags.
    pub fn commit_finalized_block_v0(
        &self,
        request: FinalizedNativeApplicationCommitRequestV0,
    ) -> DurableResult<NativeApplicationCommitResultV0> {
        let FinalizedNativeApplicationCommitRequestV0 {
            executed,
            finality_proof,
            authenticated_parent_timestamp_ms,
        } = request;
        let execution = executed.request();
        let finalized_header = finality_proof.finalized_block().header();

        ensure_finalized_header_binding_v0(finalized_header, execution)?;
        validate_native_finalized_execution_receipts_v0(&executed)?;
        finality_proof
            .verify(
                &self.config.validator_set,
                None,
                &self.config.parameters,
                authenticated_parent_timestamp_ms,
                &StrictEd25519Verifier,
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "finalized_commit.finality_proof",
                )
            })?;

        NativeApplicationV0::commit_block(self, NativeApplicationCommitRequestV0::new(executed))
    }

    fn lock_operation(&self) -> DurableResult<std::sync::MutexGuard<'_, ()>> {
        self.operation_lock.lock().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Busy,
                "operation_lock",
            )
        })
    }
}

impl NativeApplicationV0 for DurableNativeApplicationV0 {
    type Error = NativeApplicationExecutionErrorV0;

    fn initialize(
        &self,
        request: NativeApplicationGenesisRequestV0,
    ) -> Result<NativeApplicationGenesisResultV0, Self::Error> {
        let _guard = self.lock_operation()?;
        validate_genesis_request_v0(&self.config, &request)?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        if metadata_exists_v0(&connection)? {
            let metadata = load_metadata_v0(&connection, &self.config)?;
            validate_metadata_v0(&connection, &self.config, &metadata)?;
            if metadata.head.height().get() != 0 {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::NonContiguous,
                    "initialize.committed_head",
                ));
            }
            // A prior initialize may have returned CommitUncertain after its
            // SQLite transaction committed but before the host sync.  An
            // idempotent retry must re-establish the same durability fence
            // before returning the exact existing genesis.
            sync_store_commit_boundary_named_v0(
                &self.path,
                "initialize.fsync",
                "initialize.directory_fsync",
            )?;
            return NativeApplicationGenesisResultV0::new(
                &request,
                metadata.head,
                ValidatorSetIdV0::new(*self.config.validator_set.id().as_bytes()).map_err(
                    |_| {
                        error(
                            NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                            "validator_set_id",
                        )
                    },
                )?,
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "initialize.result",
                )
            });
        }
        validate_virgin_inventory_v0(&connection)?;
        let head = ApplicationHeadV0::new(
            HeightV0::GENESIS,
            BlockIdV0::new(self.config.initial_block_id).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                    "initial_block",
                )
            })?,
            StateRootV0::new(self.config.initial_state_root).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                    "initial_root",
                )
            })?,
            ApplicationCommitIdV0::new(self.config.initial_commit_id).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                    "initial_commit",
                )
            })?,
        );
        let snapshot_digest = sha256_v0(&self.config.initial_snapshot);
        let empty_commands = encode_borsh_v0(&BTreeSet::<String>::new(), "initialize.commands")?;
        let empty_nonces = encode_borsh_v0(&BTreeSet::<(String, u64)>::new(), "initialize.nonces")?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::Storage,
                    "initialize.transaction",
                )
            })?;
        transaction
            .execute(
                "INSERT INTO native_application_metadata_v0 (
                   singleton,schema_version,store_id,chain_id,genesis_hash,chain_descriptor_hash,
                   signer_policy_commitment,validator_set_id,parameters_hash,durable_sequence,
                   head_height,head_block_id,head_state_root,head_commit_id,authenticated_snapshot,
                   authenticated_snapshot_digest,replay_command_ids,replay_signer_nonces
                 ) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![
                    u64_bytes_v0(APPLICATION_SCHEMA_VERSION_V0).as_slice(),
                    self.config.store_id.as_slice(),
                    self.config.chain_id,
                    self.config.genesis_hash.as_slice(),
                    self.config.chain_descriptor_hash.as_slice(),
                    self.config.signer_policy_commitment.as_slice(),
                    self.config.validator_set.id().as_bytes().as_slice(),
                    self.config.parameters.hash().as_bytes().as_slice(),
                    u64_bytes_v0(1).as_slice(),
                    u64_bytes_v0(0).as_slice(),
                    self.config.initial_block_id.as_slice(),
                    self.config.initial_state_root.as_slice(),
                    self.config.initial_commit_id.as_slice(),
                    self.config.initial_snapshot.as_slice(),
                    snapshot_digest.as_slice(),
                    empty_commands,
                    empty_nonces,
                ],
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::Storage,
                    "initialize.insert",
                )
            })?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("initialize_before_commit");
        transaction.commit().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "initialize.commit",
            )
        })?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("initialize_before_fsync");
        sync_store_commit_boundary_named_v0(
            &self.path,
            "initialize.fsync",
            "initialize.directory_fsync",
        )?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("initialize_after_fsync");
        fresh_validate_v0(&self.path, &self.config)?;
        NativeApplicationGenesisResultV0::new(
            &request,
            head,
            ValidatorSetIdV0::new(*self.config.validator_set.id().as_bytes()).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                    "validator_set_id",
                )
            })?,
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "initialize.result",
            )
        })
    }

    fn execute_block(
        &self,
        request: NativeBlockExecutionRequestV0,
    ) -> Result<NativeBlockExecutionResultV0, Self::Error> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;

        if let Some(existing) = load_p_by_block_v0(&connection, *request.block_id().as_bytes())? {
            validate_p_v0(&self.config, &existing)?;
            let executed =
                decode_native_executed_block_artifact_v0(&existing.artifact).map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "p.artifact_decode",
                    )
                })?;
            if executed.request() != &request {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "p.request",
                ));
            }
            fresh_validate_p_v0(&self.path, &self.config, &existing)?;
            return Ok(NativeBlockExecutionResultV0::valid(executed));
        }

        let store =
            resolve_parent_store_v0(&connection, &self.config, &metadata, request.parent())?;
        let complete = match execute_complete_native_block_v0(
            &store,
            &self.config.validator_set,
            GenesisHash::new(self.config.genesis_hash),
            &request,
        ) {
            Ok(value) => value,
            Err(execution_error) => {
                if let Some(classified) = execution_error
                    .downcast_ref::<CompleteNativeExecutionFailureV0>()
                {
                    match classified {
                        CompleteNativeExecutionFailureV0::StateUnavailable => {
                            return Ok(NativeBlockExecutionResultV0::unavailable(
                                &request,
                                NativeUnavailableReasonV0::AuthenticatedStateUnavailable,
                            ));
                        }
                        CompleteNativeExecutionFailureV0::Deterministic(classification) => {
                            if classification.disposition()
                                == trnm_runtime::DeterministicRuntimeFailureDispositionV0::InvariantFault
                            {
                                return Err(error(
                                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                                    "execute.runtime_invariant",
                                ));
                            }
                            let invalid = NativeDeterministicInvalidV0::new(
                                &request,
                                classification.code(),
                            )
                            .map_err(|_| {
                                error(
                                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                                    "execute.invalid_code",
                                )
                            })?;
                            return Ok(NativeBlockExecutionResultV0::DeterministicallyInvalid(
                                invalid,
                            ));
                        }
                        CompleteNativeExecutionFailureV0::Unclassified => {
                            return Err(error(
                                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                                "execute.unclassified_runtime_failure",
                            ));
                        }
                    }
                }

                // Preserve the pre-existing deterministic-invalid result for
                // complete-body/schema errors which are not runtime attempt
                // failures.  Runtime state unavailability and invariant
                // faults take the typed branches above and can no longer be
                // silently downgraded to a transaction rejection.
                let invalid = NativeDeterministicInvalidV0::new(
                    &request,
                    "frozen_v0_execution_rejected",
                )
                .map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "execute.invalid_code",
                    )
                })?;
                return Ok(NativeBlockExecutionResultV0::DeterministicallyInvalid(invalid));
            }
        };
        let (executed, plan, replay_identities, lifecycle) = complete.into_parts();
        if plan.version() != request.height().get() {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.plan_version",
            ));
        }
        let _complete_write_count = plan.writes().len();
        let artifact = encode_native_executed_block_artifact_v0(&executed).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.artifact_encode",
            )
        })?;
        let artifact_digest = sha256_v0(&artifact);
        let mut target_store = store;
        let state_root = target_store
            .apply_complete_state_plan_v0(plan)
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.apply_plan",
                )
            })?;
        if state_root.as_bytes() != executed.request().expected().post_state_root().as_bytes() {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "p.target_root",
            ));
        }
        for replay in &replay_identities {
            target_store
                .mark_committed_command_v0(replay.command_id(), replay.signer_id(), replay.nonce())
                .map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "p.replay_apply",
                    )
                })?;
        }
        let target_snapshot = target_store
            .encode_authenticated_snapshot_v0()
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.snapshot_encode",
                )
            })?;
        let target_snapshot_digest = sha256_v0(&target_snapshot);
        let (target_commands, target_nonces) = target_store.replay_sets_v0();
        let target_command_bytes = encode_borsh_v0(target_commands, "p.target_commands")?;
        let target_nonce_bytes = encode_borsh_v0(target_nonces, "p.target_nonces")?;
        let lifecycle_json = serde_json::to_vec(&lifecycle).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.lifecycle_encode",
            )
        })?;
        let p_sequence = metadata.durable_sequence.checked_add(1).ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.sequence_overflow",
            )
        })?;
        let p_digest = p_digest_v0(
            self.config.store_id,
            p_sequence,
            artifact_digest,
            target_snapshot_digest,
            &target_command_bytes,
            &target_nonce_bytes,
            &lifecycle_json,
        );
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::Storage,
                    "p.transaction",
                )
            })?;
        transaction
            .execute(
                "INSERT INTO native_durable_execution_p_v0 (
                   target_height,store_id,p_sequence,status,parent_height,parent_block_id,
                   parent_state_root,parent_commit_id,block_id,artifact,artifact_digest,target_snapshot,
                   target_snapshot_digest,target_replay_command_ids,target_replay_signer_nonces,
                   target_lifecycle_json,p_digest,commit_sequence,commit_id
                 ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
                params![
                    u64_bytes_v0(request.height().get()).as_slice(),
                    self.config.store_id.as_slice(),
                    u64_bytes_v0(p_sequence).as_slice(),
                    u64_bytes_v0(P_STATUS_PREPARED).as_slice(),
                    u64_bytes_v0(request.parent().height().get()).as_slice(),
                    request.parent().block_id().as_bytes().as_slice(),
                    request.parent().state_root().as_bytes().as_slice(),
                    request.parent().commit_id().as_bytes().as_slice(),
                    request.block_id().as_bytes().as_slice(),
                    artifact,
                    artifact_digest.as_slice(),
                    target_snapshot,
                    target_snapshot_digest.as_slice(),
                    target_command_bytes,
                    target_nonce_bytes,
                    lifecycle_json,
                    p_digest.as_slice(),
                ],
            )
            .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::CommitUncertain, "p.insert"))?;
        let changed = transaction
            .execute(
                "UPDATE native_application_metadata_v0 SET durable_sequence = ? WHERE singleton = 1 AND durable_sequence = ?",
                params![u64_bytes_v0(p_sequence).as_slice(), u64_bytes_v0(metadata.durable_sequence).as_slice()],
            )
            .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::CommitUncertain, "p.sequence_update"))?;
        if changed != 1 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "p.sequence_cas",
            ));
        }
        transaction.commit().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "p.commit",
            )
        })?;
        let persisted = fresh_load_p_by_block_v0(&self.path, *request.block_id().as_bytes())?;
        validate_p_v0(&self.config, &persisted)?;
        if persisted.artifact_digest != artifact_digest || persisted.p_digest != p_digest {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "p.fresh_readback",
            ));
        }
        validate_target_snapshot_v0(&self.config, &persisted)?;
        Ok(NativeBlockExecutionResultV0::valid(executed))
    }

    fn commit_block(
        &self,
        request: NativeApplicationCommitRequestV0,
    ) -> Result<NativeApplicationCommitResultV0, Self::Error> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let mut p = load_p_by_block_v0(
            &connection,
            *request.executed().request().block_id().as_bytes(),
        )?
        .ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::NonContiguous,
                "commit.missing_p",
            )
        })?;
        validate_p_v0(&self.config, &p)?;
        let exact_artifact =
            encode_native_executed_block_artifact_v0(request.executed()).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "commit.artifact_encode",
                )
            })?;
        if exact_artifact != p.artifact {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "commit.artifact",
            ));
        }
        if p.status == P_STATUS_COMMITTED {
            if metadata.head.height().get() != p.target_height
                || metadata.head.block_id().as_bytes() != &p.block_id
            {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "commit.replay_head",
                ));
            }
            let sequence = p.commit_sequence.ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "commit.sequence",
                )
            })?;
            return NativeApplicationCommitResultV0::new(&request, metadata.head, sequence, None)
                .map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                        "commit.replay_result",
                    )
                });
        }
        if metadata.head.height().get() != p.parent_height
            || metadata.head.block_id().as_bytes() != &p.parent_block_id
            || metadata.head.state_root().as_bytes() != &p.parent_state_root
            || metadata.head.commit_id().as_bytes() != &p.parent_commit_id
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "commit.parent_or_sequence",
            ));
        }
        validate_target_snapshot_v0(&self.config, &p)?;
        let commit_sequence = metadata.durable_sequence.checked_add(1).ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "commit.sequence_overflow",
            )
        })?;
        let commit_id = application_commit_id_v0(&p);
        let pruned = prepared_blocks_not_descending_from_v0(&connection, p.block_id)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::Storage,
                    "commit.transaction",
                )
            })?;
        let changed = transaction
            .execute(
                "UPDATE native_application_metadata_v0 SET durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,head_commit_id=?,authenticated_snapshot=?,authenticated_snapshot_digest=?,replay_command_ids=?,replay_signer_nonces=? WHERE singleton=1 AND durable_sequence=? AND head_height=? AND head_block_id=? AND head_state_root=? AND head_commit_id=?",
                params![
                    u64_bytes_v0(commit_sequence).as_slice(),
                    u64_bytes_v0(p.target_height).as_slice(),
                    p.block_id.as_slice(),
                    request.executed().request().expected().post_state_root().as_bytes().as_slice(),
                    commit_id.as_slice(),
                    p.target_snapshot,
                    p.target_snapshot_digest.as_slice(),
                    p.target_command_bytes,
                    p.target_nonce_bytes,
                    u64_bytes_v0(metadata.durable_sequence).as_slice(),
                    u64_bytes_v0(p.parent_height).as_slice(),
                    p.parent_block_id.as_slice(),
                    p.parent_state_root.as_slice(),
                    p.parent_commit_id.as_slice(),
                ],
            )
            .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::CommitUncertain, "commit.metadata_update"))?;
        if changed != 1 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "commit.metadata_cas",
            ));
        }
        let changed = transaction
            .execute(
                "UPDATE native_durable_execution_p_v0 SET status=?,commit_sequence=?,commit_id=? WHERE block_id=? AND status=? AND p_digest=?",
                params![
                    u64_bytes_v0(P_STATUS_COMMITTED).as_slice(),
                    u64_bytes_v0(commit_sequence).as_slice(),
                    commit_id.as_slice(),
                    p.block_id.as_slice(),
                    u64_bytes_v0(P_STATUS_PREPARED).as_slice(),
                    p.p_digest.as_slice(),
                ],
            )
            .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::CommitUncertain, "commit.p_update"))?;
        if changed != 1 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "commit.p_cas",
            ));
        }
        for block_id in pruned {
            let changed = transaction
                .execute(
                    "DELETE FROM native_durable_execution_p_v0 WHERE block_id=? AND status=?",
                    params![
                        block_id.as_slice(),
                        u64_bytes_v0(P_STATUS_PREPARED).as_slice()
                    ],
                )
                .map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                        "commit.prune",
                    )
                })?;
            if changed != 1 {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                    "commit.prune_cas",
                ));
            }
        }
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("before_commit");
        // SQLite's FULL synchronous mode orders the database journal, but a
        // successful transaction does not by itself make the directory entry
        // durable across a sudden power loss. Sync the database and its
        // containing directory before doing the fresh readback. A sync error
        // is deliberately reported as CommitUncertain: the transaction may
        // already be durable and the caller must recover by exact readback,
        // never by issuing a second write.
        transaction.commit().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "commit.commit",
            )
        })?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("after_commit");
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("after_fsync");
        let fresh = fresh_validate_v0(&self.path, &self.config)?;
        p = fresh_load_p_by_block_v0(&self.path, p.block_id)?;
        validate_p_v0(&self.config, &p)?;
        if fresh.durable_sequence != commit_sequence || p.status != P_STATUS_COMMITTED {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "commit.fresh_readback",
            ));
        }
        NativeApplicationCommitResultV0::new(&request, fresh.head, commit_sequence, None).map_err(
            |_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "commit.result",
                )
            },
        )
    }

    fn state_proof(
        &self,
        request: NativeStateProofRequestV0,
    ) -> Result<NativeStateProofV0, Self::Error> {
        let _guard = self.lock_operation()?;
        let connection = open_writable_connection_v0(&self.path)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        if request.head() != &metadata.head {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "state_proof.head",
            ));
        }
        let store = metadata.to_store(&self.config)?;
        let (value, proof) = store
            .prove_raw_key_v0(request.head().height().get(), request.key())
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "state_proof.jmt",
                )
            })?;
        NativeStateProofV0::new(request, NativeStateProofSchemeV0::JmtIcs23V0, value, proof)
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "state_proof.result",
                )
            })
    }

    fn snapshot(
        &self,
        request: NativeSnapshotRequestV0,
    ) -> Result<NativeSnapshotManifestV0, Self::Error> {
        let _guard = self.lock_operation()?;
        let connection = open_writable_connection_v0(&self.path)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        if request.head() != &metadata.head {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "snapshot.head",
            ));
        }
        let maximum = usize::try_from(request.maximum_chunk_bytes()).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                "snapshot.chunk_limit",
            )
        })?;
        let mut chunks = Vec::new();
        for (index, bytes) in metadata.snapshot.chunks(maximum).enumerate() {
            let index = u32::try_from(index).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "snapshot.chunk_count",
                )
            })?;
            let digest = hash_domain(SNAPSHOT_CHUNK_DOMAIN_V0, &[&index.to_be_bytes(), bytes]);
            chunks.push(
                NativeSnapshotChunkV0::new(
                    index,
                    u32::try_from(bytes.len()).map_err(|_| {
                        error(
                            NativeApplicationExecutionErrorCodeV0::CorruptStore,
                            "snapshot.chunk_size",
                        )
                    })?,
                    Hash32V0::new(digest),
                )
                .map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "snapshot.chunk",
                    )
                })?,
            );
        }
        let chunk_digests = chunks
            .iter()
            .map(|chunk| chunk.digest().into_bytes())
            .collect::<Vec<_>>();
        let mut manifest_parts = Vec::with_capacity(chunk_digests.len() + 1);
        manifest_parts.push(metadata.snapshot_digest.as_slice());
        manifest_parts.extend(chunk_digests.iter().map(<[u8; 32]>::as_slice));
        let digest = hash_domain(SNAPSHOT_MANIFEST_DOMAIN_V0, &manifest_parts);
        NativeSnapshotManifestV0::new(request, chunks, Hash32V0::new(digest)).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "snapshot.manifest",
            )
        })
    }

    fn recover(
        &self,
        request: NativeApplicationRecoveryRequestV0,
    ) -> Result<NativeApplicationRecoveryResultV0, Self::Error> {
        let _guard = self.lock_operation()?;
        let connection = open_writable_connection_v0(&self.path)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        if request.chain_id().as_str() != self.config.chain_id
            || request.genesis_hash().as_bytes() != &self.config.genesis_hash
            || request.chain_descriptor_hash().as_bytes() != &self.config.chain_descriptor_hash
            || request.signer_policy_commitment().as_bytes()
                != &self.config.signer_policy_commitment
            || request.expected_head() != &metadata.head
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                "recover.binding",
            ));
        }
        let pending = count_prepared_p_v0(&connection)?;
        let watermarks = NativeRecoveryWatermarksV0::new(metadata.durable_sequence, 0, 0);
        let disposition = if pending == 0 {
            NativeRecoveryDispositionV0::Exact
        } else {
            NativeRecoveryDispositionV0::ValidationReplayRequired {
                pending_records: pending,
            }
        };
        NativeApplicationRecoveryResultV0::new(&request, metadata.head, watermarks, disposition)
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::BindingMismatch,
                    "recover.result",
                )
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct MetadataV0 {
    durable_sequence: u64,
    head: ApplicationHeadV0,
    snapshot: Vec<u8>,
    snapshot_digest: [u8; 32],
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
}

struct H1StateSyncTrustedBaseV0 {
    store_id: [u8; 32],
    install_sequence: u64,
    proof_id: [u8; 32],
    artifact: Vec<u8>,
    artifact_digest: [u8; 32],
    target_snapshot_digest: [u8; 32],
    target_commit_id: [u8; 32],
    import_digest: [u8; 32],
}

struct ComputedH1StateSyncImportV0 {
    artifact: Vec<u8>,
    artifact_digest: [u8; 32],
    snapshot: Vec<u8>,
    snapshot_digest: [u8; 32],
    command_bytes: Vec<u8>,
    nonce_bytes: Vec<u8>,
}

impl MetadataV0 {
    fn to_store(
        &self,
        config: &NativeApplicationConfigV0,
    ) -> DurableResult<InMemoryNativeExecutionStoreV0> {
        InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
            config.chain_id.clone(),
            config.signers.clone(),
            config.parameters,
            self.command_ids.clone(),
            self.signer_nonces.clone(),
            &self.snapshot,
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "metadata.snapshot_decode",
            )
        })
    }
}

fn initial_store_v0(
    config: &NativeApplicationConfigV0,
) -> DurableResult<InMemoryNativeExecutionStoreV0> {
    InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
        config.chain_id.clone(),
        config.signers.clone(),
        config.parameters,
        BTreeSet::new(),
        BTreeSet::new(),
        &config.initial_snapshot,
    )
    .map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "h1_state_sync.initial_snapshot",
        )
    })
}

fn compute_h1_state_sync_import_v0(
    config: &NativeApplicationConfigV0,
    request: &NativeH1StateSyncTrustedBaseRequestV0,
) -> DurableResult<ComputedH1StateSyncImportV0> {
    let execution = request.execution_v0();
    if execution.height().get() != 1
        || execution.parent().height().get() != 0
        || execution.parent().block_id().as_bytes() != &config.initial_block_id
        || execution.parent().state_root().as_bytes() != &config.initial_state_root
        || execution.parent().commit_id().as_bytes() != &config.initial_commit_id
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "h1_state_sync.parent",
        ));
    }
    let store = initial_store_v0(config)?;
    let complete = execute_complete_native_block_v0(
        &store,
        &config.validator_set,
        GenesisHash::new(config.genesis_hash),
        execution,
    )
    .map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::DeterministicallyInvalid,
            "h1_state_sync.execution",
        )
    })?;
    let (executed, plan, replay_identities, _lifecycle) = complete.into_parts();
    if executed.request() != execution || plan.version() != 1 {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "h1_state_sync.execution_binding",
        ));
    }
    let artifact = encode_native_executed_block_artifact_v0(&executed).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "h1_state_sync.artifact_encode",
        )
    })?;
    let artifact_digest = sha256_v0(&artifact);
    let mut target_store = store;
    let state_root = target_store
        .apply_complete_state_plan_v0(plan)
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "h1_state_sync.apply_plan",
            )
        })?;
    if state_root.as_bytes() != execution.expected().post_state_root().as_bytes() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "h1_state_sync.target_root",
        ));
    }
    for replay in &replay_identities {
        target_store
            .mark_committed_command_v0(replay.command_id(), replay.signer_id(), replay.nonce())
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "h1_state_sync.replay_apply",
                )
            })?;
    }
    let snapshot = target_store
        .encode_authenticated_snapshot_v0()
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "h1_state_sync.snapshot_encode",
            )
        })?;
    let snapshot_digest = sha256_v0(&snapshot);
    let (commands, nonces) = target_store.replay_sets_v0();
    let command_bytes = encode_borsh_v0(commands, "h1_state_sync.commands")?;
    let nonce_bytes = encode_borsh_v0(nonces, "h1_state_sync.nonces")?;
    Ok(ComputedH1StateSyncImportV0 {
        artifact,
        artifact_digest,
        snapshot,
        snapshot_digest,
        command_bytes,
        nonce_bytes,
    })
}

fn resolve_parent_store_v0(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
    parent: &ApplicationHeadV0,
) -> DurableResult<InMemoryNativeExecutionStoreV0> {
    if parent == &metadata.head {
        return metadata.to_store(config);
    }
    let p = load_p_by_block_v0(connection, *parent.block_id().as_bytes())?.ok_or_else(|| {
        error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "parent_overlay.missing",
        )
    })?;
    validate_p_v0(config, &p)?;
    if p.status != P_STATUS_PREPARED
        || p.target_height <= metadata.head.height().get()
        || parent.height().get() != p.target_height
        || parent.state_root().as_bytes()
            != decode_native_executed_block_artifact_v0(&p.artifact)
                .map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "parent_overlay.artifact",
                    )
                })?
                .request()
                .expected()
                .post_state_root()
                .as_bytes()
        || parent.commit_id().as_bytes() != &application_commit_id_v0(&p)
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "parent_overlay.binding",
        ));
    }
    target_store_v0(config, &p)
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct DurablePV0 {
    target_height: u64,
    store_id: [u8; 32],
    p_sequence: u64,
    status: u64,
    parent_height: u64,
    parent_block_id: [u8; 32],
    parent_state_root: [u8; 32],
    parent_commit_id: [u8; 32],
    block_id: [u8; 32],
    artifact: Vec<u8>,
    artifact_digest: [u8; 32],
    target_snapshot: Vec<u8>,
    target_snapshot_digest: [u8; 32],
    target_command_bytes: Vec<u8>,
    target_nonce_bytes: Vec<u8>,
    lifecycle_json: Vec<u8>,
    p_digest: [u8; 32],
    commit_sequence: Option<u64>,
    commit_id: Option<[u8; 32]>,
}

fn validate_genesis_request_v0(
    config: &NativeApplicationConfigV0,
    request: &NativeApplicationGenesisRequestV0,
) -> DurableResult<()> {
    if request.chain_id().as_str() != config.chain_id
        || request.genesis_hash().as_bytes() != &config.genesis_hash
        || request.chain_descriptor_hash().as_bytes() != &config.chain_descriptor_hash
        || request.signer_policy_commitment().as_bytes() != &config.signer_policy_commitment
        || request.initial_state_root().as_bytes() != &config.initial_state_root
        || request.initial_validator_set() != &config.native_validator_set
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "genesis.request",
        ));
    }
    Ok(())
}

fn native_validator_set_v0(set: &ValidatorSet) -> anyhow::Result<NativeValidatorSetV0> {
    let validators = set
        .validators()
        .iter()
        .map(|validator| {
            NativeValidatorV0::new(
                hex::encode(validator.id().as_bytes()),
                *validator.consensus_key().as_bytes(),
                validator.voting_power().get(),
            )
            .map_err(|error| anyhow::anyhow!("construct native validator: {error}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    NativeValidatorSetV0::new(
        ValidatorSetIdV0::new(*set.id().as_bytes())
            .map_err(|error| anyhow::anyhow!("construct native set id: {error}"))?,
        validators,
    )
    .map_err(|error| anyhow::anyhow!("construct native validator set: {error}"))
}

fn validate_metadata_v0(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> DurableResult<()> {
    if metadata.durable_sequence == 0 || metadata.snapshot_digest != sha256_v0(&metadata.snapshot) {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "metadata.digest_or_sequence",
        ));
    }
    let store = metadata.to_store(config)?;
    if store.parent_version_v0().map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "metadata.version",
        )
    })? != metadata.head.height().get()
        || store
            .parent_root_v0()
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "metadata.root",
                )
            })?
            .0
            != *metadata.head.state_root().as_bytes()
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "metadata.head_snapshot",
        ));
    }
    let maximum_p_sequence: Option<Vec<u8>> = connection
        .query_row(
            "SELECT MAX(p_sequence) FROM native_durable_execution_p_v0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "metadata.max_p_sequence",
            )
        })?;
    if let Some(bytes) = maximum_p_sequence {
        if decode_u64_v0(&bytes, "metadata.max_p_sequence")? > metadata.durable_sequence {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "metadata.sequence_rollback",
            ));
        }
    }
    validate_p_inventory_v0(connection, config, metadata)?;
    Ok(())
}

fn validate_p_inventory_v0(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> DurableResult<()> {
    let rows = load_all_p_v0(connection)?;
    let by_block = rows
        .iter()
        .map(|p| (p.block_id, p))
        .collect::<BTreeMap<_, _>>();
    if by_block.len() != rows.len() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.inventory_duplicate_block",
        ));
    }

    let trusted_base = load_h1_state_sync_trusted_base_v0(connection)?;
    let mut trusted_base_head = None;
    let mut allocated_sequences = BTreeSet::from([1_u64]);
    let mut maximum_sequence = 1_u64;
    if let Some(imported) = &trusted_base {
        let executed =
            decode_native_executed_block_artifact_v0(&imported.artifact).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "h1_state_sync.inventory_artifact",
                )
            })?;
        let trusted_base_request = NativeH1StateSyncTrustedBaseRequestV0::new(
            imported.proof_id,
            executed.request().clone(),
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "h1_state_sync.inventory_request",
            )
        })?;
        let recomputed = compute_h1_state_sync_import_v0(config, &trusted_base_request)?;
        if imported.store_id != config.store_id
            || imported.install_sequence != 2
            || imported.artifact != recomputed.artifact
            || imported.artifact_digest != recomputed.artifact_digest
            || imported.target_snapshot_digest != recomputed.snapshot_digest
            || executed.request().height().get() != 1
            || executed.request().parent().height().get() != 0
            || executed.request().parent().block_id().as_bytes() != &config.initial_block_id
            || executed.request().parent().state_root().as_bytes() != &config.initial_state_root
            || executed.request().parent().commit_id().as_bytes() != &config.initial_commit_id
            || imported.target_commit_id
                != h1_state_sync_commit_id_v0(
                    imported.store_id,
                    imported.proof_id,
                    imported.artifact_digest,
                    imported.target_snapshot_digest,
                    *executed.request().block_id().as_bytes(),
                )
            || imported.import_digest
                != h1_state_sync_import_digest_v0(
                    imported.store_id,
                    imported.install_sequence,
                    imported.proof_id,
                    imported.artifact_digest,
                    imported.target_snapshot_digest,
                    imported.target_commit_id,
                )
            || !allocated_sequences.insert(imported.install_sequence)
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "h1_state_sync.inventory_binding",
            ));
        }
        trusted_base_head = Some((
            executed.request().height().get(),
            *executed.request().block_id().as_bytes(),
            *executed.request().expected().post_state_root().as_bytes(),
            imported.target_commit_id,
        ));
        maximum_sequence = imported.install_sequence;
    }
    let mut target_roots = BTreeMap::new();
    for p in &rows {
        validate_p_v0(config, p)?;
        validate_target_snapshot_v0(config, p)?;
        if p.p_sequence <= 1
            || p.p_sequence > metadata.durable_sequence
            || !allocated_sequences.insert(p.p_sequence)
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.inventory_p_sequence",
            ));
        }
        maximum_sequence = maximum_sequence.max(p.p_sequence);
        if let Some(sequence) = p.commit_sequence {
            if sequence > metadata.durable_sequence || !allocated_sequences.insert(sequence) {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.inventory_commit_sequence",
                ));
            }
            maximum_sequence = maximum_sequence.max(sequence);
        }
        let executed = decode_native_executed_block_artifact_v0(&p.artifact).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.inventory_artifact",
            )
        })?;
        target_roots.insert(
            p.block_id,
            *executed.request().expected().post_state_root().as_bytes(),
        );
    }
    if maximum_sequence != metadata.durable_sequence {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.inventory_sequence_head",
        ));
    }

    for p in &rows {
        if p.parent_block_id == config.initial_block_id {
            if p.parent_height != 0
                || p.parent_state_root != config.initial_state_root
                || p.parent_commit_id != config.initial_commit_id
            {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.inventory_genesis_parent",
                ));
            }
            continue;
        }
        if let Some((height, block_id, state_root, commit_id)) = trusted_base_head {
            if p.parent_block_id == block_id {
                if p.parent_height != height
                    || p.parent_state_root != state_root
                    || p.parent_commit_id != commit_id
                    || height.checked_add(1) != Some(p.target_height)
                {
                    return Err(error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "p.inventory_trusted_base_parent",
                    ));
                }
                continue;
            }
        }
        let parent = by_block.get(&p.parent_block_id).ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.inventory_parent_missing",
            )
        })?;
        if parent.target_height != p.parent_height
            || parent.target_height.checked_add(1) != Some(p.target_height)
            || parent.p_sequence >= p.p_sequence
            || target_roots.get(&parent.block_id) != Some(&p.parent_state_root)
            || application_commit_id_v0(parent) != p.parent_commit_id
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.inventory_parent_binding",
            ));
        }
    }

    let mut committed = rows
        .iter()
        .filter(|p| p.status == P_STATUS_COMMITTED)
        .collect::<Vec<_>>();
    committed.sort_unstable_by_key(|p| p.target_height);
    let imported_height = u64::from(trusted_base.is_some());
    if u64::try_from(committed.len())
        .ok()
        .and_then(|count| count.checked_add(imported_height))
        != Some(metadata.head.height().get())
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.inventory_committed_length",
        ));
    }
    let (mut previous_height, mut previous_block, mut previous_root, mut previous_commit) =
        if let Some(imported) = &trusted_base {
            let executed =
                decode_native_executed_block_artifact_v0(&imported.artifact).map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "h1_state_sync.inventory_artifact",
                    )
                })?;
            if executed.request().height().get() != 1
                || executed.request().parent().height().get() != 0
                || executed.request().parent().block_id().as_bytes() != &config.initial_block_id
                || executed.request().parent().state_root().as_bytes() != &config.initial_state_root
                || executed.request().parent().commit_id().as_bytes() != &config.initial_commit_id
                || (committed.is_empty()
                    && (executed.request().block_id().as_bytes()
                        != metadata.head.block_id().as_bytes()
                        || executed.request().expected().post_state_root().as_bytes()
                            != metadata.head.state_root().as_bytes()
                        || imported.target_snapshot_digest != metadata.snapshot_digest
                        || imported.target_commit_id != *metadata.head.commit_id().as_bytes()))
            {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "h1_state_sync.inventory_artifact_binding",
                ));
            }
            (
                1_u64,
                *executed.request().block_id().as_bytes(),
                *executed.request().expected().post_state_root().as_bytes(),
                imported.target_commit_id,
            )
        } else {
            (
                0_u64,
                config.initial_block_id,
                config.initial_state_root,
                config.initial_commit_id,
            )
        };
    for p in committed {
        if p.target_height
            != previous_height.checked_add(1).ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.inventory_committed_height_overflow",
                )
            })?
            || p.parent_block_id != previous_block
            || p.parent_state_root != previous_root
            || p.parent_commit_id != previous_commit
        {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.inventory_committed_chain",
            ));
        }
        previous_height = p.target_height;
        previous_block = p.block_id;
        previous_root = *target_roots.get(&p.block_id).ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.inventory_committed_root",
            )
        })?;
        previous_commit = application_commit_id_v0(p);
    }
    if metadata.head.height().get() != previous_height
        || metadata.head.block_id().as_bytes() != &previous_block
        || metadata.head.state_root().as_bytes() != &previous_root
        || metadata.head.commit_id().as_bytes() != &previous_commit
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.inventory_head_binding",
        ));
    }

    for p in rows
        .iter()
        .filter(|candidate| candidate.status == P_STATUS_PREPARED)
    {
        if p.target_height <= metadata.head.height().get() {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.inventory_prepared_below_head",
            ));
        }
        let mut cursor = p;
        for _ in 0..=rows.len() {
            if cursor.parent_height == metadata.head.height().get() {
                if cursor.parent_block_id != *metadata.head.block_id().as_bytes()
                    || cursor.parent_state_root != *metadata.head.state_root().as_bytes()
                    || cursor.parent_commit_id != *metadata.head.commit_id().as_bytes()
                {
                    return Err(error(
                        NativeApplicationExecutionErrorCodeV0::CorruptStore,
                        "p.inventory_prepared_head",
                    ));
                }
                break;
            }
            cursor = by_block.get(&cursor.parent_block_id).ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.inventory_prepared_ancestry",
                )
            })?;
        }
        if cursor.parent_height != metadata.head.height().get() {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.inventory_prepared_cycle",
            ));
        }
    }
    Ok(())
}

fn target_store_v0(
    config: &NativeApplicationConfigV0,
    p: &DurablePV0,
) -> DurableResult<InMemoryNativeExecutionStoreV0> {
    if p.target_snapshot_digest != sha256_v0(&p.target_snapshot) {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.snapshot_digest",
        ));
    }
    let commands: BTreeSet<String> = decode_borsh_v0(&p.target_command_bytes, "p.target_commands")?;
    let nonces: BTreeSet<(String, u64)> =
        decode_borsh_v0(&p.target_nonce_bytes, "p.target_nonces")?;
    let store = InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
        config.chain_id.clone(),
        config.signers.clone(),
        config.parameters,
        commands,
        nonces,
        &p.target_snapshot,
    )
    .map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.snapshot_decode",
        )
    })?;
    if store.parent_version_v0().map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.snapshot_version",
        )
    })? != p.target_height
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.snapshot_height",
        ));
    }
    let executed = decode_native_executed_block_artifact_v0(&p.artifact).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.artifact",
        )
    })?;
    if store
        .parent_root_v0()
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.snapshot_root",
            )
        })?
        .0
        != *executed.request().expected().post_state_root().as_bytes()
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.snapshot_artifact_root",
        ));
    }
    let live = store
        .verified_live_values_v0(p.target_height)
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.snapshot_live",
            )
        })?;
    let lifecycle =
        load_validator_lifecycle_from_live_v0(&live, p.target_height).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.lifecycle_tree",
            )
        })?;
    let lifecycle_json = serde_json::to_vec(&lifecycle).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.lifecycle_encode",
        )
    })?;
    if lifecycle_json != p.lifecycle_json {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.lifecycle_binding",
        ));
    }
    Ok(store)
}

fn validate_target_snapshot_v0(
    config: &NativeApplicationConfigV0,
    p: &DurablePV0,
) -> DurableResult<()> {
    target_store_v0(config, p).map(drop)
}

fn validate_p_v0(config: &NativeApplicationConfigV0, p: &DurablePV0) -> DurableResult<()> {
    if p.store_id != config.store_id
        || p.target_height
            != p.parent_height.checked_add(1).ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.height_overflow",
                )
            })?
        || !matches!(p.status, P_STATUS_PREPARED | P_STATUS_COMMITTED)
        || p.artifact_digest != sha256_v0(&p.artifact)
        || p.p_digest
            != p_digest_v0(
                p.store_id,
                p.p_sequence,
                p.artifact_digest,
                p.target_snapshot_digest,
                &p.target_command_bytes,
                &p.target_nonce_bytes,
                &p.lifecycle_json,
            )
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.binding",
        ));
    }
    let executed = decode_native_executed_block_artifact_v0(&p.artifact).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.artifact_decode",
        )
    })?;
    if executed.request().height().get() != p.target_height
        || executed.request().parent().height().get() != p.parent_height
        || executed.request().parent().block_id().as_bytes() != &p.parent_block_id
        || executed.request().parent().state_root().as_bytes() != &p.parent_state_root
        || executed.request().parent().commit_id().as_bytes() != &p.parent_commit_id
        || executed.request().block_id().as_bytes() != &p.block_id
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.artifact_binding",
        ));
    }
    match (p.status, p.commit_sequence, p.commit_id) {
        (P_STATUS_PREPARED, None, None) => {}
        (P_STATUS_COMMITTED, Some(sequence), Some(commit_id)) => {
            if sequence <= p.p_sequence || commit_id != application_commit_id_v0(p) {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.commit_binding",
                ));
            }
        }
        _ => {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "p.status_binding",
            ))
        }
    }
    Ok(())
}

fn p_digest_v0(
    store_id: [u8; 32],
    sequence: u64,
    artifact_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    commands: &[u8],
    nonces: &[u8],
    lifecycle: &[u8],
) -> [u8; 32] {
    hash_domain(
        P_DIGEST_DOMAIN_V0,
        &[
            &store_id,
            &u64_bytes_v0(sequence),
            &artifact_digest,
            &snapshot_digest,
            &sha256_v0(commands),
            &sha256_v0(nonces),
            &sha256_v0(lifecycle),
        ],
    )
}

fn application_commit_id_v0(p: &DurablePV0) -> [u8; 32] {
    hash_domain(
        COMMIT_ID_DOMAIN_V0,
        &[&p.p_digest, &p.block_id, &p.target_snapshot_digest],
    )
}

fn h1_state_sync_commit_id_v0(
    store_id: [u8; 32],
    proof_id: [u8; 32],
    artifact_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    block_id: [u8; 32],
) -> [u8; 32] {
    hash_domain(
        H1_STATE_SYNC_COMMIT_ID_DOMAIN_V0,
        &[
            &store_id,
            &proof_id,
            &artifact_digest,
            &snapshot_digest,
            &block_id,
        ],
    )
}

fn h1_state_sync_import_digest_v0(
    store_id: [u8; 32],
    install_sequence: u64,
    proof_id: [u8; 32],
    artifact_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    commit_id: [u8; 32],
) -> [u8; 32] {
    hash_domain(
        H1_STATE_SYNC_IMPORT_DIGEST_DOMAIN_V0,
        &[
            &store_id,
            &u64_bytes_v0(install_sequence),
            &proof_id,
            &artifact_digest,
            &snapshot_digest,
            &commit_id,
        ],
    )
}

fn fresh_confirm_h1_state_sync_trusted_base_v0(
    path: &Path,
    config: &NativeApplicationConfigV0,
    request: &NativeH1StateSyncTrustedBaseRequestV0,
    owner_affinity: Arc<()>,
) -> DurableResult<ConfirmedNativeH1StateSyncTrustedBaseV0> {
    reject_sqlite_sidecars_v0(path)?;
    let connection = open_immutable_connection_v0(path)?;
    verify_schema_v0(&connection)?;
    let metadata = load_metadata_v0(&connection, config)?;
    validate_metadata_v0(&connection, config, &metadata)?;
    let imported = load_h1_state_sync_trusted_base_v0(&connection)?.ok_or_else(|| {
        error(
            NativeApplicationExecutionErrorCodeV0::NonContiguous,
            "h1_state_sync.fresh_missing",
        )
    })?;
    let computed = compute_h1_state_sync_import_v0(config, request)?;
    let target_commit_id = h1_state_sync_commit_id_v0(
        config.store_id,
        request.proof_id,
        computed.artifact_digest,
        computed.snapshot_digest,
        *request.execution.block_id().as_bytes(),
    );
    let import_digest = h1_state_sync_import_digest_v0(
        config.store_id,
        imported.install_sequence,
        request.proof_id,
        computed.artifact_digest,
        computed.snapshot_digest,
        target_commit_id,
    );
    if imported.store_id != config.store_id
        || imported.install_sequence != 2
        || imported.proof_id != request.proof_id
        || imported.artifact != computed.artifact
        || imported.artifact_digest != computed.artifact_digest
        || imported.target_snapshot_digest != computed.snapshot_digest
        || imported.target_commit_id != target_commit_id
        || imported.import_digest != import_digest
        || metadata.durable_sequence != imported.install_sequence
        || metadata.head.height().get() != 1
        || metadata.head.block_id().as_bytes() != request.execution.block_id().as_bytes()
        || metadata.head.state_root().as_bytes()
            != request.execution.expected().post_state_root().as_bytes()
        || metadata.head.commit_id().as_bytes() != &target_commit_id
        || metadata.snapshot != computed.snapshot
        || metadata.snapshot_digest != computed.snapshot_digest
        || !load_all_p_v0(&connection)?.is_empty()
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "h1_state_sync.fresh_exact",
        ));
    }
    Ok(ConfirmedNativeH1StateSyncTrustedBaseV0 {
        store_id: config.store_id,
        install_sequence: imported.install_sequence,
        proof_id: imported.proof_id,
        head: metadata.head,
        artifact_digest: imported.artifact_digest,
        snapshot_digest: imported.target_snapshot_digest,
        import_digest: imported.import_digest,
        owner_affinity,
    })
}

fn fresh_validate_v0(path: &Path, config: &NativeApplicationConfigV0) -> DurableResult<MetadataV0> {
    reject_sqlite_sidecars_v0(path)?;
    let connection = open_immutable_connection_v0(path)?;
    verify_schema_v0(&connection)?;
    let metadata = load_metadata_v0(&connection, config)?;
    validate_metadata_v0(&connection, config, &metadata)?;
    Ok(metadata)
}

fn fresh_validate_p_v0(
    path: &Path,
    config: &NativeApplicationConfigV0,
    expected: &DurablePV0,
) -> DurableResult<()> {
    let actual = fresh_load_p_by_block_v0(path, expected.block_id)?;
    validate_p_v0(config, &actual)?;
    if actual.p_digest != expected.p_digest {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            "p.fresh_exact",
        ));
    }
    validate_target_snapshot_v0(config, &actual)
}

fn fresh_load_p_by_block_v0(path: &Path, block_id: [u8; 32]) -> DurableResult<DurablePV0> {
    reject_sqlite_sidecars_v0(path)?;
    let connection = open_immutable_connection_v0(path)?;
    verify_schema_v0(&connection)?;
    load_p_by_block_v0(&connection, block_id)?.ok_or_else(|| {
        error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            "p.fresh_missing",
        )
    })
}

fn load_metadata_v0(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
) -> DurableResult<MetadataV0> {
    let row: MetadataSqlRowV0 = connection
        .query_row(
            "SELECT schema_version,store_id,chain_id,genesis_hash,chain_descriptor_hash,signer_policy_commitment,validator_set_id,parameters_hash,durable_sequence,head_height,head_block_id,head_state_root,head_commit_id,authenticated_snapshot,authenticated_snapshot_digest,replay_command_ids,replay_signer_nonces FROM native_application_metadata_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?,row.get(16)?)),
        )
        .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::Storage, "metadata.query"))?;
    if decode_u64_v0(&row.0, "metadata.schema")? != APPLICATION_SCHEMA_VERSION_V0
        || array32_v0(&row.1, "metadata.store_id")? != config.store_id
        || row.2 != config.chain_id
        || array32_v0(&row.3, "metadata.genesis")? != config.genesis_hash
        || array32_v0(&row.4, "metadata.descriptor")? != config.chain_descriptor_hash
        || array32_v0(&row.5, "metadata.signer_policy")? != config.signer_policy_commitment
        || array32_v0(&row.6, "metadata.validator_set")? != *config.validator_set.id().as_bytes()
        || array32_v0(&row.7, "metadata.parameters")? != *config.parameters.hash().as_bytes()
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::BindingMismatch,
            "metadata.config",
        ));
    }
    Ok(MetadataV0 {
        durable_sequence: decode_u64_v0(&row.8, "metadata.sequence")?,
        head: ApplicationHeadV0::new(
            HeightV0::new(decode_u64_v0(&row.9, "metadata.height")?),
            BlockIdV0::new(array32_v0(&row.10, "metadata.block")?).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "metadata.block",
                )
            })?,
            StateRootV0::new(array32_v0(&row.11, "metadata.root")?).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "metadata.root",
                )
            })?,
            ApplicationCommitIdV0::new(array32_v0(&row.12, "metadata.commit")?).map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "metadata.commit",
                )
            })?,
        ),
        snapshot: row.13,
        snapshot_digest: array32_v0(&row.14, "metadata.snapshot_digest")?,
        command_ids: decode_borsh_v0(&row.15, "metadata.commands")?,
        signer_nonces: decode_borsh_v0(&row.16, "metadata.nonces")?,
    })
}

fn load_h1_state_sync_trusted_base_v0(
    connection: &Connection,
) -> DurableResult<Option<H1StateSyncTrustedBaseV0>> {
    let row = connection
        .query_row(
            "SELECT store_id,install_sequence,proof_id,artifact,artifact_digest,
                    target_snapshot_digest,target_commit_id,import_digest
             FROM native_h1_state_sync_trusted_base_v0 WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "h1_state_sync.query",
            )
        })?;
    row.map(|row| {
        Ok(H1StateSyncTrustedBaseV0 {
            store_id: array32_v0(&row.0, "h1_state_sync.store_id")?,
            install_sequence: decode_u64_v0(&row.1, "h1_state_sync.sequence")?,
            proof_id: array32_v0(&row.2, "h1_state_sync.proof_id")?,
            artifact: row.3,
            artifact_digest: array32_v0(&row.4, "h1_state_sync.artifact_digest")?,
            target_snapshot_digest: array32_v0(&row.5, "h1_state_sync.snapshot_digest")?,
            target_commit_id: array32_v0(&row.6, "h1_state_sync.commit_id")?,
            import_digest: array32_v0(&row.7, "h1_state_sync.import_digest")?,
        })
    })
    .transpose()
}

fn load_p_by_block_v0(
    connection: &Connection,
    block_id: [u8; 32],
) -> DurableResult<Option<DurablePV0>> {
    let row = connection
        .query_row(
            "SELECT target_height,store_id,p_sequence,status,parent_height,parent_block_id,parent_state_root,parent_commit_id,block_id,artifact,artifact_digest,target_snapshot,target_snapshot_digest,target_replay_command_ids,target_replay_signer_nonces,target_lifecycle_json,p_digest,commit_sequence,commit_id FROM native_durable_execution_p_v0 WHERE block_id=?",
            params![block_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?, row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?, row.get::<_, Vec<u8>>(10)?, row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?, row.get::<_, Vec<u8>>(13)?, row.get::<_, Vec<u8>>(14)?,
                    row.get::<_, Vec<u8>>(15)?, row.get::<_, Vec<u8>>(16)?, row.get::<_, Option<Vec<u8>>>(17)?,
                    row.get::<_, Option<Vec<u8>>>(18)?,
                ))
            },
        )
        .optional()
        .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::Storage, "p.query"))?;
    row.map(|row| {
        Ok(DurablePV0 {
            target_height: decode_u64_v0(&row.0, "p.target_height")?,
            store_id: array32_v0(&row.1, "p.store_id")?,
            p_sequence: decode_u64_v0(&row.2, "p.sequence")?,
            status: decode_u64_v0(&row.3, "p.status")?,
            parent_height: decode_u64_v0(&row.4, "p.parent_height")?,
            parent_block_id: array32_v0(&row.5, "p.parent_block")?,
            parent_state_root: array32_v0(&row.6, "p.parent_root")?,
            parent_commit_id: array32_v0(&row.7, "p.parent_commit")?,
            block_id: array32_v0(&row.8, "p.block")?,
            artifact: row.9,
            artifact_digest: array32_v0(&row.10, "p.artifact_digest")?,
            target_snapshot: row.11,
            target_snapshot_digest: array32_v0(&row.12, "p.snapshot_digest")?,
            target_command_bytes: row.13,
            target_nonce_bytes: row.14,
            lifecycle_json: row.15,
            p_digest: array32_v0(&row.16, "p.digest")?,
            commit_sequence: row
                .17
                .as_deref()
                .map(|value| decode_u64_v0(value, "p.commit_sequence"))
                .transpose()?,
            commit_id: row
                .18
                .as_deref()
                .map(|value| array32_v0(value, "p.commit_id"))
                .transpose()?,
        })
    })
    .transpose()
}

fn load_p_by_height_v0(
    connection: &Connection,
    target_height: u64,
) -> DurableResult<Option<DurablePV0>> {
    let mut statement = connection
        .prepare("SELECT block_id FROM native_durable_execution_p_v0 WHERE target_height=?")
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "p.height_prepare",
            )
        })?;
    let block_ids = statement
        .query_map(params![u64_bytes_v0(target_height).as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "p.height_query",
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "p.height_rows",
            )
        })?;
    if block_ids.len() > 1 {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.height_duplicate",
        ));
    }
    let Some(bytes) = block_ids.into_iter().next() else {
        return Ok(None);
    };
    let block_id = array32_v0(&bytes, "p.height_block")?;
    load_p_by_block_v0(connection, block_id)
}

fn load_all_p_v0(connection: &Connection) -> DurableResult<Vec<DurablePV0>> {
    let mut statement = connection
        .prepare("SELECT block_id FROM native_durable_execution_p_v0 ORDER BY p_sequence ASC")
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "p.inventory_prepare",
            )
        })?;
    let block_ids = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "p.inventory_query",
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "p.inventory_rows",
            )
        })?;
    block_ids
        .into_iter()
        .map(|bytes| {
            let block_id = array32_v0(&bytes, "p.inventory_block")?;
            load_p_by_block_v0(connection, block_id)?.ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "p.inventory_missing",
                )
            })
        })
        .collect()
}

fn prepared_blocks_not_descending_from_v0(
    connection: &Connection,
    finalized_block_id: [u8; 32],
) -> DurableResult<Vec<[u8; 32]>> {
    let rows = load_all_p_v0(connection)?;
    let by_block = rows
        .iter()
        .map(|p| (p.block_id, p))
        .collect::<BTreeMap<_, _>>();
    let mut pruned = Vec::new();
    for p in rows
        .iter()
        .filter(|candidate| candidate.status == P_STATUS_PREPARED)
    {
        let mut cursor = p;
        let mut descends = cursor.block_id == finalized_block_id;
        for _ in 0..=rows.len() {
            if descends {
                break;
            }
            let Some(parent) = by_block.get(&cursor.parent_block_id) else {
                break;
            };
            cursor = parent;
            descends = cursor.block_id == finalized_block_id;
        }
        if !descends {
            pruned.push(p.block_id);
        }
    }
    Ok(pruned)
}

fn count_prepared_p_v0(connection: &Connection) -> DurableResult<u64> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM native_durable_execution_p_v0 WHERE status=?",
            params![u64_bytes_v0(P_STATUS_PREPARED).as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::Storage, "p.count"))?;
    u64::try_from(count).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "p.count_range",
        )
    })
}

fn metadata_exists_v0(connection: &Connection) -> DurableResult<bool> {
    connection
        .query_row(
            "SELECT 1 FROM native_application_metadata_v0 WHERE singleton=1",
            [],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "metadata.exists",
            )
        })
}

/// A schema-valid file with no metadata singleton is only a virgin store when
/// both data tables are empty.  Without this check, a deleted metadata row
/// could make residual prepared/TrustedBase state look like a fresh genesis
/// and let `initialize` overwrite the authenticated inventory boundary.
fn validate_virgin_inventory_v0(connection: &Connection) -> DurableResult<()> {
    let p_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM native_durable_execution_p_v0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "metadata.virgin_p_inventory",
            )
        })?;
    let h1_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM native_h1_state_sync_trusted_base_v0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "metadata.virgin_h1_inventory",
            )
        })?;
    if p_count != 0 || h1_count != 0 {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "metadata.missing_inventory",
        ));
    }
    Ok(())
}

fn initialize_schema_v0(connection: &Connection) -> DurableResult<()> {
    connection
        .execute_batch(&format!(
            "PRAGMA foreign_keys=ON;{};{};{};",
            EXPECTED_SCHEMA_V0[0].1, EXPECTED_SCHEMA_V0[1].1, EXPECTED_SCHEMA_V0[2].1
        ))
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "schema.initialize",
            )
        })
}

fn verify_schema_v0(connection: &Connection) -> DurableResult<()> {
    let mut statement = connection
        .prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")
        .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::Storage, "schema.prepare"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "schema.query",
            )
        })?;
    let mut actual = Vec::new();
    for row in rows {
        let (kind, name, sql) =
            row.map_err(|_| error(NativeApplicationExecutionErrorCodeV0::Storage, "schema.row"))?;
        if kind != "table" {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "schema.object_type",
            ));
        }
        actual.push((
            name,
            normalize_sql_v0(&sql.ok_or_else(|| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CorruptStore,
                    "schema.sql",
                )
            })?),
        ));
    }
    let expected = EXPECTED_SCHEMA_V0
        .iter()
        .map(|(name, sql)| ((*name).to_string(), normalize_sql_v0(sql)))
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CorruptStore,
            "schema.exact",
        ));
    }
    Ok(())
}

fn normalize_sql_v0(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn open_writable_connection_v0(path: &Path) -> DurableResult<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::Storage,
            "connection.open",
        )
    })?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "connection.timeout",
            )
        })?;
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "connection.journal",
            )
        })?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "connection.sync",
            )
        })?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "connection.foreign_keys",
            )
        })?;
    Ok(connection)
}

#[cfg(unix)]
fn open_immutable_connection_v0(path: &Path) -> DurableResult<Connection> {
    use std::{fmt::Write as _, os::unix::ffi::OsStrExt};
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'.' | b'_' | b'~' => {
                uri.push(char::from(*byte))
            }
            value => write!(&mut uri, "%{value:02X}").expect("String writes cannot fail"),
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Connection::open_with_flags(
        Path::new(&uri),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::Storage,
            "connection.immutable",
        )
    })
}

#[cfg(not(unix))]
fn open_immutable_connection_v0(path: &Path) -> DurableResult<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::Storage,
            "connection.read_only",
        )
    })
}

fn sqlite_auxiliary_path_v0(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn sqlite_sidecars_present_v0(path: &Path) -> DurableResult<bool> {
    for suffix in ["-journal", "-wal", "-shm"] {
        match sqlite_auxiliary_path_v0(path, suffix).symlink_metadata() {
            Ok(_) => return Ok(true),
            Err(value) if value.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::Storage,
                    "sqlite.sidecar_metadata",
                ))
            }
        }
    }
    Ok(false)
}

/// Performs the one safe startup repair that SQLite itself can provide after a
/// process dies with a hot rollback journal. WAL/SHM images are intentionally
/// not auto-recovered: they require a separate checkpoint/state-sync owner.
/// The metadata page is dirtied and restored in one transaction so SQLite
/// rolls back the hot journal and removes it atomically. For the strict virgin
/// pre-genesis case, the SQLite header is toggled and restored instead because
/// no metadata singleton exists yet. All canonical store validation still runs
/// on the immutable connection afterwards.
fn recover_sqlite_rollback_journal_v0(path: &Path) -> DurableResult<()> {
    let journal_path = sqlite_auxiliary_path_v0(path, "-journal");
    let wal_path = sqlite_auxiliary_path_v0(path, "-wal");
    let shm_path = sqlite_auxiliary_path_v0(path, "-shm");
    if wal_path.exists() || shm_path.exists() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            "sqlite.wal_sidecar",
        ));
    }
    let journal_metadata = journal_path.symlink_metadata().map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            "sqlite.journal_metadata",
        )
    })?;
    if !journal_metadata.file_type().is_file()
        || journal_metadata.file_type().is_symlink()
        || journal_metadata.len() < 512
    {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            "sqlite.journal_unverifiable",
        ));
    }

    let mut connection = open_writable_connection_v0(path)?;
    verify_schema_v0(&connection)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "sqlite.journal_recovery_transaction",
            )
        })?;
    let original: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT durable_sequence FROM native_application_metadata_v0
             WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "sqlite.journal_recovery_metadata",
            )
        })?;
    let Some(original) = original else {
        // A process can die during the very first genesis INSERT, before the
        // metadata singleton exists. SQLite has already rolled the hot
        // journal back while opening this writable connection; accept that
        // state only when every canonical data table is still truly virgin.
        // A missing metadata row alongside any P or H1 row is a mixed/corrupt
        // cut and must never be normalized into a fresh store.
        let p_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM native_durable_execution_p_v0",
                [],
                |row| row.get(0),
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                    "sqlite.journal_recovery_inventory",
                )
            })?;
        let h1_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM native_h1_state_sync_trusted_base_v0",
                [],
                |row| row.get(0),
            )
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                    "sqlite.journal_recovery_inventory",
                )
            })?;
        if p_count != 0 || h1_count != 0 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "sqlite.journal_recovery_inventory",
            ));
        }
        // Force SQLite to complete the hot-journal rollback/cleanup even
        // though the virgin store has no metadata row that can be toggled.
        // `user_version` is outside the authenticated schema; restore its
        // exact prior value in the same transaction before releasing it.
        let user_version: u32 = transaction
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                    "sqlite.journal_recovery_header",
                )
            })?;
        let temporary_user_version = if user_version == u32::MAX {
            0
        } else {
            user_version + 1
        };
        transaction
            .execute(
                &format!("PRAGMA user_version = {temporary_user_version}"),
                [],
            )
            .and_then(|_| transaction.execute(&format!("PRAGMA user_version = {user_version}"), []))
            .map_err(|_| {
                error(
                    NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                    "sqlite.journal_recovery_header",
                )
            })?;
        transaction.commit().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "sqlite.journal_recovery_commit",
            )
        })?;
        drop(connection);
        sync_store_commit_boundary_v0(path)?;
        if journal_path.exists() {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "sqlite.journal_persisted",
            ));
        }
        return Ok(());
    };
    let temporary = if original == vec![0xff_u8; 8] {
        vec![0_u8; 8]
    } else {
        vec![0xff_u8; 8]
    };
    transaction
        .execute(
            "UPDATE native_application_metadata_v0 SET durable_sequence=?1
             WHERE singleton=1",
            params![temporary],
        )
        .and_then(|_| {
            transaction.execute(
                "UPDATE native_application_metadata_v0 SET durable_sequence=?1
                 WHERE singleton=1",
                params![original],
            )
        })
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                "sqlite.journal_recovery_write",
            )
        })?;
    transaction.commit().map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            "sqlite.journal_recovery_commit",
        )
    })?;
    sync_store_commit_boundary_v0(path)?;
    if journal_path.exists() {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            "sqlite.journal_persisted",
        ));
    }
    Ok(())
}

fn reject_sqlite_sidecars_v0(path: &Path) -> DurableResult<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        match sqlite_auxiliary_path_v0(path, suffix).symlink_metadata() {
            Ok(_) => {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                    "sqlite.sidecar",
                ))
            }
            Err(value) if value.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::Storage,
                    "sqlite.sidecar_metadata",
                ))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncStoreCommitBoundaryFaultPointV0 {
    Database,
    Directory,
}

#[cfg(test)]
static SYNC_STORE_COMMIT_BOUNDARY_FAULT_V0: Mutex<
    Option<(PathBuf, SyncStoreCommitBoundaryFaultPointV0)>,
> = Mutex::new(None);

#[cfg(test)]
fn sync_store_commit_boundary_fault_lock_v0(
) -> std::sync::MutexGuard<'static, Option<(PathBuf, SyncStoreCommitBoundaryFaultPointV0)>> {
    SYNC_STORE_COMMIT_BOUNDARY_FAULT_V0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
#[must_use = "the fault guard clears an armed sync fault on scope exit"]
struct SyncStoreCommitBoundaryFaultGuardV0 {
    path: PathBuf,
    point: SyncStoreCommitBoundaryFaultPointV0,
}

#[cfg(test)]
impl Drop for SyncStoreCommitBoundaryFaultGuardV0 {
    fn drop(&mut self) {
        let mut fault = sync_store_commit_boundary_fault_lock_v0();
        if fault.as_ref().is_some_and(|(path, point)| {
            path.as_path() == self.path.as_path() && *point == self.point
        }) {
            *fault = None;
        }
    }
}

#[cfg(test)]
fn arm_sync_store_commit_boundary_fault_v0(
    path: &Path,
    point: SyncStoreCommitBoundaryFaultPointV0,
) -> SyncStoreCommitBoundaryFaultGuardV0 {
    let mut fault = sync_store_commit_boundary_fault_lock_v0();
    assert!(
        fault.is_none(),
        "another sync boundary fault is already armed"
    );
    *fault = Some((path.to_path_buf(), point));
    SyncStoreCommitBoundaryFaultGuardV0 {
        path: path.to_path_buf(),
        point,
    }
}

#[cfg(test)]
fn consume_sync_store_commit_boundary_fault_v0(
    path: &Path,
    point: SyncStoreCommitBoundaryFaultPointV0,
) -> bool {
    let mut fault = sync_store_commit_boundary_fault_lock_v0();
    let matches = fault.as_ref().is_some_and(|(armed_path, armed_point)| {
        armed_path.as_path() == path && *armed_point == point
    });
    if matches {
        *fault = None;
    }
    matches
}

/// Flushes the commit image and its directory entry before the caller does a
/// fresh-connection readback.  SQLite already runs in `synchronous=FULL`
/// mode; the explicit file/directory sync closes the remaining host durability
/// boundary (journal rename and directory metadata) without pretending that a
/// local filesystem is an external anti-rollback authority.
fn sync_store_commit_boundary_v0(path: &Path) -> DurableResult<()> {
    sync_store_commit_boundary_named_v0(path, "commit.fsync", "commit.directory_fsync")
}

fn sync_store_commit_boundary_named_v0(
    path: &Path,
    database_field: &'static str,
    directory_field: &'static str,
) -> DurableResult<()> {
    let database = OpenOptions::new().read(true).open(path).map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            database_field,
        )
    })?;
    #[cfg(test)]
    if consume_sync_store_commit_boundary_fault_v0(
        path,
        SyncStoreCommitBoundaryFaultPointV0::Database,
    ) {
        return Err(error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            database_field,
        ));
    }
    database.sync_all().map_err(|_| {
        error(
            NativeApplicationExecutionErrorCodeV0::CommitUncertain,
            database_field,
        )
    })?;

    #[cfg(unix)]
    {
        let parent = path.parent().ok_or_else(|| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                directory_field,
            )
        })?;
        let directory = File::open(parent).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                directory_field,
            )
        })?;
        #[cfg(test)]
        if consume_sync_store_commit_boundary_fault_v0(
            path,
            SyncStoreCommitBoundaryFaultPointV0::Directory,
        ) {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                directory_field,
            ));
        }
        directory.sync_all().map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CommitUncertain,
                directory_field,
            )
        })?;
    }

    Ok(())
}

/// Test-only crash injector used by the subprocess SIGKILL matrix below. It
/// is compiled out of every non-test build and therefore cannot become a
/// runtime control surface. The parent process kills the child while it is
/// parked at one exact SQLite boundary, then reopens the store and validates
/// the only two legal outcomes (pre-commit P or fully committed head).
#[cfg(test)]
fn park_for_sigkill_commit_boundary_v0(stage: &str) {
    const STAGE_ENV: &str = "TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE";
    const MARKER_ENV: &str = "TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER";
    let Ok(expected) = std::env::var(STAGE_ENV) else {
        return;
    };
    if expected != stage {
        return;
    }
    let marker = std::env::var(MARKER_ENV).expect("SIGKILL test marker is set");
    fs::write(marker, stage.as_bytes()).expect("write SIGKILL test marker");
    loop {
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn prepare_store_file_v0(path: &Path) -> DurableResult<(PathBuf, bool)> {
    let name = path.file_name().ok_or_else(|| {
        error(
            NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
            "store.file_name",
        )
    })?;
    let parent =
        fs::canonicalize(path.parent().unwrap_or_else(|| Path::new("."))).map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "store.parent",
            )
        })?;
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(error(
                    NativeApplicationExecutionErrorCodeV0::ReplacedStore,
                    "store.file_type",
                ));
            }
            Ok((path, false))
        }
        Err(value) if value.kind() == std::io::ErrorKind::NotFound => {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_| {
                    error(
                        NativeApplicationExecutionErrorCodeV0::Storage,
                        "store.create",
                    )
                })?;
            Ok((path, true))
        }
        Err(_) => Err(error(
            NativeApplicationExecutionErrorCodeV0::Storage,
            "store.metadata",
        )),
    }
}

fn lock_path_v0(path: &Path) -> DurableResult<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        error(
            NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
            "lock.file_name",
        )
    })?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

fn sha256_v0(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn u64_bytes_v0(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64_v0(bytes: &[u8], field: &'static str) -> DurableResult<u64> {
    let value: [u8; 8] = bytes
        .try_into()
        .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::CorruptStore, field))?;
    Ok(u64::from_be_bytes(value))
}

fn array32_v0(bytes: &[u8], field: &'static str) -> DurableResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::CorruptStore, field))
}

fn encode_borsh_v0<T: BorshSerialize>(value: &T, field: &'static str) -> DurableResult<Vec<u8>> {
    borsh::to_vec(value)
        .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::CorruptStore, field))
}

fn decode_borsh_v0<T: BorshDeserialize>(bytes: &[u8], field: &'static str) -> DurableResult<T> {
    borsh::from_slice(bytes)
        .map_err(|_| error(NativeApplicationExecutionErrorCodeV0::CorruptStore, field))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::{process::Command, thread, time::Instant};
    use tempfile::TempDir;
    use trnm_consensus_types::{
        BlockHeader, BlockId, BlockKind, CertifiedHeaderV0, ChainId, ConsensusPublicKey, Epoch,
        EvidenceRoot, FinalityProofV0, GenesisQcV0, Height, PayloadDigest, ProposalWitnessV0,
        ProtocolVersion, QcReferenceV0, QuorumCertificate, ReceiptsRoot, Signature64,
        SignatureBytes, StateRoot, Validator, ValidatorId, View, Vote, VotingPower,
    };
    use trnm_finality_types::{crypto::public_key_hex, SignedCommandEnvelopeV1};
    use trnm_native_application::{
        ChainIdV0, GenesisHashV0, NativeApplicationRecoveryRequestV0, NativeBlockExecutionResultV0,
        NativeExecutionReceiptV0, NativeExpectedBlockCommitmentsV0, NativeRecoveryDispositionV0,
        NativeRecoveryWatermarksV0, NativeStateProofRequestV0,
    };
    use trnm_protocol::{
        account_key, CanonicalCommandV1, CanonicalTxV1, CANONICAL_TX_PAYLOAD_TYPE_V1,
        CANONICAL_TX_SCHEMA_V1,
    };

    use super::*;
    use crate::{
        complete::{compute_complete_native_block_v0, ComputedCompleteExecutionV0},
        stored_object_key_v0,
        validator_lifecycle::{
            ConsensusValidatorV1, ValidatorGovernanceV1, ValidatorLifecycleStateV1,
            VALIDATOR_GOVERNANCE_SCHEMA_V1,
        },
    };

    const CHAIN: &str = "trnm-native-durable-test";
    const GENESIS: [u8; 32] = [7; 32];
    const DESCRIPTOR: [u8; 32] = [8; 32];
    const INITIAL_BLOCK: [u8; 32] = [9; 32];
    const INITIAL_COMMIT: [u8; 32] = [10; 32];
    const STORE_A: [u8; 32] = [11; 32];
    const STORE_FINALITY: [u8; 32] = [13; 32];

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn application_signers() -> Vec<AuthorizedSignerV0> {
        vec![
            AuthorizedSignerV0::new(
                "did:operator:1",
                "operator",
                public_key_hex(&signing_key(81)),
            )
            .unwrap(),
            AuthorizedSignerV0::new("did:client:1", "hepta", public_key_hex(&signing_key(82)))
                .unwrap(),
        ]
    }

    fn consensus_set(parameters: &ConsensusParametersV0) -> ValidatorSet {
        let validators = (0u8..4)
            .map(|index| {
                let key = signing_key(20 + index).verifying_key().to_bytes();
                Validator::new(
                    ValidatorId::from_bytes(format!("validator-{index}").as_bytes()).unwrap(),
                    ConsensusPublicKey::new(key),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        ValidatorSet::new(
            GenesisHash::new(GENESIS),
            ChainId::new(CHAIN).unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap()
    }

    fn structurally_valid_finality_proof_v0(
        set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
    ) -> FinalityProofV0 {
        fn qc_for(set: &ValidatorSet, header: &BlockHeader) -> QuorumCertificate {
            let votes = set
                .validators()
                .iter()
                .take(3)
                .map(|validator| {
                    Vote::new(
                        set.chain_id(),
                        set.protocol_version(),
                        set.epoch(),
                        header.view(),
                        header.height(),
                        header.id(),
                        set.id(),
                        validator.id(),
                        SignatureBytes::from_array([1; 64]),
                        set,
                    )
                    .unwrap()
                })
                .collect();
            QuorumCertificate::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                header.view(),
                header.height(),
                header.id(),
                set.id(),
                votes,
                set,
            )
            .unwrap()
        }

        let parent_timestamp_ms = 1_700_000_000_000;
        let genesis_qc = GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap();
        let h1 = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            BlockKind::Regular,
            BlockId::new(GENESIS),
            set.validators()[0].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([0x31; 32]),
            StateRoot::new([0x32; 32]),
            ReceiptsRoot::new([0x33; 32]),
            EvidenceRoot::new([0x34; 32]),
            parent_timestamp_ms + 1,
            None,
        )
        .unwrap();
        let qc1 = qc_for(set, &h1);
        let c1 = CertifiedHeaderV0::new(
            h1.clone(),
            QcReferenceV0::genesis_anchor(genesis_qc),
            None,
            None,
            Signature64::from_array([2; 64]),
            qc1.clone(),
            set,
            None,
            parameters,
            parent_timestamp_ms,
        )
        .unwrap();

        let h2 = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            Height::new(2),
            BlockKind::Regular,
            h1.id(),
            set.validators()[1].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([0x41; 32]),
            StateRoot::new([0x42; 32]),
            ReceiptsRoot::new([0x43; 32]),
            EvidenceRoot::new([0x44; 32]),
            parent_timestamp_ms + 2,
            None,
        )
        .unwrap();
        let qc2 = qc_for(set, &h2);
        let c2 = CertifiedHeaderV0::new(
            h2.clone(),
            QcReferenceV0::ordinary(qc1),
            None,
            None,
            Signature64::from_array([3; 64]),
            qc2.clone(),
            set,
            None,
            parameters,
            h1.timestamp_ms(),
        )
        .unwrap();

        let h3 = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(3),
            Height::new(3),
            BlockKind::Regular,
            h2.id(),
            set.validators()[2].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([0x51; 32]),
            StateRoot::new([0x52; 32]),
            ReceiptsRoot::new([0x53; 32]),
            EvidenceRoot::new([0x54; 32]),
            parent_timestamp_ms + 3,
            None,
        )
        .unwrap();
        let qc3 = qc_for(set, &h3);
        let c3 = CertifiedHeaderV0::new(
            h3,
            QcReferenceV0::ordinary(qc2),
            None,
            None,
            Signature64::from_array([4; 64]),
            qc3,
            set,
            None,
            parameters,
            h2.timestamp_ms(),
        )
        .unwrap();
        FinalityProofV0::new(c1, c2, c3, set, None, parameters, parent_timestamp_ms).unwrap()
    }

    fn header_for_execution_v0(
        execution: &NativeBlockExecutionRequestV0,
        set: &ValidatorSet,
        view: u64,
        timestamp_ms: u64,
    ) -> BlockHeader {
        let expected = execution.expected();
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(execution.height().get()),
            BlockKind::Regular,
            BlockId::new(*execution.parent().block_id().as_bytes()),
            set.validators()[(view.saturating_sub(1) as usize) % set.validators().len()].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new(*expected.payload_root().as_bytes()),
            StateRoot::new(*expected.post_state_root().as_bytes()),
            ReceiptsRoot::new(*expected.receipts_root().as_bytes()),
            EvidenceRoot::new(*expected.evidence_root().as_bytes()),
            timestamp_ms,
            None,
        )
        .unwrap()
    }

    /// Build the smallest strict-Ed25519 three-chain that can carry one
    /// application execution header.  The native application deliberately
    /// does not manufacture this proof; this helper is test-only evidence that
    /// the finalized-commit adapter consumes the same authenticated proposal
    /// and QC objects as the consensus verifier.
    fn signed_finality_proof_for_execution_v0(
        execution: &NativeBlockExecutionRequestV0,
        set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> FinalityProofV0 {
        fn consensus_key(index: usize) -> SigningKey {
            signing_key(20 + index as u8)
        }

        fn signed_qc_for_coordinates(
            set: &ValidatorSet,
            view: View,
            height: Height,
            block_id: BlockId,
        ) -> QuorumCertificate {
            let votes = set
                .validators()
                .iter()
                .take(3)
                .enumerate()
                .map(|(index, validator)| {
                    let root = Vote::signing_root_for_set(set, view, height, block_id).unwrap();
                    let signature = SignatureBytes::from_array(
                        consensus_key(index).sign(root.as_bytes()).to_bytes(),
                    );
                    Vote::new(
                        set.chain_id(),
                        set.protocol_version(),
                        set.epoch(),
                        view,
                        height,
                        block_id,
                        set.id(),
                        validator.id(),
                        signature,
                        set,
                    )
                    .unwrap()
                })
                .collect();
            QuorumCertificate::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                view,
                height,
                block_id,
                set.id(),
                votes,
                set,
            )
            .unwrap()
        }

        fn signed_qc(set: &ValidatorSet, header: &BlockHeader) -> QuorumCertificate {
            signed_qc_for_coordinates(set, header.view(), header.height(), header.id())
        }

        fn certified(
            header: BlockHeader,
            justify: QcReferenceV0,
            qc: QuorumCertificate,
            set: &ValidatorSet,
            parameters: &ConsensusParametersV0,
            authenticated_parent_timestamp_ms: u64,
        ) -> CertifiedHeaderV0 {
            let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
            let proposer_index = set
                .validators()
                .iter()
                .position(|validator| validator.id() == header.proposer_id())
                .unwrap();
            let signature = Signature64::from_array(
                consensus_key(proposer_index)
                    .sign(root.as_bytes())
                    .to_bytes(),
            );
            CertifiedHeaderV0::new(
                header,
                justify,
                None,
                None,
                signature,
                qc,
                set,
                None,
                parameters,
                authenticated_parent_timestamp_ms,
            )
            .unwrap()
        }

        let first_view = execution.height().get();
        let h1 = header_for_execution_v0(execution, set, first_view, execution.timestamp_ms());
        assert_eq!(h1.id().as_bytes(), execution.block_id().as_bytes());
        let q1 = signed_qc(set, &h1);
        let first_justify = if execution.height().get() == 1 {
            QcReferenceV0::genesis_anchor(
                GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap(),
            )
        } else {
            let parent_height = execution.parent().height();
            let parent_view = View::new(
                first_view
                    .checked_sub(1)
                    .expect("execution proof parent view"),
            );
            let parent_block_id = BlockId::new(*execution.parent().block_id().as_bytes());
            QcReferenceV0::ordinary(signed_qc_for_coordinates(
                set,
                parent_view,
                Height::new(parent_height.get()),
                parent_block_id,
            ))
        };
        let c1 = certified(
            h1.clone(),
            first_justify,
            q1.clone(),
            set,
            parameters,
            authenticated_parent_timestamp_ms,
        );

        let h2_height = execution
            .height()
            .get()
            .checked_add(1)
            .expect("execution proof second height");
        let h2 = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(
                first_view
                    .checked_add(1)
                    .expect("execution proof second view"),
            ),
            Height::new(h2_height),
            BlockKind::Regular,
            h1.id(),
            set.validators()[(first_view as usize) % set.validators().len()].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([0x61; 32]),
            StateRoot::new([0x62; 32]),
            ReceiptsRoot::new([0x63; 32]),
            EvidenceRoot::new([0x64; 32]),
            execution.timestamp_ms() + 1,
            None,
        )
        .unwrap();
        let q2 = signed_qc(set, &h2);
        let c2 = certified(
            h2.clone(),
            QcReferenceV0::ordinary(q1),
            q2.clone(),
            set,
            parameters,
            h1.timestamp_ms(),
        );

        let h3_height = h2_height
            .checked_add(1)
            .expect("execution proof third height");
        let h3 = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(
                first_view
                    .checked_add(2)
                    .expect("execution proof third view"),
            ),
            Height::new(h3_height),
            BlockKind::Regular,
            h2.id(),
            set.validators()[((first_view + 1) as usize) % set.validators().len()].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([0x71; 32]),
            StateRoot::new([0x72; 32]),
            ReceiptsRoot::new([0x73; 32]),
            EvidenceRoot::new([0x74; 32]),
            execution.timestamp_ms() + 2,
            None,
        )
        .unwrap();
        let q3 = signed_qc(set, &h3);
        let c3 = certified(
            h3,
            QcReferenceV0::ordinary(q2),
            q3,
            set,
            parameters,
            h2.timestamp_ms(),
        );

        let proof = FinalityProofV0::new(
            c1,
            c2,
            c3,
            set,
            None,
            parameters,
            authenticated_parent_timestamp_ms,
        )
        .unwrap();
        proof
            .verify(
                set,
                None,
                parameters,
                authenticated_parent_timestamp_ms,
                &trnm_consensus_crypto::StrictEd25519Verifier,
            )
            .unwrap();
        proof
    }

    fn canonical_lab_inputs(
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
        local_validator: ValidatorId,
        run_id: &str,
        topology: [u8; 32],
        candidate_source: [u8; 32],
        application_signers: Vec<AuthorizedSignerV0>,
    ) -> CanonicalLabNativeApplicationConfigInputsV0 {
        CanonicalLabNativeApplicationConfigInputsV0::new(
            run_id,
            [0x91; 32],
            topology,
            [0x93; 32],
            candidate_source,
            local_validator,
            validator_set,
            parameters,
            application_signers,
            "did:operator:1",
        )
        .unwrap()
    }

    #[test]
    fn canonical_lab_config_keeps_chain_identity_common_and_store_identity_local_v0() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = consensus_set(&parameters);
        let first = set.validators()[0].id();
        let second = set.validators()[1].id();
        let config_a =
            NativeApplicationConfigV0::from_canonical_lab_inputs_v0(canonical_lab_inputs(
                set.clone(),
                parameters,
                first,
                "g3-7-equal-run-001",
                [0x92; 32],
                [0x94; 32],
                application_signers(),
            ))
            .unwrap();
        let mut reversed_signers = application_signers();
        reversed_signers.reverse();
        let config_b =
            NativeApplicationConfigV0::from_canonical_lab_inputs_v0(canonical_lab_inputs(
                set.clone(),
                parameters,
                second,
                "g3-7-equal-run-001",
                [0x92; 32],
                [0x94; 32],
                reversed_signers,
            ))
            .unwrap();
        let config_redeployed =
            NativeApplicationConfigV0::from_canonical_lab_inputs_v0(canonical_lab_inputs(
                set.clone(),
                parameters,
                first,
                "g3-7-equal-run-001",
                [0xa2; 32],
                [0x94; 32],
                application_signers(),
            ))
            .unwrap();
        let config_rerun =
            NativeApplicationConfigV0::from_canonical_lab_inputs_v0(canonical_lab_inputs(
                set.clone(),
                parameters,
                first,
                "g3-7-equal-run-002",
                [0x92; 32],
                [0x94; 32],
                application_signers(),
            ))
            .unwrap();
        let config_rebuilt =
            NativeApplicationConfigV0::from_canonical_lab_inputs_v0(canonical_lab_inputs(
                set,
                parameters,
                first,
                "g3-7-equal-run-001",
                [0x92; 32],
                [0xa4; 32],
                application_signers(),
            ))
            .unwrap();

        assert_eq!(
            config_a.initial_block_id_v0(),
            *config_a.validator_set_v0().genesis_hash().as_bytes()
        );

        for other in [
            &config_b,
            &config_redeployed,
            &config_rerun,
            &config_rebuilt,
        ] {
            assert_eq!(
                config_a.chain_descriptor_hash_v0(),
                other.chain_descriptor_hash_v0()
            );
            assert_eq!(
                config_a.signer_policy_commitment_v0(),
                other.signer_policy_commitment_v0()
            );
            assert_eq!(config_a.initial_block_id_v0(), other.initial_block_id_v0());
            assert_eq!(
                config_a.initial_commit_id_v0(),
                other.initial_commit_id_v0()
            );
            assert_eq!(config_a.initial_state_root(), other.initial_state_root());
        }
        assert_ne!(config_a.store_id(), config_b.store_id());
        assert_ne!(config_a.store_id(), config_redeployed.store_id());
        assert_ne!(config_a.store_id(), config_rerun.store_id());
        assert_ne!(config_a.store_id(), config_rebuilt.store_id());
    }

    #[test]
    fn canonical_lab_config_accepts_the_exact_fleet_timestamp_markers_v0() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = consensus_set(&parameters);
        let local = set.validators()[0].id();
        NativeApplicationConfigV0::from_canonical_lab_inputs_v0(canonical_lab_inputs(
            set,
            parameters,
            local,
            "poco-g3-7-20260821T085050Z-d74fe7e2",
            [0x92; 32],
            [0x94; 32],
            application_signers(),
        ))
        .expect("the fleet-wide canonical run ID must commission native application state");
    }

    #[test]
    fn canonical_lab_config_rejects_consensus_key_as_application_authority_v0() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = consensus_set(&parameters);
        let local = set.validators()[0].id();
        let signer = AuthorizedSignerV0::new(
            "did:operator:1",
            "operator",
            hex::encode(set.validators()[0].consensus_key().as_bytes()),
        )
        .unwrap();
        let inputs = canonical_lab_inputs(
            set,
            parameters,
            local,
            "g3-7-equal-run-001",
            [0x92; 32],
            [0x94; 32],
            vec![signer],
        );
        assert!(NativeApplicationConfigV0::from_canonical_lab_inputs_v0(inputs).is_err());
    }

    fn config(store_id: [u8; 32]) -> NativeApplicationConfigV0 {
        config_with_initial_block(store_id, INITIAL_BLOCK)
    }

    fn config_with_initial_block(
        store_id: [u8; 32],
        initial_block_id: [u8; 32],
    ) -> NativeApplicationConfigV0 {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = consensus_set(&parameters);
        let signers = application_signers();
        let lifecycle = ValidatorLifecycleStateV1::from_genesis(
            CHAIN.to_string(),
            1,
            hex::encode(crate::signer_policy_commitment_v0(&signers).unwrap()),
            ValidatorGovernanceV1 {
                schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
                signer_id: "did:operator:1".to_string(),
                min_activation_delay_blocks: 2,
                unsafe_allow_single_validator_genesis: false,
            },
            set.validators()
                .iter()
                .map(|validator| ConsensusValidatorV1 {
                    public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
                    voting_power: validator.voting_power().get(),
                })
                .collect(),
        )
        .unwrap();
        NativeApplicationConfigV0::new(
            CHAIN,
            GENESIS,
            DESCRIPTOR,
            store_id,
            initial_block_id,
            INITIAL_COMMIT,
            set,
            parameters,
            serde_json::to_vec(&lifecycle).unwrap(),
            signers,
            Vec::new(),
        )
        .unwrap()
    }

    fn genesis_request(config: &NativeApplicationConfigV0) -> NativeApplicationGenesisRequestV0 {
        NativeApplicationGenesisRequestV0::new(
            ChainIdV0::new(CHAIN).unwrap(),
            GenesisHashV0::new(GENESIS).unwrap(),
            Hash32V0::new(DESCRIPTOR),
            Hash32V0::new(config.signer_policy_commitment),
            StateRootV0::new(config.initial_state_root).unwrap(),
            config.native_validator_set.clone(),
        )
        .unwrap()
    }

    fn outer_transactions() -> Vec<Vec<u8>> {
        outer_transactions_for_v0(1)
    }

    fn outer_transactions_for_v0(nonce: u64) -> Vec<Vec<u8>> {
        let transactions = [
            CanonicalTxV1 {
                schema: CANONICAL_TX_SCHEMA_V1.to_string(),
                sender: "did:operator:1".to_string(),
                nonce,
                max_gas: 100_000,
                fee_limit: 100_000,
                command: CanonicalCommandV1::CreditAccount {
                    account: "did:client:1".to_string(),
                    amount: 10_000,
                },
            },
            CanonicalTxV1 {
                schema: CANONICAL_TX_SCHEMA_V1.to_string(),
                sender: "did:client:1".to_string(),
                nonce,
                max_gas: 100_000,
                fee_limit: 100_000,
                command: CanonicalCommandV1::CreateTask {
                    task_id: format!("durable-task-{}", nonce - 1),
                    reward: 1_000,
                    worker_stake: 500,
                    result_deadline_height: 20,
                    challenge_window_blocks: 10,
                },
            },
        ];
        transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| {
                let (seed, id, role, command_id) = if index == 0 {
                    (
                        81,
                        "did:operator:1",
                        "operator",
                        format!("durable-credit-{nonce}"),
                    )
                } else {
                    (
                        82,
                        "did:client:1",
                        "hepta",
                        format!("durable-create-{nonce}"),
                    )
                };
                let inner = serde_json::to_vec(transaction).unwrap();
                let envelope = SignedCommandEnvelopeV1::sign(
                    CHAIN,
                    &command_id,
                    id,
                    role,
                    transaction.nonce,
                    1_700_000_000_000,
                    1_700_000_100_000,
                    CANONICAL_TX_PAYLOAD_TYPE_V1,
                    &inner,
                    &signing_key(seed),
                )
                .unwrap();
                serde_json::to_vec(&envelope).unwrap()
            })
            .collect()
    }

    fn assert_complete_vector_v0(
        config: &NativeApplicationConfigV0,
        transactions: &[Vec<u8>],
        computed: &ComputedCompleteExecutionV0,
    ) {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/native-complete-durable-p-v0.json"))
                .unwrap();
        let inputs = vector.get("inputs").unwrap();
        let expected = vector.get("expected").unwrap();
        assert_eq!(
            inputs.get("initial_state_root_hex").unwrap(),
            &serde_json::Value::String(hex::encode(config.initial_state_root))
        );
        let transaction_hashes = transactions
            .iter()
            .map(|transaction| serde_json::Value::String(hex::encode(sha256_v0(transaction))))
            .collect::<Vec<_>>();
        assert_eq!(
            inputs.get("outer_transaction_sha256_hex").unwrap(),
            &serde_json::Value::Array(transaction_hashes)
        );
        for (field, actual) in [
            ("payload_root_hex", computed.payload_root),
            ("post_state_root_hex", computed.post_state_root),
            ("receipts_root_hex", computed.receipts_root),
            ("evidence_root_hex", computed.evidence_root),
        ] {
            assert_eq!(
                expected.get(field).unwrap(),
                &serde_json::Value::String(hex::encode(actual)),
                "complete vector field {field} drifted"
            );
        }
    }

    fn execution_request(
        config: &NativeApplicationConfigV0,
        head: &ApplicationHeadV0,
    ) -> NativeBlockExecutionRequestV0 {
        let placeholder = NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new([1; 32]),
            StateRootV0::new([2; 32]).unwrap(),
            trnm_native_application::ReceiptsRootV0::new([3; 32]).unwrap(),
            Hash32V0::new([4; 32]),
        )
        .unwrap();
        let transactions = outer_transactions();
        let request = NativeBlockExecutionRequestV0::new(
            ChainIdV0::new(CHAIN).unwrap(),
            GenesisHashV0::new(GENESIS).unwrap(),
            head.clone(),
            BlockIdV0::new([12; 32]).unwrap(),
            HeightV0::new(1),
            1_700_000_001_000,
            ValidatorSetIdV0::new(*config.validator_set.id().as_bytes()).unwrap(),
            transactions.clone(),
            placeholder,
        )
        .unwrap();
        let store = InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
            CHAIN,
            config.signers.clone(),
            config.parameters,
            BTreeSet::new(),
            BTreeSet::new(),
            &config.initial_snapshot,
        )
        .unwrap();
        let computed = compute_complete_native_block_v0(
            &store,
            &config.validator_set,
            GenesisHash::new(GENESIS),
            &request,
        )
        .unwrap();
        assert_complete_vector_v0(config, &transactions, &computed);
        let expected = NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new(computed.payload_root),
            StateRootV0::new(computed.post_state_root).unwrap(),
            trnm_native_application::ReceiptsRootV0::new(computed.receipts_root).unwrap(),
            Hash32V0::new(computed.evidence_root),
        )
        .unwrap();
        NativeBlockExecutionRequestV0::new(
            ChainIdV0::new(CHAIN).unwrap(),
            GenesisHashV0::new(GENESIS).unwrap(),
            head.clone(),
            BlockIdV0::new([12; 32]).unwrap(),
            HeightV0::new(1),
            1_700_000_001_000,
            ValidatorSetIdV0::new(*config.validator_set.id().as_bytes()).unwrap(),
            transactions,
            expected,
        )
        .unwrap()
    }

    fn previewed_execution_request_v0(
        application: &DurableNativeApplicationV0,
        config: &NativeApplicationConfigV0,
        parent: ApplicationHeadV0,
        height: u64,
        block_byte: u8,
        nonce: u64,
    ) -> NativeBlockExecutionRequestV0 {
        let transactions = outer_transactions_for_v0(nonce);
        let timestamp_ms = 1_700_000_001_000 + height;
        let preview_request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(CHAIN).unwrap(),
            GenesisHashV0::new(GENESIS).unwrap(),
            parent.clone(),
            HeightV0::new(height),
            timestamp_ms,
            ValidatorSetIdV0::new(*config.validator_set.id().as_bytes()).unwrap(),
            transactions.clone(),
        )
        .unwrap();
        let preview = application.preview_block_v0(&preview_request).unwrap();
        NativeBlockExecutionRequestV0::new(
            ChainIdV0::new(CHAIN).unwrap(),
            GenesisHashV0::new(GENESIS).unwrap(),
            parent,
            BlockIdV0::new([block_byte; 32]).unwrap(),
            HeightV0::new(height),
            timestamp_ms,
            ValidatorSetIdV0::new(*config.validator_set.id().as_bytes()).unwrap(),
            transactions,
            NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn initialized(
        temporary: &TempDir,
    ) -> (
        PathBuf,
        DurableNativeApplicationV0,
        ApplicationHeadV0,
        NativeBlockExecutionRequestV0,
    ) {
        let path = temporary.path().join("application.sqlite");
        let config = config(STORE_A);
        let request = genesis_request(&config);
        let execution = execution_request(
            &config,
            &ApplicationHeadV0::new(
                HeightV0::GENESIS,
                BlockIdV0::new(INITIAL_BLOCK).unwrap(),
                StateRootV0::new(config.initial_state_root).unwrap(),
                ApplicationCommitIdV0::new(INITIAL_COMMIT).unwrap(),
            ),
        );
        let application = DurableNativeApplicationV0::open(&path, config).unwrap();
        let genesis = application.initialize(request).unwrap();
        (path, application, genesis.head().clone(), execution)
    }

    fn computed_executed_without_p(
        config: &NativeApplicationConfigV0,
        request: &NativeBlockExecutionRequestV0,
    ) -> trnm_native_application::NativeExecutedBlockV0 {
        let store = InMemoryNativeExecutionStoreV0::decode_authenticated_snapshot_v0(
            CHAIN,
            config.signers.clone(),
            config.parameters,
            BTreeSet::new(),
            BTreeSet::new(),
            &config.initial_snapshot,
        )
        .unwrap();
        let complete = execute_complete_native_block_v0(
            &store,
            &config.validator_set,
            GenesisHash::new(GENESIS),
            request,
        )
        .unwrap();
        let (executed, _plan, _replay, _lifecycle) = complete.into_parts();
        executed
    }

    #[test]
    fn preview_is_independent_read_only_and_final_execution_recomputes_it() {
        let temporary = TempDir::new().unwrap();
        let (path, application, genesis_head, request) = initialized(&temporary);
        let preview_request = NativeBlockPreviewRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            request.transactions().to_vec(),
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let preview = application.preview_block_v0(&preview_request).unwrap();
        let after = fs::read(&path).unwrap();
        assert_eq!(before, after, "preview must not mutate the SQLite file");
        assert_eq!(preview.payload_root(), request.expected().payload_root());
        assert_eq!(
            preview.post_state_root(),
            request.expected().post_state_root()
        );
        assert_eq!(preview.receipts_root(), request.expected().receipts_root());
        assert_eq!(preview.evidence_root(), request.expected().evidence_root());
        assert_eq!(preview.receipts().len(), request.transactions().len());
        assert!(preview.write_count() > 0);
        assert_ne!(preview.request_fingerprint().as_bytes(), &[0; 32]);
        assert_ne!(preview.write_plan_fingerprint().as_bytes(), &[0; 32]);

        let timestamp_variant = NativeBlockPreviewRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            request.height(),
            request.timestamp_ms() + 1,
            request.active_validator_set_id(),
            request.transactions().to_vec(),
        )
        .unwrap();
        let variant = application.preview_block_v0(&timestamp_variant).unwrap();
        assert_ne!(
            variant.request_fingerprint(),
            preview.request_fingerprint(),
            "preview fingerprint must bind timestamp even when roots are unchanged"
        );
        assert_eq!(variant.payload_root(), preview.payload_root());
        assert_eq!(variant.post_state_root(), preview.post_state_root());

        let recovered = application
            .recover(
                NativeApplicationRecoveryRequestV0::new(
                    ChainIdV0::new(CHAIN).unwrap(),
                    GenesisHashV0::new(GENESIS).unwrap(),
                    Hash32V0::new(DESCRIPTOR),
                    Hash32V0::new(
                        crate::signer_policy_commitment_v0(&application_signers()).unwrap(),
                    ),
                    genesis_head,
                    NativeRecoveryWatermarksV0::new(1, 0, 0),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(recovered.disposition(), NativeRecoveryDispositionV0::Exact);

        let executed = match application.execute_block(request).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected recomputed valid execution, got {other:?}"),
        };
        assert_eq!(
            executed.request().expected().post_state_root(),
            preview.post_state_root()
        );
    }

    #[test]
    fn durable_p_fresh_reopen_commit_and_recovery_are_exact() {
        let temporary = TempDir::new().unwrap();
        let (path, application, _genesis_head, request) = initialized(&temporary);
        let executed = match application.execute_block(request.clone()).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid execution, got {other:?}"),
        };
        drop(application);

        let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
        let replayed = match reopened.execute_block(request).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected exact durable-P replay, got {other:?}"),
        };
        assert_eq!(replayed, executed);
        let commit_request = NativeApplicationCommitRequestV0::new(executed.clone());
        let committed = reopened.commit_block(commit_request.clone()).unwrap();
        assert_eq!(committed.head().height().get(), 1);
        assert_eq!(committed.durable_sequence(), 3);
        let replay_commit = reopened.commit_block(commit_request).unwrap();
        assert_eq!(replay_commit.head(), committed.head());
        assert_eq!(
            replay_commit.durable_sequence(),
            committed.durable_sequence()
        );

        let proof = reopened
            .state_proof(
                NativeStateProofRequestV0::new(
                    committed.head().clone(),
                    stored_object_key_v0(&account_key("did:client:1")).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(proof.value().is_some());
        assert!(!proof.proof_bytes().is_empty());
        let snapshot = reopened
            .snapshot(NativeSnapshotRequestV0::new(committed.head().clone(), 1_048_576).unwrap())
            .unwrap();
        assert!(snapshot.total_bytes() > 0);
        drop(reopened);

        let recovered = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
        let result = recovered
            .recover(
                NativeApplicationRecoveryRequestV0::new(
                    ChainIdV0::new(CHAIN).unwrap(),
                    GenesisHashV0::new(GENESIS).unwrap(),
                    Hash32V0::new(DESCRIPTOR),
                    Hash32V0::new(
                        crate::signer_policy_commitment_v0(&application_signers()).unwrap(),
                    ),
                    committed.head().clone(),
                    NativeRecoveryWatermarksV0::new(3, 0, 0),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(result.disposition(), NativeRecoveryDispositionV0::Exact);
        assert_eq!(result.head(), committed.head());
    }

    #[test]
    fn finalized_read_by_block_and_height_returns_fresh_p_row_and_receipts_v0() {
        let temporary = TempDir::new().unwrap();
        let (path, application, _genesis_head, request) = initialized(&temporary);
        let executed = match application.execute_block(request.clone()).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid execution, got {other:?}"),
        };
        let expected_receipts = executed
            .receipts()
            .iter()
            .map(|receipt| Hash32V0::new(*receipt.commitment().as_bytes()))
            .collect::<Vec<_>>();
        let committed = application
            .commit_block(NativeApplicationCommitRequestV0::new(executed.clone()))
            .unwrap();

        let by_block = application
            .read_finalized_by_block_id_v0(request.block_id())
            .unwrap();
        assert_eq!(by_block.confirmed_head_v0(), committed.head());
        assert_eq!(by_block.finalized_head_v0().unwrap(), *committed.head());
        assert_eq!(
            by_block.durable_row_v0().status_v0(),
            DurableExecutionHistoryStatusV0::Committed
        );
        assert_eq!(
            by_block.durable_row_v0().target_head_v0().unwrap(),
            *committed.head()
        );
        assert_eq!(by_block.executed_v0(), &executed);
        assert_eq!(
            by_block.receipt_commitments_v0(),
            expected_receipts.as_slice()
        );
        assert_eq!(
            by_block.receipts_root_v0(),
            request.expected().receipts_root()
        );

        let by_height = application
            .read_finalized_by_height_v0(request.height())
            .unwrap();
        assert_eq!(by_height.confirmed_head_v0(), by_block.confirmed_head_v0());
        assert_eq!(
            by_height.durable_row_v0().p_digest_v0(),
            by_block.durable_row_v0().p_digest_v0()
        );
        assert_eq!(
            by_height.receipt_commitments_v0(),
            expected_receipts.as_slice()
        );

        drop(application);
        let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
        let reopened_read = reopened
            .read_finalized_by_block_id_v0(request.block_id())
            .unwrap();
        assert_eq!(reopened_read.confirmed_head_v0(), committed.head());
        assert_eq!(
            reopened_read.receipt_commitments_v0(),
            expected_receipts.as_slice()
        );
    }

    #[test]
    fn finalized_read_rejects_prepared_and_missing_or_mismatched_keys_v0() {
        let temporary = TempDir::new().unwrap();
        let (_path, application, _genesis_head, request) = initialized(&temporary);
        let _executed = match application.execute_block(request.clone()).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid execution, got {other:?}"),
        };

        let prepared = application
            .read_finalized_by_block_id_v0(request.block_id())
            .expect_err("prepared P must not be exposed as finalized");
        assert_eq!(
            prepared.code(),
            NativeApplicationExecutionErrorCodeV0::NonContiguous
        );
        assert_eq!(prepared.field(), "read_finalized.not_committed");

        let missing_block = application
            .read_finalized_by_block_id_v0(BlockIdV0::new([0xee; 32]).unwrap())
            .expect_err("unknown BlockId must fail closed");
        assert_eq!(
            missing_block.code(),
            NativeApplicationExecutionErrorCodeV0::NonContiguous
        );
        assert_eq!(missing_block.field(), "read_finalized.missing_block");

        let missing_height = application
            .read_finalized_by_height_v0(HeightV0::new(request.height().get() + 1))
            .expect_err("unknown height must fail closed");
        assert_eq!(
            missing_height.code(),
            NativeApplicationExecutionErrorCodeV0::NonContiguous
        );
        assert_eq!(missing_height.field(), "read_finalized.missing_height");

        let genesis = application
            .read_finalized_by_height_v0(HeightV0::GENESIS)
            .expect_err("genesis has no durable P row");
        assert_eq!(
            genesis.code(),
            NativeApplicationExecutionErrorCodeV0::NonContiguous
        );
        assert_eq!(genesis.field(), "read_finalized.genesis");
    }

    #[test]
    fn finalized_commit_adapter_runs_signed_tx_to_state_proof_and_reopen_v0() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("finality-application.sqlite");
        // The consensus genesis anchor is also the authenticated application
        // parent in this one-node seam.  Real deployments will obtain this
        // parent from Core/Safety commissioning rather than this test helper.
        let config = config_with_initial_block(STORE_FINALITY, GENESIS);
        let genesis_request = genesis_request(&config);
        let validator_set = config.validator_set.clone();
        let parameters = config.parameters;
        let signer_policy_commitment = config.signer_policy_commitment_v0();
        let parent = ApplicationHeadV0::new(
            HeightV0::GENESIS,
            BlockIdV0::new(GENESIS).unwrap(),
            StateRootV0::new(config.initial_state_root).unwrap(),
            ApplicationCommitIdV0::new(INITIAL_COMMIT).unwrap(),
        );
        let template = execution_request(&config, &parent);
        let finalized_header =
            header_for_execution_v0(&template, &config.validator_set, 1, template.timestamp_ms());
        let request = NativeBlockExecutionRequestV0::new(
            template.chain_id().clone(),
            template.genesis_hash(),
            parent.clone(),
            BlockIdV0::new(*finalized_header.id().as_bytes()).unwrap(),
            template.height(),
            template.timestamp_ms(),
            template.active_validator_set_id(),
            template.transactions().to_vec(),
            template.expected(),
        )
        .unwrap();
        let application = DurableNativeApplicationV0::open(&path, config).unwrap();
        let genesis = application.initialize(genesis_request).unwrap();
        assert_eq!(genesis.head().block_id(), parent.block_id());

        // The body is made of the same SignedCommandEnvelopeV1 fixtures used
        // by the durable execution vector; no unsigned transaction shortcut
        // is involved in this path.
        let executed = match application.execute_block(request.clone()).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("signed transaction execution was not valid: {other:?}"),
        };
        let proof = signed_finality_proof_for_execution_v0(
            executed.request(),
            &validator_set,
            &parameters,
            template.timestamp_ms() - 1_000,
        );
        let committed = application
            .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                executed.clone(),
                proof.clone(),
                template.timestamp_ms() - 1_000,
            ))
            .unwrap();
        assert_eq!(committed.head().height().get(), 1);
        assert_eq!(committed.head().block_id(), request.block_id());
        let replayed = application
            .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                executed,
                proof.clone(),
                template.timestamp_ms() - 1_000,
            ))
            .expect("exact finalized commit replay must be idempotent");
        assert_eq!(replayed, committed);

        let proof_read = application
            .read_finalized_by_block_id_with_proof_v0(
                request.block_id(),
                &proof,
                template.timestamp_ms() - 1_000,
            )
            .unwrap();
        assert_eq!(proof_read.confirmed_head_v0(), committed.head());
        assert_eq!(
            proof_read.durable_row_v0().target_head_v0().unwrap(),
            *committed.head()
        );
        let proof_height_read = application
            .read_finalized_by_height_with_proof_v0(
                request.height(),
                &proof,
                template.timestamp_ms() - 1_000,
            )
            .unwrap();
        assert_eq!(
            proof_height_read.receipts_root_v0(),
            request.expected().receipts_root()
        );
        let rejected_timestamp = application
            .read_finalized_by_block_id_with_proof_v0(
                request.block_id(),
                &proof,
                template.timestamp_ms(),
            )
            .expect_err("a mismatched authenticated parent timestamp must fail closed");
        assert_eq!(
            rejected_timestamp.code(),
            NativeApplicationExecutionErrorCodeV0::BindingMismatch
        );

        let state_proof = application
            .state_proof(
                NativeStateProofRequestV0::new(
                    committed.head().clone(),
                    stored_object_key_v0(&account_key("did:client:1")).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(state_proof.value().is_some());
        assert!(!state_proof.proof_bytes().is_empty());
        drop(application);

        let reopened = DurableNativeApplicationV0::open(
            &path,
            config_with_initial_block(STORE_FINALITY, GENESIS),
        )
        .unwrap();
        assert_eq!(
            reopened.confirmed_committed_head_v0().unwrap(),
            *committed.head()
        );
        let recovery = reopened
            .recover(
                NativeApplicationRecoveryRequestV0::new(
                    ChainIdV0::new(CHAIN).unwrap(),
                    GenesisHashV0::new(GENESIS).unwrap(),
                    Hash32V0::new(DESCRIPTOR),
                    Hash32V0::new(signer_policy_commitment),
                    committed.head().clone(),
                    NativeRecoveryWatermarksV0::new(3, 0, 0),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(recovery.disposition(), NativeRecoveryDispositionV0::Exact);
        assert_eq!(recovery.head(), committed.head());
    }

    #[test]
    fn finalized_commit_adapter_rejects_header_mismatch_before_atomic_commit_v0() {
        let temporary = TempDir::new().unwrap();
        let (_path, application, genesis_head, request) = initialized(&temporary);
        let executed = match application.execute_block(request).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid execution, got {other:?}"),
        };
        let proof = structurally_valid_finality_proof_v0(
            application.config_v0().validator_set_v0(),
            application.config_v0().consensus_parameters_v0(),
        );
        let result = application.commit_finalized_block_v0(
            FinalizedNativeApplicationCommitRequestV0::new(executed, proof, 1_700_000_000_000),
        );
        let error = result.expect_err("header mismatch must fail before application commit");
        assert_eq!(
            error.code(),
            NativeApplicationExecutionErrorCodeV0::BindingMismatch
        );
        assert_eq!(error.field(), "finalized_commit.block_id");
        assert_eq!(
            application.confirmed_committed_head_v0().unwrap(),
            genesis_head,
            "a rejected finalized proof must not advance the application head"
        );
    }

    #[test]
    fn finalized_commit_adapter_rejects_substituted_receipt_bindings_and_replays_exactly_v0() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("finality-receipt-bindings.sqlite");
        let config = config_with_initial_block(STORE_FINALITY, GENESIS);
        let validator_set = config.validator_set.clone();
        let parameters = config.parameters;
        let parent = ApplicationHeadV0::new(
            HeightV0::GENESIS,
            BlockIdV0::new(GENESIS).unwrap(),
            StateRootV0::new(config.initial_state_root).unwrap(),
            ApplicationCommitIdV0::new(INITIAL_COMMIT).unwrap(),
        );
        let template = execution_request(&config, &parent);
        let header = header_for_execution_v0(&template, &validator_set, 1, template.timestamp_ms());
        let request = NativeBlockExecutionRequestV0::new(
            template.chain_id().clone(),
            template.genesis_hash(),
            parent.clone(),
            BlockIdV0::new(*header.id().as_bytes()).unwrap(),
            template.height(),
            template.timestamp_ms(),
            template.active_validator_set_id(),
            template.transactions().to_vec(),
            template.expected(),
        )
        .unwrap();
        let application = DurableNativeApplicationV0::open(&path, config).unwrap();
        application
            .initialize(genesis_request(&config_with_initial_block(
                STORE_FINALITY,
                GENESIS,
            )))
            .unwrap();
        let executed = match application.execute_block(request).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid execution, got {other:?}"),
        };
        let authenticated_parent_timestamp_ms = template.timestamp_ms() - 1_000;
        let proof = signed_finality_proof_for_execution_v0(
            executed.request(),
            &validator_set,
            &parameters,
            authenticated_parent_timestamp_ms,
        );
        let original = executed.receipts()[0].clone();
        let substituted_digest = NativeExecutionReceiptV0::new(
            original.transaction_index(),
            Hash32V0::new([0xe1; 32]),
            original.gas_used(),
            original.fee_charged(),
            original.events().to_vec(),
            original.commitment(),
        )
        .unwrap();
        let substituted_commitment = NativeExecutionReceiptV0::new(
            original.transaction_index(),
            original.transaction_digest(),
            original.gas_used(),
            original.fee_charged(),
            original.events().to_vec(),
            Hash32V0::new([0xe2; 32]),
        )
        .unwrap();
        for (replacement, field) in [
            (
                substituted_digest,
                "finalized_commit.receipt_transaction_digest",
            ),
            (
                substituted_commitment,
                "finalized_commit.receipt_commitment",
            ),
        ] {
            let mut receipts = executed.receipts().to_vec();
            receipts[0] = replacement;
            let expected = executed.request().expected();
            let substituted = NativeExecutedBlockV0::new(
                executed.request().clone(),
                expected.payload_root(),
                expected.post_state_root(),
                expected.receipts_root(),
                expected.evidence_root(),
                receipts,
            )
            .unwrap();
            let error = application
                .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                    substituted,
                    proof.clone(),
                    authenticated_parent_timestamp_ms,
                ))
                .expect_err("substituted receipt binding must fail closed");
            assert_eq!(
                error.code(),
                NativeApplicationExecutionErrorCodeV0::BindingMismatch
            );
            assert_eq!(error.field(), field);
            assert_eq!(
                application.confirmed_committed_head_v0().unwrap().height(),
                HeightV0::GENESIS,
                "rejected receipt binding must not advance the application head"
            );
        }

        let committed = application
            .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                executed.clone(),
                proof.clone(),
                authenticated_parent_timestamp_ms,
            ))
            .unwrap();
        let replayed = application
            .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                executed,
                proof,
                authenticated_parent_timestamp_ms,
            ))
            .expect("valid finalized commit retry must be exact");
        assert_eq!(replayed, committed);
        assert_eq!(committed.head().height(), HeightV0::new(1));
    }

    #[test]
    fn finalized_commit_adapter_source_contract_keeps_finality_and_atomicity_explicit_v0() {
        let source = include_str!("durable.rs");
        let start = source
            .find("pub fn commit_finalized_block_v0(")
            .expect("finalized commit adapter remains explicit");
        let end = source[start..]
            .find("    fn lock_operation(")
            .map(|offset| start + offset)
            .expect("finalized commit adapter has a bounded body");
        let body = &source[start..end];
        assert!(body.contains("finality_proof\n            .verify("));
        assert!(body.contains("StrictEd25519Verifier"));
        assert!(body.contains("validate_native_finalized_execution_receipts_v0"));
        assert!(body.contains("NativeApplicationV0::commit_block"));
        assert!(!body.contains("qc_as_application_commit = true"));
        assert!(!body.contains("production_activation: true"));
    }

    /// Injects one software-visible sync error after the SQLite transaction has
    /// committed, then proves that a fresh owner observes the exact target and
    /// that an idempotent replay does not create a second logical write. This
    /// is deliberately narrower than a physical power-loss campaign: the
    /// latter remains unevaluated and must not inherit this result.
    #[cfg(unix)]
    #[test]
    fn fsync_uncertainty_reopens_exact_and_replay_is_logically_read_only_v0() {
        const FAULTS: [(SyncStoreCommitBoundaryFaultPointV0, &str); 2] = [
            (
                SyncStoreCommitBoundaryFaultPointV0::Database,
                "commit.fsync",
            ),
            (
                SyncStoreCommitBoundaryFaultPointV0::Directory,
                "commit.directory_fsync",
            ),
        ];

        for (point, expected_field) in FAULTS {
            let temporary = TempDir::new().unwrap();
            let (path, application, _genesis_head, request) = initialized(&temporary);
            let executed = match application.execute_block(request.clone()).unwrap() {
                NativeBlockExecutionResultV0::Valid(value) => *value,
                other => panic!("expected valid execution before fsync fault, got {other:?}"),
            };
            let expected_head = application
                .confirm_durable_p_v0(&executed)
                .unwrap()
                .overlay_parent_head_v0()
                .unwrap();

            let _fault = arm_sync_store_commit_boundary_fault_v0(application.path(), point);
            let uncertain = application
                .commit_block(NativeApplicationCommitRequestV0::new(executed.clone()))
                .expect_err("injected sync failure must report an uncertain commit");
            assert_eq!(
                uncertain.code(),
                NativeApplicationExecutionErrorCodeV0::CommitUncertain
            );
            assert_eq!(uncertain.field(), expected_field);
            drop(application);

            let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
            assert_eq!(
                reopened.confirmed_committed_head_v0().unwrap(),
                expected_head,
                "fresh readback must resolve the post-transaction target exactly"
            );
            let recovery = reopened
                .recover(
                    NativeApplicationRecoveryRequestV0::new(
                        ChainIdV0::new(CHAIN).unwrap(),
                        GenesisHashV0::new(GENESIS).unwrap(),
                        Hash32V0::new(DESCRIPTOR),
                        Hash32V0::new(
                            crate::signer_policy_commitment_v0(&application_signers()).unwrap(),
                        ),
                        expected_head.clone(),
                        NativeRecoveryWatermarksV0::new(3, 0, 0),
                    )
                    .unwrap(),
                )
                .unwrap();
            assert_eq!(recovery.disposition(), NativeRecoveryDispositionV0::Exact);
            assert_eq!(recovery.head(), &expected_head);

            let (metadata_before, p_before) = {
                let connection = open_immutable_connection_v0(&path).unwrap();
                (
                    load_metadata_v0(&connection, &config(STORE_A)).unwrap(),
                    load_p_by_block_v0(&connection, *executed.request().block_id().as_bytes())
                        .unwrap()
                        .unwrap(),
                )
            };
            assert_eq!(metadata_before.durable_sequence, 3);
            assert_eq!(p_before.status, P_STATUS_COMMITTED);
            assert_eq!(p_before.commit_sequence, Some(3));

            let replay = reopened
                .commit_block(NativeApplicationCommitRequestV0::new(executed))
                .expect("committed row replay must be an exact read-only result");
            assert_eq!(replay.head(), &expected_head);
            assert_eq!(replay.durable_sequence(), 3);

            let (metadata_after, p_after) = {
                let connection = open_immutable_connection_v0(&path).unwrap();
                (
                    load_metadata_v0(&connection, &config(STORE_A)).unwrap(),
                    load_p_by_block_v0(&connection, *replay.head().block_id().as_bytes())
                        .unwrap()
                        .unwrap(),
                )
            };
            assert_eq!(metadata_after, metadata_before);
            assert_eq!(p_after, p_before);
        }
    }

    /// Genesis and H1 TrustedBase are durable state transitions too.  Exercise
    /// their post-transaction database/directory sync boundary so a reported
    /// sync failure is recovered by exact readback rather than by re-running a
    /// second logical write.  This remains a software fault injection test;
    /// it is not physical power-loss evidence.
    #[cfg(unix)]
    #[test]
    fn initialization_and_h1_sync_uncertainty_reopens_exactly_v0() {
        const FAULTS: [(SyncStoreCommitBoundaryFaultPointV0, &str, &str); 2] = [
            (
                SyncStoreCommitBoundaryFaultPointV0::Database,
                "initialize.fsync",
                "h1_state_sync.fsync",
            ),
            (
                SyncStoreCommitBoundaryFaultPointV0::Directory,
                "initialize.directory_fsync",
                "h1_state_sync.directory_fsync",
            ),
        ];

        for (point, initialize_field, h1_field) in FAULTS {
            let temporary = TempDir::new().unwrap();
            let path = temporary.path().join("application.sqlite");
            let initialize_config = config(STORE_A);
            let genesis = genesis_request(&initialize_config);
            let application = DurableNativeApplicationV0::open(&path, initialize_config).unwrap();
            let fault = arm_sync_store_commit_boundary_fault_v0(application.path(), point);
            let initialize_error = application
                .initialize(genesis.clone())
                .expect_err("initialize sync failure must be reported as uncertain");
            assert_eq!(
                initialize_error.code(),
                NativeApplicationExecutionErrorCodeV0::CommitUncertain
            );
            assert_eq!(initialize_error.field(), initialize_field);
            drop(fault);

            // A retry in the same owner must not bypass the host durability
            // fence merely because the exact metadata row is now visible.
            let retry_fault = arm_sync_store_commit_boundary_fault_v0(application.path(), point);
            let retry_error = application
                .initialize(genesis.clone())
                .expect_err("initialize retry must re-attempt its sync fence");
            assert_eq!(
                retry_error.code(),
                NativeApplicationExecutionErrorCodeV0::CommitUncertain
            );
            assert_eq!(retry_error.field(), initialize_field);
            drop(retry_fault);

            let in_process_genesis = application
                .initialize(genesis.clone())
                .expect("initialize retry succeeds only after a clean sync");
            assert_eq!(in_process_genesis.head().height(), HeightV0::GENESIS);
            drop(application);

            let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
            let genesis_result = reopened
                .initialize(genesis)
                .expect("reopen must observe the exact committed genesis");
            assert_eq!(genesis_result.head().height(), HeightV0::GENESIS);
            drop(reopened);

            let (h1_path, h1_application, _head, execution) = initialized(&temporary);
            let h1_request =
                NativeH1StateSyncTrustedBaseRequestV0::new([0xA1; 32], execution).unwrap();
            let fault = arm_sync_store_commit_boundary_fault_v0(h1_application.path(), point);
            let h1_error = h1_application
                .install_h1_state_sync_trusted_base_v0(&h1_request)
                .expect_err("H1 sync failure must be reported as uncertain");
            assert_eq!(
                h1_error.code(),
                NativeApplicationExecutionErrorCodeV0::CommitUncertain
            );
            assert_eq!(h1_error.field(), h1_field);
            drop(fault);

            // The existing TrustedBase branch is also an idempotent retry
            // boundary and must not turn a failed sync into a silent success.
            let retry_fault = arm_sync_store_commit_boundary_fault_v0(h1_application.path(), point);
            let retry_error = h1_application
                .install_h1_state_sync_trusted_base_v0(&h1_request)
                .expect_err("H1 retry must re-attempt its sync fence");
            assert_eq!(
                retry_error.code(),
                NativeApplicationExecutionErrorCodeV0::CommitUncertain
            );
            assert_eq!(retry_error.field(), h1_field);
            drop(retry_fault);

            let in_process_confirmed = h1_application
                .install_h1_state_sync_trusted_base_v0(&h1_request)
                .expect("H1 retry succeeds only after a clean sync");
            assert_eq!(in_process_confirmed.install_sequence_v0(), 2);
            drop(h1_application);

            let reopened_h1 = DurableNativeApplicationV0::open(&h1_path, config(STORE_A)).unwrap();
            let confirmed = reopened_h1
                .install_h1_state_sync_trusted_base_v0(&h1_request)
                .expect("reopen must observe the exact committed H1 TrustedBase");
            assert_eq!(confirmed.install_sequence_v0(), 2);
        }
    }

    /// Child-process entry point for the real SIGKILL boundary test below.
    /// The test harness invokes this exact test with a path and stage in its
    /// environment; ordinary `cargo test` discovery runs it as a no-op.
    #[cfg(unix)]
    #[test]
    fn sigkill_commit_boundary_child_v0() {
        let Ok(path) = std::env::var("TRNM_NATIVE_EXECUTION_TEST_STORE") else {
            return;
        };
        let config = config(STORE_A);
        let parent = ApplicationHeadV0::new(
            HeightV0::GENESIS,
            BlockIdV0::new(INITIAL_BLOCK).unwrap(),
            StateRootV0::new(config.initial_state_root).unwrap(),
            ApplicationCommitIdV0::new(INITIAL_COMMIT).unwrap(),
        );
        let request = execution_request(&config, &parent);
        let application = DurableNativeApplicationV0::open(PathBuf::from(path), config)
            .expect("SIGKILL child opens prepared application");
        let executed = match application
            .execute_block(request)
            .expect("SIGKILL child reloads exact durable P")
        {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("SIGKILL child expected valid P, got {other:?}"),
        };
        // The commit hook parks this process before/after SQLite commit. The
        // parent test sends SIGKILL; reaching this line means the hook failed.
        let _ = application.commit_block(NativeApplicationCommitRequestV0::new(executed));
        panic!("SIGKILL child unexpectedly returned from the parked boundary");
    }

    /// Child-process entry point for the initialize SIGKILL matrix below.
    /// The parent kills this process while the one-time genesis transaction is
    /// either open, committed but not host-synced, or fully host-synced.
    #[cfg(unix)]
    #[test]
    fn sigkill_initialize_boundary_child_v0() {
        let Ok(path) = std::env::var("TRNM_NATIVE_EXECUTION_TEST_STORE") else {
            return;
        };
        let config = config(STORE_A);
        let request = genesis_request(&config);
        let application = DurableNativeApplicationV0::open(PathBuf::from(path), config)
            .expect("SIGKILL initialize child opens the empty store");
        let _ = application.initialize(request);
        panic!("SIGKILL initialize child unexpectedly returned from the parked boundary");
    }

    /// Child-process entry point for the h1 TrustedBase SIGKILL matrix below.
    /// The request is rebuilt from the same frozen genesis inputs in the
    /// parent and child; no serialized or caller-selected authority crosses
    /// the process boundary.
    #[cfg(unix)]
    #[test]
    fn sigkill_h1_boundary_child_v0() {
        let Ok(path) = std::env::var("TRNM_NATIVE_EXECUTION_TEST_STORE") else {
            return;
        };
        let config = config(STORE_A);
        let parent = ApplicationHeadV0::new(
            HeightV0::GENESIS,
            BlockIdV0::new(INITIAL_BLOCK).unwrap(),
            StateRootV0::new(config.initial_state_root).unwrap(),
            ApplicationCommitIdV0::new(INITIAL_COMMIT).unwrap(),
        );
        let execution = execution_request(&config, &parent);
        let request = NativeH1StateSyncTrustedBaseRequestV0::new([0xA1; 32], execution)
            .expect("SIGKILL h1 child builds the exact genesis successor request");
        let application = DurableNativeApplicationV0::open(PathBuf::from(path), config)
            .expect("SIGKILL h1 child opens the initialized store");
        let _ = application.install_h1_state_sync_trusted_base_v0(&request);
        panic!("SIGKILL h1 child unexpectedly returned from the parked boundary");
    }

    /// Kill one child at a named test-only durability boundary and require it
    /// to have reached the boundary marker first.  This helper intentionally
    /// uses the same exact-test invocation as the existing commit matrix so a
    /// future refactor cannot silently turn this into an in-process simulation.
    #[cfg(unix)]
    fn kill_sigkill_boundary_child_v0(path: &Path, stage: &str, marker: &Path, child_test: &str) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", child_test, "--nocapture"])
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE", stage)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER", marker)
            .env("TRNM_NATIVE_EXECUTION_TEST_STORE", path)
            .spawn()
            .expect("spawn SIGKILL durability child");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = Command::new("kill")
                .args(["-KILL", &child.id().to_string()])
                .status();
            let status = child.wait().expect("wait failed durability child");
            panic!("SIGKILL child did not reach {stage}; status={status:?}");
        }
        let kill_status = Command::new("kill")
            .args(["-KILL", &child.id().to_string()])
            .status()
            .expect("invoke kill -KILL for durability child");
        assert!(kill_status.success(), "kill -KILL failed for {stage}");
        let status = child.wait().expect("wait for SIGKILL durability child");
        assert!(!status.success(), "SIGKILL child survived {stage}");
    }

    /// Exercise the three legal initialize crash cuts in a separate process:
    /// before SQLite commit, after commit but before the explicit host sync,
    /// and after host sync but before fresh readback.  Reopen must expose only
    /// the exact genesis source/target (never a fabricated mixed state), and
    /// repeated initialize calls must remain read-only/idempotent.
    #[cfg(unix)]
    #[test]
    fn sigkill_initialize_boundaries_reopen_exactly_v0() {
        const STAGES: [&str; 3] = [
            "initialize_before_commit",
            "initialize_before_fsync",
            "initialize_after_fsync",
        ];
        for stage in STAGES {
            let temporary = TempDir::new().unwrap();
            let path = temporary.path().join("application.sqlite");
            let expected_config = config(STORE_A);
            let genesis = genesis_request(&expected_config);
            let marker = temporary.path().join(format!("sigkill-{stage}.ready"));
            kill_sigkill_boundary_child_v0(
                &path,
                stage,
                &marker,
                "durable::tests::sigkill_initialize_boundary_child_v0",
            );

            let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A))
                .expect("reopen after initialize SIGKILL");
            let first = reopened
                .initialize(genesis.clone())
                .expect("initialize retry must converge to exact genesis");
            let second = reopened
                .initialize(genesis)
                .expect("repeated initialize must be exact and idempotent");
            assert_eq!(first.head(), second.head());
            assert_eq!(first.head().height(), HeightV0::GENESIS);
            let connection = open_immutable_connection_v0(&path).unwrap();
            let metadata = load_metadata_v0(&connection, &expected_config).unwrap();
            assert_eq!(metadata.durable_sequence, 1);
            assert!(load_all_p_v0(&connection).unwrap().is_empty());
            assert!(load_h1_state_sync_trusted_base_v0(&connection)
                .unwrap()
                .is_none());
        }
    }

    /// Exercise the three legal h1 TrustedBase crash cuts in a separate
    /// process and prove that retry/reopen yields one exact install.  This is
    /// a software SIGKILL/SQLite rollback campaign; it deliberately makes no
    /// claim about physical power-loss behavior or external CAS authority.
    #[cfg(unix)]
    #[test]
    fn sigkill_h1_boundaries_reopen_exactly_v0() {
        const STAGES: [&str; 3] = ["h1_before_commit", "h1_before_fsync", "h1_after_fsync"];
        for stage in STAGES {
            let temporary = TempDir::new().unwrap();
            let (path, application, _head, execution) = initialized(&temporary);
            let request = NativeH1StateSyncTrustedBaseRequestV0::new([0xA1; 32], execution)
                .expect("build exact h1 request");
            drop(application);
            let marker = temporary.path().join(format!("sigkill-{stage}.ready"));
            kill_sigkill_boundary_child_v0(
                &path,
                stage,
                &marker,
                "durable::tests::sigkill_h1_boundary_child_v0",
            );

            let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A))
                .expect("reopen after h1 SIGKILL");
            let first = reopened
                .install_h1_state_sync_trusted_base_v0(&request)
                .expect("h1 retry must converge to exact TrustedBase");
            let second = reopened
                .install_h1_state_sync_trusted_base_v0(&request)
                .expect("repeated h1 install must be exact and idempotent");
            assert_eq!(first.head_v0(), second.head_v0());
            assert_eq!(first.proof_id_v0(), [0xA1; 32]);
            assert_eq!(first.install_sequence_v0(), 2);
            let connection = open_immutable_connection_v0(&path).unwrap();
            let metadata = load_metadata_v0(&connection, &config(STORE_A)).unwrap();
            assert_eq!(metadata.durable_sequence, 2);
            assert_eq!(metadata.head.height().get(), 1);
            assert!(load_all_p_v0(&connection).unwrap().is_empty());
            assert!(load_h1_state_sync_trusted_base_v0(&connection)
                .unwrap()
                .is_some());
        }
    }

    /// Kill a separate process at each commit boundary and prove that reopen
    /// sees either the untouched prepared P or the complete committed head.
    /// No mixed metadata/P state is accepted, and retry is exact/idempotent.
    #[cfg(unix)]
    #[test]
    fn sigkill_commit_boundaries_are_atomic_and_replay_safe_v0() {
        const STAGES: [&str; 3] = ["before_commit", "after_commit", "after_fsync"];
        for stage in STAGES {
            let temporary = TempDir::new().unwrap();
            let (path, application, genesis_head, request) = initialized(&temporary);
            let _executed = match application.execute_block(request.clone()).unwrap() {
                NativeBlockExecutionResultV0::Valid(value) => *value,
                other => panic!("expected valid P before {stage}, got {other:?}"),
            };
            drop(application);

            let marker = temporary.path().join(format!("sigkill-{stage}.ready"));
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "durable::tests::sigkill_commit_boundary_child_v0",
                    "--nocapture",
                ])
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE", stage)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER", &marker)
                .env("TRNM_NATIVE_EXECUTION_TEST_STORE", &path)
                .spawn()
                .expect("spawn SIGKILL commit child");
            let deadline = Instant::now() + Duration::from_secs(10);
            while !marker.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                marker.exists(),
                "SIGKILL child did not reach {stage}; status={:?}",
                child.try_wait().unwrap()
            );
            let kill_status = Command::new("kill")
                .args(["-KILL", &child.id().to_string()])
                .status()
                .expect("invoke kill -KILL for SIGKILL boundary");
            assert!(kill_status.success(), "kill -KILL failed for {stage}");
            let status = child.wait().expect("wait for SIGKILL child");
            assert!(!status.success(), "SIGKILL child survived {stage}");

            // A killed SQLite writer may leave its rollback journal. Startup
            // recognizes only the regular SQLite rollback-journal shape,
            // performs the atomic SQLite repair, fsyncs the image/directory,
            // then runs the immutable application audit. WAL/SHM or malformed
            // sidecars remain fail-closed.
            let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A))
                .expect("reopen after automatic SQLite rollback-journal recovery");
            let expected_head = if stage == "before_commit" {
                genesis_head.clone()
            } else {
                reopened
                    .confirmed_committed_head_v0()
                    .expect("post-commit SIGKILL retains a readable committed head")
            };
            let recovery = reopened
                .recover(
                    NativeApplicationRecoveryRequestV0::new(
                        ChainIdV0::new(CHAIN).unwrap(),
                        GenesisHashV0::new(GENESIS).unwrap(),
                        Hash32V0::new(DESCRIPTOR),
                        Hash32V0::new(
                            crate::signer_policy_commitment_v0(&application_signers()).unwrap(),
                        ),
                        expected_head,
                        NativeRecoveryWatermarksV0::new(0, 0, 0),
                    )
                    .unwrap(),
                )
                .unwrap();
            if stage == "before_commit" {
                assert_eq!(
                    recovery.disposition(),
                    NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records: 1 }
                );
                let replay = match reopened.execute_block(request.clone()).unwrap() {
                    NativeBlockExecutionResultV0::Valid(value) => *value,
                    other => panic!("prepared P was not replayable after {stage}: {other:?}"),
                };
                let committed = reopened
                    .commit_block(NativeApplicationCommitRequestV0::new(replay.clone()))
                    .unwrap();
                let duplicate = reopened
                    .commit_block(NativeApplicationCommitRequestV0::new(replay))
                    .unwrap();
                assert_eq!(duplicate.head(), committed.head());
                assert_eq!(duplicate.durable_sequence(), committed.durable_sequence());
            } else {
                assert_eq!(
                    recovery.disposition(),
                    NativeRecoveryDispositionV0::Exact,
                    "post-commit SIGKILL must leave one complete committed head",
                );
                let replay = match reopened.execute_block(request).unwrap() {
                    NativeBlockExecutionResultV0::Valid(value) => *value,
                    other => panic!("committed P was not replayable after {stage}: {other:?}"),
                };
                let duplicate = reopened
                    .commit_block(NativeApplicationCommitRequestV0::new(replay))
                    .unwrap();
                assert_eq!(duplicate.head().height().get(), 1);
            }
        }
    }

    #[test]
    fn short_write_database_images_fail_closed_v0() {
        let temporary = TempDir::new().unwrap();
        let (path, application, _head, request) = initialized(&temporary);
        let _ = application.execute_block(request).unwrap();
        drop(application);
        let bytes = fs::read(&path).unwrap();
        assert!(
            bytes.len() > 64,
            "fixture SQLite image is unexpectedly tiny"
        );
        let page_size = open_immutable_connection_v0(&path)
            .unwrap()
            .query_row("PRAGMA page_size", [], |row| row.get::<_, u64>(0))
            .unwrap() as usize;
        // These cuts remove the SQLite header or an entire occupied page.
        // Truncating only unused trailing pages is not a corruption signal in
        // SQLite and is therefore intentionally outside this assertion.
        for cut in [0, 1, page_size, page_size + 1] {
            if cut >= bytes.len() {
                continue;
            }
            let short_path = temporary.path().join(format!("short-write-{cut}.sqlite"));
            fs::write(&short_path, &bytes[..cut]).unwrap();
            let result = DurableNativeApplicationV0::open(&short_path, config(STORE_A));
            let error = result.expect_err("short SQLite image must not be normalized");
            assert!(
                matches!(
                    error.code(),
                    NativeApplicationExecutionErrorCodeV0::CorruptStore
                        | NativeApplicationExecutionErrorCodeV0::Storage
                        | NativeApplicationExecutionErrorCodeV0::CommitUncertain
                ),
                "short image at {cut} returned unexpected {:?}",
                error.code()
            );
        }
    }

    #[test]
    fn sibling_forks_survive_reopen_and_cross_store_reopens_fail_closed() {
        let temporary = TempDir::new().unwrap();
        let (path, application, genesis_head, request) = initialized(&temporary);
        let _ = application.execute_block(request.clone()).unwrap();
        let conflicting_request = NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            BlockIdV0::new([13; 32]).unwrap(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            request.transactions().to_vec(),
            request.expected(),
        )
        .unwrap();
        assert!(matches!(
            application.execute_block(conflicting_request).unwrap(),
            NativeBlockExecutionResultV0::Valid(_)
        ));
        let recovery = application
            .recover(
                NativeApplicationRecoveryRequestV0::new(
                    ChainIdV0::new(CHAIN).unwrap(),
                    GenesisHashV0::new(GENESIS).unwrap(),
                    Hash32V0::new(DESCRIPTOR),
                    Hash32V0::new(
                        crate::signer_policy_commitment_v0(&application_signers()).unwrap(),
                    ),
                    genesis_head,
                    NativeRecoveryWatermarksV0::new(2, 0, 0),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            recovery.disposition(),
            NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records: 2 }
        );
        drop(application);
        let error = DurableNativeApplicationV0::open(&path, config([99; 32])).unwrap_err();
        assert_eq!(
            error.code(),
            NativeApplicationExecutionErrorCodeV0::BindingMismatch
        );
    }

    #[test]
    fn durable_overlay_dag_survives_restart_and_finalized_prefix_prunes_only_forks() {
        let temporary = TempDir::new().unwrap();
        let (path, application, genesis_head, request_b1) = initialized(&temporary);
        let executed_b1 = match application.execute_block(request_b1.clone()).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid B1, got {other:?}"),
        };
        let confirmed_b1 = application.confirm_durable_p_v0(&executed_b1).unwrap();
        let overlay_b1 = confirmed_b1.overlay_parent_head_v0().unwrap();

        let sibling_b1 = NativeBlockExecutionRequestV0::new(
            request_b1.chain_id().clone(),
            request_b1.genesis_hash(),
            request_b1.parent().clone(),
            BlockIdV0::new([13; 32]).unwrap(),
            request_b1.height(),
            request_b1.timestamp_ms(),
            request_b1.active_validator_set_id(),
            request_b1.transactions().to_vec(),
            request_b1.expected(),
        )
        .unwrap();
        assert!(matches!(
            application.execute_block(sibling_b1.clone()).unwrap(),
            NativeBlockExecutionResultV0::Valid(_)
        ));

        let request_b2 =
            previewed_execution_request_v0(&application, &config(STORE_A), overlay_b1, 2, 14, 2);
        let executed_b2 = match application.execute_block(request_b2).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid B2, got {other:?}"),
        };
        let overlay_b2 = application
            .confirm_durable_p_v0(&executed_b2)
            .unwrap()
            .overlay_parent_head_v0()
            .unwrap();
        let request_b3 =
            previewed_execution_request_v0(&application, &config(STORE_A), overlay_b2, 3, 15, 3);
        let executed_b3 = match application.execute_block(request_b3).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid B3, got {other:?}"),
        };
        drop(application);

        let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
        let pending = reopened
            .recover(
                NativeApplicationRecoveryRequestV0::new(
                    ChainIdV0::new(CHAIN).unwrap(),
                    GenesisHashV0::new(GENESIS).unwrap(),
                    Hash32V0::new(DESCRIPTOR),
                    Hash32V0::new(
                        crate::signer_policy_commitment_v0(&application_signers()).unwrap(),
                    ),
                    genesis_head,
                    NativeRecoveryWatermarksV0::new(5, 0, 0),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            pending.disposition(),
            NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records: 4 }
        );
        assert_eq!(
            reopened
                .confirm_durable_p_v0(&executed_b3)
                .unwrap()
                .target_height_v0(),
            3
        );

        let committed_b1 = reopened
            .commit_block(NativeApplicationCommitRequestV0::new(executed_b1.clone()))
            .unwrap();
        assert_eq!(committed_b1.durable_sequence(), 6);
        assert_eq!(committed_b1.head().height().get(), 1);
        let replayed_b1 = reopened
            .commit_block(NativeApplicationCommitRequestV0::new(executed_b1))
            .unwrap();
        assert_eq!(replayed_b1.head(), committed_b1.head());
        assert_eq!(replayed_b1.durable_sequence(), 6);
        let pruned = reopened.execute_block(sibling_b1).unwrap_err();
        assert_eq!(
            pruned.code(),
            NativeApplicationExecutionErrorCodeV0::BindingMismatch
        );
        drop(reopened);

        let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
        let committed_b2 = reopened
            .commit_block(NativeApplicationCommitRequestV0::new(executed_b2))
            .unwrap();
        assert_eq!(committed_b2.durable_sequence(), 7);
        assert_eq!(committed_b2.head().height().get(), 2);
        drop(reopened);

        let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
        let committed_b3 = reopened
            .commit_block(NativeApplicationCommitRequestV0::new(executed_b3))
            .unwrap();
        assert_eq!(committed_b3.durable_sequence(), 8);
        assert_eq!(committed_b3.head().height().get(), 3);
        let exact = reopened
            .recover(
                NativeApplicationRecoveryRequestV0::new(
                    ChainIdV0::new(CHAIN).unwrap(),
                    GenesisHashV0::new(GENESIS).unwrap(),
                    Hash32V0::new(DESCRIPTOR),
                    Hash32V0::new(
                        crate::signer_policy_commitment_v0(&application_signers()).unwrap(),
                    ),
                    committed_b3.head().clone(),
                    NativeRecoveryWatermarksV0::new(8, 0, 0),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(exact.disposition(), NativeRecoveryDispositionV0::Exact);
    }

    #[test]
    fn partial_commit_third_states_are_permanently_fenced_on_reopen() {
        for partial in ["metadata_only", "p_only"] {
            let temporary = TempDir::new().unwrap();
            let (path, application, _head, request) = initialized(&temporary);
            let executed = match application.execute_block(request).unwrap() {
                NativeBlockExecutionResultV0::Valid(value) => *value,
                other => panic!("expected valid P before {partial}, got {other:?}"),
            };
            drop(application);

            let mut connection = open_writable_connection_v0(&path).unwrap();
            let p = load_p_by_block_v0(&connection, *executed.request().block_id().as_bytes())
                .unwrap()
                .unwrap();
            let commit_sequence = p.p_sequence + 1;
            let commit_id = application_commit_id_v0(&p);
            let transaction = connection.transaction().unwrap();
            match partial {
                "metadata_only" => {
                    transaction
                        .execute(
                            "UPDATE native_application_metadata_v0 SET durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,head_commit_id=?,authenticated_snapshot=?,authenticated_snapshot_digest=?,replay_command_ids=?,replay_signer_nonces=? WHERE singleton=1",
                            params![
                                u64_bytes_v0(commit_sequence).as_slice(),
                                u64_bytes_v0(p.target_height).as_slice(),
                                p.block_id.as_slice(),
                                executed.request().expected().post_state_root().as_bytes().as_slice(),
                                commit_id.as_slice(),
                                p.target_snapshot,
                                p.target_snapshot_digest.as_slice(),
                                p.target_command_bytes,
                                p.target_nonce_bytes,
                            ],
                        )
                        .unwrap();
                }
                "p_only" => {
                    transaction
                        .execute(
                            "UPDATE native_durable_execution_p_v0 SET status=?,commit_sequence=?,commit_id=? WHERE block_id=?",
                            params![
                                u64_bytes_v0(P_STATUS_COMMITTED).as_slice(),
                                u64_bytes_v0(commit_sequence).as_slice(),
                                commit_id.as_slice(),
                                p.block_id.as_slice(),
                            ],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            transaction.commit().unwrap();
            drop(connection);
            let fenced = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap_err();
            assert_eq!(
                fenced.code(),
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "partial commit state {partial} must never be normalized"
            );
        }
    }

    #[test]
    fn missing_metadata_with_residual_inventory_fails_closed_v0() {
        for inventory in ["p", "h1"] {
            let temporary = TempDir::new().unwrap();
            let (path, application, _head, execution) = initialized(&temporary);
            match inventory {
                "p" => {
                    application
                        .execute_block(execution.clone())
                        .expect("create one durable prepared P row");
                }
                "h1" => {
                    let request = NativeH1StateSyncTrustedBaseRequestV0::new([0xA1; 32], execution)
                        .expect("build exact h1 request");
                    let _ = application
                        .install_h1_state_sync_trusted_base_v0(&request)
                        .expect("create one durable H1 row");
                }
                _ => unreachable!(),
            }

            let connection = open_writable_connection_v0(&path).unwrap();
            connection
                .execute(
                    "DELETE FROM native_application_metadata_v0 WHERE singleton=1",
                    [],
                )
                .unwrap();
            drop(connection);

            let live_error = application
                .initialize(genesis_request(&config(STORE_A)))
                .expect_err("live initialize must not overwrite residual inventory");
            assert_eq!(
                live_error.code(),
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "live missing-metadata {inventory} inventory must fail closed"
            );
            drop(application);

            let reopen_error = DurableNativeApplicationV0::open(&path, config(STORE_A))
                .expect_err("reopen must not treat residual inventory as virgin");
            assert_eq!(
                reopen_error.code(),
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "reopen missing-metadata {inventory} inventory must fail closed"
            );
        }
    }

    #[test]
    fn artifact_snapshot_store_and_sequence_tampering_fail_closed() {
        for mutation in [
            "artifact_bytes",
            "artifact_digest",
            "snapshot_bytes",
            "snapshot_digest",
            "replay",
            "lifecycle",
            "store",
            "sequence",
        ] {
            let temporary = TempDir::new().unwrap();
            let (path, application, _head, request) = initialized(&temporary);
            let _ = application.execute_block(request).unwrap();
            drop(application);
            let connection = open_writable_connection_v0(&path).unwrap();
            match mutation {
                "artifact_bytes" => {
                    connection
                        .execute(
                            "UPDATE native_durable_execution_p_v0 SET artifact=?",
                            params![b"not-a-canonical-artifact".as_slice()],
                        )
                        .unwrap();
                }
                "artifact_digest" => {
                    connection
                        .execute(
                            "UPDATE native_durable_execution_p_v0 SET artifact_digest=?",
                            params![[55u8; 32].as_slice()],
                        )
                        .unwrap();
                }
                "snapshot_bytes" => {
                    connection
                        .execute(
                            "UPDATE native_durable_execution_p_v0 SET target_snapshot=?",
                            params![b"not-an-authenticated-snapshot".as_slice()],
                        )
                        .unwrap();
                }
                "snapshot_digest" => {
                    connection
                        .execute(
                            "UPDATE native_durable_execution_p_v0 SET target_snapshot_digest=?",
                            params![[56u8; 32].as_slice()],
                        )
                        .unwrap();
                }
                "replay" => {
                    connection
                        .execute(
                            "UPDATE native_durable_execution_p_v0 SET target_replay_command_ids=?",
                            params![b"not-canonical-borsh".as_slice()],
                        )
                        .unwrap();
                }
                "lifecycle" => {
                    connection
                        .execute(
                            "UPDATE native_durable_execution_p_v0 SET target_lifecycle_json=?",
                            params![b"{}".as_slice()],
                        )
                        .unwrap();
                }
                "store" => {
                    connection
                        .execute(
                            "UPDATE native_durable_execution_p_v0 SET store_id=?",
                            params![[57u8; 32].as_slice()],
                        )
                        .unwrap();
                }
                "sequence" => {
                    connection.execute("UPDATE native_application_metadata_v0 SET durable_sequence=? WHERE singleton=1", params![u64_bytes_v0(1).as_slice()]).unwrap();
                }
                _ => unreachable!(),
            }
            drop(connection);
            let error = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap_err();
            assert_eq!(
                error.code(),
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "mutation {mutation} must fail during immutable inventory preflight"
            );
        }
    }

    #[test]
    fn owner_contention_sqlite_sidecars_and_schema_drift_fail_closed() {
        let temporary = TempDir::new().unwrap();
        let (path, application, _head, _request) = initialized(&temporary);
        let busy = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap_err();
        assert_eq!(busy.code(), NativeApplicationExecutionErrorCodeV0::Busy);
        drop(application);

        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        fs::write(PathBuf::from(&wal), b"unresolved-sidecar").unwrap();
        let uncertain = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap_err();
        assert_eq!(
            uncertain.code(),
            NativeApplicationExecutionErrorCodeV0::CommitUncertain
        );
        fs::remove_file(PathBuf::from(&wal)).unwrap();

        let connection = open_writable_connection_v0(&path).unwrap();
        connection
            .execute("CREATE TABLE unexpected_schema_drift(value BLOB)", [])
            .unwrap();
        drop(connection);
        let drift = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap_err();
        assert_eq!(
            drift.code(),
            NativeApplicationExecutionErrorCodeV0::CorruptStore
        );
    }

    #[test]
    fn h1_state_sync_anchor_trusted_base_installs_without_local_p_and_accepts_first_durable_child()
    {
        let temporary = TempDir::new().unwrap();
        let (path, application, _head, execution) = initialized(&temporary);
        let proof_id = [0xA1; 32];
        let request = NativeH1StateSyncTrustedBaseRequestV0::new(proof_id, execution).unwrap();
        let confirmed = application
            .install_h1_state_sync_trusted_base_v0(&request)
            .unwrap();
        assert!(confirmed.belongs_to_application_at_path_v0(&application, &path));
        assert_eq!(confirmed.proof_id_v0(), proof_id);
        assert_eq!(confirmed.install_sequence_v0(), 2);
        assert_eq!(confirmed.head_v0().height().get(), 1);
        assert_eq!(
            confirmed.head_v0().block_id(),
            request.execution_v0().block_id()
        );

        let connection = open_immutable_connection_v0(&path).unwrap();
        assert_eq!(load_all_p_v0(&connection).unwrap().len(), 0);
        drop(connection);
        let replay = application
            .install_h1_state_sync_trusted_base_v0(&request)
            .unwrap();
        assert_eq!(replay.import_digest_v0(), confirmed.import_digest_v0());
        drop(application);

        let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
        let reopened_confirmed = reopened
            .confirm_h1_state_sync_trusted_base_exact_v0(&request)
            .unwrap();
        assert_eq!(reopened_confirmed.head_v0(), confirmed.head_v0());
        assert_eq!(
            reopened_confirmed.artifact_digest_v0(),
            confirmed.artifact_digest_v0()
        );
        assert_eq!(
            reopened_confirmed.snapshot_digest_v0(),
            confirmed.snapshot_digest_v0()
        );
        assert_eq!(
            reopened_confirmed.import_digest_v0(),
            confirmed.import_digest_v0()
        );

        let child_request = previewed_execution_request_v0(
            &reopened,
            &config(STORE_A),
            reopened_confirmed.head_v0().clone(),
            2,
            0x2a,
            2,
        );
        // Rebind the child request to the canonical BlockId derived by the
        // same header constructor used by the proof helper.  The preview
        // fixture intentionally uses a placeholder ID; a proof-bound commit
        // must name the exact header ID instead of accepting that shortcut.
        let child_config = config(STORE_A);
        let canonical_child_header = header_for_execution_v0(
            &child_request,
            &child_config.validator_set,
            2,
            child_request.timestamp_ms(),
        );
        let canonical_child_request = NativeBlockExecutionRequestV0::new(
            child_request.chain_id().clone(),
            child_request.genesis_hash(),
            child_request.parent().clone(),
            BlockIdV0::new(*canonical_child_header.id().as_bytes()).unwrap(),
            child_request.height(),
            child_request.timestamp_ms(),
            child_request.active_validator_set_id(),
            child_request.transactions().to_vec(),
            child_request.expected(),
        )
        .unwrap();
        let child = match reopened.execute_block(canonical_child_request).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            other => panic!("expected valid first child of imported h1, got {other:?}"),
        };
        let confirmed_child = reopened.confirm_durable_p_v0(&child).unwrap();
        assert_eq!(
            confirmed_child.parent_block_id_v0(),
            *reopened_confirmed.head_v0().block_id().as_bytes()
        );
        assert_eq!(confirmed_child.target_height_v0(), 2);
        drop(reopened);

        let reopened_with_child = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
        assert_eq!(
            reopened_with_child
                .confirm_durable_p_v0(&child)
                .unwrap()
                .target_height_v0(),
            2
        );
        let reopened_config = child_config;
        let authenticated_parent_timestamp_ms = request.execution_v0().timestamp_ms();
        let child_proof = signed_finality_proof_for_execution_v0(
            child.request(),
            &reopened_config.validator_set,
            &reopened_config.parameters,
            authenticated_parent_timestamp_ms,
        );
        let child_block_id =
            BlockIdV0::new(*child_proof.finalized_block().header().id().as_bytes()).unwrap();
        let committed_child = reopened_with_child
            .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                child,
                child_proof.clone(),
                authenticated_parent_timestamp_ms,
            ))
            .unwrap();
        assert_eq!(committed_child.head().height().get(), 2);
        drop(reopened_with_child);

        let reopened_after_child_commit =
            DurableNativeApplicationV0::open(&path, reopened_config).unwrap();
        let committed_head = reopened_after_child_commit
            .confirmed_committed_head_v0()
            .unwrap();
        assert_eq!(committed_head, committed_child.head().clone());
        assert_eq!(committed_head.height().get(), 2);
        let proof_read = reopened_after_child_commit
            .read_finalized_by_block_id_with_proof_v0(
                child_block_id,
                &child_proof,
                authenticated_parent_timestamp_ms,
            )
            .unwrap();
        assert_eq!(proof_read.confirmed_head_v0(), &committed_head);
        assert_eq!(proof_read.finalized_head_v0().unwrap(), committed_head);
        assert_eq!(
            proof_read.receipts_root_v0().as_bytes(),
            child_proof
                .finalized_block()
                .header()
                .receipts_root()
                .as_bytes()
        );
        assert_eq!(
            proof_read
                .durable_row_v0()
                .target_head_v0()
                .unwrap()
                .height()
                .get(),
            committed_head.height().get()
        );
    }

    #[test]
    fn h1_state_sync_trusted_base_rejects_foreign_proof_request_and_used_store() {
        let temporary = TempDir::new().unwrap();
        let (_path, application, _head, execution) = initialized(&temporary);
        let request = NativeH1StateSyncTrustedBaseRequestV0::new([0xA1; 32], execution).unwrap();
        let _confirmed = application
            .install_h1_state_sync_trusted_base_v0(&request)
            .unwrap();
        let foreign =
            NativeH1StateSyncTrustedBaseRequestV0::new([0xA2; 32], request.execution_v0().clone())
                .unwrap();
        assert_eq!(
            application
                .confirm_h1_state_sync_trusted_base_exact_v0(&foreign)
                .unwrap_err()
                .code(),
            NativeApplicationExecutionErrorCodeV0::BindingMismatch
        );

        let second = TempDir::new().unwrap();
        let (_path, used, _head, execution) = initialized(&second);
        let executed = match used.execute_block(execution).unwrap() {
            NativeBlockExecutionResultV0::Valid(value) => value,
            NativeBlockExecutionResultV0::DeterministicallyInvalid(_)
            | NativeBlockExecutionResultV0::Unavailable(_) => unreachable!(),
        };
        let used_request =
            NativeH1StateSyncTrustedBaseRequestV0::new([0xA3; 32], executed.request().clone())
                .unwrap();
        assert_eq!(
            used.install_h1_state_sync_trusted_base_v0(&used_request)
                .unwrap_err()
                .code(),
            NativeApplicationExecutionErrorCodeV0::NonContiguous
        );
    }

    #[test]
    fn h1_state_sync_trusted_base_tamper_is_rejected_on_reopen() {
        let temporary = TempDir::new().unwrap();
        let (path, application, _head, execution) = initialized(&temporary);
        let request = NativeH1StateSyncTrustedBaseRequestV0::new([0xA1; 32], execution).unwrap();
        let _confirmed = application
            .install_h1_state_sync_trusted_base_v0(&request)
            .unwrap();
        drop(application);

        let connection = open_writable_connection_v0(&path).unwrap();
        connection
            .execute(
                "UPDATE native_h1_state_sync_trusted_base_v0 SET proof_id=? WHERE singleton=1",
                params![[0xFF_u8; 32].as_slice()],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            DurableNativeApplicationV0::open(&path, config(STORE_A))
                .unwrap_err()
                .code(),
            NativeApplicationExecutionErrorCodeV0::CorruptStore
        );
    }

    #[test]
    fn wrong_expected_root_and_commit_without_exact_p_are_rejected() {
        let temporary = TempDir::new().unwrap();
        let (_path, application, _head, request) = initialized(&temporary);
        let config = config(STORE_A);
        let executed_without_p = computed_executed_without_p(&config, &request);
        let missing_p = application
            .commit_block(NativeApplicationCommitRequestV0::new(executed_without_p))
            .unwrap_err();
        assert_eq!(
            missing_p.code(),
            NativeApplicationExecutionErrorCodeV0::NonContiguous
        );
        let wrong = NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            request.block_id(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            request.transactions().to_vec(),
            NativeExpectedBlockCommitmentsV0::new(
                Hash32V0::new([99; 32]),
                request.expected().post_state_root(),
                request.expected().receipts_root(),
                request.expected().evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            application.execute_block(wrong).unwrap(),
            NativeBlockExecutionResultV0::DeterministicallyInvalid(_)
        ));
    }
}
