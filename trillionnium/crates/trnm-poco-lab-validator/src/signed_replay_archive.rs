//! Crash-ordered signed Proposal/QC archive for deployed laboratory recovery.
//!
//! The append-only entry log is fsynced before its independently replaced
//! head file.  Recovery accepts either an exact head or the sole audited
//! one-entry local-ahead window left by process loss after the log fsync and
//! before the head replacement.  Every entry is content addressed and joined
//! to one manifest/config/validator context plus the preceding entry hash.
//!
//! This archive is deliberately not activation authority.  Its only consuming
//! recovery seam supplies exact signed Proposal/QC material to the Node's
//! already replay-fenced deployed recovery owner and returns a still-inert
//! typed owner retaining both filesystem pins.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    CertifiedHeaderV0, ConsensusParametersV0, FinalityProofV0, QcRef, QuorumCertificate,
    SignatureBytes, SignedProposalV0, ValidatorSet, Vote,
};
use trnm_poco_node::{
    PocoNodeDeployedLabAuthenticatedReplayFactsV0, PocoNodeDeployedLabAuthenticatedReplayOwnerV0,
    PocoNodeDeployedLabOrdinaryRecoveryOwnerV0, PocoNodeDeployedLabProcess2CaughtUpOwnerV1,
    PocoNodeDeployedLabProcess2RecoveryFactsV0, PocoNodeDeployedLabProcess2RecoveryOwnerV0,
    PocoNodeDeployedLabRecoveryFactsV0, PocoNodeDeployedLabSignedReplayEntryV0,
    PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1, PocoNodeDeployedLabZeroDeltaRestartCutV1,
};

use crate::{
    bootstrap_material::VerifiedPublicBootstrapInitialCutV1,
    config::{LoadedValidatorConfig, PublicReportVerifierContext},
    continuous_runtime::ContinuousSignerLifetimeBoundsV0,
    crypto::LabFileWatermark,
    frame::MAX_FRAME_PAYLOAD_BYTES,
    process_event::CleanStoppedJournalCutV1,
    wire::{decode_quorum_certificate, encode_quorum_certificate, UnboundProposalV0},
    workload_corpus::{WORKLOAD_BLOCK_TIME_STEP_MS_V1, WORKLOAD_GENESIS_TIMESTAMP_MS_V1},
};

const ARCHIVE_DIRECTORY_V1: &str = "signed-replay-archive-v1";
const CONTEXT_FILE_V1: &str = "context.json";
const ENTRY_FILE_V1: &str = "entries.jsonl";
const HEAD_FILE_V1: &str = "head.json";
const NEXT_HEAD_FILE_V1: &str = "head.next";
const REPAIR_TOMBSTONE_FILE_V1: &str = "repair-tombstone.json";
const SCHEMA_VERSION_V1: u32 = 1;
const MAXIMUM_CONTEXT_BYTES_V1: u64 = 64 * 1024;
const MAXIMUM_HEAD_BYTES_V1: u64 = 16 * 1024;
const MAXIMUM_REPAIR_TOMBSTONE_BYTES_V1: u64 = 16 * 1024;
pub(crate) const MAXIMUM_ENTRY_COUNT_V1: u64 = 8_192;
const MAXIMUM_ENTRY_LINE_BYTES_V1: usize = MAX_FRAME_PAYLOAD_BYTES * 2 + 4_096;
const MAXIMUM_ENTRY_FILE_BYTES_V1: u64 =
    MAXIMUM_ENTRY_COUNT_V1 * MAXIMUM_ENTRY_LINE_BYTES_V1 as u64;
const CONTEXT_DOMAIN_V1: &[u8] = b"trnm.poco-g3.signed-replay-archive.context.v1";
const GENESIS_DOMAIN_V1: &[u8] = b"trnm.poco-g3.signed-replay-archive.genesis.v1";
const CONTENT_DOMAIN_V1: &[u8] = b"trnm.poco-g3.signed-replay-archive.content.v1";
const RECORD_DOMAIN_V1: &[u8] = b"trnm.poco-g3.signed-replay-archive.record.v1";
const REPAIR_TOMBSTONE_DOMAIN_V1: &[u8] = b"trnm.poco-g3.signed-replay-archive.repair-tombstone.v1";
const TERMINAL_SEAL_FILE_V1: &str = "archive-terminal-seal.json";
const TERMINAL_SEAL_SCHEMA_VERSION_V1: u32 = 1;
const MAXIMUM_TERMINAL_SEAL_BYTES_V1: u64 = 256 * 1024;
const TERMINAL_SEAL_BODY_DOMAIN_V1: &[u8] = b"trnm.poco-g3.replay-archive-terminal-seal.body.v1";
const TERMINAL_SEAL_SIGNATURE_DOMAIN_V1: &[u8] =
    b"trnm.poco-g3.replay-archive-terminal-seal.signature.v1";
const FINALIZED_PREFIX_CHAIN_ROOT_DOMAIN_V0: &[u8] =
    b"trnm.consensus-core.finalized-prefix-chain-root.v0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayArchiveContextJsonV1 {
    schema_version: u32,
    run_id: String,
    chain_id: String,
    genesis_hash: String,
    validator_set_id: String,
    local_validator_id: String,
    local_consensus_public_key: String,
    coordinator_manifest_sha256: String,
    validator_set_sha256: String,
    topology_sha256: String,
    config_sha256: String,
    candidate_source_sha256: String,
    binary_sha256: String,
    workload_corpus_sha256: String,
    workload_policy_sha256: String,
    ordinary_start_height: u64,
    maximum_timeout_view_advances: u64,
    maximum_proposal_entries: u64,
    maximum_quorum_certificate_entries: u64,
    maximum_archive_entries: u64,
    context_sha256: String,
}

/// Create-once provenance that durably records an exact crash-window head
/// repair across ordinary process loss. It is deliberately unsigned local
/// durability evidence, but is context-addressed, canonical,
/// single-link/private, and never removable through an archive API. Its
/// presence excludes sealing; same-UID deletion and whole-namespace rollback
/// remain outside this archive-local authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayArchiveRepairTombstoneV1 {
    schema_version: u32,
    context_sha256: String,
    reason: String,
    log_head_sequence: u64,
    log_head_record_sha256: String,
    durable_head_sequence: u64,
    durable_head_record_sha256: String,
    next_head_sequence: Option<u64>,
    next_head_record_sha256: Option<String>,
    tombstone_sha256: String,
}

impl ReplayArchiveRepairTombstoneV1 {
    fn new_v1(
        context_sha256: [u8; 32],
        reason: &'static str,
        log_head: ReplayArchiveHeadV1,
        durable_head: ReplayArchiveHeadV1,
        next_head: Option<ReplayArchiveHeadV1>,
    ) -> Result<Self> {
        let mut value = Self {
            schema_version: SCHEMA_VERSION_V1,
            context_sha256: hex::encode(context_sha256),
            reason: reason.to_owned(),
            log_head_sequence: log_head.sequence,
            log_head_record_sha256: hex::encode(log_head.record_sha256),
            durable_head_sequence: durable_head.sequence,
            durable_head_record_sha256: hex::encode(durable_head.record_sha256),
            next_head_sequence: next_head.map(|head| head.sequence),
            next_head_record_sha256: next_head.map(|head| hex::encode(head.record_sha256)),
            tombstone_sha256: String::new(),
        };
        let digest = value.computed_sha256_v1()?;
        value.tombstone_sha256 = hex::encode(digest);
        value.validate_v1(context_sha256)?;
        Ok(value)
    }

    fn computed_sha256_v1(&self) -> Result<[u8; 32]> {
        let mut body = self.clone();
        body.tombstone_sha256.clear();
        let bytes = serde_json::to_vec(&body).context("encode repair tombstone body")?;
        Ok(hash_parts_v1(REPAIR_TOMBSTONE_DOMAIN_V1, &[&bytes]))
    }

    fn validate_v1(&self, context_sha256: [u8; 32]) -> Result<()> {
        let log_hash = decode_hex32_v1(&self.log_head_record_sha256, "repair tombstone log head")?;
        let durable_hash = decode_hex32_v1(
            &self.durable_head_record_sha256,
            "repair tombstone durable head",
        )?;
        let next_hash = self
            .next_head_record_sha256
            .as_deref()
            .map(|value| decode_hex32_v1(value, "repair tombstone next head"))
            .transpose()?;
        ensure!(
            self.schema_version == SCHEMA_VERSION_V1
                && decode_hex32_v1(&self.context_sha256, "repair tombstone context")?
                    == context_sha256
                && log_hash != [0; 32]
                && durable_hash != [0; 32]
                && decode_hex32_v1(&self.tombstone_sha256, "repair tombstone digest")?
                    == self.computed_sha256_v1()?,
            "repair tombstone is not canonical context-bound provenance"
        );
        match self.reason.as_str() {
            "next-head-present" => ensure!(
                self.next_head_sequence == Some(self.log_head_sequence)
                    && next_hash == Some(log_hash)
                    && (self.durable_head_sequence == self.log_head_sequence
                        || self.durable_head_sequence.checked_add(1)
                            == Some(self.log_head_sequence)),
                "next-head repair tombstone has impossible coordinates"
            ),
            "one-ahead-log" => ensure!(
                self.next_head_sequence.is_none()
                    && next_hash.is_none()
                    && self.durable_head_sequence.checked_add(1) == Some(self.log_head_sequence),
                "one-ahead repair tombstone has impossible coordinates"
            ),
            _ => bail!("repair tombstone has an unknown reason"),
        }
        Ok(())
    }

    fn same_repair_event_v1(&self, other: &Self) -> bool {
        self.context_sha256 == other.context_sha256
            && self.reason == other.reason
            && self.log_head_sequence == other.log_head_sequence
            && self.log_head_record_sha256 == other.log_head_record_sha256
            && self.durable_head_sequence == other.durable_head_sequence
            && self.durable_head_record_sha256 == other.durable_head_record_sha256
            && self.next_head_sequence == other.next_head_sequence
            && self.next_head_record_sha256 == other.next_head_record_sha256
    }

    fn canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).context("encode repair tombstone")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Validator-signed, post-CleanStop commitment to one exact immutable replay
/// archive.  It is an evidence artifact only: no recovery, catch-up, runner,
/// completion, G3, or production authority is released by this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayArchiveTerminalSealV1 {
    schema_version: u32,
    run_id: String,
    validator_id: String,
    validator_set_id: String,
    validator_set_sha256: String,
    topology_sha256: String,
    coordinator_manifest_sha256: String,
    candidate_source_sha256: String,
    binary_sha256: String,
    config_sha256: String,
    fleet_start_certificate_sha256: String,
    process_instance: u64,
    clean_stop_journal_sequence: u64,
    clean_stop_journal_sha256: String,
    finalized_height: u64,
    finalized_block_id: String,
    finalized_state_root: String,
    finalized_chain_root: String,
    finality_proof_id: String,
    finality_child_block_id: String,
    finality_grandchild_block_id: String,
    archive_context_sha256: String,
    archive_context_file_sha256: String,
    archive_context_file_bytes: u64,
    archive_entries_file_sha256: String,
    archive_entries_file_bytes: u64,
    archive_head_file_sha256: String,
    archive_head_file_bytes: u64,
    terminal_archive_sequence: u64,
    terminal_archive_record_sha256: String,
    proposal_count: u64,
    quorum_certificate_count: u64,
    body_sha256: String,
    signature: String,
}

impl ReplayArchiveTerminalSealV1 {
    fn computed_body_sha256_v1(&self) -> Result<[u8; 32]> {
        let mut unsigned = self.clone();
        unsigned.body_sha256.clear();
        unsigned.signature.clear();
        let canonical =
            serde_json::to_vec(&unsigned).context("encode terminal replay archive seal body")?;
        Ok(hash_parts_v1(TERMINAL_SEAL_BODY_DOMAIN_V1, &[&canonical]))
    }

    fn canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).context("encode terminal replay archive seal")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayArchiveTerminalSnapshotV1 {
    context_file_sha256: [u8; 32],
    context_file_bytes: u64,
    entries_file_sha256: [u8; 32],
    entries_file_bytes: u64,
    head_file_sha256: [u8; 32],
    head_file_bytes: u64,
    head: ReplayArchiveHeadV1,
    proposal_count: u64,
    quorum_certificate_count: u64,
}

/// Per-certificate signature-share accounting from strict QC admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayArchiveVerifiedCertificateV1 {
    pub certificate_id: String,
    pub signature_share_count: u64,
}

/// Secret-free output of the strictly read-only archive verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayArchiveVerificationV1 {
    pub schema_version: u32,
    pub status: String,
    pub run_id: String,
    pub validator_id: String,
    pub fleet_start_certificate_sha256: String,
    pub clean_stop_journal_sequence: u64,
    pub clean_stop_journal_sha256: String,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finalized_state_root: String,
    pub finalized_chain_root: String,
    pub archive_covers_signed_final_tip: bool,
    pub finality_proof_id: String,
    pub finality_child_block_id: String,
    pub finality_grandchild_block_id: String,
    pub archive_context_sha256: String,
    pub archive_context_file_sha256: String,
    pub archive_entries_file_sha256: String,
    pub archive_head_file_sha256: String,
    pub terminal_archive_sequence: u64,
    pub terminal_archive_record_sha256: String,
    pub proposal_count: u64,
    pub quorum_certificate_count: u64,
    pub quorum_certificate_signature_share_count: u64,
    pub unique_quorum_certificates: Vec<ReplayArchiveVerifiedCertificateV1>,
    pub negative_control_certificate_id: String,
    pub negative_control_signer_id: String,
    pub invalid_signature_control_rejected: bool,
    pub input_sha256_unchanged: bool,
    pub observer_verified_nonempty_workload: bool,
    pub observer_verified_finality: bool,
    pub validator_run_completed: bool,
    pub g3_evidence_complete: bool,
    pub geo_wan_evidence: bool,
    pub production_activation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignedReplayArchiveBoundsV1 {
    maximum_timeout_view_advances: u64,
    maximum_proposal_entries: u64,
    maximum_quorum_certificate_entries: u64,
    maximum_archive_entries: u64,
}

/// Narrow terminal-evidence projection of one already authenticated validator
/// configuration.  The production implementation is [`LoadedValidatorConfig`];
/// keeping the writer generic over this projection lets the unit suite drive
/// the exact production writer with a real signed journal and an independently
/// authored archive, without adding a field-selected constructor to
/// `LoadedValidatorConfig`.
trait ReplayArchiveTerminalConfigV1 {
    fn run_root(&self) -> &Path;
    fn run_id(&self) -> &str;
    fn local_validator(&self) -> trnm_consensus_types::ValidatorId;
    fn validator_set(&self) -> &ValidatorSet;
    fn consensus_parameters(&self) -> &ConsensusParametersV0;
    fn consensus_signing_key(&self) -> &SigningKey;
    fn validator_set_sha256(&self) -> [u8; 32];
    fn topology_sha256(&self) -> [u8; 32];
    fn config_sha256(&self) -> [u8; 32];
    fn coordinator_manifest_sha256(&self) -> [u8; 32];
    fn binary_sha256(&self) -> [u8; 32];
    fn candidate_source_sha256(&self) -> [u8; 32];
    fn ordinary_start_height(&self) -> u64;
    fn workload_corpus_sha256(&self) -> [u8; 32];
    fn workload_policy_sha256(&self) -> [u8; 32];
}

impl ReplayArchiveTerminalConfigV1 for LoadedValidatorConfig {
    fn run_root(&self) -> &Path {
        LoadedValidatorConfig::run_root(self)
    }

    fn run_id(&self) -> &str {
        LoadedValidatorConfig::run_id(self)
    }

    fn local_validator(&self) -> trnm_consensus_types::ValidatorId {
        LoadedValidatorConfig::local_validator(self)
    }

    fn validator_set(&self) -> &ValidatorSet {
        LoadedValidatorConfig::validator_set(self)
    }

    fn consensus_parameters(&self) -> &ConsensusParametersV0 {
        LoadedValidatorConfig::consensus_parameters(self)
    }

    fn consensus_signing_key(&self) -> &SigningKey {
        LoadedValidatorConfig::consensus_signing_key(self)
    }

    fn validator_set_sha256(&self) -> [u8; 32] {
        LoadedValidatorConfig::validator_set_sha256(self)
    }

    fn topology_sha256(&self) -> [u8; 32] {
        LoadedValidatorConfig::topology_sha256(self)
    }

    fn config_sha256(&self) -> [u8; 32] {
        LoadedValidatorConfig::config_sha256(self)
    }

    fn coordinator_manifest_sha256(&self) -> [u8; 32] {
        LoadedValidatorConfig::coordinator_manifest_sha256(self)
    }

    fn binary_sha256(&self) -> [u8; 32] {
        LoadedValidatorConfig::binary_sha256(self)
    }

    fn candidate_source_sha256(&self) -> [u8; 32] {
        LoadedValidatorConfig::candidate_source_sha256(self)
    }

    fn ordinary_start_height(&self) -> u64 {
        LoadedValidatorConfig::ordinary_start_height(self)
    }

    fn workload_corpus_sha256(&self) -> [u8; 32] {
        LoadedValidatorConfig::workload_corpus_sha256(self)
    }

    fn workload_policy_sha256(&self) -> [u8; 32] {
        LoadedValidatorConfig::workload_policy_sha256(self)
    }
}

impl SignedReplayArchiveBoundsV1 {
    pub(crate) fn from_signer_lifetime_v1(
        signer: ContinuousSignerLifetimeBoundsV0,
    ) -> Result<Self> {
        let maximum_proposal_entries = signer.maximum_local_vote_intents_v0();
        let maximum_quorum_certificate_entries = maximum_proposal_entries
            .checked_add(1)
            .context("signed replay QC ceiling overflows")?;
        let maximum_archive_entries = maximum_proposal_entries
            .checked_add(maximum_quorum_certificate_entries)
            .context("signed replay aggregate ceiling overflows")?;
        ensure!(
            maximum_archive_entries <= MAXIMUM_ENTRY_COUNT_V1,
            "bounded campaign requires {maximum_archive_entries} signed replay entries, exceeding archive capacity {MAXIMUM_ENTRY_COUNT_V1}"
        );
        Ok(Self {
            maximum_timeout_view_advances: signer.maximum_timeout_view_advances_v0(),
            maximum_proposal_entries,
            maximum_quorum_certificate_entries,
            maximum_archive_entries,
        })
    }

    #[cfg(test)]
    pub(crate) const fn maximum_timeout_view_advances_v1(self) -> u64 {
        self.maximum_timeout_view_advances
    }

    pub(crate) const fn maximum_proposal_entries_v1(self) -> u64 {
        self.maximum_proposal_entries
    }

    pub(crate) const fn maximum_quorum_certificate_entries_v1(self) -> u64 {
        self.maximum_quorum_certificate_entries
    }

    pub(crate) const fn maximum_archive_entries_v1(self) -> u64 {
        self.maximum_archive_entries
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayArchiveContextV1 {
    json: ReplayArchiveContextJsonV1,
    digest: [u8; 32],
}

impl ReplayArchiveContextV1 {
    fn from_config_v1<C: ReplayArchiveTerminalConfigV1 + ?Sized>(
        config: &C,
        bounds: SignedReplayArchiveBoundsV1,
    ) -> Result<Self> {
        let local = config
            .validator_set()
            .validator(config.local_validator())
            .ok_or_else(|| anyhow!("archive local validator is absent from validator set"))?;
        Self::from_fields_v1(ReplayArchiveContextJsonV1 {
            schema_version: SCHEMA_VERSION_V1,
            run_id: config.run_id().to_owned(),
            chain_id: config.validator_set().chain_id().as_str().to_owned(),
            genesis_hash: hex::encode(config.validator_set().genesis_hash().as_bytes()),
            validator_set_id: hex::encode(config.validator_set().id().as_bytes()),
            local_validator_id: hex::encode(config.local_validator().as_bytes()),
            local_consensus_public_key: hex::encode(local.consensus_key().as_bytes()),
            coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
            validator_set_sha256: hex::encode(config.validator_set_sha256()),
            topology_sha256: hex::encode(config.topology_sha256()),
            config_sha256: hex::encode(config.config_sha256()),
            candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
            binary_sha256: hex::encode(config.binary_sha256()),
            workload_corpus_sha256: hex::encode(config.workload_corpus_sha256()),
            workload_policy_sha256: hex::encode(config.workload_policy_sha256()),
            ordinary_start_height: config.ordinary_start_height(),
            maximum_timeout_view_advances: bounds.maximum_timeout_view_advances,
            maximum_proposal_entries: bounds.maximum_proposal_entries,
            maximum_quorum_certificate_entries: bounds.maximum_quorum_certificate_entries,
            maximum_archive_entries: bounds.maximum_archive_entries,
            context_sha256: String::new(),
        })
    }

    fn from_fields_v1(mut json: ReplayArchiveContextJsonV1) -> Result<Self> {
        ensure!(
            json.schema_version == SCHEMA_VERSION_V1,
            "wrong archive context schema"
        );
        ensure!(
            !json.run_id.is_empty() && !json.chain_id.is_empty(),
            "empty archive context"
        );
        let genesis_hash = decode_hex32_v1(&json.genesis_hash, "context genesis")?;
        let validator_set_id = decode_hex32_v1(&json.validator_set_id, "context validator set")?;
        let local_validator_id =
            decode_hex32_v1(&json.local_validator_id, "context local validator")?;
        let local_consensus_public_key =
            decode_hex32_v1(&json.local_consensus_public_key, "context consensus key")?;
        let coordinator_manifest_sha256 =
            decode_hex32_v1(&json.coordinator_manifest_sha256, "context manifest")?;
        let validator_set_sha256 =
            decode_hex32_v1(&json.validator_set_sha256, "context validator set file")?;
        let topology_sha256 = decode_hex32_v1(&json.topology_sha256, "context topology")?;
        let config_sha256 = decode_hex32_v1(&json.config_sha256, "context config")?;
        let candidate_source_sha256 =
            decode_hex32_v1(&json.candidate_source_sha256, "context source")?;
        let binary_sha256 = decode_hex32_v1(&json.binary_sha256, "context binary")?;
        let workload_corpus_sha256 =
            decode_hex32_v1(&json.workload_corpus_sha256, "context workload corpus")?;
        let workload_policy_sha256 =
            decode_hex32_v1(&json.workload_policy_sha256, "context workload policy")?;
        ensure!(
            json.maximum_proposal_entries > 0
                && json.maximum_quorum_certificate_entries
                    == json
                        .maximum_proposal_entries
                        .checked_add(1)
                        .context("archive context QC ceiling overflows")?
                && json.maximum_archive_entries
                    == json
                        .maximum_proposal_entries
                        .checked_add(json.maximum_quorum_certificate_entries)
                        .context("archive context aggregate ceiling overflows")?
                && json.maximum_archive_entries <= MAXIMUM_ENTRY_COUNT_V1,
            "archive context capacity fields are inconsistent"
        );
        let ordinary_start_height = json.ordinary_start_height.to_be_bytes();
        let maximum_timeout_view_advances = json.maximum_timeout_view_advances.to_be_bytes();
        let maximum_proposal_entries = json.maximum_proposal_entries.to_be_bytes();
        let maximum_quorum_certificate_entries =
            json.maximum_quorum_certificate_entries.to_be_bytes();
        let maximum_archive_entries = json.maximum_archive_entries.to_be_bytes();
        let digest = hash_parts_v1(
            CONTEXT_DOMAIN_V1,
            &[
                json.run_id.as_bytes(),
                json.chain_id.as_bytes(),
                &genesis_hash,
                &validator_set_id,
                &local_validator_id,
                &local_consensus_public_key,
                &coordinator_manifest_sha256,
                &validator_set_sha256,
                &topology_sha256,
                &config_sha256,
                &candidate_source_sha256,
                &binary_sha256,
                &workload_corpus_sha256,
                &workload_policy_sha256,
                &ordinary_start_height,
                &maximum_timeout_view_advances,
                &maximum_proposal_entries,
                &maximum_quorum_certificate_entries,
                &maximum_archive_entries,
            ],
        );
        if json.context_sha256.is_empty() {
            json.context_sha256 = hex::encode(digest);
        } else {
            ensure!(
                decode_hex32_v1(&json.context_sha256, "context digest")? == digest,
                "archive context digest differs from its exact fields"
            );
        }
        Ok(Self { json, digest })
    }

    fn canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(&self.json).context("encode replay archive context")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReplayArchiveEntryKindV1 {
    Proposal,
    QuorumCertificate,
}

impl ReplayArchiveEntryKindV1 {
    const fn label_v1(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::QuorumCertificate => "quorum-certificate",
        }
    }

    const fn code_v1(self) -> u8 {
        match self {
            Self::Proposal => 1,
            Self::QuorumCertificate => 2,
        }
    }

    fn parse_v1(value: &str) -> Result<Self> {
        match value {
            "proposal" => Ok(Self::Proposal),
            "quorum-certificate" => Ok(Self::QuorumCertificate),
            _ => bail!("unknown signed replay archive entry kind"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReplayArchiveCoordinateV1 {
    kind: ReplayArchiveEntryKindV1,
    height: u64,
    view: u64,
    block_id: [u8; 32],
}

#[derive(Debug, Clone)]
struct ReplayArchiveStatementV1 {
    coordinate: ReplayArchiveCoordinateV1,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayArchiveEntryJsonV1 {
    schema_version: u32,
    sequence: u64,
    context_sha256: String,
    previous_record_sha256: String,
    kind: String,
    height: u64,
    view: u64,
    block_id: String,
    content_sha256: String,
    payload_hex: String,
    record_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayArchiveHeadJsonV1 {
    schema_version: u32,
    sequence: u64,
    context_sha256: Hex32V1,
    record_sha256: Hex32V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct Hex32V1(#[serde(with = "hex32_serde_v1")] [u8; 32]);

mod hex32_serde_v1 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes = hex::decode(&value).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hex value"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayArchiveHeadV1 {
    sequence: u64,
    record_sha256: [u8; 32],
}

impl ReplayArchiveHeadV1 {
    fn genesis_v1(context_sha256: [u8; 32]) -> Self {
        Self {
            sequence: 0,
            record_sha256: hash_parts_v1(GENESIS_DOMAIN_V1, &[&context_sha256]),
        }
    }

    fn json_v1(self, context_sha256: [u8; 32]) -> ReplayArchiveHeadJsonV1 {
        ReplayArchiveHeadJsonV1 {
            schema_version: SCHEMA_VERSION_V1,
            sequence: self.sequence,
            context_sha256: Hex32V1(context_sha256),
            record_sha256: Hex32V1(self.record_sha256),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentityV1 {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

impl FileIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            links: metadata.nlink(),
        }
    }

    fn from_file_v1(file: &File) -> Result<Self> {
        let metadata = file
            .metadata()
            .context("inspect pinned replay archive file")?;
        Ok(Self::from_metadata_v1(&metadata))
    }

    fn matches_metadata_v1(self, metadata: &fs::Metadata) -> bool {
        metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.uid() == self.owner
            && metadata.permissions().mode() & 0o7777 == self.mode
            && metadata.nlink() == self.links
    }

    fn matches_file_v1(self, file: &File) -> Result<bool> {
        let metadata = file
            .metadata()
            .context("reinspect pinned replay archive file")?;
        Ok(self.matches_metadata_v1(&metadata))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayArchiveEntryIndexV1 {
    coordinate: ReplayArchiveCoordinateV1,
    content_sha256: [u8; 32],
    record_sha256: [u8; 32],
    offset: u64,
    line_bytes: usize,
}

#[derive(Debug, Clone)]
struct AuthenticatedReplayProposalV1 {
    proposal: SignedProposalV0,
    authenticated_parent_timestamp_ms: u64,
}

#[derive(Debug)]
struct StrictReplayArchiveSemanticsV1 {
    proposals: BTreeMap<[u8; 32], AuthenticatedReplayProposalV1>,
    certificates: BTreeMap<[u8; 32], QuorumCertificate>,
    signature_share_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedFinalTipCoverageV1 {
    proof_id: [u8; 32],
    child_block_id: [u8; 32],
    grandchild_block_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalSealCutContextV1 {
    run_id: String,
    validator_id: trnm_consensus_types::ValidatorId,
    validator_set_id: [u8; 32],
    coordinator_manifest_sha256: [u8; 32],
    validator_set_sha256: [u8; 32],
    config_sha256: [u8; 32],
    candidate_source_sha256: [u8; 32],
    binary_sha256: [u8; 32],
}

impl TerminalSealCutContextV1 {
    fn from_config_v1<C: ReplayArchiveTerminalConfigV1 + ?Sized>(config: &C) -> Self {
        Self {
            run_id: config.run_id().to_owned(),
            validator_id: config.local_validator(),
            validator_set_id: *config.validator_set().id().as_bytes(),
            coordinator_manifest_sha256: config.coordinator_manifest_sha256(),
            validator_set_sha256: config.validator_set_sha256(),
            config_sha256: config.config_sha256(),
            candidate_source_sha256: config.candidate_source_sha256(),
            binary_sha256: config.binary_sha256(),
        }
    }

    fn require_exact_cut_v1(&self, clean_stop: &CleanStoppedJournalCutV1) -> Result<()> {
        ensure!(
            clean_stop.run_id() == self.run_id
                && clean_stop.validator_id() == self.validator_id
                && clean_stop.validator_set_id() == self.validator_set_id
                && clean_stop.coordinator_manifest_sha256() == self.coordinator_manifest_sha256
                && clean_stop.validator_set_sha256() == self.validator_set_sha256
                && clean_stop.config_sha256() == self.config_sha256
                && clean_stop.candidate_source_sha256() == self.candidate_source_sha256
                && clean_stop.binary_sha256() == self.binary_sha256,
            "CleanStop cut context differs from the loaded validator"
        );
        Ok(())
    }
}

/// Read-only facts for one completely audited archive head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignedReplayArchiveFactsV1 {
    context_sha256: [u8; 32],
    sequence: u64,
    record_sha256: [u8; 32],
}

impl SignedReplayArchiveFactsV1 {
    pub(crate) const fn context_sha256_v1(self) -> [u8; 32] {
        self.context_sha256
    }

    pub(crate) const fn sequence_v1(self) -> u64 {
        self.sequence
    }

    pub(crate) const fn record_sha256_v1(self) -> [u8; 32] {
        self.record_sha256
    }
}

/// Process-affined owner of the exact append-only archive.
pub(crate) struct SignedReplayArchiveV1 {
    root: PathBuf,
    context: ReplayArchiveContextV1,
    directory: File,
    entries_file: File,
    context_file: File,
    head_file: File,
    directory_identity: FileIdentityV1,
    entries_identity: FileIdentityV1,
    context_identity: FileIdentityV1,
    head_identity: FileIdentityV1,
    repair_tombstone_file: Option<File>,
    repair_tombstone_identity: Option<FileIdentityV1>,
    entries_len: u64,
    head: ReplayArchiveHeadV1,
    index: BTreeMap<ReplayArchiveCoordinateV1, ReplayArchiveEntryIndexV1>,
    owner_pid: u32,
    fail_stopped: bool,
    historically_repaired: bool,
}

impl std::fmt::Debug for SignedReplayArchiveV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedReplayArchiveV1")
            .field("root", &self.root)
            .field("head", &self.head)
            .field("entries", &self.index.len())
            .finish_non_exhaustive()
    }
}

impl SignedReplayArchiveV1 {
    pub(crate) fn initialize_new_v1(
        config: &LoadedValidatorConfig,
        bounds: SignedReplayArchiveBoundsV1,
    ) -> Result<Self> {
        let context = ReplayArchiveContextV1::from_config_v1(config, bounds)?;
        let root = config.run_root().join(ARCHIVE_DIRECTORY_V1);
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&root)
            .with_context(|| format!("create fresh replay archive {}", root.display()))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .context("set fresh replay archive directory permissions")?;
        let root = require_archive_directory_v1(&root)?;
        write_new_private_file_v1(&root.join(CONTEXT_FILE_V1), &context.canonical_bytes_v1()?)?;
        write_new_private_file_v1(&root.join(ENTRY_FILE_V1), &[])?;
        let directory = open_directory_pinned_v1(&root)?;
        FileExt::try_lock_exclusive(&directory).context("lock fresh replay archive directory")?;
        write_head_atomic_v1(
            &root,
            context.digest,
            ReplayArchiveHeadV1::genesis_v1(context.digest),
            &directory,
        )?;
        drop(directory);
        Self::open_expected_v1(config, bounds)
    }

    pub(crate) fn open_existing_v1(
        config: &LoadedValidatorConfig,
        bounds: SignedReplayArchiveBoundsV1,
    ) -> Result<Self> {
        Self::open_expected_v1(config, bounds)
    }

    fn open_expected_v1(
        config: &LoadedValidatorConfig,
        bounds: SignedReplayArchiveBoundsV1,
    ) -> Result<Self> {
        let expected = ReplayArchiveContextV1::from_config_v1(config, bounds)?;
        let root = require_archive_directory_v1(&config.run_root().join(ARCHIVE_DIRECTORY_V1))?;
        let directory = open_directory_pinned_v1(&root)?;
        FileExt::try_lock_exclusive(&directory).context("lock replay archive directory")?;
        validate_inventory_v1(&root)?;
        let context_file = open_private_file_v1(&root.join(CONTEXT_FILE_V1), false)?;
        let observed_context: ReplayArchiveContextJsonV1 =
            read_bounded_json_v1(&context_file, MAXIMUM_CONTEXT_BYTES_V1, "archive context")?;
        let observed_context = ReplayArchiveContextV1::from_fields_v1(observed_context)?;
        ensure!(
            observed_context == expected,
            "replay archive context differs from loaded validator"
        );
        let mut entries_file = open_private_file_v1(&root.join(ENTRY_FILE_V1), true)?;
        let (head_from_log, tail_predecessor, index, entries_len, _entries_sha256) =
            audit_entry_log_v1(
                &mut entries_file,
                expected.digest,
                expected.json.maximum_archive_entries,
            )?;
        require_index_within_context_capacity_v1(&index, &expected)?;
        let historically_repaired = repair_or_reject_head_v1(
            &root,
            expected.digest,
            head_from_log,
            tail_predecessor,
            &directory,
        )?;
        let head_file = open_private_file_v1(&root.join(HEAD_FILE_V1), false)?;
        let observed_head = read_head_from_file_v1(&head_file, expected.digest)?;
        ensure!(
            observed_head == head_from_log,
            "replay archive head differs after recovery audit"
        );
        let directory_identity = FileIdentityV1::from_file_v1(&directory)?;
        let entries_identity = FileIdentityV1::from_file_v1(&entries_file)?;
        let context_identity = FileIdentityV1::from_file_v1(&context_file)?;
        let head_identity = FileIdentityV1::from_file_v1(&head_file)?;
        let repair_tombstone_file = if historically_repaired {
            Some(open_and_validate_repair_tombstone_v1(
                &root,
                expected.digest,
            )?)
        } else {
            None
        };
        let repair_tombstone_identity = repair_tombstone_file
            .as_ref()
            .map(FileIdentityV1::from_file_v1)
            .transpose()?;
        let archive = Self {
            root,
            context: expected,
            directory,
            entries_file,
            context_file,
            head_file,
            directory_identity,
            entries_identity,
            context_identity,
            head_identity,
            repair_tombstone_file,
            repair_tombstone_identity,
            entries_len,
            head: observed_head,
            index,
            owner_pid: std::process::id(),
            fail_stopped: false,
            historically_repaired,
        };
        archive.revalidate_identity_v1()?;
        Ok(archive)
    }

    pub(crate) fn facts_v1(&self) -> SignedReplayArchiveFactsV1 {
        SignedReplayArchiveFactsV1 {
            context_sha256: self.context.digest,
            sequence: self.head.sequence,
            record_sha256: self.head.record_sha256,
        }
    }

    pub(crate) fn append_proposal_v1(&mut self, proposal: &UnboundProposalV0) -> Result<()> {
        let payload = proposal
            .encode()
            .map_err(|error| anyhow!("encode archived Proposal: {error}"))?;
        let header = proposal.block().header();
        self.append_statement_v1(ReplayArchiveStatementV1 {
            coordinate: ReplayArchiveCoordinateV1 {
                kind: ReplayArchiveEntryKindV1::Proposal,
                height: header.height().get(),
                view: header.view().get(),
                block_id: *proposal.block().id().as_bytes(),
            },
            payload,
        })
    }

    pub(crate) fn append_quorum_certificate_v1(
        &mut self,
        certificate: &QuorumCertificate,
    ) -> Result<()> {
        let payload = encode_quorum_certificate(certificate)
            .map_err(|error| anyhow!("encode archived quorum certificate: {error}"))?;
        self.append_statement_v1(ReplayArchiveStatementV1 {
            coordinate: ReplayArchiveCoordinateV1 {
                kind: ReplayArchiveEntryKindV1::QuorumCertificate,
                height: certificate.height().get(),
                view: certificate.view().get(),
                block_id: *certificate.block_id().as_bytes(),
            },
            payload,
        })
    }

    fn append_statement_v1(&mut self, statement: ReplayArchiveStatementV1) -> Result<()> {
        self.append_statement_with_observer_v1(statement, |_| Ok(()))
    }

    fn append_statement_with_observer_v1<F>(
        &mut self,
        statement: ReplayArchiveStatementV1,
        mut observer: F,
    ) -> Result<()>
    where
        F: FnMut(ReplayArchiveAppendStageV1) -> Result<()>,
    {
        ensure!(
            !self.fail_stopped,
            "signed replay archive owner is permanently fail-stopped"
        );
        let result = (|| {
            observer(ReplayArchiveAppendStageV1::BeforeArchive)?;
            self.revalidate_identity_v1()?;
            ensure!(
                !statement.payload.is_empty() && statement.payload.len() <= MAX_FRAME_PAYLOAD_BYTES,
                "signed replay archive payload is empty or oversized"
            );
            let content_sha256 = content_sha256_v1(statement.coordinate.kind, &statement.payload);
            if let Some(existing) = self.index.get(&statement.coordinate) {
                ensure!(
                    existing.content_sha256 == content_sha256,
                    "signed replay archive coordinate conflicts with existing content"
                );
                let payload = self.read_indexed_payload_v1(existing.clone())?;
                ensure!(
                    payload == statement.payload,
                    "content-addressed replay retry differs bytewise"
                );
                observer(ReplayArchiveAppendStageV1::AfterArchiveDurable)?;
                observer(ReplayArchiveAppendStageV1::BeforeAuthorityMutation)?;
                return Ok(());
            }
            let kind_count = u64::try_from(
                self.index
                    .keys()
                    .filter(|coordinate| coordinate.kind == statement.coordinate.kind)
                    .count(),
            )
            .context("signed replay kind count overflows")?;
            let kind_capacity = match statement.coordinate.kind {
                ReplayArchiveEntryKindV1::Proposal => self.context.json.maximum_proposal_entries,
                ReplayArchiveEntryKindV1::QuorumCertificate => {
                    self.context.json.maximum_quorum_certificate_entries
                }
            };
            ensure!(
                kind_count < kind_capacity,
                "signed replay archive {} capacity exhausted",
                statement.coordinate.kind.label_v1()
            );
            let sequence = self
                .head
                .sequence
                .checked_add(1)
                .ok_or_else(|| anyhow!("signed replay archive sequence exhausted"))?;
            ensure!(
                sequence <= self.context.json.maximum_archive_entries,
                "signed replay archive capacity exhausted"
            );
            let record_sha256 = record_sha256_v1(
                self.context.digest,
                sequence,
                self.head.record_sha256,
                statement.coordinate,
                content_sha256,
            );
            let entry = ReplayArchiveEntryJsonV1 {
                schema_version: SCHEMA_VERSION_V1,
                sequence,
                context_sha256: hex::encode(self.context.digest),
                previous_record_sha256: hex::encode(self.head.record_sha256),
                kind: statement.coordinate.kind.label_v1().to_owned(),
                height: statement.coordinate.height,
                view: statement.coordinate.view,
                block_id: hex::encode(statement.coordinate.block_id),
                content_sha256: hex::encode(content_sha256),
                payload_hex: hex::encode(&statement.payload),
                record_sha256: hex::encode(record_sha256),
            };
            let mut line =
                serde_json::to_vec(&entry).context("encode signed replay archive entry")?;
            line.push(b'\n');
            ensure!(
                line.len() <= MAXIMUM_ENTRY_LINE_BYTES_V1,
                "signed replay archive line is oversized"
            );
            let offset = self.entries_len;
            self.entries_file
                .seek(SeekFrom::Start(offset))
                .context("seek signed replay archive tail")?;
            self.entries_file
                .write_all(&line)
                .context("append signed replay archive entry")?;
            self.entries_file
                .sync_all()
                .context("fsync signed replay archive entry")?;
            observer(ReplayArchiveAppendStageV1::AfterArchiveDurable)?;
            let next_head = ReplayArchiveHeadV1 {
                sequence,
                record_sha256,
            };
            write_head_atomic_v1(&self.root, self.context.digest, next_head, &self.directory)?;
            let head_file = open_private_file_v1(&self.root.join(HEAD_FILE_V1), false)?;
            ensure!(
                read_head_from_file_v1(&head_file, self.context.digest)? == next_head,
                "new replay archive head failed exact readback"
            );
            let head_identity = FileIdentityV1::from_file_v1(&head_file)?;
            self.entries_len = self
                .entries_len
                .checked_add(u64::try_from(line.len()).context("archive line length overflows")?)
                .context("archive byte length overflows")?;
            self.head = next_head;
            self.head_file = head_file;
            self.head_identity = head_identity;
            self.index.insert(
                statement.coordinate,
                ReplayArchiveEntryIndexV1 {
                    coordinate: statement.coordinate,
                    content_sha256,
                    record_sha256,
                    offset,
                    line_bytes: line.len(),
                },
            );
            self.revalidate_identity_v1()?;
            observer(ReplayArchiveAppendStageV1::BeforeAuthorityMutation)?;
            Ok(())
        })();
        if result.is_err() {
            // Any failure may represent process loss after a durable write.
            // This owner can never distinguish that state safely; only a
            // fresh process may reopen and audit the crash window.
            self.fail_stopped = true;
        }
        result
    }

    fn read_indexed_payload_v1(&mut self, index: ReplayArchiveEntryIndexV1) -> Result<Vec<u8>> {
        self.revalidate_identity_v1()?;
        self.entries_file
            .seek(SeekFrom::Start(index.offset))
            .context("seek indexed replay archive entry")?;
        let mut line = vec![0_u8; index.line_bytes];
        self.entries_file
            .read_exact(&mut line)
            .context("read indexed replay archive entry")?;
        let parsed = parse_entry_line_v1(&line, self.context.digest, None)?;
        ensure!(
            parsed.index.coordinate == index.coordinate
                && parsed.index.content_sha256 == index.content_sha256
                && parsed.index.record_sha256 == index.record_sha256,
            "indexed replay archive entry changed after audit"
        );
        Ok(parsed.payload)
    }

    fn entry_payload_v1(&mut self, coordinate: ReplayArchiveCoordinateV1) -> Result<Vec<u8>> {
        let index = self
            .index
            .get(&coordinate)
            .cloned()
            .ok_or_else(|| anyhow!("signed replay archive is missing an exact coordinate"))?;
        self.read_indexed_payload_v1(index)
    }

    fn revalidate_identity_v1(&self) -> Result<()> {
        ensure!(
            std::process::id() == self.owner_pid,
            "replay archive owner process changed"
        );
        ensure!(
            self.directory_identity.matches_file_v1(&self.directory)?
                && self.entries_identity.matches_file_v1(&self.entries_file)?
                && self.context_identity.matches_file_v1(&self.context_file)?
                && self.head_identity.matches_file_v1(&self.head_file)?,
            "a pinned replay archive file identity changed"
        );
        let directory_path = open_directory_pinned_v1(&self.root)?;
        let entries_path = open_private_file_v1(&self.root.join(ENTRY_FILE_V1), false)?;
        let context_path = open_private_file_v1(&self.root.join(CONTEXT_FILE_V1), false)?;
        let head_path = open_private_file_v1(&self.root.join(HEAD_FILE_V1), false)?;
        ensure!(
            self.directory_identity.matches_file_v1(&directory_path)?
                && self.entries_identity.matches_file_v1(&entries_path)?
                && self.context_identity.matches_file_v1(&context_path)?
                && self.head_identity.matches_file_v1(&head_path)?
                && self.entries_file.metadata()?.len() == self.entries_len,
            "replay archive path was replaced, truncated, or externally extended"
        );
        let observed_context: ReplayArchiveContextJsonV1 = read_bounded_json_v1(
            &self.context_file,
            MAXIMUM_CONTEXT_BYTES_V1,
            "pinned archive context",
        )?;
        ensure!(
            ReplayArchiveContextV1::from_fields_v1(observed_context)? == self.context,
            "pinned replay archive context changed"
        );
        ensure!(
            read_head_from_file_v1(&self.head_file, self.context.digest)? == self.head,
            "pinned replay archive head changed"
        );
        validate_inventory_v1(&self.root)?;
        match (
            self.historically_repaired,
            self.repair_tombstone_file.as_ref(),
            self.repair_tombstone_identity,
        ) {
            (true, Some(tombstone), Some(identity)) => {
                ensure!(
                    identity.matches_file_v1(tombstone)?,
                    "pinned replay archive repair tombstone identity changed"
                );
                let tombstone_path =
                    open_and_validate_repair_tombstone_v1(&self.root, self.context.digest)?;
                ensure!(
                    identity.matches_file_v1(&tombstone_path)?,
                    "replay archive repair tombstone path was replaced"
                );
                let pinned = read_repair_tombstone_from_file_v1(tombstone, self.context.digest)?;
                let reopened =
                    read_repair_tombstone_from_file_v1(&tombstone_path, self.context.digest)?;
                ensure!(
                    pinned == reopened,
                    "replay archive repair tombstone changed after open"
                );
            }
            (false, None, None) => ensure!(
                !path_exists_no_follow_v1(&self.root.join(REPAIR_TOMBSTONE_FILE_V1))?,
                "untracked replay archive repair tombstone appeared"
            ),
            _ => bail!("replay archive repair provenance ownership is inconsistent"),
        }
        Ok(())
    }

    /// Performs a fresh, exact, non-repairing audit of every pinned archive
    /// byte.  In particular, a recoverable one-entry-ahead log is rejected
    /// here rather than repaired; terminal evidence may only describe an
    /// already stable head.
    fn fresh_terminal_snapshot_v1(&self) -> Result<ReplayArchiveTerminalSnapshotV1> {
        ensure!(
            !self.fail_stopped && !self.historically_repaired,
            "fail-stopped or crash-repaired replay archive cannot produce terminal evidence"
        );
        self.revalidate_identity_v1()?;
        validate_terminal_inventory_v1(&self.root)?;

        let mut entries = self
            .entries_file
            .try_clone()
            .context("clone replay archive for terminal audit")?;
        let (head, _tail_predecessor, index, entries_len, _entries_sha256) = audit_entry_log_v1(
            &mut entries,
            self.context.digest,
            self.context.json.maximum_archive_entries,
        )?;
        require_index_within_context_capacity_v1(&index, &self.context)?;
        ensure!(
            head == self.head && index == self.index && entries_len == self.entries_len,
            "fresh terminal replay audit differs from the pinned owner"
        );
        ensure!(
            read_head_from_file_v1(&self.head_file, self.context.digest)? == head,
            "terminal replay log is one-ahead of its durable head"
        );

        let context_bytes = read_exact_file_bytes_v1(
            &self.context_file,
            MAXIMUM_CONTEXT_BYTES_V1,
            false,
            "terminal archive context",
        )?;
        ensure!(
            context_bytes == self.context.canonical_bytes_v1()?,
            "terminal archive context bytes are not canonical"
        );
        let (entries_file_sha256, entries_file_bytes) = hash_exact_file_sha256_v1(
            &self.entries_file,
            context_bound_entry_file_bytes_v1(self.context.json.maximum_archive_entries)?,
            false,
            "terminal archive entries",
        )?;
        let head_bytes = read_exact_file_bytes_v1(
            &self.head_file,
            MAXIMUM_HEAD_BYTES_V1,
            false,
            "terminal archive head",
        )?;
        let mut expected_head_bytes = serde_json::to_vec(&head.json_v1(self.context.digest))
            .context("encode archive head")?;
        expected_head_bytes.push(b'\n');
        ensure!(
            head_bytes == expected_head_bytes,
            "terminal archive head bytes are not canonical"
        );

        let proposal_count = u64::try_from(
            index
                .keys()
                .filter(|coordinate| coordinate.kind == ReplayArchiveEntryKindV1::Proposal)
                .count(),
        )
        .context("proposal archive count overflows")?;
        let quorum_certificate_count = u64::try_from(
            index
                .keys()
                .filter(|coordinate| coordinate.kind == ReplayArchiveEntryKindV1::QuorumCertificate)
                .count(),
        )
        .context("QC archive count overflows")?;
        ensure!(
            proposal_count > 0
                && quorum_certificate_count > 0
                && proposal_count <= self.context.json.maximum_proposal_entries
                && quorum_certificate_count <= self.context.json.maximum_quorum_certificate_entries,
            "terminal archive lacks bounded Proposal/QC evidence"
        );

        self.revalidate_identity_v1()?;
        Ok(ReplayArchiveTerminalSnapshotV1 {
            context_file_sha256: Sha256::digest(&context_bytes).into(),
            context_file_bytes: u64::try_from(context_bytes.len())
                .context("context byte count overflows")?,
            entries_file_sha256,
            entries_file_bytes,
            head_file_sha256: Sha256::digest(&head_bytes).into(),
            head_file_bytes: u64::try_from(head_bytes.len())
                .context("head byte count overflows")?,
            head,
            proposal_count,
            quorum_certificate_count,
        })
    }

    /// Writes the independent validator-signed terminal seal only after the
    /// exact signed journal has reached CleanStop and the pinned archive has
    /// passed two identical full, non-repairing audits.
    #[allow(private_bounds)]
    pub(crate) fn write_terminal_seal_v1<C: ReplayArchiveTerminalConfigV1 + ?Sized>(
        &self,
        config: &C,
        clean_stop: &CleanStoppedJournalCutV1,
        bootstrap_initial_cut: VerifiedPublicBootstrapInitialCutV1,
    ) -> Result<PathBuf> {
        let signing_key = config.consensus_signing_key();
        let validator = config
            .validator_set()
            .validator(config.local_validator())
            .ok_or_else(|| anyhow!("terminal seal validator is absent from validator set"))?;
        ensure!(
            validator.consensus_key().as_bytes() == &signing_key.verifying_key().to_bytes(),
            "terminal seal signing key differs from validator set"
        );
        self.write_terminal_seal_with_signer_v1(
            config,
            clean_stop,
            bootstrap_initial_cut,
            &mut |root| Ok(signing_key.sign(&root).to_bytes()),
        )
    }

    #[allow(private_bounds)]
    pub(crate) fn write_terminal_seal_with_signer_v1<C: ReplayArchiveTerminalConfigV1 + ?Sized>(
        &self,
        config: &C,
        clean_stop: &CleanStoppedJournalCutV1,
        bootstrap_initial_cut: VerifiedPublicBootstrapInitialCutV1,
        signer: &mut dyn FnMut([u8; 32]) -> Result<[u8; 64]>,
    ) -> Result<PathBuf> {
        let run_directory = open_directory_pinned_v1(config.run_root())?;
        let run_directory_identity = FileIdentityV1::from_file_v1(&run_directory)?;
        ensure!(
            self.root.parent() == Some(config.run_root()),
            "terminal archive is outside the loaded private run root"
        );
        let archive_parent = open_directory_pinned_v1(
            self.root
                .parent()
                .ok_or_else(|| anyhow!("terminal archive has no parent directory"))?,
        )?;
        ensure!(
            run_directory_identity.matches_file_v1(&archive_parent)?,
            "terminal archive parent differs from the pinned private run root"
        );
        let expected = ReplayArchiveContextV1::from_config_v1(
            config,
            SignedReplayArchiveBoundsV1 {
                maximum_timeout_view_advances: self.context.json.maximum_timeout_view_advances,
                maximum_proposal_entries: self.context.json.maximum_proposal_entries,
                maximum_quorum_certificate_entries: self
                    .context
                    .json
                    .maximum_quorum_certificate_entries,
                maximum_archive_entries: self.context.json.maximum_archive_entries,
            },
        )?;
        ensure!(
            expected == self.context,
            "terminal archive context differs from loaded validator"
        );
        TerminalSealCutContextV1::from_config_v1(config).require_exact_cut_v1(clean_stop)?;
        ensure!(
            clean_stop.event_sequence() > 0
                && clean_stop.event_sha256() != [0; 32]
                && clean_stop.fleet_start_certificate_sha256() != [0; 32]
                && clean_stop.finalized_height() > 0
                && clean_stop.finalized_block_id() != [0; 32]
                && clean_stop.finalized_state_root() != [0; 32]
                && clean_stop.finalized_chain_root() != [0; 32],
            "terminal seal requires the exact loaded context and nonzero CleanStop/FleetStart/final-tip cut"
        );
        let snapshot = self.fresh_terminal_snapshot_v1()?;
        let semantics = decode_strict_archive_semantics_v1(
            &self.entries_file,
            &self.index,
            self.context.digest,
            config.validator_set(),
            config.consensus_parameters(),
            config.ordinary_start_height(),
            bootstrap_initial_cut,
        )?;
        ensure!(
            u64::try_from(semantics.proposals.len()).context("proposal count overflows")?
                == snapshot.proposal_count
                && u64::try_from(semantics.certificates.len()).context("QC count overflows")?
                    == snapshot.quorum_certificate_count,
            "strict terminal semantics count differs from the exact archive snapshot"
        );
        let coverage = verify_signed_final_tip_coverage_v1(
            &semantics,
            config.validator_set(),
            config.consensus_parameters(),
            clean_stop.finalized_height(),
            clean_stop.finalized_block_id(),
            clean_stop.finalized_state_root(),
            clean_stop.finalized_chain_root(),
        )?;
        let validator = config
            .validator_set()
            .validator(config.local_validator())
            .ok_or_else(|| anyhow!("terminal seal validator is absent from validator set"))?;
        ensure!(
            validator.consensus_key().as_bytes() != &[0; 32],
            "terminal seal validator has an empty consensus public key"
        );
        let mut seal = ReplayArchiveTerminalSealV1 {
            schema_version: TERMINAL_SEAL_SCHEMA_VERSION_V1,
            run_id: config.run_id().to_owned(),
            validator_id: hex::encode(config.local_validator().as_bytes()),
            validator_set_id: hex::encode(config.validator_set().id().as_bytes()),
            validator_set_sha256: hex::encode(config.validator_set_sha256()),
            topology_sha256: hex::encode(config.topology_sha256()),
            coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
            candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
            binary_sha256: hex::encode(config.binary_sha256()),
            config_sha256: hex::encode(config.config_sha256()),
            fleet_start_certificate_sha256: hex::encode(
                clean_stop.fleet_start_certificate_sha256(),
            ),
            process_instance: clean_stop.process_instance(),
            clean_stop_journal_sequence: clean_stop.event_sequence(),
            clean_stop_journal_sha256: hex::encode(clean_stop.event_sha256()),
            finalized_height: clean_stop.finalized_height(),
            finalized_block_id: hex::encode(clean_stop.finalized_block_id()),
            finalized_state_root: hex::encode(clean_stop.finalized_state_root()),
            finalized_chain_root: hex::encode(clean_stop.finalized_chain_root()),
            finality_proof_id: hex::encode(coverage.proof_id),
            finality_child_block_id: hex::encode(coverage.child_block_id),
            finality_grandchild_block_id: hex::encode(coverage.grandchild_block_id),
            archive_context_sha256: hex::encode(self.context.digest),
            archive_context_file_sha256: hex::encode(snapshot.context_file_sha256),
            archive_context_file_bytes: snapshot.context_file_bytes,
            archive_entries_file_sha256: hex::encode(snapshot.entries_file_sha256),
            archive_entries_file_bytes: snapshot.entries_file_bytes,
            archive_head_file_sha256: hex::encode(snapshot.head_file_sha256),
            archive_head_file_bytes: snapshot.head_file_bytes,
            terminal_archive_sequence: snapshot.head.sequence,
            terminal_archive_record_sha256: hex::encode(snapshot.head.record_sha256),
            proposal_count: snapshot.proposal_count,
            quorum_certificate_count: snapshot.quorum_certificate_count,
            body_sha256: String::new(),
            signature: String::new(),
        };
        let body_sha256 = seal.computed_body_sha256_v1()?;
        seal.body_sha256 = hex::encode(body_sha256);
        let signature_root = hash_parts_v1(TERMINAL_SEAL_SIGNATURE_DOMAIN_V1, &[&body_sha256]);
        let signature = signer(signature_root)?;
        let signature = Signature::from_bytes(&signature);
        let verifying_key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .context("decode terminal seal validator public key")?;
        verifying_key
            .verify_strict(&signature_root, &signature)
            .context("verify terminal replay archive seal signature")?;
        seal.signature = hex::encode(signature.to_bytes());

        ensure!(
            self.fresh_terminal_snapshot_v1()? == snapshot,
            "terminal archive changed before seal persistence"
        );
        revalidate_directory_path_identity_v1(
            config.run_root(),
            &run_directory,
            run_directory_identity,
            "private run root before terminal seal create",
        )?;
        let path = config.run_root().join(TERMINAL_SEAL_FILE_V1);
        let bytes = seal.canonical_bytes_v1()?;
        write_new_private_file_v1(&path, &bytes)?;
        run_directory
            .sync_all()
            .context("fsync private run root after terminal seal")?;
        let seal_file = open_private_file_v1(&path, false)?;
        ensure!(
            read_exact_file_bytes_v1(
                &seal_file,
                MAXIMUM_TERMINAL_SEAL_BYTES_V1,
                false,
                "terminal archive seal readback",
            )? == bytes,
            "terminal archive seal differs after durable readback"
        );
        revalidate_directory_path_identity_v1(
            config.run_root(),
            &run_directory,
            run_directory_identity,
            "private run root after terminal seal create",
        )?;
        ensure!(
            self.fresh_terminal_snapshot_v1()? == snapshot,
            "terminal archive changed while its seal was persisted"
        );
        Ok(path)
    }

    /// Consumes the audited archive together with one replay-fenced Node
    /// owner.  Success remains inert and releases no Core, signer, timer, or
    /// ingress capability.
    pub(crate) fn authenticate_recovery_v1(
        mut self,
        recovery: PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<LabFileWatermark>,
        config: &LoadedValidatorConfig,
    ) -> Result<ArchivedDeployedReplayOwnerV1> {
        ensure!(
            !self.fail_stopped,
            "fail-stopped archive owner cannot authenticate recovery"
        );
        let challenge = recovery.signed_ancestry_replay_challenge_v0();
        ensure!(
            challenge.requires_signed_ancestry_replay_v0(),
            "archive authentication requires a revision>5 replay challenge"
        );
        let mut parent_timestamps = BTreeMap::new();
        for block in recovery.facts_v0().high_qc_replay_path_v0() {
            ensure!(
                parent_timestamps
                    .insert(block.block_id_v0(), block.timestamp_ms_v0())
                    .is_none(),
                "recovered replay path contains a duplicate block"
            );
        }
        let required = challenge.required_blocks_v0();
        let mut proposals = Vec::with_capacity(required.len());
        for coordinate in required {
            let payload = self.entry_payload_v1(ReplayArchiveCoordinateV1 {
                kind: ReplayArchiveEntryKindV1::Proposal,
                height: coordinate.height_v0(),
                view: coordinate.view_v0().get(),
                block_id: *coordinate.block_id_v0().as_bytes(),
            })?;
            let proposal = UnboundProposalV0::decode(
                &payload,
                config.validator_set(),
                config.consensus_parameters(),
            )
            .map_err(|error| anyhow!("decode archived Proposal: {error}"))?;
            ensure!(
                proposal.block().id() == coordinate.block_id_v0()
                    && proposal.block().header().parent_id() == coordinate.parent_block_id_v0()
                    && proposal.block().header().height().get() == coordinate.height_v0()
                    && proposal.block().header().view() == coordinate.view_v0(),
                "archived Proposal differs from recovery challenge"
            );
            let parent_timestamp = parent_timestamps
                .get(&coordinate.parent_block_id_v0())
                .copied()
                .ok_or_else(|| anyhow!("archived Proposal parent timestamp is unavailable"))?;
            let proposal = proposal
                .bind_authenticated_parent(
                    config.validator_set(),
                    config.consensus_parameters(),
                    parent_timestamp,
                )
                .map_err(|error| anyhow!("bind archived Proposal parent: {error}"))?;
            proposals.push(proposal);
        }
        let mut entries = Vec::with_capacity(required.len());
        for index in 0..required.len() {
            let target = if let Some(next) = proposals.get(index + 1) {
                next.witness().justify_qc().qc_ref()
            } else {
                challenge.high_qc_v0()
            };
            let payload = self.entry_payload_v1(ReplayArchiveCoordinateV1 {
                kind: ReplayArchiveEntryKindV1::QuorumCertificate,
                height: target.height().get(),
                view: target.view().get(),
                block_id: *target.block_id().as_bytes(),
            })?;
            let certificate = decode_quorum_certificate(&payload, config.validator_set())
                .map_err(|error| anyhow!("decode archived quorum certificate: {error}"))?;
            ensure!(
                QcRef::from(&certificate) == target,
                "archived quorum certificate differs from exact replay chain"
            );
            entries.push(PocoNodeDeployedLabSignedReplayEntryV0::new(
                proposals[index].clone(),
                certificate,
            ));
        }
        let archive_facts = self.facts_v1();
        let node = recovery
            .authenticate_signed_ancestry_replay_v0(entries)
            .map_err(|error| anyhow!("authenticate archived signed ancestry: {error}"))?;
        self.revalidate_identity_v1()?;
        Ok(ArchivedDeployedReplayOwnerV1 {
            _archive: self,
            node,
            archive_facts,
        })
    }
}

struct PinnedReadOnlyEvidenceFileV1 {
    path: PathBuf,
    file: File,
    identity: FileIdentityV1,
    length: u64,
    sha256: [u8; 32],
    sha256_bound: bool,
    maximum: u64,
    label: &'static str,
}

impl PinnedReadOnlyEvidenceFileV1 {
    fn open_v1(path: &Path, maximum: u64, label: &'static str) -> Result<Self> {
        ensure!(path.is_absolute(), "read-only {label} path is not absolute");
        ensure!(
            path.canonicalize()
                .with_context(|| format!("canonicalize read-only {label} path"))?
                == path,
            "read-only {label} path has a symlink or non-canonical ancestor"
        );
        let before = fs::symlink_metadata(path)
            .with_context(|| format!("inspect read-only {label} path"))?;
        ensure!(
            !before.file_type().is_symlink(),
            "read-only {label} path is a symlink"
        );
        validate_private_regular_metadata_v1(&before, label)?;
        ensure!(
            before.len() > 0 && before.len() <= maximum,
            "read-only {label} has an invalid byte length"
        );
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open read-only {label}"))?;
        let opened = file
            .metadata()
            .with_context(|| format!("inspect read-only {label} handle"))?;
        validate_private_regular_metadata_v1(&opened, label)?;
        let identity = FileIdentityV1::from_metadata_v1(&before);
        ensure!(
            identity.matches_metadata_v1(&opened) && opened.len() == before.len(),
            "read-only {label} identity changed while opening"
        );
        let (sha256, length) = hash_exact_file_sha256_v1(&file, maximum, false, label)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
            length,
            sha256,
            sha256_bound: true,
            maximum,
            label,
        })
    }

    /// Pins an exact, already authenticated file length and filesystem
    /// identity without reading the file body. The caller must bind the hash
    /// produced by its mandatory full semantic audit before revalidation.
    fn open_unhashed_exact_length_v1(
        path: &Path,
        maximum: u64,
        expected_length: u64,
        label: &'static str,
    ) -> Result<Self> {
        ensure!(path.is_absolute(), "read-only {label} path is not absolute");
        ensure!(
            path.canonicalize()
                .with_context(|| format!("canonicalize read-only {label} path"))?
                == path,
            "read-only {label} path has a symlink or non-canonical ancestor"
        );
        let before = fs::symlink_metadata(path)
            .with_context(|| format!("inspect read-only {label} path"))?;
        ensure!(
            !before.file_type().is_symlink(),
            "read-only {label} path is a symlink"
        );
        validate_private_regular_metadata_v1(&before, label)?;
        ensure!(
            expected_length > 0 && expected_length <= maximum && before.len() == expected_length,
            "read-only {label} differs from its authenticated byte length"
        );
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open read-only {label}"))?;
        let opened = file
            .metadata()
            .with_context(|| format!("inspect read-only {label} handle"))?;
        validate_private_regular_metadata_v1(&opened, label)?;
        let identity = FileIdentityV1::from_metadata_v1(&before);
        ensure!(
            identity.matches_metadata_v1(&opened) && opened.len() == expected_length,
            "read-only {label} identity changed while opening"
        );
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
            length: expected_length,
            sha256: [0; 32],
            sha256_bound: false,
            maximum,
            label,
        })
    }

    fn bind_audited_sha256_v1(&mut self, sha256: [u8; 32], length: u64) -> Result<()> {
        ensure!(
            !self.sha256_bound && length == self.length,
            "read-only audited hash binding is repeated or has the wrong length"
        );
        self.sha256 = sha256;
        self.sha256_bound = true;
        Ok(())
    }

    fn bytes_v1(&self) -> Result<Vec<u8>> {
        read_exact_file_bytes_v1(&self.file, self.maximum, false, self.label)
    }

    fn revalidate_v1(&self) -> Result<()> {
        ensure!(
            self.sha256_bound,
            "read-only evidence hash was not bound by its semantic audit"
        );
        ensure!(
            self.identity.matches_file_v1(&self.file)?
                && self.file.metadata()?.len() == self.length,
            "pinned read-only evidence identity or length changed"
        );
        let (observed_sha256, observed_length) =
            hash_exact_file_sha256_v1(&self.file, self.maximum, false, self.label)?;
        ensure!(
            observed_sha256 == self.sha256 && observed_length == self.length,
            "pinned read-only evidence SHA-256 changed"
        );
        let reopened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
            .with_context(|| format!("reopen read-only {}", self.label))?;
        let metadata = reopened
            .metadata()
            .with_context(|| format!("reinspect read-only {}", self.label))?;
        validate_private_regular_metadata_v1(&metadata, self.label)?;
        ensure!(
            self.identity.matches_metadata_v1(&metadata) && metadata.len() == self.length,
            "read-only evidence path was replaced"
        );
        Ok(())
    }
}

/// Strictly and exclusively read-only verification of one sealed archive.
/// This entry point never calls `open_existing_v1`, `open_expected_v1`,
/// `repair_or_reject_head_v1`, or any writer/rename/remove operation.
#[allow(clippy::too_many_arguments)]
pub fn verify_replay_archive_v1(
    context_path: &Path,
    entries_path: &Path,
    head_path: &Path,
    terminal_seal_path: &Path,
    public_context: &PublicReportVerifierContext,
) -> Result<ReplayArchiveVerificationV1> {
    let context_file = PinnedReadOnlyEvidenceFileV1::open_v1(
        context_path,
        MAXIMUM_CONTEXT_BYTES_V1,
        "replay archive context",
    )?;
    let context_bytes = context_file.bytes_v1()?;
    let context_json: ReplayArchiveContextJsonV1 = serde_json::from_slice(&context_bytes)
        .context("decode read-only replay archive context")?;
    let context = ReplayArchiveContextV1::from_fields_v1(context_json)?;
    ensure!(
        context_bytes == context.canonical_bytes_v1()?,
        "replay archive context has trailing or non-canonical bytes"
    );
    let local = public_context
        .validator_set()
        .validator(public_context.local_validator())
        .ok_or_else(|| anyhow!("selected archive validator is absent from validator set"))?;
    ensure!(
        context.json.run_id == public_context.run_id()
            && context.json.chain_id == public_context.validator_set().chain_id().as_str()
            && decode_hex32_v1(&context.json.genesis_hash, "archive genesis")?
                == *public_context.validator_set().genesis_hash().as_bytes()
            && decode_hex32_v1(&context.json.validator_set_id, "archive validator set ID")?
                == *public_context.validator_set().id().as_bytes()
            && decode_hex32_v1(&context.json.local_validator_id, "archive validator ID")?
                == *public_context.local_validator().as_bytes()
            && decode_hex32_v1(
                &context.json.local_consensus_public_key,
                "archive consensus public key",
            )? == *local.consensus_key().as_bytes()
            && decode_hex32_v1(
                &context.json.coordinator_manifest_sha256,
                "archive coordinator manifest",
            )? == public_context.coordinator_manifest_sha256()
            && decode_hex32_v1(
                &context.json.validator_set_sha256,
                "archive validator set file",
            )? == public_context.validator_set_sha256()
            && decode_hex32_v1(&context.json.topology_sha256, "archive topology")?
                == public_context.topology_sha256()
            && decode_hex32_v1(&context.json.config_sha256, "archive config")?
                == public_context.config_sha256()
            && decode_hex32_v1(&context.json.candidate_source_sha256, "archive source")?
                == public_context.candidate_source_sha256()
            && decode_hex32_v1(&context.json.binary_sha256, "archive binary")?
                == public_context.binary_sha256()
            && decode_hex32_v1(
                &context.json.workload_corpus_sha256,
                "archive workload corpus",
            )? == public_context.workload_corpus_sha256()
            && decode_hex32_v1(
                &context.json.workload_policy_sha256,
                "archive workload policy",
            )? == public_context.workload_policy_sha256()
            && context.json.ordinary_start_height == public_context.ordinary_start_height(),
        "replay archive context differs from observer-public"
    );

    let entries_maximum = context_bound_entry_file_bytes_v1(context.json.maximum_archive_entries)?;
    let seal_file = PinnedReadOnlyEvidenceFileV1::open_v1(
        terminal_seal_path,
        MAXIMUM_TERMINAL_SEAL_BYTES_V1,
        "replay archive terminal seal",
    )?;
    let seal_bytes = seal_file.bytes_v1()?;
    let seal: ReplayArchiveTerminalSealV1 =
        serde_json::from_slice(&seal_bytes).context("decode replay archive terminal seal")?;
    ensure!(
        seal_bytes == seal.canonical_bytes_v1()?,
        "replay archive terminal seal has trailing or non-canonical bytes"
    );
    let body_sha256 = seal.computed_body_sha256_v1()?;
    ensure!(
        seal.schema_version == TERMINAL_SEAL_SCHEMA_VERSION_V1
            && decode_hex32_v1(&seal.body_sha256, "terminal seal body")? == body_sha256
            && seal.run_id == public_context.run_id()
            && decode_hex32_v1(&seal.validator_id, "terminal seal validator")?
                == *public_context.local_validator().as_bytes()
            && decode_hex32_v1(&seal.validator_set_id, "terminal seal validator set ID")?
                == *public_context.validator_set().id().as_bytes()
            && decode_hex32_v1(&seal.validator_set_sha256, "terminal seal validator set")?
                == public_context.validator_set_sha256()
            && decode_hex32_v1(&seal.topology_sha256, "terminal seal topology")?
                == public_context.topology_sha256()
            && decode_hex32_v1(
                &seal.coordinator_manifest_sha256,
                "terminal seal coordinator manifest",
            )? == public_context.coordinator_manifest_sha256()
            && decode_hex32_v1(&seal.candidate_source_sha256, "terminal seal source")?
                == public_context.candidate_source_sha256()
            && decode_hex32_v1(&seal.binary_sha256, "terminal seal binary")?
                == public_context.binary_sha256()
            && decode_hex32_v1(&seal.config_sha256, "terminal seal config")?
                == public_context.config_sha256()
            && decode_hex32_v1(&seal.archive_context_sha256, "terminal seal context")?
                == context.digest
            && decode_hex32_v1(
                &seal.archive_context_file_sha256,
                "terminal seal context file",
            )? == context_file.sha256
            && seal.archive_context_file_bytes == context_file.length
            && seal.archive_entries_file_bytes > 0
            && seal.archive_entries_file_bytes <= entries_maximum,
        "terminal replay archive seal prefix differs from authenticated public/context bounds"
    );
    let signature_bytes = hex::decode(&seal.signature).context("decode terminal seal signature")?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow!("terminal seal signature is not exactly 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(local.consensus_key().as_bytes())
        .context("decode terminal seal consensus key")?;
    let signature_root = hash_parts_v1(TERMINAL_SEAL_SIGNATURE_DOMAIN_V1, &[&body_sha256]);
    verifying_key
        .verify_strict(&signature_root, &signature)
        .context("verify terminal replay archive seal signature")?;

    let mut entries_file = PinnedReadOnlyEvidenceFileV1::open_unhashed_exact_length_v1(
        entries_path,
        entries_maximum,
        seal.archive_entries_file_bytes,
        "replay archive entries",
    )?;
    let head_file = PinnedReadOnlyEvidenceFileV1::open_v1(
        head_path,
        MAXIMUM_HEAD_BYTES_V1,
        "replay archive head",
    )?;
    let mut audit_file = entries_file
        .file
        .try_clone()
        .context("clone read-only replay entries for full audit")?;
    let (log_head, _tail_predecessor, index, entries_len, entries_sha256) = audit_entry_log_v1(
        &mut audit_file,
        context.digest,
        context.json.maximum_archive_entries,
    )?;
    entries_file.bind_audited_sha256_v1(entries_sha256, entries_len)?;
    require_index_within_context_capacity_v1(&index, &context)?;
    ensure!(
        entries_len == entries_file.length,
        "audited replay entry length differs from pinned file"
    );
    let observed_head = read_head_from_file_v1(&head_file.file, context.digest)?;
    ensure!(
        observed_head == log_head,
        "replay archive head is ahead, behind, or forked from the full log"
    );
    let mut canonical_head =
        serde_json::to_vec(&observed_head.json_v1(context.digest)).context("encode replay head")?;
    canonical_head.push(b'\n');
    let head_bytes = head_file.bytes_v1()?;
    ensure!(
        head_bytes == canonical_head,
        "replay archive head has trailing or non-canonical bytes"
    );

    ensure!(
        seal.schema_version == TERMINAL_SEAL_SCHEMA_VERSION_V1
            && decode_hex32_v1(&seal.body_sha256, "terminal seal body")? == body_sha256
            && seal.run_id == public_context.run_id()
            && decode_hex32_v1(&seal.validator_id, "terminal seal validator")?
                == *public_context.local_validator().as_bytes()
            && decode_hex32_v1(&seal.validator_set_id, "terminal seal validator set ID")?
                == *public_context.validator_set().id().as_bytes()
            && decode_hex32_v1(&seal.validator_set_sha256, "terminal seal validator set")?
                == public_context.validator_set_sha256()
            && decode_hex32_v1(&seal.topology_sha256, "terminal seal topology")?
                == public_context.topology_sha256()
            && decode_hex32_v1(
                &seal.coordinator_manifest_sha256,
                "terminal seal coordinator manifest",
            )? == public_context.coordinator_manifest_sha256()
            && decode_hex32_v1(&seal.candidate_source_sha256, "terminal seal source")?
                == public_context.candidate_source_sha256()
            && decode_hex32_v1(&seal.binary_sha256, "terminal seal binary")?
                == public_context.binary_sha256()
            && decode_hex32_v1(&seal.config_sha256, "terminal seal config")?
                == public_context.config_sha256()
            && decode_hex32_v1(
                &seal.fleet_start_certificate_sha256,
                "terminal seal FleetStart"
            )? != [0; 32]
            && matches!(seal.process_instance, 1 | 2)
            && seal.clean_stop_journal_sequence > 0
            && decode_hex32_v1(&seal.clean_stop_journal_sha256, "terminal seal CleanStop")?
                != [0; 32]
            && seal.finalized_height > 0
            && decode_hex32_v1(&seal.finalized_block_id, "terminal seal finalized block")?
                != [0; 32]
            && decode_hex32_v1(&seal.finalized_state_root, "terminal seal finalized state")?
                != [0; 32]
            && decode_hex32_v1(&seal.finalized_chain_root, "terminal seal finalized chain")?
                != [0; 32]
            && decode_hex32_v1(&seal.archive_context_sha256, "terminal seal context")?
                == context.digest
            && decode_hex32_v1(
                &seal.archive_context_file_sha256,
                "terminal seal context file",
            )? == context_file.sha256
            && seal.archive_context_file_bytes == context_file.length
            && decode_hex32_v1(
                &seal.archive_entries_file_sha256,
                "terminal seal entries file",
            )? == entries_file.sha256
            && seal.archive_entries_file_bytes == entries_file.length
            && decode_hex32_v1(&seal.archive_head_file_sha256, "terminal seal head file")?
                == head_file.sha256
            && seal.archive_head_file_bytes == head_file.length
            && seal.terminal_archive_sequence == log_head.sequence
            && decode_hex32_v1(&seal.terminal_archive_record_sha256, "terminal seal record",)?
                == log_head.record_sha256,
        "terminal replay archive seal differs from exact public/archive facts"
    );
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let semantics = decode_strict_archive_semantics_v1(
        &entries_file.file,
        &index,
        context.digest,
        public_context.validator_set(),
        &parameters,
        public_context.ordinary_start_height(),
        public_context.bootstrap_initial_cut(),
    )?;
    ensure!(
        u64::try_from(semantics.proposals.len()).context("proposal count overflows")?
            == seal.proposal_count
            && u64::try_from(semantics.certificates.len()).context("QC count overflows")?
                == seal.quorum_certificate_count
            && seal.proposal_count > 0
            && seal.quorum_certificate_count > 0,
        "strict Proposal/QC counts differ from terminal seal"
    );
    let coverage = verify_signed_final_tip_coverage_v1(
        &semantics,
        public_context.validator_set(),
        &parameters,
        seal.finalized_height,
        decode_hex32_v1(&seal.finalized_block_id, "terminal seal finalized block")?,
        decode_hex32_v1(&seal.finalized_state_root, "terminal seal finalized state")?,
        decode_hex32_v1(&seal.finalized_chain_root, "terminal seal finalized chain")?,
    )?;
    ensure!(
        decode_hex32_v1(&seal.finality_proof_id, "terminal seal finality proof")?
            == coverage.proof_id
            && decode_hex32_v1(
                &seal.finality_child_block_id,
                "terminal seal finality child"
            )? == coverage.child_block_id
            && decode_hex32_v1(
                &seal.finality_grandchild_block_id,
                "terminal seal finality grandchild",
            )? == coverage.grandchild_block_id,
        "terminal seal finality coverage differs from the strict archived three-chain"
    );
    let (negative_control_certificate_id, negative_control_signer_id) =
        verify_qc_signature_negative_control_v1(
            &semantics.certificates,
            public_context.validator_set(),
        )?;

    let unique_quorum_certificates = semantics
        .certificates
        .iter()
        .map(|(id, certificate)| ReplayArchiveVerifiedCertificateV1 {
            certificate_id: hex::encode(id),
            signature_share_count: u64::try_from(certificate.votes().len())
                .expect("QC share count is bounded by validator count"),
        })
        .collect();

    context_file.revalidate_v1()?;
    entries_file.revalidate_v1()?;
    head_file.revalidate_v1()?;
    seal_file.revalidate_v1()?;
    Ok(ReplayArchiveVerificationV1 {
        schema_version: 1,
        status: "validator-signed-terminal-replay-archive-verified".to_owned(),
        run_id: public_context.run_id().to_owned(),
        validator_id: hex::encode(public_context.local_validator().as_bytes()),
        fleet_start_certificate_sha256: seal.fleet_start_certificate_sha256,
        clean_stop_journal_sequence: seal.clean_stop_journal_sequence,
        clean_stop_journal_sha256: seal.clean_stop_journal_sha256,
        finalized_height: seal.finalized_height,
        finalized_block_id: seal.finalized_block_id,
        finalized_state_root: seal.finalized_state_root,
        finalized_chain_root: seal.finalized_chain_root,
        archive_covers_signed_final_tip: true,
        finality_proof_id: seal.finality_proof_id,
        finality_child_block_id: seal.finality_child_block_id,
        finality_grandchild_block_id: seal.finality_grandchild_block_id,
        archive_context_sha256: hex::encode(context.digest),
        archive_context_file_sha256: hex::encode(context_file.sha256),
        archive_entries_file_sha256: hex::encode(entries_file.sha256),
        archive_head_file_sha256: hex::encode(head_file.sha256),
        terminal_archive_sequence: log_head.sequence,
        terminal_archive_record_sha256: hex::encode(log_head.record_sha256),
        proposal_count: seal.proposal_count,
        quorum_certificate_count: seal.quorum_certificate_count,
        quorum_certificate_signature_share_count: semantics.signature_share_count,
        unique_quorum_certificates,
        negative_control_certificate_id,
        negative_control_signer_id,
        invalid_signature_control_rejected: true,
        input_sha256_unchanged: true,
        observer_verified_nonempty_workload: false,
        observer_verified_finality: false,
        validator_run_completed: false,
        g3_evidence_complete: false,
        geo_wan_evidence: false,
        production_activation: false,
    })
}

fn read_entry_payload_from_pinned_v1(
    entries: &File,
    index: &ReplayArchiveEntryIndexV1,
    context_sha256: [u8; 32],
) -> Result<Vec<u8>> {
    let mut reader = entries
        .try_clone()
        .context("clone pinned replay entry file")?;
    reader
        .seek(SeekFrom::Start(index.offset))
        .context("seek pinned replay entry")?;
    let mut line = vec![0_u8; index.line_bytes];
    reader
        .read_exact(&mut line)
        .context("read pinned replay entry")?;
    let parsed = parse_entry_line_v1(&line, context_sha256, None)?;
    ensure!(
        parsed.index.coordinate == index.coordinate
            && parsed.index.content_sha256 == index.content_sha256
            && parsed.index.record_sha256 == index.record_sha256,
        "pinned replay entry differs from full-log audit"
    );
    Ok(parsed.payload)
}

fn authenticate_all_proposals_v1(
    proposals: &[(ReplayArchiveCoordinateV1, UnboundProposalV0)],
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    ordinary_start_height: u64,
    bootstrap: VerifiedPublicBootstrapInitialCutV1,
) -> Result<BTreeMap<[u8; 32], AuthenticatedReplayProposalV1>> {
    ensure!(
        bootstrap.proposal_parent_height.checked_add(1) == Some(ordinary_start_height),
        "bootstrap parent is not the ordinary-start predecessor"
    );
    let bootstrap_timestamp = WORKLOAD_GENESIS_TIMESTAMP_MS_V1
        .checked_add(
            bootstrap
                .proposal_parent_height
                .checked_mul(WORKLOAD_BLOCK_TIME_STEP_MS_V1)
                .context("bootstrap parent timestamp multiplication overflows")?,
        )
        .context("bootstrap parent timestamp overflows")?;
    let mut authenticated_timestamps = BTreeMap::new();
    authenticated_timestamps.insert(bootstrap.proposal_parent_block_id, bootstrap_timestamp);
    let mut authenticated = BTreeMap::new();
    let mut pending = proposals.to_vec();
    while !pending.is_empty() {
        let mut next = Vec::new();
        let mut admitted = 0_usize;
        for (coordinate, proposal) in pending {
            let parent_id = *proposal.block().header().parent_id().as_bytes();
            let Some(parent_timestamp) = authenticated_timestamps.get(&parent_id).copied() else {
                next.push((coordinate, proposal));
                continue;
            };
            let signed = proposal
                .clone()
                .bind_authenticated_parent(validator_set, parameters, parent_timestamp)
                .map_err(|error| anyhow!("strictly verify archived Proposal signature: {error}"))?;
            ensure!(
                signed.block().id().as_bytes() == &coordinate.block_id,
                "signature-verified Proposal changed archive identity"
            );
            let timestamp = signed.block().header().timestamp_ms();
            ensure!(
                authenticated_timestamps
                    .insert(coordinate.block_id, timestamp)
                    .is_none(),
                "archive repeats one Proposal block ID"
            );
            ensure!(
                authenticated
                    .insert(
                        coordinate.block_id,
                        AuthenticatedReplayProposalV1 {
                            proposal: signed,
                            authenticated_parent_timestamp_ms: parent_timestamp,
                        },
                    )
                    .is_none(),
                "archive repeats one authenticated Proposal block ID"
            );
            admitted += 1;
        }
        ensure!(
            admitted > 0,
            "archived Proposal parent ancestry is missing, forked, or cyclic"
        );
        pending = next;
    }
    Ok(authenticated)
}

fn decode_strict_archive_semantics_v1(
    entries: &File,
    index: &BTreeMap<ReplayArchiveCoordinateV1, ReplayArchiveEntryIndexV1>,
    context_sha256: [u8; 32],
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    ordinary_start_height: u64,
    bootstrap: VerifiedPublicBootstrapInitialCutV1,
) -> Result<StrictReplayArchiveSemanticsV1> {
    let mut unbound_proposals = Vec::new();
    let mut certificates = BTreeMap::<[u8; 32], QuorumCertificate>::new();
    let mut signature_share_count = 0_u64;
    for entry_index in index.values() {
        let payload = read_entry_payload_from_pinned_v1(entries, entry_index, context_sha256)?;
        match entry_index.coordinate.kind {
            ReplayArchiveEntryKindV1::Proposal => {
                let proposal = UnboundProposalV0::decode(&payload, validator_set, parameters)
                    .map_err(|error| anyhow!("strictly decode archived Proposal: {error}"))?;
                let header = proposal.block().header();
                ensure!(
                    header.height().get() == entry_index.coordinate.height
                        && header.view().get() == entry_index.coordinate.view
                        && proposal.block().id().as_bytes() == &entry_index.coordinate.block_id,
                    "decoded Proposal differs from its archive coordinate"
                );
                unbound_proposals.push((entry_index.coordinate, proposal));
            }
            ReplayArchiveEntryKindV1::QuorumCertificate => {
                let certificate = decode_quorum_certificate(&payload, validator_set)
                    .map_err(|error| anyhow!("strictly decode archived QC: {error}"))?;
                ensure!(
                    certificate.height().get() == entry_index.coordinate.height
                        && certificate.view().get() == entry_index.coordinate.view
                        && certificate.block_id().as_bytes() == &entry_index.coordinate.block_id,
                    "decoded QC differs from its archive coordinate"
                );
                signature_share_count = signature_share_count
                    .checked_add(
                        u64::try_from(certificate.votes().len())
                            .context("QC signature-share count overflows")?,
                    )
                    .context("aggregate QC signature-share count overflows")?;
                ensure!(
                    certificates
                        .insert(*certificate.id().as_bytes(), certificate)
                        .is_none(),
                    "archive repeats one QC certificate ID"
                );
            }
        }
    }
    let proposals = authenticate_all_proposals_v1(
        &unbound_proposals,
        validator_set,
        parameters,
        ordinary_start_height,
        bootstrap,
    )?;
    Ok(StrictReplayArchiveSemanticsV1 {
        proposals,
        certificates,
        signature_share_count,
    })
}

fn verify_signed_final_tip_coverage_v1(
    semantics: &StrictReplayArchiveSemanticsV1,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    finalized_height: u64,
    finalized_block_id: [u8; 32],
    finalized_state_root: [u8; 32],
    finalized_chain_root: [u8; 32],
) -> Result<SignedFinalTipCoverageV1> {
    let finalized = semantics
        .proposals
        .get(&finalized_block_id)
        .ok_or_else(|| anyhow!("archive lacks the signed CleanStop finalized Proposal"))?;
    let finalized_header = finalized.proposal.block().header();
    ensure!(
        finalized_header.height().get() == finalized_height
            && finalized.proposal.block().id().as_bytes() == &finalized_block_id
            && finalized_header.state_root().as_bytes() == &finalized_state_root,
        "signed finalized Proposal differs from the CleanStop final tip"
    );
    let finalized_height_bytes = finalized_header.height().get().to_be_bytes();
    let finalized_view_bytes = finalized_header.view().get().to_be_bytes();
    let finalized_timestamp_bytes = finalized_header.timestamp_ms().to_be_bytes();
    let derived_chain_root = hash_parts_v1(
        FINALIZED_PREFIX_CHAIN_ROOT_DOMAIN_V0,
        &[
            finalized_header.chain_id().as_str().as_bytes(),
            validator_set.genesis_hash().as_bytes(),
            &finalized_height_bytes,
            &finalized_view_bytes,
            &finalized_block_id,
            &finalized_timestamp_bytes,
        ],
    );
    ensure!(
        derived_chain_root == finalized_chain_root,
        "signed finalized Proposal differs from the CleanStop finalized chain root"
    );
    let child_height = finalized_height
        .checked_add(1)
        .context("finality child height overflows")?;
    let grandchild_height = child_height
        .checked_add(1)
        .context("finality grandchild height overflows")?;

    for child in semantics.proposals.values() {
        let child_header = child.proposal.block().header();
        if child_header.height().get() != child_height
            || child_header.parent_id().as_bytes() != &finalized_block_id
        {
            continue;
        }
        let finalized_qc_ref = child.proposal.witness().justify_qc().qc_ref();
        let Some(finalized_qc) = semantics
            .certificates
            .get(finalized_qc_ref.qc_digest().as_bytes())
        else {
            continue;
        };
        if QcRef::from(finalized_qc) != finalized_qc_ref {
            continue;
        }
        for grandchild in semantics.proposals.values() {
            let grandchild_header = grandchild.proposal.block().header();
            if grandchild_header.height().get() != grandchild_height
                || grandchild_header.parent_id() != child.proposal.block().id()
            {
                continue;
            }
            let child_qc_ref = grandchild.proposal.witness().justify_qc().qc_ref();
            let Some(child_qc) = semantics
                .certificates
                .get(child_qc_ref.qc_digest().as_bytes())
            else {
                continue;
            };
            if QcRef::from(child_qc) != child_qc_ref {
                continue;
            }
            for grandchild_qc in semantics.certificates.values().filter(|certificate| {
                certificate.block_id() == grandchild.proposal.block().id()
                    && certificate.height().get() == grandchild_height
            }) {
                let Ok(finalized_certified) = CertifiedHeaderV0::from_signed_proposal(
                    finalized.proposal.clone(),
                    finalized_qc.clone(),
                    validator_set,
                    None,
                    parameters,
                    finalized.authenticated_parent_timestamp_ms,
                ) else {
                    continue;
                };
                let Ok(child_certified) = CertifiedHeaderV0::from_signed_proposal(
                    child.proposal.clone(),
                    child_qc.clone(),
                    validator_set,
                    None,
                    parameters,
                    child.authenticated_parent_timestamp_ms,
                ) else {
                    continue;
                };
                let Ok(grandchild_certified) = CertifiedHeaderV0::from_signed_proposal(
                    grandchild.proposal.clone(),
                    grandchild_qc.clone(),
                    validator_set,
                    None,
                    parameters,
                    grandchild.authenticated_parent_timestamp_ms,
                ) else {
                    continue;
                };
                let Ok(proof) = FinalityProofV0::new(
                    finalized_certified,
                    child_certified,
                    grandchild_certified,
                    validator_set,
                    None,
                    parameters,
                    finalized.authenticated_parent_timestamp_ms,
                ) else {
                    continue;
                };
                if proof
                    .verify(
                        validator_set,
                        None,
                        parameters,
                        finalized.authenticated_parent_timestamp_ms,
                        &StrictEd25519Verifier,
                    )
                    .is_err()
                {
                    continue;
                }
                return Ok(SignedFinalTipCoverageV1 {
                    proof_id: *proof.id().as_bytes(),
                    child_block_id: *child.proposal.block().id().as_bytes(),
                    grandchild_block_id: *grandchild.proposal.block().id().as_bytes(),
                });
            }
        }
    }
    bail!("archive does not contain one strict signed three-chain covering the CleanStop final tip")
}

fn verify_qc_signature_negative_control_v1(
    certificates: &BTreeMap<[u8; 32], QuorumCertificate>,
    validator_set: &trnm_consensus_types::ValidatorSet,
) -> Result<(String, String)> {
    let (certificate_id, certificate) = certificates
        .iter()
        .next()
        .ok_or_else(|| anyhow!("negative control requires one archived QC"))?;
    let first_vote = certificate
        .votes()
        .first()
        .ok_or_else(|| anyhow!("negative control QC has no signature shares"))?;
    let corrupted = [0xff; 64];
    let author = validator_set
        .validator(first_vote.author())
        .ok_or_else(|| anyhow!("negative control vote author is absent from validator set"))?;
    let verifying_key = VerifyingKey::from_bytes(author.consensus_key().as_bytes())
        .context("decode negative control vote author key")?;
    let signing_root = Vote::signing_root_for_set(
        validator_set,
        first_vote.view(),
        first_vote.height(),
        first_vote.block_id(),
    )
    .map_err(|error| anyhow!("derive QC negative control signing root: {error:?}"))?;
    ensure!(
        verifying_key
            .verify_strict(signing_root.as_bytes(), &Signature::from_bytes(&corrupted))
            .is_err(),
        "strict Ed25519 verifier accepted the deterministic non-canonical signature control"
    );
    let replacement = Vote::new(
        first_vote.chain_id(),
        first_vote.protocol_version(),
        first_vote.epoch(),
        first_vote.view(),
        first_vote.height(),
        first_vote.block_id(),
        first_vote.validator_set_id(),
        first_vote.author(),
        SignatureBytes::from_array(corrupted),
        validator_set,
    )
    .map_err(|error| anyhow!("construct in-memory QC negative control vote: {error:?}"))?;
    let mut votes = certificate.votes().to_vec();
    votes[0] = replacement;
    let corrupted_certificate = QuorumCertificate::new(
        certificate.chain_id(),
        certificate.protocol_version(),
        certificate.epoch(),
        certificate.view(),
        certificate.height(),
        certificate.block_id(),
        certificate.validator_set_id(),
        votes,
        validator_set,
    )
    .map_err(|error| anyhow!("construct in-memory QC negative control: {error:?}"))?;
    let bytes = encode_quorum_certificate(&corrupted_certificate)
        .map_err(|error| anyhow!("encode in-memory QC negative control: {error}"))?;
    ensure!(
        decode_quorum_certificate(&bytes, validator_set).is_err(),
        "strict QC decoder accepted the deterministic non-canonical signature control"
    );
    Ok((
        hex::encode(certificate_id),
        hex::encode(first_vote.author().as_bytes()),
    ))
}

/// Still-inert process2 owner retaining the audited archive and Node replay
/// owner together.
#[must_use = "authenticated archive replay must be consumed by the full inert process2 recovery"]
pub(crate) struct ArchivedDeployedReplayOwnerV1 {
    _archive: SignedReplayArchiveV1,
    node: PocoNodeDeployedLabAuthenticatedReplayOwnerV0<LabFileWatermark>,
    archive_facts: SignedReplayArchiveFactsV1,
}

impl ArchivedDeployedReplayOwnerV1 {
    /// Consumes the archive-authenticated replay owner into Node's complete
    /// process-2 recovery while keeping the independent archive pins live.
    /// The old recovery owner is deliberately destroyed before the same
    /// authority root is reopened, and no activation method is called.
    pub(crate) fn recover_full_process2_inert_v1(
        self,
        config: &LoadedValidatorConfig,
    ) -> Result<ArchivedDeployedProcess2RecoveryOwnerV1> {
        let Self {
            _archive: archive,
            node,
            archive_facts,
        } = self;
        archive
            .revalidate_identity_v1()
            .context("revalidate pinned replay archive before full process2 recovery")?;
        let recovery_facts = node.recovery_facts_v0().clone();
        let authenticated_replay_facts = node.facts_v0();
        let entries = node.signed_replay_v0().to_vec();
        drop(node);
        let node = config
            .recover_deployed_process2_inert_v1(entries)
            .context("recover complete inert process2 authority")?;
        archive
            .revalidate_identity_v1()
            .context("revalidate pinned replay archive after full process2 recovery")?;
        Ok(ArchivedDeployedProcess2RecoveryOwnerV1 {
            _archive: archive,
            node,
            archive_facts,
            recovery_facts,
            authenticated_replay_facts,
        })
    }
}

impl std::fmt::Debug for ArchivedDeployedReplayOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArchivedDeployedReplayOwnerV1")
            .field("archive_facts", &self.archive_facts)
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

/// Complete, but still inert, process-2 Node recovery retaining the exact
/// audited archive owner that supplied its signed replay entries.
#[must_use = "full process2 recovery must first join RestartCut and later prove signed catch-up"]
pub(crate) struct ArchivedDeployedProcess2RecoveryOwnerV1 {
    _archive: SignedReplayArchiveV1,
    node: PocoNodeDeployedLabProcess2RecoveryOwnerV0<LabFileWatermark>,
    archive_facts: SignedReplayArchiveFactsV1,
    recovery_facts: PocoNodeDeployedLabRecoveryFactsV0,
    authenticated_replay_facts: PocoNodeDeployedLabAuthenticatedReplayFactsV0,
}

impl ArchivedDeployedProcess2RecoveryOwnerV1 {
    /// Rechecks both pinned filesystem identity and the exact audited head
    /// retained by this process-2 recovery owner.  This remains descriptive
    /// and releases no Node, signer, timer, network, or activation authority.
    pub(crate) fn revalidate_archive_identity_v1(&self) -> Result<()> {
        self._archive
            .revalidate_identity_v1()
            .context("revalidate process2 pinned replay archive identity")?;
        ensure!(
            self._archive.facts_v1() == self.archive_facts,
            "process2 pinned replay archive head differs from recovered owner"
        );
        Ok(())
    }

    pub(crate) const fn archive_facts_v1(&self) -> SignedReplayArchiveFactsV1 {
        self.archive_facts
    }

    pub(crate) const fn prior_recovery_facts_v1(&self) -> &PocoNodeDeployedLabRecoveryFactsV0 {
        &self.recovery_facts
    }

    pub(crate) const fn authenticated_replay_facts_v1(
        &self,
    ) -> PocoNodeDeployedLabAuthenticatedReplayFactsV0 {
        self.authenticated_replay_facts
    }

    pub(crate) const fn process2_facts_v1(&self) -> PocoNodeDeployedLabProcess2RecoveryFactsV0 {
        self.node.facts_v0()
    }

    /// Consumes the complete archive-pinned process-2 recovery into Node's
    /// exact, still replay-fenced zero-delta owner.  The archive identity is
    /// freshly revalidated on both sides of the consuming Node join and is
    /// retained in the result; no signer, timer, mesh, or activation authority
    /// is released.
    pub(crate) fn confirm_zero_delta_caught_up_v1(
        self,
        expected: PocoNodeDeployedLabZeroDeltaRestartCutV1,
    ) -> Result<ArchivedDeployedProcess2ZeroDeltaCaughtUpOwnerV1> {
        let Self {
            _archive: archive,
            node,
            archive_facts,
            recovery_facts,
            authenticated_replay_facts,
        } = self;
        archive
            .revalidate_identity_v1()
            .context("revalidate pinned replay archive before zero-delta join")?;
        ensure!(
            archive.facts_v1() == archive_facts,
            "pinned replay archive differs before zero-delta join"
        );
        let process2_facts = node.facts_v0();
        let node = node
            .into_zero_delta_caught_up_v1(expected)
            .map_err(|error| anyhow!("confirm Node zero-delta cut: {error}"))?;
        ensure!(
            node.facts_v1().process2_v1() == process2_facts,
            "Node zero-delta owner changed the process2 recovery projection"
        );
        archive
            .revalidate_identity_v1()
            .context("revalidate pinned replay archive after zero-delta join")?;
        ensure!(
            archive.facts_v1() == archive_facts,
            "pinned replay archive differs after zero-delta join"
        );
        Ok(ArchivedDeployedProcess2ZeroDeltaCaughtUpOwnerV1 {
            _archive: archive,
            node,
            archive_facts,
            recovery_facts,
            authenticated_replay_facts,
        })
    }
}

impl std::fmt::Debug for ArchivedDeployedProcess2RecoveryOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArchivedDeployedProcess2RecoveryOwnerV1")
            .field("archive_facts", &self.archive_facts)
            .field("recovery_facts", &self.recovery_facts)
            .field(
                "authenticated_replay_facts",
                &self.authenticated_replay_facts,
            )
            .field("process2_facts", &self.node.facts_v0())
            .finish_non_exhaustive()
    }
}

/// Archive-pinned, replay-fenced zero-delta process-2 owner.
///
/// The Node owner remains opaque and non-Clone.  This wrapper exposes only
/// descriptive facts plus fresh archive revalidation; it has no Ready/Start,
/// activation, signer, timer, mesh, or raw-parts API.
#[must_use = "zero-delta recovery must retain both Node and replay-archive authority"]
pub(crate) struct ArchivedDeployedProcess2ZeroDeltaCaughtUpOwnerV1 {
    _archive: SignedReplayArchiveV1,
    node: PocoNodeDeployedLabProcess2CaughtUpOwnerV1<LabFileWatermark>,
    archive_facts: SignedReplayArchiveFactsV1,
    recovery_facts: PocoNodeDeployedLabRecoveryFactsV0,
    authenticated_replay_facts: PocoNodeDeployedLabAuthenticatedReplayFactsV0,
}

impl ArchivedDeployedProcess2ZeroDeltaCaughtUpOwnerV1 {
    pub(crate) fn revalidate_archive_identity_v1(&self) -> Result<()> {
        self._archive
            .revalidate_identity_v1()
            .context("revalidate zero-delta pinned replay archive identity")?;
        ensure!(
            self._archive.facts_v1() == self.archive_facts,
            "zero-delta pinned replay archive head differs"
        );
        Ok(())
    }

    /// Revalidates the pinned archive around Node's complete borrowed
    /// zero-delta durable-head audit. No retained authority is released and
    /// Node remains replay-fenced throughout.
    pub(crate) fn revalidate_zero_delta_caught_up_v1(&mut self) -> Result<()> {
        self.revalidate_archive_identity_v1()?;
        let expected = self.node.facts_v1();
        self.node
            .revalidate_zero_delta_caught_up_v1()
            .map_err(|error| anyhow!("freshly revalidate Node zero-delta owner: {error}"))?;
        ensure!(
            self.node.facts_v1() == expected,
            "fresh Node zero-delta revalidation changed retained facts"
        );
        self.revalidate_archive_identity_v1()
    }

    pub(crate) const fn archive_facts_v1(&self) -> SignedReplayArchiveFactsV1 {
        self.archive_facts
    }

    pub(crate) const fn prior_recovery_facts_v1(&self) -> &PocoNodeDeployedLabRecoveryFactsV0 {
        &self.recovery_facts
    }

    pub(crate) const fn authenticated_replay_facts_v1(
        &self,
    ) -> PocoNodeDeployedLabAuthenticatedReplayFactsV0 {
        self.authenticated_replay_facts
    }

    pub(crate) const fn zero_delta_facts_v1(&self) -> PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1 {
        self.node.facts_v1()
    }
}

impl std::fmt::Debug for ArchivedDeployedProcess2ZeroDeltaCaughtUpOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArchivedDeployedProcess2ZeroDeltaCaughtUpOwnerV1")
            .field("archive_facts", &self.archive_facts)
            .field("zero_delta_facts", &self.node.facts_v1())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayArchiveAppendStageV1 {
    BeforeArchive,
    AfterArchiveDurable,
    BeforeAuthorityMutation,
}

struct ParsedReplayArchiveEntryV1 {
    index: ReplayArchiveEntryIndexV1,
    payload: Vec<u8>,
    sequence: u64,
    previous_record_sha256: [u8; 32],
}

fn require_index_within_context_capacity_v1(
    index: &BTreeMap<ReplayArchiveCoordinateV1, ReplayArchiveEntryIndexV1>,
    context: &ReplayArchiveContextV1,
) -> Result<()> {
    let proposals = u64::try_from(
        index
            .keys()
            .filter(|coordinate| coordinate.kind == ReplayArchiveEntryKindV1::Proposal)
            .count(),
    )
    .context("audited replay Proposal count overflows")?;
    let quorum_certificates = u64::try_from(
        index
            .keys()
            .filter(|coordinate| coordinate.kind == ReplayArchiveEntryKindV1::QuorumCertificate)
            .count(),
    )
    .context("audited replay QC count overflows")?;
    let total = proposals
        .checked_add(quorum_certificates)
        .context("audited replay total overflows")?;
    ensure!(
        proposals <= context.json.maximum_proposal_entries
            && quorum_certificates <= context.json.maximum_quorum_certificate_entries
            && total <= context.json.maximum_archive_entries,
        "audited replay inventory exceeds its context-bound capacity"
    );
    Ok(())
}

fn audit_entry_log_v1(
    entries: &mut File,
    context_sha256: [u8; 32],
    maximum_entries: u64,
) -> Result<(
    ReplayArchiveHeadV1,
    Option<ReplayArchiveHeadV1>,
    BTreeMap<ReplayArchiveCoordinateV1, ReplayArchiveEntryIndexV1>,
    u64,
    [u8; 32],
)> {
    ensure!(
        maximum_entries > 0 && maximum_entries <= MAXIMUM_ENTRY_COUNT_V1,
        "replay archive audit entry bound is invalid"
    );
    entries
        .seek(SeekFrom::Start(0))
        .context("seek replay archive for audit")?;
    let audit_file = entries
        .try_clone()
        .context("clone replay archive audit handle")?;
    let mut reader = BufReader::new(audit_file);
    let mut offset = 0_u64;
    let mut head = ReplayArchiveHeadV1::genesis_v1(context_sha256);
    let mut tail_predecessor = None;
    let mut index = BTreeMap::new();
    let mut file_hasher = Sha256::new();
    loop {
        if head.sequence == maximum_entries {
            ensure!(
                reader
                    .fill_buf()
                    .context("peek replay archive past context entry cap")?
                    .is_empty(),
                "context-bound replay archive entry count exceeded"
            );
            break;
        }
        let mut line = Vec::new();
        let mut bounded = (&mut reader).take(
            u64::try_from(MAXIMUM_ENTRY_LINE_BYTES_V1)
                .context("archive line bound overflows")?
                .checked_add(1)
                .context("archive line bound overflows")?,
        );
        let bytes = bounded
            .read_until(b'\n', &mut line)
            .context("read replay archive entry")?;
        if bytes == 0 {
            break;
        }
        ensure!(
            line.last() == Some(&b'\n'),
            "replay archive has a truncated final entry"
        );
        ensure!(
            line.len() <= MAXIMUM_ENTRY_LINE_BYTES_V1,
            "replay archive entry is oversized"
        );
        file_hasher.update(&line);
        let mut parsed = parse_entry_line_v1(&line, context_sha256, Some(head))?;
        parsed.index.offset = offset;
        ensure!(
            parsed.sequence == head.sequence + 1
                && parsed.previous_record_sha256 == head.record_sha256,
            "replay archive sequence or hash chain is discontinuous"
        );
        ensure!(
            index
                .insert(parsed.index.coordinate, parsed.index.clone())
                .is_none(),
            "replay archive contains a duplicate/forked logical coordinate"
        );
        tail_predecessor = Some(head);
        head = ReplayArchiveHeadV1 {
            sequence: parsed.sequence,
            record_sha256: parsed.index.record_sha256,
        };
        ensure!(
            head.sequence <= maximum_entries,
            "context-bound replay archive entry count exceeded"
        );
        offset = offset
            .checked_add(u64::try_from(bytes).context("archive line length overflows")?)
            .context("archive byte offset overflows")?;
    }
    ensure!(
        entries.metadata()?.len() == offset,
        "replay archive length changed during audit"
    );
    Ok((
        head,
        tail_predecessor,
        index,
        offset,
        file_hasher.finalize().into(),
    ))
}

fn context_bound_entry_file_bytes_v1(maximum_entries: u64) -> Result<u64> {
    let maximum = maximum_entries
        .checked_mul(
            u64::try_from(MAXIMUM_ENTRY_LINE_BYTES_V1)
                .context("context-bound replay entry byte ceiling overflows")?,
        )
        .context("context-bound replay archive byte ceiling overflows")?;
    ensure!(
        maximum_entries > 0
            && maximum_entries <= MAXIMUM_ENTRY_COUNT_V1
            && maximum > 0
            && maximum <= MAXIMUM_ENTRY_FILE_BYTES_V1,
        "context-bound replay archive byte ceiling exceeds implementation capacity"
    );
    Ok(maximum)
}

fn parse_entry_line_v1(
    line: &[u8],
    context_sha256: [u8; 32],
    prior: Option<ReplayArchiveHeadV1>,
) -> Result<ParsedReplayArchiveEntryV1> {
    let entry: ReplayArchiveEntryJsonV1 =
        serde_json::from_slice(line).context("decode replay archive entry")?;
    let mut canonical_line =
        serde_json::to_vec(&entry).context("re-encode replay archive entry")?;
    canonical_line.push(b'\n');
    ensure!(
        line == canonical_line,
        "replay archive entry has trailing or non-canonical bytes"
    );
    ensure!(
        entry.schema_version == SCHEMA_VERSION_V1,
        "wrong replay archive entry schema"
    );
    let kind = ReplayArchiveEntryKindV1::parse_v1(&entry.kind)?;
    let coordinate = ReplayArchiveCoordinateV1 {
        kind,
        height: entry.height,
        view: entry.view,
        block_id: decode_hex32_v1(&entry.block_id, "entry block id")?,
    };
    ensure!(
        coordinate.height > 0 && coordinate.view > 0,
        "zero replay archive coordinate"
    );
    let observed_context = decode_hex32_v1(&entry.context_sha256, "entry context")?;
    ensure!(
        observed_context == context_sha256,
        "entry context differs from archive context"
    );
    let previous_record_sha256 =
        decode_hex32_v1(&entry.previous_record_sha256, "entry predecessor")?;
    if let Some(prior) = prior {
        ensure!(
            entry.sequence == prior.sequence + 1 && previous_record_sha256 == prior.record_sha256,
            "entry predecessor differs from audited archive head"
        );
    }
    let payload = hex::decode(&entry.payload_hex).context("decode replay archive payload")?;
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_FRAME_PAYLOAD_BYTES,
        "invalid archived payload size"
    );
    let content_sha256 = decode_hex32_v1(&entry.content_sha256, "entry content digest")?;
    ensure!(
        content_sha256 == content_sha256_v1(kind, &payload),
        "replay archive content digest mismatch"
    );
    let record_sha256 = decode_hex32_v1(&entry.record_sha256, "entry record digest")?;
    ensure!(
        record_sha256
            == record_sha256_v1(
                context_sha256,
                entry.sequence,
                previous_record_sha256,
                coordinate,
                content_sha256,
            ),
        "replay archive record digest mismatch"
    );
    Ok(ParsedReplayArchiveEntryV1 {
        index: ReplayArchiveEntryIndexV1 {
            coordinate,
            content_sha256,
            record_sha256,
            offset: 0,
            line_bytes: line.len(),
        },
        payload,
        sequence: entry.sequence,
        previous_record_sha256,
    })
}

fn repair_or_reject_head_v1(
    root: &Path,
    context_sha256: [u8; 32],
    log_head: ReplayArchiveHeadV1,
    tail_predecessor: Option<ReplayArchiveHeadV1>,
    directory: &File,
) -> Result<bool> {
    let head_path = root.join(HEAD_FILE_V1);
    let next_path = root.join(NEXT_HEAD_FILE_V1);
    let existing_tombstone = load_repair_tombstone_v1(root, context_sha256)?;
    if path_exists_no_follow_v1(&next_path)? {
        let next = read_head_v1(&next_path, context_sha256)?;
        let current = read_head_v1(&head_path, context_sha256)?;
        ensure!(
            next == log_head && (current == log_head || tail_predecessor == Some(current)),
            "orphan replay archive next-head is not the exact log successor"
        );
        let tombstone = ReplayArchiveRepairTombstoneV1::new_v1(
            context_sha256,
            "next-head-present",
            log_head,
            current,
            Some(next),
        )?;
        persist_or_validate_repair_tombstone_v1(
            root,
            context_sha256,
            existing_tombstone.as_ref(),
            &tombstone,
            directory,
        )?;
        if current != log_head {
            fs::rename(&next_path, &head_path)
                .context("complete replay archive head replacement")?;
        } else {
            fs::remove_file(&next_path).context("remove redundant replay archive next-head")?;
        }
        directory
            .sync_all()
            .context("fsync repaired replay archive directory")?;
    }
    let observed = read_head_v1(&head_path, context_sha256)?;
    if observed == log_head {
        return Ok(existing_tombstone.is_some()
            || path_exists_no_follow_v1(&root.join(REPAIR_TOMBSTONE_FILE_V1))?);
    }
    if tail_predecessor == Some(observed) {
        let tombstone = ReplayArchiveRepairTombstoneV1::new_v1(
            context_sha256,
            "one-ahead-log",
            log_head,
            observed,
            None,
        )?;
        persist_or_validate_repair_tombstone_v1(
            root,
            context_sha256,
            existing_tombstone.as_ref(),
            &tombstone,
            directory,
        )?;
        write_head_atomic_v1(root, context_sha256, log_head, directory)?;
        return Ok(true);
    }
    bail!("replay archive head proves truncation, multi-entry loss, or a fork")
}

fn read_repair_tombstone_from_file_v1(
    file: &File,
    context_sha256: [u8; 32],
) -> Result<ReplayArchiveRepairTombstoneV1> {
    let bytes = read_exact_file_bytes_v1(
        file,
        MAXIMUM_REPAIR_TOMBSTONE_BYTES_V1,
        false,
        "replay archive repair tombstone",
    )?;
    let value: ReplayArchiveRepairTombstoneV1 =
        serde_json::from_slice(&bytes).context("decode replay archive repair tombstone")?;
    value.validate_v1(context_sha256)?;
    ensure!(
        bytes == value.canonical_bytes_v1()?,
        "replay archive repair tombstone has trailing or non-canonical bytes"
    );
    Ok(value)
}

fn open_and_validate_repair_tombstone_v1(root: &Path, context_sha256: [u8; 32]) -> Result<File> {
    let file = open_private_file_v1(&root.join(REPAIR_TOMBSTONE_FILE_V1), false)?;
    let _ = read_repair_tombstone_from_file_v1(&file, context_sha256)?;
    Ok(file)
}

fn load_repair_tombstone_v1(
    root: &Path,
    context_sha256: [u8; 32],
) -> Result<Option<ReplayArchiveRepairTombstoneV1>> {
    if !path_exists_no_follow_v1(&root.join(REPAIR_TOMBSTONE_FILE_V1))? {
        return Ok(None);
    }
    let file = open_and_validate_repair_tombstone_v1(root, context_sha256)?;
    Ok(Some(read_repair_tombstone_from_file_v1(
        &file,
        context_sha256,
    )?))
}

fn persist_or_validate_repair_tombstone_v1(
    root: &Path,
    context_sha256: [u8; 32],
    existing: Option<&ReplayArchiveRepairTombstoneV1>,
    candidate: &ReplayArchiveRepairTombstoneV1,
    directory: &File,
) -> Result<()> {
    candidate.validate_v1(context_sha256)?;
    if let Some(existing) = existing {
        ensure!(
            existing.same_repair_event_v1(candidate),
            "existing repair tombstone describes a different repair event"
        );
    } else {
        write_new_private_file_v1(
            &root.join(REPAIR_TOMBSTONE_FILE_V1),
            &candidate.canonical_bytes_v1()?,
        )?;
        directory
            .sync_all()
            .context("fsync replay archive directory after repair tombstone")?;
    }
    let observed = load_repair_tombstone_v1(root, context_sha256)?
        .ok_or_else(|| anyhow!("durable repair tombstone disappeared"))?;
    ensure!(
        observed.same_repair_event_v1(candidate),
        "durable repair tombstone differs from intended repair"
    );
    Ok(())
}

fn write_head_atomic_v1(
    root: &Path,
    context_sha256: [u8; 32],
    head: ReplayArchiveHeadV1,
    directory: &File,
) -> Result<()> {
    let next = root.join(NEXT_HEAD_FILE_V1);
    ensure!(
        !path_exists_no_follow_v1(&next)?,
        "replay archive next-head already exists"
    );
    let mut bytes =
        serde_json::to_vec(&head.json_v1(context_sha256)).context("encode replay archive head")?;
    bytes.push(b'\n');
    write_new_private_file_v1(&next, &bytes)?;
    fs::rename(&next, root.join(HEAD_FILE_V1)).context("replace replay archive head")?;
    directory
        .sync_all()
        .context("fsync replay archive directory")?;
    ensure!(
        read_head_v1(&root.join(HEAD_FILE_V1), context_sha256)? == head,
        "replaced replay archive head failed exact readback"
    );
    Ok(())
}

fn read_head_v1(path: &Path, context_sha256: [u8; 32]) -> Result<ReplayArchiveHeadV1> {
    let file = open_private_file_v1(path, false)?;
    read_head_from_file_v1(&file, context_sha256)
}

fn read_head_from_file_v1(file: &File, context_sha256: [u8; 32]) -> Result<ReplayArchiveHeadV1> {
    let value: ReplayArchiveHeadJsonV1 =
        read_bounded_json_v1(&file, MAXIMUM_HEAD_BYTES_V1, "archive head")?;
    ensure!(
        value.schema_version == SCHEMA_VERSION_V1,
        "wrong replay archive head schema"
    );
    ensure!(
        value.context_sha256.0 == context_sha256,
        "replay archive head context mismatch"
    );
    let head = ReplayArchiveHeadV1 {
        sequence: value.sequence,
        record_sha256: value.record_sha256.0,
    };
    if head.sequence == 0 {
        ensure!(
            head == ReplayArchiveHeadV1::genesis_v1(context_sha256),
            "replay archive genesis head is not canonical"
        );
    }
    Ok(head)
}

fn validate_inventory_v1(root: &Path) -> Result<()> {
    let observed = fs::read_dir(root)
        .context("read replay archive inventory")?
        .map(|entry| {
            entry
                .context("read replay archive inventory entry")?
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("non-UTF8 replay archive entry"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let required = [CONTEXT_FILE_V1, ENTRY_FILE_V1, HEAD_FILE_V1]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut allowed = required.clone();
    allowed.insert(NEXT_HEAD_FILE_V1.to_owned());
    allowed.insert(REPAIR_TOMBSTONE_FILE_V1.to_owned());
    ensure!(
        required.is_subset(&observed) && observed.is_subset(&allowed),
        "unexpected replay archive inventory"
    );
    Ok(())
}

fn validate_terminal_inventory_v1(root: &Path) -> Result<()> {
    let observed = fs::read_dir(root)
        .context("read terminal replay archive inventory")?
        .map(|entry| {
            entry
                .context("read terminal replay archive inventory entry")?
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("non-UTF8 terminal replay archive entry"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let required = [CONTEXT_FILE_V1, ENTRY_FILE_V1, HEAD_FILE_V1]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    ensure!(
        observed == required,
        "terminal replay archive inventory contains a repair or foreign artifact"
    );
    Ok(())
}

fn require_archive_directory_v1(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect replay archive directory {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "replay archive directory is a symlink"
    );
    validate_private_directory_metadata_v1(&metadata, "replay archive directory")?;
    let canonical = path
        .canonicalize()
        .context("canonicalize replay archive directory")?;
    ensure!(canonical == path, "replay archive path is not canonical");
    Ok(canonical)
}

fn open_directory_pinned_v1(path: &Path) -> Result<File> {
    let before = fs::symlink_metadata(path).context("inspect replay archive directory path")?;
    ensure!(
        !before.file_type().is_symlink(),
        "replay archive directory path is a symlink"
    );
    validate_private_directory_metadata_v1(&before, "replay archive directory path")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .context("open replay archive directory")?;
    let metadata = file
        .metadata()
        .context("inspect replay archive directory handle")?;
    validate_private_directory_metadata_v1(&metadata, "replay archive directory handle")?;
    ensure!(
        FileIdentityV1::from_metadata_v1(&before).matches_metadata_v1(&metadata),
        "replay archive directory identity changed while opening"
    );
    Ok(file)
}

fn revalidate_directory_path_identity_v1(
    path: &Path,
    pinned: &File,
    identity: FileIdentityV1,
    label: &'static str,
) -> Result<()> {
    ensure!(
        identity.matches_file_v1(pinned)?,
        "pinned {label} identity changed"
    );
    let reopened = open_directory_pinned_v1(path)?;
    ensure!(
        identity.matches_file_v1(&reopened)?,
        "{label} path was replaced"
    );
    Ok(())
}

fn open_private_file_v1(path: &Path, writable: bool) -> Result<File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect replay archive file {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "replay archive file is a symlink"
    );
    validate_private_regular_metadata_v1(&metadata, "replay archive file path")?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    if writable {
        options.write(true);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open replay archive file {}", path.display()))?;
    let opened = file
        .metadata()
        .context("inspect opened replay archive file")?;
    validate_private_regular_metadata_v1(&opened, "opened replay archive file")?;
    ensure!(
        FileIdentityV1::from_metadata_v1(&metadata).matches_metadata_v1(&opened)
            && opened.len() == metadata.len(),
        "replay archive file identity changed while opening"
    );
    Ok(file)
}

fn write_new_private_file_v1(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("create replay archive file {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set replay archive file mode {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write replay archive file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync replay archive file {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect new replay archive file {}", path.display()))?;
    validate_private_regular_metadata_v1(&opened, "new replay archive file")?;
    ensure!(
        opened.len() == u64::try_from(bytes.len()).context("new archive file length overflows")?,
        "new replay archive file length differs after fsync"
    );
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reinspect new replay archive file {}", path.display()))?;
    ensure!(
        !path_metadata.file_type().is_symlink()
            && FileIdentityV1::from_metadata_v1(&opened).matches_metadata_v1(&path_metadata),
        "new replay archive file path changed after fsync"
    );
    Ok(())
}

fn read_bounded_json_v1<T: for<'de> Deserialize<'de>>(
    file: &File,
    maximum: u64,
    label: &'static str,
) -> Result<T> {
    let length = file
        .metadata()
        .with_context(|| format!("stat {label}"))?
        .len();
    ensure!(
        length > 0 && length <= maximum,
        "{label} has an invalid byte length"
    );
    let mut bytes = Vec::with_capacity(usize::try_from(length).context("JSON length overflows")?);
    let mut reader = file
        .try_clone()
        .with_context(|| format!("clone {label} handle"))?;
    reader
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("seek {label}"))?;
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    ensure!(
        bytes.len() == usize::try_from(length).context("JSON length overflows")?,
        "{label} changed while reading"
    );
    serde_json::from_slice(&bytes).with_context(|| format!("decode {label}"))
}

fn read_exact_file_bytes_v1(
    file: &File,
    maximum: u64,
    allow_empty: bool,
    label: &'static str,
) -> Result<Vec<u8>> {
    let metadata = file.metadata().with_context(|| format!("stat {label}"))?;
    ensure!(
        (allow_empty || metadata.len() > 0) && metadata.len() <= maximum,
        "{label} has an invalid byte length"
    );
    let mut reader = file
        .try_clone()
        .with_context(|| format!("clone {label} handle"))?;
    reader
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("seek {label}"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).with_context(|| format!("{label} length overflows"))?,
    );
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    ensure!(
        u64::try_from(bytes.len()).with_context(|| format!("{label} length overflows"))?
            == metadata.len()
            && file.metadata()?.len() == metadata.len(),
        "{label} changed while reading"
    );
    Ok(bytes)
}

fn hash_exact_file_sha256_v1(
    file: &File,
    maximum: u64,
    allow_empty: bool,
    label: &'static str,
) -> Result<([u8; 32], u64)> {
    let metadata = file.metadata().with_context(|| format!("stat {label}"))?;
    ensure!(
        (allow_empty || metadata.len() > 0) && metadata.len() <= maximum,
        "{label} has an invalid byte length"
    );
    let mut reader = file
        .try_clone()
        .with_context(|| format!("clone {label} hash handle"))?;
    reader
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("seek {label} for SHA-256"))?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("hash {label}"))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(count).context("hash byte count overflows")?)
            .context("hash byte count overflows")?;
        ensure!(observed <= maximum, "{label} exceeded its byte bound");
        hasher.update(&buffer[..count]);
    }
    ensure!(
        observed == metadata.len() && file.metadata()?.len() == metadata.len(),
        "{label} changed while hashing"
    );
    Ok((hasher.finalize().into(), observed))
}

fn effective_uid_v1() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn validate_private_directory_metadata_v1(
    metadata: &fs::Metadata,
    label: &'static str,
) -> Result<()> {
    ensure!(
        metadata.is_dir()
            && metadata.uid() == effective_uid_v1()
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "{label} is not an effective-user-owned 0700 directory"
    );
    Ok(())
}

fn validate_private_regular_metadata_v1(
    metadata: &fs::Metadata,
    label: &'static str,
) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.uid() == effective_uid_v1()
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.nlink() == 1,
        "{label} is not an effective-user-owned single-link 0600 regular file"
    );
    Ok(())
}

fn path_exists_no_follow_v1(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("inspect archive path {}", path.display()))
        }
    }
}

fn content_sha256_v1(kind: ReplayArchiveEntryKindV1, payload: &[u8]) -> [u8; 32] {
    hash_parts_v1(CONTENT_DOMAIN_V1, &[&[kind.code_v1()], payload])
}

fn record_sha256_v1(
    context_sha256: [u8; 32],
    sequence: u64,
    previous_record_sha256: [u8; 32],
    coordinate: ReplayArchiveCoordinateV1,
    content_sha256: [u8; 32],
) -> [u8; 32] {
    hash_parts_v1(
        RECORD_DOMAIN_V1,
        &[
            &context_sha256,
            &sequence.to_be_bytes(),
            &previous_record_sha256,
            &[coordinate.kind.code_v1()],
            &coordinate.height.to_be_bytes(),
            &coordinate.view.to_be_bytes(),
            &coordinate.block_id,
            &content_sha256,
        ],
    )
}

fn hash_parts_v1(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
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

fn decode_hex32_v1(value: &str, label: &'static str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("decode {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} is not exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use ed25519_dalek::{Signer as _, SigningKey};
    use tempfile::TempDir;
    use trnm_consensus_core::leader_for;
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockHeader, BlockId, BlockKind, ChainId, ConsensusPublicKey,
        Epoch, EvidenceRoot, GenesisHash, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion,
        QcReferenceV0, ReceiptsRoot, StateRoot, Validator, ValidatorId, ValidatorSet, View,
        VotingPower,
    };

    use super::*;

    fn context_v1() -> ReplayArchiveContextV1 {
        ReplayArchiveContextV1::from_fields_v1(ReplayArchiveContextJsonV1 {
            schema_version: SCHEMA_VERSION_V1,
            run_id: "archive-test-run".to_owned(),
            chain_id: "archive-test-chain".to_owned(),
            genesis_hash: hex::encode([1; 32]),
            validator_set_id: hex::encode([2; 32]),
            local_validator_id: hex::encode([3; 32]),
            local_consensus_public_key: hex::encode([4; 32]),
            coordinator_manifest_sha256: hex::encode([5; 32]),
            validator_set_sha256: hex::encode([6; 32]),
            topology_sha256: hex::encode([7; 32]),
            config_sha256: hex::encode([8; 32]),
            candidate_source_sha256: hex::encode([9; 32]),
            binary_sha256: hex::encode([10; 32]),
            workload_corpus_sha256: hex::encode([11; 32]),
            workload_policy_sha256: hex::encode([12; 32]),
            ordinary_start_height: 4,
            maximum_timeout_view_advances: 8,
            maximum_proposal_entries: 16,
            maximum_quorum_certificate_entries: 17,
            maximum_archive_entries: 33,
            context_sha256: String::new(),
        })
        .unwrap()
    }

    struct TerminalSealTestConfigV1 {
        run_root: PathBuf,
        run_id: String,
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        signing_key: SigningKey,
        validator_set_sha256: [u8; 32],
        topology_sha256: [u8; 32],
        config_sha256: [u8; 32],
        coordinator_manifest_sha256: [u8; 32],
        binary_sha256: [u8; 32],
        candidate_source_sha256: [u8; 32],
        ordinary_start_height: u64,
        workload_corpus_sha256: [u8; 32],
        workload_policy_sha256: [u8; 32],
    }

    impl ReplayArchiveTerminalConfigV1 for TerminalSealTestConfigV1 {
        fn run_root(&self) -> &Path {
            &self.run_root
        }

        fn run_id(&self) -> &str {
            &self.run_id
        }

        fn local_validator(&self) -> ValidatorId {
            self.local_validator
        }

        fn validator_set(&self) -> &ValidatorSet {
            &self.validator_set
        }

        fn consensus_parameters(&self) -> &ConsensusParametersV0 {
            &self.consensus_parameters
        }

        fn consensus_signing_key(&self) -> &SigningKey {
            &self.signing_key
        }

        fn validator_set_sha256(&self) -> [u8; 32] {
            self.validator_set_sha256
        }

        fn topology_sha256(&self) -> [u8; 32] {
            self.topology_sha256
        }

        fn config_sha256(&self) -> [u8; 32] {
            self.config_sha256
        }

        fn coordinator_manifest_sha256(&self) -> [u8; 32] {
            self.coordinator_manifest_sha256
        }

        fn binary_sha256(&self) -> [u8; 32] {
            self.binary_sha256
        }

        fn candidate_source_sha256(&self) -> [u8; 32] {
            self.candidate_source_sha256
        }

        fn ordinary_start_height(&self) -> u64 {
            self.ordinary_start_height
        }

        fn workload_corpus_sha256(&self) -> [u8; 32] {
            self.workload_corpus_sha256
        }

        fn workload_policy_sha256(&self) -> [u8; 32] {
            self.workload_policy_sha256
        }
    }

    fn initialize_for_test_v1(temp: &TempDir) -> SignedReplayArchiveV1 {
        initialize_for_context_v1(temp, context_v1())
    }

    fn initialize_for_context_v1(
        temp: &TempDir,
        context: ReplayArchiveContextV1,
    ) -> SignedReplayArchiveV1 {
        let root = temp.path().join(ARCHIVE_DIRECTORY_V1);
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        write_new_private_file_v1(
            &root.join(CONTEXT_FILE_V1),
            &context.canonical_bytes_v1().unwrap(),
        )
        .unwrap();
        write_new_private_file_v1(&root.join(ENTRY_FILE_V1), &[]).unwrap();
        let directory = open_directory_pinned_v1(&root).unwrap();
        write_head_atomic_v1(
            &root,
            context.digest,
            ReplayArchiveHeadV1::genesis_v1(context.digest),
            &directory,
        )
        .unwrap();
        drop(directory);
        open_for_test_v1(&root, context)
    }

    fn open_for_test_v1(root: &Path, expected: ReplayArchiveContextV1) -> SignedReplayArchiveV1 {
        let root = require_archive_directory_v1(root).unwrap();
        let directory = open_directory_pinned_v1(&root).unwrap();
        FileExt::try_lock_exclusive(&directory).unwrap();
        validate_inventory_v1(&root).unwrap();
        let context_file = open_private_file_v1(&root.join(CONTEXT_FILE_V1), false).unwrap();
        let observed: ReplayArchiveContextJsonV1 =
            read_bounded_json_v1(&context_file, MAXIMUM_CONTEXT_BYTES_V1, "test context").unwrap();
        assert_eq!(
            ReplayArchiveContextV1::from_fields_v1(observed).unwrap(),
            expected
        );
        let mut entries_file = open_private_file_v1(&root.join(ENTRY_FILE_V1), true).unwrap();
        let (head, tail_predecessor, index, entries_len, _entries_sha256) = audit_entry_log_v1(
            &mut entries_file,
            expected.digest,
            expected.json.maximum_archive_entries,
        )
        .unwrap();
        require_index_within_context_capacity_v1(&index, &expected).unwrap();
        let historically_repaired =
            repair_or_reject_head_v1(&root, expected.digest, head, tail_predecessor, &directory)
                .unwrap();
        let head_file = open_private_file_v1(&root.join(HEAD_FILE_V1), false).unwrap();
        let repair_tombstone_file = historically_repaired
            .then(|| open_and_validate_repair_tombstone_v1(&root, expected.digest).unwrap());
        let repair_tombstone_identity = repair_tombstone_file
            .as_ref()
            .map(|file| FileIdentityV1::from_file_v1(file).unwrap());
        SignedReplayArchiveV1 {
            directory_identity: FileIdentityV1::from_file_v1(&directory).unwrap(),
            entries_identity: FileIdentityV1::from_file_v1(&entries_file).unwrap(),
            context_identity: FileIdentityV1::from_file_v1(&context_file).unwrap(),
            head_identity: FileIdentityV1::from_file_v1(&head_file).unwrap(),
            root,
            context: expected,
            directory,
            entries_file,
            context_file,
            head_file,
            repair_tombstone_file,
            repair_tombstone_identity,
            entries_len,
            head,
            index,
            owner_pid: std::process::id(),
            fail_stopped: false,
            historically_repaired,
        }
    }

    fn statement_v1(payload: &[u8]) -> ReplayArchiveStatementV1 {
        ReplayArchiveStatementV1 {
            coordinate: ReplayArchiveCoordinateV1 {
                kind: ReplayArchiveEntryKindV1::Proposal,
                height: 4,
                view: 4,
                block_id: [0x44; 32],
            },
            payload: payload.to_vec(),
        }
    }

    fn successor_statement_v1(payload: &[u8]) -> ReplayArchiveStatementV1 {
        ReplayArchiveStatementV1 {
            coordinate: ReplayArchiveCoordinateV1 {
                kind: ReplayArchiveEntryKindV1::Proposal,
                height: 5,
                view: 5,
                block_id: [0x55; 32],
            },
            payload: payload.to_vec(),
        }
    }

    fn replace_head_for_test_v1(root: &Path, context_sha256: [u8; 32], head: ReplayArchiveHeadV1) {
        let path = root.join(HEAD_FILE_V1);
        fs::remove_file(&path).unwrap();
        let mut bytes = serde_json::to_vec(&head.json_v1(context_sha256)).unwrap();
        bytes.push(b'\n');
        write_new_private_file_v1(&path, &bytes).unwrap();
    }

    fn terminal_seal_v1(key: &SigningKey) -> ReplayArchiveTerminalSealV1 {
        let mut seal = ReplayArchiveTerminalSealV1 {
            schema_version: TERMINAL_SEAL_SCHEMA_VERSION_V1,
            run_id: "poco-g3-7-20260818T000000Z-a1b0a001".to_owned(),
            validator_id: hex::encode([1; 32]),
            validator_set_id: hex::encode([2; 32]),
            validator_set_sha256: hex::encode([3; 32]),
            topology_sha256: hex::encode([4; 32]),
            coordinator_manifest_sha256: hex::encode([5; 32]),
            candidate_source_sha256: hex::encode([6; 32]),
            binary_sha256: hex::encode([7; 32]),
            config_sha256: hex::encode([8; 32]),
            fleet_start_certificate_sha256: hex::encode([9; 32]),
            process_instance: 1,
            clean_stop_journal_sequence: 11,
            clean_stop_journal_sha256: hex::encode([10; 32]),
            finalized_height: 19,
            finalized_block_id: hex::encode([0x19; 32]),
            finalized_state_root: hex::encode([0x1a; 32]),
            finalized_chain_root: hex::encode([0x1b; 32]),
            finality_proof_id: hex::encode([0x1c; 32]),
            finality_child_block_id: hex::encode([0x1d; 32]),
            finality_grandchild_block_id: hex::encode([0x1e; 32]),
            archive_context_sha256: hex::encode([11; 32]),
            archive_context_file_sha256: hex::encode([12; 32]),
            archive_context_file_bytes: 101,
            archive_entries_file_sha256: hex::encode([13; 32]),
            archive_entries_file_bytes: 202,
            archive_head_file_sha256: hex::encode([14; 32]),
            archive_head_file_bytes: 303,
            terminal_archive_sequence: 17,
            terminal_archive_record_sha256: hex::encode([15; 32]),
            proposal_count: 8,
            quorum_certificate_count: 9,
            body_sha256: String::new(),
            signature: String::new(),
        };
        let body = seal.computed_body_sha256_v1().unwrap();
        seal.body_sha256 = hex::encode(body);
        let root = hash_parts_v1(TERMINAL_SEAL_SIGNATURE_DOMAIN_V1, &[&body]);
        seal.signature = hex::encode(key.sign(&root).to_bytes());
        seal
    }

    fn qc_fixture_v1() -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (1_u8..=4)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([u8::try_from(index + 1).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x91; 32]),
            ChainId::new("trnm-poco-replay-seal-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn signed_proposal_fixture_v1(set: &ValidatorSet, key: &SigningKey) -> UnboundProposalV0 {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let payload = ApplicationPayloadV0::new(vec![b"sealed-replay-proposal".to_vec()]).unwrap();
        let payload_bytes = payload.try_cev0_bytes().unwrap();
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            BlockKind::Regular,
            BlockId::new(*set.genesis_hash().as_bytes()),
            set.validators()[0].id(),
            set.id(),
            parameters.hash(),
            payload.payload_root().unwrap(),
            StateRoot::new([0x45; 32]),
            ReceiptsRoot::new([0x46; 32]),
            EvidenceRoot::new([0x47; 32]),
            1,
            None,
        )
        .unwrap();
        let justify = QcReferenceV0::genesis_anchor(
            GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap(),
        );
        let signing_root =
            ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
        let witness = ProposalWitnessV0::new(
            &header,
            justify,
            None,
            None,
            SignatureBytes::from_array(key.sign(signing_root.as_bytes()).to_bytes()),
            set,
            None,
            &parameters,
            0,
        )
        .unwrap();
        let proposal = trnm_consensus_types::SignedProposalV0::new(
            Block::new(header, payload_bytes, Vec::new()).unwrap(),
            witness,
            set,
            None,
            &parameters,
            0,
        )
        .unwrap();
        UnboundProposalV0::from_signed(&proposal).unwrap()
    }

    fn strict_qc_fixture_for_block_v1(
        set: &ValidatorSet,
        keys: &[SigningKey],
        height: u64,
        block_id: BlockId,
    ) -> QuorumCertificate {
        let view = View::new(height);
        let height = Height::new(height);
        let root = Vote::signing_root_for_set(set, view, height, block_id).unwrap();
        let votes = set
            .validators()
            .iter()
            .zip(keys)
            .map(|(validator, key)| {
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    view,
                    height,
                    block_id,
                    set.id(),
                    validator.id(),
                    SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes()),
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

    fn strict_proposal_fixture_v1(
        set: &ValidatorSet,
        keys: &[SigningKey],
        height: u64,
        parent_id: BlockId,
        parent_timestamp_ms: u64,
        justify_qc: QuorumCertificate,
        state_root: StateRoot,
    ) -> SignedProposalV0 {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let view = View::new(height);
        let proposer = leader_for(set, view);
        let proposer_index = set
            .validators()
            .iter()
            .position(|validator| validator.id() == proposer)
            .unwrap();
        let payload = ApplicationPayloadV0::new(vec![height.to_be_bytes().to_vec()]).unwrap();
        let payload_bytes = payload.try_cev0_bytes().unwrap();
        let timestamp_ms =
            WORKLOAD_GENESIS_TIMESTAMP_MS_V1 + WORKLOAD_BLOCK_TIME_STEP_MS_V1 * height;
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            view,
            Height::new(height),
            BlockKind::Regular,
            parent_id,
            proposer,
            set.id(),
            parameters.hash(),
            payload.payload_root().unwrap(),
            state_root,
            ReceiptsRoot::new([0x61 + u8::try_from(height).unwrap(); 32]),
            EvidenceRoot::new([0x71 + u8::try_from(height).unwrap(); 32]),
            timestamp_ms,
            None,
        )
        .unwrap();
        let justify = QcReferenceV0::ordinary(justify_qc);
        let signing_root =
            ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
        let witness = ProposalWitnessV0::new(
            &header,
            justify,
            None,
            None,
            SignatureBytes::from_array(
                keys[proposer_index]
                    .sign(signing_root.as_bytes())
                    .to_bytes(),
            ),
            set,
            None,
            &parameters,
            parent_timestamp_ms,
        )
        .unwrap();
        SignedProposalV0::new(
            Block::new(header, payload_bytes, Vec::new()).unwrap(),
            witness,
            set,
            None,
            &parameters,
            parent_timestamp_ms,
        )
        .unwrap()
    }

    fn strict_three_chain_semantics_fixture_v1() -> (
        ValidatorSet,
        Vec<SigningKey>,
        ConsensusParametersV0,
        VerifiedPublicBootstrapInitialCutV1,
        StrictReplayArchiveSemanticsV1,
        SignedProposalV0,
    ) {
        let (set, keys) = qc_fixture_v1();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let h3_id = BlockId::new([0x33; 32]);
        let q3 = strict_qc_fixture_for_block_v1(&set, &keys, 3, h3_id);
        let h3_timestamp = WORKLOAD_GENESIS_TIMESTAMP_MS_V1 + WORKLOAD_BLOCK_TIME_STEP_MS_V1 * 3;
        let h4 = strict_proposal_fixture_v1(
            &set,
            &keys,
            4,
            h3_id,
            h3_timestamp,
            q3.clone(),
            StateRoot::new([0x44; 32]),
        );
        let q4 = strict_qc_fixture_for_block_v1(&set, &keys, 4, h4.block().id());
        let h5 = strict_proposal_fixture_v1(
            &set,
            &keys,
            5,
            h4.block().id(),
            h4.block().header().timestamp_ms(),
            q4.clone(),
            StateRoot::new([0x45; 32]),
        );
        let q5 = strict_qc_fixture_for_block_v1(&set, &keys, 5, h5.block().id());
        let h6 = strict_proposal_fixture_v1(
            &set,
            &keys,
            6,
            h5.block().id(),
            h5.block().header().timestamp_ms(),
            q5.clone(),
            StateRoot::new([0x46; 32]),
        );
        let q6 = strict_qc_fixture_for_block_v1(&set, &keys, 6, h6.block().id());
        let signed = [&h4, &h5, &h6];
        let unbound = signed
            .iter()
            .map(|proposal| {
                let header = proposal.block().header();
                (
                    ReplayArchiveCoordinateV1 {
                        kind: ReplayArchiveEntryKindV1::Proposal,
                        height: header.height().get(),
                        view: header.view().get(),
                        block_id: *proposal.block().id().as_bytes(),
                    },
                    UnboundProposalV0::from_signed(proposal).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let bootstrap = VerifiedPublicBootstrapInitialCutV1 {
            high_qc_certificate_id: *q3.id().as_bytes(),
            high_qc_view: 3,
            high_qc_height: 3,
            high_qc_block_id: *h3_id.as_bytes(),
            finalized_height: 1,
            finalized_block_id: [0x31; 32],
            application_height: 1,
            application_block_id: [0x31; 32],
            proposal_parent_height: 3,
            proposal_parent_block_id: *h3_id.as_bytes(),
            application_state_root: [0x43; 32],
        };
        let proposals =
            authenticate_all_proposals_v1(&unbound, &set, &parameters, 4, bootstrap).unwrap();
        let certificates = [q4, q5, q6]
            .into_iter()
            .map(|certificate| (*certificate.id().as_bytes(), certificate))
            .collect();
        (
            set,
            keys,
            parameters,
            bootstrap,
            StrictReplayArchiveSemanticsV1 {
                proposals,
                certificates,
                signature_share_count: 12,
            },
            h4,
        )
    }

    #[test]
    fn process_loss_before_archive_leaves_genesis_head_v1() {
        let temp = TempDir::new().unwrap();
        let context = context_v1();
        let mut archive = initialize_for_test_v1(&temp);
        assert!(archive
            .append_statement_with_observer_v1(statement_v1(b"proposal"), |stage| {
                if stage == ReplayArchiveAppendStageV1::BeforeArchive {
                    bail!("injected process loss")
                }
                Ok(())
            })
            .is_err());
        assert!(archive
            .append_statement_v1(statement_v1(b"proposal"))
            .is_err());
        drop(archive);
        let reopened = open_for_test_v1(&temp.path().join(ARCHIVE_DIRECTORY_V1), context);
        assert_eq!(reopened.facts_v1().sequence_v1(), 0);
    }

    #[test]
    fn process_loss_after_archive_fsync_repairs_exact_one_ahead_head_v1() {
        let temp = TempDir::new().unwrap();
        let context = context_v1();
        let mut archive = initialize_for_test_v1(&temp);
        assert!(archive
            .append_statement_with_observer_v1(statement_v1(b"proposal"), |stage| {
                if stage == ReplayArchiveAppendStageV1::AfterArchiveDurable {
                    bail!("injected process loss")
                }
                Ok(())
            })
            .is_err());
        assert!(archive
            .append_statement_v1(statement_v1(b"proposal"))
            .is_err());
        drop(archive);
        let reopened = open_for_test_v1(&temp.path().join(ARCHIVE_DIRECTORY_V1), context);
        assert_eq!(reopened.facts_v1().sequence_v1(), 1);
        assert!(reopened.historically_repaired);
        assert!(reopened.fresh_terminal_snapshot_v1().is_err());
        assert!(reopened.root.join(REPAIR_TOMBSTONE_FILE_V1).is_file());
        let root = reopened.root.clone();
        let context = reopened.context.clone();
        drop(reopened);
        let reopened_again = open_for_test_v1(&root, context);
        assert!(reopened_again.historically_repaired);
        assert!(reopened_again.fresh_terminal_snapshot_v1().is_err());
    }

    #[test]
    fn durable_repair_tombstone_closes_marker_before_head_repair_crash_window_v1() {
        let temp = TempDir::new().unwrap();
        let context = context_v1();
        let mut archive = initialize_for_test_v1(&temp);
        let durable_head = archive.head;
        assert!(archive
            .append_statement_with_observer_v1(statement_v1(b"proposal"), |stage| {
                if stage == ReplayArchiveAppendStageV1::AfterArchiveDurable {
                    bail!("injected process loss")
                }
                Ok(())
            })
            .is_err());
        let root = archive.root.clone();
        drop(archive);
        let mut entries = open_private_file_v1(&root.join(ENTRY_FILE_V1), false).unwrap();
        let (log_head, predecessor, _, _, _) = audit_entry_log_v1(
            &mut entries,
            context.digest,
            context.json.maximum_archive_entries,
        )
        .unwrap();
        assert_eq!(predecessor, Some(durable_head));
        let tombstone = ReplayArchiveRepairTombstoneV1::new_v1(
            context.digest,
            "one-ahead-log",
            log_head,
            durable_head,
            None,
        )
        .unwrap();
        write_new_private_file_v1(
            &root.join(REPAIR_TOMBSTONE_FILE_V1),
            &tombstone.canonical_bytes_v1().unwrap(),
        )
        .unwrap();
        open_directory_pinned_v1(&root).unwrap().sync_all().unwrap();

        let reopened = open_for_test_v1(&root, context);
        assert_eq!(reopened.head, log_head);
        assert!(reopened.historically_repaired);
        assert!(reopened.fresh_terminal_snapshot_v1().is_err());
    }

    #[test]
    fn same_uid_marker_deletion_is_explicitly_outside_archive_local_authority_v1() {
        let temp = TempDir::new().unwrap();
        let context = context_v1();
        let mut archive = initialize_for_test_v1(&temp);
        assert!(archive
            .append_statement_with_observer_v1(statement_v1(b"proposal"), |stage| {
                if stage == ReplayArchiveAppendStageV1::AfterArchiveDurable {
                    bail!("injected process loss")
                }
                Ok(())
            })
            .is_err());
        let root = archive.root.clone();
        drop(archive);
        let repaired = open_for_test_v1(&root, context.clone());
        assert!(repaired.historically_repaired);
        drop(repaired);

        fs::remove_file(root.join(REPAIR_TOMBSTONE_FILE_V1)).unwrap();
        let reopened_after_same_uid_deletion = open_for_test_v1(&root, context);
        assert!(!reopened_after_same_uid_deletion.historically_repaired);
        assert!(!crate::COHERENT_WHOLE_AUTHORITY_ROOT_ROLLBACK_PROTECTION);
    }

    #[test]
    fn repair_tombstone_tamper_and_foreign_inventory_fail_closed_v1() {
        let temp = TempDir::new().unwrap();
        let context = context_v1();
        let mut archive = initialize_for_test_v1(&temp);
        assert!(archive
            .append_statement_with_observer_v1(statement_v1(b"proposal"), |stage| {
                if stage == ReplayArchiveAppendStageV1::AfterArchiveDurable {
                    bail!("injected process loss")
                }
                Ok(())
            })
            .is_err());
        let root = archive.root.clone();
        drop(archive);
        let repaired = open_for_test_v1(&root, context.clone());
        drop(repaired);
        let marker = root.join(REPAIR_TOMBSTONE_FILE_V1);
        let mut value: ReplayArchiveRepairTombstoneV1 =
            serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
        value.tombstone_sha256 = hex::encode([0xee; 32]);
        fs::remove_file(&marker).unwrap();
        write_new_private_file_v1(&marker, &value.canonical_bytes_v1().unwrap()).unwrap();
        assert!(std::panic::catch_unwind(|| open_for_test_v1(&root, context.clone())).is_err());

        fs::remove_file(&marker).unwrap();
        let foreign = root.join("foreign-artifact");
        write_new_private_file_v1(&foreign, b"foreign\n").unwrap();
        assert!(validate_inventory_v1(&root).is_err());
        assert!(validate_terminal_inventory_v1(&root).is_err());
    }

    #[test]
    fn process_loss_before_authority_keeps_exact_archived_statement_v1() {
        let temp = TempDir::new().unwrap();
        let context = context_v1();
        let mut archive = initialize_for_test_v1(&temp);
        assert!(archive
            .append_statement_with_observer_v1(statement_v1(b"proposal"), |stage| {
                if stage == ReplayArchiveAppendStageV1::BeforeAuthorityMutation {
                    bail!("injected process loss")
                }
                Ok(())
            })
            .is_err());
        assert!(archive
            .append_statement_v1(statement_v1(b"proposal"))
            .is_err());
        drop(archive);
        let reopened = open_for_test_v1(&temp.path().join(ARCHIVE_DIRECTORY_V1), context);
        assert_eq!(reopened.facts_v1().sequence_v1(), 1);
    }

    #[test]
    fn exact_retry_is_inert_and_coordinate_fork_is_rejected_v1() {
        let temp = TempDir::new().unwrap();
        let mut archive = initialize_for_test_v1(&temp);
        archive
            .append_statement_v1(statement_v1(b"proposal"))
            .unwrap();
        archive
            .append_statement_v1(statement_v1(b"proposal"))
            .unwrap();
        assert_eq!(archive.facts_v1().sequence_v1(), 1);
        assert!(archive.append_statement_v1(statement_v1(b"fork")).is_err());
        assert_eq!(archive.facts_v1().sequence_v1(), 1);
    }

    #[test]
    fn context_bound_kind_and_aggregate_capacity_fail_closed_v1() {
        let mut digest_mutant = context_v1().json;
        digest_mutant.config_sha256 = hex::encode([0xe1; 32]);
        assert!(ReplayArchiveContextV1::from_fields_v1(digest_mutant).is_err());

        let mut fields = context_v1().json;
        fields.maximum_timeout_view_advances = 0;
        fields.maximum_proposal_entries = 1;
        fields.maximum_quorum_certificate_entries = 2;
        fields.maximum_archive_entries = 3;
        fields.context_sha256.clear();
        let context = ReplayArchiveContextV1::from_fields_v1(fields.clone()).unwrap();
        let temp = TempDir::new().unwrap();
        let mut archive = initialize_for_context_v1(&temp, context);
        archive
            .append_statement_v1(statement_v1(b"first-proposal"))
            .unwrap();
        let mut second = successor_statement_v1(b"second-proposal");
        second.coordinate.height = 5;
        second.coordinate.view = 5;
        second.coordinate.block_id = [0x55; 32];
        let error = archive.append_statement_v1(second).unwrap_err();
        assert!(error.to_string().contains("proposal capacity exhausted"));

        fields.maximum_quorum_certificate_entries = 3;
        fields.context_sha256.clear();
        assert!(ReplayArchiveContextV1::from_fields_v1(fields).is_err());
    }

    #[test]
    fn entry_audit_rejects_the_immediate_count_plus_one_v1() {
        let temp = TempDir::new().unwrap();
        let mut archive = initialize_for_test_v1(&temp);
        archive
            .append_statement_v1(statement_v1(b"first-proposal"))
            .unwrap();
        let mut second = successor_statement_v1(b"second-proposal");
        second.coordinate.height = 5;
        second.coordinate.view = 5;
        second.coordinate.block_id = [0x55; 32];
        archive.append_statement_v1(second).unwrap();

        let mut entries = archive.entries_file.try_clone().unwrap();
        let error = audit_entry_log_v1(&mut entries, archive.context.digest, 1).unwrap_err();
        assert!(error
            .to_string()
            .contains("context-bound replay archive entry count exceeded"));
    }

    #[test]
    fn unhashed_entry_pin_requires_the_full_semantic_audit_before_revalidation_v1() {
        let temp = TempDir::new().unwrap();
        let mut archive = initialize_for_test_v1(&temp);
        archive
            .append_statement_v1(statement_v1(b"proposal"))
            .unwrap();
        let context = archive.context.clone();
        let path = archive.root.join(ENTRY_FILE_V1);
        let length = archive.entries_len;
        drop(archive);

        let maximum =
            context_bound_entry_file_bytes_v1(context.json.maximum_archive_entries).unwrap();
        let mut pinned = PinnedReadOnlyEvidenceFileV1::open_unhashed_exact_length_v1(
            &path,
            maximum,
            length,
            "test replay entries",
        )
        .unwrap();
        assert!(pinned.revalidate_v1().is_err());
        let mut audit = pinned.file.try_clone().unwrap();
        let (_, _, _, audited_length, audited_sha256) = audit_entry_log_v1(
            &mut audit,
            context.digest,
            context.json.maximum_archive_entries,
        )
        .unwrap();
        pinned
            .bind_audited_sha256_v1(audited_sha256, audited_length)
            .unwrap();
        pinned.revalidate_v1().unwrap();
    }

    #[test]
    fn truncated_log_and_symlink_substitution_fail_closed_v1() {
        let temp = TempDir::new().unwrap();
        let context = context_v1();
        let mut archive = initialize_for_test_v1(&temp);
        archive
            .append_statement_v1(statement_v1(b"proposal"))
            .unwrap();
        let root = archive.root.clone();
        drop(archive);
        let path = root.join(ENTRY_FILE_V1);
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        let length = file.metadata().unwrap().len();
        file.set_len(length - 1).unwrap();
        drop(file);
        let result = std::panic::catch_unwind(|| open_for_test_v1(&root, context.clone()));
        assert!(result.is_err());

        let symlink_temp = TempDir::new().unwrap();
        let archive = initialize_for_test_v1(&symlink_temp);
        let root = archive.root.clone();
        drop(archive);
        let context_path = root.join(CONTEXT_FILE_V1);
        let replacement = root.join("replacement");
        fs::rename(&context_path, &replacement).unwrap();
        symlink(&replacement, &context_path).unwrap();
        assert!(open_private_file_v1(&context_path, false).is_err());
    }

    #[test]
    fn forged_one_behind_head_is_never_repaired_v1() {
        for with_next_head in [false, true] {
            let temp = TempDir::new().unwrap();
            let context = context_v1();
            let mut archive = initialize_for_test_v1(&temp);
            archive
                .append_statement_v1(statement_v1(b"proposal-4"))
                .unwrap();
            archive
                .append_statement_v1(successor_statement_v1(b"proposal-5"))
                .unwrap();
            let root = archive.root.clone();
            let exact_log_head = archive.head;
            drop(archive);

            replace_head_for_test_v1(
                &root,
                context.digest,
                ReplayArchiveHeadV1 {
                    sequence: 1,
                    record_sha256: [0xf1; 32],
                },
            );
            if with_next_head {
                let mut bytes =
                    serde_json::to_vec(&exact_log_head.json_v1(context.digest)).unwrap();
                bytes.push(b'\n');
                write_new_private_file_v1(&root.join(NEXT_HEAD_FILE_V1), &bytes).unwrap();
            }
            let result = std::panic::catch_unwind(|| open_for_test_v1(&root, context.clone()));
            assert!(result.is_err());
        }
    }

    #[test]
    fn forged_head_ahead_of_log_is_rejected_v1() {
        let temp = TempDir::new().unwrap();
        let context = context_v1();
        let archive = initialize_for_test_v1(&temp);
        let root = archive.root.clone();
        drop(archive);
        replace_head_for_test_v1(
            &root,
            context.digest,
            ReplayArchiveHeadV1 {
                sequence: 1,
                record_sha256: [0xa1; 32],
            },
        );
        let result = std::panic::catch_unwind(|| open_for_test_v1(&root, context));
        assert!(result.is_err());
    }

    #[test]
    fn archive_mode_and_hard_link_tamper_fail_closed_v1() {
        let mode_temp = TempDir::new().unwrap();
        let archive = initialize_for_test_v1(&mode_temp);
        let root = archive.root.clone();
        drop(archive);
        let context_path = root.join(CONTEXT_FILE_V1);
        fs::set_permissions(&context_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(open_private_file_v1(&context_path, false).is_err());

        let link_temp = TempDir::new().unwrap();
        let archive = initialize_for_test_v1(&link_temp);
        let root = archive.root.clone();
        drop(archive);
        let context_path = root.join(CONTEXT_FILE_V1);
        fs::hard_link(&context_path, root.join("context-hard-link")).unwrap();
        assert!(open_private_file_v1(&context_path, false).is_err());

        let directory_temp = TempDir::new().unwrap();
        let archive = initialize_for_test_v1(&directory_temp);
        let root = archive.root.clone();
        drop(archive);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(require_archive_directory_v1(&root).is_err());
    }

    #[test]
    fn terminal_audit_rejects_repair_artifact_and_one_ahead_log_v1() {
        let temp = TempDir::new().unwrap();
        let mut archive = initialize_for_test_v1(&temp);
        archive
            .append_statement_v1(statement_v1(b"proposal"))
            .unwrap();
        let mut qc = successor_statement_v1(b"qc");
        qc.coordinate.kind = ReplayArchiveEntryKindV1::QuorumCertificate;
        archive.append_statement_v1(qc).unwrap();
        assert!(archive.fresh_terminal_snapshot_v1().is_ok());

        write_new_private_file_v1(&archive.root.join(NEXT_HEAD_FILE_V1), b"not-a-head\n").unwrap();
        assert!(archive.fresh_terminal_snapshot_v1().is_err());
        fs::remove_file(archive.root.join(NEXT_HEAD_FILE_V1)).unwrap();

        assert!(archive
            .append_statement_with_observer_v1(
                ReplayArchiveStatementV1 {
                    coordinate: ReplayArchiveCoordinateV1 {
                        kind: ReplayArchiveEntryKindV1::Proposal,
                        height: 6,
                        view: 6,
                        block_id: [0x66; 32],
                    },
                    payload: b"one-ahead".to_vec(),
                },
                |stage| {
                    if stage == ReplayArchiveAppendStageV1::AfterArchiveDurable {
                        bail!("injected one-ahead stop")
                    }
                    Ok(())
                },
            )
            .is_err());
        assert!(archive.fresh_terminal_snapshot_v1().is_err());
    }

    #[test]
    fn canonical_entry_and_read_only_file_guards_reject_trailing_symlink_link_and_mode_v1() {
        let temp = TempDir::new().unwrap();
        let mut archive = initialize_for_test_v1(&temp);
        archive
            .append_statement_v1(statement_v1(b"proposal"))
            .unwrap();
        let index = archive.index.values().next().unwrap();
        let mut file = archive.entries_file.try_clone().unwrap();
        file.seek(SeekFrom::Start(index.offset)).unwrap();
        let mut line = vec![0; index.line_bytes];
        file.read_exact(&mut line).unwrap();
        line.extend_from_slice(b" \n");
        assert!(parse_entry_line_v1(&line, archive.context.digest, None).is_err());

        let source = archive.root.join(CONTEXT_FILE_V1);
        drop(archive);
        let link = temp.path().join("context-link");
        symlink(&source, &link).unwrap();
        assert!(PinnedReadOnlyEvidenceFileV1::open_v1(
            &link,
            MAXIMUM_CONTEXT_BYTES_V1,
            "test context"
        )
        .is_err());
        let hard = temp.path().join("context-hard");
        fs::hard_link(&source, &hard).unwrap();
        assert!(PinnedReadOnlyEvidenceFileV1::open_v1(
            &source,
            MAXIMUM_CONTEXT_BYTES_V1,
            "test context"
        )
        .is_err());
        fs::remove_file(&hard).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(PinnedReadOnlyEvidenceFileV1::open_v1(
            &source,
            MAXIMUM_CONTEXT_BYTES_V1,
            "test context"
        )
        .is_err());
    }

    #[test]
    fn terminal_seal_domains_bind_context_clean_stop_fleet_start_and_files_v1() {
        let source = include_str!("signed_replay_archive.rs");
        let forbidden_non_strict_verify = [".verify(", "&signature_root"].concat();
        assert!(!source.contains(&forbidden_non_strict_verify));
        assert!(source.matches(".verify_strict(&signature_root").count() >= 2);
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let seal = terminal_seal_v1(&key);
        let original_body = seal.computed_body_sha256_v1().unwrap();
        let signature: [u8; 64] = hex::decode(&seal.signature).unwrap().try_into().unwrap();
        let signature = Signature::from_bytes(&signature);
        let original_root = hash_parts_v1(TERMINAL_SEAL_SIGNATURE_DOMAIN_V1, &[&original_body]);
        key.verifying_key()
            .verify_strict(&original_root, &signature)
            .unwrap();

        let mut mutants = Vec::new();
        let mut context = seal.clone();
        context.archive_context_sha256 = hex::encode([0x81; 32]);
        mutants.push(context);
        let mut clean_stop = seal.clone();
        clean_stop.clean_stop_journal_sha256 = hex::encode([0x82; 32]);
        mutants.push(clean_stop);
        let mut finalized = seal.clone();
        finalized.finalized_chain_root = hex::encode([0x86; 32]);
        mutants.push(finalized);
        let mut proof = seal.clone();
        proof.finality_proof_id = hex::encode([0x87; 32]);
        mutants.push(proof);
        let mut fleet_start = seal.clone();
        fleet_start.fleet_start_certificate_sha256 = hex::encode([0x83; 32]);
        mutants.push(fleet_start);
        let mut entries = seal.clone();
        entries.archive_entries_file_sha256 = hex::encode([0x84; 32]);
        mutants.push(entries);
        let mut head = seal.clone();
        head.terminal_archive_record_sha256 = hex::encode([0x85; 32]);
        mutants.push(head);
        let mut counts = seal.clone();
        counts.quorum_certificate_count += 1;
        mutants.push(counts);
        for mutant in mutants {
            let body = mutant.computed_body_sha256_v1().unwrap();
            assert_ne!(body, original_body);
            let root = hash_parts_v1(TERMINAL_SEAL_SIGNATURE_DOMAIN_V1, &[&body]);
            assert!(key
                .verifying_key()
                .verify_strict(&root, &signature)
                .is_err());
        }
    }

    #[test]
    fn terminal_seal_rejects_cross_run_validator_and_config_clean_stop_cuts_v1() {
        let cut = CleanStoppedJournalCutV1::test_only(
            1, 7, 9, [0x51; 32], 11, 4, [0x52; 32], [0x53; 32], [0x54; 32],
        );
        let expected = TerminalSealCutContextV1 {
            run_id: cut.run_id().to_owned(),
            validator_id: cut.validator_id(),
            validator_set_id: cut.validator_set_id(),
            coordinator_manifest_sha256: cut.coordinator_manifest_sha256(),
            validator_set_sha256: cut.validator_set_sha256(),
            config_sha256: cut.config_sha256(),
            candidate_source_sha256: cut.candidate_source_sha256(),
            binary_sha256: cut.binary_sha256(),
        };
        expected.require_exact_cut_v1(&cut).unwrap();

        let mut wrong_run = expected.clone();
        wrong_run.run_id = "test-clean-stopped-other-run".to_owned();
        assert!(wrong_run.require_exact_cut_v1(&cut).is_err());
        let mut wrong_validator = expected.clone();
        wrong_validator.validator_id = trnm_consensus_types::ValidatorId::new([0xee; 32]);
        assert!(wrong_validator.require_exact_cut_v1(&cut).is_err());
        let mut wrong_config = expected;
        wrong_config.config_sha256 = [0xef; 32];
        assert!(wrong_config.require_exact_cut_v1(&cut).is_err());
    }

    #[test]
    fn strict_three_chain_covers_exact_final_tip_without_completion_authority_v1() {
        let (set, _keys, parameters, _bootstrap, semantics, finalized) =
            strict_three_chain_semantics_fixture_v1();
        let header = finalized.block().header();
        let height = header.height().get().to_be_bytes();
        let view = header.view().get().to_be_bytes();
        let timestamp = header.timestamp_ms().to_be_bytes();
        let chain_root = hash_parts_v1(
            FINALIZED_PREFIX_CHAIN_ROOT_DOMAIN_V0,
            &[
                set.chain_id().as_str().as_bytes(),
                set.genesis_hash().as_bytes(),
                &height,
                &view,
                finalized.block().id().as_bytes(),
                &timestamp,
            ],
        );
        let coverage = verify_signed_final_tip_coverage_v1(
            &semantics,
            &set,
            &parameters,
            header.height().get(),
            *finalized.block().id().as_bytes(),
            *header.state_root().as_bytes(),
            chain_root,
        )
        .unwrap();
        assert_ne!(coverage.proof_id, [0; 32]);
        assert_ne!(coverage.child_block_id, [0; 32]);
        assert_ne!(coverage.grandchild_block_id, [0; 32]);

        assert!(verify_signed_final_tip_coverage_v1(
            &semantics,
            &set,
            &parameters,
            header.height().get(),
            *finalized.block().id().as_bytes(),
            [0xee; 32],
            chain_root,
        )
        .is_err());
        assert!(verify_signed_final_tip_coverage_v1(
            &semantics,
            &set,
            &parameters,
            header.height().get(),
            *finalized.block().id().as_bytes(),
            *header.state_root().as_bytes(),
            [0xef; 32],
        )
        .is_err());

        let mut missing_grandchild_qc = semantics;
        let grandchild_qc_id = missing_grandchild_qc
            .certificates
            .iter()
            .find(|(_, certificate)| {
                certificate.block_id().as_bytes() == &coverage.grandchild_block_id
            })
            .map(|(id, _)| *id)
            .unwrap();
        missing_grandchild_qc.certificates.remove(&grandchild_qc_id);
        assert!(verify_signed_final_tip_coverage_v1(
            &missing_grandchild_qc,
            &set,
            &parameters,
            header.height().get(),
            *finalized.block().id().as_bytes(),
            *header.state_root().as_bytes(),
            chain_root,
        )
        .is_err());
    }

    #[test]
    fn sealed_bootstrap_ancestry_round_trips_through_read_only_verifier_v1() {
        let (set, keys, parameters, bootstrap, semantics, finalized) =
            strict_three_chain_semantics_fixture_v1();
        let local_validator = set.validators()[0].id();
        let mut fields = context_v1().json;
        fields.chain_id = set.chain_id().as_str().to_owned();
        fields.genesis_hash = hex::encode(set.genesis_hash().as_bytes());
        fields.validator_set_id = hex::encode(set.id().as_bytes());
        fields.local_validator_id = hex::encode(local_validator.as_bytes());
        fields.local_consensus_public_key = hex::encode(keys[0].verifying_key().to_bytes());
        fields.ordinary_start_height = 4;
        fields.context_sha256.clear();
        let context = ReplayArchiveContextV1::from_fields_v1(fields).unwrap();
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut archive = initialize_for_context_v1(&temp, context.clone());
        for proposal in semantics.proposals.values() {
            archive
                .append_proposal_v1(&UnboundProposalV0::from_signed(&proposal.proposal).unwrap())
                .unwrap();
        }
        for certificate in semantics.certificates.values() {
            archive.append_quorum_certificate_v1(certificate).unwrap();
        }
        let final_header = finalized.block().header();
        let height = final_header.height().get().to_be_bytes();
        let view = final_header.view().get().to_be_bytes();
        let timestamp = final_header.timestamp_ms().to_be_bytes();
        let finalized_chain_root = hash_parts_v1(
            FINALIZED_PREFIX_CHAIN_ROOT_DOMAIN_V0,
            &[
                set.chain_id().as_str().as_bytes(),
                set.genesis_hash().as_bytes(),
                &height,
                &view,
                finalized.block().id().as_bytes(),
                &timestamp,
            ],
        );
        let public = PublicReportVerifierContext::from_replay_archive_test_parts_v1(
            context.json.run_id.clone(),
            set.clone(),
            local_validator,
            decode_hex32_v1(&context.json.validator_set_sha256, "test validator set").unwrap(),
            decode_hex32_v1(&context.json.topology_sha256, "test topology").unwrap(),
            decode_hex32_v1(&context.json.config_sha256, "test config").unwrap(),
            decode_hex32_v1(&context.json.coordinator_manifest_sha256, "test manifest").unwrap(),
            decode_hex32_v1(&context.json.binary_sha256, "test binary").unwrap(),
            decode_hex32_v1(&context.json.candidate_source_sha256, "test source").unwrap(),
            4,
            decode_hex32_v1(&context.json.workload_corpus_sha256, "test corpus").unwrap(),
            decode_hex32_v1(&context.json.workload_policy_sha256, "test policy").unwrap(),
            bootstrap,
        );

        let event_context =
            crate::process_event::RuntimeEventContextV1::from_public_context(&public);
        let journal_path = temp.path().join("runtime-events.jsonl");
        let mut journal = crate::process_event::RuntimeEventJournalV1::start_with_context(
            &journal_path,
            event_context,
            keys[0].clone(),
        )
        .unwrap();
        journal
            .append(
                crate::process_event::RuntimeEventKindV1::Finalized,
                &hex::encode([0x71; 32]),
                3,
            )
            .unwrap();
        journal
            .append(
                crate::process_event::RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode([0x72; 32]),
                3,
            )
            .unwrap();
        journal.record_fleet_ready([0x73; 32], 1).unwrap();
        let fleet_start_certificate_sha256 = [0x91; 32];
        journal
            .record_fleet_started(fleet_start_certificate_sha256, 1)
            .unwrap();
        journal
            .append(
                crate::process_event::RuntimeEventKindV1::Finalized,
                &hex::encode(finalized.block().id().as_bytes()),
                final_header.height().get(),
            )
            .unwrap();
        journal
            .append(
                crate::process_event::RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode(final_header.state_root().as_bytes()),
                final_header.height().get(),
            )
            .unwrap();
        journal
            .record_final_tip(
                *finalized.block().id().as_bytes(),
                *final_header.state_root().as_bytes(),
                finalized_chain_root,
                final_header.height().get(),
            )
            .unwrap();
        journal.record_clean_stop().unwrap();
        let cut = journal.clean_stopped_cut().unwrap();
        assert_eq!(
            cut.fleet_start_certificate_sha256(),
            fleet_start_certificate_sha256
        );

        let terminal_config = TerminalSealTestConfigV1 {
            run_root: temp.path().to_path_buf(),
            run_id: context.json.run_id.clone(),
            local_validator,
            validator_set: set,
            consensus_parameters: parameters,
            signing_key: keys[0].clone(),
            validator_set_sha256: decode_hex32_v1(
                &context.json.validator_set_sha256,
                "test validator set",
            )
            .unwrap(),
            topology_sha256: decode_hex32_v1(&context.json.topology_sha256, "test topology")
                .unwrap(),
            config_sha256: decode_hex32_v1(&context.json.config_sha256, "test config").unwrap(),
            coordinator_manifest_sha256: decode_hex32_v1(
                &context.json.coordinator_manifest_sha256,
                "test manifest",
            )
            .unwrap(),
            binary_sha256: decode_hex32_v1(&context.json.binary_sha256, "test binary").unwrap(),
            candidate_source_sha256: decode_hex32_v1(
                &context.json.candidate_source_sha256,
                "test source",
            )
            .unwrap(),
            ordinary_start_height: context.json.ordinary_start_height,
            workload_corpus_sha256: decode_hex32_v1(
                &context.json.workload_corpus_sha256,
                "test corpus",
            )
            .unwrap(),
            workload_policy_sha256: decode_hex32_v1(
                &context.json.workload_policy_sha256,
                "test policy",
            )
            .unwrap(),
        };
        let seal_path = archive
            .write_terminal_seal_v1(&terminal_config, &cut, bootstrap)
            .unwrap();
        let mut seal: ReplayArchiveTerminalSealV1 =
            serde_json::from_slice(&fs::read(&seal_path).unwrap()).unwrap();
        assert_eq!(seal.clean_stop_journal_sequence, cut.event_sequence());
        assert_eq!(
            seal.clean_stop_journal_sha256,
            hex::encode(cut.event_sha256())
        );

        let root = archive.root.clone();
        drop(archive);
        let verified = verify_replay_archive_v1(
            &root.join(CONTEXT_FILE_V1),
            &root.join(ENTRY_FILE_V1),
            &root.join(HEAD_FILE_V1),
            &seal_path,
            &public,
        )
        .unwrap();
        assert!(verified.archive_covers_signed_final_tip);
        assert!(!verified.observer_verified_finality);
        assert!(!verified.validator_run_completed);
        assert!(!verified.g3_evidence_complete);

        fs::remove_file(&seal_path).unwrap();
        seal.signature = hex::encode([0xff; 64]);
        write_new_private_file_v1(&seal_path, &seal.canonical_bytes_v1().unwrap()).unwrap();
        assert!(verify_replay_archive_v1(
            &root.join(CONTEXT_FILE_V1),
            &root.join(ENTRY_FILE_V1),
            &root.join(HEAD_FILE_V1),
            &seal_path,
            &public,
        )
        .is_err());
    }

    #[test]
    fn strict_qc_negative_control_uses_noncanonical_memory_only_signature_v1() {
        let (set, keys) = qc_fixture_v1();
        let block = BlockId::new([0x33; 32]);
        let votes = (0..3)
            .map(|index| {
                let root =
                    Vote::signing_root_for_set(&set, View::new(1), Height::new(4), block).unwrap();
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    View::new(1),
                    Height::new(4),
                    block,
                    set.id(),
                    set.validators()[index].id(),
                    SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
                    &set,
                )
                .unwrap()
            })
            .collect();
        let certificate = QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(4),
            block,
            set.id(),
            votes,
            &set,
        )
        .unwrap();
        let id = *certificate.id().as_bytes();
        let mut certificates = BTreeMap::new();
        certificates.insert(id, certificate);
        let (selected, signer) = verify_qc_signature_negative_control_v1(&certificates, &set)
            .expect("strict decoder rejects deterministic non-canonical vote signature");
        assert_eq!(selected, hex::encode(id));
        assert_eq!(signer, hex::encode(set.validators()[0].id().as_bytes()));
    }

    #[test]
    fn archived_proposal_signature_bitflip_is_rejected_before_archive_v1() {
        let (set, keys) = qc_fixture_v1();
        let proposal = signed_proposal_fixture_v1(&set, &keys[0]);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let encoded = proposal.encode().unwrap();
        UnboundProposalV0::decode(&encoded, &set, &parameters)
            .unwrap()
            .bind_authenticated_parent(&set, &parameters, 0)
            .unwrap();

        let mut corrupt = encoded;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(UnboundProposalV0::decode(&corrupt, &set, &parameters).is_err());
    }

    #[test]
    fn read_only_input_hash_is_unchanged_after_revalidation_v1() {
        let temp = TempDir::new().unwrap();
        let archive = initialize_for_test_v1(&temp);
        let path = archive.root.join(CONTEXT_FILE_V1);
        drop(archive);
        let before = fs::read(&path).unwrap();
        let pinned = PinnedReadOnlyEvidenceFileV1::open_v1(
            &path,
            MAXIMUM_CONTEXT_BYTES_V1,
            "unchanged context",
        )
        .unwrap();
        pinned.revalidate_v1().unwrap();
        assert_eq!(fs::read(path).unwrap(), before);
        let expected_sha256: [u8; 32] = Sha256::digest(&before).into();
        assert_eq!(pinned.sha256, expected_sha256);
    }

    #[test]
    fn read_only_input_same_inode_mutation_during_verification_is_rejected_v1() {
        let temp = TempDir::new().unwrap();
        let archive = initialize_for_test_v1(&temp);
        let path = archive.root.join(CONTEXT_FILE_V1);
        drop(archive);
        let pinned = PinnedReadOnlyEvidenceFileV1::open_v1(
            &path,
            MAXIMUM_CONTEXT_BYTES_V1,
            "mutated context",
        )
        .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write_all(&bytes).unwrap();
        writer.sync_all().unwrap();
        assert!(pinned.revalidate_v1().is_err());
    }

    #[test]
    fn read_only_verifier_has_no_repair_or_write_surface_v1() {
        let source = include_str!("signed_replay_archive.rs");
        let start = source
            .find("struct PinnedReadOnlyEvidenceFileV1")
            .expect("read-only verifier remains present");
        let end = source[start..]
            .find("fn read_entry_payload_from_pinned_v1")
            .map(|offset| start + offset)
            .expect("read-only verifier remains lexically bounded");
        let verifier = &source[start..end];
        for forbidden in [
            "repair_or_reject_head_v1(",
            "open_expected_v1(",
            ".write(true)",
            ".create(",
            ".create_new(",
            "fs::rename(",
            "fs::remove_file(",
        ] {
            assert!(
                !verifier.contains(forbidden),
                "read-only verifier contains forbidden surface {forbidden}"
            );
        }
        assert!(verifier.contains("O_NOFOLLOW | libc::O_NONBLOCK"));
        assert!(verifier.contains("input_sha256_unchanged: true"));
        assert!(verifier.contains("observer_verified_nonempty_workload: false"));
        assert!(verifier.contains("observer_verified_finality: false"));
    }

    #[test]
    fn full_process2_transition_retains_archive_ownership_around_node_reopen_v1() {
        let source = include_str!("signed_replay_archive.rs");
        let start = source
            .find("pub(crate) fn recover_full_process2_inert_v1")
            .expect("full inert process2 consuming transition remains present");
        let end = source[start..]
            .find("impl std::fmt::Debug for ArchivedDeployedReplayOwnerV1")
            .map(|offset| start + offset)
            .expect("authenticated replay owner implementation remains bounded");
        let transition = &source[start..end];
        let pre_revalidate = transition
            .find(".revalidate_identity_v1()")
            .expect("archive is revalidated before releasing the old Node owner");
        let clone_entries = transition
            .find("node.signed_replay_v0().to_vec()")
            .expect("authenticated replay entries are cloned before release");
        let drop_old = transition
            .find("drop(node)")
            .expect("old pinned Node owner is explicitly destroyed");
        let reopen = transition
            .find(".recover_deployed_process2_inert_v1(entries)")
            .expect("full process2 recovery reopens the authority root");
        let post_revalidate = transition
            .rfind(".revalidate_identity_v1()")
            .expect("archive is revalidated after full process2 recovery");
        assert!(
            pre_revalidate < clone_entries
                && clone_entries < drop_old
                && drop_old < reopen
                && reopen < post_revalidate
        );

        let wrapper = source
            .find("pub(crate) struct ArchivedDeployedProcess2RecoveryOwnerV1")
            .map(|offset| &source[offset..])
            .expect("archive-pinned full recovery wrapper remains present");
        assert!(wrapper.contains("_archive: SignedReplayArchiveV1"));
        assert!(wrapper.contains("node: PocoNodeDeployedLabProcess2RecoveryOwnerV0"));
        for forbidden in [
            "into_recovered_ordinary_runtime_v1",
            "activate_for_lab_authority_v1",
        ] {
            assert!(
                !transition.contains(forbidden),
                "consuming transition unexpectedly contains {forbidden}"
            );
        }
    }

    #[test]
    fn zero_delta_borrowed_revalidation_pins_archive_around_node_audit_v1() {
        let source = include_str!("signed_replay_archive.rs");
        let start = source
            .find("pub(crate) fn revalidate_zero_delta_caught_up_v1(&mut self)")
            .expect("archive-pinned zero-delta borrowed audit remains present");
        let end = source[start..]
            .find("pub(crate) const fn archive_facts_v1")
            .map(|offset| start + offset)
            .expect("archive-pinned zero-delta borrowed audit remains bounded");
        let audit = &source[start..end];
        let archive_before = audit
            .find("self.revalidate_archive_identity_v1()?")
            .expect("archive is revalidated before Node");
        let node = audit
            .find(".revalidate_zero_delta_caught_up_v1()")
            .expect("Node durable heads are freshly revalidated");
        let archive_after = audit
            .rfind("self.revalidate_archive_identity_v1()")
            .expect("archive is revalidated after Node");
        assert!(archive_before < node && node < archive_after);
        for forbidden in [
            "into_parts",
            "RecoveryReady",
            "RecoveryStart",
            "activate",
            "signer",
            "mesh",
        ] {
            assert!(
                !audit.contains(forbidden),
                "borrowed zero-delta audit unexpectedly exposes {forbidden}"
            );
        }
    }
}
