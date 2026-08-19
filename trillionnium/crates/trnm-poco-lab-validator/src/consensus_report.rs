//! Signed terminal-report contract for a future bounded G3 consensus run.
//!
//! This module freezes the machine-readable report and independent-verifier
//! output before the continuous runtime exists.  Constructing a report is a
//! crate-private authority: only a runtime which owns the exact terminal
//! facts can call it.  Parsing a valid signature alone is never sufficient;
//! the verifier also binds every deployment hash and requires a clean,
//! obligation-free, positive-height terminal cut.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    config::{LoadedValidatorConfig, PublicReportVerifierContext},
    continuous_runtime::{
        ContinuousValidatorTerminalCutV0, CONTINUOUS_RUNTIME_MAXIMUM_SIGNER_INTENTS_V0,
    },
    process_event::CleanStoppedJournalCutV1,
    signed_replay_archive::MAXIMUM_ENTRY_COUNT_V1,
};

const REPORT_SCHEMA_VERSION: u32 = 3;
const REPORT_HASH_DOMAIN: &[u8] = b"trnm.poco-g3.consensus-run-report.v3";
const REPORT_SIGNATURE_DOMAIN: &[u8] = b"trnm.poco-g3.consensus-run-report-signature.v3";
const MAX_SIGNED_REPORT_BYTES: u64 = 512 * 1024;
pub const MAX_CONSENSUS_RUN_DURATION_SECONDS_V1: u64 = 7 * 24 * 60 * 60;
pub const MAX_CONSENSUS_RUN_BLOCKS_V1: u64 = 10_000_000;

/// Exact positive terminal facts captured by the future runtime owner.
///
/// The type and fields are crate-private so a downstream binary cannot turn
/// comparison data into a report which appears to have crossed Core, Safety,
/// Application, signer, checkpoint, and event-journal authority boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsensusRunTerminalFactsV1 {
    submitted_height: u64,
    committed_height: u64,
    finalized_height: u64,
    application_head_block_id: [u8; 32],
    application_committed_height: u64,
    application_state_root: [u8; 32],
    safety_revision: u64,
    safety_state_record_checksum: [u8; 32],
    safety_record_chain_checksum: [u8; 32],
    application_store_id: [u8; 32],
    application_store_sequence: u64,
    application_head_row_checksum: [u8; 32],
    whole_node_checkpoint_generation: u64,
    whole_node_checkpoint_checksum: [u8; 32],
    signer_scope: [u8; 32],
    signer_journal_id: [u8; 32],
    signer_watermark_sequence: u64,
    signer_chain_checksum: [u8; 32],
    continuous_signed_vote_intents: u64,
    continuous_signed_timeout_intents: u64,
    safety_halt_count: u64,
    double_vote_count: u64,
    double_timeout_count: u64,
    conflicting_certificate_count: u64,
    pending_safety_persistence_count: u64,
    pending_payload_validation_count: u64,
    pending_signature_count: u64,
    pending_finalization_count: u64,
    pending_sync_count: u64,
    unresolved_obligation_count: u64,
}

impl ConsensusRunTerminalFactsV1 {
    /// Sole production mapping from the consuming continuous terminal cut.
    /// Every zero pending/halt value below is justified by successful typed
    /// Node terminal construction; no runner-supplied scalar can enter this
    /// projection. Height ordering is checked again at the report boundary so
    /// `submitted < highQC` or `highQC < finalized` can never be normalized.
    pub(crate) fn from_continuous_terminal(
        terminal: &ContinuousValidatorTerminalCutV0,
    ) -> Result<Self> {
        let node = terminal.node_v0();
        let submitted_height = terminal.submitted_height_v0();
        let committed_height = node.high_qc_v0().height().get();
        let finalized_height = node.finalized_height_v0();
        if submitted_height < committed_height || committed_height < finalized_height {
            bail!("continuous terminal heights violate submitted >= highQC >= finalized");
        }
        let watermark = node.signer_exact_watermark_v0();
        if terminal.finalized_chain_root_v0() == [0; 32]
            || node.application_state_root_v0() == [0; 32]
            || node.application_store_id_v0() == [0; 32]
            || node.application_committed_head_row_checksum_v0() == [0; 32]
            || node.checkpoint_v0().checkpoint_checksum() == [0; 32]
            || watermark.scope() == [0; 32]
            || watermark.journal_id() == [0; 32]
            || watermark.chain_checksum() == [0; 32]
        {
            bail!("continuous terminal evidence contains a zero authoritative commitment");
        }
        if watermark.journal_id() != node.signer_journal_id_v0() {
            bail!("continuous terminal signer watermark names a different journal");
        }
        Ok(Self {
            submitted_height,
            committed_height,
            finalized_height,
            application_head_block_id: *node.finalized_block_id_v0().as_bytes(),
            application_committed_height: finalized_height,
            application_state_root: node.application_state_root_v0(),
            safety_revision: node.safety_revision_v0(),
            safety_state_record_checksum: node.safety_state_record_checksum_v0(),
            safety_record_chain_checksum: node.safety_record_chain_checksum_v0(),
            application_store_id: node.application_store_id_v0(),
            application_store_sequence: node.application_durable_sequence_v0(),
            application_head_row_checksum: node.application_committed_head_row_checksum_v0(),
            whole_node_checkpoint_generation: node.checkpoint_v0().generation(),
            whole_node_checkpoint_checksum: node.checkpoint_v0().checkpoint_checksum(),
            signer_scope: watermark.scope(),
            signer_journal_id: node.signer_journal_id_v0(),
            signer_watermark_sequence: watermark.sequence(),
            signer_chain_checksum: watermark.chain_checksum(),
            continuous_signed_vote_intents: terminal.signed_vote_intents_v0(),
            continuous_signed_timeout_intents: terminal.signed_timeout_intents_v0(),
            safety_halt_count: 0,
            double_vote_count: terminal.double_vote_count_v0(),
            double_timeout_count: terminal.double_timeout_count_v0(),
            conflicting_certificate_count: terminal.conflicting_certificate_count_v0(),
            pending_safety_persistence_count: 0,
            pending_payload_validation_count: 0,
            pending_signature_count: 0,
            pending_finalization_count: 0,
            pending_sync_count: 0,
            unresolved_obligation_count: 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsensusRunBoundsV1 {
    pub(crate) requested_duration_seconds: u64,
    pub(crate) requested_max_blocks: u64,
    pub(crate) pacemaker_base_timeout_seconds: u64,
    pub(crate) terminal_drain_allowance_seconds: u64,
    pub(crate) timeout_view_budget_allowance_seconds: u64,
    pub(crate) signer_journal_capacity: u64,
    pub(crate) maximum_timeout_view_advances: u64,
    pub(crate) maximum_local_vote_intents: u64,
    pub(crate) maximum_local_timeout_intents: u64,
    pub(crate) maximum_total_signer_intents: u64,
    pub(crate) signed_replay_archive_capacity: u64,
    pub(crate) maximum_proposal_archive_entries: u64,
    pub(crate) maximum_quorum_certificate_archive_entries: u64,
    pub(crate) maximum_signed_replay_archive_entries: u64,
}

/// Flat, strict, signed report consumed by the fleet coordinator.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedConsensusRunReportV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub protocol_id: String,
    pub profile: String,
    pub network_scope: String,
    pub validator_id: String,
    pub validator_set_id: String,
    pub validator_set_sha256: String,
    pub topology_sha256: String,
    pub coordinator_manifest_sha256: String,
    pub candidate_source_sha256: String,
    pub binary_sha256: String,
    pub config_sha256: String,
    pub host_id: String,
    pub process_id: u32,
    pub process_instance: u64,
    pub requested_duration_seconds: u64,
    pub requested_max_blocks: u64,
    pub pacemaker_base_timeout_seconds: u64,
    pub terminal_drain_allowance_seconds: u64,
    pub timeout_view_budget_allowance_seconds: u64,
    pub signer_journal_capacity: u64,
    pub maximum_timeout_view_advances: u64,
    pub maximum_local_vote_intents: u64,
    pub maximum_local_timeout_intents: u64,
    pub maximum_total_signer_intents: u64,
    pub signed_replay_archive_capacity: u64,
    pub maximum_proposal_archive_entries: u64,
    pub maximum_quorum_certificate_archive_entries: u64,
    pub maximum_signed_replay_archive_entries: u64,
    /// First non-bootstrap height. The authenticated zero-Comet bundle fixes
    /// empty h1-h3, so the current laboratory profile requires h4.
    pub ordinary_start_height: u64,
    /// Always zero: the origin of this process-local `Instant` interval.
    pub started_monotonic_ns: u64,
    pub ended_monotonic_ns: u64,
    pub monotonic_clock: String,
    pub external_wall_clock_temporal_provenance: bool,
    pub submitted_height: u64,
    pub committed_height: u64,
    pub finalized_height: u64,
    pub submitted_ordinary_block_count: u64,
    pub committed_ordinary_block_count: u64,
    pub finalized_ordinary_block_count: u64,
    pub application_head_block_id: String,
    pub application_committed_height: u64,
    pub application_state_root: String,
    pub safety_revision: u64,
    pub safety_state_record_checksum: String,
    pub safety_record_chain_checksum: String,
    pub application_store_id: String,
    pub application_store_sequence: u64,
    pub application_head_row_checksum: String,
    pub whole_node_checkpoint_generation: u64,
    pub whole_node_checkpoint_checksum: String,
    pub signer_scope: String,
    pub signer_journal_id: String,
    pub signer_watermark_sequence: u64,
    pub signer_chain_checksum: String,
    pub continuous_signed_vote_intents: u64,
    pub continuous_signed_timeout_intents: u64,
    pub runtime_event_sequence: u64,
    pub runtime_event_sha256: String,
    pub safety_halt_count: u64,
    pub double_vote_count: u64,
    pub double_timeout_count: u64,
    pub conflicting_certificate_count: u64,
    pub pending_safety_persistence_count: u64,
    pub pending_payload_validation_count: u64,
    pub pending_signature_count: u64,
    pub pending_finalization_count: u64,
    pub pending_sync_count: u64,
    pub unresolved_obligation_count: u64,
    pub clean_stop: bool,
    pub validator_run_completed: bool,
    pub continuous_consensus_runtime: bool,
    pub g3_evidence_complete: bool,
    pub geo_wan_evidence: bool,
    pub production_activation: bool,
    pub report_sha256: String,
    pub signature: String,
}

/// Exact JSON object printed by `verify-consensus-report` after both strict
/// signature and semantic verification succeed.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusReportVerificationV1 {
    pub schema_version: u32,
    pub status: String,
    pub run_id: String,
    pub validator_id: String,
    pub validator_set_id: String,
    pub validator_set_sha256: String,
    pub topology_sha256: String,
    pub coordinator_manifest_sha256: String,
    pub candidate_source_sha256: String,
    pub binary_sha256: String,
    pub config_sha256: String,
    pub process_instance: u64,
    pub ordinary_start_height: u64,
    pub submitted_height: u64,
    pub committed_height: u64,
    pub finalized_height: u64,
    pub submitted_ordinary_block_count: u64,
    pub committed_ordinary_block_count: u64,
    pub finalized_ordinary_block_count: u64,
    pub application_state_root: String,
    pub safety_revision: u64,
    pub application_store_sequence: u64,
    pub whole_node_checkpoint_generation: u64,
    pub signer_watermark_sequence: u64,
    pub safety_halt_count: u64,
    pub double_vote_count: u64,
    pub double_timeout_count: u64,
    pub conflicting_certificate_count: u64,
    pub unresolved_obligation_count: u64,
    pub clean_stop: bool,
    pub validator_run_completed: bool,
    pub continuous_consensus_runtime: bool,
    pub signature_verified: bool,
    pub semantics_verified: bool,
    pub g3_evidence_complete: bool,
    pub geo_wan_evidence: bool,
    pub production_activation: bool,
}

#[derive(Serialize)]
struct ConsensusRunReportBodyV1<'a> {
    schema_version: u32,
    run_id: &'a str,
    protocol_id: &'a str,
    profile: &'a str,
    network_scope: &'a str,
    validator_id: &'a str,
    validator_set_id: &'a str,
    validator_set_sha256: &'a str,
    topology_sha256: &'a str,
    coordinator_manifest_sha256: &'a str,
    candidate_source_sha256: &'a str,
    binary_sha256: &'a str,
    config_sha256: &'a str,
    host_id: &'a str,
    process_id: u32,
    process_instance: u64,
    requested_duration_seconds: u64,
    requested_max_blocks: u64,
    pacemaker_base_timeout_seconds: u64,
    terminal_drain_allowance_seconds: u64,
    timeout_view_budget_allowance_seconds: u64,
    signer_journal_capacity: u64,
    maximum_timeout_view_advances: u64,
    maximum_local_vote_intents: u64,
    maximum_local_timeout_intents: u64,
    maximum_total_signer_intents: u64,
    signed_replay_archive_capacity: u64,
    maximum_proposal_archive_entries: u64,
    maximum_quorum_certificate_archive_entries: u64,
    maximum_signed_replay_archive_entries: u64,
    ordinary_start_height: u64,
    started_monotonic_ns: u64,
    ended_monotonic_ns: u64,
    monotonic_clock: &'a str,
    external_wall_clock_temporal_provenance: bool,
    submitted_height: u64,
    committed_height: u64,
    finalized_height: u64,
    submitted_ordinary_block_count: u64,
    committed_ordinary_block_count: u64,
    finalized_ordinary_block_count: u64,
    application_head_block_id: &'a str,
    application_committed_height: u64,
    application_state_root: &'a str,
    safety_revision: u64,
    safety_state_record_checksum: &'a str,
    safety_record_chain_checksum: &'a str,
    application_store_id: &'a str,
    application_store_sequence: u64,
    application_head_row_checksum: &'a str,
    whole_node_checkpoint_generation: u64,
    whole_node_checkpoint_checksum: &'a str,
    signer_scope: &'a str,
    signer_journal_id: &'a str,
    signer_watermark_sequence: u64,
    signer_chain_checksum: &'a str,
    continuous_signed_vote_intents: u64,
    continuous_signed_timeout_intents: u64,
    runtime_event_sequence: u64,
    runtime_event_sha256: &'a str,
    safety_halt_count: u64,
    double_vote_count: u64,
    double_timeout_count: u64,
    conflicting_certificate_count: u64,
    pending_safety_persistence_count: u64,
    pending_payload_validation_count: u64,
    pending_signature_count: u64,
    pending_finalization_count: u64,
    pending_sync_count: u64,
    unresolved_obligation_count: u64,
    clean_stop: bool,
    validator_run_completed: bool,
    continuous_consensus_runtime: bool,
    g3_evidence_complete: bool,
    geo_wan_evidence: bool,
    production_activation: bool,
}

impl SignedConsensusRunReportV1 {
    fn body(&self) -> ConsensusRunReportBodyV1<'_> {
        ConsensusRunReportBodyV1 {
            schema_version: self.schema_version,
            run_id: &self.run_id,
            protocol_id: &self.protocol_id,
            profile: &self.profile,
            network_scope: &self.network_scope,
            validator_id: &self.validator_id,
            validator_set_id: &self.validator_set_id,
            validator_set_sha256: &self.validator_set_sha256,
            topology_sha256: &self.topology_sha256,
            coordinator_manifest_sha256: &self.coordinator_manifest_sha256,
            candidate_source_sha256: &self.candidate_source_sha256,
            binary_sha256: &self.binary_sha256,
            config_sha256: &self.config_sha256,
            host_id: &self.host_id,
            process_id: self.process_id,
            process_instance: self.process_instance,
            requested_duration_seconds: self.requested_duration_seconds,
            requested_max_blocks: self.requested_max_blocks,
            pacemaker_base_timeout_seconds: self.pacemaker_base_timeout_seconds,
            terminal_drain_allowance_seconds: self.terminal_drain_allowance_seconds,
            timeout_view_budget_allowance_seconds: self.timeout_view_budget_allowance_seconds,
            signer_journal_capacity: self.signer_journal_capacity,
            maximum_timeout_view_advances: self.maximum_timeout_view_advances,
            maximum_local_vote_intents: self.maximum_local_vote_intents,
            maximum_local_timeout_intents: self.maximum_local_timeout_intents,
            maximum_total_signer_intents: self.maximum_total_signer_intents,
            signed_replay_archive_capacity: self.signed_replay_archive_capacity,
            maximum_proposal_archive_entries: self.maximum_proposal_archive_entries,
            maximum_quorum_certificate_archive_entries: self
                .maximum_quorum_certificate_archive_entries,
            maximum_signed_replay_archive_entries: self.maximum_signed_replay_archive_entries,
            ordinary_start_height: self.ordinary_start_height,
            started_monotonic_ns: self.started_monotonic_ns,
            ended_monotonic_ns: self.ended_monotonic_ns,
            monotonic_clock: &self.monotonic_clock,
            external_wall_clock_temporal_provenance: self.external_wall_clock_temporal_provenance,
            submitted_height: self.submitted_height,
            committed_height: self.committed_height,
            finalized_height: self.finalized_height,
            submitted_ordinary_block_count: self.submitted_ordinary_block_count,
            committed_ordinary_block_count: self.committed_ordinary_block_count,
            finalized_ordinary_block_count: self.finalized_ordinary_block_count,
            application_head_block_id: &self.application_head_block_id,
            application_committed_height: self.application_committed_height,
            application_state_root: &self.application_state_root,
            safety_revision: self.safety_revision,
            safety_state_record_checksum: &self.safety_state_record_checksum,
            safety_record_chain_checksum: &self.safety_record_chain_checksum,
            application_store_id: &self.application_store_id,
            application_store_sequence: self.application_store_sequence,
            application_head_row_checksum: &self.application_head_row_checksum,
            whole_node_checkpoint_generation: self.whole_node_checkpoint_generation,
            whole_node_checkpoint_checksum: &self.whole_node_checkpoint_checksum,
            signer_scope: &self.signer_scope,
            signer_journal_id: &self.signer_journal_id,
            signer_watermark_sequence: self.signer_watermark_sequence,
            signer_chain_checksum: &self.signer_chain_checksum,
            continuous_signed_vote_intents: self.continuous_signed_vote_intents,
            continuous_signed_timeout_intents: self.continuous_signed_timeout_intents,
            runtime_event_sequence: self.runtime_event_sequence,
            runtime_event_sha256: &self.runtime_event_sha256,
            safety_halt_count: self.safety_halt_count,
            double_vote_count: self.double_vote_count,
            double_timeout_count: self.double_timeout_count,
            conflicting_certificate_count: self.conflicting_certificate_count,
            pending_safety_persistence_count: self.pending_safety_persistence_count,
            pending_payload_validation_count: self.pending_payload_validation_count,
            pending_signature_count: self.pending_signature_count,
            pending_finalization_count: self.pending_finalization_count,
            pending_sync_count: self.pending_sync_count,
            unresolved_obligation_count: self.unresolved_obligation_count,
            clean_stop: self.clean_stop,
            validator_run_completed: self.validator_run_completed,
            continuous_consensus_runtime: self.continuous_consensus_runtime,
            g3_evidence_complete: self.g3_evidence_complete,
            geo_wan_evidence: self.geo_wan_evidence,
            production_activation: self.production_activation,
        }
    }

    fn computed_report_sha256(&self) -> Result<[u8; 32]> {
        let body = serde_json::to_vec(&self.body()).context("encode consensus report body")?;
        Ok(domain_hash(REPORT_HASH_DOMAIN, &body))
    }

    fn verify_with_context(
        &self,
        validator_set: &ValidatorSet,
        expected: &ConsensusReportContextV1,
    ) -> Result<ConsensusReportVerificationV1> {
        validate_semantics(self, expected)?;
        let report_sha256 = canonical_hex::<32>(&self.report_sha256, "report hash")?;
        if report_sha256 != self.computed_report_sha256()? {
            bail!("consensus report hash differs from canonical body");
        }
        let author = ValidatorId::new(canonical_hex::<32>(&self.validator_id, "validator ID")?);
        let validator = validator_set
            .validator(author)
            .ok_or_else(|| anyhow!("consensus report author is absent from validator set"))?;
        let public_key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .context("decode consensus report public key")?;
        let signature = Signature::from_bytes(&canonical_hex::<64>(
            &self.signature,
            "consensus report signature",
        )?);
        public_key
            .verify_strict(&signature_root(report_sha256), &signature)
            .context("verify consensus report signature")?;
        Ok(self.verification_summary())
    }

    pub fn verify_for_config(
        &self,
        config: &LoadedValidatorConfig,
    ) -> Result<ConsensusReportVerificationV1> {
        let expected = ConsensusReportContextV1::from_loaded(config);
        self.verify_with_context(config.validator_set(), &expected)
    }

    pub fn verify_for_public_context(
        &self,
        context: &PublicReportVerifierContext,
    ) -> Result<ConsensusReportVerificationV1> {
        let expected = ConsensusReportContextV1::from_public(context);
        self.verify_with_context(context.validator_set(), &expected)
    }

    fn verification_summary(&self) -> ConsensusReportVerificationV1 {
        ConsensusReportVerificationV1 {
            schema_version: REPORT_SCHEMA_VERSION,
            status: "consensus-run-report-signature-and-semantics-verified".to_owned(),
            run_id: self.run_id.clone(),
            validator_id: self.validator_id.clone(),
            validator_set_id: self.validator_set_id.clone(),
            validator_set_sha256: self.validator_set_sha256.clone(),
            topology_sha256: self.topology_sha256.clone(),
            coordinator_manifest_sha256: self.coordinator_manifest_sha256.clone(),
            candidate_source_sha256: self.candidate_source_sha256.clone(),
            binary_sha256: self.binary_sha256.clone(),
            config_sha256: self.config_sha256.clone(),
            process_instance: self.process_instance,
            ordinary_start_height: self.ordinary_start_height,
            submitted_height: self.submitted_height,
            committed_height: self.committed_height,
            finalized_height: self.finalized_height,
            submitted_ordinary_block_count: self.submitted_ordinary_block_count,
            committed_ordinary_block_count: self.committed_ordinary_block_count,
            finalized_ordinary_block_count: self.finalized_ordinary_block_count,
            application_state_root: self.application_state_root.clone(),
            safety_revision: self.safety_revision,
            application_store_sequence: self.application_store_sequence,
            whole_node_checkpoint_generation: self.whole_node_checkpoint_generation,
            signer_watermark_sequence: self.signer_watermark_sequence,
            safety_halt_count: self.safety_halt_count,
            double_vote_count: self.double_vote_count,
            double_timeout_count: self.double_timeout_count,
            conflicting_certificate_count: self.conflicting_certificate_count,
            unresolved_obligation_count: self.unresolved_obligation_count,
            clean_stop: self.clean_stop,
            validator_run_completed: self.validator_run_completed,
            continuous_consensus_runtime: self.continuous_consensus_runtime,
            signature_verified: true,
            semantics_verified: true,
            g3_evidence_complete: self.g3_evidence_complete,
            geo_wan_evidence: self.geo_wan_evidence,
            production_activation: self.production_activation,
        }
    }
}

#[derive(Debug, Clone)]
struct ConsensusReportContextV1 {
    run_id: String,
    validator_id: String,
    validator_set_id: String,
    validator_set_sha256: String,
    topology_sha256: String,
    coordinator_manifest_sha256: String,
    candidate_source_sha256: String,
    binary_sha256: String,
    config_sha256: String,
    host_id: String,
    ordinary_start_height: u64,
}

impl ConsensusReportContextV1 {
    fn from_loaded(config: &LoadedValidatorConfig) -> Self {
        Self {
            run_id: config.run_id().to_owned(),
            validator_id: hex::encode(config.local_validator().as_bytes()),
            validator_set_id: hex::encode(config.validator_set().id().as_bytes()),
            validator_set_sha256: hex::encode(config.validator_set_sha256()),
            topology_sha256: hex::encode(config.topology_sha256()),
            coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
            candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
            binary_sha256: hex::encode(config.binary_sha256()),
            config_sha256: hex::encode(config.config_sha256()),
            host_id: config.host_id().to_owned(),
            ordinary_start_height: config.ordinary_start_height(),
        }
    }

    fn from_public(config: &PublicReportVerifierContext) -> Self {
        Self {
            run_id: config.run_id().to_owned(),
            validator_id: hex::encode(config.local_validator().as_bytes()),
            validator_set_id: hex::encode(config.validator_set().id().as_bytes()),
            validator_set_sha256: hex::encode(config.validator_set_sha256()),
            topology_sha256: hex::encode(config.topology_sha256()),
            coordinator_manifest_sha256: hex::encode(config.coordinator_manifest_sha256()),
            candidate_source_sha256: hex::encode(config.candidate_source_sha256()),
            binary_sha256: hex::encode(config.binary_sha256()),
            config_sha256: hex::encode(config.config_sha256()),
            host_id: config.host_id().to_owned(),
            ordinary_start_height: config.ordinary_start_height(),
        }
    }
}

/// Creates the signed terminal value. The caller must already have obtained
/// every field from fresh authority readback; this function provides no such
/// authority and is intentionally unavailable outside this crate.
pub(crate) fn sign_consensus_run_report_v1(
    config: &LoadedValidatorConfig,
    bounds: ConsensusRunBoundsV1,
    facts: ConsensusRunTerminalFactsV1,
    clean_stopped_journal: &CleanStoppedJournalCutV1,
) -> Result<SignedConsensusRunReportV1> {
    sign_with_context(
        ConsensusReportContextV1::from_loaded(config),
        config.validator_set(),
        config.signing_key(),
        bounds,
        facts,
        clean_stopped_journal,
    )
}

fn sign_with_context(
    context: ConsensusReportContextV1,
    validator_set: &ValidatorSet,
    signing_key: &SigningKey,
    bounds: ConsensusRunBoundsV1,
    facts: ConsensusRunTerminalFactsV1,
    clean_stopped_journal: &CleanStoppedJournalCutV1,
) -> Result<SignedConsensusRunReportV1> {
    let author = ValidatorId::new(canonical_hex::<32>(&context.validator_id, "validator ID")?);
    let validator = validator_set
        .validator(author)
        .ok_or_else(|| anyhow!("consensus report author is absent from validator set"))?;
    if validator.consensus_key().as_bytes() != &signing_key.verifying_key().to_bytes() {
        bail!("consensus report signing key differs from validator set");
    }
    if clean_stopped_journal.finalized_height() != facts.finalized_height
        || clean_stopped_journal.finalized_height() != facts.application_committed_height
        || clean_stopped_journal.finalized_block_id() != facts.application_head_block_id
        || clean_stopped_journal.finalized_state_root() != facts.application_state_root
    {
        bail!("consensus report terminal owner differs from clean-stopped journal tip");
    }
    let submitted_ordinary_block_count =
        ordinary_block_count(context.ordinary_start_height, facts.submitted_height)?;
    let committed_ordinary_block_count =
        ordinary_block_count(context.ordinary_start_height, facts.committed_height)?;
    let finalized_ordinary_block_count =
        ordinary_block_count(context.ordinary_start_height, facts.finalized_height)?;
    let mut report = SignedConsensusRunReportV1 {
        schema_version: REPORT_SCHEMA_VERSION,
        run_id: context.run_id,
        protocol_id: "poco-bft-v0".to_owned(),
        profile: "authenticated-h1-h3-bootstrap-single-epoch-bounded-consensus-v3".to_owned(),
        network_scope: "single-lan".to_owned(),
        validator_id: context.validator_id,
        validator_set_id: context.validator_set_id,
        validator_set_sha256: context.validator_set_sha256,
        topology_sha256: context.topology_sha256,
        coordinator_manifest_sha256: context.coordinator_manifest_sha256,
        candidate_source_sha256: context.candidate_source_sha256,
        binary_sha256: context.binary_sha256,
        config_sha256: context.config_sha256,
        host_id: context.host_id,
        process_id: clean_stopped_journal.process_id(),
        process_instance: clean_stopped_journal.process_instance(),
        requested_duration_seconds: bounds.requested_duration_seconds,
        requested_max_blocks: bounds.requested_max_blocks,
        pacemaker_base_timeout_seconds: bounds.pacemaker_base_timeout_seconds,
        terminal_drain_allowance_seconds: bounds.terminal_drain_allowance_seconds,
        timeout_view_budget_allowance_seconds: bounds.timeout_view_budget_allowance_seconds,
        signer_journal_capacity: bounds.signer_journal_capacity,
        maximum_timeout_view_advances: bounds.maximum_timeout_view_advances,
        maximum_local_vote_intents: bounds.maximum_local_vote_intents,
        maximum_local_timeout_intents: bounds.maximum_local_timeout_intents,
        maximum_total_signer_intents: bounds.maximum_total_signer_intents,
        signed_replay_archive_capacity: bounds.signed_replay_archive_capacity,
        maximum_proposal_archive_entries: bounds.maximum_proposal_archive_entries,
        maximum_quorum_certificate_archive_entries: bounds
            .maximum_quorum_certificate_archive_entries,
        maximum_signed_replay_archive_entries: bounds.maximum_signed_replay_archive_entries,
        ordinary_start_height: context.ordinary_start_height,
        started_monotonic_ns: 0,
        ended_monotonic_ns: clean_stopped_journal.clean_stop_monotonic_ns(),
        monotonic_clock: "process-local-std-instant".to_owned(),
        external_wall_clock_temporal_provenance: false,
        submitted_height: facts.submitted_height,
        committed_height: facts.committed_height,
        finalized_height: facts.finalized_height,
        submitted_ordinary_block_count,
        committed_ordinary_block_count,
        finalized_ordinary_block_count,
        application_head_block_id: hex::encode(facts.application_head_block_id),
        application_committed_height: facts.application_committed_height,
        application_state_root: hex::encode(facts.application_state_root),
        safety_revision: facts.safety_revision,
        safety_state_record_checksum: hex::encode(facts.safety_state_record_checksum),
        safety_record_chain_checksum: hex::encode(facts.safety_record_chain_checksum),
        application_store_id: hex::encode(facts.application_store_id),
        application_store_sequence: facts.application_store_sequence,
        application_head_row_checksum: hex::encode(facts.application_head_row_checksum),
        whole_node_checkpoint_generation: facts.whole_node_checkpoint_generation,
        whole_node_checkpoint_checksum: hex::encode(facts.whole_node_checkpoint_checksum),
        signer_scope: hex::encode(facts.signer_scope),
        signer_journal_id: hex::encode(facts.signer_journal_id),
        signer_watermark_sequence: facts.signer_watermark_sequence,
        signer_chain_checksum: hex::encode(facts.signer_chain_checksum),
        continuous_signed_vote_intents: facts.continuous_signed_vote_intents,
        continuous_signed_timeout_intents: facts.continuous_signed_timeout_intents,
        runtime_event_sequence: clean_stopped_journal.event_sequence(),
        runtime_event_sha256: hex::encode(clean_stopped_journal.event_sha256()),
        safety_halt_count: facts.safety_halt_count,
        double_vote_count: facts.double_vote_count,
        double_timeout_count: facts.double_timeout_count,
        conflicting_certificate_count: facts.conflicting_certificate_count,
        pending_safety_persistence_count: facts.pending_safety_persistence_count,
        pending_payload_validation_count: facts.pending_payload_validation_count,
        pending_signature_count: facts.pending_signature_count,
        pending_finalization_count: facts.pending_finalization_count,
        pending_sync_count: facts.pending_sync_count,
        unresolved_obligation_count: facts.unresolved_obligation_count,
        clean_stop: true,
        validator_run_completed: true,
        continuous_consensus_runtime: true,
        g3_evidence_complete: false,
        geo_wan_evidence: false,
        production_activation: false,
        report_sha256: String::new(),
        signature: String::new(),
    };
    let report_hash = report.computed_report_sha256()?;
    report.report_sha256 = hex::encode(report_hash);
    report.signature = hex::encode(signing_key.sign(&signature_root(report_hash)).to_bytes());
    report.verify_with_context(
        validator_set,
        &ConsensusReportContextV1 {
            run_id: report.run_id.clone(),
            validator_id: report.validator_id.clone(),
            validator_set_id: report.validator_set_id.clone(),
            validator_set_sha256: report.validator_set_sha256.clone(),
            topology_sha256: report.topology_sha256.clone(),
            coordinator_manifest_sha256: report.coordinator_manifest_sha256.clone(),
            candidate_source_sha256: report.candidate_source_sha256.clone(),
            binary_sha256: report.binary_sha256.clone(),
            config_sha256: report.config_sha256.clone(),
            host_id: report.host_id.clone(),
            ordinary_start_height: report.ordinary_start_height,
        },
    )?;
    Ok(report)
}

fn validate_semantics(
    report: &SignedConsensusRunReportV1,
    expected: &ConsensusReportContextV1,
) -> Result<()> {
    let timeout_view_budget_horizon = report
        .requested_duration_seconds
        .checked_add(report.terminal_drain_allowance_seconds)
        .and_then(|value| value.checked_add(report.timeout_view_budget_allowance_seconds))
        .ok_or_else(|| anyhow!("consensus report timeout-view budget horizon overflows"))?;
    let expected_timeout_view_advances = checked_ceil_div_v1(
        timeout_view_budget_horizon,
        report.pacemaker_base_timeout_seconds,
    )?;
    let expected_local_timeouts = expected_timeout_view_advances;
    let expected_vote_intents = report
        .requested_max_blocks
        .checked_add(expected_timeout_view_advances)
        .ok_or_else(|| anyhow!("consensus report Vote-intent ceiling overflows"))?;
    let expected_total_signer_intents = expected_vote_intents
        .checked_add(expected_local_timeouts)
        .ok_or_else(|| anyhow!("consensus report signer ceiling overflows"))?;
    let expected_qc_entries = expected_vote_intents
        .checked_add(1)
        .ok_or_else(|| anyhow!("consensus report QC ceiling overflows"))?;
    let expected_archive_entries = expected_vote_intents
        .checked_add(expected_qc_entries)
        .ok_or_else(|| anyhow!("consensus report archive ceiling overflows"))?;
    let actual_continuous_intents = report
        .continuous_signed_vote_intents
        .checked_add(report.continuous_signed_timeout_intents)
        .ok_or_else(|| anyhow!("consensus report actual signer accounting overflows"))?;
    if report.schema_version != REPORT_SCHEMA_VERSION
        || report.protocol_id != "poco-bft-v0"
        || report.profile != "authenticated-h1-h3-bootstrap-single-epoch-bounded-consensus-v3"
        || report.network_scope != "single-lan"
        || report.run_id != expected.run_id
        || report.validator_id != expected.validator_id
        || report.validator_set_id != expected.validator_set_id
        || report.validator_set_sha256 != expected.validator_set_sha256
        || report.topology_sha256 != expected.topology_sha256
        || report.coordinator_manifest_sha256 != expected.coordinator_manifest_sha256
        || report.candidate_source_sha256 != expected.candidate_source_sha256
        || report.binary_sha256 != expected.binary_sha256
        || report.config_sha256 != expected.config_sha256
        || report.host_id != expected.host_id
        || report.ordinary_start_height != expected.ordinary_start_height
        || report.process_id == 0
        || report.process_instance == 0
        || report.requested_duration_seconds == 0
        || report.requested_duration_seconds > MAX_CONSENSUS_RUN_DURATION_SECONDS_V1
        || report.requested_max_blocks == 0
        || report.requested_max_blocks > MAX_CONSENSUS_RUN_BLOCKS_V1
        || report.pacemaker_base_timeout_seconds == 0
        || report.signer_journal_capacity != CONTINUOUS_RUNTIME_MAXIMUM_SIGNER_INTENTS_V0
        || report.maximum_timeout_view_advances != expected_timeout_view_advances
        || report.maximum_local_vote_intents != expected_vote_intents
        || report.maximum_local_timeout_intents != expected_local_timeouts
        || report.maximum_total_signer_intents != expected_total_signer_intents
        || report.maximum_total_signer_intents > report.signer_journal_capacity
        || report.signed_replay_archive_capacity != MAXIMUM_ENTRY_COUNT_V1
        || report.maximum_proposal_archive_entries != expected_vote_intents
        || report.maximum_quorum_certificate_archive_entries != expected_qc_entries
        || report.maximum_signed_replay_archive_entries != expected_archive_entries
        || report.maximum_signed_replay_archive_entries > report.signed_replay_archive_capacity
        || report.continuous_signed_vote_intents > report.maximum_local_vote_intents
        || report.continuous_signed_timeout_intents > report.maximum_local_timeout_intents
        || actual_continuous_intents > report.maximum_total_signer_intents
        || actual_continuous_intents > report.signer_watermark_sequence
        || report.started_monotonic_ns != 0
        || report.ended_monotonic_ns == 0
        || report.monotonic_clock != "process-local-std-instant"
        || report.external_wall_clock_temporal_provenance
        || report.submitted_ordinary_block_count == 0
        || report.submitted_ordinary_block_count > report.requested_max_blocks
        || report.committed_ordinary_block_count == 0
        || report.finalized_ordinary_block_count == 0
        || report.submitted_height
            != exact_ordinary_tip(
                report.ordinary_start_height,
                report.submitted_ordinary_block_count,
            )?
        || report.committed_height
            != exact_ordinary_tip(
                report.ordinary_start_height,
                report.committed_ordinary_block_count,
            )?
        || report.finalized_height
            != exact_ordinary_tip(
                report.ordinary_start_height,
                report.finalized_ordinary_block_count,
            )?
        || report.submitted_height < report.committed_height
        || report.committed_height < report.finalized_height
        || report.submitted_ordinary_block_count < report.committed_ordinary_block_count
        || report.committed_ordinary_block_count < report.finalized_ordinary_block_count
        || report.application_committed_height != report.finalized_height
        || report.safety_revision == 0
        || report.application_store_sequence == 0
        || report.whole_node_checkpoint_generation == 0
        || report.signer_watermark_sequence == 0
        || report.runtime_event_sequence == 0
        || report.safety_halt_count != 0
        || report.double_vote_count != 0
        || report.double_timeout_count != 0
        || report.conflicting_certificate_count != 0
        || report.pending_safety_persistence_count != 0
        || report.pending_payload_validation_count != 0
        || report.pending_signature_count != 0
        || report.pending_finalization_count != 0
        || report.pending_sync_count != 0
        || report.unresolved_obligation_count != 0
        || !report.clean_stop
        || !report.validator_run_completed
        || !report.continuous_consensus_runtime
        || report.g3_evidence_complete
        || report.geo_wan_evidence
        || report.production_activation
    {
        bail!("consensus report crosses its exact bounded semantic profile");
    }
    for (value, field) in [
        (
            &report.application_head_block_id,
            "application head block ID",
        ),
        (&report.application_state_root, "application state root"),
        (
            &report.safety_state_record_checksum,
            "Safety record checksum",
        ),
        (
            &report.safety_record_chain_checksum,
            "Safety chain checksum",
        ),
        (&report.application_store_id, "application store ID"),
        (
            &report.application_head_row_checksum,
            "application row checksum",
        ),
        (
            &report.whole_node_checkpoint_checksum,
            "checkpoint checksum",
        ),
        (&report.signer_scope, "signer scope"),
        (&report.signer_journal_id, "signer journal ID"),
        (&report.signer_chain_checksum, "signer chain checksum"),
        (&report.runtime_event_sha256, "runtime event hash"),
    ] {
        if canonical_hex::<32>(value, field)? == [0; 32] {
            bail!("consensus report contains a zero {field}");
        }
    }
    canonical_hex::<32>(&report.validator_set_sha256, "validator-set hash")?;
    canonical_hex::<32>(&report.topology_sha256, "topology hash")?;
    canonical_hex::<32>(&report.coordinator_manifest_sha256, "coordinator hash")?;
    canonical_hex::<32>(&report.candidate_source_sha256, "candidate hash")?;
    canonical_hex::<32>(&report.binary_sha256, "binary hash")?;
    canonical_hex::<32>(&report.config_sha256, "config hash")?;
    Ok(())
}

fn checked_ceil_div_v1(numerator: u64, denominator: u64) -> Result<u64> {
    if denominator == 0 {
        bail!("consensus report ceiling divisor is zero");
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or_else(|| anyhow!("consensus report ceiling division overflows"))
}

fn ordinary_block_count(ordinary_start_height: u64, absolute_tip: u64) -> Result<u64> {
    if ordinary_start_height == 0 || absolute_tip < ordinary_start_height {
        bail!("consensus report lacks a positive ordinary-block tip");
    }
    absolute_tip
        .checked_sub(ordinary_start_height)
        .and_then(|distance| distance.checked_add(1))
        .ok_or_else(|| anyhow!("consensus ordinary-block count overflows"))
}

fn exact_ordinary_tip(ordinary_start_height: u64, ordinary_count: u64) -> Result<u64> {
    if ordinary_start_height == 0 || ordinary_count == 0 {
        bail!("consensus ordinary height/count is zero");
    }
    ordinary_start_height
        .checked_add(ordinary_count - 1)
        .ok_or_else(|| anyhow!("consensus ordinary-block tip overflows"))
}

/// Persists one already signed terminal report without replacement, then
/// verifies its exact fresh readback before returning.
pub(crate) fn write_consensus_run_report_v1(
    path: &Path,
    report: &SignedConsensusRunReportV1,
    config: &LoadedValidatorConfig,
) -> Result<PathBuf> {
    report.verify_for_config(config)?;
    if !path.is_absolute() || path.file_name().is_none() {
        bail!("consensus report path must be absolute");
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow!("consensus report parent is missing"))?
        .canonicalize()
        .context("canonicalize consensus report parent")?;
    let parent_metadata = fs::metadata(&parent_path).context("inspect consensus report parent")?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o077 != 0 {
        bail!("consensus report parent is not private");
    }
    let target = parent_path.join(path.file_name().expect("file name was checked"));
    let parent = File::open(&parent_path).context("open consensus report parent")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&target)
        .context("create consensus report")?;
    file.try_lock_exclusive().context("lock consensus report")?;
    let bytes = serde_json::to_vec(report).context("encode canonical consensus report")?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SIGNED_REPORT_BYTES
    {
        bail!("consensus report crosses its size bound");
    }
    file.write_all(&bytes).context("write consensus report")?;
    file.sync_all().context("sync consensus report")?;
    parent.sync_all().context("sync consensus report parent")?;
    let metadata = file.metadata().context("inspect consensus report")?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != parent_metadata.uid()
        || metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        bail!("consensus report file identity differs after write");
    }
    let readback = load_signed_consensus_run_report_v1(&target)?;
    readback.verify_for_config(config)?;
    if &readback != report {
        bail!("consensus report fresh readback differs");
    }
    Ok(target)
}

/// Performs the effect-free target checks used before a bounded run starts.
/// Successful validation never creates, truncates, replaces, or opens the
/// report path. The final writer repeats every check before its create-new
/// operation.
pub fn validate_consensus_run_report_target_v1(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.file_name().is_none() {
        bail!("consensus report path must be absolute");
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow!("consensus report parent is missing"))?
        .canonicalize()
        .context("canonicalize consensus report parent")?;
    let parent_metadata = fs::metadata(&parent_path).context("inspect consensus report parent")?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o077 != 0 {
        bail!("consensus report parent is not private");
    }
    let target = parent_path.join(path.file_name().expect("file name was checked"));
    match fs::symlink_metadata(&target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(target),
        Err(error) => Err(error).context("inspect consensus report target"),
        Ok(_) => bail!("consensus report target already exists"),
    }
}

/// Loads strict canonical JSON from one pinned regular file. Public observer
/// copies need not preserve the validator's private output-directory mode.
pub fn load_signed_consensus_run_report_v1(path: &Path) -> Result<SignedConsensusRunReportV1> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open pinned consensus report {}", path.display()))?;
    let metadata = file.metadata().context("inspect consensus report")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_SIGNED_REPORT_BYTES {
        bail!("consensus report file crosses its bounded profile");
    }
    let capacity = usize::try_from(metadata.len()).context("consensus report size overflow")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .context("read consensus report")?;
    if bytes.len() != capacity {
        bail!("consensus report changed length while read");
    }
    let report: SignedConsensusRunReportV1 =
        serde_json::from_slice(&bytes).context("decode strict consensus report")?;
    if serde_json::to_vec(&report).context("re-encode strict consensus report")? != bytes {
        bail!("consensus report JSON is not canonical");
    }
    Ok(report)
}

fn canonical_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} is not canonical lowercase hex");
    }
    let bytes = hex::decode(value).with_context(|| format!("decode {field}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{field} has the wrong length"))
}

fn domain_hash(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn signature_root(report_sha256: [u8; 32]) -> [u8; 32] {
    domain_hash(REPORT_SIGNATURE_DOMAIN, &report_sha256)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;

    fn fixture() -> (
        TempDir,
        ConsensusReportContextV1,
        ValidatorSet,
        SigningKey,
        ConsensusRunBoundsV1,
        ConsensusRunTerminalFactsV1,
        CleanStoppedJournalCutV1,
    ) {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let keys: Vec<_> = (1u8..=4)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
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
        let set = ValidatorSet::new(
            GenesisHash::new([0x31; 32]),
            ChainId::new("trnm-g3-consensus-report-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        let context = ConsensusReportContextV1 {
            run_id: "poco-g3-7-20260814t000000z-1234abcd".to_owned(),
            validator_id: hex::encode(set.validators()[0].id().as_bytes()),
            validator_set_id: hex::encode(set.id().as_bytes()),
            validator_set_sha256: hex::encode([0x41; 32]),
            topology_sha256: hex::encode([0x42; 32]),
            coordinator_manifest_sha256: hex::encode([0x43; 32]),
            candidate_source_sha256: hex::encode([0x44; 32]),
            binary_sha256: hex::encode([0x45; 32]),
            config_sha256: hex::encode([0x46; 32]),
            host_id: "local".to_owned(),
            ordinary_start_height: 4,
        };
        let bounds = ConsensusRunBoundsV1 {
            requested_duration_seconds: 60,
            requested_max_blocks: 100,
            pacemaker_base_timeout_seconds: 2,
            terminal_drain_allowance_seconds: 30,
            timeout_view_budget_allowance_seconds: 30,
            signer_journal_capacity: 4_096,
            maximum_timeout_view_advances: 60,
            maximum_local_vote_intents: 160,
            maximum_local_timeout_intents: 60,
            maximum_total_signer_intents: 220,
            signed_replay_archive_capacity: 8_192,
            maximum_proposal_archive_entries: 160,
            maximum_quorum_certificate_archive_entries: 161,
            maximum_signed_replay_archive_entries: 321,
        };
        let facts = ConsensusRunTerminalFactsV1 {
            submitted_height: 13,
            committed_height: 12,
            finalized_height: 11,
            application_head_block_id: [0x51; 32],
            application_committed_height: 11,
            application_state_root: [0x52; 32],
            safety_revision: 21,
            safety_state_record_checksum: [0x53; 32],
            safety_record_chain_checksum: [0x54; 32],
            application_store_id: [0x55; 32],
            application_store_sequence: 13,
            application_head_row_checksum: [0x56; 32],
            whole_node_checkpoint_generation: 12,
            whole_node_checkpoint_checksum: [0x57; 32],
            signer_scope: [0x58; 32],
            signer_journal_id: [0x59; 32],
            signer_watermark_sequence: 18,
            signer_chain_checksum: [0x5a; 32],
            continuous_signed_vote_intents: 10,
            continuous_signed_timeout_intents: 2,
            safety_halt_count: 0,
            double_vote_count: 0,
            double_timeout_count: 0,
            conflicting_certificate_count: 0,
            pending_safety_persistence_count: 0,
            pending_payload_validation_count: 0,
            pending_signature_count: 0,
            pending_finalization_count: 0,
            pending_sync_count: 0,
            unresolved_obligation_count: 0,
        };
        let journal_cut = CleanStoppedJournalCutV1::test_only(
            1, 7, 42, [0x5b; 32], 1_000_000, 11, [0x51; 32], [0x52; 32], [0x5c; 32],
        );
        (
            temporary,
            context,
            set,
            keys[0].clone(),
            bounds,
            facts,
            journal_cut,
        )
    }

    #[test]
    fn signed_terminal_report_and_verifier_summary_are_exact() {
        let (_temporary, context, set, key, bounds, facts, journal_cut) = fixture();
        let report =
            sign_with_context(context.clone(), &set, &key, bounds, facts, &journal_cut).unwrap();
        let summary = report.verify_with_context(&set, &context).unwrap();
        assert_eq!(
            summary.status,
            "consensus-run-report-signature-and-semantics-verified"
        );
        assert_eq!(summary.ordinary_start_height, 4);
        assert_eq!(summary.finalized_height, 11);
        assert_eq!(summary.submitted_ordinary_block_count, 10);
        assert_eq!(summary.committed_ordinary_block_count, 9);
        assert_eq!(summary.finalized_ordinary_block_count, 8);
        assert!(summary.signature_verified);
        assert!(summary.semantics_verified);
        assert!(summary.validator_run_completed);
        assert!(summary.continuous_consensus_runtime);
        assert!(!summary.g3_evidence_complete);
        assert!(!summary.geo_wan_evidence);
        assert!(!summary.production_activation);
    }

    #[test]
    fn context_terminal_and_signature_substitution_fail_closed() {
        let (_temporary, context, set, key, bounds, facts, journal_cut) = fixture();
        let report =
            sign_with_context(context.clone(), &set, &key, bounds, facts, &journal_cut).unwrap();
        let mut cases = Vec::new();
        let mut wrong_context = report.clone();
        wrong_context.coordinator_manifest_sha256 = hex::encode([0x99; 32]);
        cases.push(wrong_context);
        let mut wrong_height = report.clone();
        wrong_height.finalized_height = wrong_height.committed_height + 1;
        cases.push(wrong_height);
        let mut wrong_count = report.clone();
        wrong_count.finalized_ordinary_block_count += 1;
        cases.push(wrong_count);
        let mut pending = report.clone();
        pending.pending_signature_count = 1;
        cases.push(pending);
        let mut halted = report.clone();
        halted.safety_halt_count = 1;
        cases.push(halted);
        let mut bad_signature = report;
        let replacement = if bad_signature.signature.starts_with("00") {
            "01"
        } else {
            "00"
        };
        bad_signature.signature.replace_range(0..2, replacement);
        cases.push(bad_signature);
        for candidate in cases {
            assert!(candidate.verify_with_context(&set, &context).is_err());
        }
    }

    #[test]
    fn report_loader_requires_canonical_regular_file() {
        let (temporary, context, set, key, bounds, facts, journal_cut) = fixture();
        let report = sign_with_context(context, &set, &key, bounds, facts, &journal_cut).unwrap();
        let path = temporary.path().join("report.json");
        fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(load_signed_consensus_run_report_v1(&path).unwrap(), report);

        let whitespace = temporary.path().join("whitespace.json");
        fs::write(
            &whitespace,
            [serde_json::to_vec(&report).unwrap(), b"\n".to_vec()].concat(),
        )
        .unwrap();
        assert!(load_signed_consensus_run_report_v1(&whitespace).is_err());

        let symlink_path = temporary.path().join("report-link.json");
        symlink(&path, &symlink_path).unwrap();
        assert!(load_signed_consensus_run_report_v1(&symlink_path).is_err());
    }

    #[test]
    fn prospective_report_target_is_private_absolute_and_create_new() {
        let (temporary, _context, _set, _key, _bounds, _facts, _journal_cut) = fixture();
        let path = temporary.path().join("new-report.json");
        assert_eq!(
            validate_consensus_run_report_target_v1(&path).unwrap(),
            path
        );
        assert!(!path.exists());

        fs::write(&path, b"occupied").unwrap();
        assert!(validate_consensus_run_report_target_v1(&path).is_err());
        assert!(validate_consensus_run_report_target_v1(Path::new("relative.json")).is_err());

        let public_parent = temporary.path().join("public-parent");
        fs::create_dir(&public_parent).unwrap();
        fs::set_permissions(&public_parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            validate_consensus_run_report_target_v1(&public_parent.join("report.json")).is_err()
        );
    }
}
