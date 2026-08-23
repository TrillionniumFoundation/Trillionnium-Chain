//! Origin-authenticated wire contract for the controlled G3 fleet barrier.
//!
//! The direct transport frame and sparse relay envelope authenticate a hop.
//! They are not the durable authority for a fleet-wide start decision.  Ready
//! and Start statements therefore carry their own validator signature and bind
//! the complete campaign, initial chain cut, and validator-local durable cut.
//! The canonical ReadySet and StartCertificate contain exactly one statement
//! from every validator.  Apart from the already-frozen run identifier, their
//! common digests contain no observed UTC time, PID, fleet launch skew, or
//! cross-machine `Instant` value.
//!
//! This module is a wire/collector primitive only.  It does not arm a
//! pacemaker, release ingress, mutate a journal, or establish G3 evidence.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ChainId, ValidatorId, ValidatorSet};

use crate::frame::validate_run_id_bytes;

const READY_MAGIC_V1: &[u8; 8] = b"TRNMFBR1";
const START_MAGIC_V1: &[u8; 8] = b"TRNMFBS1";
const START_CERTIFICATE_MAGIC_V1: &[u8; 8] = b"TRNMFBC1";
const WIRE_VERSION_V1: u16 = 1;
const READY_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.fleet-ready-signature.v1";
const START_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.fleet-start-signature.v1";
const CONTEXT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.fleet-barrier-context.v1";
const READY_STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.fleet-ready-statement.v1";
const START_STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.fleet-start-statement.v1";
const READY_SET_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.fleet-ready-set.v1";
const START_CERTIFICATE_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.fleet-start-certificate.v1";
const MESH_SESSION_SET_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.fleet-ready-mesh-session-set.v1";
const SIGNATURE_BYTES_V1: usize = 64;
const MAX_CONTEXT_BYTES_V1: usize = 4 * 1024;
const MAX_LOCAL_READY_BYTES_V1: usize = 2 * 1024;
const MAX_MESH_SESSION_SET_BYTES_V1: usize = 2 * 1024;
const MAX_MESH_SESSION_COUNT_V1: usize = 16;
pub const MAX_FLEET_BARRIER_PAYLOAD_BYTES_V1: usize = 16 * 1024;
pub const MAX_FLEET_START_CERTIFICATE_BYTES_V1: usize = 4 * 1024 * 1024;
pub const MAX_FLEET_BARRIER_SIGNER_INTENTS_V1: u64 = 4_096;
pub const MAX_FLEET_BARRIER_ARCHIVE_ENTRIES_V1: u64 = 8_192;
pub const MAX_FLEET_BARRIER_RELAY_ENTRIES_V1: u64 = 131_072;
pub const FLEET_BARRIER_RETAINED_VIEW_TAIL_V1: u64 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetBarrierTransportV1 {
    Direct,
    SparseRelay { hop_budget: u8 },
}

impl FleetBarrierTransportV1 {
    fn validate(self) -> Result<(), FleetBarrierErrorV1> {
        match self {
            Self::Direct => Ok(()),
            Self::SparseRelay { hop_budget } if (1..=32).contains(&hop_budget) => Ok(()),
            Self::SparseRelay { .. } => Err(FleetBarrierErrorV1::Malformed("relay hop budget")),
        }
    }

    fn encode(self, output: &mut Vec<u8>) {
        match self {
            Self::Direct => {
                output.push(1);
                output.push(0);
            }
            Self::SparseRelay { hop_budget } => {
                output.push(2);
                output.push(hop_budget);
            }
        }
    }

    fn decode(cursor: &mut BarrierCursor<'_>) -> Result<Self, FleetBarrierErrorV1> {
        let tag = cursor.byte()?;
        let hop_budget = cursor.byte()?;
        let value = match (tag, hop_budget) {
            (1, 0) => Self::Direct,
            (2, hop_budget) => Self::SparseRelay { hop_budget },
            _ => return Err(FleetBarrierErrorV1::Malformed("transport profile")),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Immutable deployment identity shared by every validator in one barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetCampaignIdentityV1 {
    run_id: String,
    chain_id: ChainId,
    genesis_hash: [u8; 32],
    validator_set_id: [u8; 32],
    validator_set_sha256: [u8; 32],
    topology_sha256: [u8; 32],
    coordinator_manifest_sha256: [u8; 32],
    candidate_source_sha256: [u8; 32],
    binary_sha256: [u8; 32],
    workload_corpus_sha256: [u8; 32],
    workload_policy_sha256: [u8; 32],
    validator_count: u32,
}

impl FleetCampaignIdentityV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: String,
        chain_id: ChainId,
        genesis_hash: [u8; 32],
        validator_set_id: [u8; 32],
        validator_set_sha256: [u8; 32],
        topology_sha256: [u8; 32],
        coordinator_manifest_sha256: [u8; 32],
        candidate_source_sha256: [u8; 32],
        binary_sha256: [u8; 32],
        workload_corpus_sha256: [u8; 32],
        workload_policy_sha256: [u8; 32],
        validator_count: u32,
    ) -> Result<Self, FleetBarrierErrorV1> {
        let value = Self {
            run_id,
            chain_id,
            genesis_hash,
            validator_set_id,
            validator_set_sha256,
            topology_sha256,
            coordinator_manifest_sha256,
            candidate_source_sha256,
            binary_sha256,
            workload_corpus_sha256,
            workload_policy_sha256,
            validator_count,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), FleetBarrierErrorV1> {
        validate_run_id_bytes(self.run_id.as_bytes())
            .map_err(|_| FleetBarrierErrorV1::Malformed("run ID"))?;
        if self.validator_count == 0 {
            return Err(FleetBarrierErrorV1::Malformed("validator count"));
        }
        if !self
            .run_id
            .starts_with(&format!("poco-g3-{}-", self.validator_count))
        {
            return Err(FleetBarrierErrorV1::Malformed("run ID validator count"));
        }
        for digest in [
            self.genesis_hash,
            self.validator_set_id,
            self.validator_set_sha256,
            self.topology_sha256,
            self.coordinator_manifest_sha256,
            self.candidate_source_sha256,
            self.binary_sha256,
            self.workload_corpus_sha256,
            self.workload_policy_sha256,
        ] {
            if digest == [0; 32] {
                return Err(FleetBarrierErrorV1::Malformed(
                    "zero campaign identity digest",
                ));
            }
        }
        Ok(())
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub const fn validator_set_id(&self) -> [u8; 32] {
        self.validator_set_id
    }

    pub const fn validator_set_sha256(&self) -> [u8; 32] {
        self.validator_set_sha256
    }

    pub const fn topology_sha256(&self) -> [u8; 32] {
        self.topology_sha256
    }

    pub const fn coordinator_manifest_sha256(&self) -> [u8; 32] {
        self.coordinator_manifest_sha256
    }

    pub const fn candidate_source_sha256(&self) -> [u8; 32] {
        self.candidate_source_sha256
    }

    pub const fn binary_sha256(&self) -> [u8; 32] {
        self.binary_sha256
    }

    pub const fn workload_corpus_sha256(&self) -> [u8; 32] {
        self.workload_corpus_sha256
    }

    pub const fn workload_policy_sha256(&self) -> [u8; 32] {
        self.workload_policy_sha256
    }

    pub const fn validator_count(&self) -> u32 {
        self.validator_count
    }

    fn encode(&self, output: &mut Vec<u8>) {
        put_string(output, &self.run_id);
        put_string(output, self.chain_id.as_str());
        output.extend_from_slice(&self.genesis_hash);
        output.extend_from_slice(&self.validator_set_id);
        output.extend_from_slice(&self.validator_set_sha256);
        output.extend_from_slice(&self.topology_sha256);
        output.extend_from_slice(&self.coordinator_manifest_sha256);
        output.extend_from_slice(&self.candidate_source_sha256);
        output.extend_from_slice(&self.binary_sha256);
        output.extend_from_slice(&self.workload_corpus_sha256);
        output.extend_from_slice(&self.workload_policy_sha256);
        output.extend_from_slice(&self.validator_count.to_be_bytes());
    }

    fn decode(cursor: &mut BarrierCursor<'_>) -> Result<Self, FleetBarrierErrorV1> {
        let run_id = cursor.string("run ID")?;
        let chain_id = ChainId::new(&cursor.string("chain ID")?)
            .map_err(|_| FleetBarrierErrorV1::Malformed("chain ID"))?;
        Self::new(
            run_id,
            chain_id,
            cursor.array()?,
            cursor.array()?,
            cursor.array()?,
            cursor.array()?,
            cursor.array()?,
            cursor.array()?,
            cursor.array()?,
            cursor.array()?,
            cursor.array()?,
            u32::from_be_bytes(cursor.array()?),
        )
    }
}

/// Frozen bounded-run request.  No wall-clock observation is part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetCampaignRequestV1 {
    barrier_round: u64,
    ordinary_start_height: u64,
    duration_seconds: u64,
    pacemaker_base_timeout_seconds: u64,
    terminal_drain_allowance_seconds: u64,
    timeout_view_budget_allowance_seconds: u64,
    maximum_blocks: u64,
    target_height: u64,
    transport: FleetBarrierTransportV1,
}

impl FleetCampaignRequestV1 {
    pub fn new(
        barrier_round: u64,
        ordinary_start_height: u64,
        duration_seconds: u64,
        pacemaker_base_timeout_seconds: u64,
        terminal_drain_allowance_seconds: u64,
        timeout_view_budget_allowance_seconds: u64,
        maximum_blocks: u64,
        target_height: u64,
        transport: FleetBarrierTransportV1,
    ) -> Result<Self, FleetBarrierErrorV1> {
        let value = Self {
            barrier_round,
            ordinary_start_height,
            duration_seconds,
            pacemaker_base_timeout_seconds,
            terminal_drain_allowance_seconds,
            timeout_view_budget_allowance_seconds,
            maximum_blocks,
            target_height,
            transport,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), FleetBarrierErrorV1> {
        self.transport.validate()?;
        if self.barrier_round == 0
            || self.ordinary_start_height == 0
            || self.duration_seconds == 0
            || self.pacemaker_base_timeout_seconds == 0
            || self.maximum_blocks == 0
            || self.target_height
                != self
                    .ordinary_start_height
                    .checked_add(self.maximum_blocks - 1)
                    .ok_or(FleetBarrierErrorV1::Malformed("target height overflow"))?
        {
            return Err(FleetBarrierErrorV1::Malformed("campaign request"));
        }
        Ok(())
    }

    pub const fn barrier_round(self) -> u64 {
        self.barrier_round
    }

    pub const fn ordinary_start_height(self) -> u64 {
        self.ordinary_start_height
    }

    pub const fn duration_seconds(self) -> u64 {
        self.duration_seconds
    }

    pub const fn pacemaker_base_timeout_seconds(self) -> u64 {
        self.pacemaker_base_timeout_seconds
    }

    pub const fn terminal_drain_allowance_seconds(self) -> u64 {
        self.terminal_drain_allowance_seconds
    }

    pub const fn timeout_view_budget_allowance_seconds(self) -> u64 {
        self.timeout_view_budget_allowance_seconds
    }

    pub const fn maximum_blocks(self) -> u64 {
        self.maximum_blocks
    }

    pub const fn target_height(self) -> u64 {
        self.target_height
    }

    pub const fn transport(self) -> FleetBarrierTransportV1 {
        self.transport
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.barrier_round.to_be_bytes());
        output.extend_from_slice(&self.ordinary_start_height.to_be_bytes());
        output.extend_from_slice(&self.duration_seconds.to_be_bytes());
        output.extend_from_slice(&self.pacemaker_base_timeout_seconds.to_be_bytes());
        output.extend_from_slice(&self.terminal_drain_allowance_seconds.to_be_bytes());
        output.extend_from_slice(&self.timeout_view_budget_allowance_seconds.to_be_bytes());
        output.extend_from_slice(&self.maximum_blocks.to_be_bytes());
        output.extend_from_slice(&self.target_height.to_be_bytes());
        self.transport.encode(output);
    }

    fn decode(cursor: &mut BarrierCursor<'_>) -> Result<Self, FleetBarrierErrorV1> {
        Self::new(
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            FleetBarrierTransportV1::decode(cursor)?,
        )
    }
}

/// Exact signer/archive/relay bounds shared by the controlled campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetCampaignCapacitiesV1 {
    signer_journal_capacity: u64,
    maximum_timeout_view_advances: u64,
    maximum_consensus_message_view: u64,
    maximum_local_vote_intents: u64,
    maximum_local_timeout_intents: u64,
    maximum_total_signer_intents: u64,
    signed_replay_archive_capacity: u64,
    maximum_proposal_archive_entries: u64,
    maximum_quorum_certificate_archive_entries: u64,
    maximum_signed_replay_archive_entries: u64,
    relay_admission_capacity: u64,
}

impl FleetCampaignCapacitiesV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer_journal_capacity: u64,
        maximum_timeout_view_advances: u64,
        maximum_consensus_message_view: u64,
        maximum_local_vote_intents: u64,
        maximum_local_timeout_intents: u64,
        maximum_total_signer_intents: u64,
        signed_replay_archive_capacity: u64,
        maximum_proposal_archive_entries: u64,
        maximum_quorum_certificate_archive_entries: u64,
        maximum_signed_replay_archive_entries: u64,
        relay_admission_capacity: u64,
    ) -> Result<Self, FleetBarrierErrorV1> {
        let value = Self {
            signer_journal_capacity,
            maximum_timeout_view_advances,
            maximum_consensus_message_view,
            maximum_local_vote_intents,
            maximum_local_timeout_intents,
            maximum_total_signer_intents,
            signed_replay_archive_capacity,
            maximum_proposal_archive_entries,
            maximum_quorum_certificate_archive_entries,
            maximum_signed_replay_archive_entries,
            relay_admission_capacity,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), FleetBarrierErrorV1> {
        let values = [
            self.signer_journal_capacity,
            self.maximum_timeout_view_advances,
            self.maximum_consensus_message_view,
            self.maximum_local_vote_intents,
            self.maximum_local_timeout_intents,
            self.maximum_total_signer_intents,
            self.signed_replay_archive_capacity,
            self.maximum_proposal_archive_entries,
            self.maximum_quorum_certificate_archive_entries,
            self.maximum_signed_replay_archive_entries,
            self.relay_admission_capacity,
        ];
        if values.contains(&0)
            || self.maximum_total_signer_intents
                != self
                    .maximum_local_vote_intents
                    .checked_add(self.maximum_local_timeout_intents)
                    .ok_or(FleetBarrierErrorV1::Malformed("signer capacity overflow"))?
            || self.maximum_total_signer_intents > self.signer_journal_capacity
            || self.signer_journal_capacity > MAX_FLEET_BARRIER_SIGNER_INTENTS_V1
            || self.maximum_signed_replay_archive_entries
                != self
                    .maximum_proposal_archive_entries
                    .checked_add(self.maximum_quorum_certificate_archive_entries)
                    .ok_or(FleetBarrierErrorV1::Malformed("archive capacity overflow"))?
            || self.maximum_signed_replay_archive_entries > self.signed_replay_archive_capacity
            || self.signed_replay_archive_capacity > MAX_FLEET_BARRIER_ARCHIVE_ENTRIES_V1
            || self.relay_admission_capacity > MAX_FLEET_BARRIER_RELAY_ENTRIES_V1
        {
            return Err(FleetBarrierErrorV1::Malformed("campaign capacities"));
        }
        Ok(())
    }

    pub const fn signer_journal_capacity(self) -> u64 {
        self.signer_journal_capacity
    }

    pub const fn maximum_timeout_view_advances(self) -> u64 {
        self.maximum_timeout_view_advances
    }

    pub const fn maximum_consensus_message_view(self) -> u64 {
        self.maximum_consensus_message_view
    }

    pub const fn maximum_local_vote_intents(self) -> u64 {
        self.maximum_local_vote_intents
    }

    pub const fn maximum_local_timeout_intents(self) -> u64 {
        self.maximum_local_timeout_intents
    }

    pub const fn maximum_total_signer_intents(self) -> u64 {
        self.maximum_total_signer_intents
    }

    pub const fn signed_replay_archive_capacity(self) -> u64 {
        self.signed_replay_archive_capacity
    }

    pub const fn maximum_proposal_archive_entries(self) -> u64 {
        self.maximum_proposal_archive_entries
    }

    pub const fn maximum_quorum_certificate_archive_entries(self) -> u64 {
        self.maximum_quorum_certificate_archive_entries
    }

    pub const fn maximum_signed_replay_archive_entries(self) -> u64 {
        self.maximum_signed_replay_archive_entries
    }

    pub const fn relay_admission_capacity(self) -> u64 {
        self.relay_admission_capacity
    }

    fn encode(self, output: &mut Vec<u8>) {
        for value in [
            self.signer_journal_capacity,
            self.maximum_timeout_view_advances,
            self.maximum_consensus_message_view,
            self.maximum_local_vote_intents,
            self.maximum_local_timeout_intents,
            self.maximum_total_signer_intents,
            self.signed_replay_archive_capacity,
            self.maximum_proposal_archive_entries,
            self.maximum_quorum_certificate_archive_entries,
            self.maximum_signed_replay_archive_entries,
            self.relay_admission_capacity,
        ] {
            output.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn decode(cursor: &mut BarrierCursor<'_>) -> Result<Self, FleetBarrierErrorV1> {
        Self::new(
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
        )
    }

    fn validate_for_campaign(
        self,
        request: FleetCampaignRequestV1,
        initial_chain_cut: CommonChainCutV1,
        validator_count: u32,
    ) -> Result<(), FleetBarrierErrorV1> {
        let sizing_seconds = request
            .duration_seconds
            .checked_add(request.terminal_drain_allowance_seconds)
            .and_then(|value| value.checked_add(request.timeout_view_budget_allowance_seconds))
            .ok_or(FleetBarrierErrorV1::Malformed(
                "timeout sizing window overflow",
            ))?;
        let theta = checked_ceil_div(sizing_seconds, request.pacemaker_base_timeout_seconds)?;
        let vote_bound = request
            .maximum_blocks
            .checked_add(theta)
            .ok_or(FleetBarrierErrorV1::Malformed("Vote capacity overflow"))?;
        let signer_bound = request
            .maximum_blocks
            .checked_add(
                theta
                    .checked_mul(2)
                    .ok_or(FleetBarrierErrorV1::Malformed("signer capacity overflow"))?,
            )
            .ok_or(FleetBarrierErrorV1::Malformed("signer capacity overflow"))?;
        let qc_bound = vote_bound
            .checked_add(1)
            .ok_or(FleetBarrierErrorV1::Malformed("QC capacity overflow"))?;
        let archive_bound = vote_bound
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(FleetBarrierErrorV1::Malformed("archive capacity overflow"))?;
        let maximum_view = initial_chain_cut
            .current_view
            .checked_add(request.maximum_blocks)
            .and_then(|value| value.checked_add(theta))
            .and_then(|value| value.checked_sub(1))
            .ok_or(FleetBarrierErrorV1::Malformed(
                "message view bound overflow",
            ))?;
        let relay_bound = u64::from(validator_count)
            .checked_mul(2)
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_mul(FLEET_BARRIER_RETAINED_VIEW_TAIL_V1))
            .ok_or(FleetBarrierErrorV1::Malformed("relay capacity overflow"))?;
        if self.maximum_timeout_view_advances != theta
            || self.maximum_consensus_message_view != maximum_view
            || self.maximum_local_vote_intents != vote_bound
            || self.maximum_local_timeout_intents != theta
            || self.maximum_total_signer_intents != signer_bound
            || self.maximum_proposal_archive_entries != vote_bound
            || self.maximum_quorum_certificate_archive_entries != qc_bound
            || self.maximum_signed_replay_archive_entries != archive_bound
            || self.relay_admission_capacity != relay_bound
        {
            return Err(FleetBarrierErrorV1::Malformed(
                "campaign capacity derivation",
            ));
        }
        Ok(())
    }
}

/// Validator-independent initial consensus/application/storage cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonChainCutV1 {
    minimum_retained_view: u64,
    current_view: u64,
    epoch: u64,
    high_qc_certificate_id: [u8; 32],
    high_qc_view: u64,
    high_qc_height: u64,
    high_qc_block_id: [u8; 32],
    finalized_height: u64,
    finalized_block_id: [u8; 32],
    application_height: u64,
    application_block_id: [u8; 32],
    proposal_parent_height: u64,
    proposal_parent_block_id: [u8; 32],
    application_state_root: [u8; 32],
    safety_revision: u64,
    signer_watermark_sequence: u64,
    checkpoint_generation: u64,
}

impl CommonChainCutV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        minimum_retained_view: u64,
        current_view: u64,
        epoch: u64,
        high_qc_certificate_id: [u8; 32],
        high_qc_view: u64,
        high_qc_height: u64,
        high_qc_block_id: [u8; 32],
        finalized_height: u64,
        finalized_block_id: [u8; 32],
        application_height: u64,
        application_block_id: [u8; 32],
        proposal_parent_height: u64,
        proposal_parent_block_id: [u8; 32],
        application_state_root: [u8; 32],
        safety_revision: u64,
        signer_watermark_sequence: u64,
        checkpoint_generation: u64,
    ) -> Result<Self, FleetBarrierErrorV1> {
        let value = Self {
            minimum_retained_view,
            current_view,
            epoch,
            high_qc_certificate_id,
            high_qc_view,
            high_qc_height,
            high_qc_block_id,
            finalized_height,
            finalized_block_id,
            application_height,
            application_block_id,
            proposal_parent_height,
            proposal_parent_block_id,
            application_state_root,
            safety_revision,
            signer_watermark_sequence,
            checkpoint_generation,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), FleetBarrierErrorV1> {
        if self.current_view < self.minimum_retained_view
            || self.high_qc_view > self.current_view
            || self.application_height < self.finalized_height
            || self.proposal_parent_height < self.application_height
            || self.safety_revision == 0
            || self.checkpoint_generation == 0
            || [
                self.high_qc_certificate_id,
                self.high_qc_block_id,
                self.finalized_block_id,
                self.application_block_id,
                self.proposal_parent_block_id,
                self.application_state_root,
            ]
            .contains(&[0; 32])
        {
            return Err(FleetBarrierErrorV1::Malformed("common chain cut"));
        }
        Ok(())
    }

    pub const fn current_view(self) -> u64 {
        self.current_view
    }

    pub const fn minimum_retained_view(self) -> u64 {
        self.minimum_retained_view
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn high_qc_certificate_id(self) -> [u8; 32] {
        self.high_qc_certificate_id
    }

    pub const fn high_qc_view(self) -> u64 {
        self.high_qc_view
    }

    pub const fn high_qc_height(self) -> u64 {
        self.high_qc_height
    }

    pub const fn high_qc_block_id(self) -> [u8; 32] {
        self.high_qc_block_id
    }

    pub const fn finalized_height(self) -> u64 {
        self.finalized_height
    }

    pub const fn finalized_block_id(self) -> [u8; 32] {
        self.finalized_block_id
    }

    pub const fn application_height(self) -> u64 {
        self.application_height
    }

    pub const fn application_block_id(self) -> [u8; 32] {
        self.application_block_id
    }

    pub const fn proposal_parent_height(self) -> u64 {
        self.proposal_parent_height
    }

    pub const fn proposal_parent_block_id(self) -> [u8; 32] {
        self.proposal_parent_block_id
    }

    pub const fn application_state_root(self) -> [u8; 32] {
        self.application_state_root
    }

    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }

    pub const fn signer_watermark_sequence(self) -> u64 {
        self.signer_watermark_sequence
    }

    pub const fn checkpoint_generation(self) -> u64 {
        self.checkpoint_generation
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.minimum_retained_view.to_be_bytes());
        output.extend_from_slice(&self.current_view.to_be_bytes());
        output.extend_from_slice(&self.epoch.to_be_bytes());
        output.extend_from_slice(&self.high_qc_certificate_id);
        output.extend_from_slice(&self.high_qc_view.to_be_bytes());
        output.extend_from_slice(&self.high_qc_height.to_be_bytes());
        output.extend_from_slice(&self.high_qc_block_id);
        output.extend_from_slice(&self.finalized_height.to_be_bytes());
        output.extend_from_slice(&self.finalized_block_id);
        output.extend_from_slice(&self.application_height.to_be_bytes());
        output.extend_from_slice(&self.application_block_id);
        output.extend_from_slice(&self.proposal_parent_height.to_be_bytes());
        output.extend_from_slice(&self.proposal_parent_block_id);
        output.extend_from_slice(&self.application_state_root);
        output.extend_from_slice(&self.safety_revision.to_be_bytes());
        output.extend_from_slice(&self.signer_watermark_sequence.to_be_bytes());
        output.extend_from_slice(&self.checkpoint_generation.to_be_bytes());
    }

    fn decode(cursor: &mut BarrierCursor<'_>) -> Result<Self, FleetBarrierErrorV1> {
        Self::new(
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            cursor.array()?,
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            cursor.array()?,
            u64::from_be_bytes(cursor.array()?),
            cursor.array()?,
            u64::from_be_bytes(cursor.array()?),
            cursor.array()?,
            u64::from_be_bytes(cursor.array()?),
            cursor.array()?,
            cursor.array()?,
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
            u64::from_be_bytes(cursor.array()?),
        )
    }
}

/// Complete shared context.  It is self-describing rather than hiding the
/// campaign behind one unspecified opaque digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonCampaignContextV1 {
    identity: FleetCampaignIdentityV1,
    request: FleetCampaignRequestV1,
    capacities: FleetCampaignCapacitiesV1,
    initial_chain_cut: CommonChainCutV1,
}

impl CommonCampaignContextV1 {
    pub fn new(
        identity: FleetCampaignIdentityV1,
        request: FleetCampaignRequestV1,
        capacities: FleetCampaignCapacitiesV1,
        initial_chain_cut: CommonChainCutV1,
    ) -> Result<Self, FleetBarrierErrorV1> {
        identity.validate()?;
        request.validate()?;
        capacities.validate()?;
        initial_chain_cut.validate()?;
        match (identity.validator_count, request.transport) {
            (7, FleetBarrierTransportV1::Direct)
            | (31, FleetBarrierTransportV1::SparseRelay { hop_budget: 4 })
            | (100, FleetBarrierTransportV1::SparseRelay { hop_budget: 13 }) => {}
            _ => return Err(FleetBarrierErrorV1::Malformed("G3 topology profile")),
        }
        capacities.validate_for_campaign(request, initial_chain_cut, identity.validator_count)?;
        Ok(Self {
            identity,
            request,
            capacities,
            initial_chain_cut,
        })
    }

    pub const fn identity(&self) -> &FleetCampaignIdentityV1 {
        &self.identity
    }

    pub const fn request(&self) -> FleetCampaignRequestV1 {
        self.request
    }

    pub const fn capacities(&self) -> FleetCampaignCapacitiesV1 {
        self.capacities
    }

    pub const fn initial_chain_cut(&self) -> CommonChainCutV1 {
        self.initial_chain_cut
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(CONTEXT_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1024);
        self.identity.encode(&mut output);
        self.request.encode(&mut output);
        self.capacities.encode(&mut output);
        self.initial_chain_cut.encode(&mut output);
        output
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FleetBarrierErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_CONTEXT_BYTES_V1 {
            return Err(FleetBarrierErrorV1::TooLarge);
        }
        let mut cursor = BarrierCursor::new(bytes);
        let value = Self::new(
            FleetCampaignIdentityV1::decode(&mut cursor)?,
            FleetCampaignRequestV1::decode(&mut cursor)?,
            FleetCampaignCapacitiesV1::decode(&mut cursor)?,
            CommonChainCutV1::decode(&mut cursor)?,
        )?;
        cursor.finish()?;
        Ok(value)
    }

    fn validate_for_set(&self, validator_set: &ValidatorSet) -> Result<(), FleetBarrierErrorV1> {
        if self.identity.chain_id != validator_set.chain_id()
            || self.identity.genesis_hash != *validator_set.genesis_hash().as_bytes()
            || self.identity.validator_set_id != *validator_set.id().as_bytes()
            || usize::try_from(self.identity.validator_count).ok()
                != Some(validator_set.validators().len())
        {
            return Err(FleetBarrierErrorV1::WrongContext);
        }
        match (validator_set.validators().len(), self.request.transport) {
            (7, FleetBarrierTransportV1::Direct)
            | (31, FleetBarrierTransportV1::SparseRelay { hop_budget: 4 })
            | (100, FleetBarrierTransportV1::SparseRelay { hop_budget: 13 }) => {}
            _ => return Err(FleetBarrierErrorV1::WrongContext),
        }
        Ok(())
    }

    pub fn expected_mesh_session_count(&self) -> u32 {
        match self.request.transport {
            FleetBarrierTransportV1::Direct => self
                .identity
                .validator_count
                .checked_sub(1)
                .and_then(|value| value.checked_mul(2))
                .expect("validated direct G3 validator count"),
            FleetBarrierTransportV1::SparseRelay { .. } => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FleetMeshSessionDirectionV1 {
    Incoming = 1,
    Outgoing = 2,
}

impl FleetMeshSessionDirectionV1 {
    const fn opposite(self) -> Self {
        match self {
            Self::Incoming => Self::Outgoing,
            Self::Outgoing => Self::Incoming,
        }
    }
}

/// One authenticated mesh session identity.  Socket addresses, process IDs,
/// and local monotonic-clock observations are intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetMeshSessionV1 {
    direction: FleetMeshSessionDirectionV1,
    remote: ValidatorId,
    session_id: [u8; 32],
}

impl FleetMeshSessionV1 {
    pub fn new(
        direction: FleetMeshSessionDirectionV1,
        remote: ValidatorId,
        session_id: [u8; 32],
    ) -> Result<Self, FleetBarrierErrorV1> {
        if remote == ValidatorId::new([0; 32]) || session_id == [0; 32] {
            return Err(FleetBarrierErrorV1::Malformed("mesh session"));
        }
        Ok(Self {
            direction,
            remote,
            session_id,
        })
    }

    pub const fn direction(self) -> FleetMeshSessionDirectionV1 {
        self.direction
    }

    pub const fn remote(self) -> ValidatorId {
        self.remote
    }

    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }
}

/// Canonical local mesh cut sorted by `(remote ValidatorId, direction)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetMeshSessionSetV1 {
    local: ValidatorId,
    sessions: Vec<FleetMeshSessionV1>,
}

impl FleetMeshSessionSetV1 {
    pub fn new(
        local: ValidatorId,
        sessions: Vec<FleetMeshSessionV1>,
        validator_set: &ValidatorSet,
    ) -> Result<Self, FleetBarrierErrorV1> {
        if validator_set.validator(local).is_none() || sessions.is_empty() {
            return Err(FleetBarrierErrorV1::Malformed("mesh session set"));
        }
        let maximum_sessions = validator_set
            .validators()
            .len()
            .checked_sub(1)
            .and_then(|value| value.checked_mul(2))
            .ok_or(FleetBarrierErrorV1::Capacity)?;
        if sessions.len() > maximum_sessions || sessions.len() > MAX_MESH_SESSION_COUNT_V1 {
            return Err(FleetBarrierErrorV1::Capacity);
        }
        let mut canonical = BTreeMap::new();
        for session in sessions {
            if session.remote == local || validator_set.validator(session.remote).is_none() {
                return Err(FleetBarrierErrorV1::UnknownOrigin);
            }
            if canonical
                .insert((session.remote, session.direction), session)
                .is_some()
            {
                return Err(FleetBarrierErrorV1::DuplicateOrigin);
            }
        }
        Ok(Self {
            local,
            sessions: canonical.into_values().collect(),
        })
    }

    pub const fn local(&self) -> ValidatorId {
        self.local
    }

    pub fn sessions(&self) -> &[FleetMeshSessionV1] {
        &self.sessions
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(36 + self.sessions.len() * 65);
        output.extend_from_slice(self.local.as_bytes());
        output.extend_from_slice(
            &u32::try_from(self.sessions.len())
                .expect("validator-bounded mesh inventory fits u32")
                .to_be_bytes(),
        );
        for session in &self.sessions {
            output.extend_from_slice(session.remote.as_bytes());
            output.push(session.direction as u8);
            output.extend_from_slice(&session.session_id);
        }
        output
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(MESH_SESSION_SET_DIGEST_DOMAIN_V1, &self.canonical_bytes())
    }

    pub fn encode(&self) -> Vec<u8> {
        self.canonical_bytes()
    }

    fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, FleetBarrierErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_MESH_SESSION_SET_BYTES_V1 {
            return Err(FleetBarrierErrorV1::TooLarge);
        }
        let mut cursor = BarrierCursor::new(bytes);
        let local = ValidatorId::new(cursor.array()?);
        let count = u32::from_be_bytes(cursor.array()?) as usize;
        if count == 0 || count > MAX_MESH_SESSION_COUNT_V1 {
            return Err(FleetBarrierErrorV1::Capacity);
        }
        let mut sessions = Vec::with_capacity(count);
        for _ in 0..count {
            let remote = ValidatorId::new(cursor.array()?);
            let direction = match cursor.byte()? {
                1 => FleetMeshSessionDirectionV1::Incoming,
                2 => FleetMeshSessionDirectionV1::Outgoing,
                _ => return Err(FleetBarrierErrorV1::Malformed("mesh session direction")),
            };
            sessions.push(FleetMeshSessionV1::new(direction, remote, cursor.array()?)?);
        }
        cursor.finish()?;
        let value = Self::new(local, sessions, validator_set)?;
        if value.encode() != bytes {
            return Err(FleetBarrierErrorV1::Malformed(
                "non-canonical mesh session set",
            ));
        }
        Ok(value)
    }
}

/// Validator-local durable cut captured immediately before Ready is journaled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalReadyCutV1 {
    validator_id: ValidatorId,
    config_sha256: [u8; 32],
    process_instance: u64,
    pre_ready_journal_sequence: u64,
    pre_ready_journal_sha256: [u8; 32],
    mesh_generation: u64,
    mesh_session_count: u32,
    mesh_session_set_sha256: [u8; 32],
    safety_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signed_replay_archive_context_sha256: [u8; 32],
    signed_replay_archive_head_sequence: u64,
    signed_replay_archive_head_sha256: [u8; 32],
}

impl LocalReadyCutV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator_id: ValidatorId,
        config_sha256: [u8; 32],
        process_instance: u64,
        pre_ready_journal_sequence: u64,
        pre_ready_journal_sha256: [u8; 32],
        mesh_session_set: &FleetMeshSessionSetV1,
        safety_record_checksum: [u8; 32],
        safety_chain_checksum: [u8; 32],
        signed_replay_archive_context_sha256: [u8; 32],
        signed_replay_archive_head_sha256: [u8; 32],
    ) -> Result<Self, FleetBarrierErrorV1> {
        if mesh_session_set.local != validator_id {
            return Err(FleetBarrierErrorV1::Malformed(
                "mesh session set local validator",
            ));
        }
        let value = Self {
            validator_id,
            config_sha256,
            process_instance,
            pre_ready_journal_sequence,
            pre_ready_journal_sha256,
            mesh_generation: 1,
            mesh_session_count: u32::try_from(mesh_session_set.sessions.len())
                .map_err(|_| FleetBarrierErrorV1::Capacity)?,
            mesh_session_set_sha256: mesh_session_set.digest(),
            safety_record_checksum,
            safety_chain_checksum,
            signed_replay_archive_context_sha256,
            signed_replay_archive_head_sequence: 0,
            signed_replay_archive_head_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), FleetBarrierErrorV1> {
        if self.validator_id == ValidatorId::new([0; 32])
            || self.process_instance == 0
            || self.pre_ready_journal_sequence == 0
            || self.mesh_generation != 1
            || self.mesh_session_count == 0
            || self.signed_replay_archive_head_sequence != 0
            || [
                self.config_sha256,
                self.pre_ready_journal_sha256,
                self.mesh_session_set_sha256,
                self.safety_record_checksum,
                self.safety_chain_checksum,
                self.signed_replay_archive_context_sha256,
                self.signed_replay_archive_head_sha256,
            ]
            .contains(&[0; 32])
        {
            return Err(FleetBarrierErrorV1::Malformed("local Ready cut"));
        }
        Ok(())
    }

    pub const fn validator_id(self) -> ValidatorId {
        self.validator_id
    }

    pub const fn config_sha256(self) -> [u8; 32] {
        self.config_sha256
    }

    pub const fn process_instance(self) -> u64 {
        self.process_instance
    }

    pub const fn pre_ready_journal_sequence(self) -> u64 {
        self.pre_ready_journal_sequence
    }

    pub const fn pre_ready_journal_sha256(self) -> [u8; 32] {
        self.pre_ready_journal_sha256
    }

    pub const fn mesh_session_count(self) -> u32 {
        self.mesh_session_count
    }

    pub const fn mesh_generation(self) -> u64 {
        self.mesh_generation
    }

    pub const fn mesh_session_set_sha256(self) -> [u8; 32] {
        self.mesh_session_set_sha256
    }

    pub const fn safety_record_checksum(self) -> [u8; 32] {
        self.safety_record_checksum
    }

    pub const fn safety_chain_checksum(self) -> [u8; 32] {
        self.safety_chain_checksum
    }

    pub const fn signed_replay_archive_context_sha256(self) -> [u8; 32] {
        self.signed_replay_archive_context_sha256
    }

    pub const fn signed_replay_archive_head_sequence(self) -> u64 {
        self.signed_replay_archive_head_sequence
    }

    pub const fn signed_replay_archive_head_sha256(self) -> [u8; 32] {
        self.signed_replay_archive_head_sha256
    }

    fn encode(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(384);
        output.extend_from_slice(self.validator_id.as_bytes());
        output.extend_from_slice(&self.config_sha256);
        output.extend_from_slice(&self.process_instance.to_be_bytes());
        output.extend_from_slice(&self.pre_ready_journal_sequence.to_be_bytes());
        output.extend_from_slice(&self.pre_ready_journal_sha256);
        // These explicit declarations are part of the signed Ready body.
        output.push(1); // authority phase: Ready
        output.push(0); // pending timeout certificate: absent
        output.extend_from_slice(&0u64.to_be_bytes()); // signed Vote intents
        output.extend_from_slice(&0u64.to_be_bytes()); // signed Timeout intents
        output.extend_from_slice(&self.mesh_generation.to_be_bytes());
        output.extend_from_slice(&self.mesh_session_count.to_be_bytes());
        output.extend_from_slice(&self.mesh_session_set_sha256);
        output.push(0); // pacemaker constructed: false
        output.push(0); // pacemaker armed: false
        output.extend_from_slice(&self.safety_record_checksum);
        output.extend_from_slice(&self.safety_chain_checksum);
        output.extend_from_slice(&self.signed_replay_archive_context_sha256);
        output.extend_from_slice(&self.signed_replay_archive_head_sequence.to_be_bytes());
        output.extend_from_slice(&self.signed_replay_archive_head_sha256);
        output
    }

    fn decode(bytes: &[u8]) -> Result<Self, FleetBarrierErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_LOCAL_READY_BYTES_V1 {
            return Err(FleetBarrierErrorV1::TooLarge);
        }
        let mut cursor = BarrierCursor::new(bytes);
        let validator_id = ValidatorId::new(cursor.array()?);
        let config_sha256 = cursor.array()?;
        let process_instance = u64::from_be_bytes(cursor.array()?);
        let pre_ready_journal_sequence = u64::from_be_bytes(cursor.array()?);
        let pre_ready_journal_sha256 = cursor.array()?;
        if cursor.byte()? != 1
            || cursor.byte()? != 0
            || u64::from_be_bytes(cursor.array()?) != 0
            || u64::from_be_bytes(cursor.array()?) != 0
        {
            return Err(FleetBarrierErrorV1::Malformed(
                "Ready authority declaration",
            ));
        }
        let mesh_generation = u64::from_be_bytes(cursor.array()?);
        let mesh_session_count = u32::from_be_bytes(cursor.array()?);
        let mesh_session_set_sha256 = cursor.array()?;
        if cursor.byte()? != 0 || cursor.byte()? != 0 {
            return Err(FleetBarrierErrorV1::Malformed(
                "Ready pacemaker declaration",
            ));
        }
        let value = Self {
            validator_id,
            config_sha256,
            process_instance,
            pre_ready_journal_sequence,
            pre_ready_journal_sha256,
            mesh_generation,
            mesh_session_count,
            mesh_session_set_sha256,
            safety_record_checksum: cursor.array()?,
            safety_chain_checksum: cursor.array()?,
            signed_replay_archive_context_sha256: cursor.array()?,
            signed_replay_archive_head_sequence: u64::from_be_bytes(cursor.array()?),
            signed_replay_archive_head_sha256: cursor.array()?,
        };
        cursor.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFleetReadyV1 {
    context: CommonCampaignContextV1,
    local_cut: LocalReadyCutV1,
    mesh_session_set: FleetMeshSessionSetV1,
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl SignedFleetReadyV1 {
    /// Constructs a Ready statement from externally produced signature bytes.
    /// This is the deployed-safe constructor: callers can obtain the exact
    /// signing root with [`Self::signing_root_for_parts_v1`] and ask a remote
    /// signer/HSM to sign it without copying a `SigningKey` into runtime.
    pub fn new_with_signature(
        context: CommonCampaignContextV1,
        local_cut: LocalReadyCutV1,
        mesh_session_set: FleetMeshSessionSetV1,
        validator_set: &ValidatorSet,
        signature: [u8; SIGNATURE_BYTES_V1],
    ) -> Result<Self, FleetBarrierErrorV1> {
        context.validate_for_set(validator_set)?;
        local_cut.validate()?;
        validate_ready_mesh_binding(&context, local_cut, &mesh_session_set)?;
        let value = Self {
            context,
            local_cut,
            mesh_session_set,
            signature,
        };
        value.verify(validator_set)?;
        Ok(value)
    }

    /// Returns the exact Ready signing root for external signature
    /// production.  All fields are validated and encoded identically to the
    /// normal fixture constructor.
    pub fn signing_root_for_parts_v1(
        context: &CommonCampaignContextV1,
        local_cut: LocalReadyCutV1,
        mesh_session_set: &FleetMeshSessionSetV1,
        validator_set: &ValidatorSet,
    ) -> Result<[u8; 32], FleetBarrierErrorV1> {
        context.validate_for_set(validator_set)?;
        local_cut.validate()?;
        validate_ready_mesh_binding(context, local_cut, mesh_session_set)?;
        let unsigned = encode_ready_unsigned(context, local_cut, mesh_session_set)?;
        Ok(signing_root(READY_SIGNING_DOMAIN_V1, &unsigned))
    }

    /// Fixture-only compatibility constructor.  Deployed composition should
    /// use [`Self::new_with_signature`] instead.
    pub fn new(
        context: CommonCampaignContextV1,
        local_cut: LocalReadyCutV1,
        mesh_session_set: FleetMeshSessionSetV1,
        validator_set: &ValidatorSet,
        key: &SigningKey,
    ) -> Result<Self, FleetBarrierErrorV1> {
        context.validate_for_set(validator_set)?;
        local_cut.validate()?;
        validate_ready_mesh_binding(&context, local_cut, &mesh_session_set)?;
        require_origin_key(local_cut.validator_id, validator_set, key)?;
        let unsigned = encode_ready_unsigned(&context, local_cut, &mesh_session_set)?;
        Self::new_with_signature(
            context,
            local_cut,
            mesh_session_set,
            validator_set,
            key.sign(&signing_root(READY_SIGNING_DOMAIN_V1, &unsigned))
                .to_bytes(),
        )
    }

    pub const fn origin(&self) -> ValidatorId {
        self.local_cut.validator_id
    }

    pub const fn local_cut(&self) -> LocalReadyCutV1 {
        self.local_cut
    }

    pub const fn context(&self) -> &CommonCampaignContextV1 {
        &self.context
    }

    pub const fn mesh_session_set(&self) -> &FleetMeshSessionSetV1 {
        &self.mesh_session_set
    }

    pub fn statement_sha256(&self) -> [u8; 32] {
        hash_canonical(READY_STATEMENT_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output =
            encode_ready_unsigned(&self.context, self.local_cut, &self.mesh_session_set)
                .expect("validated Ready fields fit the bounded wire");
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, FleetBarrierErrorV1> {
        let (unsigned, signature) = split_signed_payload(bytes)?;
        let mut cursor = BarrierCursor::new(unsigned);
        if cursor.take(8)? != READY_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(FleetBarrierErrorV1::Malformed("Ready header"));
        }
        let context_len = u32::from_be_bytes(cursor.array()?) as usize;
        let context = CommonCampaignContextV1::decode(cursor.take(context_len)?)?;
        let local_len = u32::from_be_bytes(cursor.array()?) as usize;
        let local_cut = LocalReadyCutV1::decode(cursor.take(local_len)?)?;
        let session_set_len = u32::from_be_bytes(cursor.array()?) as usize;
        let mesh_session_set =
            FleetMeshSessionSetV1::decode(cursor.take(session_set_len)?, validator_set)?;
        cursor.finish()?;
        let value = Self {
            context,
            local_cut,
            mesh_session_set,
            signature,
        };
        value.verify(validator_set)?;
        Ok(value)
    }

    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<(), FleetBarrierErrorV1> {
        self.context.validate_for_set(validator_set)?;
        self.local_cut.validate()?;
        validate_ready_mesh_binding(&self.context, self.local_cut, &self.mesh_session_set)?;
        verify_origin_signature(
            self.origin(),
            validator_set,
            READY_SIGNING_DOMAIN_V1,
            &encode_ready_unsigned(&self.context, self.local_cut, &self.mesh_session_set)?,
            &self.signature,
        )
    }
}

fn validate_ready_mesh_binding(
    context: &CommonCampaignContextV1,
    local_cut: LocalReadyCutV1,
    mesh_session_set: &FleetMeshSessionSetV1,
) -> Result<(), FleetBarrierErrorV1> {
    if mesh_session_set.local != local_cut.validator_id
        || u32::try_from(mesh_session_set.sessions.len()).ok() != Some(local_cut.mesh_session_count)
        || mesh_session_set.digest() != local_cut.mesh_session_set_sha256
        || local_cut.mesh_session_count != context.expected_mesh_session_count()
    {
        return Err(FleetBarrierErrorV1::Malformed(
            "Ready mesh session preimage binding",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFleetStartV1 {
    context: CommonCampaignContextV1,
    local_ready_cut: LocalReadyCutV1,
    ready_statement_sha256: [u8; 32],
    ready_set_sha256: [u8; 32],
    fleet_ready_event_sequence: u64,
    fleet_ready_event_sha256: [u8; 32],
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl SignedFleetStartV1 {
    /// Constructs a Start statement from externally produced signature bytes.
    /// The Ready/ReadySet relationship is revalidated before the supplied
    /// signature is admitted, so a remote signer receives only a canonical
    /// start root and never a raw consensus key.
    pub fn new_with_signature(
        ready: &SignedFleetReadyV1,
        ready_set: &FleetReadySetV1,
        fleet_ready_event_sequence: u64,
        fleet_ready_event_sha256: [u8; 32],
        validator_set: &ValidatorSet,
        signature: [u8; SIGNATURE_BYTES_V1],
    ) -> Result<Self, FleetBarrierErrorV1> {
        ready.verify(validator_set)?;
        ready_set.verify(validator_set)?;
        if ready.context != ready_set.context {
            return Err(FleetBarrierErrorV1::WrongContext);
        }
        let canonical_ready = ready_set
            .statement(ready.origin())
            .ok_or(FleetBarrierErrorV1::Incomplete)?;
        if canonical_ready.statement_sha256() != ready.statement_sha256() {
            return Err(FleetBarrierErrorV1::Malformed(
                "Start source differs from canonical ReadySet",
            ));
        }
        let value = Self {
            context: ready.context.clone(),
            local_ready_cut: ready.local_cut,
            ready_statement_sha256: ready.statement_sha256(),
            ready_set_sha256: ready_set.digest(),
            fleet_ready_event_sequence,
            fleet_ready_event_sha256,
            signature,
        };
        value.validate_fields()?;
        value.verify(validator_set)?;
        Ok(value)
    }

    /// Returns the exact Start signing root for external signature
    /// production after validating the canonical Ready/ReadySet relationship.
    pub fn signing_root_for_parts_v1(
        ready: &SignedFleetReadyV1,
        ready_set: &FleetReadySetV1,
        fleet_ready_event_sequence: u64,
        fleet_ready_event_sha256: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<[u8; 32], FleetBarrierErrorV1> {
        ready.verify(validator_set)?;
        ready_set.verify(validator_set)?;
        if ready.context != ready_set.context {
            return Err(FleetBarrierErrorV1::WrongContext);
        }
        let canonical_ready = ready_set
            .statement(ready.origin())
            .ok_or(FleetBarrierErrorV1::Incomplete)?;
        if canonical_ready.statement_sha256() != ready.statement_sha256() {
            return Err(FleetBarrierErrorV1::Malformed(
                "Start source differs from canonical ReadySet",
            ));
        }
        let value = Self {
            context: ready.context.clone(),
            local_ready_cut: ready.local_cut,
            ready_statement_sha256: ready.statement_sha256(),
            ready_set_sha256: ready_set.digest(),
            fleet_ready_event_sequence,
            fleet_ready_event_sha256,
            signature: [0; SIGNATURE_BYTES_V1],
        };
        value.validate_fields()?;
        Ok(signing_root(
            START_SIGNING_DOMAIN_V1,
            &encode_start_unsigned(&value)?,
        ))
    }

    /// Fixture-only compatibility constructor.  Deployed composition should
    /// use [`Self::new_with_signature`] instead.
    pub fn new(
        ready: &SignedFleetReadyV1,
        ready_set: &FleetReadySetV1,
        fleet_ready_event_sequence: u64,
        fleet_ready_event_sha256: [u8; 32],
        validator_set: &ValidatorSet,
        key: &SigningKey,
    ) -> Result<Self, FleetBarrierErrorV1> {
        ready.verify(validator_set)?;
        ready_set.verify(validator_set)?;
        if ready.context != ready_set.context {
            return Err(FleetBarrierErrorV1::WrongContext);
        }
        let canonical_ready = ready_set
            .statement(ready.origin())
            .ok_or(FleetBarrierErrorV1::Incomplete)?;
        if canonical_ready.statement_sha256() != ready.statement_sha256() {
            return Err(FleetBarrierErrorV1::Malformed(
                "Start source differs from canonical ReadySet",
            ));
        }
        require_origin_key(ready.origin(), validator_set, key)?;
        let signing_root = Self::signing_root_for_parts_v1(
            ready,
            ready_set,
            fleet_ready_event_sequence,
            fleet_ready_event_sha256,
            validator_set,
        )?;
        Self::new_with_signature(
            ready,
            ready_set,
            fleet_ready_event_sequence,
            fleet_ready_event_sha256,
            validator_set,
            key.sign(&signing_root).to_bytes(),
        )
    }

    pub const fn origin(&self) -> ValidatorId {
        self.local_ready_cut.validator_id
    }

    pub const fn context(&self) -> &CommonCampaignContextV1 {
        &self.context
    }

    pub const fn local_ready_cut(&self) -> LocalReadyCutV1 {
        self.local_ready_cut
    }

    pub const fn ready_statement_sha256(&self) -> [u8; 32] {
        self.ready_statement_sha256
    }

    pub const fn ready_set_sha256(&self) -> [u8; 32] {
        self.ready_set_sha256
    }

    pub const fn fleet_ready_event_sequence(&self) -> u64 {
        self.fleet_ready_event_sequence
    }

    pub const fn fleet_ready_event_sha256(&self) -> [u8; 32] {
        self.fleet_ready_event_sha256
    }

    pub fn statement_sha256(&self) -> [u8; 32] {
        hash_canonical(START_STATEMENT_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output =
            encode_start_unsigned(self).expect("validated Start fields fit the bounded wire");
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, FleetBarrierErrorV1> {
        let (unsigned, signature) = split_signed_payload(bytes)?;
        let mut cursor = BarrierCursor::new(unsigned);
        if cursor.take(8)? != START_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(FleetBarrierErrorV1::Malformed("Start header"));
        }
        let context_len = u32::from_be_bytes(cursor.array()?) as usize;
        let context = CommonCampaignContextV1::decode(cursor.take(context_len)?)?;
        let local_len = u32::from_be_bytes(cursor.array()?) as usize;
        let local_ready_cut = LocalReadyCutV1::decode(cursor.take(local_len)?)?;
        let value = Self {
            context,
            local_ready_cut,
            ready_statement_sha256: cursor.array()?,
            ready_set_sha256: cursor.array()?,
            fleet_ready_event_sequence: u64::from_be_bytes(cursor.array()?),
            fleet_ready_event_sha256: cursor.array()?,
            signature,
        };
        cursor.finish()?;
        value.verify(validator_set)?;
        Ok(value)
    }

    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<(), FleetBarrierErrorV1> {
        self.context.validate_for_set(validator_set)?;
        self.validate_fields()?;
        verify_origin_signature(
            self.origin(),
            validator_set,
            START_SIGNING_DOMAIN_V1,
            &encode_start_unsigned(self)?,
            &self.signature,
        )
    }

    fn validate_fields(&self) -> Result<(), FleetBarrierErrorV1> {
        self.local_ready_cut.validate()?;
        if self.ready_statement_sha256 == [0; 32]
            || self.ready_set_sha256 == [0; 32]
            || self.fleet_ready_event_sha256 == [0; 32]
            || self
                .local_ready_cut
                .pre_ready_journal_sequence
                .checked_add(1)
                != Some(self.fleet_ready_event_sequence)
        {
            return Err(FleetBarrierErrorV1::Malformed("Start durable Ready cut"));
        }
        Ok(())
    }
}

/// Canonical N/N commitment. Statements are always stored in ValidatorId order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetReadySetV1 {
    context: CommonCampaignContextV1,
    statements: Vec<SignedFleetReadyV1>,
}

impl FleetReadySetV1 {
    pub fn new(
        context: CommonCampaignContextV1,
        statements: Vec<SignedFleetReadyV1>,
        validator_set: &ValidatorSet,
    ) -> Result<Self, FleetBarrierErrorV1> {
        context.validate_for_set(validator_set)?;
        let mut canonical = BTreeMap::new();
        for statement in statements {
            statement.verify(validator_set)?;
            if statement.context != context {
                return Err(FleetBarrierErrorV1::WrongContext);
            }
            if canonical.insert(statement.origin(), statement).is_some() {
                return Err(FleetBarrierErrorV1::DuplicateOrigin);
            }
        }
        if canonical.len() != validator_set.validators().len()
            || validator_set
                .validators()
                .iter()
                .any(|validator| !canonical.contains_key(&validator.id()))
        {
            return Err(FleetBarrierErrorV1::Incomplete);
        }
        let value = Self {
            context,
            statements: canonical.into_values().collect(),
        };
        value.validate_session_pairing()?;
        Ok(value)
    }

    pub const fn context(&self) -> &CommonCampaignContextV1 {
        &self.context
    }

    pub fn statements(&self) -> &[SignedFleetReadyV1] {
        &self.statements
    }

    pub fn statement(&self, origin: ValidatorId) -> Option<&SignedFleetReadyV1> {
        self.statements
            .binary_search_by_key(&origin, SignedFleetReadyV1::origin)
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(68 + self.statements.len() * 64);
        output.extend_from_slice(&self.context.digest());
        output.extend_from_slice(
            &u32::try_from(self.statements.len())
                .expect("validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in &self.statements {
            output.extend_from_slice(statement.origin().as_bytes());
            output.extend_from_slice(&statement.statement_sha256());
        }
        output
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(READY_SET_DIGEST_DOMAIN_V1, &self.canonical_bytes())
    }

    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<(), FleetBarrierErrorV1> {
        let rebuilt = Self::new(self.context.clone(), self.statements.clone(), validator_set)?;
        if rebuilt.canonical_bytes() != self.canonical_bytes() {
            return Err(FleetBarrierErrorV1::Malformed("non-canonical ReadySet"));
        }
        Ok(())
    }

    /// Verifies every full session-set preimage against the frozen directed
    /// topology and requires the two independently signed endpoints of each
    /// authenticated session to commit the same nonzero session identity.
    pub fn verify_exact_mesh_topology(
        &self,
        expected_outgoing: &BTreeMap<ValidatorId, BTreeSet<ValidatorId>>,
    ) -> Result<(), FleetBarrierErrorV1> {
        let origins = self
            .statements
            .iter()
            .map(SignedFleetReadyV1::origin)
            .collect::<BTreeSet<_>>();
        if expected_outgoing.keys().copied().collect::<BTreeSet<_>>() != origins {
            return Err(FleetBarrierErrorV1::Malformed(
                "mesh topology validator inventory",
            ));
        }
        for statement in &self.statements {
            let local = statement.origin();
            let expected_out = expected_outgoing
                .get(&local)
                .ok_or(FleetBarrierErrorV1::Incomplete)?;
            if expected_out.contains(&local)
                || !expected_out.is_subset(&origins)
                || expected_out.len()
                    != usize::try_from(self.context.expected_mesh_session_count() / 2)
                        .map_err(|_| FleetBarrierErrorV1::Capacity)?
            {
                return Err(FleetBarrierErrorV1::Malformed("mesh outgoing topology"));
            }
            let expected_in = expected_outgoing
                .iter()
                .filter_map(|(origin, peers)| peers.contains(&local).then_some(*origin))
                .collect::<BTreeSet<_>>();
            let actual_out = statement
                .mesh_session_set
                .sessions
                .iter()
                .filter_map(|session| {
                    (session.direction == FleetMeshSessionDirectionV1::Outgoing)
                        .then_some(session.remote)
                })
                .collect::<BTreeSet<_>>();
            let actual_in = statement
                .mesh_session_set
                .sessions
                .iter()
                .filter_map(|session| {
                    (session.direction == FleetMeshSessionDirectionV1::Incoming)
                        .then_some(session.remote)
                })
                .collect::<BTreeSet<_>>();
            if actual_out != *expected_out || actual_in != expected_in {
                return Err(FleetBarrierErrorV1::Malformed(
                    "mesh session set differs from topology",
                ));
            }
        }
        self.validate_session_pairing()
    }

    fn validate_session_pairing(&self) -> Result<(), FleetBarrierErrorV1> {
        let by_origin = self
            .statements
            .iter()
            .map(|statement| (statement.origin(), statement))
            .collect::<BTreeMap<_, _>>();
        for statement in &self.statements {
            for session in &statement.mesh_session_set.sessions {
                let remote = by_origin
                    .get(&session.remote)
                    .ok_or(FleetBarrierErrorV1::Incomplete)?;
                let counterpart = remote
                    .mesh_session_set
                    .sessions
                    .iter()
                    .find(|candidate| {
                        candidate.remote == statement.origin()
                            && candidate.direction == session.direction.opposite()
                    })
                    .ok_or(FleetBarrierErrorV1::Incomplete)?;
                if counterpart.session_id != session.session_id {
                    return Err(FleetBarrierErrorV1::Malformed(
                        "mesh session endpoint identity disagreement",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Canonical N/N Start commitment over one exact N/N ReadySet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetStartCertificateV1 {
    ready_set: FleetReadySetV1,
    statements: Vec<SignedFleetStartV1>,
}

impl FleetStartCertificateV1 {
    pub fn new(
        ready_set: FleetReadySetV1,
        statements: Vec<SignedFleetStartV1>,
        validator_set: &ValidatorSet,
    ) -> Result<Self, FleetBarrierErrorV1> {
        ready_set.verify(validator_set)?;
        let ready_set_sha256 = ready_set.digest();
        let mut canonical = BTreeMap::new();
        for statement in statements {
            statement.verify(validator_set)?;
            if statement.context != ready_set.context
                || statement.ready_set_sha256 != ready_set_sha256
            {
                return Err(FleetBarrierErrorV1::WrongContext);
            }
            let ready = ready_set
                .statement(statement.origin())
                .ok_or(FleetBarrierErrorV1::Incomplete)?;
            if statement.local_ready_cut != ready.local_cut
                || statement.ready_statement_sha256 != ready.statement_sha256()
            {
                return Err(FleetBarrierErrorV1::Malformed(
                    "Start differs from origin Ready",
                ));
            }
            if canonical.insert(statement.origin(), statement).is_some() {
                return Err(FleetBarrierErrorV1::DuplicateOrigin);
            }
        }
        if canonical.len() != validator_set.validators().len()
            || validator_set
                .validators()
                .iter()
                .any(|validator| !canonical.contains_key(&validator.id()))
        {
            return Err(FleetBarrierErrorV1::Incomplete);
        }
        Ok(Self {
            ready_set,
            statements: canonical.into_values().collect(),
        })
    }

    pub const fn ready_set(&self) -> &FleetReadySetV1 {
        &self.ready_set
    }

    pub fn statements(&self) -> &[SignedFleetStartV1] {
        &self.statements
    }

    pub fn statement(&self, origin: ValidatorId) -> Option<&SignedFleetStartV1> {
        self.statements
            .binary_search_by_key(&origin, SignedFleetStartV1::origin)
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(100 + self.statements.len() * 64);
        output.extend_from_slice(&self.ready_set.context.digest());
        output.extend_from_slice(&self.ready_set.digest());
        output.extend_from_slice(
            &u32::try_from(self.statements.len())
                .expect("validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in &self.statements {
            output.extend_from_slice(statement.origin().as_bytes());
            output.extend_from_slice(&statement.statement_sha256());
        }
        output
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(START_CERTIFICATE_DIGEST_DOMAIN_V1, &self.canonical_bytes())
    }

    /// Encodes the complete canonical certificate, including every signed
    /// Ready and Start statement. `canonical_bytes` remains the compact digest
    /// projection; this full form is the durable/replayable barrier authority.
    pub fn encode(&self) -> Vec<u8> {
        let ready = self
            .ready_set
            .statements
            .iter()
            .map(SignedFleetReadyV1::encode)
            .collect::<Vec<_>>();
        let starts = self
            .statements
            .iter()
            .map(SignedFleetStartV1::encode)
            .collect::<Vec<_>>();
        let total = 8usize
            .checked_add(2 + 4 + 4)
            .and_then(|size| {
                ready
                    .iter()
                    .chain(&starts)
                    .try_fold(size, |size, statement| {
                        size.checked_add(4 + statement.len())
                    })
            })
            .expect("validated fleet certificate fits its 4 MiB bound");
        assert!(total <= MAX_FLEET_START_CERTIFICATE_BYTES_V1);
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(START_CERTIFICATE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.extend_from_slice(
            &u32::try_from(ready.len())
                .expect("validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in ready {
            put_bytes_u32(&mut output, &statement);
        }
        output.extend_from_slice(
            &u32::try_from(starts.len())
                .expect("validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in starts {
            put_bytes_u32(&mut output, &statement);
        }
        output
    }

    pub fn decode(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Self, FleetBarrierErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_FLEET_START_CERTIFICATE_BYTES_V1 {
            return Err(FleetBarrierErrorV1::TooLarge);
        }
        let expected_count = validator_set.validators().len();
        if !matches!(expected_count, 7 | 31 | 100) {
            return Err(FleetBarrierErrorV1::WrongContext);
        }
        let mut cursor = BarrierCursor::new(bytes);
        if cursor.take(8)? != START_CERTIFICATE_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(FleetBarrierErrorV1::Malformed("StartCertificate header"));
        }
        let ready_count = u32::from_be_bytes(cursor.array()?) as usize;
        if ready_count != expected_count {
            return Err(FleetBarrierErrorV1::Incomplete);
        }
        let mut ready = Vec::with_capacity(ready_count);
        for _ in 0..ready_count {
            let length = u32::from_be_bytes(cursor.array()?) as usize;
            if length == 0 || length > MAX_FLEET_BARRIER_PAYLOAD_BYTES_V1 {
                return Err(FleetBarrierErrorV1::TooLarge);
            }
            ready.push(SignedFleetReadyV1::decode(
                cursor.take(length)?,
                validator_set,
            )?);
        }
        let start_count = u32::from_be_bytes(cursor.array()?) as usize;
        if start_count != expected_count {
            return Err(FleetBarrierErrorV1::Incomplete);
        }
        let mut starts = Vec::with_capacity(start_count);
        for _ in 0..start_count {
            let length = u32::from_be_bytes(cursor.array()?) as usize;
            if length == 0 || length > MAX_FLEET_BARRIER_PAYLOAD_BYTES_V1 {
                return Err(FleetBarrierErrorV1::TooLarge);
            }
            starts.push(SignedFleetStartV1::decode(
                cursor.take(length)?,
                validator_set,
            )?);
        }
        cursor.finish()?;
        let context = ready
            .first()
            .ok_or(FleetBarrierErrorV1::Incomplete)?
            .context
            .clone();
        let ready_set = FleetReadySetV1::new(context, ready, validator_set)?;
        let value = Self::new(ready_set, starts, validator_set)?;
        if value.encode() != bytes {
            return Err(FleetBarrierErrorV1::Malformed(
                "non-canonical full StartCertificate",
            ));
        }
        Ok(value)
    }

    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<(), FleetBarrierErrorV1> {
        let rebuilt = Self::new(
            self.ready_set.clone(),
            self.statements.clone(),
            validator_set,
        )?;
        if rebuilt.canonical_bytes() != self.canonical_bytes() {
            return Err(FleetBarrierErrorV1::Malformed(
                "non-canonical StartCertificate",
            ));
        }
        Ok(())
    }

    pub fn verify_exact_mesh_topology(
        &self,
        expected_outgoing: &BTreeMap<ValidatorId, BTreeSet<ValidatorId>>,
    ) -> Result<(), FleetBarrierErrorV1> {
        self.ready_set.verify_exact_mesh_topology(expected_outgoing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FleetBarrierPhaseV1 {
    Ready,
    Start,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetBarrierAdmissionV1 {
    New,
    ExactReplay,
}

/// Independent strict 2N map.  No entry is evicted or overwritten.  A second
/// valid body for one `(origin, phase, context)` permanently poisons the map.
pub struct FleetBarrierAdmissionMapV1 {
    context: CommonCampaignContextV1,
    validator_set: ValidatorSet,
    maximum_entries: usize,
    entries: BTreeMap<(ValidatorId, FleetBarrierPhaseV1), [u8; 32]>,
    ready: BTreeMap<ValidatorId, SignedFleetReadyV1>,
    start: BTreeMap<ValidatorId, SignedFleetStartV1>,
    poisoned: bool,
}

impl FleetBarrierAdmissionMapV1 {
    pub fn new(
        context: CommonCampaignContextV1,
        validator_set: ValidatorSet,
    ) -> Result<Self, FleetBarrierErrorV1> {
        context.validate_for_set(&validator_set)?;
        let maximum_entries = validator_set
            .validators()
            .len()
            .checked_mul(2)
            .ok_or(FleetBarrierErrorV1::Capacity)?;
        Ok(Self {
            context,
            validator_set,
            maximum_entries,
            entries: BTreeMap::new(),
            ready: BTreeMap::new(),
            start: BTreeMap::new(),
            poisoned: false,
        })
    }

    pub fn admit_ready_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<FleetBarrierAdmissionV1, FleetBarrierErrorV1> {
        self.ensure_live()?;
        let statement = SignedFleetReadyV1::decode(bytes, &self.validator_set)?;
        self.admit_ready(statement)
    }

    pub fn admit_ready(
        &mut self,
        statement: SignedFleetReadyV1,
    ) -> Result<FleetBarrierAdmissionV1, FleetBarrierErrorV1> {
        self.ensure_live()?;
        statement.verify(&self.validator_set)?;
        if statement.context != self.context {
            return Err(FleetBarrierErrorV1::WrongContext);
        }
        let origin = statement.origin();
        let digest = statement.statement_sha256();
        match self.preflight_slot(origin, FleetBarrierPhaseV1::Ready, digest)? {
            FleetBarrierAdmissionV1::ExactReplay => {
                return Ok(FleetBarrierAdmissionV1::ExactReplay)
            }
            FleetBarrierAdmissionV1::New => {}
        }
        self.commit_slot(origin, FleetBarrierPhaseV1::Ready, digest)?;
        self.ready.insert(origin, statement);
        Ok(FleetBarrierAdmissionV1::New)
    }

    pub fn admit_start_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<FleetBarrierAdmissionV1, FleetBarrierErrorV1> {
        self.ensure_live()?;
        let statement = SignedFleetStartV1::decode(bytes, &self.validator_set)?;
        self.admit_start(statement)
    }

    pub fn admit_start(
        &mut self,
        statement: SignedFleetStartV1,
    ) -> Result<FleetBarrierAdmissionV1, FleetBarrierErrorV1> {
        self.ensure_live()?;
        statement.verify(&self.validator_set)?;
        if statement.context != self.context {
            return Err(FleetBarrierErrorV1::WrongContext);
        }
        let origin = statement.origin();
        let digest = statement.statement_sha256();
        match self.preflight_slot(origin, FleetBarrierPhaseV1::Start, digest)? {
            FleetBarrierAdmissionV1::ExactReplay => {
                return Ok(FleetBarrierAdmissionV1::ExactReplay)
            }
            FleetBarrierAdmissionV1::New => {}
        }
        let ready_set = self.ready_set()?;
        let ready = ready_set
            .statement(origin)
            .ok_or(FleetBarrierErrorV1::Incomplete)?;
        if statement.ready_set_sha256 != ready_set.digest()
            || statement.ready_statement_sha256 != ready.statement_sha256()
            || statement.local_ready_cut != ready.local_cut
        {
            return Err(FleetBarrierErrorV1::Malformed(
                "Start does not bind admitted ReadySet",
            ));
        }
        self.commit_slot(origin, FleetBarrierPhaseV1::Start, digest)?;
        self.start.insert(origin, statement);
        Ok(FleetBarrierAdmissionV1::New)
    }

    pub fn ready_set(&self) -> Result<FleetReadySetV1, FleetBarrierErrorV1> {
        self.ensure_live()?;
        FleetReadySetV1::new(
            self.context.clone(),
            self.ready.values().cloned().collect(),
            &self.validator_set,
        )
    }

    pub fn start_certificate(&self) -> Result<FleetStartCertificateV1, FleetBarrierErrorV1> {
        self.ensure_live()?;
        FleetStartCertificateV1::new(
            self.ready_set()?,
            self.start.values().cloned().collect(),
            &self.validator_set,
        )
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn ready_count(&self) -> usize {
        self.ready.len()
    }

    pub fn start_count(&self) -> usize {
        self.start.len()
    }

    pub const fn context(&self) -> &CommonCampaignContextV1 {
        &self.context
    }

    pub const fn maximum_entries(&self) -> usize {
        self.maximum_entries
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn preflight_slot(
        &mut self,
        origin: ValidatorId,
        phase: FleetBarrierPhaseV1,
        digest: [u8; 32],
    ) -> Result<FleetBarrierAdmissionV1, FleetBarrierErrorV1> {
        let key = (origin, phase);
        if let Some(existing) = self.entries.get(&key) {
            if *existing == digest {
                return Ok(FleetBarrierAdmissionV1::ExactReplay);
            }
            self.poisoned = true;
            return Err(FleetBarrierErrorV1::Equivocation { origin, phase });
        }
        if self.entries.len() == self.maximum_entries {
            self.poisoned = true;
            return Err(FleetBarrierErrorV1::Capacity);
        }
        Ok(FleetBarrierAdmissionV1::New)
    }

    fn commit_slot(
        &mut self,
        origin: ValidatorId,
        phase: FleetBarrierPhaseV1,
        digest: [u8; 32],
    ) -> Result<(), FleetBarrierErrorV1> {
        if self.entries.len() == self.maximum_entries
            || self.entries.insert((origin, phase), digest).is_some()
        {
            self.poisoned = true;
            return Err(FleetBarrierErrorV1::Poisoned);
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), FleetBarrierErrorV1> {
        if self.poisoned {
            Err(FleetBarrierErrorV1::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn encode_ready_unsigned(
    context: &CommonCampaignContextV1,
    local_cut: LocalReadyCutV1,
    mesh_session_set: &FleetMeshSessionSetV1,
) -> Result<Vec<u8>, FleetBarrierErrorV1> {
    let context = context.encode();
    let local = local_cut.encode();
    let sessions = mesh_session_set.encode();
    let total = 8usize
        .checked_add(2 + 4)
        .and_then(|value| value.checked_add(context.len()))
        .and_then(|value| value.checked_add(4 + local.len()))
        .and_then(|value| value.checked_add(4 + sessions.len() + SIGNATURE_BYTES_V1))
        .ok_or(FleetBarrierErrorV1::TooLarge)?;
    if context.len() > MAX_CONTEXT_BYTES_V1
        || local.len() > MAX_LOCAL_READY_BYTES_V1
        || sessions.len() > MAX_MESH_SESSION_SET_BYTES_V1
        || total > MAX_FLEET_BARRIER_PAYLOAD_BYTES_V1
    {
        return Err(FleetBarrierErrorV1::TooLarge);
    }
    let mut output = Vec::with_capacity(total - SIGNATURE_BYTES_V1);
    output.extend_from_slice(READY_MAGIC_V1);
    output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(context.len())
            .map_err(|_| FleetBarrierErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&context);
    output.extend_from_slice(
        &u32::try_from(local.len())
            .map_err(|_| FleetBarrierErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&local);
    output.extend_from_slice(
        &u32::try_from(sessions.len())
            .map_err(|_| FleetBarrierErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&sessions);
    Ok(output)
}

fn encode_start_unsigned(value: &SignedFleetStartV1) -> Result<Vec<u8>, FleetBarrierErrorV1> {
    let context = value.context.encode();
    let local = value.local_ready_cut.encode();
    let total = 8usize
        .checked_add(2 + 4)
        .and_then(|size| size.checked_add(context.len()))
        .and_then(|size| size.checked_add(4 + local.len() + 32 + 32 + 8 + 32))
        .and_then(|size| size.checked_add(SIGNATURE_BYTES_V1))
        .ok_or(FleetBarrierErrorV1::TooLarge)?;
    if context.len() > MAX_CONTEXT_BYTES_V1
        || local.len() > MAX_LOCAL_READY_BYTES_V1
        || total > MAX_FLEET_BARRIER_PAYLOAD_BYTES_V1
    {
        return Err(FleetBarrierErrorV1::TooLarge);
    }
    let mut output = Vec::with_capacity(total - SIGNATURE_BYTES_V1);
    output.extend_from_slice(START_MAGIC_V1);
    output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(context.len())
            .map_err(|_| FleetBarrierErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&context);
    output.extend_from_slice(
        &u32::try_from(local.len())
            .map_err(|_| FleetBarrierErrorV1::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&local);
    output.extend_from_slice(&value.ready_statement_sha256);
    output.extend_from_slice(&value.ready_set_sha256);
    output.extend_from_slice(&value.fleet_ready_event_sequence.to_be_bytes());
    output.extend_from_slice(&value.fleet_ready_event_sha256);
    Ok(output)
}

fn split_signed_payload(
    bytes: &[u8],
) -> Result<(&[u8], [u8; SIGNATURE_BYTES_V1]), FleetBarrierErrorV1> {
    if bytes.len() <= SIGNATURE_BYTES_V1 || bytes.len() > MAX_FLEET_BARRIER_PAYLOAD_BYTES_V1 {
        return Err(FleetBarrierErrorV1::TooLarge);
    }
    let signed_end = bytes.len() - SIGNATURE_BYTES_V1;
    let signature = bytes[signed_end..]
        .try_into()
        .map_err(|_| FleetBarrierErrorV1::Malformed("signature"))?;
    Ok((&bytes[..signed_end], signature))
}

fn require_origin_key(
    origin: ValidatorId,
    validator_set: &ValidatorSet,
    key: &SigningKey,
) -> Result<(), FleetBarrierErrorV1> {
    let validator = validator_set
        .validator(origin)
        .ok_or(FleetBarrierErrorV1::UnknownOrigin)?;
    if validator.consensus_key().as_bytes() != &key.verifying_key().to_bytes() {
        return Err(FleetBarrierErrorV1::OriginKeyMismatch);
    }
    Ok(())
}

fn verify_origin_signature(
    origin: ValidatorId,
    validator_set: &ValidatorSet,
    domain: &[u8],
    unsigned: &[u8],
    signature: &[u8; SIGNATURE_BYTES_V1],
) -> Result<(), FleetBarrierErrorV1> {
    let validator = validator_set
        .validator(origin)
        .ok_or(FleetBarrierErrorV1::UnknownOrigin)?;
    let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
        .map_err(|_| FleetBarrierErrorV1::InvalidSignature)?;
    key.verify_strict(
        &signing_root(domain, unsigned),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| FleetBarrierErrorV1::InvalidSignature)
}

fn signing_root(domain: &[u8], unsigned: &[u8]) -> [u8; 32] {
    hash_canonical(domain, unsigned)
}

fn hash_canonical(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    hasher.finalize().into()
}

fn checked_ceil_div(numerator: u64, denominator: u64) -> Result<u64, FleetBarrierErrorV1> {
    if denominator == 0 {
        return Err(FleetBarrierErrorV1::Malformed("zero capacity denominator"));
    }
    let quotient = numerator / denominator;
    quotient
        .checked_add(u64::from(numerator % denominator != 0))
        .ok_or(FleetBarrierErrorV1::Malformed("capacity division overflow"))
}

fn put_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("validated campaign string fits u16")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}

fn put_bytes_u32(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("bounded fleet statement fits u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

struct BarrierCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BarrierCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], FleetBarrierErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FleetBarrierErrorV1::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FleetBarrierErrorV1::Malformed("truncated payload"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FleetBarrierErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| FleetBarrierErrorV1::Malformed("array"))
    }

    fn byte(&mut self) -> Result<u8, FleetBarrierErrorV1> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(FleetBarrierErrorV1::Malformed("byte"))
    }

    fn string(&mut self, field: &'static str) -> Result<String, FleetBarrierErrorV1> {
        let length = u16::from_be_bytes(self.array()?) as usize;
        let value = self.take(length)?;
        let value = std::str::from_utf8(value)
            .map_err(|_| FleetBarrierErrorV1::Malformed(field))?
            .to_owned();
        Ok(value)
    }

    fn finish(self) -> Result<(), FleetBarrierErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(FleetBarrierErrorV1::Malformed("trailing payload"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetBarrierErrorV1 {
    Malformed(&'static str),
    TooLarge,
    WrongContext,
    UnknownOrigin,
    OriginKeyMismatch,
    InvalidSignature,
    DuplicateOrigin,
    Incomplete,
    Capacity,
    Equivocation {
        origin: ValidatorId,
        phase: FleetBarrierPhaseV1,
    },
    Poisoned,
}

impl std::fmt::Display for FleetBarrierErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(field) => write!(formatter, "malformed fleet barrier field: {field}"),
            Self::TooLarge => formatter.write_str("fleet barrier payload crosses its bound"),
            Self::WrongContext => formatter.write_str("fleet barrier context differs"),
            Self::UnknownOrigin => formatter.write_str("fleet barrier origin is outside set"),
            Self::OriginKeyMismatch => {
                formatter.write_str("fleet barrier key differs from origin key")
            }
            Self::InvalidSignature => formatter.write_str("fleet barrier signature is invalid"),
            Self::DuplicateOrigin => formatter.write_str("fleet barrier origin is duplicated"),
            Self::Incomplete => formatter.write_str("fleet barrier is not N/N complete"),
            Self::Capacity => formatter.write_str("fleet barrier strict 2N capacity exhausted"),
            Self::Equivocation { origin, phase } => write!(
                formatter,
                "fleet barrier origin {origin:?} equivocated in phase {phase:?}"
            ),
            Self::Poisoned => formatter.write_str("fleet barrier admission map is poisoned"),
        }
    }
}

impl std::error::Error for FleetBarrierErrorV1 {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion, Validator,
        VotingPower,
    };

    use super::*;

    fn fixture() -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0..7)
            .map(|index| SigningKey::from_bytes(&[0x31 + index; 32]))
            .collect::<Vec<_>>();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([0x11 + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x21; 32]),
            ChainId::new("trnm-poco-g3-barrier-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn context(set: &ValidatorSet) -> CommonCampaignContextV1 {
        CommonCampaignContextV1::new(
            FleetCampaignIdentityV1::new(
                "poco-g3-7-20260814T000000Z-1234abcd".to_owned(),
                set.chain_id(),
                *set.genesis_hash().as_bytes(),
                *set.id().as_bytes(),
                [0x41; 32],
                [0x42; 32],
                [0x43; 32],
                [0x44; 32],
                [0x45; 32],
                [0x46; 32],
                [0x47; 32],
                u32::try_from(set.validators().len()).unwrap(),
            )
            .unwrap(),
            FleetCampaignRequestV1::new(
                1,
                4,
                60,
                2,
                30,
                30,
                100,
                103,
                FleetBarrierTransportV1::Direct,
            )
            .unwrap(),
            FleetCampaignCapacitiesV1::new(4_096, 60, 163, 160, 60, 220, 8_192, 160, 161, 321, 108)
                .unwrap(),
            CommonChainCutV1::new(
                3, 4, 0, [0x50; 32], 3, 3, [0x51; 32], 1, [0x52; 32], 3, [0x53; 32], 3, [0x53; 32],
                [0x54; 32], 5, 2, 5,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn local(
        set: &ValidatorSet,
        index: usize,
        journal_sequence: u64,
    ) -> (LocalReadyCutV1, FleetMeshSessionSetV1) {
        let local = set.validators()[index].id();
        let mut sessions = Vec::new();
        for (remote_index, remote) in set.validators().iter().enumerate() {
            if remote.id() == local {
                continue;
            }
            sessions.push(
                FleetMeshSessionV1::new(
                    FleetMeshSessionDirectionV1::Incoming,
                    remote.id(),
                    [0x20 + u8::try_from(remote_index * set.validators().len() + index).unwrap();
                        32],
                )
                .unwrap(),
            );
            sessions.push(
                FleetMeshSessionV1::new(
                    FleetMeshSessionDirectionV1::Outgoing,
                    remote.id(),
                    [0x20 + u8::try_from(index * set.validators().len() + remote_index).unwrap();
                        32],
                )
                .unwrap(),
            );
        }
        let mesh = FleetMeshSessionSetV1::new(local, sessions, set).unwrap();
        let local_cut = LocalReadyCutV1::new(
            local,
            [0x61 + u8::try_from(index).unwrap(); 32],
            1,
            journal_sequence,
            [0x71 + u8::try_from(index).unwrap(); 32],
            &mesh,
            [0x91 + u8::try_from(index).unwrap(); 32],
            [0xa1 + u8::try_from(index).unwrap(); 32],
            [0xb1 + u8::try_from(index).unwrap(); 32],
            [0xc1 + u8::try_from(index).unwrap(); 32],
        )
        .unwrap();
        (local_cut, mesh)
    }

    fn ready_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        context: &CommonCampaignContextV1,
    ) -> Vec<SignedFleetReadyV1> {
        keys.iter()
            .enumerate()
            .map(|(index, key)| {
                let (local_cut, mesh_session_set) =
                    local(set, index, 10 + u64::try_from(index).unwrap());
                SignedFleetReadyV1::new(context.clone(), local_cut, mesh_session_set, set, key)
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn signed_ready_and_start_roundtrip_into_canonical_n_of_n_certificate() {
        let (set, keys) = fixture();
        let context = context(&set);
        let ready = ready_statements(&set, &keys, &context);
        for statement in &ready {
            assert_eq!(
                SignedFleetReadyV1::decode(&statement.encode(), &set).unwrap(),
                statement.clone()
            );
        }
        let ready_set = FleetReadySetV1::new(context.clone(), ready.clone(), &set).unwrap();
        let starts = ready
            .iter()
            .zip(&keys)
            .enumerate()
            .map(|(index, (ready, key))| {
                SignedFleetStartV1::new(
                    ready,
                    &ready_set,
                    ready.local_cut().pre_ready_journal_sequence() + 1,
                    [0xd1 + u8::try_from(index).unwrap(); 32],
                    &set,
                    key,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        for statement in &starts {
            assert_eq!(
                SignedFleetStartV1::decode(&statement.encode(), &set).unwrap(),
                statement.clone()
            );
        }
        let certificate =
            FleetStartCertificateV1::new(ready_set.clone(), starts.clone(), &set).unwrap();
        assert_ne!(ready_set.digest(), [0; 32]);
        assert_ne!(certificate.digest(), [0; 32]);
        let full_certificate = certificate.encode();
        let expected_outgoing = set
            .validators()
            .iter()
            .map(|validator| {
                (
                    validator.id(),
                    set.validators()
                        .iter()
                        .map(|peer| peer.id())
                        .filter(|peer| *peer != validator.id())
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        certificate
            .verify_exact_mesh_topology(&expected_outgoing)
            .unwrap();
        let artifact_sha256: [u8; 32] = Sha256::digest(&full_certificate).into();
        assert_ne!(
            artifact_sha256,
            certificate.digest(),
            "artifact SHA-256 and typed compact certificate digest are distinct contracts"
        );
        assert_eq!(
            FleetStartCertificateV1::decode(&full_certificate, &set).unwrap(),
            certificate
        );
        let mut noncanonical = certificate.clone();
        noncanonical.statements.swap(0, 1);
        assert!(FleetStartCertificateV1::decode(&noncanonical.encode(), &set).is_err());

        let mut collector = FleetBarrierAdmissionMapV1::new(context, set.clone()).unwrap();
        for statement in ready.iter().rev() {
            assert_eq!(
                collector.admit_ready(statement.clone()).unwrap(),
                FleetBarrierAdmissionV1::New
            );
        }
        assert_eq!(collector.ready_set().unwrap().digest(), ready_set.digest());
        for statement in starts.iter().rev() {
            assert_eq!(
                collector.admit_start(statement.clone()).unwrap(),
                FleetBarrierAdmissionV1::New
            );
        }
        assert_eq!(collector.len(), collector.maximum_entries());
        assert_eq!(
            collector.start_certificate().unwrap().digest(),
            certificate.digest()
        );
        assert_eq!(
            collector.admit_start(starts[0].clone()).unwrap(),
            FleetBarrierAdmissionV1::ExactReplay
        );
    }

    #[test]
    fn externally_produced_ready_and_start_signatures_roundtrip_v1() {
        let (set, keys) = fixture();
        let context = context(&set);
        let (local_cut, mesh_session_set) = local(&set, 0, 10);
        let ready_root = SignedFleetReadyV1::signing_root_for_parts_v1(
            &context,
            local_cut,
            &mesh_session_set,
            &set,
        )
        .unwrap();
        let externally_produced_ready = SignedFleetReadyV1::new_with_signature(
            context.clone(),
            local_cut,
            mesh_session_set,
            &set,
            keys[0].sign(&ready_root).to_bytes(),
        )
        .unwrap();
        let mut ready = ready_statements(&set, &keys, &context);
        ready[0] = externally_produced_ready;
        let ready_set = FleetReadySetV1::new(context, ready, &set).unwrap();
        let start_root = SignedFleetStartV1::signing_root_for_parts_v1(
            &ready_set.statement(set.validators()[0].id()).unwrap(),
            &ready_set,
            11,
            [0xd1; 32],
            &set,
        )
        .unwrap();
        let start = SignedFleetStartV1::new_with_signature(
            ready_set.statement(set.validators()[0].id()).unwrap(),
            &ready_set,
            11,
            [0xd1; 32],
            &set,
            keys[0].sign(&start_root).to_bytes(),
        )
        .unwrap();
        assert_eq!(
            SignedFleetStartV1::decode(&start.encode(), &set).unwrap(),
            start
        );
    }

    #[test]
    fn valid_different_body_for_same_origin_phase_poison_fail_stops() {
        let (set, keys) = fixture();
        let context = context(&set);
        let (first_cut, first_mesh) = local(&set, 0, 10);
        let first = SignedFleetReadyV1::new(context.clone(), first_cut, first_mesh, &set, &keys[0])
            .unwrap();
        let (conflicting_cut, conflicting_mesh) = local(&set, 0, 11);
        let conflicting = SignedFleetReadyV1::new(
            context.clone(),
            conflicting_cut,
            conflicting_mesh,
            &set,
            &keys[0],
        )
        .unwrap();
        let mut collector = FleetBarrierAdmissionMapV1::new(context, set).unwrap();
        collector.admit_ready(first.clone()).unwrap();
        assert!(matches!(
            collector.admit_ready(conflicting),
            Err(FleetBarrierErrorV1::Equivocation {
                phase: FleetBarrierPhaseV1::Ready,
                ..
            })
        ));
        assert!(collector.is_poisoned());
        assert_eq!(
            collector.admit_ready(first),
            Err(FleetBarrierErrorV1::Poisoned)
        );
    }

    #[test]
    fn valid_different_start_body_poison_fail_stops_before_semantic_replacement() {
        let (set, keys) = fixture();
        let context = context(&set);
        let ready = ready_statements(&set, &keys, &context);
        let ready_set = FleetReadySetV1::new(context.clone(), ready.clone(), &set).unwrap();
        let first =
            SignedFleetStartV1::new(&ready[0], &ready_set, 11, [0xd1; 32], &set, &keys[0]).unwrap();
        let conflicting =
            SignedFleetStartV1::new(&ready[0], &ready_set, 11, [0xd2; 32], &set, &keys[0]).unwrap();
        let mut collector = FleetBarrierAdmissionMapV1::new(context, set).unwrap();
        for statement in ready {
            collector.admit_ready(statement).unwrap();
        }
        collector.admit_start(first).unwrap();
        assert!(matches!(
            collector.admit_start(conflicting),
            Err(FleetBarrierErrorV1::Equivocation {
                phase: FleetBarrierPhaseV1::Start,
                ..
            })
        ));
        assert!(collector.is_poisoned());
    }

    #[test]
    fn mutation_foreign_context_and_start_before_n_of_n_fail_closed() {
        let (set, keys) = fixture();
        let context = context(&set);
        let ready = ready_statements(&set, &keys, &context);
        let mut mutated = ready[0].encode();
        *mutated.last_mut().unwrap() ^= 1;
        assert_eq!(
            SignedFleetReadyV1::decode(&mutated, &set),
            Err(FleetBarrierErrorV1::InvalidSignature)
        );

        let mut collector = FleetBarrierAdmissionMapV1::new(context.clone(), set.clone()).unwrap();
        collector.admit_ready(ready[0].clone()).unwrap();
        assert_eq!(collector.ready_set(), Err(FleetBarrierErrorV1::Incomplete));

        let mut foreign = context.clone();
        foreign.request.barrier_round += 1;
        let (foreign_cut, foreign_mesh) = local(&set, 1, 12);
        let foreign_ready =
            SignedFleetReadyV1::new(foreign, foreign_cut, foreign_mesh, &set, &keys[1]).unwrap();
        assert_eq!(
            collector.admit_ready(foreign_ready),
            Err(FleetBarrierErrorV1::WrongContext)
        );
        assert!(!collector.is_poisoned());
    }

    #[test]
    fn exact_theta_capacity_and_message_view_formula_is_context_authoritative() {
        let (set, _) = fixture();
        let valid = context(&set);
        assert_eq!(valid.capacities.maximum_timeout_view_advances(), 60);
        assert_eq!(valid.capacities.maximum_local_vote_intents(), 160);
        assert_eq!(valid.capacities.maximum_local_timeout_intents(), 60);
        assert_eq!(valid.capacities.maximum_total_signer_intents(), 220);
        assert_eq!(valid.capacities.maximum_consensus_message_view(), 163);

        let mut stale_split_budget = valid.capacities;
        stale_split_budget.maximum_local_timeout_intents = 45;
        stale_split_budget.maximum_total_signer_intents = 205;
        assert_eq!(
            CommonCampaignContextV1::new(
                valid.identity.clone(),
                valid.request,
                stale_split_budget,
                valid.initial_chain_cut,
            ),
            Err(FleetBarrierErrorV1::Malformed(
                "campaign capacity derivation"
            ))
        );
    }

    #[test]
    fn mesh_session_digest_is_order_independent_but_direction_sensitive() {
        let (set, _) = fixture();
        let local = set.validators()[0].id();
        let remote = set.validators()[1].id();
        let incoming =
            FleetMeshSessionV1::new(FleetMeshSessionDirectionV1::Incoming, remote, [0xe1; 32])
                .unwrap();
        let outgoing =
            FleetMeshSessionV1::new(FleetMeshSessionDirectionV1::Outgoing, remote, [0xe2; 32])
                .unwrap();
        let first = FleetMeshSessionSetV1::new(local, vec![incoming, outgoing], &set).unwrap();
        let reversed = FleetMeshSessionSetV1::new(local, vec![outgoing, incoming], &set).unwrap();
        assert_eq!(first.canonical_bytes(), reversed.canonical_bytes());
        assert_eq!(first.digest(), reversed.digest());

        let changed_direction = FleetMeshSessionSetV1::new(
            local,
            vec![FleetMeshSessionV1::new(
                FleetMeshSessionDirectionV1::Incoming,
                remote,
                [0xe2; 32],
            )
            .unwrap()],
            &set,
        )
        .unwrap();
        assert_ne!(first.digest(), changed_direction.digest());
    }
}
