//! Canonical joint-N/N evidence for one observed laboratory epoch handoff.
//!
//! The old and new validator inventories are independent: membership and
//! consensus keys may both change. Every old-set validator signs once in the
//! old role and every new-set validator signs once in the new role. The role
//! is part of the signing preimage, so an overlapping validator/key cannot
//! replay one declaration into the other inventory.
//!
//! This module is evidence-only. In particular, the wire carries a digest and
//! projection of a verified transition proof, but decoding that wire never
//! mints a success carrier. [`EpochHandoffEvidenceCertificateV1::verify_owned`]
//! additionally requires the non-forgeable Node
//! [`PocoNodeLabVerifiedEpochTransitionObservationV0`] and the exact raw
//! FleetStartCertificate before returning a non-Clone verified carrier. There
//! is no conversion to Core, signer, timer, storage, or handoff authority.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{QcRef, ValidatorId, ValidatorSet};
use trnm_poco_node::PocoNodeLabVerifiedEpochTransitionObservationV0;

use crate::fleet_barrier::{CommonCampaignContextV1, FleetStartCertificateV1};

const BODY_MAGIC_V1: &[u8; 8] = b"TRNMEHB1";
const STATEMENT_MAGIC_V1: &[u8; 8] = b"TRNMEHS1";
const CERTIFICATE_MAGIC_V1: &[u8; 8] = b"TRNMEHC1";
const WIRE_VERSION_V1: u16 = 1;
const STATEMENT_SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.epoch-handoff.statement.v1";
const BODY_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.epoch-handoff.body.v1";
const STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.epoch-handoff.statement-digest.v1";
const CERTIFICATE_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.epoch-handoff.certificate.v1";
const SIGNATURE_BYTES_V1: usize = 64;
const MAX_BODY_BYTES_V1: usize = 32 * 1024;
const MAX_STATEMENT_BYTES_V1: usize = 48 * 1024;
pub const MAX_EPOCH_HANDOFF_EVIDENCE_CERTIFICATE_BYTES_V1: usize = 16 * 1024 * 1024;

/// Exact old-epoch runtime cut reported before the handoff boundary.
/// Finalized and applied application coordinates must be equal and are joined
/// to the Node-owned verified transition observation. The high-QC may be
/// ahead, but remains a signed evidence fact rather than activation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochHandoffOldCutV1 {
    pub current_view: u64,
    pub finalized_view: u64,
    pub finalized_height: u64,
    pub finalized_block_id: [u8; 32],
    pub application_height: u64,
    pub application_block_id: [u8; 32],
    pub application_state_root: [u8; 32],
    pub checkpoint_generation: u64,
    pub checkpoint_checksum: [u8; 32],
    pub high_qc: QcRef,
}

impl EpochHandoffOldCutV1 {
    fn validate(self, old_validator_set: &ValidatorSet) -> Result<(), EpochHandoffEvidenceErrorV1> {
        if self.current_view < self.finalized_view
            || self.current_view < self.high_qc.view().get()
            || self.finalized_height == 0
            || self.finalized_height != self.application_height
            || self.finalized_block_id != self.application_block_id
            || self.high_qc.epoch() != old_validator_set.epoch()
            || self.high_qc.validator_set_id() != old_validator_set.id()
            || self.high_qc.height().get() < self.application_height
            || self.checkpoint_generation == 0
            || self.high_qc.qc_digest().is_zero()
            || self.high_qc.block_id().is_zero()
            || [
                self.finalized_block_id,
                self.application_state_root,
                self.checkpoint_checksum,
            ]
            .contains(&[0; 32])
        {
            return Err(EpochHandoffEvidenceErrorV1::Malformed("old epoch cut"));
        }
        Ok(())
    }

    fn validate_observation(
        self,
        observation: TransitionObservationProjectionV1,
    ) -> Result<(), EpochHandoffEvidenceErrorV1> {
        if self.finalized_view != observation.committed_parent_view
            || self.finalized_height != observation.committed_parent_height
            || self.finalized_block_id != observation.committed_parent_block_id
            || self.application_height != observation.committed_parent_height
            || self.application_block_id != observation.committed_parent_block_id
            || self.application_state_root != observation.committed_parent_state_root
            || self.checkpoint_generation != observation.local_checkpoint_generation
            || self.checkpoint_checksum != observation.local_checkpoint_checksum
        {
            return Err(EpochHandoffEvidenceErrorV1::WrongTransitionObservation);
        }
        Ok(())
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.current_view.to_be_bytes());
        output.extend_from_slice(&self.finalized_view.to_be_bytes());
        output.extend_from_slice(&self.finalized_height.to_be_bytes());
        output.extend_from_slice(&self.finalized_block_id);
        output.extend_from_slice(&self.application_height.to_be_bytes());
        output.extend_from_slice(&self.application_block_id);
        output.extend_from_slice(&self.application_state_root);
        output.extend_from_slice(&self.checkpoint_generation.to_be_bytes());
        output.extend_from_slice(&self.checkpoint_checksum);
        encode_qc_ref(self.high_qc, output);
    }

    fn decode(cursor: &mut EpochEvidenceCursor<'_>) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        Ok(Self {
            current_view: u64::from_be_bytes(cursor.array()?),
            finalized_view: u64::from_be_bytes(cursor.array()?),
            finalized_height: u64::from_be_bytes(cursor.array()?),
            finalized_block_id: cursor.array()?,
            application_height: u64::from_be_bytes(cursor.array()?),
            application_block_id: cursor.array()?,
            application_state_root: cursor.array()?,
            checkpoint_generation: u64::from_be_bytes(cursor.array()?),
            checkpoint_checksum: cursor.array()?,
            high_qc: decode_qc_ref(cursor)?,
        })
    }
}

/// Projection of the strict same-version transition proof and first
/// new-epoch terminal proof. There is no public field-selected constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochHandoffVerifiedTransitionBindingV1 {
    observation_checksum: [u8; 32],
    committed_parent_timestamp_ms: u64,
    old_checkpoint_finality_proof_id: [u8; 32],
    handoff_certificate_digest: [u8; 32],
    first_new_epoch_finality_proof_id: [u8; 32],
    terminal_old_block_id: [u8; 32],
    terminal_old_height: u64,
    first_new_epoch_block_id: [u8; 32],
    first_new_epoch_height: u64,
    first_new_epoch_state_root: [u8; 32],
    observed_new_epoch_tip_block_id: [u8; 32],
    observed_new_epoch_tip_height: u64,
    observed_new_epoch_tip_view: u64,
}

impl EpochHandoffVerifiedTransitionBindingV1 {
    fn from_projection(observation: TransitionObservationProjectionV1) -> Self {
        Self {
            observation_checksum: observation.observation_checksum,
            committed_parent_timestamp_ms: observation.committed_parent_timestamp_ms,
            old_checkpoint_finality_proof_id: observation.old_checkpoint_finality_proof_id,
            handoff_certificate_digest: observation.handoff_certificate_digest,
            first_new_epoch_finality_proof_id: observation.first_new_epoch_finality_proof_id,
            terminal_old_block_id: observation.terminal_old_block_id,
            terminal_old_height: observation.terminal_old_height,
            first_new_epoch_block_id: observation.first_new_epoch_block_id,
            first_new_epoch_height: observation.first_new_epoch_height,
            first_new_epoch_state_root: observation.first_new_epoch_state_root,
            observed_new_epoch_tip_block_id: observation.observed_new_epoch_tip_block_id,
            observed_new_epoch_tip_height: observation.observed_new_epoch_tip_height,
            observed_new_epoch_tip_view: observation.observed_new_epoch_tip_view,
        }
    }

    pub const fn observation_checksum(&self) -> [u8; 32] {
        self.observation_checksum
    }

    pub const fn handoff_certificate_digest(&self) -> [u8; 32] {
        self.handoff_certificate_digest
    }

    pub const fn first_new_epoch_block_id(&self) -> [u8; 32] {
        self.first_new_epoch_block_id
    }

    pub const fn first_new_epoch_height(&self) -> u64 {
        self.first_new_epoch_height
    }

    pub const fn first_new_epoch_state_root(&self) -> [u8; 32] {
        self.first_new_epoch_state_root
    }

    pub const fn observed_new_epoch_tip_block_id(&self) -> [u8; 32] {
        self.observed_new_epoch_tip_block_id
    }

    pub const fn observed_new_epoch_tip_height(&self) -> u64 {
        self.observed_new_epoch_tip_height
    }

    pub const fn observed_new_epoch_tip_view(&self) -> u64 {
        self.observed_new_epoch_tip_view
    }

    fn validate(self) -> Result<(), EpochHandoffEvidenceErrorV1> {
        if self.committed_parent_timestamp_ms == 0
            || self.terminal_old_height == 0
            || self.first_new_epoch_height
                != self
                    .terminal_old_height
                    .checked_add(1)
                    .ok_or(EpochHandoffEvidenceErrorV1::Capacity)?
            || self.observed_new_epoch_tip_height < self.first_new_epoch_height
            || self.observed_new_epoch_tip_view == 0
            || [
                self.observation_checksum,
                self.old_checkpoint_finality_proof_id,
                self.handoff_certificate_digest,
                self.first_new_epoch_finality_proof_id,
                self.terminal_old_block_id,
                self.first_new_epoch_block_id,
                self.first_new_epoch_state_root,
                self.observed_new_epoch_tip_block_id,
            ]
            .contains(&[0; 32])
        {
            return Err(EpochHandoffEvidenceErrorV1::Malformed(
                "verified transition binding",
            ));
        }
        Ok(())
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.observation_checksum);
        output.extend_from_slice(&self.committed_parent_timestamp_ms.to_be_bytes());
        output.extend_from_slice(&self.old_checkpoint_finality_proof_id);
        output.extend_from_slice(&self.handoff_certificate_digest);
        output.extend_from_slice(&self.first_new_epoch_finality_proof_id);
        output.extend_from_slice(&self.terminal_old_block_id);
        output.extend_from_slice(&self.terminal_old_height.to_be_bytes());
        output.extend_from_slice(&self.first_new_epoch_block_id);
        output.extend_from_slice(&self.first_new_epoch_height.to_be_bytes());
        output.extend_from_slice(&self.first_new_epoch_state_root);
        output.extend_from_slice(&self.observed_new_epoch_tip_block_id);
        output.extend_from_slice(&self.observed_new_epoch_tip_height.to_be_bytes());
        output.extend_from_slice(&self.observed_new_epoch_tip_view.to_be_bytes());
    }

    fn decode(cursor: &mut EpochEvidenceCursor<'_>) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        let value = Self {
            observation_checksum: cursor.array()?,
            committed_parent_timestamp_ms: u64::from_be_bytes(cursor.array()?),
            old_checkpoint_finality_proof_id: cursor.array()?,
            handoff_certificate_digest: cursor.array()?,
            first_new_epoch_finality_proof_id: cursor.array()?,
            terminal_old_block_id: cursor.array()?,
            terminal_old_height: u64::from_be_bytes(cursor.array()?),
            first_new_epoch_block_id: cursor.array()?,
            first_new_epoch_height: u64::from_be_bytes(cursor.array()?),
            first_new_epoch_state_root: cursor.array()?,
            observed_new_epoch_tip_block_id: cursor.array()?,
            observed_new_epoch_tip_height: u64::from_be_bytes(cursor.array()?),
            observed_new_epoch_tip_view: u64::from_be_bytes(cursor.array()?),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Common evidence statement signed independently by every old and new
/// validator. Set descriptor SHA-256 values are over exact canonical CEV0 set
/// bytes and therefore bind each consensus key and voting power.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochHandoffEvidenceBodyV1 {
    campaign: CommonCampaignContextV1,
    fleet_start_certificate_sha256: [u8; 32],
    new_epoch_deployment_manifest_sha256: [u8; 32],
    old_epoch: u64,
    new_epoch: u64,
    old_validator_set_id: [u8; 32],
    old_validator_set_descriptor_sha256: [u8; 32],
    new_validator_set_id: [u8; 32],
    new_validator_set_descriptor_sha256: [u8; 32],
    old_cut: EpochHandoffOldCutV1,
    transition: EpochHandoffVerifiedTransitionBindingV1,
}

impl EpochHandoffEvidenceBodyV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaign: CommonCampaignContextV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        new_epoch_deployment_manifest_sha256: [u8; 32],
        old_cut: EpochHandoffOldCutV1,
        observation: &PocoNodeLabVerifiedEpochTransitionObservationV0,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        Self::new_from_projection(
            campaign,
            fleet_start_certificate,
            new_epoch_deployment_manifest_sha256,
            old_cut,
            TransitionObservationProjectionV1::from_node(observation),
            old_validator_set,
            new_validator_set,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_from_projection(
        campaign: CommonCampaignContextV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        new_epoch_deployment_manifest_sha256: [u8; 32],
        old_cut: EpochHandoffOldCutV1,
        observation: TransitionObservationProjectionV1,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        fleet_start_certificate
            .verify(old_validator_set)
            .map_err(|_| EpochHandoffEvidenceErrorV1::InvalidFleetStartCertificate)?;
        if fleet_start_certificate.ready_set().context() != &campaign {
            return Err(EpochHandoffEvidenceErrorV1::WrongCampaign);
        }
        let value = Self {
            fleet_start_certificate_sha256: Sha256::digest(fleet_start_certificate.encode()).into(),
            new_epoch_deployment_manifest_sha256,
            old_epoch: old_validator_set.epoch().get(),
            new_epoch: new_validator_set.epoch().get(),
            old_validator_set_id: *old_validator_set.id().as_bytes(),
            old_validator_set_descriptor_sha256: validator_set_descriptor_sha256(
                old_validator_set,
            )?,
            new_validator_set_id: *new_validator_set.id().as_bytes(),
            new_validator_set_descriptor_sha256: validator_set_descriptor_sha256(
                new_validator_set,
            )?,
            old_cut,
            transition: EpochHandoffVerifiedTransitionBindingV1::from_projection(observation),
            campaign,
        };
        value.validate_for_sets(old_validator_set, new_validator_set)?;
        value.validate_observation(observation)?;
        value.validate_fleet_start_certificate(fleet_start_certificate, old_validator_set)?;
        Ok(value)
    }

    pub const fn campaign(&self) -> &CommonCampaignContextV1 {
        &self.campaign
    }

    pub fn run_id(&self) -> &str {
        self.campaign.identity().run_id()
    }

    pub const fn coordinator_manifest_sha256(&self) -> [u8; 32] {
        self.campaign.identity().coordinator_manifest_sha256()
    }

    pub const fn topology_sha256(&self) -> [u8; 32] {
        self.campaign.identity().topology_sha256()
    }

    pub const fn fleet_start_certificate_sha256(&self) -> [u8; 32] {
        self.fleet_start_certificate_sha256
    }

    pub const fn new_epoch_deployment_manifest_sha256(&self) -> [u8; 32] {
        self.new_epoch_deployment_manifest_sha256
    }

    pub const fn old_epoch(&self) -> u64 {
        self.old_epoch
    }

    pub const fn new_epoch(&self) -> u64 {
        self.new_epoch
    }

    pub const fn old_validator_set_descriptor_sha256(&self) -> [u8; 32] {
        self.old_validator_set_descriptor_sha256
    }

    pub const fn new_validator_set_descriptor_sha256(&self) -> [u8; 32] {
        self.new_validator_set_descriptor_sha256
    }

    pub const fn old_cut(&self) -> EpochHandoffOldCutV1 {
        self.old_cut
    }

    pub const fn transition(&self) -> EpochHandoffVerifiedTransitionBindingV1 {
        self.transition
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_canonical(BODY_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let campaign = self.campaign.encode();
        let mut output = Vec::with_capacity(2048);
        output.extend_from_slice(BODY_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_bytes_u32(&mut output, &campaign);
        output.extend_from_slice(&self.fleet_start_certificate_sha256);
        output.extend_from_slice(&self.new_epoch_deployment_manifest_sha256);
        output.extend_from_slice(&self.old_epoch.to_be_bytes());
        output.extend_from_slice(&self.new_epoch.to_be_bytes());
        output.extend_from_slice(&self.old_validator_set_id);
        output.extend_from_slice(&self.old_validator_set_descriptor_sha256);
        output.extend_from_slice(&self.new_validator_set_id);
        output.extend_from_slice(&self.new_validator_set_descriptor_sha256);
        self.old_cut.encode(&mut output);
        self.transition.encode(&mut output);
        assert!(output.len() <= MAX_BODY_BYTES_V1);
        output
    }

    pub fn decode(
        bytes: &[u8],
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_BODY_BYTES_V1 {
            return Err(EpochHandoffEvidenceErrorV1::TooLarge);
        }
        let mut cursor = EpochEvidenceCursor::new(bytes);
        if cursor.take(8)? != BODY_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(EpochHandoffEvidenceErrorV1::Malformed("body header"));
        }
        let campaign_length = u32::from_be_bytes(cursor.array()?) as usize;
        let campaign = CommonCampaignContextV1::decode(cursor.take(campaign_length)?)
            .map_err(|_| EpochHandoffEvidenceErrorV1::Malformed("campaign context"))?;
        let value = Self {
            campaign,
            fleet_start_certificate_sha256: cursor.array()?,
            new_epoch_deployment_manifest_sha256: cursor.array()?,
            old_epoch: u64::from_be_bytes(cursor.array()?),
            new_epoch: u64::from_be_bytes(cursor.array()?),
            old_validator_set_id: cursor.array()?,
            old_validator_set_descriptor_sha256: cursor.array()?,
            new_validator_set_id: cursor.array()?,
            new_validator_set_descriptor_sha256: cursor.array()?,
            old_cut: EpochHandoffOldCutV1::decode(&mut cursor)?,
            transition: EpochHandoffVerifiedTransitionBindingV1::decode(&mut cursor)?,
        };
        cursor.finish()?;
        value.validate_for_sets(old_validator_set, new_validator_set)?;
        if value.encode() != bytes {
            return Err(EpochHandoffEvidenceErrorV1::NonCanonical);
        }
        Ok(value)
    }

    fn validate_for_sets(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<(), EpochHandoffEvidenceErrorV1> {
        validate_set_transition(&self.campaign, old_validator_set, new_validator_set)?;
        self.old_cut.validate(old_validator_set)?;
        self.transition.validate()?;
        let old_descriptor = validator_set_descriptor_sha256(old_validator_set)?;
        let new_descriptor = validator_set_descriptor_sha256(new_validator_set)?;
        if self.old_epoch != old_validator_set.epoch().get()
            || self.new_epoch != new_validator_set.epoch().get()
            || self.new_epoch
                != self
                    .old_epoch
                    .checked_add(1)
                    .ok_or(EpochHandoffEvidenceErrorV1::Malformed(
                        "epoch direct successor overflow",
                    ))?
            || self.old_validator_set_id != *old_validator_set.id().as_bytes()
            || self.new_validator_set_id != *new_validator_set.id().as_bytes()
            || self.old_validator_set_descriptor_sha256 != old_descriptor
            || self.new_validator_set_descriptor_sha256 != new_descriptor
            || self.campaign.identity().validator_set_sha256() != old_descriptor
            || self.fleet_start_certificate_sha256 == [0; 32]
            || self.new_epoch_deployment_manifest_sha256 == [0; 32]
        {
            return Err(EpochHandoffEvidenceErrorV1::WrongSetTransition);
        }
        Ok(())
    }

    fn validate_observation(
        &self,
        observation: TransitionObservationProjectionV1,
    ) -> Result<(), EpochHandoffEvidenceErrorV1> {
        self.old_cut.validate_observation(observation)?;
        if observation.old_epoch != self.old_epoch
            || observation.new_epoch != self.new_epoch
            || self.transition
                != EpochHandoffVerifiedTransitionBindingV1::from_projection(observation)
        {
            return Err(EpochHandoffEvidenceErrorV1::WrongTransitionObservation);
        }
        Ok(())
    }

    fn validate_fleet_start_certificate(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        old_validator_set: &ValidatorSet,
    ) -> Result<(), EpochHandoffEvidenceErrorV1> {
        fleet_start_certificate
            .verify(old_validator_set)
            .map_err(|_| EpochHandoffEvidenceErrorV1::InvalidFleetStartCertificate)?;
        let raw_sha256: [u8; 32] = Sha256::digest(fleet_start_certificate.encode()).into();
        if fleet_start_certificate.ready_set().context() != &self.campaign
            || raw_sha256 != self.fleet_start_certificate_sha256
        {
            return Err(EpochHandoffEvidenceErrorV1::InvalidFleetStartCertificate);
        }
        Ok(())
    }
}

/// Old/new signer role. Ordering is the canonical certificate ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum EpochHandoffSignerRoleV1 {
    OldEpoch = 1,
    NewEpoch = 2,
}

/// Per-signer signed journal/process profile. The only permitted fault profile
/// is one recovered `epoch_handoff` fault, no active fault, and no other
/// recovered fault. A process-2 report must bind exactly one completed restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochHandoffLocalProcessProfileV1 {
    pub process_instance: u64,
    pub restart_event_count: u64,
    pub restart_completed: bool,
    pub active_fault_count: u32,
    pub other_recovered_fault_count: u32,
    pub epoch_handoff_applied_event_sequence: u64,
    pub epoch_handoff_applied_event_sha256: [u8; 32],
    pub epoch_handoff_recovered_event_sequence: u64,
    pub epoch_handoff_recovered_event_sha256: [u8; 32],
    pub terminal_event_sequence: u64,
    pub terminal_event_sha256: [u8; 32],
    pub journal_head_sequence: u64,
    pub journal_head_sha256: [u8; 32],
}

impl EpochHandoffLocalProcessProfileV1 {
    fn validate(self) -> Result<(), EpochHandoffEvidenceErrorV1> {
        let expected_restart_count = self.process_instance.checked_sub(1);
        if !matches!(self.process_instance, 1 | 2)
            || expected_restart_count != Some(self.restart_event_count)
            || self.restart_completed != (self.process_instance == 2)
            || self.active_fault_count != 0
            || self.other_recovered_fault_count != 0
            || self.epoch_handoff_applied_event_sequence == 0
            || self.epoch_handoff_applied_event_sequence
                >= self.epoch_handoff_recovered_event_sequence
            || self.epoch_handoff_recovered_event_sequence >= self.terminal_event_sequence
            || self.terminal_event_sequence > self.journal_head_sequence
            || [
                self.epoch_handoff_applied_event_sha256,
                self.epoch_handoff_recovered_event_sha256,
                self.terminal_event_sha256,
                self.journal_head_sha256,
            ]
            .contains(&[0; 32])
        {
            return Err(EpochHandoffEvidenceErrorV1::Malformed(
                "process/restart/fault profile",
            ));
        }
        Ok(())
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.process_instance.to_be_bytes());
        output.extend_from_slice(&self.restart_event_count.to_be_bytes());
        output.push(u8::from(self.restart_completed));
        output.extend_from_slice(&self.active_fault_count.to_be_bytes());
        output.extend_from_slice(&self.other_recovered_fault_count.to_be_bytes());
        output.extend_from_slice(&self.epoch_handoff_applied_event_sequence.to_be_bytes());
        output.extend_from_slice(&self.epoch_handoff_applied_event_sha256);
        output.extend_from_slice(&self.epoch_handoff_recovered_event_sequence.to_be_bytes());
        output.extend_from_slice(&self.epoch_handoff_recovered_event_sha256);
        output.extend_from_slice(&self.terminal_event_sequence.to_be_bytes());
        output.extend_from_slice(&self.terminal_event_sha256);
        output.extend_from_slice(&self.journal_head_sequence.to_be_bytes());
        output.extend_from_slice(&self.journal_head_sha256);
    }

    fn decode(cursor: &mut EpochEvidenceCursor<'_>) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        let process_instance = u64::from_be_bytes(cursor.array()?);
        let restart_event_count = u64::from_be_bytes(cursor.array()?);
        let restart_completed = match cursor.byte()? {
            0 => false,
            1 => true,
            _ => return Err(EpochHandoffEvidenceErrorV1::Malformed("restart boolean")),
        };
        let value = Self {
            process_instance,
            restart_event_count,
            restart_completed,
            active_fault_count: u32::from_be_bytes(cursor.array()?),
            other_recovered_fault_count: u32::from_be_bytes(cursor.array()?),
            epoch_handoff_applied_event_sequence: u64::from_be_bytes(cursor.array()?),
            epoch_handoff_applied_event_sha256: cursor.array()?,
            epoch_handoff_recovered_event_sequence: u64::from_be_bytes(cursor.array()?),
            epoch_handoff_recovered_event_sha256: cursor.array()?,
            terminal_event_sequence: u64::from_be_bytes(cursor.array()?),
            terminal_event_sha256: cursor.array()?,
            journal_head_sequence: u64::from_be_bytes(cursor.array()?),
            journal_head_sha256: cursor.array()?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// One role-qualified signed declaration. The config digest is local to this
/// role; old-role configs are rejoined to the FleetStartCertificate, while the
/// new role is bound to the common new deployment-manifest digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEpochHandoffEvidenceStatementV1 {
    role: EpochHandoffSignerRoleV1,
    origin: ValidatorId,
    body: EpochHandoffEvidenceBodyV1,
    config_sha256: [u8; 32],
    process_profile: EpochHandoffLocalProcessProfileV1,
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl SignedEpochHandoffEvidenceStatementV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: EpochHandoffSignerRoleV1,
        origin: ValidatorId,
        body: EpochHandoffEvidenceBodyV1,
        config_sha256: [u8; 32],
        process_profile: EpochHandoffLocalProcessProfileV1,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        key: &SigningKey,
    ) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        let mut value = Self {
            role,
            origin,
            body,
            config_sha256,
            process_profile,
            signature: [0; SIGNATURE_BYTES_V1],
        };
        value.validate_fields(old_validator_set, new_validator_set)?;
        require_role_key(role, origin, old_validator_set, new_validator_set, key)?;
        value.signature = key
            .sign(&hash_canonical(
                STATEMENT_SIGNING_DOMAIN_V1,
                &value.encode_unsigned()?,
            ))
            .to_bytes();
        Ok(value)
    }

    pub const fn role(&self) -> EpochHandoffSignerRoleV1 {
        self.role
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn body(&self) -> &EpochHandoffEvidenceBodyV1 {
        &self.body
    }

    pub const fn config_sha256(&self) -> [u8; 32] {
        self.config_sha256
    }

    pub const fn process_profile(&self) -> EpochHandoffLocalProcessProfileV1 {
        self.process_profile
    }

    pub fn statement_sha256(&self) -> [u8; 32] {
        hash_canonical(STATEMENT_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = self
            .encode_unsigned()
            .expect("validated epoch-handoff statement fits its wire bound");
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn decode(
        bytes: &[u8],
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        if bytes.len() <= SIGNATURE_BYTES_V1 || bytes.len() > MAX_STATEMENT_BYTES_V1 {
            return Err(EpochHandoffEvidenceErrorV1::TooLarge);
        }
        let split = bytes.len() - SIGNATURE_BYTES_V1;
        let unsigned = &bytes[..split];
        let signature: [u8; SIGNATURE_BYTES_V1] = bytes[split..]
            .try_into()
            .map_err(|_| EpochHandoffEvidenceErrorV1::Malformed("signature"))?;
        let mut cursor = EpochEvidenceCursor::new(unsigned);
        if cursor.take(8)? != STATEMENT_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(EpochHandoffEvidenceErrorV1::Malformed("statement header"));
        }
        let role = decode_role(cursor.byte()?)?;
        let origin = cursor.validator_id()?;
        let body_length = u32::from_be_bytes(cursor.array()?) as usize;
        let body = EpochHandoffEvidenceBodyV1::decode(
            cursor.take(body_length)?,
            old_validator_set,
            new_validator_set,
        )?;
        let config_sha256 = cursor.array()?;
        let process_profile = EpochHandoffLocalProcessProfileV1::decode(&mut cursor)?;
        cursor.finish()?;
        let value = Self {
            role,
            origin,
            body,
            config_sha256,
            process_profile,
            signature,
        };
        value.verify(old_validator_set, new_validator_set)?;
        if value.encode() != bytes {
            return Err(EpochHandoffEvidenceErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<(), EpochHandoffEvidenceErrorV1> {
        self.validate_fields(old_validator_set, new_validator_set)?;
        let set = role_set(self.role, old_validator_set, new_validator_set);
        let validator = set
            .validator(self.origin)
            .ok_or(EpochHandoffEvidenceErrorV1::UnknownOrigin)?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .map_err(|_| EpochHandoffEvidenceErrorV1::InvalidSignature)?;
        key.verify_strict(
            &hash_canonical(STATEMENT_SIGNING_DOMAIN_V1, &self.encode_unsigned()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| EpochHandoffEvidenceErrorV1::InvalidSignature)
    }

    fn validate_fields(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<(), EpochHandoffEvidenceErrorV1> {
        self.body
            .validate_for_sets(old_validator_set, new_validator_set)?;
        if role_set(self.role, old_validator_set, new_validator_set)
            .validator(self.origin)
            .is_none()
        {
            return Err(EpochHandoffEvidenceErrorV1::UnknownOrigin);
        }
        if self.config_sha256 == [0; 32] {
            return Err(EpochHandoffEvidenceErrorV1::Malformed("config digest"));
        }
        self.process_profile.validate()
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, EpochHandoffEvidenceErrorV1> {
        let body = self.body.encode();
        let mut output = Vec::with_capacity(body.len() + 512);
        output.extend_from_slice(STATEMENT_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.push(self.role as u8);
        put_validator_id(&mut output, self.origin);
        put_bytes_u32(&mut output, &body);
        output.extend_from_slice(&self.config_sha256);
        self.process_profile.encode(&mut output);
        if output.len() + SIGNATURE_BYTES_V1 > MAX_STATEMENT_BYTES_V1 {
            return Err(EpochHandoffEvidenceErrorV1::TooLarge);
        }
        Ok(output)
    }
}

/// Canonical old-N/N plus new-N/N certificate. The raw certificate is not the
/// verified carrier: a Node-owned transition observation is still required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochHandoffEvidenceCertificateV1 {
    body: EpochHandoffEvidenceBodyV1,
    statements: Vec<SignedEpochHandoffEvidenceStatementV1>,
}

impl EpochHandoffEvidenceCertificateV1 {
    pub fn new(
        statements: Vec<SignedEpochHandoffEvidenceStatementV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        observation: &PocoNodeLabVerifiedEpochTransitionObservationV0,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        let value = Self::from_statements(statements, old_validator_set, new_validator_set)?;
        value.validate_external(
            fleet_start_certificate,
            TransitionObservationProjectionV1::from_node(observation),
            old_validator_set,
            new_validator_set,
        )?;
        Ok(value)
    }

    fn from_statements(
        statements: Vec<SignedEpochHandoffEvidenceStatementV1>,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        let body = statements
            .first()
            .ok_or(EpochHandoffEvidenceErrorV1::Incomplete)?
            .body
            .clone();
        body.validate_for_sets(old_validator_set, new_validator_set)?;
        let mut canonical = BTreeMap::new();
        for statement in statements {
            statement.verify(old_validator_set, new_validator_set)?;
            if statement.body != body {
                return Err(EpochHandoffEvidenceErrorV1::DifferentBody);
            }
            if canonical
                .insert((statement.role, statement.origin), statement)
                .is_some()
            {
                return Err(EpochHandoffEvidenceErrorV1::DuplicateOrigin);
            }
        }
        for (role, set) in [
            (EpochHandoffSignerRoleV1::OldEpoch, old_validator_set),
            (EpochHandoffSignerRoleV1::NewEpoch, new_validator_set),
        ] {
            if set
                .validators()
                .iter()
                .any(|validator| !canonical.contains_key(&(role, validator.id())))
                || canonical
                    .keys()
                    .filter(|(candidate, _)| *candidate == role)
                    .count()
                    != set.validators().len()
            {
                return Err(EpochHandoffEvidenceErrorV1::Incomplete);
            }
        }
        let statements = canonical.into_values().collect::<Vec<_>>();
        let mut new_configs = BTreeSet::new();
        for statement in statements
            .iter()
            .filter(|statement| statement.role == EpochHandoffSignerRoleV1::NewEpoch)
        {
            if !new_configs.insert(statement.config_sha256) {
                return Err(EpochHandoffEvidenceErrorV1::DuplicateNewConfig);
            }
        }
        Ok(Self { body, statements })
    }

    pub const fn body(&self) -> &EpochHandoffEvidenceBodyV1 {
        &self.body
    }

    pub fn statements(&self) -> &[SignedEpochHandoffEvidenceStatementV1] {
        &self.statements
    }

    pub fn statement(
        &self,
        role: EpochHandoffSignerRoleV1,
        origin: ValidatorId,
    ) -> Option<&SignedEpochHandoffEvidenceStatementV1> {
        self.statements
            .binary_search_by_key(&(role, origin), |statement| {
                (statement.role, statement.origin)
            })
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut canonical = Vec::with_capacity(68 + self.statements.len() * 67);
        canonical.extend_from_slice(&self.body.digest());
        canonical.extend_from_slice(
            &u32::try_from(self.statements.len())
                .expect("joint validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in &self.statements {
            canonical.push(statement.role as u8);
            put_validator_id(&mut canonical, statement.origin);
            canonical.extend_from_slice(&statement.statement_sha256());
        }
        hash_canonical(CERTIFICATE_DIGEST_DOMAIN_V1, &canonical)
    }

    pub fn encode(&self) -> Vec<u8> {
        let encoded = self
            .statements
            .iter()
            .map(SignedEpochHandoffEvidenceStatementV1::encode)
            .collect::<Vec<_>>();
        let total = encoded
            .iter()
            .try_fold(8usize + 2 + 4, |size, statement| {
                size.checked_add(4 + statement.len())
            })
            .expect("validated epoch-handoff certificate length does not overflow");
        assert!(total <= MAX_EPOCH_HANDOFF_EVIDENCE_CERTIFICATE_BYTES_V1);
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(CERTIFICATE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.extend_from_slice(
            &u32::try_from(encoded.len())
                .expect("joint validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in encoded {
            put_bytes_u32(&mut output, &statement);
        }
        output
    }

    pub fn decode(
        bytes: &[u8],
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self, EpochHandoffEvidenceErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_EPOCH_HANDOFF_EVIDENCE_CERTIFICATE_BYTES_V1 {
            return Err(EpochHandoffEvidenceErrorV1::TooLarge);
        }
        let expected_count = old_validator_set
            .validators()
            .len()
            .checked_add(new_validator_set.validators().len())
            .ok_or(EpochHandoffEvidenceErrorV1::Capacity)?;
        let mut cursor = EpochEvidenceCursor::new(bytes);
        if cursor.take(8)? != CERTIFICATE_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(EpochHandoffEvidenceErrorV1::Malformed("certificate header"));
        }
        if u32::from_be_bytes(cursor.array()?) as usize != expected_count {
            return Err(EpochHandoffEvidenceErrorV1::Incomplete);
        }
        let mut statements = Vec::with_capacity(expected_count);
        for _ in 0..expected_count {
            let length = u32::from_be_bytes(cursor.array()?) as usize;
            if length == 0 || length > MAX_STATEMENT_BYTES_V1 {
                return Err(EpochHandoffEvidenceErrorV1::TooLarge);
            }
            statements.push(SignedEpochHandoffEvidenceStatementV1::decode(
                cursor.take(length)?,
                old_validator_set,
                new_validator_set,
            )?);
        }
        cursor.finish()?;
        let value = Self::from_statements(statements, old_validator_set, new_validator_set)?;
        if value.encode() != bytes {
            return Err(EpochHandoffEvidenceErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify_owned(
        self,
        fleet_start_certificate: &FleetStartCertificateV1,
        observation: &PocoNodeLabVerifiedEpochTransitionObservationV0,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<VerifiedEpochHandoffEvidenceCertificateV1, EpochHandoffEvidenceErrorV1> {
        self.verify_owned_projection(
            fleet_start_certificate,
            TransitionObservationProjectionV1::from_node(observation),
            old_validator_set,
            new_validator_set,
        )
    }

    fn verify_owned_projection(
        self,
        fleet_start_certificate: &FleetStartCertificateV1,
        observation: TransitionObservationProjectionV1,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<VerifiedEpochHandoffEvidenceCertificateV1, EpochHandoffEvidenceErrorV1> {
        let rebuilt = Self::from_statements(
            self.statements.clone(),
            old_validator_set,
            new_validator_set,
        )?;
        if rebuilt.encode() != self.encode() || rebuilt.body != self.body {
            return Err(EpochHandoffEvidenceErrorV1::NonCanonical);
        }
        self.validate_external(
            fleet_start_certificate,
            observation,
            old_validator_set,
            new_validator_set,
        )?;
        let artifact_sha256 = Sha256::digest(self.encode()).into();
        Ok(VerifiedEpochHandoffEvidenceCertificateV1 {
            certificate: self,
            artifact_sha256,
        })
    }

    fn validate_external(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        observation: TransitionObservationProjectionV1,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<(), EpochHandoffEvidenceErrorV1> {
        self.body
            .validate_for_sets(old_validator_set, new_validator_set)?;
        self.body.validate_observation(observation)?;
        self.body
            .validate_fleet_start_certificate(fleet_start_certificate, old_validator_set)?;
        for statement in self
            .statements
            .iter()
            .filter(|statement| statement.role == EpochHandoffSignerRoleV1::OldEpoch)
        {
            let expected = fleet_start_certificate
                .ready_set()
                .statement(statement.origin)
                .ok_or(EpochHandoffEvidenceErrorV1::Incomplete)?
                .local_cut()
                .config_sha256();
            if statement.config_sha256 != expected {
                return Err(EpochHandoffEvidenceErrorV1::WrongConfig);
            }
        }
        Ok(())
    }
}

/// Non-Clone carrier proving the real Node transition observation, exact raw
/// FleetStartCertificate, old N/N role, new N/N role, configs, process/fault
/// profiles, and common first-new-epoch terminal proof were joined.
///
/// It intentionally grants no operational handoff authority.
#[must_use = "the verified epoch-handoff evidence carrier grants no runtime authority"]
pub struct VerifiedEpochHandoffEvidenceCertificateV1 {
    certificate: EpochHandoffEvidenceCertificateV1,
    artifact_sha256: [u8; 32],
}

impl std::fmt::Debug for VerifiedEpochHandoffEvidenceCertificateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedEpochHandoffEvidenceCertificateV1")
            .field("run_id", &self.certificate.body.run_id())
            .field("old_epoch", &self.certificate.body.old_epoch)
            .field("new_epoch", &self.certificate.body.new_epoch)
            .field("statement_count", &self.certificate.statements.len())
            .field("artifact_sha256", &self.artifact_sha256)
            .field("operational_handoff_authority", &false)
            .finish_non_exhaustive()
    }
}

impl VerifiedEpochHandoffEvidenceCertificateV1 {
    pub const fn certificate(&self) -> &EpochHandoffEvidenceCertificateV1 {
        &self.certificate
    }

    pub const fn artifact_sha256(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub const fn operational_handoff_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransitionObservationProjectionV1 {
    local_checkpoint_generation: u64,
    local_checkpoint_checksum: [u8; 32],
    committed_parent_block_id: [u8; 32],
    committed_parent_height: u64,
    committed_parent_state_root: [u8; 32],
    committed_parent_view: u64,
    committed_parent_timestamp_ms: u64,
    old_epoch: u64,
    new_epoch: u64,
    old_checkpoint_finality_proof_id: [u8; 32],
    handoff_certificate_digest: [u8; 32],
    first_new_epoch_finality_proof_id: [u8; 32],
    terminal_old_block_id: [u8; 32],
    terminal_old_height: u64,
    first_new_epoch_block_id: [u8; 32],
    first_new_epoch_height: u64,
    first_new_epoch_state_root: [u8; 32],
    observed_new_epoch_tip_block_id: [u8; 32],
    observed_new_epoch_tip_height: u64,
    observed_new_epoch_tip_view: u64,
    observation_checksum: [u8; 32],
}

impl TransitionObservationProjectionV1 {
    fn from_node(observation: &PocoNodeLabVerifiedEpochTransitionObservationV0) -> Self {
        Self {
            local_checkpoint_generation: observation.local_checkpoint_generation_v0(),
            local_checkpoint_checksum: observation.local_checkpoint_checksum_v0(),
            committed_parent_block_id: *observation.committed_parent_block_id_v0().as_bytes(),
            committed_parent_height: observation.committed_parent_height_v0().get(),
            committed_parent_state_root: *observation.committed_parent_state_root_v0().as_bytes(),
            committed_parent_view: observation.committed_parent_view_v0().get(),
            committed_parent_timestamp_ms: observation.committed_parent_timestamp_ms_v0(),
            old_epoch: observation.old_epoch_v0().get(),
            new_epoch: observation.new_epoch_v0().get(),
            old_checkpoint_finality_proof_id: *observation
                .old_checkpoint_finality_proof_id_v0()
                .as_bytes(),
            handoff_certificate_digest: *observation.handoff_certificate_digest_v0().as_bytes(),
            first_new_epoch_finality_proof_id: *observation
                .first_new_epoch_finality_proof_id_v0()
                .as_bytes(),
            terminal_old_block_id: *observation.terminal_old_block_id_v0().as_bytes(),
            terminal_old_height: observation.terminal_old_height_v0().get(),
            first_new_epoch_block_id: *observation.first_new_epoch_block_id_v0().as_bytes(),
            first_new_epoch_height: observation.first_new_epoch_height_v0().get(),
            first_new_epoch_state_root: *observation.first_new_epoch_state_root_v0().as_bytes(),
            observed_new_epoch_tip_block_id: *observation
                .observed_new_epoch_tip_block_id_v0()
                .as_bytes(),
            observed_new_epoch_tip_height: observation.observed_new_epoch_tip_height_v0().get(),
            observed_new_epoch_tip_view: observation.observed_new_epoch_tip_view_v0().get(),
            observation_checksum: observation.observation_checksum_v0(),
        }
    }
}

fn validate_set_transition(
    campaign: &CommonCampaignContextV1,
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
) -> Result<(), EpochHandoffEvidenceErrorV1> {
    old_validator_set
        .validate_shape()
        .map_err(|_| EpochHandoffEvidenceErrorV1::WrongSetTransition)?;
    new_validator_set
        .validate_shape()
        .map_err(|_| EpochHandoffEvidenceErrorV1::WrongSetTransition)?;
    let identity = campaign.identity();
    if identity.chain_id() != old_validator_set.chain_id()
        || identity.genesis_hash() != *old_validator_set.genesis_hash().as_bytes()
        || identity.validator_set_id() != *old_validator_set.id().as_bytes()
        || campaign.initial_chain_cut().epoch() != old_validator_set.epoch().get()
        || usize::try_from(identity.validator_count()).ok()
            != Some(old_validator_set.validators().len())
        || old_validator_set.chain_id() != new_validator_set.chain_id()
        || old_validator_set.genesis_hash() != new_validator_set.genesis_hash()
        || old_validator_set.protocol_version() != new_validator_set.protocol_version()
        || new_validator_set.epoch().get()
            != old_validator_set
                .epoch()
                .get()
                .checked_add(1)
                .ok_or(EpochHandoffEvidenceErrorV1::Capacity)?
        || !matches!(old_validator_set.validators().len(), 7 | 31 | 100)
        || !matches!(new_validator_set.validators().len(), 7 | 31 | 100)
    {
        return Err(EpochHandoffEvidenceErrorV1::WrongSetTransition);
    }
    Ok(())
}

fn validator_set_descriptor_sha256(
    validator_set: &ValidatorSet,
) -> Result<[u8; 32], EpochHandoffEvidenceErrorV1> {
    let bytes = validator_set
        .try_cev0_bytes()
        .map_err(|_| EpochHandoffEvidenceErrorV1::WrongSetTransition)?;
    Ok(Sha256::digest(bytes).into())
}

fn role_set<'a>(
    role: EpochHandoffSignerRoleV1,
    old_validator_set: &'a ValidatorSet,
    new_validator_set: &'a ValidatorSet,
) -> &'a ValidatorSet {
    match role {
        EpochHandoffSignerRoleV1::OldEpoch => old_validator_set,
        EpochHandoffSignerRoleV1::NewEpoch => new_validator_set,
    }
}

fn require_role_key(
    role: EpochHandoffSignerRoleV1,
    origin: ValidatorId,
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
    key: &SigningKey,
) -> Result<(), EpochHandoffEvidenceErrorV1> {
    let validator = role_set(role, old_validator_set, new_validator_set)
        .validator(origin)
        .ok_or(EpochHandoffEvidenceErrorV1::UnknownOrigin)?;
    if validator.consensus_key().as_bytes() != &key.verifying_key().to_bytes() {
        return Err(EpochHandoffEvidenceErrorV1::OriginKeyMismatch);
    }
    Ok(())
}

fn decode_role(value: u8) -> Result<EpochHandoffSignerRoleV1, EpochHandoffEvidenceErrorV1> {
    match value {
        1 => Ok(EpochHandoffSignerRoleV1::OldEpoch),
        2 => Ok(EpochHandoffSignerRoleV1::NewEpoch),
        _ => Err(EpochHandoffEvidenceErrorV1::Malformed("signer role")),
    }
}

fn encode_qc_ref(value: QcRef, output: &mut Vec<u8>) {
    output.extend_from_slice(value.qc_digest().as_bytes());
    output.extend_from_slice(&value.epoch().get().to_be_bytes());
    output.extend_from_slice(&value.view().get().to_be_bytes());
    output.extend_from_slice(&value.height().get().to_be_bytes());
    output.extend_from_slice(value.block_id().as_bytes());
    output.extend_from_slice(value.validator_set_id().as_bytes());
}

fn decode_qc_ref(
    cursor: &mut EpochEvidenceCursor<'_>,
) -> Result<QcRef, EpochHandoffEvidenceErrorV1> {
    Ok(QcRef::new(
        trnm_consensus_types::CertificateId::new(cursor.array()?),
        trnm_consensus_types::Epoch::new(u64::from_be_bytes(cursor.array()?)),
        trnm_consensus_types::View::new(u64::from_be_bytes(cursor.array()?)),
        trnm_consensus_types::Height::new(u64::from_be_bytes(cursor.array()?)),
        trnm_consensus_types::BlockId::new(cursor.array()?),
        trnm_consensus_types::ValidatorSetId::new(cursor.array()?),
    ))
}

fn hash_canonical(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    hasher.finalize().into()
}

fn put_bytes_u32(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("bounded epoch-handoff field fits u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn put_validator_id(output: &mut Vec<u8>, value: ValidatorId) {
    output.extend_from_slice(
        &u16::try_from(value.as_bytes().len())
            .expect("validated ValidatorId fits u16")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}

struct EpochEvidenceCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> EpochEvidenceCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], EpochHandoffEvidenceErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EpochHandoffEvidenceErrorV1::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(EpochHandoffEvidenceErrorV1::Malformed("truncated payload"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], EpochHandoffEvidenceErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| EpochHandoffEvidenceErrorV1::Malformed("array"))
    }

    fn byte(&mut self) -> Result<u8, EpochHandoffEvidenceErrorV1> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(EpochHandoffEvidenceErrorV1::Malformed("byte"))
    }

    fn validator_id(&mut self) -> Result<ValidatorId, EpochHandoffEvidenceErrorV1> {
        let length = u16::from_be_bytes(self.array()?) as usize;
        ValidatorId::from_bytes(self.take(length)?)
            .map_err(|_| EpochHandoffEvidenceErrorV1::Malformed("validator ID"))
    }

    fn finish(self) -> Result<(), EpochHandoffEvidenceErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(EpochHandoffEvidenceErrorV1::Malformed("trailing payload"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochHandoffEvidenceErrorV1 {
    Malformed(&'static str),
    TooLarge,
    Capacity,
    WrongCampaign,
    WrongSetTransition,
    WrongTransitionObservation,
    InvalidFleetStartCertificate,
    UnknownOrigin,
    OriginKeyMismatch,
    InvalidSignature,
    WrongConfig,
    DuplicateNewConfig,
    DuplicateOrigin,
    Incomplete,
    DifferentBody,
    NonCanonical,
}

impl std::fmt::Display for EpochHandoffEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(field) => write!(formatter, "malformed epoch-handoff field: {field}"),
            Self::TooLarge => formatter.write_str("epoch-handoff evidence crosses its bound"),
            Self::Capacity => formatter.write_str("epoch-handoff evidence arithmetic overflow"),
            Self::WrongCampaign => formatter.write_str("epoch-handoff campaign differs"),
            Self::WrongSetTransition => {
                formatter.write_str("epoch-handoff old/new set transition differs")
            }
            Self::WrongTransitionObservation => formatter
                .write_str("epoch-handoff Node transition observation does not match evidence"),
            Self::InvalidFleetStartCertificate => {
                formatter.write_str("epoch-handoff FleetStartCertificate binding is invalid")
            }
            Self::UnknownOrigin => {
                formatter.write_str("epoch-handoff role signer is outside its validator set")
            }
            Self::OriginKeyMismatch => {
                formatter.write_str("epoch-handoff signing key differs from role origin")
            }
            Self::InvalidSignature => {
                formatter.write_str("epoch-handoff evidence signature is invalid")
            }
            Self::WrongConfig => {
                formatter.write_str("epoch-handoff old-role config differs from fleet start")
            }
            Self::DuplicateNewConfig => {
                formatter.write_str("epoch-handoff new-role config digest is duplicated")
            }
            Self::DuplicateOrigin => formatter.write_str("epoch-handoff role/origin is duplicated"),
            Self::Incomplete => {
                formatter.write_str("epoch-handoff certificate is not old-N/N plus new-N/N")
            }
            Self::DifferentBody => {
                formatter.write_str("epoch-handoff statements do not converge on one body")
            }
            Self::NonCanonical => formatter.write_str("epoch-handoff wire is non-canonical"),
        }
    }
}

impl std::error::Error for EpochHandoffEvidenceErrorV1 {}

#[cfg(test)]
mod tests {
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, Height,
        ProtocolVersion, Validator, View, VotingPower,
    };

    use crate::fleet_barrier::{
        CommonChainCutV1, FleetBarrierTransportV1, FleetCampaignCapacitiesV1,
        FleetCampaignIdentityV1, FleetCampaignRequestV1, FleetMeshSessionDirectionV1,
        FleetMeshSessionSetV1, FleetMeshSessionV1, FleetReadySetV1, LocalReadyCutV1,
        SignedFleetReadyV1, SignedFleetStartV1,
    };

    use super::*;

    struct Fixture {
        old_set: ValidatorSet,
        old_keys: Vec<SigningKey>,
        new_set: ValidatorSet,
        new_keys: Vec<SigningKey>,
        campaign: CommonCampaignContextV1,
        start: FleetStartCertificateV1,
        projection: TransitionObservationProjectionV1,
        body: EpochHandoffEvidenceBodyV1,
    }

    fn validator_set(epoch: u64, id_salt: u8, key_salt: u8) -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0..7)
            .map(|index| SigningKey::from_bytes(&[key_salt + index; 32]))
            .collect::<Vec<_>>();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([id_salt + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        (
            ValidatorSet::new(
                GenesisHash::new([0x21; 32]),
                ChainId::new("trnm-poco-g3-epoch-evidence-test").unwrap(),
                ProtocolVersion::V0,
                Epoch::new(epoch),
                parameters.hash(),
                validators,
            )
            .unwrap(),
            keys,
        )
    }

    fn campaign(set: &ValidatorSet) -> CommonCampaignContextV1 {
        CommonCampaignContextV1::new(
            FleetCampaignIdentityV1::new(
                "poco-g3-7-20260814T000000Z-91abcdef".to_owned(),
                set.chain_id(),
                *set.genesis_hash().as_bytes(),
                *set.id().as_bytes(),
                validator_set_descriptor_sha256(set).unwrap(),
                [0x42; 32],
                [0x43; 32],
                [0x44; 32],
                [0x45; 32],
                [0x46; 32],
                [0x47; 32],
                7,
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
                3,
                4,
                set.epoch().get(),
                [0x50; 32],
                3,
                3,
                [0x51; 32],
                1,
                [0x52; 32],
                3,
                [0x53; 32],
                3,
                [0x53; 32],
                [0x54; 32],
                5,
                2,
                5,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn mesh_and_local_cut(
        set: &ValidatorSet,
        index: usize,
    ) -> (FleetMeshSessionSetV1, LocalReadyCutV1) {
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
        let cut = LocalReadyCutV1::new(
            local,
            [0x61 + u8::try_from(index).unwrap(); 32],
            1,
            10 + u64::try_from(index).unwrap(),
            [0x71 + u8::try_from(index).unwrap(); 32],
            &mesh,
            [0x91 + u8::try_from(index).unwrap(); 32],
            [0xa1 + u8::try_from(index).unwrap(); 32],
            [0xb1 + u8::try_from(index).unwrap(); 32],
            [0xc1 + u8::try_from(index).unwrap(); 32],
        )
        .unwrap();
        (mesh, cut)
    }

    fn fleet_start(
        set: &ValidatorSet,
        keys: &[SigningKey],
        campaign: &CommonCampaignContextV1,
    ) -> FleetStartCertificateV1 {
        let ready = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let (mesh, cut) = mesh_and_local_cut(set, index);
                SignedFleetReadyV1::new(campaign.clone(), cut, mesh, set, key).unwrap()
            })
            .collect::<Vec<_>>();
        let ready_set = FleetReadySetV1::new(campaign.clone(), ready.clone(), set).unwrap();
        let starts = ready
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (ready, key))| {
                SignedFleetStartV1::new(
                    ready,
                    &ready_set,
                    ready.local_cut().pre_ready_journal_sequence() + 1,
                    [0xd0 + u8::try_from(index).unwrap(); 32],
                    set,
                    key,
                )
                .unwrap()
            })
            .collect();
        FleetStartCertificateV1::new(ready_set, starts, set).unwrap()
    }

    fn projection() -> TransitionObservationProjectionV1 {
        TransitionObservationProjectionV1 {
            local_checkpoint_generation: 12,
            local_checkpoint_checksum: [0x62; 32],
            committed_parent_block_id: [0x63; 32],
            committed_parent_height: 98,
            committed_parent_state_root: [0x64; 32],
            committed_parent_view: 120,
            committed_parent_timestamp_ms: 1_700_000_000_000,
            old_epoch: 0,
            new_epoch: 1,
            old_checkpoint_finality_proof_id: [0x65; 32],
            handoff_certificate_digest: [0x66; 32],
            first_new_epoch_finality_proof_id: [0x67; 32],
            terminal_old_block_id: [0x68; 32],
            terminal_old_height: 100,
            first_new_epoch_block_id: [0x69; 32],
            first_new_epoch_height: 101,
            first_new_epoch_state_root: [0x6a; 32],
            observed_new_epoch_tip_block_id: [0x6b; 32],
            observed_new_epoch_tip_height: 103,
            observed_new_epoch_tip_view: 4,
            observation_checksum: [0x6c; 32],
        }
    }

    fn old_cut(old_set: &ValidatorSet) -> EpochHandoffOldCutV1 {
        EpochHandoffOldCutV1 {
            current_view: 123,
            finalized_view: 120,
            finalized_height: 98,
            finalized_block_id: [0x63; 32],
            application_height: 98,
            application_block_id: [0x63; 32],
            application_state_root: [0x64; 32],
            checkpoint_generation: 12,
            checkpoint_checksum: [0x62; 32],
            high_qc: QcRef::new(
                trnm_consensus_types::CertificateId::new([0x6d; 32]),
                old_set.epoch(),
                View::new(122),
                Height::new(100),
                BlockId::new([0x68; 32]),
                old_set.id(),
            ),
        }
    }

    fn fixture() -> Fixture {
        let (old_set, old_keys) = validator_set(0, 0x10, 0x30);
        let (new_set, new_keys) = validator_set(1, 0x80, 0xa0);
        let campaign = campaign(&old_set);
        let start = fleet_start(&old_set, &old_keys, &campaign);
        let projection = projection();
        let body = EpochHandoffEvidenceBodyV1::new_from_projection(
            campaign.clone(),
            &start,
            [0x70; 32],
            old_cut(&old_set),
            projection,
            &old_set,
            &new_set,
        )
        .unwrap();
        Fixture {
            old_set,
            old_keys,
            new_set,
            new_keys,
            campaign,
            start,
            projection,
            body,
        }
    }

    fn process_profile(index: usize) -> EpochHandoffLocalProcessProfileV1 {
        let process_instance = if index % 3 == 0 { 2 } else { 1 };
        let salt = u8::try_from(index).unwrap();
        EpochHandoffLocalProcessProfileV1 {
            process_instance,
            restart_event_count: process_instance - 1,
            restart_completed: process_instance == 2,
            active_fault_count: 0,
            other_recovered_fault_count: 0,
            epoch_handoff_applied_event_sequence: 20 + u64::try_from(index).unwrap(),
            epoch_handoff_applied_event_sha256: [0x20 + salt; 32],
            epoch_handoff_recovered_event_sequence: 30 + u64::try_from(index).unwrap(),
            epoch_handoff_recovered_event_sha256: [0x40 + salt; 32],
            terminal_event_sequence: 40 + u64::try_from(index).unwrap(),
            terminal_event_sha256: [0x60 + salt; 32],
            journal_head_sequence: 41 + u64::try_from(index).unwrap(),
            journal_head_sha256: [0x80 + salt; 32],
        }
    }

    fn statements(fixture: &Fixture) -> Vec<SignedEpochHandoffEvidenceStatementV1> {
        let mut statements = Vec::new();
        for (index, key) in fixture.old_keys.iter().enumerate() {
            let origin = fixture.old_set.validators()[index].id();
            let config = fixture
                .start
                .ready_set()
                .statement(origin)
                .unwrap()
                .local_cut()
                .config_sha256();
            statements.push(
                SignedEpochHandoffEvidenceStatementV1::new(
                    EpochHandoffSignerRoleV1::OldEpoch,
                    origin,
                    fixture.body.clone(),
                    config,
                    process_profile(index),
                    &fixture.old_set,
                    &fixture.new_set,
                    key,
                )
                .unwrap(),
            );
        }
        for (index, key) in fixture.new_keys.iter().enumerate() {
            statements.push(
                SignedEpochHandoffEvidenceStatementV1::new(
                    EpochHandoffSignerRoleV1::NewEpoch,
                    fixture.new_set.validators()[index].id(),
                    fixture.body.clone(),
                    [0xe0 + u8::try_from(index).unwrap(); 32],
                    process_profile(7 + index),
                    &fixture.old_set,
                    &fixture.new_set,
                    key,
                )
                .unwrap(),
            );
        }
        statements
    }

    #[test]
    fn changed_membership_and_keys_roundtrip_as_joint_n_of_n_evidence() {
        let fixture = fixture();
        assert!(fixture
            .old_set
            .validators()
            .iter()
            .all(|old| fixture.new_set.validator(old.id()).is_none()));
        let statements = statements(&fixture);
        for statement in &statements {
            assert_eq!(
                SignedEpochHandoffEvidenceStatementV1::decode(
                    &statement.encode(),
                    &fixture.old_set,
                    &fixture.new_set,
                )
                .unwrap(),
                *statement
            );
        }
        let certificate = EpochHandoffEvidenceCertificateV1::from_statements(
            statements.into_iter().rev().collect(),
            &fixture.old_set,
            &fixture.new_set,
        )
        .unwrap();
        assert_eq!(certificate.statements().len(), 14);
        assert_eq!(certificate.body().old_epoch(), 0);
        assert_eq!(certificate.body().new_epoch(), 1);
        let encoded = certificate.encode();
        let decoded =
            EpochHandoffEvidenceCertificateV1::decode(&encoded, &fixture.old_set, &fixture.new_set)
                .unwrap();
        assert_eq!(decoded, certificate);
        let verified = decoded
            .verify_owned_projection(
                &fixture.start,
                fixture.projection,
                &fixture.old_set,
                &fixture.new_set,
            )
            .unwrap();
        assert!(!verified.operational_handoff_authority());
        assert_eq!(
            verified.artifact_sha256(),
            <[u8; 32]>::from(Sha256::digest(&encoded))
        );
    }

    #[test]
    fn role_inventory_signature_and_key_mismatch_fail_closed() {
        let fixture = fixture();
        let canonical = statements(&fixture);
        assert_eq!(
            EpochHandoffEvidenceCertificateV1::from_statements(
                canonical[..13].to_vec(),
                &fixture.old_set,
                &fixture.new_set,
            ),
            Err(EpochHandoffEvidenceErrorV1::Incomplete)
        );
        let mut duplicate = canonical.clone();
        duplicate[13] = duplicate[7].clone();
        assert_eq!(
            EpochHandoffEvidenceCertificateV1::from_statements(
                duplicate,
                &fixture.old_set,
                &fixture.new_set,
            ),
            Err(EpochHandoffEvidenceErrorV1::DuplicateOrigin)
        );
        assert_eq!(
            SignedEpochHandoffEvidenceStatementV1::new(
                EpochHandoffSignerRoleV1::NewEpoch,
                fixture.new_set.validators()[0].id(),
                fixture.body.clone(),
                [0xee; 32],
                process_profile(8),
                &fixture.old_set,
                &fixture.new_set,
                &fixture.old_keys[0],
            ),
            Err(EpochHandoffEvidenceErrorV1::OriginKeyMismatch)
        );
        let mut corrupted = canonical[0].encode();
        *corrupted.last_mut().unwrap() ^= 1;
        assert_eq!(
            SignedEpochHandoffEvidenceStatementV1::decode(
                &corrupted,
                &fixture.old_set,
                &fixture.new_set,
            ),
            Err(EpochHandoffEvidenceErrorV1::InvalidSignature)
        );
    }

    #[test]
    fn epoch_successor_set_descriptor_and_transition_owner_join_fail_closed() {
        let fixture = fixture();
        let (epoch_two, _) = validator_set(2, 0x80, 0xa0);
        assert_eq!(
            EpochHandoffEvidenceBodyV1::new_from_projection(
                fixture.campaign.clone(),
                &fixture.start,
                [0x70; 32],
                old_cut(&fixture.old_set),
                fixture.projection,
                &fixture.old_set,
                &epoch_two,
            ),
            Err(EpochHandoffEvidenceErrorV1::WrongSetTransition)
        );

        let certificate = EpochHandoffEvidenceCertificateV1::from_statements(
            statements(&fixture),
            &fixture.old_set,
            &fixture.new_set,
        )
        .unwrap();
        let mut foreign_observation = fixture.projection;
        foreign_observation.observation_checksum = [0xff; 32];
        assert_eq!(
            certificate
                .verify_owned_projection(
                    &fixture.start,
                    foreign_observation,
                    &fixture.old_set,
                    &fixture.new_set,
                )
                .unwrap_err(),
            EpochHandoffEvidenceErrorV1::WrongTransitionObservation
        );
    }

    #[test]
    fn exact_body_config_and_process_fault_profile_fail_closed() {
        let fixture = fixture();
        let mut divergent = statements(&fixture);
        let mut different_cut = old_cut(&fixture.old_set);
        different_cut.current_view += 1;
        let different_body = EpochHandoffEvidenceBodyV1::new_from_projection(
            fixture.campaign.clone(),
            &fixture.start,
            [0x70; 32],
            different_cut,
            fixture.projection,
            &fixture.old_set,
            &fixture.new_set,
        )
        .unwrap();
        divergent[0] = SignedEpochHandoffEvidenceStatementV1::new(
            EpochHandoffSignerRoleV1::OldEpoch,
            fixture.old_set.validators()[0].id(),
            different_body,
            divergent[0].config_sha256(),
            process_profile(0),
            &fixture.old_set,
            &fixture.new_set,
            &fixture.old_keys[0],
        )
        .unwrap();
        assert_eq!(
            EpochHandoffEvidenceCertificateV1::from_statements(
                divergent,
                &fixture.old_set,
                &fixture.new_set,
            ),
            Err(EpochHandoffEvidenceErrorV1::DifferentBody)
        );

        let mut wrong_config = statements(&fixture);
        wrong_config[2] = SignedEpochHandoffEvidenceStatementV1::new(
            EpochHandoffSignerRoleV1::OldEpoch,
            fixture.old_set.validators()[2].id(),
            fixture.body.clone(),
            [0xff; 32],
            process_profile(2),
            &fixture.old_set,
            &fixture.new_set,
            &fixture.old_keys[2],
        )
        .unwrap();
        let certificate = EpochHandoffEvidenceCertificateV1::from_statements(
            wrong_config,
            &fixture.old_set,
            &fixture.new_set,
        )
        .unwrap();
        assert_eq!(
            certificate
                .verify_owned_projection(
                    &fixture.start,
                    fixture.projection,
                    &fixture.old_set,
                    &fixture.new_set,
                )
                .unwrap_err(),
            EpochHandoffEvidenceErrorV1::WrongConfig
        );

        let mut invalid_profile = process_profile(1);
        invalid_profile.active_fault_count = 1;
        assert_eq!(
            SignedEpochHandoffEvidenceStatementV1::new(
                EpochHandoffSignerRoleV1::OldEpoch,
                fixture.old_set.validators()[1].id(),
                fixture.body,
                [0xee; 32],
                invalid_profile,
                &fixture.old_set,
                &fixture.new_set,
                &fixture.old_keys[1],
            ),
            Err(EpochHandoffEvidenceErrorV1::Malformed(
                "process/restart/fault profile"
            ))
        );
    }

    #[test]
    fn duplicate_new_config_noncanonical_order_and_trailing_wire_fail_closed() {
        let fixture = fixture();
        let mut duplicate_config = statements(&fixture);
        let repeated = duplicate_config[7].config_sha256();
        duplicate_config[8] = SignedEpochHandoffEvidenceStatementV1::new(
            EpochHandoffSignerRoleV1::NewEpoch,
            fixture.new_set.validators()[1].id(),
            fixture.body.clone(),
            repeated,
            process_profile(8),
            &fixture.old_set,
            &fixture.new_set,
            &fixture.new_keys[1],
        )
        .unwrap();
        assert_eq!(
            EpochHandoffEvidenceCertificateV1::from_statements(
                duplicate_config,
                &fixture.old_set,
                &fixture.new_set,
            ),
            Err(EpochHandoffEvidenceErrorV1::DuplicateNewConfig)
        );

        let canonical = statements(&fixture);
        let certificate = EpochHandoffEvidenceCertificateV1::from_statements(
            canonical.clone(),
            &fixture.old_set,
            &fixture.new_set,
        )
        .unwrap();
        let mut noncanonical = Vec::new();
        noncanonical.extend_from_slice(CERTIFICATE_MAGIC_V1);
        noncanonical.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        noncanonical.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
        for statement in canonical.iter().rev() {
            put_bytes_u32(&mut noncanonical, &statement.encode());
        }
        assert_eq!(
            EpochHandoffEvidenceCertificateV1::decode(
                &noncanonical,
                &fixture.old_set,
                &fixture.new_set,
            ),
            Err(EpochHandoffEvidenceErrorV1::NonCanonical)
        );

        let mut trailing = certificate.encode();
        trailing.push(0);
        assert_eq!(
            EpochHandoffEvidenceCertificateV1::decode(
                &trailing,
                &fixture.old_set,
                &fixture.new_set,
            ),
            Err(EpochHandoffEvidenceErrorV1::Malformed("trailing payload"))
        );
    }
}
