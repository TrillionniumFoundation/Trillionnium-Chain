//! Signed, inert evidence for one bounded-delay/loss degradation window.
//!
//! This Phase-D1 contract deliberately does not inject a fault, drive the
//! runtime, append a journal event, or claim that a fault campaign ran.  It
//! only gives an independent verifier a canonical way to join:
//!
//! - the exact G3 campaign and raw N/N FleetStartCertificate artifact;
//! - one content-addressed delay/loss target, window, and generation;
//! - N/N process-1, restart-free journal-head attestations;
//! - threshold timeout authority inside that common window; and
//! - one exact terminal finalized cut signed by every validator.
//!
//! A validator may contribute either its own fully verified TimeoutVote, a
//! fully verified TC that it observed, or no timeout artifact.  A local vote
//! proves only its own author.  An observed TC may be reported by any member
//! because the embedded certificate independently authenticates its quorum.
//! The N/N certificate is accepted only when either one TC is present or the
//! local TimeoutVotes for one exact view carry quorum voting power.  Thus N/N
//! terminal convergence is not confused with an N/N local-timeout condition.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{TimeoutCertificateV0, TimeoutVote, ValidatorId, ValidatorSet};

use crate::{
    fleet_barrier::{CommonCampaignContextV1, FleetStartCertificateV1},
    wire::{
        decode_timeout_certificate_trusted_local_v0, decode_timeout_vote_trusted_local_v0,
        encode_timeout_certificate, encode_timeout_vote,
    },
};

const WINDOW_MAGIC_V1: &[u8; 8] = b"TRNMDWC1";
const STATEMENT_MAGIC_V1: &[u8; 8] = b"TRNMDWS1";
const CERTIFICATE_MAGIC_V1: &[u8; 8] = b"TRNMDWN1";
const WIRE_VERSION_V1: u16 = 1;
const SIGNING_DOMAIN_V1: &[u8] = b"trnm.poco-g3.bounded-delay-loss.statement.v1";
const STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.bounded-delay-loss.statement-digest.v1";
const CERTIFICATE_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.bounded-delay-loss.certificate.v1";
const FAULT_KIND_BOUNDED_DELAY_LOSS_V1: u8 = 1;
const SIGNATURE_BYTES_V1: usize = 64;
const MAX_CONTEXT_BYTES_V1: usize = 16 * 1024;
const MAX_TIMEOUT_ARTIFACT_BYTES_V1: usize = 512 * 1024;
const MAX_STATEMENT_BYTES_V1: usize = 640 * 1024;
pub const MAX_DEGRADED_WINDOW_CERTIFICATE_BYTES_V1: usize = 64 * 1024 * 1024;

/// One exact finalized observation.  The start and recovery cuts need not be
/// converged across independently collected reports outside this certificate;
/// inside this protocol they are deliberately common signed window facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DegradedWindowFinalizedCutV1 {
    pub view: u64,
    pub finalized_height: u64,
    pub finalized_block_id: [u8; 32],
    pub finalized_state_root: [u8; 32],
    pub finalized_chain_root: [u8; 32],
}

impl DegradedWindowFinalizedCutV1 {
    fn validate(self) -> Result<(), DegradedWindowErrorV1> {
        if self.view == 0
            || self.finalized_height == 0
            || [
                self.finalized_block_id,
                self.finalized_state_root,
                self.finalized_chain_root,
            ]
            .contains(&[0; 32])
        {
            return Err(DegradedWindowErrorV1::Malformed("finalized cut"));
        }
        Ok(())
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.view.to_be_bytes());
        output.extend_from_slice(&self.finalized_height.to_be_bytes());
        output.extend_from_slice(&self.finalized_block_id);
        output.extend_from_slice(&self.finalized_state_root);
        output.extend_from_slice(&self.finalized_chain_root);
    }

    fn decode(cursor: &mut DegradedCursor<'_>) -> Result<Self, DegradedWindowErrorV1> {
        let value = Self {
            view: u64::from_be_bytes(cursor.array()?),
            finalized_height: u64::from_be_bytes(cursor.array()?),
            finalized_block_id: cursor.array()?,
            finalized_state_root: cursor.array()?,
            finalized_chain_root: cursor.array()?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Shared fault/window and terminal-convergence statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedWindowFaultKindV1 {
    BoundedDelayLoss,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedWindowContextV1 {
    campaign: CommonCampaignContextV1,
    fleet_start_certificate_sha256: [u8; 32],
    fault_target_sha256: [u8; 32],
    fault_window_sha256: [u8; 32],
    fault_generation: u64,
    start: DegradedWindowFinalizedCutV1,
    recovery: DegradedWindowFinalizedCutV1,
    terminal: DegradedWindowFinalizedCutV1,
}

impl DegradedWindowContextV1 {
    /// Creates a context only after authenticating the exact raw fleet-start
    /// artifact. `fault_target_sha256` addresses the canonical target manifest
    /// (affected links plus delay/loss parameters), while
    /// `fault_window_sha256` addresses its exact bounded schedule.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaign: CommonCampaignContextV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        fault_target_sha256: [u8; 32],
        fault_window_sha256: [u8; 32],
        fault_generation: u64,
        start: DegradedWindowFinalizedCutV1,
        recovery: DegradedWindowFinalizedCutV1,
        terminal: DegradedWindowFinalizedCutV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        fleet_start_certificate
            .verify(validator_set)
            .map_err(|_| DegradedWindowErrorV1::InvalidFleetStartCertificate)?;
        if fleet_start_certificate.ready_set().context() != &campaign {
            return Err(DegradedWindowErrorV1::WrongCampaign);
        }
        let value = Self {
            campaign,
            fleet_start_certificate_sha256: Sha256::digest(fleet_start_certificate.encode()).into(),
            fault_target_sha256,
            fault_window_sha256,
            fault_generation,
            start,
            recovery,
            terminal,
        };
        value.validate_for_set(validator_set)?;
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

    pub const fn validator_set_id(&self) -> [u8; 32] {
        self.campaign.identity().validator_set_id()
    }

    pub const fn validator_set_sha256(&self) -> [u8; 32] {
        self.campaign.identity().validator_set_sha256()
    }

    pub const fn fleet_start_certificate_sha256(&self) -> [u8; 32] {
        self.fleet_start_certificate_sha256
    }

    pub const fn fault_kind(&self) -> DegradedWindowFaultKindV1 {
        DegradedWindowFaultKindV1::BoundedDelayLoss
    }

    pub const fn fault_target_sha256(&self) -> [u8; 32] {
        self.fault_target_sha256
    }

    pub const fn fault_window_sha256(&self) -> [u8; 32] {
        self.fault_window_sha256
    }

    pub const fn fault_generation(&self) -> u64 {
        self.fault_generation
    }

    pub const fn start(&self) -> DegradedWindowFinalizedCutV1 {
        self.start
    }

    pub const fn recovery(&self) -> DegradedWindowFinalizedCutV1 {
        self.recovery
    }

    pub const fn terminal(&self) -> DegradedWindowFinalizedCutV1 {
        self.terminal
    }

    pub fn encode(&self) -> Vec<u8> {
        let campaign = self.campaign.encode();
        let mut output = Vec::with_capacity(1024);
        output.extend_from_slice(WINDOW_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.push(FAULT_KIND_BOUNDED_DELAY_LOSS_V1);
        put_bytes_u32(&mut output, &campaign);
        output.extend_from_slice(&self.fleet_start_certificate_sha256);
        output.extend_from_slice(&self.fault_target_sha256);
        output.extend_from_slice(&self.fault_window_sha256);
        output.extend_from_slice(&self.fault_generation.to_be_bytes());
        self.start.encode(&mut output);
        self.recovery.encode(&mut output);
        self.terminal.encode(&mut output);
        assert!(output.len() <= MAX_CONTEXT_BYTES_V1);
        output
    }

    pub fn decode(
        bytes: &[u8],
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_CONTEXT_BYTES_V1 {
            return Err(DegradedWindowErrorV1::TooLarge);
        }
        let mut cursor = DegradedCursor::new(bytes);
        if cursor.take(8)? != WINDOW_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
            || cursor.byte()? != FAULT_KIND_BOUNDED_DELAY_LOSS_V1
        {
            return Err(DegradedWindowErrorV1::Malformed("window header"));
        }
        let campaign_length = u32::from_be_bytes(cursor.array()?) as usize;
        let campaign = CommonCampaignContextV1::decode(cursor.take(campaign_length)?)
            .map_err(|_| DegradedWindowErrorV1::Malformed("campaign context"))?;
        let value = Self {
            campaign,
            fleet_start_certificate_sha256: cursor.array()?,
            fault_target_sha256: cursor.array()?,
            fault_window_sha256: cursor.array()?,
            fault_generation: u64::from_be_bytes(cursor.array()?),
            start: DegradedWindowFinalizedCutV1::decode(&mut cursor)?,
            recovery: DegradedWindowFinalizedCutV1::decode(&mut cursor)?,
            terminal: DegradedWindowFinalizedCutV1::decode(&mut cursor)?,
        };
        cursor.finish()?;
        value.validate_for_set(validator_set)?;
        if value.encode() != bytes {
            return Err(DegradedWindowErrorV1::NonCanonical);
        }
        Ok(value)
    }

    fn validate_for_set(&self, validator_set: &ValidatorSet) -> Result<(), DegradedWindowErrorV1> {
        validate_campaign_for_set(&self.campaign, validator_set)?;
        self.start.validate()?;
        self.recovery.validate()?;
        self.terminal.validate()?;
        if self.fleet_start_certificate_sha256 == [0; 32]
            || self.fault_target_sha256 == [0; 32]
            || self.fault_window_sha256 == [0; 32]
            || self.fault_generation == 0
        {
            return Err(DegradedWindowErrorV1::Malformed("window binding"));
        }
        if self.start.view >= self.recovery.view
            || self.recovery.view >= self.terminal.view
            || self.start.finalized_height > self.recovery.finalized_height
            || self.recovery.finalized_height >= self.terminal.finalized_height
            || (self.start.finalized_height == self.recovery.finalized_height
                && (self.start.finalized_block_id != self.recovery.finalized_block_id
                    || self.start.finalized_state_root != self.recovery.finalized_state_root
                    || self.start.finalized_chain_root != self.recovery.finalized_chain_root))
        {
            return Err(DegradedWindowErrorV1::Malformed(
                "fault/recovery/terminal relation",
            ));
        }
        Ok(())
    }

    fn validate_fleet_start_certificate(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), DegradedWindowErrorV1> {
        fleet_start_certificate
            .verify(validator_set)
            .map_err(|_| DegradedWindowErrorV1::InvalidFleetStartCertificate)?;
        let artifact_sha256: [u8; 32] = Sha256::digest(fleet_start_certificate.encode()).into();
        if fleet_start_certificate.ready_set().context() != &self.campaign
            || artifact_sha256 != self.fleet_start_certificate_sha256
        {
            return Err(DegradedWindowErrorV1::InvalidFleetStartCertificate);
        }
        Ok(())
    }
}

/// Exact ordering and head of one validator's process-1 signed runtime
/// journal. The explicit zero restart count prevents process-instance `1`
/// from being interpreted as a sufficient restart-free assertion on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DegradedWindowJournalCutV1 {
    pub process_instance: u64,
    pub restart_event_count: u64,
    pub fault_applied_event_sequence: u64,
    pub fault_applied_event_sha256: [u8; 32],
    pub fault_recovered_event_sequence: u64,
    pub fault_recovered_event_sha256: [u8; 32],
    pub terminal_finalized_event_sequence: u64,
    pub terminal_finalized_event_sha256: [u8; 32],
    pub journal_head_sequence: u64,
    pub journal_head_sha256: [u8; 32],
}

impl DegradedWindowJournalCutV1 {
    fn validate(self) -> Result<(), DegradedWindowErrorV1> {
        if self.process_instance != 1
            || self.restart_event_count != 0
            || self.fault_applied_event_sequence == 0
            || self.fault_applied_event_sequence >= self.fault_recovered_event_sequence
            || self.fault_recovered_event_sequence >= self.terminal_finalized_event_sequence
            || self.terminal_finalized_event_sequence > self.journal_head_sequence
            || [
                self.fault_applied_event_sha256,
                self.fault_recovered_event_sha256,
                self.terminal_finalized_event_sha256,
                self.journal_head_sha256,
            ]
            .contains(&[0; 32])
        {
            return Err(DegradedWindowErrorV1::Malformed("restart-free journal cut"));
        }
        Ok(())
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.process_instance.to_be_bytes());
        output.extend_from_slice(&self.restart_event_count.to_be_bytes());
        output.extend_from_slice(&self.fault_applied_event_sequence.to_be_bytes());
        output.extend_from_slice(&self.fault_applied_event_sha256);
        output.extend_from_slice(&self.fault_recovered_event_sequence.to_be_bytes());
        output.extend_from_slice(&self.fault_recovered_event_sha256);
        output.extend_from_slice(&self.terminal_finalized_event_sequence.to_be_bytes());
        output.extend_from_slice(&self.terminal_finalized_event_sha256);
        output.extend_from_slice(&self.journal_head_sequence.to_be_bytes());
        output.extend_from_slice(&self.journal_head_sha256);
    }

    fn decode(cursor: &mut DegradedCursor<'_>) -> Result<Self, DegradedWindowErrorV1> {
        let value = Self {
            process_instance: u64::from_be_bytes(cursor.array()?),
            restart_event_count: u64::from_be_bytes(cursor.array()?),
            fault_applied_event_sequence: u64::from_be_bytes(cursor.array()?),
            fault_applied_event_sha256: cursor.array()?,
            fault_recovered_event_sequence: u64::from_be_bytes(cursor.array()?),
            fault_recovered_event_sha256: cursor.array()?,
            terminal_finalized_event_sequence: u64::from_be_bytes(cursor.array()?),
            terminal_finalized_event_sha256: cursor.array()?,
            journal_head_sequence: u64::from_be_bytes(cursor.array()?),
            journal_head_sha256: cursor.array()?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedWindowTimeoutAuthorityKindV1 {
    LocalTimeoutVote,
    VerifiedTimeoutCertificate,
}

/// A full consensus artifact plus the exact signed-journal event that observed
/// it. Constructors and decode both run the ordinary strict consensus verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedWindowTimeoutObservationV1 {
    kind: DegradedWindowTimeoutAuthorityKindV1,
    journal_event_sequence: u64,
    journal_event_sha256: [u8; 32],
    timed_out_view: u64,
    authority_id: [u8; 32],
    artifact_sha256: [u8; 32],
    artifact: Vec<u8>,
}

impl DegradedWindowTimeoutObservationV1 {
    pub fn from_local_timeout_vote(
        journal_event_sequence: u64,
        journal_event_sha256: [u8; 32],
        timeout_vote: &TimeoutVote,
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        let artifact = encode_timeout_vote(timeout_vote);
        let verified = decode_timeout_vote_trusted_local_v0(&artifact, validator_set)
            .map_err(|_| DegradedWindowErrorV1::InvalidTimeoutArtifact)?;
        if &verified != timeout_vote {
            return Err(DegradedWindowErrorV1::InvalidTimeoutArtifact);
        }
        let artifact_sha256: [u8; 32] = Sha256::digest(&artifact).into();
        let value = Self {
            kind: DegradedWindowTimeoutAuthorityKindV1::LocalTimeoutVote,
            journal_event_sequence,
            journal_event_sha256,
            timed_out_view: timeout_vote.view().get(),
            authority_id: artifact_sha256,
            artifact_sha256,
            artifact,
        };
        value.validate(validator_set)?;
        Ok(value)
    }

    pub fn from_verified_timeout_certificate(
        journal_event_sequence: u64,
        journal_event_sha256: [u8; 32],
        timeout_certificate: &TimeoutCertificateV0,
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        let artifact = encode_timeout_certificate(timeout_certificate)
            .map_err(|_| DegradedWindowErrorV1::InvalidTimeoutArtifact)?;
        let verified = decode_timeout_certificate_trusted_local_v0(&artifact, validator_set)
            .map_err(|_| DegradedWindowErrorV1::InvalidTimeoutArtifact)?;
        if &verified != timeout_certificate {
            return Err(DegradedWindowErrorV1::InvalidTimeoutArtifact);
        }
        let value = Self {
            kind: DegradedWindowTimeoutAuthorityKindV1::VerifiedTimeoutCertificate,
            journal_event_sequence,
            journal_event_sha256,
            timed_out_view: timeout_certificate.timed_out_view().get(),
            authority_id: *timeout_certificate.id().as_bytes(),
            artifact_sha256: Sha256::digest(&artifact).into(),
            artifact,
        };
        value.validate(validator_set)?;
        Ok(value)
    }

    pub const fn kind(&self) -> DegradedWindowTimeoutAuthorityKindV1 {
        self.kind
    }

    pub const fn journal_event_sequence(&self) -> u64 {
        self.journal_event_sequence
    }

    pub const fn journal_event_sha256(&self) -> [u8; 32] {
        self.journal_event_sha256
    }

    pub const fn timed_out_view(&self) -> u64 {
        self.timed_out_view
    }

    pub const fn authority_id(&self) -> [u8; 32] {
        self.authority_id
    }

    pub const fn artifact_sha256(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub fn artifact(&self) -> &[u8] {
        &self.artifact
    }

    fn local_timeout_author(
        &self,
        validator_set: &ValidatorSet,
    ) -> Result<Option<ValidatorId>, DegradedWindowErrorV1> {
        match self.kind {
            DegradedWindowTimeoutAuthorityKindV1::LocalTimeoutVote => {
                let vote = decode_timeout_vote_trusted_local_v0(&self.artifact, validator_set)
                    .map_err(|_| DegradedWindowErrorV1::InvalidTimeoutArtifact)?;
                Ok(Some(vote.author()))
            }
            DegradedWindowTimeoutAuthorityKindV1::VerifiedTimeoutCertificate => Ok(None),
        }
    }

    fn validate(&self, validator_set: &ValidatorSet) -> Result<(), DegradedWindowErrorV1> {
        if self.journal_event_sequence == 0
            || self.journal_event_sha256 == [0; 32]
            || self.timed_out_view == 0
            || self.authority_id == [0; 32]
            || self.artifact_sha256 == [0; 32]
            || self.artifact.is_empty()
            || self.artifact.len() > MAX_TIMEOUT_ARTIFACT_BYTES_V1
            || <[u8; 32]>::from(Sha256::digest(&self.artifact)) != self.artifact_sha256
        {
            return Err(DegradedWindowErrorV1::InvalidTimeoutArtifact);
        }
        match self.kind {
            DegradedWindowTimeoutAuthorityKindV1::LocalTimeoutVote => {
                let vote = decode_timeout_vote_trusted_local_v0(&self.artifact, validator_set)
                    .map_err(|_| DegradedWindowErrorV1::InvalidTimeoutArtifact)?;
                if vote.view().get() != self.timed_out_view
                    || self.authority_id != self.artifact_sha256
                {
                    return Err(DegradedWindowErrorV1::InvalidTimeoutArtifact);
                }
            }
            DegradedWindowTimeoutAuthorityKindV1::VerifiedTimeoutCertificate => {
                let certificate =
                    decode_timeout_certificate_trusted_local_v0(&self.artifact, validator_set)
                        .map_err(|_| DegradedWindowErrorV1::InvalidTimeoutArtifact)?;
                if certificate.timed_out_view().get() != self.timed_out_view
                    || certificate.id().as_bytes() != &self.authority_id
                {
                    return Err(DegradedWindowErrorV1::InvalidTimeoutArtifact);
                }
            }
        }
        Ok(())
    }

    fn encode(&self, output: &mut Vec<u8>) {
        output.push(match self.kind {
            DegradedWindowTimeoutAuthorityKindV1::LocalTimeoutVote => 1,
            DegradedWindowTimeoutAuthorityKindV1::VerifiedTimeoutCertificate => 2,
        });
        output.extend_from_slice(&self.journal_event_sequence.to_be_bytes());
        output.extend_from_slice(&self.journal_event_sha256);
        output.extend_from_slice(&self.timed_out_view.to_be_bytes());
        output.extend_from_slice(&self.authority_id);
        output.extend_from_slice(&self.artifact_sha256);
        put_bytes_u32(output, &self.artifact);
    }

    fn decode(
        cursor: &mut DegradedCursor<'_>,
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        let kind = match cursor.byte()? {
            1 => DegradedWindowTimeoutAuthorityKindV1::LocalTimeoutVote,
            2 => DegradedWindowTimeoutAuthorityKindV1::VerifiedTimeoutCertificate,
            _ => return Err(DegradedWindowErrorV1::Malformed("timeout authority tag")),
        };
        let journal_event_sequence = u64::from_be_bytes(cursor.array()?);
        let journal_event_sha256 = cursor.array()?;
        let timed_out_view = u64::from_be_bytes(cursor.array()?);
        let authority_id = cursor.array()?;
        let artifact_sha256 = cursor.array()?;
        let artifact_length = u32::from_be_bytes(cursor.array()?) as usize;
        if artifact_length == 0 || artifact_length > MAX_TIMEOUT_ARTIFACT_BYTES_V1 {
            return Err(DegradedWindowErrorV1::TooLarge);
        }
        let value = Self {
            kind,
            journal_event_sequence,
            journal_event_sha256,
            timed_out_view,
            authority_id,
            artifact_sha256,
            artifact: cursor.take(artifact_length)?.to_vec(),
        };
        value.validate(validator_set)?;
        Ok(value)
    }
}

/// One validator's signed view of the common window. `timeout_observation`
/// may be absent; threshold timeout authority is a certificate-level property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDegradedWindowStatementV1 {
    origin: ValidatorId,
    context: DegradedWindowContextV1,
    config_sha256: [u8; 32],
    journal: DegradedWindowJournalCutV1,
    timeout_observation: Option<DegradedWindowTimeoutObservationV1>,
    signature: [u8; SIGNATURE_BYTES_V1],
}

impl SignedDegradedWindowStatementV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin: ValidatorId,
        context: DegradedWindowContextV1,
        config_sha256: [u8; 32],
        journal: DegradedWindowJournalCutV1,
        timeout_observation: Option<DegradedWindowTimeoutObservationV1>,
        validator_set: &ValidatorSet,
        key: &SigningKey,
    ) -> Result<Self, DegradedWindowErrorV1> {
        let mut value = Self {
            origin,
            context,
            config_sha256,
            journal,
            timeout_observation,
            signature: [0; SIGNATURE_BYTES_V1],
        };
        value.validate_fields(validator_set)?;
        require_origin_key(origin, validator_set, key)?;
        let unsigned = value.encode_unsigned()?;
        value.signature = key
            .sign(&hash_canonical(SIGNING_DOMAIN_V1, &unsigned))
            .to_bytes();
        Ok(value)
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn context(&self) -> &DegradedWindowContextV1 {
        &self.context
    }

    pub const fn config_sha256(&self) -> [u8; 32] {
        self.config_sha256
    }

    pub const fn journal(&self) -> DegradedWindowJournalCutV1 {
        self.journal
    }

    pub const fn timeout_observation(&self) -> Option<&DegradedWindowTimeoutObservationV1> {
        self.timeout_observation.as_ref()
    }

    pub fn statement_sha256(&self) -> [u8; 32] {
        hash_canonical(STATEMENT_DIGEST_DOMAIN_V1, &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = self
            .encode_unsigned()
            .expect("validated degraded-window statement fits its wire bound");
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn decode(
        bytes: &[u8],
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        if bytes.len() <= SIGNATURE_BYTES_V1 || bytes.len() > MAX_STATEMENT_BYTES_V1 {
            return Err(DegradedWindowErrorV1::TooLarge);
        }
        let split = bytes.len() - SIGNATURE_BYTES_V1;
        let unsigned = &bytes[..split];
        let signature: [u8; SIGNATURE_BYTES_V1] = bytes[split..]
            .try_into()
            .map_err(|_| DegradedWindowErrorV1::Malformed("signature"))?;
        let mut cursor = DegradedCursor::new(unsigned);
        if cursor.take(8)? != STATEMENT_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(DegradedWindowErrorV1::Malformed("statement header"));
        }
        let origin = cursor.validator_id()?;
        let context_length = u32::from_be_bytes(cursor.array()?) as usize;
        let context = DegradedWindowContextV1::decode(cursor.take(context_length)?, validator_set)?;
        let config_sha256 = cursor.array()?;
        let journal = DegradedWindowJournalCutV1::decode(&mut cursor)?;
        let timeout_observation = match cursor.byte()? {
            0 => None,
            1 => Some(DegradedWindowTimeoutObservationV1::decode(
                &mut cursor,
                validator_set,
            )?),
            _ => return Err(DegradedWindowErrorV1::Malformed("observation presence tag")),
        };
        cursor.finish()?;
        let value = Self {
            origin,
            context,
            config_sha256,
            journal,
            timeout_observation,
            signature,
        };
        value.verify(validator_set)?;
        if value.encode() != bytes {
            return Err(DegradedWindowErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<(), DegradedWindowErrorV1> {
        self.validate_fields(validator_set)?;
        let validator = validator_set
            .validator(self.origin)
            .ok_or(DegradedWindowErrorV1::UnknownOrigin)?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .map_err(|_| DegradedWindowErrorV1::InvalidSignature)?;
        key.verify_strict(
            &hash_canonical(SIGNING_DOMAIN_V1, &self.encode_unsigned()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| DegradedWindowErrorV1::InvalidSignature)
    }

    fn validate_fields(&self, validator_set: &ValidatorSet) -> Result<(), DegradedWindowErrorV1> {
        self.context.validate_for_set(validator_set)?;
        if self.config_sha256 == [0; 32] {
            return Err(DegradedWindowErrorV1::Malformed("config digest"));
        }
        self.journal.validate()?;
        if let Some(observation) = &self.timeout_observation {
            observation.validate(validator_set)?;
            if observation.timed_out_view < self.context.start.view
                || observation.timed_out_view > self.context.recovery.view
                || observation.journal_event_sequence <= self.journal.fault_applied_event_sequence
                || observation.journal_event_sequence > self.journal.fault_recovered_event_sequence
            {
                return Err(DegradedWindowErrorV1::Malformed(
                    "timeout observation outside fault window",
                ));
            }
            if observation
                .local_timeout_author(validator_set)?
                .is_some_and(|author| author != self.origin)
            {
                return Err(DegradedWindowErrorV1::ForeignLocalTimeoutVote);
            }
        }
        Ok(())
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, DegradedWindowErrorV1> {
        let context = self.context.encode();
        let mut output = Vec::with_capacity(context.len() + 512);
        output.extend_from_slice(STATEMENT_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        put_validator_id(&mut output, self.origin);
        put_bytes_u32(&mut output, &context);
        output.extend_from_slice(&self.config_sha256);
        self.journal.encode(&mut output);
        match &self.timeout_observation {
            None => output.push(0),
            Some(observation) => {
                output.push(1);
                observation.encode(&mut output);
            }
        }
        if output.len() + SIGNATURE_BYTES_V1 > MAX_STATEMENT_BYTES_V1 {
            return Err(DegradedWindowErrorV1::TooLarge);
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedWindowThresholdAuthorityV1 {
    LocalTimeoutVotes {
        timed_out_view: u64,
        signed_power: u128,
    },
    TimeoutCertificate {
        timed_out_view: u64,
        certificate_id: [u8; 32],
    },
}

/// Canonical N/N statement bundle. Decode verifies every statement but the
/// non-Clone verified carrier is withheld until the raw fleet-start artifact
/// and all validator-specific config digests are joined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedWindowCertificateV1 {
    context: DegradedWindowContextV1,
    statements: Vec<SignedDegradedWindowStatementV1>,
    threshold_authority: DegradedWindowThresholdAuthorityV1,
}

impl DegradedWindowCertificateV1 {
    pub fn new(
        statements: Vec<SignedDegradedWindowStatementV1>,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        let value = Self::from_statements(statements, validator_set)?;
        value.validate_fleet_and_configs(fleet_start_certificate, validator_set)?;
        Ok(value)
    }

    fn from_statements(
        statements: Vec<SignedDegradedWindowStatementV1>,
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        let context = statements
            .first()
            .ok_or(DegradedWindowErrorV1::Incomplete)?
            .context
            .clone();
        context.validate_for_set(validator_set)?;
        let mut canonical = BTreeMap::new();
        for statement in statements {
            statement.verify(validator_set)?;
            if statement.context != context {
                return Err(DegradedWindowErrorV1::DifferentWindow);
            }
            if canonical.insert(statement.origin, statement).is_some() {
                return Err(DegradedWindowErrorV1::DuplicateOrigin);
            }
        }
        if canonical.len() != validator_set.validators().len()
            || validator_set
                .validators()
                .iter()
                .any(|validator| !canonical.contains_key(&validator.id()))
        {
            return Err(DegradedWindowErrorV1::Incomplete);
        }
        let statements = canonical.into_values().collect::<Vec<_>>();
        let threshold_authority = derive_threshold_authority(&statements, validator_set)?;
        Ok(Self {
            context,
            statements,
            threshold_authority,
        })
    }

    pub const fn context(&self) -> &DegradedWindowContextV1 {
        &self.context
    }

    pub fn statements(&self) -> &[SignedDegradedWindowStatementV1] {
        &self.statements
    }

    pub fn statement(&self, origin: ValidatorId) -> Option<&SignedDegradedWindowStatementV1> {
        self.statements
            .binary_search_by_key(&origin, SignedDegradedWindowStatementV1::origin)
            .ok()
            .and_then(|index| self.statements.get(index))
    }

    pub const fn threshold_authority(&self) -> DegradedWindowThresholdAuthorityV1 {
        self.threshold_authority
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut canonical = Vec::with_capacity(68 + self.statements.len() * 64);
        canonical.extend_from_slice(&hash_canonical(
            b"trnm.poco-g3.bounded-delay-loss.context.v1",
            &self.context.encode(),
        ));
        canonical.extend_from_slice(
            &u32::try_from(self.statements.len())
                .expect("validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in &self.statements {
            put_validator_id(&mut canonical, statement.origin);
            canonical.extend_from_slice(&statement.statement_sha256());
        }
        hash_canonical(CERTIFICATE_DIGEST_DOMAIN_V1, &canonical)
    }

    pub fn encode(&self) -> Vec<u8> {
        let encoded = self
            .statements
            .iter()
            .map(SignedDegradedWindowStatementV1::encode)
            .collect::<Vec<_>>();
        let total = encoded
            .iter()
            .try_fold(8usize + 2 + 4, |size, statement| {
                size.checked_add(4 + statement.len())
            })
            .expect("validated degraded-window certificate length does not overflow");
        assert!(total <= MAX_DEGRADED_WINDOW_CERTIFICATE_BYTES_V1);
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(CERTIFICATE_MAGIC_V1);
        output.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        output.extend_from_slice(
            &u32::try_from(encoded.len())
                .expect("validator count is u32-bound")
                .to_be_bytes(),
        );
        for statement in encoded {
            put_bytes_u32(&mut output, &statement);
        }
        output
    }

    pub fn decode(
        bytes: &[u8],
        validator_set: &ValidatorSet,
    ) -> Result<Self, DegradedWindowErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_DEGRADED_WINDOW_CERTIFICATE_BYTES_V1 {
            return Err(DegradedWindowErrorV1::TooLarge);
        }
        if !matches!(validator_set.validators().len(), 7 | 31 | 100) {
            return Err(DegradedWindowErrorV1::WrongCampaign);
        }
        let mut cursor = DegradedCursor::new(bytes);
        if cursor.take(8)? != CERTIFICATE_MAGIC_V1
            || u16::from_be_bytes(cursor.array()?) != WIRE_VERSION_V1
        {
            return Err(DegradedWindowErrorV1::Malformed("certificate header"));
        }
        let count = u32::from_be_bytes(cursor.array()?) as usize;
        if count != validator_set.validators().len() {
            return Err(DegradedWindowErrorV1::Incomplete);
        }
        let mut statements = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u32::from_be_bytes(cursor.array()?) as usize;
            if length == 0 || length > MAX_STATEMENT_BYTES_V1 {
                return Err(DegradedWindowErrorV1::TooLarge);
            }
            statements.push(SignedDegradedWindowStatementV1::decode(
                cursor.take(length)?,
                validator_set,
            )?);
        }
        cursor.finish()?;
        let value = Self::from_statements(statements, validator_set)?;
        if value.encode() != bytes {
            return Err(DegradedWindowErrorV1::NonCanonical);
        }
        Ok(value)
    }

    pub fn verify_owned(
        self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<VerifiedDegradedWindowCertificateV1, DegradedWindowErrorV1> {
        let rebuilt = Self::from_statements(self.statements.clone(), validator_set)?;
        if rebuilt.encode() != self.encode()
            || rebuilt.context != self.context
            || rebuilt.threshold_authority != self.threshold_authority
        {
            return Err(DegradedWindowErrorV1::NonCanonical);
        }
        self.validate_fleet_and_configs(fleet_start_certificate, validator_set)?;
        let artifact_sha256 = Sha256::digest(self.encode()).into();
        Ok(VerifiedDegradedWindowCertificateV1 {
            certificate: self,
            artifact_sha256,
        })
    }

    pub fn decode_verified(
        bytes: &[u8],
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<VerifiedDegradedWindowCertificateV1, DegradedWindowErrorV1> {
        Self::decode(bytes, validator_set)?.verify_owned(fleet_start_certificate, validator_set)
    }

    fn validate_fleet_and_configs(
        &self,
        fleet_start_certificate: &FleetStartCertificateV1,
        validator_set: &ValidatorSet,
    ) -> Result<(), DegradedWindowErrorV1> {
        self.context
            .validate_fleet_start_certificate(fleet_start_certificate, validator_set)?;
        for statement in &self.statements {
            let expected = fleet_start_certificate
                .ready_set()
                .statement(statement.origin)
                .ok_or(DegradedWindowErrorV1::Incomplete)?
                .local_cut()
                .config_sha256();
            if statement.config_sha256 != expected {
                return Err(DegradedWindowErrorV1::WrongConfig);
            }
        }
        Ok(())
    }
}

/// Non-Clone proof that the exact FleetStartCertificate, N/N restart-free
/// statements, threshold timeout authority, per-validator configs, and common
/// terminal finalized cut have all been authenticated together.
#[must_use = "the verified degraded-window carrier is the complete Phase-D1 join"]
pub struct VerifiedDegradedWindowCertificateV1 {
    certificate: DegradedWindowCertificateV1,
    artifact_sha256: [u8; 32],
}

impl std::fmt::Debug for VerifiedDegradedWindowCertificateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedDegradedWindowCertificateV1")
            .field("run_id", &self.certificate.context.run_id())
            .field(
                "fault_generation",
                &self.certificate.context.fault_generation,
            )
            .field("statement_count", &self.certificate.statements.len())
            .field("threshold_authority", &self.certificate.threshold_authority)
            .field("artifact_sha256", &self.artifact_sha256)
            .finish_non_exhaustive()
    }
}

impl VerifiedDegradedWindowCertificateV1 {
    pub const fn certificate(&self) -> &DegradedWindowCertificateV1 {
        &self.certificate
    }

    pub const fn context(&self) -> &DegradedWindowContextV1 {
        &self.certificate.context
    }

    pub const fn threshold_authority(&self) -> DegradedWindowThresholdAuthorityV1 {
        self.certificate.threshold_authority
    }

    pub const fn artifact_sha256(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub fn into_certificate(self) -> DegradedWindowCertificateV1 {
        self.certificate
    }
}

fn derive_threshold_authority(
    statements: &[SignedDegradedWindowStatementV1],
    validator_set: &ValidatorSet,
) -> Result<DegradedWindowThresholdAuthorityV1, DegradedWindowErrorV1> {
    let mut local_power_by_view = BTreeMap::<u64, u128>::new();
    let mut observed_tc = Vec::<(u64, [u8; 32])>::new();
    for statement in statements {
        let Some(observation) = &statement.timeout_observation else {
            continue;
        };
        match observation.kind {
            DegradedWindowTimeoutAuthorityKindV1::LocalTimeoutVote => {
                let author = observation
                    .local_timeout_author(validator_set)?
                    .ok_or(DegradedWindowErrorV1::InvalidTimeoutArtifact)?;
                if author != statement.origin {
                    return Err(DegradedWindowErrorV1::ForeignLocalTimeoutVote);
                }
                let power = validator_set
                    .power_of(author)
                    .ok_or(DegradedWindowErrorV1::UnknownOrigin)?;
                let accumulated = local_power_by_view
                    .entry(observation.timed_out_view)
                    .or_default();
                *accumulated = accumulated
                    .checked_add(power)
                    .ok_or(DegradedWindowErrorV1::Capacity)?;
            }
            DegradedWindowTimeoutAuthorityKindV1::VerifiedTimeoutCertificate => {
                observed_tc.push((observation.timed_out_view, observation.authority_id));
            }
        }
    }
    observed_tc.sort_unstable();
    let tc = observed_tc.first().copied();
    let local = local_power_by_view
        .into_iter()
        .find(|(_, power)| *power >= validator_set.quorum_power());
    match (tc, local) {
        (Some((tc_view, _certificate_id)), Some((local_view, signed_power)))
            if local_view < tc_view =>
        {
            Ok(DegradedWindowThresholdAuthorityV1::LocalTimeoutVotes {
                timed_out_view: local_view,
                signed_power,
            })
        }
        (Some((timed_out_view, certificate_id)), _) => {
            Ok(DegradedWindowThresholdAuthorityV1::TimeoutCertificate {
                timed_out_view,
                certificate_id,
            })
        }
        (None, Some((timed_out_view, signed_power))) => {
            Ok(DegradedWindowThresholdAuthorityV1::LocalTimeoutVotes {
                timed_out_view,
                signed_power,
            })
        }
        (None, None) => Err(DegradedWindowErrorV1::InsufficientTimeoutAuthority),
    }
}

fn validate_campaign_for_set(
    campaign: &CommonCampaignContextV1,
    validator_set: &ValidatorSet,
) -> Result<(), DegradedWindowErrorV1> {
    let identity = campaign.identity();
    if identity.chain_id() != validator_set.chain_id()
        || identity.genesis_hash() != *validator_set.genesis_hash().as_bytes()
        || identity.validator_set_id() != *validator_set.id().as_bytes()
        || usize::try_from(identity.validator_count()).ok()
            != Some(validator_set.validators().len())
        || !matches!(validator_set.validators().len(), 7 | 31 | 100)
    {
        return Err(DegradedWindowErrorV1::WrongCampaign);
    }
    Ok(())
}

fn require_origin_key(
    origin: ValidatorId,
    validator_set: &ValidatorSet,
    key: &SigningKey,
) -> Result<(), DegradedWindowErrorV1> {
    let validator = validator_set
        .validator(origin)
        .ok_or(DegradedWindowErrorV1::UnknownOrigin)?;
    if validator.consensus_key().as_bytes() != &key.verifying_key().to_bytes() {
        return Err(DegradedWindowErrorV1::OriginKeyMismatch);
    }
    Ok(())
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
            .expect("bounded degraded-window field fits u32")
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

struct DegradedCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DegradedCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DegradedWindowErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DegradedWindowErrorV1::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DegradedWindowErrorV1::Malformed("truncated payload"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DegradedWindowErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| DegradedWindowErrorV1::Malformed("array"))
    }

    fn byte(&mut self) -> Result<u8, DegradedWindowErrorV1> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(DegradedWindowErrorV1::Malformed("byte"))
    }

    fn validator_id(&mut self) -> Result<ValidatorId, DegradedWindowErrorV1> {
        let length = u16::from_be_bytes(self.array()?) as usize;
        ValidatorId::from_bytes(self.take(length)?)
            .map_err(|_| DegradedWindowErrorV1::Malformed("validator ID"))
    }

    fn finish(self) -> Result<(), DegradedWindowErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DegradedWindowErrorV1::Malformed("trailing payload"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradedWindowErrorV1 {
    Malformed(&'static str),
    TooLarge,
    Capacity,
    WrongCampaign,
    WrongConfig,
    UnknownOrigin,
    OriginKeyMismatch,
    InvalidSignature,
    InvalidFleetStartCertificate,
    InvalidTimeoutArtifact,
    ForeignLocalTimeoutVote,
    InsufficientTimeoutAuthority,
    DuplicateOrigin,
    Incomplete,
    DifferentWindow,
    NonCanonical,
}

impl std::fmt::Display for DegradedWindowErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(field) => write!(formatter, "malformed degraded-window field: {field}"),
            Self::TooLarge => formatter.write_str("degraded-window payload crosses its bound"),
            Self::Capacity => formatter.write_str("degraded-window arithmetic crosses its bound"),
            Self::WrongCampaign => formatter.write_str("degraded-window campaign differs"),
            Self::WrongConfig => formatter.write_str("degraded-window config digest differs"),
            Self::UnknownOrigin => {
                formatter.write_str("degraded-window signer is outside validator set")
            }
            Self::OriginKeyMismatch => {
                formatter.write_str("degraded-window key differs from signer")
            }
            Self::InvalidSignature => formatter.write_str("degraded-window signature is invalid"),
            Self::InvalidFleetStartCertificate => {
                formatter.write_str("degraded-window FleetStartCertificate binding is invalid")
            }
            Self::InvalidTimeoutArtifact => {
                formatter.write_str("degraded-window timeout artifact is invalid")
            }
            Self::ForeignLocalTimeoutVote => formatter
                .write_str("degraded-window local TimeoutVote is not authored by its signer"),
            Self::InsufficientTimeoutAuthority => formatter
                .write_str("degraded-window has no same-view quorum TimeoutVotes or verified TC"),
            Self::DuplicateOrigin => formatter.write_str("degraded-window signer is duplicated"),
            Self::Incomplete => formatter.write_str("degraded-window certificate is not N/N"),
            Self::DifferentWindow => formatter
                .write_str("degraded-window statements do not share one exact window/terminal cut"),
            Self::NonCanonical => formatter.write_str("degraded-window wire is non-canonical"),
        }
    }
}

impl std::error::Error for DegradedWindowErrorV1 {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, Height,
        ProtocolVersion, QcRef, SignatureBytes, Validator, View, Vote, VotingPower,
    };

    use crate::{
        collector::ConsensusCertificateCollectorV0,
        fleet_barrier::{
            CommonChainCutV1, FleetBarrierTransportV1, FleetCampaignCapacitiesV1,
            FleetCampaignIdentityV1, FleetCampaignRequestV1, FleetMeshSessionDirectionV1,
            FleetMeshSessionSetV1, FleetMeshSessionV1, FleetReadySetV1, LocalReadyCutV1,
            SignedFleetReadyV1, SignedFleetStartV1,
        },
    };

    use super::*;

    fn validator_fixture() -> (ValidatorSet, Vec<SigningKey>) {
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
            ChainId::new("trnm-poco-g3-degraded-window-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn campaign(set: &ValidatorSet) -> CommonCampaignContextV1 {
        CommonCampaignContextV1::new(
            FleetCampaignIdentityV1::new(
                "poco-g3-7-20260814T000000Z-90abcdef".to_owned(),
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
        let local_cut = LocalReadyCutV1::new(
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
        (mesh, local_cut)
    }

    fn fleet_start_certificate(
        set: &ValidatorSet,
        keys: &[SigningKey],
        campaign: &CommonCampaignContextV1,
        event_salt: u8,
    ) -> FleetStartCertificateV1 {
        let ready = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let (mesh, local_cut) = mesh_and_local_cut(set, index);
                SignedFleetReadyV1::new(campaign.clone(), local_cut, mesh, set, key).unwrap()
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
                    [event_salt + u8::try_from(index).unwrap(); 32],
                    set,
                    key,
                )
                .unwrap()
            })
            .collect();
        FleetStartCertificateV1::new(ready_set, starts, set).unwrap()
    }

    fn cut(view: u64, height: u64, salt: u8) -> DegradedWindowFinalizedCutV1 {
        DegradedWindowFinalizedCutV1 {
            view,
            finalized_height: height,
            finalized_block_id: [salt; 32],
            finalized_state_root: [salt + 1; 32],
            finalized_chain_root: [salt + 2; 32],
        }
    }

    fn context(
        campaign: &CommonCampaignContextV1,
        start: &FleetStartCertificateV1,
        set: &ValidatorSet,
    ) -> DegradedWindowContextV1 {
        DegradedWindowContextV1::new(
            campaign.clone(),
            start,
            [0xd1; 32],
            [0xd2; 32],
            1,
            cut(10, 7, 0x80),
            cut(14, 7, 0x80),
            cut(18, 9, 0x86),
            set,
        )
        .unwrap()
    }

    fn journal(index: usize) -> DegradedWindowJournalCutV1 {
        let salt = u8::try_from(index).unwrap();
        DegradedWindowJournalCutV1 {
            process_instance: 1,
            restart_event_count: 0,
            fault_applied_event_sequence: 20 + u64::try_from(index).unwrap(),
            fault_applied_event_sha256: [0x90 + salt; 32],
            fault_recovered_event_sequence: 30 + u64::try_from(index).unwrap(),
            fault_recovered_event_sha256: [0xa0 + salt; 32],
            terminal_finalized_event_sequence: 40 + u64::try_from(index).unwrap(),
            terminal_finalized_event_sha256: [0xb0 + salt; 32],
            journal_head_sequence: 41 + u64::try_from(index).unwrap(),
            journal_head_sha256: [0xc0 + salt; 32],
        }
    }

    fn high_qc(set: &ValidatorSet) -> QcRef {
        QcRef::new(
            trnm_consensus_types::CertificateId::new([0x70; 32]),
            set.epoch(),
            View::new(9),
            Height::new(7),
            BlockId::new([0x71; 32]),
            set.id(),
        )
    }

    fn timeout_vote(
        set: &ValidatorSet,
        keys: &[SigningKey],
        index: usize,
        view: u64,
    ) -> TimeoutVote {
        let high_qc = high_qc(set);
        let root = TimeoutVote::signing_root_for_set(set, View::new(view), high_qc).unwrap();
        TimeoutVote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            set.id(),
            high_qc,
            set.validators()[index].id(),
            SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
            set,
        )
        .unwrap()
    }

    fn signed_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        start: &FleetStartCertificateV1,
        context: &DegradedWindowContextV1,
        local_timeout_count: usize,
    ) -> Vec<SignedDegradedWindowStatementV1> {
        keys.iter()
            .enumerate()
            .map(|(index, key)| {
                let local_journal = journal(index);
                let observation = (index < local_timeout_count).then(|| {
                    DegradedWindowTimeoutObservationV1::from_local_timeout_vote(
                        local_journal.fault_applied_event_sequence + 1,
                        [0xe0 + u8::try_from(index).unwrap(); 32],
                        &timeout_vote(set, keys, index, 12),
                        set,
                    )
                    .unwrap()
                });
                let origin = set.validators()[index].id();
                let config_sha256 = start
                    .ready_set()
                    .statement(origin)
                    .unwrap()
                    .local_cut()
                    .config_sha256();
                SignedDegradedWindowStatementV1::new(
                    origin,
                    context.clone(),
                    config_sha256,
                    local_journal,
                    observation,
                    set,
                    key,
                )
                .unwrap()
            })
            .collect()
    }

    fn vote(
        set: &ValidatorSet,
        keys: &[SigningKey],
        index: usize,
        view: u64,
        height: u64,
        block_id: BlockId,
    ) -> Vote {
        let root = Vote::signing_root_for_set(set, View::new(view), Height::new(height), block_id)
            .unwrap();
        Vote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            block_id,
            set.id(),
            set.validators()[index].id(),
            SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
            set,
        )
        .unwrap()
    }

    fn timeout_certificate(set: &ValidatorSet, keys: &[SigningKey]) -> TimeoutCertificateV0 {
        let block = BlockId::new([0xf1; 32]);
        let mut collector = ConsensusCertificateCollectorV0::new(set.clone(), 8).unwrap();
        for index in 0..5 {
            collector
                .admit_vote(vote(set, keys, index, 9, 7, block))
                .unwrap();
        }
        let qc = collector
            .try_quorum_certificate(View::new(9), Height::new(7), block)
            .unwrap()
            .unwrap();
        let high_qc = QcRef::from(&qc);
        for index in 0..5 {
            let root = TimeoutVote::signing_root_for_set(set, View::new(13), high_qc).unwrap();
            let timeout = TimeoutVote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(13),
                set.id(),
                high_qc,
                set.validators()[index].id(),
                SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
                set,
            )
            .unwrap();
            collector.admit_timeout_vote(timeout).unwrap();
        }
        collector
            .try_timeout_certificate(View::new(13))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn local_timeout_quorum_roundtrips_into_non_clone_verified_n_of_n_carrier() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let context = context(&campaign, &start, &set);
        let statements = signed_statements(&set, &keys, &start, &context, 5);
        for statement in &statements {
            assert_eq!(
                SignedDegradedWindowStatementV1::decode(&statement.encode(), &set).unwrap(),
                *statement
            );
        }
        let certificate =
            DegradedWindowCertificateV1::new(statements.into_iter().rev().collect(), &start, &set)
                .unwrap();
        assert_eq!(certificate.statements().len(), 7);
        assert_eq!(
            certificate.threshold_authority(),
            DegradedWindowThresholdAuthorityV1::LocalTimeoutVotes {
                timed_out_view: 12,
                signed_power: 5,
            }
        );
        assert_eq!(certificate.context().terminal().finalized_height, 9);
        let encoded = certificate.encode();
        let verified =
            DegradedWindowCertificateV1::decode_verified(&encoded, &start, &set).unwrap();
        assert_eq!(verified.context(), &context);
        assert_eq!(
            verified.artifact_sha256(),
            <[u8; 32]>::from(Sha256::digest(&encoded))
        );
    }

    #[test]
    fn one_verified_tc_can_supply_threshold_while_other_n_minus_one_observations_are_absent() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let context = context(&campaign, &start, &set);
        let mut statements = signed_statements(&set, &keys, &start, &context, 0);
        let tc = timeout_certificate(&set, &keys);
        let local_journal = journal(3);
        let observation = DegradedWindowTimeoutObservationV1::from_verified_timeout_certificate(
            local_journal.fault_applied_event_sequence + 1,
            [0xee; 32],
            &tc,
            &set,
        )
        .unwrap();
        let origin = set.validators()[3].id();
        statements[3] = SignedDegradedWindowStatementV1::new(
            origin,
            context,
            start
                .ready_set()
                .statement(origin)
                .unwrap()
                .local_cut()
                .config_sha256(),
            local_journal,
            Some(observation),
            &set,
            &keys[3],
        )
        .unwrap();
        let certificate = DegradedWindowCertificateV1::new(statements, &start, &set).unwrap();
        assert_eq!(
            certificate.threshold_authority(),
            DegradedWindowThresholdAuthorityV1::TimeoutCertificate {
                timed_out_view: 13,
                certificate_id: *tc.id().as_bytes(),
            }
        );
    }

    #[test]
    fn subquorum_cross_view_and_foreign_local_timeout_votes_fail_closed() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let context = context(&campaign, &start, &set);
        assert_eq!(
            DegradedWindowCertificateV1::new(
                signed_statements(&set, &keys, &start, &context, 4),
                &start,
                &set,
            ),
            Err(DegradedWindowErrorV1::InsufficientTimeoutAuthority)
        );

        let mut split = signed_statements(&set, &keys, &start, &context, 5);
        for index in 3..5 {
            let local_journal = journal(index);
            let observation = DegradedWindowTimeoutObservationV1::from_local_timeout_vote(
                local_journal.fault_applied_event_sequence + 1,
                [0xe0 + u8::try_from(index).unwrap(); 32],
                &timeout_vote(&set, &keys, index, 13),
                &set,
            )
            .unwrap();
            let origin = set.validators()[index].id();
            split[index] = SignedDegradedWindowStatementV1::new(
                origin,
                context.clone(),
                split[index].config_sha256(),
                local_journal,
                Some(observation),
                &set,
                &keys[index],
            )
            .unwrap();
        }
        assert_eq!(
            DegradedWindowCertificateV1::new(split, &start, &set),
            Err(DegradedWindowErrorV1::InsufficientTimeoutAuthority)
        );

        let foreign = DegradedWindowTimeoutObservationV1::from_local_timeout_vote(
            journal(1).fault_applied_event_sequence + 1,
            [0xef; 32],
            &timeout_vote(&set, &keys, 0, 12),
            &set,
        )
        .unwrap();
        assert_eq!(
            SignedDegradedWindowStatementV1::new(
                set.validators()[1].id(),
                context,
                [0xf0; 32],
                journal(1),
                Some(foreign),
                &set,
                &keys[1],
            ),
            Err(DegradedWindowErrorV1::ForeignLocalTimeoutVote)
        );
    }

    #[test]
    fn restart_terminal_divergence_config_and_start_artifact_fail_closed() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let context = context(&campaign, &start, &set);
        let mut restarted = journal(0);
        restarted.process_instance = 2;
        assert_eq!(
            SignedDegradedWindowStatementV1::new(
                set.validators()[0].id(),
                context.clone(),
                [0xf1; 32],
                restarted,
                None,
                &set,
                &keys[0],
            ),
            Err(DegradedWindowErrorV1::Malformed("restart-free journal cut"))
        );

        let mut statements = signed_statements(&set, &keys, &start, &context, 5);
        let divergent_context = DegradedWindowContextV1::new(
            campaign.clone(),
            &start,
            [0xd1; 32],
            [0xd2; 32],
            1,
            cut(10, 7, 0x80),
            cut(14, 7, 0x80),
            cut(18, 10, 0x89),
            &set,
        )
        .unwrap();
        let index = 6;
        let origin = set.validators()[index].id();
        statements[index] = SignedDegradedWindowStatementV1::new(
            origin,
            divergent_context,
            statements[index].config_sha256(),
            journal(index),
            None,
            &set,
            &keys[index],
        )
        .unwrap();
        assert_eq!(
            DegradedWindowCertificateV1::new(statements, &start, &set),
            Err(DegradedWindowErrorV1::DifferentWindow)
        );

        let canonical = signed_statements(&set, &keys, &start, &context, 5);
        let certificate =
            DegradedWindowCertificateV1::new(canonical.clone(), &start, &set).unwrap();
        let mut wrong_config = canonical;
        wrong_config[2] = SignedDegradedWindowStatementV1::new(
            set.validators()[2].id(),
            context.clone(),
            [0xff; 32],
            journal(2),
            wrong_config[2].timeout_observation().cloned(),
            &set,
            &keys[2],
        )
        .unwrap();
        assert_eq!(
            DegradedWindowCertificateV1::new(wrong_config, &start, &set),
            Err(DegradedWindowErrorV1::WrongConfig)
        );
        let different_start = fleet_start_certificate(&set, &keys, &campaign, 0xe0);
        assert_eq!(
            certificate
                .verify_owned(&different_start, &set)
                .unwrap_err(),
            DegradedWindowErrorV1::InvalidFleetStartCertificate
        );
    }

    #[test]
    fn signatures_completeness_artifact_tamper_and_noncanonical_order_fail_closed() {
        let (set, keys) = validator_fixture();
        let campaign = campaign(&set);
        let start = fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let context = context(&campaign, &start, &set);
        let statements = signed_statements(&set, &keys, &start, &context, 5);

        let mut corrupt_signature = statements[0].encode();
        *corrupt_signature.last_mut().unwrap() ^= 1;
        assert_eq!(
            SignedDegradedWindowStatementV1::decode(&corrupt_signature, &set),
            Err(DegradedWindowErrorV1::InvalidSignature)
        );
        assert_eq!(
            DegradedWindowCertificateV1::new(statements[..6].to_vec(), &start, &set),
            Err(DegradedWindowErrorV1::Incomplete)
        );
        let mut duplicate = statements.clone();
        duplicate[6] = duplicate[0].clone();
        assert_eq!(
            DegradedWindowCertificateV1::new(duplicate, &start, &set),
            Err(DegradedWindowErrorV1::DuplicateOrigin)
        );

        let certificate =
            DegradedWindowCertificateV1::new(statements.clone(), &start, &set).unwrap();
        let mut noncanonical = Vec::new();
        noncanonical.extend_from_slice(CERTIFICATE_MAGIC_V1);
        noncanonical.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
        noncanonical.extend_from_slice(&(statements.len() as u32).to_be_bytes());
        for statement in statements.iter().rev() {
            put_bytes_u32(&mut noncanonical, &statement.encode());
        }
        assert_eq!(
            DegradedWindowCertificateV1::decode(&noncanonical, &set),
            Err(DegradedWindowErrorV1::NonCanonical)
        );

        let mut trailing = certificate.encode();
        trailing.push(0);
        assert_eq!(
            DegradedWindowCertificateV1::decode(&trailing, &set),
            Err(DegradedWindowErrorV1::Malformed("trailing payload"))
        );

        let observation = statements[0].timeout_observation().unwrap();
        let mut tampered = observation.clone();
        tampered.artifact[0] ^= 1;
        assert_eq!(
            tampered.validate(&set),
            Err(DegradedWindowErrorV1::InvalidTimeoutArtifact)
        );
    }
}
