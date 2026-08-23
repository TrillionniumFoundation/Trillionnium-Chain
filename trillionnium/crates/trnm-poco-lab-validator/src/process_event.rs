//! Durable, signed process-event ancestry for the G3 continuous-runtime lane.
//!
//! The first event of every process incarnation is created only after
//! [`LoadedValidatorConfig`] has authenticated the closed deployment bundle.
//! Consequently the signature binds the coordinator-manifest digest read from
//! that deployment manifest. This is a causal code-path guarantee, not an
//! assertion about external wall-clock provenance.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::{
    config::{LoadedValidatorConfig, PublicReportVerifierContext},
    fleet_barrier::FleetStartCertificateV1,
    restart_cut::{
        restart_parked_ack_admission_set_sha256_for_ids_v1, RestartCutBodyV1, RestartParkRoleV1,
    },
    restart_park_protocol::{
        load_target_restart_cut_park_certificates_v1, DurablyParkedPeerRestartOwnerV1,
        StoredRestartCutParkCertificatesV1,
    },
    restart_parked_ack_protocol::DurablyAcknowledgedRestartParkedBarrierV1,
    restart_parked_ack_store::{
        load_restart_parked_ack_certificate_v1, RestartParkedAckLocalWitnessV1,
        StoredRestartParkedAckCertificateV1,
    },
    restart_protocol::{restart_protocol_message_id_for_parts_v1, RestartProtocolPhaseV1},
};

const EVENT_SCHEMA_VERSION: u32 = 1;
const EVENT_HASH_DOMAIN: &[u8] = b"trnm.poco-g3.runtime-event.v1";
const EVENT_SIGNATURE_DOMAIN: &[u8] = b"trnm.poco-g3.runtime-event-signature.v1";
const MAX_EVENT_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVENT_COUNT: usize = 262_144;
const MAX_SUBJECT_BYTES: usize = 512;

#[derive(Debug, Clone)]
pub struct RuntimeEventContextV1 {
    run_id: String,
    validator_id: ValidatorId,
    validator_set: ValidatorSet,
    coordinator_manifest_sha256: [u8; 32],
    validator_set_sha256: [u8; 32],
    config_sha256: [u8; 32],
    candidate_source_sha256: [u8; 32],
    binary_sha256: [u8; 32],
}

impl RuntimeEventContextV1 {
    /// Freezes the exact deployment facts already authenticated by config
    /// loading. There is deliberately no public field-selected constructor.
    pub fn from_loaded_config(config: &LoadedValidatorConfig) -> Self {
        Self {
            run_id: config.run_id().to_owned(),
            validator_id: config.local_validator(),
            validator_set: config.validator_set().clone(),
            coordinator_manifest_sha256: config.coordinator_manifest_sha256(),
            validator_set_sha256: config.validator_set_sha256(),
            config_sha256: config.config_sha256(),
            candidate_source_sha256: config.candidate_source_sha256(),
            binary_sha256: config.binary_sha256(),
        }
    }

    /// Freezes the same secret-free deployment facts after an observer has
    /// independently authenticated the closed public bundle. Event
    /// verification requires only the validator set and public digests; it
    /// must never open or reconstruct a validator signing key.
    pub(crate) fn from_public_context(context: &PublicReportVerifierContext) -> Self {
        Self {
            run_id: context.run_id().to_owned(),
            validator_id: context.local_validator(),
            validator_set: context.validator_set().clone(),
            coordinator_manifest_sha256: context.coordinator_manifest_sha256(),
            validator_set_sha256: context.validator_set_sha256(),
            config_sha256: context.config_sha256(),
            candidate_source_sha256: context.candidate_source_sha256(),
            binary_sha256: context.binary_sha256(),
        }
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub const fn coordinator_manifest_sha256(&self) -> [u8; 32] {
        self.coordinator_manifest_sha256
    }

    fn validate(&self, key: &SigningKey) -> Result<(), RuntimeEventErrorV1> {
        if crate::frame::validate_run_id_bytes(self.run_id.as_bytes()).is_err()
            || self.validator_id.as_bytes().len() != 32
            || self.coordinator_manifest_sha256 == [0; 32]
            || self.validator_set_sha256 == [0; 32]
            || self.config_sha256 == [0; 32]
            || self.candidate_source_sha256 == [0; 32]
            || self.binary_sha256 == [0; 32]
        {
            return Err(RuntimeEventErrorV1::Invalid("event context"));
        }
        let validator =
            self.validator_set
                .validator(self.validator_id)
                .ok_or(RuntimeEventErrorV1::Invalid(
                    "event author is absent from validator set",
                ))?;
        if validator.consensus_key().as_bytes() != &key.verifying_key().to_bytes() {
            return Err(RuntimeEventErrorV1::Invalid(
                "event signing key differs from validator set",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEventKindV1 {
    PeerSessionEstablished,
    FleetReady,
    FleetStarted,
    Restart,
    ProposalAdmitted,
    VoteBroadcast,
    QuorumCertificateAdmitted,
    TimeoutVoteBroadcast,
    TimeoutCertificateAdmitted,
    Finalized,
    ApplicationAcknowledged,
    FaultApplied,
    FaultRecovered,
    FinalTip,
    SafetyHalted,
    CleanStop,
}

impl RuntimeEventKindV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PeerSessionEstablished => "peer_session_established",
            Self::FleetReady => "fleet_ready",
            Self::FleetStarted => "fleet_started",
            Self::Restart => "restart",
            Self::ProposalAdmitted => "proposal_admitted",
            Self::VoteBroadcast => "vote_broadcast",
            Self::QuorumCertificateAdmitted => "quorum_certificate_admitted",
            Self::TimeoutVoteBroadcast => "timeout_vote_broadcast",
            Self::TimeoutCertificateAdmitted => "timeout_certificate_admitted",
            Self::Finalized => "finalized",
            Self::ApplicationAcknowledged => "application_acknowledged",
            Self::FaultApplied => "fault_applied",
            Self::FaultRecovered => "fault_recovered",
            Self::FinalTip => "final_tip",
            Self::SafetyHalted => "safety_halted",
            Self::CleanStop => "clean_stop",
        }
    }
}

/// Closed fault vocabulary for the bounded G3 campaign.  A fleet script may
/// schedule an external effect, but only the live validator runtime may append
/// the corresponding signed observation after its own effect/control boundary
/// has confirmed the exact transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeFaultV1 {
    LeaderLoss,
    ValidatorProcessKill,
    HostLoss,
    AsymmetricPartition,
    BoundedDelayLoss,
    StaleSnapshot,
    RollbackAttempt,
    EpochHandoff,
}

impl RuntimeFaultV1 {
    pub const ALL: [Self; 8] = [
        Self::LeaderLoss,
        Self::ValidatorProcessKill,
        Self::HostLoss,
        Self::AsymmetricPartition,
        Self::BoundedDelayLoss,
        Self::StaleSnapshot,
        Self::RollbackAttempt,
        Self::EpochHandoff,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaderLoss => "leader_loss",
            Self::ValidatorProcessKill => "validator_process_kill",
            Self::HostLoss => "host_loss",
            Self::AsymmetricPartition => "asymmetric_partition",
            Self::BoundedDelayLoss => "bounded_delay_loss",
            Self::StaleSnapshot => "stale_snapshot",
            Self::RollbackAttempt => "rollback_attempt",
            Self::EpochHandoff => "epoch_handoff",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|fault| fault.as_str() == value)
    }
}

/// Read-only projection of the process-journal restart phase. It carries no
/// certificate bytes and grants no transition authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeRestartPhaseV1 {
    NotStarted,
    Process1,
    Process1TargetPreparePending,
    Process1PeerParkPreparePending,
    Process1LegacyUnparked,
    Process1ParkRecordPending,
    /// Compatibility projection for a target whose Cut/Park pair and local
    /// `restart_park` are durable but whose N/N ParkedAck is not. This is an
    /// Ack-pending state and grants no process-2 handoff authority.
    Process1TargetParked,
    /// Compatibility projection for a peer whose Cut/Park pair and local
    /// `restart_park` are durable but whose N/N ParkedAck is not. This is an
    /// Ack-pending state and grants no recovery authority.
    Process1PeerParked,
    Process1TargetParkedAcked,
    Process1PeerParkedAcked,
    Process1PeerRecoveryReadyPending,
    Process1PeerRecoveryStartPending,
    Process1PeerCompleted,
    Process2RestartMarkerPending,
    Process2CatchupPending,
    Process2RecoveryReadyPending,
    Process2RecoveryStartPending,
    Process2Completed,
}

/// Read-only process-local state for orchestration and terminal reporting.
/// It is derived exclusively from the fully verified signed journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeJournalObservationV1 {
    pub process_instance: u64,
    pub next_sequence: u64,
    pub restart_prepare_nonce: Option<u64>,
    /// Process 2 still lacks its later signed/app-applied catch-up cut.
    pub restart_pending_catchup: bool,
    /// Process 2 has consumed future N/N RecoveryStart authority. For process
    /// 2, both booleans false means catch-up is complete but the RecoveryReady
    /// / RecoveryStart barrier is still pending; process 1 also reports both
    /// false and is distinguished by `process_instance`.
    pub restart_completed: bool,
    pub barrier_phase: String,
    pub fleet_ready_set_sha256: Option<[u8; 32]>,
    pub fleet_start_certificate_sha256: Option<[u8; 32]>,
    pub active_faults: Vec<String>,
    pub recovered_faults: Vec<String>,
    pub finalized_height: u64,
    pub application_height: u64,
    pub final_tip_recorded: bool,
    pub clean_stop_recorded: bool,
    pub safety_halted: bool,
}

impl RuntimeJournalObservationV1 {
    /// Coarse status-schema-compatible catch-up projection. Exact Ready versus
    /// Start pending state is available from the live journal's typed
    /// [`RuntimeEventJournalV1::restart_phase_v1`] observation.
    pub const fn restart_catchup_complete_v1(&self) -> bool {
        self.process_instance == 2 && !self.restart_pending_catchup
    }

    pub const fn restart_recovery_barrier_pending_v1(&self) -> bool {
        self.restart_catchup_complete_v1() && !self.restart_completed
    }
}

/// Freshly revalidated, read-only coordinates of the exact process-1 target
/// `restart_park` handoff boundary.  This value contains no journal writer,
/// signing key, certificate bytes, process-control handle, or permission to
/// start process 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Process1TargetParkedJournalCutV1 {
    event_sequence: u64,
    event_sha256: [u8; 32],
    restart_cut_artifact_sha256: [u8; 32],
    restart_park_artifact_sha256: [u8; 32],
    restart_parked_ack_artifact_sha256: [u8; 32],
    restart_parked_ack_admission_set_sha256: [u8; 32],
    local_restart_parked_ack_statement_sha256: [u8; 32],
}

/// Non-Clone proof that one local process-1 journal durably committed the
/// exact `restart_cut -> restart_park` suffix joined to its freshly revalidated
/// Cut/Park artifact pair.  It is created only by the owner-authenticated
/// target/peer journal writers below; callers cannot assemble it from event
/// coordinates or artifact digests.
#[must_use = "the local RestartPark journal commit must be consumed by ParkedAck issuance"]
pub(crate) struct LocalRestartParkJournalCommitV1 {
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    target_validator: ValidatorId,
    role: RestartParkRoleV1,
    process_instance: u64,
    fleet_start_certificate_sha256: [u8; 32],
    restart_cut_body_sha256: [u8; 32],
    restart_cut_artifact_sha256: [u8; 32],
    restart_park_artifact_sha256: [u8; 32],
    restart_cut_park_admission_set_sha256: [u8; 32],
    local_park_statement_sha256: [u8; 32],
    predecessor_sequence: u64,
    predecessor_sha256: [u8; 32],
    restart_cut_event_sequence: u64,
    restart_cut_event_sha256: [u8; 32],
    restart_park_event_sequence: u64,
    restart_park_event_sha256: [u8; 32],
}

impl LocalRestartParkJournalCommitV1 {
    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.local_validator
    }

    pub(crate) const fn local_config_sha256_v1(&self) -> [u8; 32] {
        self.local_config_sha256
    }

    pub(crate) const fn target_validator_v1(&self) -> ValidatorId {
        self.target_validator
    }

    pub(crate) const fn role_v1(&self) -> RestartParkRoleV1 {
        self.role
    }

    pub(crate) const fn process_instance_v1(&self) -> u64 {
        self.process_instance
    }

    pub(crate) const fn fleet_start_certificate_sha256_v1(&self) -> [u8; 32] {
        self.fleet_start_certificate_sha256
    }

    pub(crate) const fn restart_cut_body_sha256_v1(&self) -> [u8; 32] {
        self.restart_cut_body_sha256
    }

    pub(crate) const fn restart_cut_artifact_sha256_v1(&self) -> [u8; 32] {
        self.restart_cut_artifact_sha256
    }

    pub(crate) const fn restart_park_artifact_sha256_v1(&self) -> [u8; 32] {
        self.restart_park_artifact_sha256
    }

    pub(crate) const fn restart_cut_park_admission_set_sha256_v1(&self) -> [u8; 32] {
        self.restart_cut_park_admission_set_sha256
    }

    pub(crate) const fn local_park_statement_sha256_v1(&self) -> [u8; 32] {
        self.local_park_statement_sha256
    }

    pub(crate) const fn predecessor_sequence_v1(&self) -> u64 {
        self.predecessor_sequence
    }

    pub(crate) const fn predecessor_sha256_v1(&self) -> [u8; 32] {
        self.predecessor_sha256
    }

    pub(crate) const fn restart_cut_event_sequence_v1(&self) -> u64 {
        self.restart_cut_event_sequence
    }

    pub(crate) const fn restart_cut_event_sha256_v1(&self) -> [u8; 32] {
        self.restart_cut_event_sha256
    }

    pub(crate) const fn restart_park_event_sequence_v1(&self) -> u64 {
        self.restart_park_event_sequence
    }

    pub(crate) const fn restart_park_event_sha256_v1(&self) -> [u8; 32] {
        self.restart_park_event_sha256
    }
}

impl fmt::Debug for LocalRestartParkJournalCommitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRestartParkJournalCommitV1")
            .field("local_validator", &self.local_validator)
            .field("role", &self.role)
            .field("predecessor_sequence", &self.predecessor_sequence)
            .field(
                "restart_cut_event_sequence",
                &self.restart_cut_event_sequence,
            )
            .field(
                "restart_park_event_sequence",
                &self.restart_park_event_sequence,
            )
            .finish_non_exhaustive()
    }
}

impl Process1TargetParkedJournalCutV1 {
    pub(crate) const fn event_sequence_v1(self) -> u64 {
        self.event_sequence
    }

    pub(crate) const fn event_sha256_v1(self) -> [u8; 32] {
        self.event_sha256
    }

    pub(crate) const fn restart_cut_artifact_sha256_v1(self) -> [u8; 32] {
        self.restart_cut_artifact_sha256
    }

    pub(crate) const fn restart_park_artifact_sha256_v1(self) -> [u8; 32] {
        self.restart_park_artifact_sha256
    }

    pub(crate) const fn restart_parked_ack_artifact_sha256_v1(self) -> [u8; 32] {
        self.restart_parked_ack_artifact_sha256
    }

    pub(crate) const fn restart_parked_ack_admission_set_sha256_v1(self) -> [u8; 32] {
        self.restart_parked_ack_admission_set_sha256
    }

    pub(crate) const fn local_restart_parked_ack_statement_sha256_v1(self) -> [u8; 32] {
        self.local_restart_parked_ack_statement_sha256
    }
}

/// Exact JSON object printed by `verify-runtime-journal` after the observer
/// has replayed every canonical JSONL record through signature, ancestry, and
/// runtime state-machine validation.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeJournalVerificationV1 {
    pub schema_version: u32,
    pub status: String,
    pub run_id: String,
    pub validator_id: String,
    pub validator_set_sha256: String,
    pub coordinator_manifest_sha256: String,
    pub candidate_source_sha256: String,
    pub binary_sha256: String,
    pub config_sha256: String,
    pub barrier_round: u64,
    pub fleet_ready_event_sequence: u64,
    pub fleet_ready_event_sha256: String,
    pub fleet_ready_previous_event_sequence: u64,
    pub fleet_ready_previous_event_sha256: String,
    pub fleet_ready_set_sha256: String,
    pub fleet_start_certificate_sha256: String,
    pub process_instance_count: u64,
    pub event_count: u64,
    pub runtime_event_sequence: u64,
    pub runtime_event_sha256: String,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finalized_state_root: String,
    pub finalized_chain_root: String,
    pub recovered_fault_count: u64,
    pub restart_completed: bool,
    pub clean_stop: bool,
    pub signature_verified: bool,
    pub semantics_verified: bool,
    pub g3_evidence_complete: bool,
    pub geo_wan_evidence: bool,
    pub production_activation: bool,
}

/// Freshly revalidated immutable journal cut after the exact `FinalTip` →
/// `CleanStop` transition. Holding the originating journal owner keeps the
/// file lock live; its state machine rejects every later append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanStoppedJournalCutV1 {
    run_id: String,
    validator_id: ValidatorId,
    validator_set_id: [u8; 32],
    coordinator_manifest_sha256: [u8; 32],
    validator_set_sha256: [u8; 32],
    config_sha256: [u8; 32],
    candidate_source_sha256: [u8; 32],
    binary_sha256: [u8; 32],
    process_instance: u64,
    process_id: u32,
    event_sequence: u64,
    event_sha256: [u8; 32],
    clean_stop_monotonic_ns: u64,
    finalized_height: u64,
    finalized_block_id: [u8; 32],
    finalized_state_root: [u8; 32],
    finalized_chain_root: [u8; 32],
    fleet_start_certificate_sha256: [u8; 32],
    recovered_faults: Vec<String>,
    restart_completed: bool,
}

impl CleanStoppedJournalCutV1 {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn test_only(
        process_instance: u64,
        process_id: u32,
        event_sequence: u64,
        event_sha256: [u8; 32],
        clean_stop_monotonic_ns: u64,
        finalized_height: u64,
        finalized_block_id: [u8; 32],
        finalized_state_root: [u8; 32],
        finalized_chain_root: [u8; 32],
    ) -> Self {
        Self {
            run_id: "test-clean-stopped-run".to_owned(),
            validator_id: ValidatorId::new([0x41; 32]),
            validator_set_id: [0x42; 32],
            coordinator_manifest_sha256: [0x43; 32],
            validator_set_sha256: [0x44; 32],
            config_sha256: [0x45; 32],
            candidate_source_sha256: [0x46; 32],
            binary_sha256: [0x47; 32],
            process_instance,
            process_id,
            event_sequence,
            event_sha256,
            clean_stop_monotonic_ns,
            finalized_height,
            finalized_block_id,
            finalized_state_root,
            finalized_chain_root,
            fleet_start_certificate_sha256: [0x5a; 32],
            recovered_faults: Vec::new(),
            restart_completed: process_instance == 2,
        }
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub const fn validator_set_id(&self) -> [u8; 32] {
        self.validator_set_id
    }

    pub const fn coordinator_manifest_sha256(&self) -> [u8; 32] {
        self.coordinator_manifest_sha256
    }

    pub const fn validator_set_sha256(&self) -> [u8; 32] {
        self.validator_set_sha256
    }

    pub const fn config_sha256(&self) -> [u8; 32] {
        self.config_sha256
    }

    pub const fn candidate_source_sha256(&self) -> [u8; 32] {
        self.candidate_source_sha256
    }

    pub const fn binary_sha256(&self) -> [u8; 32] {
        self.binary_sha256
    }

    pub const fn process_instance(&self) -> u64 {
        self.process_instance
    }

    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    pub const fn event_sha256(&self) -> [u8; 32] {
        self.event_sha256
    }

    pub const fn clean_stop_monotonic_ns(&self) -> u64 {
        self.clean_stop_monotonic_ns
    }

    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    pub const fn finalized_block_id(&self) -> [u8; 32] {
        self.finalized_block_id
    }

    pub const fn finalized_state_root(&self) -> [u8; 32] {
        self.finalized_state_root
    }

    pub const fn finalized_chain_root(&self) -> [u8; 32] {
        self.finalized_chain_root
    }

    /// FleetStart certificate committed by the same freshly re-read signed
    /// journal which proves this exact CleanStop.  This is comparison data,
    /// not a scalar construction path for a terminal cut.
    pub const fn fleet_start_certificate_sha256(&self) -> [u8; 32] {
        self.fleet_start_certificate_sha256
    }

    pub fn recovered_faults(&self) -> &[String] {
        &self.recovered_faults
    }

    pub const fn restart_completed(&self) -> bool {
        self.restart_completed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRuntimeEventV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub validator_id: String,
    pub process_instance: u64,
    pub sequence: u64,
    /// Process-local monotonic duration since the signed process-start event.
    /// It is not consensus time and not external temporal provenance.
    pub monotonic_ns: u64,
    pub kind: String,
    pub subject: String,
    pub value: u64,
    pub coordinator_manifest_sha256: String,
    pub validator_set_sha256: String,
    pub config_sha256: String,
    pub candidate_source_sha256: String,
    pub binary_sha256: String,
    pub previous_event_sha256: String,
    pub event_sha256: String,
    pub signature: String,
    pub production_activation: bool,
}

#[derive(Serialize)]
struct RuntimeEventBodyV1<'a> {
    schema_version: u32,
    run_id: &'a str,
    validator_id: &'a str,
    process_instance: u64,
    sequence: u64,
    monotonic_ns: u64,
    kind: &'a str,
    subject: &'a str,
    value: u64,
    coordinator_manifest_sha256: &'a str,
    validator_set_sha256: &'a str,
    config_sha256: &'a str,
    candidate_source_sha256: &'a str,
    binary_sha256: &'a str,
    previous_event_sha256: &'a str,
    production_activation: bool,
}

impl SignedRuntimeEventV1 {
    fn body(&self) -> RuntimeEventBodyV1<'_> {
        RuntimeEventBodyV1 {
            schema_version: self.schema_version,
            run_id: &self.run_id,
            validator_id: &self.validator_id,
            process_instance: self.process_instance,
            sequence: self.sequence,
            monotonic_ns: self.monotonic_ns,
            kind: &self.kind,
            subject: &self.subject,
            value: self.value,
            coordinator_manifest_sha256: &self.coordinator_manifest_sha256,
            validator_set_sha256: &self.validator_set_sha256,
            config_sha256: &self.config_sha256,
            candidate_source_sha256: &self.candidate_source_sha256,
            binary_sha256: &self.binary_sha256,
            previous_event_sha256: &self.previous_event_sha256,
            production_activation: self.production_activation,
        }
    }

    fn computed_hash(&self) -> Result<[u8; 32], RuntimeEventErrorV1> {
        let body = serde_json::to_vec(&self.body()).map_err(RuntimeEventErrorV1::Json)?;
        Ok(domain_hash(EVENT_HASH_DOMAIN, &body))
    }

    fn validate(
        &self,
        context: &RuntimeEventContextV1,
        expected_sequence: u64,
        expected_instance: u64,
        expected_previous: [u8; 32],
        previous_monotonic_ns: Option<u64>,
    ) -> Result<(), RuntimeEventErrorV1> {
        if self.schema_version != EVENT_SCHEMA_VERSION
            || self.run_id != context.run_id
            || self.validator_id != hex::encode(context.validator_id.as_bytes())
            || self.sequence != expected_sequence
            || self.process_instance != expected_instance
            || self.coordinator_manifest_sha256 != hex::encode(context.coordinator_manifest_sha256)
            || self.validator_set_sha256 != hex::encode(context.validator_set_sha256)
            || self.config_sha256 != hex::encode(context.config_sha256)
            || self.candidate_source_sha256 != hex::encode(context.candidate_source_sha256)
            || self.binary_sha256 != hex::encode(context.binary_sha256)
            || self.previous_event_sha256 != hex::encode(expected_previous)
            || self.production_activation
            || self.subject.len() > MAX_SUBJECT_BYTES
            || self
                .subject
                .bytes()
                .any(|byte| byte == b'\n' || byte == b'\r')
        {
            return Err(RuntimeEventErrorV1::Invalid("event binding"));
        }
        if self.kind == "process_start" {
            if self.monotonic_ns != 0
                || self.subject != format!("instance-{}", self.process_instance)
                || self.value == 0
            {
                return Err(RuntimeEventErrorV1::Invalid("process-start event"));
            }
        } else if previous_monotonic_ns.is_none_or(|prior| self.monotonic_ns < prior) {
            return Err(RuntimeEventErrorV1::Invalid("event monotonic time"));
        }
        let event_hash = decode_hex::<32>(&self.event_sha256, "event hash")?;
        if event_hash != self.computed_hash()? {
            return Err(RuntimeEventErrorV1::Invalid("event hash"));
        }
        let signature = Signature::from_bytes(&decode_hex::<64>(&self.signature, "signature")?);
        let validator = context
            .validator_set
            .validator(context.validator_id)
            .ok_or(RuntimeEventErrorV1::Invalid("event author"))?;
        let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
            .map_err(|_| RuntimeEventErrorV1::Invalid("event public key"))?;
        key.verify_strict(&signature_root(event_hash), &signature)
            .map_err(|_| RuntimeEventErrorV1::Invalid("event signature"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartParkPrepareSubjectV1 {
    target_validator: ValidatorId,
    body_sha256: [u8; 32],
    prepare_message_id: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartCutParkSubjectV1 {
    cut_artifact_sha256: [u8; 32],
    park_artifact_sha256: [u8; 32],
    body_sha256: [u8; 32],
    admission_set_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartParkSubjectV1 {
    park_artifact_sha256: [u8; 32],
    local_park_statement_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartParkedAckSubjectV1 {
    ack_certificate_sha256: [u8; 32],
    local_ack_statement_sha256: [u8; 32],
    cut_artifact_sha256: [u8; 32],
    park_artifact_sha256: [u8; 32],
    ack_admission_set_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryZeroDeltaSubjectV1 {
    zero_delta_artifact_sha256: [u8; 32],
    recovery_context_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryReadySubjectV1 {
    ready_set_artifact_sha256: [u8; 32],
    recovery_context_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryStartSubjectV1 {
    start_certificate_artifact_sha256: [u8; 32],
    ready_set_artifact_sha256: [u8; 32],
    recovery_context_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TargetRestartPrepareJournalFactsV1 {
    request_sha256: [u8; 32],
    nonce: u64,
    prepare_head: (u64, [u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerRestartParkPrepareJournalFactsV1 {
    subject: RestartParkPrepareSubjectV1,
    shared_cut_height: u64,
    prepare_head: (u64, [u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartPreparationJournalV1 {
    Target(TargetRestartPrepareJournalFactsV1),
    Peer(PeerRestartParkPrepareJournalFactsV1),
}

impl RestartPreparationJournalV1 {
    const fn role_v1(self) -> RestartParkRoleV1 {
        match self {
            Self::Target(_) => RestartParkRoleV1::Target,
            Self::Peer(_) => RestartParkRoleV1::Peer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartCutParkJournalFactsV1 {
    preparation: RestartPreparationJournalV1,
    subject: RestartCutParkSubjectV1,
    statement_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartParkedJournalFactsV1 {
    cut_park: RestartCutParkJournalFactsV1,
    subject: RestartParkSubjectV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestartParkedAckJournalFactsV1 {
    parked: RestartParkedJournalFactsV1,
    subject: RestartParkedAckSubjectV1,
    statement_count: u64,
}

impl RestartParkedAckJournalFactsV1 {
    pub(crate) const fn role_v1(self) -> RestartParkRoleV1 {
        self.parked.cut_park.preparation.role_v1()
    }

    pub(crate) const fn ack_artifact_sha256_v1(self) -> [u8; 32] {
        self.subject.ack_certificate_sha256
    }

    pub(crate) const fn ack_admission_set_sha256_v1(self) -> [u8; 32] {
        self.subject.ack_admission_set_sha256
    }

    pub(crate) const fn local_ack_statement_sha256_v1(self) -> [u8; 32] {
        self.subject.local_ack_statement_sha256
    }

    pub(crate) const fn statement_count_v1(self) -> u64 {
        self.statement_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryZeroDeltaJournalFactsV1 {
    parked: RestartParkedJournalFactsV1,
    parked_ack: RestartParkedAckJournalFactsV1,
    subject: RecoveryZeroDeltaSubjectV1,
    height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryReadyJournalFactsV1 {
    zero_delta: RecoveryZeroDeltaJournalFactsV1,
    subject: RecoveryReadySubjectV1,
    statement_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryCompletedJournalFactsV1 {
    ready: RecoveryReadyJournalFactsV1,
    subject: RecoveryStartSubjectV1,
    statement_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum RuntimeRestartJournalStateV1 {
    #[default]
    Idle,
    Prepared(RestartPreparationJournalV1),
    /// Historical bare-hex RestartCut. It remains replayable for diagnosis but
    /// deliberately has no valid successor and cannot open process 2.
    LegacyUnparked {
        preparation: TargetRestartPrepareJournalFactsV1,
        cut_artifact_sha256: [u8; 32],
        statement_count: u64,
    },
    CutParkRecorded(RestartCutParkJournalFactsV1),
    /// The exact local Cut/Park artifacts and `rpk1` are durable, but no N/N
    /// acknowledgement certificate has yet been committed. This state is
    /// deliberately ineligible for process 2 or recovery.
    Parked(RestartParkedJournalFactsV1),
    ParkedAcked(RestartParkedAckJournalFactsV1),
    Process2RestartMarkerPending(RestartParkedAckJournalFactsV1),
    ZeroDeltaRecorded(RecoveryZeroDeltaJournalFactsV1),
    RecoveryReadyRecorded(RecoveryReadyJournalFactsV1),
    RecoveryCompleted(RecoveryCompletedJournalFactsV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct RuntimeJournalStateV1 {
    current_instance: u64,
    current_process_id: u64,
    events_in_instance: u64,
    restart: RuntimeRestartJournalStateV1,
    fleet_barrier_round: Option<u64>,
    fleet_ready_event_sequence: Option<u64>,
    fleet_ready_event_sha256: Option<[u8; 32]>,
    fleet_ready_previous_event_sequence: Option<u64>,
    fleet_ready_previous_event_sha256: Option<[u8; 32]>,
    fleet_ready_set_sha256: Option<[u8; 32]>,
    fleet_start_certificate_sha256: Option<[u8; 32]>,
    applied_faults: BTreeSet<RuntimeFaultV1>,
    active_faults: BTreeMap<RuntimeFaultV1, u64>,
    recovered_faults: BTreeSet<RuntimeFaultV1>,
    finalized_height: u64,
    application_height: u64,
    final_tip: Option<(String, u64)>,
    clean_stop: bool,
    safety_halted: bool,
    last_kind: Option<String>,
}

impl RuntimeJournalStateV1 {
    const fn restart_prepare_nonce_v1(&self) -> Option<u64> {
        match self.restart {
            RuntimeRestartJournalStateV1::Prepared(RestartPreparationJournalV1::Target(facts)) => {
                Some(facts.nonce)
            }
            RuntimeRestartJournalStateV1::LegacyUnparked { preparation, .. } => {
                Some(preparation.nonce)
            }
            RuntimeRestartJournalStateV1::CutParkRecorded(facts) => match facts.preparation {
                RestartPreparationJournalV1::Target(target) => Some(target.nonce),
                RestartPreparationJournalV1::Peer(_) => None,
            },
            RuntimeRestartJournalStateV1::Parked(facts) => match facts.cut_park.preparation {
                RestartPreparationJournalV1::Target(target) => Some(target.nonce),
                RestartPreparationJournalV1::Peer(_) => None,
            },
            RuntimeRestartJournalStateV1::ParkedAcked(facts)
            | RuntimeRestartJournalStateV1::Process2RestartMarkerPending(facts) => {
                match facts.parked.cut_park.preparation {
                    RestartPreparationJournalV1::Target(target) => Some(target.nonce),
                    RestartPreparationJournalV1::Peer(_) => None,
                }
            }
            RuntimeRestartJournalStateV1::ZeroDeltaRecorded(facts) => {
                match facts.parked.cut_park.preparation {
                    RestartPreparationJournalV1::Target(target) => Some(target.nonce),
                    RestartPreparationJournalV1::Peer(_) => None,
                }
            }
            RuntimeRestartJournalStateV1::RecoveryReadyRecorded(facts) => {
                match facts.zero_delta.parked.cut_park.preparation {
                    RestartPreparationJournalV1::Target(target) => Some(target.nonce),
                    RestartPreparationJournalV1::Peer(_) => None,
                }
            }
            RuntimeRestartJournalStateV1::RecoveryCompleted(facts) => {
                match facts.ready.zero_delta.parked.cut_park.preparation {
                    RestartPreparationJournalV1::Target(target) => Some(target.nonce),
                    RestartPreparationJournalV1::Peer(_) => None,
                }
            }
            RuntimeRestartJournalStateV1::Idle
            | RuntimeRestartJournalStateV1::Prepared(RestartPreparationJournalV1::Peer(_)) => None,
        }
    }

    const fn cut_park_facts_v1(&self) -> Option<RestartCutParkJournalFactsV1> {
        match self.restart {
            RuntimeRestartJournalStateV1::CutParkRecorded(facts) => Some(facts),
            RuntimeRestartJournalStateV1::Parked(facts) => Some(facts.cut_park),
            RuntimeRestartJournalStateV1::ParkedAcked(facts)
            | RuntimeRestartJournalStateV1::Process2RestartMarkerPending(facts) => {
                Some(facts.parked.cut_park)
            }
            RuntimeRestartJournalStateV1::ZeroDeltaRecorded(facts) => Some(facts.parked.cut_park),
            RuntimeRestartJournalStateV1::RecoveryReadyRecorded(facts) => {
                Some(facts.zero_delta.parked.cut_park)
            }
            RuntimeRestartJournalStateV1::RecoveryCompleted(facts) => {
                Some(facts.ready.zero_delta.parked.cut_park)
            }
            _ => None,
        }
    }

    const fn restart_cut_facts_v1(&self) -> Option<([u8; 32], u64)> {
        match self.restart {
            RuntimeRestartJournalStateV1::LegacyUnparked {
                cut_artifact_sha256,
                statement_count,
                ..
            } => Some((cut_artifact_sha256, statement_count)),
            _ => match self.cut_park_facts_v1() {
                Some(facts) => Some((facts.subject.cut_artifact_sha256, facts.statement_count)),
                None => None,
            },
        }
    }

    const fn restart_marker_pending_v1(&self) -> bool {
        matches!(
            self.restart,
            RuntimeRestartJournalStateV1::Process2RestartMarkerPending(_)
        )
    }

    const fn restart_pending_catchup_v1(&self) -> bool {
        self.current_instance == 2
            && matches!(self.restart, RuntimeRestartJournalStateV1::ParkedAcked(_))
    }

    const fn restart_catchup_complete_v1(&self) -> bool {
        matches!(
            self.restart,
            RuntimeRestartJournalStateV1::ZeroDeltaRecorded(_)
                | RuntimeRestartJournalStateV1::RecoveryReadyRecorded(_)
                | RuntimeRestartJournalStateV1::RecoveryCompleted(_)
        )
    }

    const fn restart_recovery_ready_v1(&self) -> bool {
        matches!(
            self.restart,
            RuntimeRestartJournalStateV1::RecoveryReadyRecorded(_)
                | RuntimeRestartJournalStateV1::RecoveryCompleted(_)
        )
    }

    const fn restart_completed_v1(&self) -> bool {
        matches!(
            self.restart,
            RuntimeRestartJournalStateV1::RecoveryCompleted(_)
        )
    }

    fn observe(
        &mut self,
        event: &SignedRuntimeEventV1,
        context: &RuntimeEventContextV1,
    ) -> Result<(), RuntimeEventErrorV1> {
        let expected_validator_count = context.validator_set.validators().len();
        self.require_restart_phase_consistent()?;
        if self.clean_stop {
            return Err(RuntimeEventErrorV1::Invalid("event follows clean stop"));
        }
        if self.safety_halted {
            return Err(RuntimeEventErrorV1::Invalid("event follows safety halt"));
        }
        if self.restart_marker_pending_v1() && event.kind != "restart" {
            return Err(RuntimeEventErrorV1::Invalid(
                "restart marker must immediately follow second process start",
            ));
        }
        match self.restart {
            RuntimeRestartJournalStateV1::Prepared(_) if event.kind != "restart_cut" => {
                return Err(RuntimeEventErrorV1::Invalid(
                    "restart cut must immediately follow process-1 restart preparation",
                ));
            }
            RuntimeRestartJournalStateV1::LegacyUnparked { .. } => {
                return Err(RuntimeEventErrorV1::Invalid(
                    "legacy restart cut has no parked successor",
                ));
            }
            RuntimeRestartJournalStateV1::CutParkRecorded(_) if event.kind != "restart_park" => {
                return Err(RuntimeEventErrorV1::Invalid(
                    "restart park must immediately follow the dual-artifact restart cut",
                ));
            }
            RuntimeRestartJournalStateV1::Parked(_)
                if self.current_instance == 1
                    && event.kind != "restart_parked_ack"
                    && event.kind != RuntimeEventKindV1::SafetyHalted.as_str() =>
            {
                return Err(RuntimeEventErrorV1::Invalid(
                    "restart Park must immediately receive the exact N/N parked acknowledgement",
                ));
            }
            RuntimeRestartJournalStateV1::ParkedAcked(facts)
                if self.current_instance == 1
                    && facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Target
                    && event.kind != "process_start"
                    && event.kind != RuntimeEventKindV1::SafetyHalted.as_str() =>
            {
                return Err(RuntimeEventErrorV1::Invalid(
                    "target parked acknowledgement permits only process-2 start",
                ));
            }
            RuntimeRestartJournalStateV1::ParkedAcked(facts)
                if ((self.current_instance == 1
                    && facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Peer)
                    || (self.current_instance == 2
                        && facts.parked.cut_park.preparation.role_v1()
                            == RestartParkRoleV1::Target))
                    && event.kind != "recovery_zero_delta"
                    && event.kind != RuntimeEventKindV1::SafetyHalted.as_str() =>
            {
                return Err(RuntimeEventErrorV1::Invalid(
                    "acknowledged parked validator must durably record the exact zero-delta cut",
                ));
            }
            RuntimeRestartJournalStateV1::ZeroDeltaRecorded(_)
                if event.kind != "recovery_ready"
                    && event.kind != RuntimeEventKindV1::SafetyHalted.as_str() =>
            {
                return Err(RuntimeEventErrorV1::Invalid(
                    "RecoveryReady must immediately follow zero-delta recovery",
                ));
            }
            RuntimeRestartJournalStateV1::RecoveryReadyRecorded(_)
                if event.kind != "recovery_start"
                    && event.kind != RuntimeEventKindV1::SafetyHalted.as_str() =>
            {
                return Err(RuntimeEventErrorV1::Invalid(
                    "RecoveryStart must immediately follow RecoveryReady",
                ));
            }
            _ => {}
        }

        match event.kind.as_str() {
            "process_start" => self.observe_process_start(event)?,
            "restart" => self.observe_restart(event)?,
            "peer_session_established" => {
                self.require_process_started()?;
                if self.fleet_ready_set_sha256.is_some()
                    && self.fleet_start_certificate_sha256.is_none()
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "peer session changes inside fleet barrier",
                    ));
                }
                require_nonempty_subject(event, "peer session")?;
            }
            "fleet_ready" => {
                self.require_process_started()?;
                if self.current_instance != 1
                    || !matches!(self.restart, RuntimeRestartJournalStateV1::Idle)
                    || self.fleet_ready_set_sha256.is_some()
                    || self.fleet_start_certificate_sha256.is_some()
                    || self.finalized_height == 0
                    || self.finalized_height != self.application_height
                    || event.value == 0
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "fleet Ready lacks one fresh commissioned cut",
                    ));
                }
                self.fleet_ready_set_sha256 = Some(require_hex32_subject(
                    &event.subject,
                    "fleet ReadySet digest",
                )?);
                self.fleet_ready_event_sequence = Some(event.sequence);
                self.fleet_ready_event_sha256 = Some(decode_hex::<32>(
                    &event.event_sha256,
                    "fleet Ready event hash",
                )?);
                self.fleet_ready_previous_event_sequence = event.sequence.checked_sub(1);
                self.fleet_ready_previous_event_sha256 = Some(decode_hex::<32>(
                    &event.previous_event_sha256,
                    "fleet Ready previous event hash",
                )?);
                self.fleet_barrier_round = Some(event.value);
            }
            "fleet_started" => {
                self.require_process_started()?;
                if self.current_instance != 1
                    || self.last_kind.as_deref() != Some("fleet_ready")
                    || self.fleet_ready_set_sha256.is_none()
                    || self.fleet_start_certificate_sha256.is_some()
                    || self.fleet_barrier_round != Some(event.value)
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "fleet Started does not immediately succeed Ready",
                    ));
                }
                self.fleet_start_certificate_sha256 = Some(require_hex32_subject(
                    &event.subject,
                    "fleet StartCertificate digest",
                )?);
            }
            "restart_prepare" => {
                self.require_consensus_ready()?;
                if self.current_instance != 1
                    || !matches!(self.restart, RuntimeRestartJournalStateV1::Idle)
                    || !self.active_faults.is_empty()
                    || self.finalized_height == 0
                    || self.finalized_height != self.application_height
                    || self.final_tip.is_some()
                    || event.value == 0
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "restart prepare lacks one fault-free applied process-1 cut",
                    ));
                }
                let request_sha256 =
                    require_hex32_subject(&event.subject, "restart prepare request digest")?;
                let prepare_head = (
                    event.sequence,
                    decode_hex::<32>(&event.event_sha256, "restart prepare event hash")?,
                );
                self.restart = RuntimeRestartJournalStateV1::Prepared(
                    RestartPreparationJournalV1::Target(TargetRestartPrepareJournalFactsV1 {
                        request_sha256,
                        nonce: event.value,
                        prepare_head,
                    }),
                );
            }
            "restart_park_prepare" => {
                self.require_consensus_ready()?;
                let subject = RestartParkPrepareSubjectV1::decode(&event.subject)?;
                if self.current_instance != 1
                    || !matches!(self.restart, RuntimeRestartJournalStateV1::Idle)
                    || expected_validator_count != 7
                    || context
                        .validator_set
                        .validator(subject.target_validator)
                        .is_none()
                    || subject.target_validator == context.validator_id
                    || !self.active_faults.is_empty()
                    || self.finalized_height == 0
                    || self.finalized_height != self.application_height
                    || self.finalized_height != event.value
                    || self.final_tip.is_some()
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "peer park prepare lacks one direct-seven fault-free applied cut",
                    ));
                }
                let prepare_head = (
                    event.sequence,
                    decode_hex::<32>(&event.event_sha256, "peer park prepare event hash")?,
                );
                self.restart = RuntimeRestartJournalStateV1::Prepared(
                    RestartPreparationJournalV1::Peer(PeerRestartParkPrepareJournalFactsV1 {
                        subject,
                        shared_cut_height: event.value,
                        prepare_head,
                    }),
                );
            }
            "restart_cut" => {
                self.require_fleet_started()?;
                let expected_statement_count = u64::try_from(expected_validator_count)
                    .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
                if self.current_instance != 1 || event.value != expected_statement_count {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "restart cut is not the exact N/N preparation successor",
                    ));
                }
                let preparation = match self.restart {
                    RuntimeRestartJournalStateV1::Prepared(preparation) => preparation,
                    _ => {
                        return Err(RuntimeEventErrorV1::Invalid(
                            "restart cut lacks one exact preparation",
                        ));
                    }
                };
                match RestartCutJournalSubjectV1::decode(&event.subject)? {
                    RestartCutJournalSubjectV1::Legacy(cut_artifact_sha256) => {
                        let RestartPreparationJournalV1::Target(preparation) = preparation else {
                            return Err(RuntimeEventErrorV1::Invalid(
                                "peer restart cut cannot use the legacy unparked subject",
                            ));
                        };
                        self.restart = RuntimeRestartJournalStateV1::LegacyUnparked {
                            preparation,
                            cut_artifact_sha256,
                            statement_count: event.value,
                        };
                    }
                    RestartCutJournalSubjectV1::CutPark(subject) => {
                        if expected_validator_count != 7
                            || matches!(
                                preparation,
                                RestartPreparationJournalV1::Peer(peer)
                                    if peer.subject.body_sha256 != subject.body_sha256
                            )
                        {
                            return Err(RuntimeEventErrorV1::Invalid(
                                "dual-artifact restart cut differs from its preparation",
                            ));
                        }
                        self.restart = RuntimeRestartJournalStateV1::CutParkRecorded(
                            RestartCutParkJournalFactsV1 {
                                preparation,
                                subject,
                                statement_count: event.value,
                            },
                        );
                    }
                }
            }
            "restart_park" => {
                self.require_fleet_started()?;
                let expected_statement_count = u64::try_from(expected_validator_count)
                    .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
                let cut_park = match self.restart {
                    RuntimeRestartJournalStateV1::CutParkRecorded(facts) => facts,
                    _ => {
                        return Err(RuntimeEventErrorV1::Invalid(
                            "restart park lacks its exact dual-artifact cut",
                        ));
                    }
                };
                let subject = RestartParkSubjectV1::decode(&event.subject)?;
                if self.current_instance != 1
                    || expected_validator_count != 7
                    || event.value != expected_statement_count
                    || event.value != cut_park.statement_count
                    || subject.park_artifact_sha256 != cut_park.subject.park_artifact_sha256
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "restart park differs from its exact dual-artifact cut",
                    ));
                }
                self.restart = RuntimeRestartJournalStateV1::Parked(RestartParkedJournalFactsV1 {
                    cut_park,
                    subject,
                });
            }
            "restart_parked_ack" => {
                self.require_fleet_started()?;
                let expected_statement_count = u64::try_from(expected_validator_count)
                    .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
                let parked = match self.restart {
                    RuntimeRestartJournalStateV1::Parked(facts) => facts,
                    _ => {
                        return Err(RuntimeEventErrorV1::Invalid(
                            "parked acknowledgement lacks its exact local Park predecessor",
                        ));
                    }
                };
                let subject = RestartParkedAckSubjectV1::decode(&event.subject)?;
                if self.current_instance != 1
                    || expected_validator_count != 7
                    || event.value != expected_statement_count
                    || event.value != parked.cut_park.statement_count
                    || subject.cut_artifact_sha256 != parked.cut_park.subject.cut_artifact_sha256
                    || subject.park_artifact_sha256 != parked.cut_park.subject.park_artifact_sha256
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "parked acknowledgement differs from its exact direct-seven Cut/Park predecessor",
                    ));
                }
                self.restart =
                    RuntimeRestartJournalStateV1::ParkedAcked(RestartParkedAckJournalFactsV1 {
                        parked,
                        subject,
                        statement_count: event.value,
                    });
            }
            "proposal_admitted" | "vote_broadcast" | "timeout_vote_broadcast" => {
                self.require_consensus_ready()?;
                require_nonempty_subject(event, "consensus event")?;
            }
            "quorum_certificate_admitted" | "timeout_certificate_admitted" => {
                self.require_consensus_ready()?;
                require_nonempty_subject(event, "certificate event")?;
            }
            "finalized" => {
                require_hex32_subject(&event.subject, "finalized block")?;
                if self.fleet_start_certificate_sha256.is_none() {
                    self.require_process_started()?;
                    if self.fleet_ready_set_sha256.is_some()
                        || self.finalized_height != 0
                        || self.application_height != 0
                        || event.value == 0
                    {
                        return Err(RuntimeEventErrorV1::Invalid(
                            "initial finalized cut is duplicate or follows fleet Ready",
                        ));
                    }
                } else {
                    self.require_consensus_ready()?;
                }
                if event.value == 0 || event.value < self.finalized_height {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "finalized height is zero or regresses",
                    ));
                }
                self.finalized_height = event.value;
            }
            "application_acknowledged" => {
                require_hex32_subject(&event.subject, "application state")?;
                if self.fleet_start_certificate_sha256.is_none() {
                    self.require_process_started()?;
                    if self.fleet_ready_set_sha256.is_some()
                        || self.application_height != 0
                        || self.finalized_height == 0
                        || self.last_kind.as_deref() != Some("finalized")
                        || event.value != self.finalized_height
                    {
                        return Err(RuntimeEventErrorV1::Invalid(
                            "initial application cut is duplicate or not exact finality",
                        ));
                    }
                } else {
                    self.require_consensus_ready()?;
                }
                if event.value == 0
                    || event.value < self.application_height
                    || event.value > self.finalized_height
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "application height is zero, regresses, or exceeds finality",
                    ));
                }
                self.application_height = event.value;
            }
            "recovery_zero_delta" => {
                self.require_fleet_started()?;
                let parked_ack = match self.restart {
                    RuntimeRestartJournalStateV1::ParkedAcked(facts) => facts,
                    _ => {
                        return Err(RuntimeEventErrorV1::Invalid(
                            "zero-delta recovery lacks one exact parked acknowledgement predecessor",
                        ));
                    }
                };
                let parked = parked_ack.parked;
                let valid_role = (self.current_instance == 1
                    && parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Peer)
                    || (self.current_instance == 2
                        && parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Target);
                let subject = RecoveryZeroDeltaSubjectV1::decode(&event.subject)?;
                if !valid_role
                    || expected_validator_count != 7
                    || event.value == 0
                    || event.value != self.finalized_height
                    || event.value != self.application_height
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "zero-delta recovery differs from the exact parked shared cut",
                    ));
                }
                self.restart = RuntimeRestartJournalStateV1::ZeroDeltaRecorded(
                    RecoveryZeroDeltaJournalFactsV1 {
                        parked,
                        parked_ack,
                        subject,
                        height: event.value,
                    },
                );
            }
            "recovery_ready" => {
                self.require_fleet_started()?;
                let expected_statement_count = u64::try_from(expected_validator_count)
                    .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
                let zero_delta = match self.restart {
                    RuntimeRestartJournalStateV1::ZeroDeltaRecorded(facts) => facts,
                    _ => {
                        return Err(RuntimeEventErrorV1::Invalid(
                            "RecoveryReady lacks the exact zero-delta predecessor",
                        ));
                    }
                };
                let subject = RecoveryReadySubjectV1::decode(&event.subject)?;
                if expected_validator_count != 7
                    || event.value != expected_statement_count
                    || subject.recovery_context_sha256 != zero_delta.subject.recovery_context_sha256
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "RecoveryReady differs from the exact zero-delta N/N predecessor",
                    ));
                }
                self.restart = RuntimeRestartJournalStateV1::RecoveryReadyRecorded(
                    RecoveryReadyJournalFactsV1 {
                        zero_delta,
                        subject,
                        statement_count: event.value,
                    },
                );
            }
            "recovery_start" => {
                self.require_fleet_started()?;
                let expected_statement_count = u64::try_from(expected_validator_count)
                    .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
                let ready = match self.restart {
                    RuntimeRestartJournalStateV1::RecoveryReadyRecorded(facts) => facts,
                    _ => {
                        return Err(RuntimeEventErrorV1::Invalid(
                            "RecoveryStart lacks the exact N/N RecoveryReady predecessor",
                        ));
                    }
                };
                let subject = RecoveryStartSubjectV1::decode(&event.subject)?;
                if expected_validator_count != 7
                    || event.value != expected_statement_count
                    || event.value != ready.statement_count
                    || subject.ready_set_artifact_sha256 != ready.subject.ready_set_artifact_sha256
                    || subject.recovery_context_sha256 != ready.subject.recovery_context_sha256
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "RecoveryStart differs from the exact N/N RecoveryReady predecessor",
                    ));
                }
                self.restart = RuntimeRestartJournalStateV1::RecoveryCompleted(
                    RecoveryCompletedJournalFactsV1 {
                        ready,
                        subject,
                        statement_count: event.value,
                    },
                );
            }
            "fault_applied" => {
                self.require_consensus_ready()?;
                let fault = RuntimeFaultV1::parse(&event.subject)
                    .ok_or(RuntimeEventErrorV1::Invalid("unknown runtime fault"))?;
                if event.value != 1
                    || !self.applied_faults.insert(fault)
                    || self.active_faults.insert(fault, event.sequence).is_some()
                    || self.recovered_faults.contains(&fault)
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "fault application is duplicate or malformed",
                    ));
                }
            }
            "fault_recovered" => {
                self.require_consensus_ready()?;
                let fault = RuntimeFaultV1::parse(&event.subject)
                    .ok_or(RuntimeEventErrorV1::Invalid("unknown runtime fault"))?;
                if event.value == 0
                    || self.active_faults.remove(&fault).is_none()
                    || !self.recovered_faults.insert(fault)
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "fault recovery lacks one exact application",
                    ));
                }
            }
            "final_tip" => {
                self.require_consensus_ready()?;
                if self.final_tip.is_some()
                    || !self.active_faults.is_empty()
                    || event.value == 0
                    || event.value != self.finalized_height
                    || event.value != self.application_height
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "final tip is duplicate, unresolved, or not fully applied",
                    ));
                }
                require_final_tip_subject(&event.subject)?;
                self.final_tip = Some((event.subject.clone(), event.value));
            }
            "clean_stop" => {
                self.require_consensus_ready()?;
                if self.last_kind.as_deref() != Some("final_tip")
                    || self.final_tip.is_none()
                    || !self.active_faults.is_empty()
                    || event.subject != "bounded-run-complete"
                    || event.value != self.current_process_id
                {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "clean stop does not immediately bind exact final tip/process",
                    ));
                }
                self.clean_stop = true;
            }
            "safety_halted" => {
                self.require_process_started()?;
                require_nonempty_subject(event, "safety halt")?;
                self.safety_halted = true;
            }
            _ => return Err(RuntimeEventErrorV1::Invalid("unknown runtime event kind")),
        }
        self.events_in_instance =
            self.events_in_instance
                .checked_add(1)
                .ok_or(RuntimeEventErrorV1::Invalid(
                    "process event counter overflow",
                ))?;
        self.last_kind = Some(event.kind.clone());
        self.require_restart_phase_consistent()
    }

    fn observe_process_start(
        &mut self,
        event: &SignedRuntimeEventV1,
    ) -> Result<(), RuntimeEventErrorV1> {
        let expected = self
            .current_instance
            .checked_add(1)
            .ok_or(RuntimeEventErrorV1::Invalid("process instance overflow"))?;
        if event.process_instance != expected
            || event.process_instance > 2
            || event.monotonic_ns != 0
            || event.subject != format!("instance-{}", event.process_instance)
            || event.value == 0
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "process start crosses bounded restart profile",
            ));
        }
        if event.process_instance == 2 {
            if self.fleet_start_certificate_sha256.is_none() {
                return Err(RuntimeEventErrorV1::Invalid(
                    "second process starts before fleet Started",
                ));
            }
            let parked_ack = match self.restart {
                RuntimeRestartJournalStateV1::ParkedAcked(facts)
                    if facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Target =>
                {
                    facts
                }
                _ => {
                    return Err(RuntimeEventErrorV1::Invalid(
                        "second process does not immediately succeed a target ParkedAck certificate",
                    ));
                }
            };
            if self.last_kind.as_deref() != Some("restart_parked_ack") {
                return Err(RuntimeEventErrorV1::Invalid(
                    "second process does not immediately succeed a semantically valid target parked acknowledgement",
                ));
            }
            self.restart = RuntimeRestartJournalStateV1::Process2RestartMarkerPending(parked_ack);
        }
        self.current_instance = event.process_instance;
        self.current_process_id = event.value;
        self.events_in_instance = 0;
        Ok(())
    }

    fn observe_restart(&mut self, event: &SignedRuntimeEventV1) -> Result<(), RuntimeEventErrorV1> {
        let parked_ack = match self.restart {
            RuntimeRestartJournalStateV1::Process2RestartMarkerPending(facts) => facts,
            _ => return Err(RuntimeEventErrorV1::Invalid("invalid restart marker")),
        };
        if self.current_instance != 2
            || self.events_in_instance != 1
            || event.subject != "instance-2"
            || event.value != self.current_process_id
        {
            return Err(RuntimeEventErrorV1::Invalid("invalid restart marker"));
        }
        self.restart = RuntimeRestartJournalStateV1::ParkedAcked(parked_ack);
        Ok(())
    }

    fn require_process_started(&self) -> Result<(), RuntimeEventErrorV1> {
        if self.current_instance == 0 {
            return Err(RuntimeEventErrorV1::Invalid("event precedes process start"));
        }
        Ok(())
    }

    fn require_fleet_started(&self) -> Result<(), RuntimeEventErrorV1> {
        self.require_process_started()?;
        if self.fleet_start_certificate_sha256.is_none() {
            return Err(RuntimeEventErrorV1::Invalid(
                "ordinary runtime event precedes fleet Started",
            ));
        }
        Ok(())
    }

    fn require_consensus_ready(&self) -> Result<(), RuntimeEventErrorV1> {
        self.require_fleet_started()?;
        let ready = match (self.current_instance, self.restart) {
            (1, RuntimeRestartJournalStateV1::Idle) => true,
            (1, RuntimeRestartJournalStateV1::RecoveryCompleted(facts)) => {
                facts.ready.zero_delta.parked.cut_park.preparation.role_v1()
                    == RestartParkRoleV1::Peer
            }
            (2, RuntimeRestartJournalStateV1::RecoveryCompleted(facts)) => {
                facts.ready.zero_delta.parked.cut_park.preparation.role_v1()
                    == RestartParkRoleV1::Target
            }
            _ => false,
        };
        if !ready {
            return Err(RuntimeEventErrorV1::Invalid(
                "consensus event precedes caught-up N/N RecoveryStart",
            ));
        }
        Ok(())
    }

    fn require_restart_phase_consistent(&self) -> Result<(), RuntimeEventErrorV1> {
        let valid = match (self.current_instance, self.restart) {
            (0, RuntimeRestartJournalStateV1::Idle) => true,
            (1, RuntimeRestartJournalStateV1::Idle) => true,
            (
                1,
                RuntimeRestartJournalStateV1::Prepared(RestartPreparationJournalV1::Target(facts)),
            ) => {
                facts.request_sha256 != [0; 32]
                    && facts.nonce != 0
                    && facts.prepare_head.1 != [0; 32]
            }
            (
                1,
                RuntimeRestartJournalStateV1::Prepared(RestartPreparationJournalV1::Peer(facts)),
            ) => {
                facts.subject.target_validator.as_bytes() != &[0; 32]
                    && facts.subject.body_sha256 != [0; 32]
                    && facts.subject.prepare_message_id != [0; 32]
                    && facts.shared_cut_height != 0
                    && facts.prepare_head.1 != [0; 32]
            }
            (
                1,
                RuntimeRestartJournalStateV1::LegacyUnparked {
                    cut_artifact_sha256,
                    statement_count,
                    ..
                },
            ) => cut_artifact_sha256 != [0; 32] && statement_count != 0,
            (1, RuntimeRestartJournalStateV1::CutParkRecorded(facts)) => {
                facts.statement_count != 0
                    && facts.subject.cut_artifact_sha256 != [0; 32]
                    && facts.subject.park_artifact_sha256 != [0; 32]
            }
            (1, RuntimeRestartJournalStateV1::Parked(facts)) => {
                matches!(
                    facts.cut_park.preparation.role_v1(),
                    RestartParkRoleV1::Target | RestartParkRoleV1::Peer
                ) && facts.subject.park_artifact_sha256
                    == facts.cut_park.subject.park_artifact_sha256
            }
            (1, RuntimeRestartJournalStateV1::ParkedAcked(facts)) => {
                matches!(
                    facts.parked.cut_park.preparation.role_v1(),
                    RestartParkRoleV1::Target | RestartParkRoleV1::Peer
                ) && facts.statement_count == facts.parked.cut_park.statement_count
                    && facts.subject.cut_artifact_sha256
                        == facts.parked.cut_park.subject.cut_artifact_sha256
                    && facts.subject.park_artifact_sha256
                        == facts.parked.cut_park.subject.park_artifact_sha256
            }
            (1, RuntimeRestartJournalStateV1::ZeroDeltaRecorded(facts)) => {
                facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Peer
                    && facts.parked_ack.parked == facts.parked
                    && facts.height != 0
            }
            (1, RuntimeRestartJournalStateV1::RecoveryReadyRecorded(facts)) => {
                facts.zero_delta.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Peer
                    && facts.statement_count != 0
            }
            (1, RuntimeRestartJournalStateV1::RecoveryCompleted(facts)) => {
                facts.ready.zero_delta.parked.cut_park.preparation.role_v1()
                    == RestartParkRoleV1::Peer
                    && facts.statement_count == facts.ready.statement_count
                    && facts.subject.ready_set_artifact_sha256
                        == facts.ready.subject.ready_set_artifact_sha256
                    && facts.subject.recovery_context_sha256
                        == facts.ready.subject.recovery_context_sha256
            }
            (2, RuntimeRestartJournalStateV1::Process2RestartMarkerPending(facts))
            | (2, RuntimeRestartJournalStateV1::ParkedAcked(facts)) => {
                facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Target
                    && facts.parked.cut_park.statement_count != 0
                    && facts.parked.subject.park_artifact_sha256
                        == facts.parked.cut_park.subject.park_artifact_sha256
                    && facts.subject.cut_artifact_sha256
                        == facts.parked.cut_park.subject.cut_artifact_sha256
                    && facts.subject.park_artifact_sha256
                        == facts.parked.cut_park.subject.park_artifact_sha256
            }
            (2, RuntimeRestartJournalStateV1::ZeroDeltaRecorded(facts)) => {
                facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Target
                    && facts.parked_ack.parked == facts.parked
                    && facts.height != 0
            }
            (2, RuntimeRestartJournalStateV1::RecoveryReadyRecorded(facts)) => {
                facts.zero_delta.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Target
                    && facts.statement_count != 0
            }
            (2, RuntimeRestartJournalStateV1::RecoveryCompleted(facts)) => {
                facts.ready.zero_delta.parked.cut_park.preparation.role_v1()
                    == RestartParkRoleV1::Target
                    && facts.statement_count == facts.ready.statement_count
                    && facts.subject.ready_set_artifact_sha256
                        == facts.ready.subject.ready_set_artifact_sha256
                    && facts.subject.recovery_context_sha256
                        == facts.ready.subject.recovery_context_sha256
            }
            _ => false,
        };
        if !valid {
            return Err(RuntimeEventErrorV1::Invalid(
                "runtime restart phase flags are inconsistent",
            ));
        }
        Ok(())
    }

    fn restart_phase_v1(&self) -> RuntimeRestartPhaseV1 {
        debug_assert!(self.require_restart_phase_consistent().is_ok());
        match (self.current_instance, self.restart) {
            (0, _) => RuntimeRestartPhaseV1::NotStarted,
            (1, RuntimeRestartJournalStateV1::Idle) => RuntimeRestartPhaseV1::Process1,
            (1, RuntimeRestartJournalStateV1::Prepared(RestartPreparationJournalV1::Target(_))) => {
                RuntimeRestartPhaseV1::Process1TargetPreparePending
            }
            (1, RuntimeRestartJournalStateV1::Prepared(RestartPreparationJournalV1::Peer(_))) => {
                RuntimeRestartPhaseV1::Process1PeerParkPreparePending
            }
            (1, RuntimeRestartJournalStateV1::LegacyUnparked { .. }) => {
                RuntimeRestartPhaseV1::Process1LegacyUnparked
            }
            (1, RuntimeRestartJournalStateV1::CutParkRecorded(_)) => {
                RuntimeRestartPhaseV1::Process1ParkRecordPending
            }
            (1, RuntimeRestartJournalStateV1::Parked(facts))
                if facts.cut_park.preparation.role_v1() == RestartParkRoleV1::Target =>
            {
                RuntimeRestartPhaseV1::Process1TargetParked
            }
            (1, RuntimeRestartJournalStateV1::Parked(_)) => {
                RuntimeRestartPhaseV1::Process1PeerParked
            }
            (1, RuntimeRestartJournalStateV1::ParkedAcked(facts))
                if facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Target =>
            {
                RuntimeRestartPhaseV1::Process1TargetParkedAcked
            }
            (1, RuntimeRestartJournalStateV1::ParkedAcked(_)) => {
                RuntimeRestartPhaseV1::Process1PeerParkedAcked
            }
            (1, RuntimeRestartJournalStateV1::ZeroDeltaRecorded(_)) => {
                RuntimeRestartPhaseV1::Process1PeerRecoveryReadyPending
            }
            (1, RuntimeRestartJournalStateV1::RecoveryReadyRecorded(_)) => {
                RuntimeRestartPhaseV1::Process1PeerRecoveryStartPending
            }
            (1, RuntimeRestartJournalStateV1::RecoveryCompleted(_)) => {
                RuntimeRestartPhaseV1::Process1PeerCompleted
            }
            (2, RuntimeRestartJournalStateV1::Process2RestartMarkerPending(_)) => {
                RuntimeRestartPhaseV1::Process2RestartMarkerPending
            }
            (2, RuntimeRestartJournalStateV1::ParkedAcked(_)) => {
                RuntimeRestartPhaseV1::Process2CatchupPending
            }
            (2, RuntimeRestartJournalStateV1::ZeroDeltaRecorded(_)) => {
                RuntimeRestartPhaseV1::Process2RecoveryReadyPending
            }
            (2, RuntimeRestartJournalStateV1::RecoveryReadyRecorded(_)) => {
                RuntimeRestartPhaseV1::Process2RecoveryStartPending
            }
            (2, RuntimeRestartJournalStateV1::RecoveryCompleted(_)) => {
                RuntimeRestartPhaseV1::Process2Completed
            }
            _ => unreachable!("validated runtime restart phase"),
        }
    }

    fn observation(&self, next_sequence: u64) -> RuntimeJournalObservationV1 {
        let barrier_phase = if self.fleet_start_certificate_sha256.is_some() {
            "started"
        } else if self.fleet_ready_set_sha256.is_some() {
            "ready"
        } else {
            "preparing"
        };
        RuntimeJournalObservationV1 {
            process_instance: self.current_instance,
            next_sequence,
            restart_prepare_nonce: self.restart_prepare_nonce_v1(),
            restart_pending_catchup: self.restart_pending_catchup_v1(),
            restart_completed: self.restart_completed_v1(),
            barrier_phase: barrier_phase.to_owned(),
            fleet_ready_set_sha256: self.fleet_ready_set_sha256,
            fleet_start_certificate_sha256: self.fleet_start_certificate_sha256,
            active_faults: self
                .active_faults
                .keys()
                .map(|fault| fault.as_str().to_owned())
                .collect(),
            recovered_faults: self
                .recovered_faults
                .iter()
                .map(|fault| fault.as_str().to_owned())
                .collect(),
            finalized_height: self.finalized_height,
            application_height: self.application_height,
            final_tip_recorded: self.final_tip.is_some(),
            clean_stop_recorded: self.clean_stop,
            safety_halted: self.safety_halted,
        }
    }
}

fn require_nonempty_subject(
    event: &SignedRuntimeEventV1,
    reason: &'static str,
) -> Result<(), RuntimeEventErrorV1> {
    if event.subject.is_empty() {
        return Err(RuntimeEventErrorV1::Invalid(reason));
    }
    Ok(())
}

fn require_hex32_subject(
    subject: &str,
    reason: &'static str,
) -> Result<[u8; 32], RuntimeEventErrorV1> {
    let value = decode_hex::<32>(subject, reason)?;
    if value == [0; 32] {
        return Err(RuntimeEventErrorV1::Invalid(reason));
    }
    Ok(value)
}

fn subject_parts_v1<'a, const N: usize>(
    subject: &'a str,
    prefix: &'static str,
    reason: &'static str,
) -> Result<[&'a str; N], RuntimeEventErrorV1> {
    let parts = subject.split(':').collect::<Vec<_>>();
    let parts: [&str; N] = parts
        .try_into()
        .map_err(|_| RuntimeEventErrorV1::Invalid(reason))?;
    if parts.first().copied() != Some(prefix) {
        return Err(RuntimeEventErrorV1::Invalid(reason));
    }
    Ok(parts)
}

impl RestartParkPrepareSubjectV1 {
    fn encode(self) -> String {
        format!(
            "rpp1:{}:{}:{}",
            hex::encode(self.target_validator.as_bytes()),
            hex::encode(self.body_sha256),
            hex::encode(self.prepare_message_id)
        )
    }

    fn decode(subject: &str) -> Result<Self, RuntimeEventErrorV1> {
        let parts = subject_parts_v1::<4>(subject, "rpp1", "restart park prepare subject")?;
        let target_validator = ValidatorId::new(require_hex32_subject(
            parts[1],
            "restart park prepare target validator",
        )?);
        let value = Self {
            target_validator,
            body_sha256: require_hex32_subject(parts[2], "restart park prepare body digest")?,
            prepare_message_id: require_hex32_subject(parts[3], "restart park prepare message ID")?,
        };
        if value.encode() != subject {
            return Err(RuntimeEventErrorV1::Invalid("restart park prepare subject"));
        }
        Ok(value)
    }
}

impl RestartCutParkSubjectV1 {
    fn encode(self) -> String {
        format!(
            "rcp1:{}:{}:{}:{}",
            hex::encode(self.cut_artifact_sha256),
            hex::encode(self.park_artifact_sha256),
            hex::encode(self.body_sha256),
            hex::encode(self.admission_set_sha256)
        )
    }

    fn decode(subject: &str) -> Result<Self, RuntimeEventErrorV1> {
        let parts = subject_parts_v1::<5>(subject, "rcp1", "dual restart cut subject")?;
        let value = Self {
            cut_artifact_sha256: require_hex32_subject(parts[1], "restart cut artifact digest")?,
            park_artifact_sha256: require_hex32_subject(parts[2], "restart park artifact digest")?,
            body_sha256: require_hex32_subject(parts[3], "restart cut body digest")?,
            admission_set_sha256: require_hex32_subject(parts[4], "restart admission set digest")?,
        };
        if value.encode() != subject {
            return Err(RuntimeEventErrorV1::Invalid("dual restart cut subject"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartCutJournalSubjectV1 {
    Legacy([u8; 32]),
    CutPark(RestartCutParkSubjectV1),
}

impl RestartCutJournalSubjectV1 {
    fn decode(subject: &str) -> Result<Self, RuntimeEventErrorV1> {
        if !subject.contains(':') {
            return require_hex32_subject(subject, "legacy restart cut artifact digest")
                .map(Self::Legacy);
        }
        RestartCutParkSubjectV1::decode(subject).map(Self::CutPark)
    }
}

impl RestartParkSubjectV1 {
    fn encode(self) -> String {
        format!(
            "rpk1:{}:{}",
            hex::encode(self.park_artifact_sha256),
            hex::encode(self.local_park_statement_sha256)
        )
    }

    fn decode(subject: &str) -> Result<Self, RuntimeEventErrorV1> {
        let parts = subject_parts_v1::<3>(subject, "rpk1", "restart park subject")?;
        let value = Self {
            park_artifact_sha256: require_hex32_subject(parts[1], "restart park artifact digest")?,
            local_park_statement_sha256: require_hex32_subject(
                parts[2],
                "local restart park statement digest",
            )?,
        };
        if value.encode() != subject {
            return Err(RuntimeEventErrorV1::Invalid("restart park subject"));
        }
        Ok(value)
    }
}

impl RestartParkedAckSubjectV1 {
    fn encode(self) -> String {
        format!(
            "rpa1:{}:{}:{}:{}:{}",
            hex::encode(self.ack_certificate_sha256),
            hex::encode(self.local_ack_statement_sha256),
            hex::encode(self.cut_artifact_sha256),
            hex::encode(self.park_artifact_sha256),
            hex::encode(self.ack_admission_set_sha256)
        )
    }

    fn decode(subject: &str) -> Result<Self, RuntimeEventErrorV1> {
        let parts =
            subject_parts_v1::<6>(subject, "rpa1", "restart parked acknowledgement subject")?;
        let value = Self {
            ack_certificate_sha256: require_hex32_subject(
                parts[1],
                "restart parked acknowledgement certificate digest",
            )?,
            local_ack_statement_sha256: require_hex32_subject(
                parts[2],
                "local restart parked acknowledgement statement digest",
            )?,
            cut_artifact_sha256: require_hex32_subject(
                parts[3],
                "restart parked acknowledgement cut artifact digest",
            )?,
            park_artifact_sha256: require_hex32_subject(
                parts[4],
                "restart parked acknowledgement park artifact digest",
            )?,
            ack_admission_set_sha256: require_hex32_subject(
                parts[5],
                "restart parked acknowledgement admission-set digest",
            )?,
        };
        if value.encode() != subject {
            return Err(RuntimeEventErrorV1::Invalid(
                "restart parked acknowledgement subject",
            ));
        }
        Ok(value)
    }
}

impl RecoveryZeroDeltaSubjectV1 {
    fn encode(self) -> String {
        format!(
            "rzd1:{}:{}",
            hex::encode(self.zero_delta_artifact_sha256),
            hex::encode(self.recovery_context_sha256)
        )
    }

    fn decode(subject: &str) -> Result<Self, RuntimeEventErrorV1> {
        let parts = subject_parts_v1::<3>(subject, "rzd1", "zero-delta recovery subject")?;
        let value = Self {
            zero_delta_artifact_sha256: require_hex32_subject(
                parts[1],
                "zero-delta recovery artifact digest",
            )?,
            recovery_context_sha256: require_hex32_subject(
                parts[2],
                "zero-delta recovery context digest",
            )?,
        };
        if value.encode() != subject {
            return Err(RuntimeEventErrorV1::Invalid("zero-delta recovery subject"));
        }
        Ok(value)
    }
}

impl RecoveryReadySubjectV1 {
    fn encode(self) -> String {
        format!(
            "rrv1:{}:{}",
            hex::encode(self.ready_set_artifact_sha256),
            hex::encode(self.recovery_context_sha256)
        )
    }

    fn decode(subject: &str) -> Result<Self, RuntimeEventErrorV1> {
        let parts = subject_parts_v1::<3>(subject, "rrv1", "RecoveryReady subject")?;
        let value = Self {
            ready_set_artifact_sha256: require_hex32_subject(
                parts[1],
                "RecoveryReady set artifact digest",
            )?,
            recovery_context_sha256: require_hex32_subject(
                parts[2],
                "RecoveryReady context digest",
            )?,
        };
        if value.encode() != subject {
            return Err(RuntimeEventErrorV1::Invalid("RecoveryReady subject"));
        }
        Ok(value)
    }
}

impl RecoveryStartSubjectV1 {
    fn encode(self) -> String {
        format!(
            "rsv1:{}:{}:{}",
            hex::encode(self.start_certificate_artifact_sha256),
            hex::encode(self.ready_set_artifact_sha256),
            hex::encode(self.recovery_context_sha256)
        )
    }

    fn decode(subject: &str) -> Result<Self, RuntimeEventErrorV1> {
        let parts = subject_parts_v1::<4>(subject, "rsv1", "RecoveryStart subject")?;
        let value = Self {
            start_certificate_artifact_sha256: require_hex32_subject(
                parts[1],
                "RecoveryStart certificate artifact digest",
            )?,
            ready_set_artifact_sha256: require_hex32_subject(
                parts[2],
                "RecoveryStart ReadySet artifact digest",
            )?,
            recovery_context_sha256: require_hex32_subject(
                parts[3],
                "RecoveryStart context digest",
            )?,
        };
        if value.encode() != subject {
            return Err(RuntimeEventErrorV1::Invalid("RecoveryStart subject"));
        }
        Ok(value)
    }
}

fn require_final_tip_subject(subject: &str) -> Result<(), RuntimeEventErrorV1> {
    decode_final_tip_subject(subject).map(|_| ())
}

type FinalTipCommitmentsV1 = ([u8; 32], [u8; 32], [u8; 32]);

fn decode_final_tip_subject(subject: &str) -> Result<FinalTipCommitmentsV1, RuntimeEventErrorV1> {
    let mut parts = subject.split(':');
    let block = require_hex32_subject(
        parts
            .next()
            .ok_or(RuntimeEventErrorV1::Invalid("final tip subject"))?,
        "final tip block",
    )?;
    let state = require_hex32_subject(
        parts
            .next()
            .ok_or(RuntimeEventErrorV1::Invalid("final tip subject"))?,
        "final tip state",
    )?;
    let chain = require_hex32_subject(
        parts
            .next()
            .ok_or(RuntimeEventErrorV1::Invalid("final tip subject"))?,
        "final tip chain",
    )?;
    if parts.next().is_some() {
        return Err(RuntimeEventErrorV1::Invalid("final tip subject"));
    }
    Ok((block, state, chain))
}

pub struct RuntimeEventJournalV1 {
    path: PathBuf,
    parent: File,
    parent_identity: RuntimeEventJournalParentIdentityV1,
    file: File,
    file_identity: RuntimeEventJournalFileIdentityV1,
    context: RuntimeEventContextV1,
    signing_key: SigningKey,
    process_instance: u64,
    next_sequence: u64,
    previous_event_sha256: [u8; 32],
    last_monotonic_ns: u64,
    started: Instant,
    state: RuntimeJournalStateV1,
    fail_stopped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeEventJournalParentIdentityV1 {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
}

impl RuntimeEventJournalParentIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Result<Self, RuntimeEventErrorV1> {
        if !metadata.is_dir() || metadata.nlink() == 0 {
            return Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal parent identity",
            ));
        }
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeEventJournalFileIdentityV1 {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
}

impl RuntimeEventJournalFileIdentityV1 {
    fn from_metadata_v1(metadata: &fs::Metadata) -> Result<Self, RuntimeEventErrorV1> {
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal file identity",
            ));
        }
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
        })
    }
}

impl fmt::Debug for RuntimeEventJournalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeEventJournalV1")
            .field("path", &self.path)
            .field("process_instance", &self.process_instance)
            .field("next_sequence", &self.next_sequence)
            .field("state", &self.state.observation(self.next_sequence))
            .field("fail_stopped", &self.fail_stopped)
            .finish_non_exhaustive()
    }
}

/// Non-Clone cross-process owner for the exact three immutable restart
/// certificates selected by one signed target `rpr1 -> rcp1 -> rpk1 -> rpa1`
/// journal suffix. The journal witness is descriptive data reconstructed from
/// that authenticated suffix; it grants no writer, signer, recovery, or
/// activation authority by itself.
#[must_use = "the reopened Cut/Park/ParkedAck triple must remain joined through process-2 start"]
pub(crate) struct ReopenedRestartCutParkAckCertificatesV1 {
    stored_cut_park: StoredRestartCutParkCertificatesV1,
    stored_ack: StoredRestartParkedAckCertificateV1,
    journal_witness: Process1TargetParkedAckJournalWitnessV1,
}

impl fmt::Debug for ReopenedRestartCutParkAckCertificatesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReopenedRestartCutParkAckCertificatesV1")
            .field(
                "local_validator",
                &self.stored_cut_park.local_validator_v1(),
            )
            .field(
                "restart_cut_artifact_sha256",
                &hex::encode(self.stored_cut_park.cut_artifact_sha256_v1()),
            )
            .field(
                "restart_park_artifact_sha256",
                &hex::encode(self.stored_cut_park.park_artifact_sha256_v1()),
            )
            .field(
                "restart_parked_ack_artifact_sha256",
                &hex::encode(self.stored_ack.artifact_sha256_v1()),
            )
            .field(
                "restart_parked_ack_admission_set_sha256",
                &hex::encode(self.journal_witness.ack_admission_set_sha256),
            )
            .finish_non_exhaustive()
    }
}

impl ReopenedRestartCutParkAckCertificatesV1 {
    fn revalidate_fresh_v1(&self) -> Result<(), RuntimeEventErrorV1> {
        self.stored_cut_park.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "reopened RestartCut/RestartPark pair failed authenticated fresh readback",
            )
        })?;
        self.stored_ack
            .revalidate_fresh_v1(
                self.stored_cut_park.fleet_start_certificate_v1(),
                self.stored_cut_park.validator_set_v1(),
            )
            .map_err(|_| {
                RuntimeEventErrorV1::Invalid(
                    "reopened RestartParkedAck certificate failed authenticated fresh readback",
                )
            })?;
        let common = self.stored_ack.common_v1();
        let local_ack = self.stored_ack.local_statement_v1();
        let witness = self.stored_ack.local_witness_v1();
        let expected_count = self.stored_cut_park.validator_set_v1().validators().len();
        let fleet_start_sha256: [u8; 32] =
            Sha256::digest(self.stored_cut_park.fleet_start_certificate_v1().encode()).into();
        let message_ids = self
            .stored_ack
            .value_v1()
            .statements()
            .iter()
            .map(|statement| {
                (
                    statement.origin(),
                    restart_protocol_message_id_for_parts_v1(
                        self.stored_cut_park.validator_set_v1().id(),
                        statement.origin(),
                        RestartProtocolPhaseV1::ParkedAck,
                        &statement.encode(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let derived_ack_admission_set_sha256 = restart_parked_ack_admission_set_sha256_for_ids_v1(
            &message_ids,
            self.stored_cut_park.validator_set_v1(),
        )
        .map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "reopened RestartParkedAck certificate has no exact direct-seven admission digest",
            )
        })?;
        if self.stored_cut_park.local_role_v1() != RestartParkRoleV1::Target
            || self.stored_cut_park.body_v1().process_instance() != 1
            || self.stored_cut_park.body_v1().target_validator()
                != self.stored_cut_park.local_validator_v1()
            || self.stored_cut_park.body_v1().target_config_sha256()
                != self.stored_cut_park.local_config_sha256_v1()
            || self.stored_cut_park.cut_artifact_sha256_v1()
                != self.journal_witness.cut_artifact_sha256
            || self.stored_cut_park.park_artifact_sha256_v1()
                != self.journal_witness.park_artifact_sha256
            || self.stored_cut_park.body_v1().digest() != self.journal_witness.body_sha256
            || self.stored_cut_park.admission_set_sha256_v1()
                != self.journal_witness.cut_park_admission_set_sha256
            || self.stored_cut_park.local_park_statement_sha256_v1()
                != self.journal_witness.local_park_statement_sha256
            || self.stored_ack.artifact_sha256_v1() != self.journal_witness.ack_artifact_sha256
            || self.stored_ack.local_statement_sha256_v1()
                != self.journal_witness.local_ack_statement_sha256
            || self.stored_ack.restart_cut_certificate_v1()
                != self.stored_cut_park.cut_certificate_v1()
            || self.stored_ack.restart_park_certificate_v1()
                != self.stored_cut_park.park_certificate_v1()
            || self.stored_ack.restart_cut_artifact_sha256_v1()
                != self.stored_cut_park.cut_artifact_sha256_v1()
            || self.stored_ack.restart_park_artifact_sha256_v1()
                != self.stored_cut_park.park_artifact_sha256_v1()
            || self.stored_ack.restart_cut_park_admission_set_sha256_v1()
                != self.stored_cut_park.admission_set_sha256_v1()
            || self.stored_ack.local_validator_v1() != self.stored_cut_park.local_validator_v1()
            || self.stored_ack.local_config_sha256_v1()
                != self.stored_cut_park.local_config_sha256_v1()
            || witness != self.journal_witness.local_witness
            || witness.role_v1() != RestartParkRoleV1::Target
            || common.target_validator() != self.stored_cut_park.local_validator_v1()
            || common.process_instance() != 1
            || common.validator_set_id() != self.stored_cut_park.validator_set_v1().id()
            || common.fleet_start_certificate_sha256() != fleet_start_sha256
            || common.restart_cut_body_sha256() != self.stored_cut_park.body_v1().digest()
            || common.restart_cut_artifact_sha256() != self.stored_cut_park.cut_artifact_sha256_v1()
            || common.restart_park_artifact_sha256()
                != self.stored_cut_park.park_artifact_sha256_v1()
            || common.restart_cut_park_admission_set_sha256()
                != self.stored_cut_park.admission_set_sha256_v1()
            || local_ack.origin() != self.stored_cut_park.local_validator_v1()
            || local_ack.role() != RestartParkRoleV1::Target
            || local_ack.local_config_sha256() != self.stored_cut_park.local_config_sha256_v1()
            || local_ack.local_park_statement_sha256()
                != self.stored_cut_park.local_park_statement_sha256_v1()
            || local_ack.predecessor_sequence() != witness.predecessor_sequence_v1()
            || local_ack.predecessor_sha256() != witness.predecessor_sha256_v1()
            || local_ack.restart_cut_event_sequence() != witness.restart_cut_event_sequence_v1()
            || local_ack.restart_cut_event_sha256() != witness.restart_cut_event_sha256_v1()
            || local_ack.restart_park_event_sequence() != witness.restart_park_event_sequence_v1()
            || local_ack.restart_park_event_sha256() != witness.restart_park_event_sha256_v1()
            || self.journal_witness.ack_admission_set_sha256 == [0; 32]
            || derived_ack_admission_set_sha256 != self.journal_witness.ack_admission_set_sha256
            || self.stored_cut_park.statement_count_v1() != expected_count
            || self.stored_ack.statement_count_v1() != expected_count
            || expected_count != 7
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "reopened Cut/Park/ParkedAck triple differs across artifacts, local statements, admission sets, or journal witness",
            ));
        }
        Ok(())
    }

    pub(crate) const fn stored_cut_park_v1(&self) -> &StoredRestartCutParkCertificatesV1 {
        &self.stored_cut_park
    }

    pub(crate) const fn stored_ack_v1(&self) -> &StoredRestartParkedAckCertificateV1 {
        &self.stored_ack
    }

    pub(crate) const fn ack_admission_set_sha256_v1(&self) -> [u8; 32] {
        self.journal_witness.ack_admission_set_sha256
    }
}

/// Linear proof that process 2 was opened from one authenticated, freshly
/// read N/N RestartCut/RestartPark/RestartParkedAck triple and that its durable
/// `process_start -> restart` successor is still the journal head. This owner
/// retains all three artifacts and the exclusively locked journal; copying scalar
/// identities can never recreate the process-start authority.
#[must_use = "process-2 journal authority must be consumed by the full inert-recovery join"]
pub(crate) struct Process2JournalStartedFromRestartCutV1 {
    journal: RuntimeEventJournalV1,
    stored: ReopenedRestartCutParkAckCertificatesV1,
    restart_prepare_request_sha256: [u8; 32],
    journal_start_head: (u64, [u8; 32]),
}

impl fmt::Debug for Process2JournalStartedFromRestartCutV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Process2JournalStartedFromRestartCutV1")
            .field("process_instance", &self.journal.process_instance())
            .field(
                "restart_cut_artifact_sha256",
                &hex::encode(self.stored.stored_cut_park.cut_artifact_sha256_v1()),
            )
            .field(
                "restart_cut_statement_count",
                &self.stored.stored_cut_park.statement_count_v1(),
            )
            .field(
                "restart_park_artifact_sha256",
                &hex::encode(self.stored.stored_cut_park.park_artifact_sha256_v1()),
            )
            .field(
                "restart_parked_ack_artifact_sha256",
                &hex::encode(self.stored.stored_ack.artifact_sha256_v1()),
            )
            .field(
                "restart_prepare_request_sha256",
                &hex::encode(self.restart_prepare_request_sha256),
            )
            .field("journal_start_head", &self.journal_start_head)
            .finish_non_exhaustive()
    }
}

impl Process2JournalStartedFromRestartCutV1 {
    fn start_with_context_v1(
        path: &Path,
        context: RuntimeEventContextV1,
        signing_key: SigningKey,
        stored: ReopenedRestartCutParkAckCertificatesV1,
    ) -> Result<Self, RuntimeEventErrorV1> {
        stored.revalidate_fresh_v1()?;
        let cut_park = stored.stored_cut_park_v1();
        let stored_ack = stored.stored_ack_v1();
        let restart_cut_artifact_sha256 = cut_park.cut_artifact_sha256_v1();
        let restart_park_artifact_sha256 = cut_park.park_artifact_sha256_v1();
        let restart_ack_artifact_sha256 = stored_ack.artifact_sha256_v1();
        let restart_cut_statement_count = cut_park.statement_count_v1();
        let statement_count = u64::try_from(restart_cut_statement_count)
            .map_err(|_| RuntimeEventErrorV1::Invalid("RestartCut statement count overflows"))?;
        let journal = RuntimeEventJournalV1::start_with_context_gate(
            path,
            context,
            signing_key,
            ProcessStartGateV1::StoredRestartCutParkAck(&stored),
        )?;
        let journal_start_head = journal
            .last_event_facts()
            .ok_or(RuntimeEventErrorV1::Invalid(
                "process2 journal start lacks a durable head",
            ))?;
        let events = read_exact_events(&journal.file)?;
        let ancestry = process2_restart_ancestry_v1(&events)?;
        let restart_prepare_request_sha256 = ancestry.request_sha256;
        if journal.process_instance() != 2
            || journal.restart_cut_facts_v1()
                != Some((restart_cut_artifact_sha256, statement_count))
            || ancestry.cut_park.cut_artifact_sha256 != restart_cut_artifact_sha256
            || ancestry.cut_park.park_artifact_sha256 != restart_park_artifact_sha256
            || ancestry.cut_park.body_sha256 != cut_park.body_v1().digest()
            || ancestry.cut_park.admission_set_sha256 != cut_park.admission_set_sha256_v1()
            || ancestry.park.park_artifact_sha256 != restart_park_artifact_sha256
            || ancestry.park.local_park_statement_sha256
                != cut_park.local_park_statement_sha256_v1()
            || ancestry.parked_ack.ack_certificate_sha256 != restart_ack_artifact_sha256
            || ancestry.parked_ack.local_ack_statement_sha256
                != stored_ack.local_statement_sha256_v1()
            || ancestry.parked_ack.cut_artifact_sha256 != restart_cut_artifact_sha256
            || ancestry.parked_ack.park_artifact_sha256 != restart_park_artifact_sha256
            || ancestry.parked_ack.ack_admission_set_sha256 != stored.ack_admission_set_sha256_v1()
            || ancestry.parked_ack_event_head
                != (
                    stored.journal_witness.parked_ack_event_sequence,
                    stored.journal_witness.parked_ack_event_sha256,
                )
            || ancestry.request_sha256 != stored.journal_witness.restart_prepare_request_sha256
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "process2 journal start differs from consumed RestartCut/RestartPark/RestartParkedAck triple",
            ));
        }
        stored.revalidate_fresh_v1()?;
        Ok(Self {
            journal,
            stored,
            restart_prepare_request_sha256,
            journal_start_head,
        })
    }

    pub(crate) const fn process_instance_v1(&self) -> u64 {
        self.journal.process_instance()
    }

    pub(crate) const fn restart_cut_body_v1(&self) -> &RestartCutBodyV1 {
        self.stored.stored_cut_park.body_v1()
    }

    pub(crate) const fn restart_cut_artifact_sha256_v1(&self) -> [u8; 32] {
        self.stored.stored_cut_park.cut_artifact_sha256_v1()
    }

    pub(crate) const fn restart_park_artifact_sha256_v1(&self) -> [u8; 32] {
        self.stored.stored_cut_park.park_artifact_sha256_v1()
    }

    pub(crate) const fn restart_admission_set_sha256_v1(&self) -> [u8; 32] {
        self.stored.stored_cut_park.admission_set_sha256_v1()
    }

    pub(crate) const fn restart_local_park_statement_sha256_v1(&self) -> [u8; 32] {
        self.stored.stored_cut_park.local_park_statement_sha256_v1()
    }

    pub(crate) const fn restart_cut_statement_count_v1(&self) -> usize {
        self.stored.stored_cut_park.statement_count_v1()
    }

    pub(crate) const fn stored_cut_park_v1(&self) -> &StoredRestartCutParkCertificatesV1 {
        &self.stored.stored_cut_park
    }

    pub(crate) const fn stored_parked_ack_v1(&self) -> &StoredRestartParkedAckCertificateV1 {
        &self.stored.stored_ack
    }

    pub(crate) const fn restart_parked_ack_artifact_sha256_v1(&self) -> [u8; 32] {
        self.stored.stored_ack.artifact_sha256_v1()
    }

    pub(crate) const fn restart_parked_ack_admission_set_sha256_v1(&self) -> [u8; 32] {
        self.stored.ack_admission_set_sha256_v1()
    }

    /// Exact canonical runtime-control request SHA-256 retained from the
    /// process-1 `restart_prepare` subject. This is inert identity data only;
    /// the journal owner remains the sole authority for fresh validation.
    pub(crate) const fn restart_prepare_request_sha256_v1(&self) -> [u8; 32] {
        self.restart_prepare_request_sha256
    }

    pub(crate) fn revalidate_unchanged_start_v1(&self) -> Result<(), RuntimeEventErrorV1> {
        self.stored.revalidate_fresh_v1()?;
        let cut_park = self.stored.stored_cut_park_v1();
        let stored_ack = self.stored.stored_ack_v1();
        let statement_count = u64::try_from(cut_park.statement_count_v1())
            .map_err(|_| RuntimeEventErrorV1::Invalid("RestartCut statement count overflows"))?;
        let events = read_exact_events(&self.journal.file)?;
        let recovered = validate_event_chain(&events, &self.journal.context)?;
        let ancestry = process2_restart_ancestry_v1(&events)?;
        let restart_prepare_request_sha256 = ancestry.request_sha256;
        let restart = events.last().ok_or(RuntimeEventErrorV1::Invalid(
            "process2 journal start lacks restart event",
        ))?;
        let process_start = events
            .len()
            .checked_sub(2)
            .and_then(|index| events.get(index))
            .ok_or(RuntimeEventErrorV1::Invalid(
                "process2 journal start lacks process-start event",
            ))?;
        if self.journal.process_instance() != 2
            || self.journal.last_event_facts() != Some(self.journal_start_head)
            || self.journal.restart_cut_facts_v1()
                != Some((cut_park.cut_artifact_sha256_v1(), statement_count))
            || ancestry.cut_park.cut_artifact_sha256 != cut_park.cut_artifact_sha256_v1()
            || ancestry.cut_park.park_artifact_sha256 != cut_park.park_artifact_sha256_v1()
            || ancestry.cut_park.body_sha256 != cut_park.body_v1().digest()
            || ancestry.cut_park.admission_set_sha256 != cut_park.admission_set_sha256_v1()
            || ancestry.park.park_artifact_sha256 != cut_park.park_artifact_sha256_v1()
            || ancestry.park.local_park_statement_sha256
                != cut_park.local_park_statement_sha256_v1()
            || ancestry.parked_ack.ack_certificate_sha256 != stored_ack.artifact_sha256_v1()
            || ancestry.parked_ack.local_ack_statement_sha256
                != stored_ack.local_statement_sha256_v1()
            || ancestry.parked_ack.cut_artifact_sha256 != cut_park.cut_artifact_sha256_v1()
            || ancestry.parked_ack.park_artifact_sha256 != cut_park.park_artifact_sha256_v1()
            || ancestry.parked_ack.ack_admission_set_sha256
                != self.stored.ack_admission_set_sha256_v1()
            || ancestry.parked_ack_event_head
                != (
                    self.stored.journal_witness.parked_ack_event_sequence,
                    self.stored.journal_witness.parked_ack_event_sha256,
                )
            || restart_prepare_request_sha256 != self.restart_prepare_request_sha256
            || recovered.process_instance != self.journal.process_instance
            || recovered.next_sequence != self.journal.next_sequence
            || recovered.previous_event_sha256 != self.journal.previous_event_sha256
            || recovered.state != self.journal.state
            || restart.kind != RuntimeEventKindV1::Restart.as_str()
            || restart.process_instance != 2
            || restart.sequence != self.journal_start_head.0
            || restart.event_sha256 != hex::encode(self.journal_start_head.1)
            || process_start.kind != "process_start"
            || process_start.process_instance != 2
            || process_start
                .sequence
                .checked_add(1)
                .is_none_or(|sequence| sequence != restart.sequence)
            || restart.previous_event_sha256 != process_start.event_sha256
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "process2 journal changed before the full inert-recovery join",
            ));
        }
        Ok(())
    }

    /// Narrow fail-stop sink used only after the consuming full-recovery join.
    /// It does not expose a general mutable journal, signer, timer, or network
    /// handle to the joined owner.
    pub(crate) fn record_joined_inert_safety_halted_v1(
        &mut self,
        subject: &str,
        value: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        self.journal
            .append(RuntimeEventKindV1::SafetyHalted, subject, value)
    }

    #[cfg(test)]
    fn journal_v1(&self) -> &RuntimeEventJournalV1 {
        &self.journal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Process2RestartAncestryV1 {
    request_sha256: [u8; 32],
    cut_park: RestartCutParkSubjectV1,
    park: RestartParkSubjectV1,
    parked_ack: RestartParkedAckSubjectV1,
    parked_ack_event_head: (u64, [u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Process1TargetParkedAckJournalWitnessV1 {
    restart_prepare_request_sha256: [u8; 32],
    fleet_start_certificate_sha256: [u8; 32],
    cut_artifact_sha256: [u8; 32],
    park_artifact_sha256: [u8; 32],
    body_sha256: [u8; 32],
    cut_park_admission_set_sha256: [u8; 32],
    local_park_statement_sha256: [u8; 32],
    ack_artifact_sha256: [u8; 32],
    local_ack_statement_sha256: [u8; 32],
    ack_admission_set_sha256: [u8; 32],
    local_witness: RestartParkedAckLocalWitnessV1,
    statement_count: u64,
    parked_ack_event_sequence: u64,
    parked_ack_event_sha256: [u8; 32],
}

fn process1_target_parked_ack_journal_witness_v1(
    events: &[SignedRuntimeEventV1],
    recovered: &RecoveredJournalV1,
    context: &RuntimeEventContextV1,
) -> Result<Process1TargetParkedAckJournalWitnessV1, RuntimeEventErrorV1> {
    let [.., restart_prepare, restart_cut, restart_park, restart_parked_ack] = events else {
        return Err(RuntimeEventErrorV1::Invalid(
            "process1 journal lacks the exact target rpr1 -> rcp1 -> rpk1 -> rpa1 suffix",
        ));
    };
    let parked_ack = match recovered.state.restart {
        RuntimeRestartJournalStateV1::ParkedAcked(facts)
            if facts.parked.cut_park.preparation.role_v1() == RestartParkRoleV1::Target =>
        {
            facts
        }
        _ => {
            return Err(RuntimeEventErrorV1::Invalid(
                "process1 journal lacks one exact target ParkedAck commit",
            ));
        }
    };
    let parked = parked_ack.parked;
    let RestartPreparationJournalV1::Target(target_prepare) = parked.cut_park.preparation else {
        return Err(RuntimeEventErrorV1::Invalid(
            "process1 ParkedAck predecessor is not the target preparation",
        ));
    };
    let restart_prepare_request_sha256 = decode_hex::<32>(
        &restart_prepare.subject,
        "restart prepare canonical request SHA-256",
    )?;
    let restart_prepare_sha256 =
        decode_hex::<32>(&restart_prepare.event_sha256, "restart prepare event hash")?;
    let restart_cut_sha256 = decode_hex::<32>(&restart_cut.event_sha256, "restart cut event hash")?;
    let restart_park_sha256 =
        decode_hex::<32>(&restart_park.event_sha256, "restart park event hash")?;
    let restart_parked_ack_sha256 = decode_hex::<32>(
        &restart_parked_ack.event_sha256,
        "restart parked acknowledgement event hash",
    )?;
    let cut_park_subject = RestartCutParkSubjectV1::decode(&restart_cut.subject)?;
    let park_subject = RestartParkSubjectV1::decode(&restart_park.subject)?;
    let ack_subject = RestartParkedAckSubjectV1::decode(&restart_parked_ack.subject)?;
    let expected_statement_count = u64::try_from(context.validator_set.validators().len())
        .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
    let fleet_start_certificate_sha256 =
        recovered
            .state
            .fleet_start_certificate_sha256
            .ok_or(RuntimeEventErrorV1::Invalid(
                "process1 target ParkedAck lacks FleetStart",
            ))?;
    if recovered.process_instance != 1
        || recovered.state.current_instance != 1
        || recovered.state.last_kind.as_deref() != Some("restart_parked_ack")
        || context.validator_set.validators().len() != 7
        || restart_prepare_request_sha256 == [0; 32]
        || restart_prepare.kind != "restart_prepare"
        || restart_prepare.process_instance != 1
        || restart_prepare.value == 0
        || restart_cut.kind != "restart_cut"
        || restart_cut.process_instance != 1
        || restart_cut.value != expected_statement_count
        || restart_park.kind != "restart_park"
        || restart_park.process_instance != 1
        || restart_park.value != expected_statement_count
        || restart_parked_ack.kind != "restart_parked_ack"
        || restart_parked_ack.process_instance != 1
        || restart_parked_ack.value != expected_statement_count
        || restart_prepare.sequence.checked_add(1) != Some(restart_cut.sequence)
        || restart_cut.sequence.checked_add(1) != Some(restart_park.sequence)
        || restart_park.sequence.checked_add(1) != Some(restart_parked_ack.sequence)
        || restart_parked_ack.sequence.checked_add(1) != Some(recovered.next_sequence)
        || restart_cut.previous_event_sha256 != restart_prepare.event_sha256
        || restart_park.previous_event_sha256 != restart_cut.event_sha256
        || restart_parked_ack.previous_event_sha256 != restart_park.event_sha256
        || recovered.previous_event_sha256 != restart_parked_ack_sha256
        || target_prepare.request_sha256 != restart_prepare_request_sha256
        || target_prepare.nonce != restart_prepare.value
        || target_prepare.prepare_head != (restart_prepare.sequence, restart_prepare_sha256)
        || parked.cut_park.subject != cut_park_subject
        || parked.cut_park.statement_count != expected_statement_count
        || parked.subject != park_subject
        || parked_ack.subject != ack_subject
        || parked_ack.statement_count != expected_statement_count
        || park_subject.park_artifact_sha256 != cut_park_subject.park_artifact_sha256
        || ack_subject.cut_artifact_sha256 != cut_park_subject.cut_artifact_sha256
        || ack_subject.park_artifact_sha256 != park_subject.park_artifact_sha256
        || cut_park_subject.cut_artifact_sha256 == [0; 32]
        || cut_park_subject.park_artifact_sha256 == [0; 32]
        || cut_park_subject.body_sha256 == [0; 32]
        || cut_park_subject.admission_set_sha256 == [0; 32]
        || park_subject.local_park_statement_sha256 == [0; 32]
        || ack_subject.ack_certificate_sha256 == [0; 32]
        || ack_subject.local_ack_statement_sha256 == [0; 32]
        || ack_subject.ack_admission_set_sha256 == [0; 32]
        || fleet_start_certificate_sha256 == [0; 32]
    {
        return Err(RuntimeEventErrorV1::Invalid(
            "process1 target ParkedAck commit differs from its exact signed journal suffix",
        ));
    }
    let local_witness = RestartParkedAckLocalWitnessV1::new(
        RestartParkRoleV1::Target,
        park_subject.local_park_statement_sha256,
        restart_prepare.sequence,
        restart_prepare_sha256,
        restart_cut.sequence,
        restart_cut_sha256,
        restart_park.sequence,
        restart_park_sha256,
    )
    .map_err(|_| {
        RuntimeEventErrorV1::Invalid(
            "process1 target ParkedAck local witness is not the exact journal suffix",
        )
    })?;
    Ok(Process1TargetParkedAckJournalWitnessV1 {
        restart_prepare_request_sha256,
        fleet_start_certificate_sha256,
        cut_artifact_sha256: cut_park_subject.cut_artifact_sha256,
        park_artifact_sha256: cut_park_subject.park_artifact_sha256,
        body_sha256: cut_park_subject.body_sha256,
        cut_park_admission_set_sha256: cut_park_subject.admission_set_sha256,
        local_park_statement_sha256: park_subject.local_park_statement_sha256,
        ack_artifact_sha256: ack_subject.ack_certificate_sha256,
        local_ack_statement_sha256: ack_subject.local_ack_statement_sha256,
        ack_admission_set_sha256: ack_subject.ack_admission_set_sha256,
        local_witness,
        statement_count: expected_statement_count,
        parked_ack_event_sequence: restart_parked_ack.sequence,
        parked_ack_event_sha256: restart_parked_ack_sha256,
    })
}

fn read_process1_target_parked_ack_journal_witness_v1(
    path: &Path,
    context: &RuntimeEventContextV1,
) -> Result<Process1TargetParkedAckJournalWitnessV1, RuntimeEventErrorV1> {
    let (_path, _parent, file) = open_locked_journal(path, false)?;
    let events = read_exact_events(&file)?;
    let recovered = validate_event_chain(&events, context)?;
    process1_target_parked_ack_journal_witness_v1(&events, &recovered, context)
}

fn load_target_restart_cut_park_ack_certificates_v1(
    config: &LoadedValidatorConfig,
    journal_witness: Process1TargetParkedAckJournalWitnessV1,
) -> Result<ReopenedRestartCutParkAckCertificatesV1, RuntimeEventErrorV1> {
    let stored_cut_park = load_target_restart_cut_park_certificates_v1(
        config,
        journal_witness.cut_artifact_sha256,
        journal_witness.park_artifact_sha256,
        journal_witness.body_sha256,
        journal_witness.cut_park_admission_set_sha256,
        journal_witness.local_park_statement_sha256,
    )
    .map_err(|_| {
        RuntimeEventErrorV1::Invalid(
            "load target RestartCut/RestartPark pair selected by rcp1/rpk1",
        )
    })?;
    let stored_ack = load_restart_parked_ack_certificate_v1(
        config.run_root(),
        journal_witness.ack_artifact_sha256,
        stored_cut_park.cut_artifact_sha256_v1(),
        stored_cut_park.cut_certificate_v1(),
        stored_cut_park.park_artifact_sha256_v1(),
        stored_cut_park.park_certificate_v1(),
        stored_cut_park.admission_set_sha256_v1(),
        config.local_validator(),
        config.config_sha256(),
        journal_witness.local_witness,
        stored_cut_park.fleet_start_certificate_v1(),
        config.validator_set(),
    )
    .map_err(|_| {
        RuntimeEventErrorV1::Invalid("load target RestartParkedAck certificate selected by rpa1")
    })?;
    let value = ReopenedRestartCutParkAckCertificatesV1 {
        stored_cut_park,
        stored_ack,
        journal_witness,
    };
    value.revalidate_fresh_v1()?;
    let fleet_start_sha256: [u8; 32] =
        Sha256::digest(value.stored_cut_park.fleet_start_certificate_v1().encode()).into();
    if fleet_start_sha256 != value.journal_witness.fleet_start_certificate_sha256 {
        return Err(RuntimeEventErrorV1::Invalid(
            "reopened Cut/Park/ParkedAck triple differs from journal FleetStart",
        ));
    }
    Ok(value)
}

fn process2_restart_ancestry_v1(
    events: &[SignedRuntimeEventV1],
) -> Result<Process2RestartAncestryV1, RuntimeEventErrorV1> {
    let [.., restart_prepare, restart_cut, restart_park, restart_parked_ack, process_start, restart] =
        events
    else {
        return Err(RuntimeEventErrorV1::Invalid(
            "process2 journal lacks the exact restart request ancestry",
        ));
    };
    let request_sha256 = decode_hex::<32>(
        &restart_prepare.subject,
        "restart prepare canonical request SHA-256",
    )?;
    let cut_park = RestartCutParkSubjectV1::decode(&restart_cut.subject)?;
    let park = RestartParkSubjectV1::decode(&restart_park.subject)?;
    let parked_ack = RestartParkedAckSubjectV1::decode(&restart_parked_ack.subject)?;
    let parked_ack_event_sha256 = decode_hex::<32>(
        &restart_parked_ack.event_sha256,
        "restart parked acknowledgement event hash",
    )?;
    if request_sha256 == [0; 32]
        || restart_prepare.kind != "restart_prepare"
        || restart_prepare.process_instance != 1
        || restart_prepare.value == 0
        || restart_cut.kind != "restart_cut"
        || restart_cut.process_instance != 1
        || restart_cut.value == 0
        || restart_park.kind != "restart_park"
        || restart_park.process_instance != 1
        || restart_park.value != restart_cut.value
        || park.park_artifact_sha256 != cut_park.park_artifact_sha256
        || restart_parked_ack.kind != "restart_parked_ack"
        || restart_parked_ack.process_instance != 1
        || restart_parked_ack.value != restart_park.value
        || parked_ack.cut_artifact_sha256 != cut_park.cut_artifact_sha256
        || parked_ack.park_artifact_sha256 != park.park_artifact_sha256
        || process_start.kind != "process_start"
        || process_start.process_instance != 2
        || process_start.subject != "instance-2"
        || process_start.value == 0
        || restart.kind != RuntimeEventKindV1::Restart.as_str()
        || restart.process_instance != 2
        || restart.subject != "instance-2"
        || restart.value != process_start.value
        || restart_prepare.sequence.checked_add(1) != Some(restart_cut.sequence)
        || restart_cut.sequence.checked_add(1) != Some(restart_park.sequence)
        || restart_park.sequence.checked_add(1) != Some(restart_parked_ack.sequence)
        || restart_parked_ack.sequence.checked_add(1) != Some(process_start.sequence)
        || process_start.sequence.checked_add(1) != Some(restart.sequence)
        || restart_cut.previous_event_sha256 != restart_prepare.event_sha256
        || restart_park.previous_event_sha256 != restart_cut.event_sha256
        || restart_parked_ack.previous_event_sha256 != restart_park.event_sha256
        || process_start.previous_event_sha256 != restart_parked_ack.event_sha256
        || restart.previous_event_sha256 != process_start.event_sha256
    {
        return Err(RuntimeEventErrorV1::Invalid(
            "process2 journal restart request ancestry changed",
        ));
    }
    Ok(Process2RestartAncestryV1 {
        request_sha256,
        cut_park,
        park,
        parked_ack,
        parked_ack_event_head: (restart_parked_ack.sequence, parked_ack_event_sha256),
    })
}

#[derive(Clone, Copy)]
enum ProcessStartGateV1<'a> {
    InitialProcessOnly,
    StoredRestartCutParkAck(&'a ReopenedRestartCutParkAckCertificatesV1),
    #[cfg(test)]
    UnverifiedTestRestart,
}

impl RuntimeEventJournalV1 {
    /// Opens and exclusively locks one exact journal, verifies its complete
    /// signed ancestry, then appends the next process-start event. The caller
    /// should retain this owner for the process lifetime.
    pub fn start(
        path: impl AsRef<Path>,
        config: &LoadedValidatorConfig,
    ) -> Result<Self, RuntimeEventErrorV1> {
        if !config.has_local_consensus_secret() {
            return Err(RuntimeEventErrorV1::ExternalAuthorityRequired);
        }
        let context = RuntimeEventContextV1::from_loaded_config(config);
        Self::start_with_context_gate(
            path.as_ref(),
            context,
            config.consensus_signing_key().clone(),
            ProcessStartGateV1::InitialProcessOnly,
        )
    }

    /// Compatibility spelling retained for the current bounded-runtime
    /// caller. Despite the historical name, this now reopens and consumes the
    /// exact journal-selected Cut/Park/ParkedAck triple; it has no pair-only
    /// fallback.
    pub(crate) fn start_process2_with_stored_restart_cut_v1(
        path: impl AsRef<Path>,
        config: &LoadedValidatorConfig,
    ) -> Result<Process2JournalStartedFromRestartCutV1, RuntimeEventErrorV1> {
        Self::start_process2_with_stored_restart_cut_park_ack_v1(path, config)
    }

    /// Reopens the exact target process-1 journal-selected Cut/Park/ParkedAck
    /// triple, then consumes it through the only normal process-2 start gate.
    pub(crate) fn start_process2_with_stored_restart_cut_park_ack_v1(
        path: impl AsRef<Path>,
        config: &LoadedValidatorConfig,
    ) -> Result<Process2JournalStartedFromRestartCutV1, RuntimeEventErrorV1> {
        if !config.has_local_consensus_secret() {
            return Err(RuntimeEventErrorV1::ExternalAuthorityRequired);
        }
        let context = RuntimeEventContextV1::from_loaded_config(config);
        let journal_witness =
            read_process1_target_parked_ack_journal_witness_v1(path.as_ref(), &context)?;
        let stored = load_target_restart_cut_park_ack_certificates_v1(config, journal_witness)?;
        Process2JournalStartedFromRestartCutV1::start_with_context_v1(
            path.as_ref(),
            context,
            config.consensus_signing_key().clone(),
            stored,
        )
    }

    /// Test-only compatibility entry for exercising the historical two-
    /// process event grammar without granting the normal build an unverified
    /// restart transition. Operational process-2 startup must use the later
    /// typed RestartCut gate, never this helper.
    #[cfg(test)]
    pub(crate) fn start_with_context(
        path: &Path,
        context: RuntimeEventContextV1,
        signing_key: SigningKey,
    ) -> Result<Self, RuntimeEventErrorV1> {
        Self::start_with_context_gate(
            path,
            context,
            signing_key,
            ProcessStartGateV1::UnverifiedTestRestart,
        )
    }

    #[cfg(test)]
    fn start_process2_with_context_and_stored_restart_cut_v1(
        path: &Path,
        context: RuntimeEventContextV1,
        signing_key: SigningKey,
        stored: StoredRestartCutParkCertificatesV1,
    ) -> Result<Process2JournalStartedFromRestartCutV1, RuntimeEventErrorV1> {
        stored.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "stored RestartCut/RestartPark pair failed authenticated fresh readback",
            )
        })?;
        let _ = (path, context, signing_key);
        Err(RuntimeEventErrorV1::Invalid(
            "legacy Cut/Park-only process-2 gate lacks the stored ParkedAck certificate",
        ))
    }

    fn start_with_context_gate(
        path: &Path,
        context: RuntimeEventContextV1,
        signing_key: SigningKey,
        gate: ProcessStartGateV1<'_>,
    ) -> Result<Self, RuntimeEventErrorV1> {
        context.validate(&signing_key)?;
        match gate {
            ProcessStartGateV1::StoredRestartCutParkAck(stored) => {
                stored.revalidate_fresh_v1()?;
            }
            ProcessStartGateV1::InitialProcessOnly => {}
            #[cfg(test)]
            ProcessStartGateV1::UnverifiedTestRestart => {}
        }
        let create_if_missing = !matches!(gate, ProcessStartGateV1::StoredRestartCutParkAck(_));
        let (path, parent, file) = open_locked_journal(path, create_if_missing)?;
        let parent_identity = RuntimeEventJournalParentIdentityV1::from_metadata_v1(
            &parent.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        let file_identity = RuntimeEventJournalFileIdentityV1::from_metadata_v1(
            &file.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        let events = read_exact_events(&file)?;
        let recovered = validate_event_chain(&events, &context)?;
        let process_instance = recovered
            .process_instance
            .checked_add(1)
            .ok_or(RuntimeEventErrorV1::Invalid("process instance overflow"))?;
        match gate {
            ProcessStartGateV1::InitialProcessOnly
                if matches!(
                    recovered.state.restart,
                    RuntimeRestartJournalStateV1::LegacyUnparked { .. }
                ) =>
            {
                return Err(RuntimeEventErrorV1::Invalid(
                    "legacy RestartCut lacks durable RestartPark authority",
                ));
            }
            ProcessStartGateV1::InitialProcessOnly
                if process_instance == 2
                    && matches!(
                        recovered.state.restart,
                        RuntimeRestartJournalStateV1::Parked(facts)
                            if facts.cut_park.preparation.role_v1()
                                == RestartParkRoleV1::Target
                    ) =>
            {
                return Err(RuntimeEventErrorV1::Invalid(
                    "process-1 target Park is still waiting for the exact N/N ParkedAck",
                ));
            }
            ProcessStartGateV1::InitialProcessOnly
                if process_instance == 2
                    && matches!(
                        recovered.state.restart,
                        RuntimeRestartJournalStateV1::ParkedAcked(facts)
                            if facts.parked.cut_park.preparation.role_v1()
                                == RestartParkRoleV1::Target
                    ) =>
            {
                return Err(RuntimeEventErrorV1::RestartCutRequiredForProcess2);
            }
            ProcessStartGateV1::InitialProcessOnly if process_instance == 2 => {
                return Err(RuntimeEventErrorV1::Invalid(
                    "process-1 journal lacks one target Park predecessor",
                ));
            }
            ProcessStartGateV1::InitialProcessOnly if process_instance > 2 => {
                return Err(RuntimeEventErrorV1::Invalid(
                    "runtime event journal exceeds the bounded two-process contract",
                ));
            }
            ProcessStartGateV1::StoredRestartCutParkAck(stored) => {
                validate_process2_restart_cut_park_ack_predecessor_v1(
                    &events, &recovered, &context, stored,
                )?;
            }
            ProcessStartGateV1::InitialProcessOnly => {}
            #[cfg(test)]
            ProcessStartGateV1::UnverifiedTestRestart => {}
        }
        match gate {
            ProcessStartGateV1::StoredRestartCutParkAck(stored) => {
                stored.revalidate_fresh_v1()?;
            }
            ProcessStartGateV1::InitialProcessOnly => {}
            #[cfg(test)]
            ProcessStartGateV1::UnverifiedTestRestart => {}
        }
        let mut journal = Self {
            path,
            parent,
            parent_identity,
            file,
            file_identity,
            context,
            signing_key,
            process_instance,
            next_sequence: recovered.next_sequence,
            previous_event_sha256: recovered.previous_event_sha256,
            last_monotonic_ns: recovered.last_monotonic_ns,
            started: Instant::now(),
            state: recovered.state,
            fail_stopped: false,
        };
        journal.append_raw(
            "process_start",
            &format!("instance-{process_instance}"),
            u64::from(std::process::id()),
            0,
        )?;
        if process_instance == 2 {
            journal.append_raw(
                RuntimeEventKindV1::Restart.as_str(),
                "instance-2",
                u64::from(std::process::id()),
                0,
            )?;
        }
        if let ProcessStartGateV1::StoredRestartCutParkAck(stored) = gate {
            stored.revalidate_fresh_v1()?;
        }
        journal.parent.sync_all().map_err(RuntimeEventErrorV1::Io)?;
        Ok(journal)
    }

    pub const fn process_instance(&self) -> u64 {
        self.process_instance
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Exact final event coordinates for a terminal report. The returned
    /// hash is meaningful only while this exclusive owner remains live.
    pub fn last_event_facts(&self) -> Option<(u64, [u8; 32])> {
        self.next_sequence
            .checked_sub(1)
            .map(|sequence| (sequence, self.previous_event_sha256))
    }

    /// Re-reads and verifies the complete signed journal after CleanStop,
    /// returning a typed cut that cannot be constructed from caller-selected
    /// report fields.
    pub fn clean_stopped_cut(&self) -> Result<CleanStoppedJournalCutV1, RuntimeEventErrorV1> {
        if self.fail_stopped || !self.state.clean_stop {
            return Err(RuntimeEventErrorV1::Invalid(
                "journal has not reached clean stop",
            ));
        }
        let events = read_exact_events(&self.file)?;
        let recovered = validate_event_chain(&events, &self.context)?;
        if recovered.process_instance != self.process_instance
            || recovered.next_sequence != self.next_sequence
            || recovered.previous_event_sha256 != self.previous_event_sha256
            || recovered.last_monotonic_ns != self.last_monotonic_ns
            || recovered.state != self.state
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "clean-stopped journal fresh readback",
            ));
        }
        let [.., final_tip, clean_stop] = events.as_slice() else {
            return Err(RuntimeEventErrorV1::Invalid(
                "clean-stopped journal terminal pair",
            ));
        };
        if final_tip.kind != "final_tip"
            || clean_stop.kind != "clean_stop"
            || final_tip.sequence.checked_add(1) != Some(clean_stop.sequence)
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "clean-stopped journal terminal pair",
            ));
        }
        let (finalized_block_id, finalized_state_root, finalized_chain_root) =
            decode_final_tip_subject(&final_tip.subject)?;
        let process_id = u32::try_from(clean_stop.value)
            .map_err(|_| RuntimeEventErrorV1::Invalid("clean-stop process ID"))?;
        let fleet_start_certificate_sha256 =
            recovered
                .state
                .fleet_start_certificate_sha256
                .ok_or(RuntimeEventErrorV1::Invalid(
                    "clean-stopped journal lacks FleetStart",
                ))?;
        Ok(CleanStoppedJournalCutV1 {
            run_id: self.context.run_id.clone(),
            validator_id: self.context.validator_id,
            validator_set_id: *self.context.validator_set.id().as_bytes(),
            coordinator_manifest_sha256: self.context.coordinator_manifest_sha256,
            validator_set_sha256: self.context.validator_set_sha256,
            config_sha256: self.context.config_sha256,
            candidate_source_sha256: self.context.candidate_source_sha256,
            binary_sha256: self.context.binary_sha256,
            process_instance: clean_stop.process_instance,
            process_id,
            event_sequence: clean_stop.sequence,
            event_sha256: decode_hex::<32>(&clean_stop.event_sha256, "clean-stop event hash")?,
            clean_stop_monotonic_ns: clean_stop.monotonic_ns,
            finalized_height: final_tip.value,
            finalized_block_id,
            finalized_state_root,
            finalized_chain_root,
            fleet_start_certificate_sha256,
            recovered_faults: recovered
                .state
                .recovered_faults
                .iter()
                .map(|fault| fault.as_str().to_owned())
                .collect(),
            restart_completed: recovered.state.restart_completed_v1(),
        })
    }

    pub fn observation(&self) -> RuntimeJournalObservationV1 {
        self.state.observation(self.next_sequence)
    }

    /// Exact read-only restart phase for status/reporting code. The enum is a
    /// projection of the verified journal state and cannot append any event.
    pub fn restart_phase_v1(&self) -> RuntimeRestartPhaseV1 {
        self.state.restart_phase_v1()
    }

    /// Grammar-only helper. Normal builds must consume the freshly validated
    /// StoredRecoveryZeroDeltaCut owner before this transition is exposed.
    #[cfg(test)]
    fn record_recovery_zero_delta_for_grammar_test(
        &mut self,
        zero_delta_artifact_sha256: [u8; 32],
        finalized_height: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let subject = RecoveryZeroDeltaSubjectV1 {
            zero_delta_artifact_sha256,
            recovery_context_sha256: [0xc1; 32],
        };
        self.append_raw(
            "recovery_zero_delta",
            &subject.encode(),
            finalized_height,
            elapsed,
        )
    }

    /// Grammar-only helper for the future N/N RecoveryReady barrier. No
    /// normal-build constructor accepts a digest/count as Ready authority.
    #[cfg(test)]
    fn record_recovery_ready_for_grammar_test(
        &mut self,
        ready_set_artifact_sha256: [u8; 32],
        statement_count: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let recovery_context_sha256 = match self.state.restart {
            RuntimeRestartJournalStateV1::ZeroDeltaRecorded(facts) => {
                facts.subject.recovery_context_sha256
            }
            _ => [0xc1; 32],
        };
        let subject = RecoveryReadySubjectV1 {
            ready_set_artifact_sha256,
            recovery_context_sha256,
        };
        self.append_raw(
            "recovery_ready",
            &subject.encode(),
            statement_count,
            elapsed,
        )
    }

    /// Grammar-only helper for the future fresh N/N RecoveryStart consuming
    /// seam. It is absent from normal builds and therefore cannot turn the
    /// B0 descriptive digest/count into restart authority.
    #[cfg(test)]
    fn record_recovery_start_for_grammar_test(
        &mut self,
        certificate_sha256: [u8; 32],
        statement_count: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let (ready_set_artifact_sha256, recovery_context_sha256) = match self.state.restart {
            RuntimeRestartJournalStateV1::RecoveryReadyRecorded(facts) => (
                facts.subject.ready_set_artifact_sha256,
                facts.subject.recovery_context_sha256,
            ),
            _ => ([0xc2; 32], [0xc1; 32]),
        };
        let subject = RecoveryStartSubjectV1 {
            start_certificate_artifact_sha256: certificate_sha256,
            ready_set_artifact_sha256,
            recovery_context_sha256,
        };
        self.append_raw(
            "recovery_start",
            &subject.encode(),
            statement_count,
            elapsed,
        )
    }

    /// Records the exact N/N ReadySet only after all signatures and the local
    /// commissioned cut have been verified by the fleet barrier owner.
    pub fn record_fleet_ready(
        &mut self,
        ready_set_sha256: [u8; 32],
        barrier_round: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        self.append(
            RuntimeEventKindV1::FleetReady,
            &hex::encode(ready_set_sha256),
            barrier_round,
        )
    }

    /// Records the freshly re-read full N/N StartCertificate. Ordinary
    /// consensus remains impossible until this durable successor exists.
    pub fn record_fleet_started(
        &mut self,
        start_certificate_sha256: [u8; 32],
        barrier_round: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        self.append(
            RuntimeEventKindV1::FleetStarted,
            &hex::encode(start_certificate_sha256),
            barrier_round,
        )
    }

    /// Records a local process-1 quiescent cut. The unforgeable input is
    /// issued only by the bounded consensus owner after it has checked every
    /// local signing, certificate, finalization, ingress, and send obligation.
    /// Public scalar event APIs deliberately have no `RestartPrepare` variant.
    pub(crate) fn record_restart_prepare_from_owner_v1(
        &mut self,
        owner: &crate::consensus_runtime::LocalRestartQuiescedOwnerV1,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        if owner.local_validator_v1() != self.context.validator_id
            || owner.process_instance_v1() != self.process_instance
            || self.last_event_facts() != Some(owner.journal_predecessor_v1())
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "restart prepare owner differs from the live journal",
            ));
        }
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.append_raw(
            "restart_prepare",
            &hex::encode(owner.request_sha256_v1()),
            owner.nonce_v1(),
            elapsed,
        )
    }

    /// Records the peer's sole durable park-preparation marker before any
    /// ordinary continuous authority is consumed into a dual Cut/Park
    /// declaration.  The non-Clone owner retains the admitted, phase-bound
    /// target Prepare; scalar body or message digests cannot call this API.
    pub(crate) fn record_restart_park_prepare_from_owner_v1(
        &mut self,
        owner: &crate::consensus_runtime::LocalRestartPeerQuiescedOwnerV1,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        let expected_count = self.context.validator_set.validators().len();
        let observation = self.observation();
        if owner.local_validator_v1() != self.context.validator_id
            || owner.local_config_sha256_v1() != self.context.config_sha256
            || owner.process_instance_v1() != self.process_instance
            || self.process_instance != 1
            || expected_count != 7
            || self.restart_phase_v1() != RuntimeRestartPhaseV1::Process1
            || owner.target_validator_v1() == self.context.validator_id
            || self.last_event_facts() != Some(owner.journal_predecessor_v1())
            || owner.body_sha256_v1() == [0; 32]
            || owner.prepare_message_id_v1() == [0; 32]
            || owner.shared_cut_height_v1() == 0
            || observation.finalized_height != owner.shared_cut_height_v1()
            || observation.application_height != owner.shared_cut_height_v1()
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "peer park-prepare owner differs from the live direct-seven journal",
            ));
        }
        let subject = RestartParkPrepareSubjectV1 {
            target_validator: owner.target_validator_v1(),
            body_sha256: owner.body_sha256_v1(),
            prepare_message_id: owner.prepare_message_id_v1(),
        };
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.append_raw(
            "restart_park_prepare",
            &subject.encode(),
            owner.shared_cut_height_v1(),
            elapsed,
        )
    }

    /// Appends the exact process-1 target terminal chain only after both N/N
    /// certificates crossed their create-new/exact-retry stores. The signed
    /// body must bind the immediately preceding owner-authenticated
    /// RestartPrepare head. No scalar-only writer exists in the normal build.
    pub(crate) fn record_restart_cut_park_from_owner_v1(
        &mut self,
        owner: &crate::consensus_runtime::LocalRestartTargetPreparedOwnerV1,
        stored: &StoredRestartCutParkCertificatesV1,
    ) -> Result<
        (
            SignedRuntimeEventV1,
            SignedRuntimeEventV1,
            LocalRestartParkJournalCommitV1,
        ),
        RuntimeEventErrorV1,
    > {
        let statement_count = u64::try_from(stored.statement_count_v1())
            .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
        let expected_count = u64::try_from(self.context.validator_set.validators().len())
            .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
        if owner.local_validator_v1() != self.context.validator_id
            || owner.process_instance_v1() != self.process_instance
            || self.process_instance != 1
            || self.last_event_facts() != Some(owner.journal_successor_v1())
            || stored.body_v1().target_validator() != self.context.validator_id
            || stored.body_v1().process_instance() != self.process_instance
            || !stored.contains_exact_target_prepare_v1(owner.target_prepare_v1())
            || stored.body_v1().runtime_journal_head_v1() != owner.journal_successor_v1()
            || stored.local_role_v1() != RestartParkRoleV1::Target
            || stored.cut_artifact_sha256_v1() == [0; 32]
            || stored.park_artifact_sha256_v1() == [0; 32]
            || stored.admission_set_sha256_v1() == [0; 32]
            || stored.local_park_statement_sha256_v1() == [0; 32]
            || statement_count != expected_count
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "stored restart Cut/Park pair differs from the live prepared owner",
            ));
        }
        stored.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "stored restart Cut/Park pair failed fresh authentication before journal append",
            )
        })?;
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let cut_subject = RestartCutParkSubjectV1 {
            cut_artifact_sha256: stored.cut_artifact_sha256_v1(),
            park_artifact_sha256: stored.park_artifact_sha256_v1(),
            body_sha256: stored.body_v1().digest(),
            admission_set_sha256: stored.admission_set_sha256_v1(),
        };
        let cut_event = self.append_raw(
            "restart_cut",
            &cut_subject.encode(),
            statement_count,
            elapsed,
        )?;
        stored.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "stored restart Cut/Park pair changed before target Park append",
            )
        })?;
        let park_subject = RestartParkSubjectV1 {
            park_artifact_sha256: stored.park_artifact_sha256_v1(),
            local_park_statement_sha256: stored.local_park_statement_sha256_v1(),
        };
        let park_event = self.append_raw(
            "restart_park",
            &park_subject.encode(),
            statement_count,
            elapsed,
        )?;
        let commit = self.finish_local_restart_park_journal_commit_v1(
            RestartParkRoleV1::Target,
            owner.journal_successor_v1(),
            stored,
            &cut_event,
            &park_event,
            cut_subject,
            park_subject,
        )?;
        Ok((cut_event, park_event, commit))
    }

    /// Appends the peer's exact process-1 parked chain only while the caller
    /// still retains the consumed continuous parked authority joined to both
    /// durable N/N artifacts. The peer owner, marker, local Park state,
    /// admitted target Prepare, and phase-admission identities must all agree
    /// before either append.
    pub(crate) fn record_peer_restart_cut_park_from_owner_v1(
        &mut self,
        owner: &crate::consensus_runtime::LocalRestartPeerJournalPreparedOwnerV1,
        parked: &DurablyParkedPeerRestartOwnerV1,
    ) -> Result<
        (
            SignedRuntimeEventV1,
            SignedRuntimeEventV1,
            LocalRestartParkJournalCommitV1,
        ),
        RuntimeEventErrorV1,
    > {
        parked.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "durably parked peer RestartCut/Park owner failed fresh authentication before journal commit",
            )
        })?;
        self.record_peer_restart_cut_park_from_stored_internal_v1(owner, parked.stored_v1())
    }

    /// Implements the stored-artifact relation checks after the public crate
    /// boundary has proved ownership of the retained parked authority. This
    /// private entry also lets this module's focused corruption fixtures test
    /// the journal mutation boundary without manufacturing continuous runtime
    /// authority.
    fn record_peer_restart_cut_park_from_stored_internal_v1(
        &mut self,
        owner: &crate::consensus_runtime::LocalRestartPeerJournalPreparedOwnerV1,
        stored: &StoredRestartCutParkCertificatesV1,
    ) -> Result<
        (
            SignedRuntimeEventV1,
            SignedRuntimeEventV1,
            LocalRestartParkJournalCommitV1,
        ),
        RuntimeEventErrorV1,
    > {
        let statement_count = u64::try_from(stored.statement_count_v1())
            .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
        let expected_count = u64::try_from(self.context.validator_set.validators().len())
            .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
        let local_park = stored.local_park_v1();
        let exact_preparation = matches!(
            self.state.restart,
            RuntimeRestartJournalStateV1::Prepared(RestartPreparationJournalV1::Peer(facts))
                if facts.subject.target_validator == owner.target_prepare_v1().body().target_validator()
                    && facts.subject.body_sha256 == owner.target_prepare_v1().body().digest()
                    && facts.subject.prepare_message_id == owner.prepare_message_id_v1()
                    && facts.shared_cut_height
                        == owner.target_prepare_v1().body().shared_cut_v1().finalized_height().get()
                    && facts.prepare_head == owner.journal_successor_v1()
        );
        if owner.local_validator_v1() != self.context.validator_id
            || owner.local_config_sha256_v1() != self.context.config_sha256
            || self.process_instance != 1
            || self.restart_phase_v1() != RuntimeRestartPhaseV1::Process1PeerParkPreparePending
            || self.last_event_facts() != Some(owner.journal_successor_v1())
            || !exact_preparation
            || stored.local_validator_v1() != self.context.validator_id
            || stored.local_config_sha256_v1() != self.context.config_sha256
            || stored.local_role_v1() != RestartParkRoleV1::Peer
            || stored.body_v1() != owner.target_prepare_v1().body()
            || !stored.contains_exact_target_prepare_v1(owner.target_prepare_v1())
            || stored.prepare_message_id_v1() != owner.prepare_message_id_v1()
            || local_park.local_state() != owner.local_state_v1()
            || local_park.local_state().runtime_journal_head_sequence
                != owner.journal_successor_v1().0
            || local_park.local_state().runtime_journal_head_sha256
                != owner.journal_successor_v1().1
            || stored.cut_artifact_sha256_v1() == [0; 32]
            || stored.park_artifact_sha256_v1() == [0; 32]
            || stored.admission_set_sha256_v1() == [0; 32]
            || stored.local_park_statement_sha256_v1() == [0; 32]
            || statement_count != expected_count
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "stored peer RestartCut/Park pair differs from its durable park preparation",
            ));
        }
        stored.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "stored peer RestartCut/Park pair failed fresh authentication before journal append",
            )
        })?;
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let cut_subject = RestartCutParkSubjectV1 {
            cut_artifact_sha256: stored.cut_artifact_sha256_v1(),
            park_artifact_sha256: stored.park_artifact_sha256_v1(),
            body_sha256: stored.body_v1().digest(),
            admission_set_sha256: stored.admission_set_sha256_v1(),
        };
        let cut_event = self.append_raw(
            "restart_cut",
            &cut_subject.encode(),
            statement_count,
            elapsed,
        )?;
        stored.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "stored peer RestartCut/Park pair changed before Park append",
            )
        })?;
        let park_subject = RestartParkSubjectV1 {
            park_artifact_sha256: stored.park_artifact_sha256_v1(),
            local_park_statement_sha256: stored.local_park_statement_sha256_v1(),
        };
        let park_event = self.append_raw(
            "restart_park",
            &park_subject.encode(),
            statement_count,
            elapsed,
        )?;
        let commit = self.finish_local_restart_park_journal_commit_v1(
            RestartParkRoleV1::Peer,
            owner.journal_successor_v1(),
            stored,
            &cut_event,
            &park_event,
            cut_subject,
            park_subject,
        )?;
        Ok((cut_event, park_event, commit))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_local_restart_park_journal_commit_v1(
        &mut self,
        role: RestartParkRoleV1,
        predecessor: (u64, [u8; 32]),
        stored: &StoredRestartCutParkCertificatesV1,
        cut_event: &SignedRuntimeEventV1,
        park_event: &SignedRuntimeEventV1,
        cut_subject: RestartCutParkSubjectV1,
        park_subject: RestartParkSubjectV1,
    ) -> Result<LocalRestartParkJournalCommitV1, RuntimeEventErrorV1> {
        stored.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "stored RestartCut/Park pair changed after local Park append",
            )
        })?;
        let cut_event_sha256 = decode_hex::<32>(&cut_event.event_sha256, "restart cut event hash")?;
        let park_event_sha256 =
            decode_hex::<32>(&park_event.event_sha256, "restart park event hash")?;
        let named_file = self.reopen_exact_named_journal_v1()?;
        let events = read_exact_events(&named_file)?;
        let recovered = validate_event_chain(&events, &self.context)?;
        let [.., preparation_event, fresh_cut, fresh_park] = events.as_slice() else {
            self.fail_stopped = true;
            return Err(RuntimeEventErrorV1::Invalid(
                "local RestartCut/Park journal lacks its exact preparation suffix",
            ));
        };
        let expected_preparation_kind = match role {
            RestartParkRoleV1::Target => "restart_prepare",
            RestartParkRoleV1::Peer => "restart_park_prepare",
        };
        if preparation_event.kind != expected_preparation_kind
            || preparation_event.sequence != predecessor.0
            || preparation_event.event_sha256 != hex::encode(predecessor.1)
            || fresh_cut != cut_event
            || fresh_park != park_event
            || cut_event.kind != "restart_cut"
            || park_event.kind != "restart_park"
            || cut_event.process_instance != 1
            || park_event.process_instance != 1
            || predecessor.0.checked_add(1) != Some(cut_event.sequence)
            || cut_event.sequence.checked_add(1) != Some(park_event.sequence)
            || cut_event.previous_event_sha256 != hex::encode(predecessor.1)
            || park_event.previous_event_sha256 != cut_event.event_sha256
            || recovered.previous_event_sha256 != park_event_sha256
            || recovered.next_sequence != park_event.sequence.checked_add(1).unwrap_or(u64::MAX)
            || recovered.process_instance != self.process_instance
            || recovered.next_sequence != self.next_sequence
            || recovered.previous_event_sha256 != self.previous_event_sha256
            || recovered.last_monotonic_ns != self.last_monotonic_ns
            || recovered.state != self.state
            || recovered.state.restart_cut_facts_v1()
                != Some((stored.cut_artifact_sha256_v1(), cut_event.value))
            || !matches!(
                recovered.state.restart,
                RuntimeRestartJournalStateV1::Parked(facts)
                    if facts.cut_park.preparation.role_v1() == role
                        && facts.cut_park.subject == cut_subject
                        && facts.subject == park_subject
            )
        {
            self.fail_stopped = true;
            return Err(RuntimeEventErrorV1::Invalid(
                "local RestartCut/Park journal fresh named readback differs",
            ));
        }
        stored.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "stored RestartCut/Park pair changed during local journal readback",
            )
        })?;
        let final_named_file = self.reopen_exact_named_journal_v1()?;
        let final_events = read_exact_events(&final_named_file)?;
        let final_recovered = validate_event_chain(&final_events, &self.context)?;
        if final_events != events || final_recovered != recovered {
            self.fail_stopped = true;
            return Err(RuntimeEventErrorV1::Invalid(
                "local RestartCut/Park named journal changed during commit validation",
            ));
        }
        Ok(LocalRestartParkJournalCommitV1 {
            local_validator: self.context.validator_id,
            local_config_sha256: self.context.config_sha256,
            target_validator: stored.body_v1().target_validator(),
            role,
            process_instance: self.process_instance,
            fleet_start_certificate_sha256: stored.body_v1().fleet_start_certificate_sha256(),
            restart_cut_body_sha256: stored.body_v1().digest(),
            restart_cut_artifact_sha256: stored.cut_artifact_sha256_v1(),
            restart_park_artifact_sha256: stored.park_artifact_sha256_v1(),
            restart_cut_park_admission_set_sha256: stored.admission_set_sha256_v1(),
            local_park_statement_sha256: stored.local_park_statement_sha256_v1(),
            predecessor_sequence: predecessor.0,
            predecessor_sha256: predecessor.1,
            restart_cut_event_sequence: cut_event.sequence,
            restart_cut_event_sha256: cut_event_sha256,
            restart_park_event_sequence: park_event.sequence,
            restart_park_event_sha256: park_event_sha256,
        })
    }

    /// Commits the exact direct-seven ParkedAck certificate only after its
    /// immutable store and the original non-Clone local `rpk1` witness agree
    /// with a fresh replay of this named journal. No scalar-only production
    /// writer exists: callers must retain the witness returned by the
    /// owner-authenticated Cut/Park writer and the pinned Ack-store owner.
    pub(crate) fn record_restart_parked_ack_from_owner_v1(
        &mut self,
        owner: &DurablyAcknowledgedRestartParkedBarrierV1,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        owner.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "durable ParkedAck composite failed fresh authentication before journal commit",
            )
        })?;
        let stored_cut_park = owner.stored_cut_park_v1();
        let event = self.record_restart_parked_ack_internal_v1(
            owner.journal_commit_v1(),
            owner.stored_ack_v1(),
            stored_cut_park.fleet_start_certificate_v1(),
            owner.ack_admission_set_sha256_v1(),
        )?;
        owner.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid("durable ParkedAck composite changed after journal commit")
        })?;
        if owner.ack_artifact_sha256_v1() != owner.stored_ack_v1().artifact_sha256_v1()
            || owner.local_statement_v1() != owner.stored_ack_v1().local_statement_v1()
        {
            self.fail_stopped = true;
            return Err(RuntimeEventErrorV1::Invalid(
                "durable ParkedAck composite differs from its retained stored Ack",
            ));
        }
        Ok(event)
    }

    /// Scalar parameters remain private to the process-event module. The only
    /// normal-build entry above accepts the complete non-Clone durable
    /// ParkedAck composite, so callers cannot select an Ack admission digest
    /// independently of the retained phase-bound barrier.
    fn record_restart_parked_ack_internal_v1(
        &mut self,
        commit: &LocalRestartParkJournalCommitV1,
        stored_ack: &StoredRestartParkedAckCertificateV1,
        fleet_start_certificate: &FleetStartCertificateV1,
        ack_admission_set_sha256: [u8; 32],
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        let expected_count = u64::try_from(self.context.validator_set.validators().len())
            .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
        let local_witness = stored_ack.local_witness_v1();
        let local_statement = stored_ack.local_statement_v1();
        let common = stored_ack.common_v1();
        let parked = match self.state.restart {
            RuntimeRestartJournalStateV1::Parked(facts) => facts,
            _ => {
                return Err(RuntimeEventErrorV1::Invalid(
                    "parked acknowledgement writer lacks the exact Ack-pending Park state",
                ));
            }
        };
        let expected_phase = match commit.role_v1() {
            RestartParkRoleV1::Target => RuntimeRestartPhaseV1::Process1TargetParked,
            RestartParkRoleV1::Peer => RuntimeRestartPhaseV1::Process1PeerParked,
        };
        let fleet_start_certificate_sha256: [u8; 32] =
            Sha256::digest(fleet_start_certificate.encode()).into();
        if self.fail_stopped
            || self.process_instance != 1
            || self.restart_phase_v1() != expected_phase
            || self.last_event_facts()
                != Some((
                    commit.restart_park_event_sequence_v1(),
                    commit.restart_park_event_sha256_v1(),
                ))
            || commit.local_validator_v1() != self.context.validator_id
            || commit.local_config_sha256_v1() != self.context.config_sha256
            || commit.process_instance_v1() != self.process_instance
            || commit.target_validator_v1() != common.target_validator()
            || commit.fleet_start_certificate_sha256_v1() != fleet_start_certificate_sha256
            || commit.restart_cut_body_sha256_v1() != common.restart_cut_body_sha256()
            || commit.restart_cut_artifact_sha256_v1() != common.restart_cut_artifact_sha256()
            || commit.restart_park_artifact_sha256_v1() != common.restart_park_artifact_sha256()
            || commit.restart_cut_park_admission_set_sha256_v1()
                != common.restart_cut_park_admission_set_sha256()
            || commit.restart_cut_artifact_sha256_v1()
                != stored_ack.restart_cut_artifact_sha256_v1()
            || commit.restart_park_artifact_sha256_v1()
                != stored_ack.restart_park_artifact_sha256_v1()
            || commit.restart_cut_park_admission_set_sha256_v1()
                != stored_ack.restart_cut_park_admission_set_sha256_v1()
            || commit.local_validator_v1() != stored_ack.local_validator_v1()
            || commit.local_config_sha256_v1() != stored_ack.local_config_sha256_v1()
            || commit.role_v1() != local_witness.role_v1()
            || commit.local_park_statement_sha256_v1()
                != local_witness.local_park_statement_sha256_v1()
            || commit.predecessor_sequence_v1() != local_witness.predecessor_sequence_v1()
            || commit.predecessor_sha256_v1() != local_witness.predecessor_sha256_v1()
            || commit.restart_cut_event_sequence_v1()
                != local_witness.restart_cut_event_sequence_v1()
            || commit.restart_cut_event_sha256_v1() != local_witness.restart_cut_event_sha256_v1()
            || commit.restart_park_event_sequence_v1()
                != local_witness.restart_park_event_sequence_v1()
            || commit.restart_park_event_sha256_v1() != local_witness.restart_park_event_sha256_v1()
            || local_statement.origin() != self.context.validator_id
            || local_statement.role() != commit.role_v1()
            || local_statement.local_config_sha256() != self.context.config_sha256
            || local_statement.local_park_statement_sha256()
                != commit.local_park_statement_sha256_v1()
            || local_statement.predecessor_sequence() != commit.predecessor_sequence_v1()
            || local_statement.predecessor_sha256() != commit.predecessor_sha256_v1()
            || local_statement.restart_cut_event_sequence()
                != commit.restart_cut_event_sequence_v1()
            || local_statement.restart_cut_event_sha256() != commit.restart_cut_event_sha256_v1()
            || local_statement.restart_park_event_sequence()
                != commit.restart_park_event_sequence_v1()
            || local_statement.restart_park_event_sha256() != commit.restart_park_event_sha256_v1()
            || parked.cut_park.preparation.role_v1() != commit.role_v1()
            || parked.cut_park.subject.cut_artifact_sha256
                != commit.restart_cut_artifact_sha256_v1()
            || parked.cut_park.subject.park_artifact_sha256
                != commit.restart_park_artifact_sha256_v1()
            || parked.cut_park.subject.body_sha256 != commit.restart_cut_body_sha256_v1()
            || parked.cut_park.subject.admission_set_sha256
                != commit.restart_cut_park_admission_set_sha256_v1()
            || parked.subject.local_park_statement_sha256 != commit.local_park_statement_sha256_v1()
            || common.process_instance() != 1
            || common.validator_set_id() != self.context.validator_set.id()
            || common.fleet_start_certificate_sha256() != fleet_start_certificate_sha256
            || stored_ack.artifact_sha256_v1() == [0; 32]
            || stored_ack.local_statement_sha256_v1() == [0; 32]
            || ack_admission_set_sha256 == [0; 32]
            || u64::try_from(stored_ack.statement_count_v1())
                .map_err(|_| RuntimeEventErrorV1::TooLarge)?
                != expected_count
            || expected_count != parked.cut_park.statement_count
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "stored ParkedAck certificate differs from the local durable Park witness",
            ));
        }
        stored_ack
            .revalidate_fresh_v1(fleet_start_certificate, &self.context.validator_set)
            .map_err(|_| {
                RuntimeEventErrorV1::Invalid(
                    "stored ParkedAck certificate failed fresh authentication before journal append",
                )
            })?;
        let subject = RestartParkedAckSubjectV1 {
            ack_certificate_sha256: stored_ack.artifact_sha256_v1(),
            local_ack_statement_sha256: stored_ack.local_statement_sha256_v1(),
            cut_artifact_sha256: commit.restart_cut_artifact_sha256_v1(),
            park_artifact_sha256: commit.restart_park_artifact_sha256_v1(),
            ack_admission_set_sha256,
        };
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let event = self.append_raw(
            "restart_parked_ack",
            &subject.encode(),
            expected_count,
            elapsed,
        )?;
        stored_ack
            .revalidate_fresh_v1(fleet_start_certificate, &self.context.validator_set)
            .map_err(|_| {
                RuntimeEventErrorV1::Invalid(
                    "stored ParkedAck certificate changed after journal append",
                )
            })?;
        let event_sha256 = decode_hex::<32>(
            &event.event_sha256,
            "restart parked acknowledgement event hash",
        )?;
        let named_file = self.reopen_exact_named_journal_v1()?;
        let events = read_exact_events(&named_file)?;
        let recovered = validate_event_chain(&events, &self.context)?;
        if events.last() != Some(&event)
            || event.sequence != commit.restart_park_event_sequence_v1().saturating_add(1)
            || event.previous_event_sha256 != hex::encode(commit.restart_park_event_sha256_v1())
            || recovered.previous_event_sha256 != event_sha256
            || recovered.next_sequence != event.sequence.checked_add(1).unwrap_or(u64::MAX)
            || recovered.process_instance != self.process_instance
            || recovered.next_sequence != self.next_sequence
            || recovered.previous_event_sha256 != self.previous_event_sha256
            || recovered.last_monotonic_ns != self.last_monotonic_ns
            || recovered.state != self.state
            || !matches!(
                recovered.state.restart,
                RuntimeRestartJournalStateV1::ParkedAcked(facts)
                    if facts.parked == parked
                        && facts.subject == subject
                        && facts.statement_count == expected_count
            )
        {
            self.fail_stopped = true;
            return Err(RuntimeEventErrorV1::Invalid(
                "ParkedAck journal fresh named readback differs",
            ));
        }
        stored_ack
            .revalidate_fresh_v1(fleet_start_certificate, &self.context.validator_set)
            .map_err(|_| {
                RuntimeEventErrorV1::Invalid(
                    "stored ParkedAck certificate changed during journal readback",
                )
            })?;
        let final_named_file = self.reopen_exact_named_journal_v1()?;
        let final_events = read_exact_events(&final_named_file)?;
        let final_recovered = validate_event_chain(&final_events, &self.context)?;
        if final_events != events || final_recovered != recovered {
            self.fail_stopped = true;
            return Err(RuntimeEventErrorV1::Invalid(
                "ParkedAck named journal changed during commit validation",
            ));
        }
        Ok(event)
    }

    pub(crate) const fn restart_cut_facts_v1(&self) -> Option<([u8; 32], u64)> {
        self.state.restart_cut_facts_v1()
    }

    /// Revalidates the exact role-specific process-1 Ack-pending Park commit
    /// immediately before ParkedAck signing. This closes the window in which
    /// a stale in-memory commit could otherwise authorize a network signature
    /// after the named journal or its `rpk1` suffix was replaced. No event is
    /// appended and no signing or recovery authority is returned.
    pub(crate) fn revalidate_local_restart_park_commit_v1(
        &self,
        commit: &LocalRestartParkJournalCommitV1,
    ) -> Result<(), RuntimeEventErrorV1> {
        let expected_phase = match commit.role_v1() {
            RestartParkRoleV1::Target => RuntimeRestartPhaseV1::Process1TargetParked,
            RestartParkRoleV1::Peer => RuntimeRestartPhaseV1::Process1PeerParked,
        };
        let named_file = self.reopen_exact_named_journal_v1()?;
        let events = read_exact_events(&named_file)?;
        let recovered = validate_event_chain(&events, &self.context)?;
        let [.., predecessor, restart_cut, restart_park] = events.as_slice() else {
            return Err(RuntimeEventErrorV1::Invalid(
                "local RestartPark commit lacks its exact three-event suffix",
            ));
        };
        let parked = match recovered.state.restart {
            RuntimeRestartJournalStateV1::Parked(facts)
                if facts.cut_park.preparation.role_v1() == commit.role_v1() =>
            {
                facts
            }
            _ => {
                return Err(RuntimeEventErrorV1::Invalid(
                    "local RestartPark commit is no longer the Ack-pending journal state",
                ));
            }
        };
        let predecessor_sha256 =
            decode_hex::<32>(&predecessor.event_sha256, "restart predecessor event hash")?;
        let restart_cut_sha256 =
            decode_hex::<32>(&restart_cut.event_sha256, "restart cut event hash")?;
        let restart_park_sha256 =
            decode_hex::<32>(&restart_park.event_sha256, "restart park event hash")?;
        let cut_subject = RestartCutParkSubjectV1::decode(&restart_cut.subject)?;
        let park_subject = RestartParkSubjectV1::decode(&restart_park.subject)?;
        let expected_predecessor_kind = match commit.role_v1() {
            RestartParkRoleV1::Target => "restart_prepare",
            RestartParkRoleV1::Peer => "restart_park_prepare",
        };
        let role_preparation_matches = match parked.cut_park.preparation {
            RestartPreparationJournalV1::Target(facts) => {
                commit.role_v1() == RestartParkRoleV1::Target
                    && commit.target_validator_v1() == self.context.validator_id
                    && facts.prepare_head == (predecessor.sequence, predecessor_sha256)
            }
            RestartPreparationJournalV1::Peer(facts) => {
                commit.role_v1() == RestartParkRoleV1::Peer
                    && commit.target_validator_v1() == facts.subject.target_validator
                    && facts.prepare_head == (predecessor.sequence, predecessor_sha256)
                    && facts.subject.body_sha256 == commit.restart_cut_body_sha256_v1()
            }
        };
        if self.fail_stopped
            || self.process_instance != 1
            || self.restart_phase_v1() != expected_phase
            || self.last_event_facts()
                != Some((
                    commit.restart_park_event_sequence_v1(),
                    commit.restart_park_event_sha256_v1(),
                ))
            || recovered.process_instance != self.process_instance
            || recovered.next_sequence != self.next_sequence
            || recovered.previous_event_sha256 != self.previous_event_sha256
            || recovered.last_monotonic_ns != self.last_monotonic_ns
            || recovered.state != self.state
            || predecessor.kind != expected_predecessor_kind
            || predecessor.process_instance != 1
            || predecessor.sequence != commit.predecessor_sequence_v1()
            || predecessor_sha256 != commit.predecessor_sha256_v1()
            || restart_cut.kind != "restart_cut"
            || restart_cut.process_instance != 1
            || restart_cut.sequence != commit.restart_cut_event_sequence_v1()
            || restart_cut_sha256 != commit.restart_cut_event_sha256_v1()
            || restart_cut.previous_event_sha256 != predecessor.event_sha256
            || restart_park.kind != "restart_park"
            || restart_park.process_instance != 1
            || restart_park.sequence != commit.restart_park_event_sequence_v1()
            || restart_park_sha256 != commit.restart_park_event_sha256_v1()
            || restart_park.previous_event_sha256 != restart_cut.event_sha256
            || restart_park.sequence.checked_add(1) != Some(recovered.next_sequence)
            || commit.local_validator_v1() != self.context.validator_id
            || commit.local_config_sha256_v1() != self.context.config_sha256
            || commit.process_instance_v1() != 1
            || commit.fleet_start_certificate_sha256_v1()
                != recovered
                    .state
                    .fleet_start_certificate_sha256
                    .unwrap_or([0; 32])
            || commit.restart_cut_artifact_sha256_v1() != cut_subject.cut_artifact_sha256
            || commit.restart_park_artifact_sha256_v1() != cut_subject.park_artifact_sha256
            || commit.restart_cut_body_sha256_v1() != cut_subject.body_sha256
            || commit.restart_cut_park_admission_set_sha256_v1() != cut_subject.admission_set_sha256
            || commit.restart_park_artifact_sha256_v1() != park_subject.park_artifact_sha256
            || commit.local_park_statement_sha256_v1() != park_subject.local_park_statement_sha256
            || parked.cut_park.subject != cut_subject
            || parked.subject != park_subject
            || !role_preparation_matches
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "local RestartPark commit differs from the fresh named Ack-pending journal",
            ));
        }
        let final_named_file = self.reopen_exact_named_journal_v1()?;
        let final_events = read_exact_events(&final_named_file)?;
        let final_recovered = validate_event_chain(&final_events, &self.context)?;
        if final_events != events || final_recovered != recovered {
            return Err(RuntimeEventErrorV1::Invalid(
                "local RestartPark commit named journal changed during validation",
            ));
        }
        Ok(())
    }

    /// Re-reads the complete signed journal and both immutable restart
    /// artifacts at the process-1 target handoff boundary.  The returned cut
    /// is descriptive only; the exclusively locked journal remains owned by
    /// `self` until the consensus owner thread has completely returned.
    pub(crate) fn revalidate_target_process1_parked_ack_handoff_v1(
        &self,
        owner: &DurablyAcknowledgedRestartParkedBarrierV1,
    ) -> Result<Process1TargetParkedJournalCutV1, RuntimeEventErrorV1> {
        owner.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "target process-1 handoff ParkedAck composite failed fresh authentication",
            )
        })?;
        let stored = owner.stored_cut_park_v1();
        let stored_ack = owner.stored_ack_v1();
        let commit = owner.journal_commit_v1();
        let named_file = self.reopen_exact_named_journal_v1()?;
        let events = read_exact_events(&named_file)?;
        let recovered = validate_event_chain(&events, &self.context)?;
        let journal_witness =
            process1_target_parked_ack_journal_witness_v1(&events, &recovered, &self.context)?;
        if self.fail_stopped
            || self.process_instance != 1
            || self.restart_phase_v1() != RuntimeRestartPhaseV1::Process1TargetParkedAcked
            || self.last_event_facts()
                != Some((
                    journal_witness.parked_ack_event_sequence,
                    journal_witness.parked_ack_event_sha256,
                ))
            || recovered.process_instance != self.process_instance
            || recovered.next_sequence != self.next_sequence
            || recovered.previous_event_sha256 != self.previous_event_sha256
            || recovered.last_monotonic_ns != self.last_monotonic_ns
            || recovered.state != self.state
            || stored.local_role_v1() != RestartParkRoleV1::Target
            || stored.local_validator_v1() != self.context.validator_id
            || stored.local_config_sha256_v1() != self.context.config_sha256
            || stored.cut_artifact_sha256_v1() != journal_witness.cut_artifact_sha256
            || stored.park_artifact_sha256_v1() != journal_witness.park_artifact_sha256
            || stored.body_v1().digest() != journal_witness.body_sha256
            || stored.admission_set_sha256_v1() != journal_witness.cut_park_admission_set_sha256
            || stored.local_park_statement_sha256_v1()
                != journal_witness.local_park_statement_sha256
            || stored_ack.artifact_sha256_v1() != journal_witness.ack_artifact_sha256
            || stored_ack.local_statement_sha256_v1() != journal_witness.local_ack_statement_sha256
            || stored_ack.local_witness_v1() != journal_witness.local_witness
            || owner.ack_admission_set_sha256_v1() != journal_witness.ack_admission_set_sha256
            || commit.local_validator_v1() != self.context.validator_id
            || commit.role_v1() != RestartParkRoleV1::Target
            || commit.predecessor_sequence_v1()
                != journal_witness.local_witness.predecessor_sequence_v1()
            || commit.predecessor_sha256_v1()
                != journal_witness.local_witness.predecessor_sha256_v1()
            || commit.restart_cut_event_sequence_v1()
                != journal_witness
                    .local_witness
                    .restart_cut_event_sequence_v1()
            || commit.restart_cut_event_sha256_v1()
                != journal_witness.local_witness.restart_cut_event_sha256_v1()
            || commit.restart_park_event_sequence_v1()
                != journal_witness
                    .local_witness
                    .restart_park_event_sequence_v1()
            || commit.restart_park_event_sha256_v1()
                != journal_witness.local_witness.restart_park_event_sha256_v1()
            || owner.local_statement_v1() != stored_ack.local_statement_v1()
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "target process-1 handoff differs across rpa1, journal witness, and durable triple",
            ));
        }
        owner.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "target process-1 handoff ParkedAck composite changed during journal replay",
            )
        })?;
        let final_named_file = self.reopen_exact_named_journal_v1()?;
        let final_events = read_exact_events(&final_named_file)?;
        let final_recovered = validate_event_chain(&final_events, &self.context)?;
        if final_events != events || final_recovered != recovered {
            return Err(RuntimeEventErrorV1::Invalid(
                "target process-1 handoff named journal changed during validation",
            ));
        }
        owner.revalidate_fresh_v1().map_err(|_| {
            RuntimeEventErrorV1::Invalid(
                "target process-1 handoff ParkedAck composite changed after journal replay",
            )
        })?;
        Ok(Process1TargetParkedJournalCutV1 {
            event_sequence: journal_witness.parked_ack_event_sequence,
            event_sha256: journal_witness.parked_ack_event_sha256,
            restart_cut_artifact_sha256: journal_witness.cut_artifact_sha256,
            restart_park_artifact_sha256: journal_witness.park_artifact_sha256,
            restart_parked_ack_artifact_sha256: journal_witness.ack_artifact_sha256,
            restart_parked_ack_admission_set_sha256: journal_witness.ack_admission_set_sha256,
            local_restart_parked_ack_statement_sha256: journal_witness.local_ack_statement_sha256,
        })
    }

    /// Historical pair-only handoff gate retained solely to fail closed. A
    /// Cut/Park pair cannot prove that every validator durably received the
    /// barrier, even when its own stores still fresh-revalidate.
    pub(crate) fn revalidate_target_process1_parked_handoff_v1(
        &self,
        stored: &StoredRestartCutParkCertificatesV1,
    ) -> Result<Process1TargetParkedJournalCutV1, RuntimeEventErrorV1> {
        let _ = (self, stored);
        Err(RuntimeEventErrorV1::Invalid(
            "target process-1 handoff requires the exact stored ParkedAck certificate",
        ))
    }

    /// Reopens the exact canonical journal name without following a terminal
    /// symlink, while retaining the original locked descriptor as the sole
    /// mutation authority. Stable directory and file identities are compared;
    /// length and timestamps are deliberately excluded because the journal is
    /// append-only while this owner is live.
    ///
    /// This detects stable same-UID pathname replacement. The pathname calls
    /// are intentionally safe Rust rather than descriptor-relative `*at`
    /// operations, so an adversary able to swap a same-UID directory away and
    /// back between checks remains outside this narrow handoff hardening.
    fn reopen_exact_named_journal_v1(&self) -> Result<File, RuntimeEventErrorV1> {
        let held_parent_identity = RuntimeEventJournalParentIdentityV1::from_metadata_v1(
            &self.parent.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        if held_parent_identity != self.parent_identity {
            return Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal held parent identity changed",
            ));
        }
        let held_file_identity = RuntimeEventJournalFileIdentityV1::from_metadata_v1(
            &self.file.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        if held_file_identity != self.file_identity {
            return Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal held file identity changed",
            ));
        }

        let parent_path = self.path.parent().ok_or(RuntimeEventErrorV1::Invalid(
            "runtime event journal canonical parent",
        ))?;
        let named_parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(parent_path)
            .map_err(RuntimeEventErrorV1::Io)?;
        let named_parent_identity = RuntimeEventJournalParentIdentityV1::from_metadata_v1(
            &named_parent.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        if named_parent_identity != self.parent_identity {
            return Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal named parent identity changed",
            ));
        }

        let named_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
            .map_err(RuntimeEventErrorV1::Io)?;
        let named_file_identity = RuntimeEventJournalFileIdentityV1::from_metadata_v1(
            &named_file.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        if named_file_identity != self.file_identity {
            return Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal named file identity changed",
            ));
        }

        let named_parent_identity_after = RuntimeEventJournalParentIdentityV1::from_metadata_v1(
            &named_parent.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        let held_parent_identity_after = RuntimeEventJournalParentIdentityV1::from_metadata_v1(
            &self.parent.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        let held_file_identity_after = RuntimeEventJournalFileIdentityV1::from_metadata_v1(
            &self.file.metadata().map_err(RuntimeEventErrorV1::Io)?,
        )?;
        if named_parent_identity_after != self.parent_identity
            || held_parent_identity_after != self.parent_identity
            || held_file_identity_after != self.file_identity
        {
            return Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal identity changed while reopened",
            ));
        }
        Ok(named_file)
    }

    /// Runtime-owned observation point after the requested external effect is
    /// actually visible at the validator's network/process/store boundary.
    pub fn record_fault_applied(
        &mut self,
        fault: RuntimeFaultV1,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        self.append(RuntimeEventKindV1::FaultApplied, fault.as_str(), 1)
    }

    /// Runtime-owned observation point after the exact fault subject has
    /// recovered and the validator has observed a positive finalized height.
    pub fn record_fault_recovered(
        &mut self,
        fault: RuntimeFaultV1,
        recovered_finalized_height: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        self.append(
            RuntimeEventKindV1::FaultRecovered,
            fault.as_str(),
            recovered_finalized_height,
        )
    }

    /// Records the exact terminal block/state/chain triplet.  A clean stop is
    /// rejected unless this is the immediately preceding durable event.
    pub fn record_final_tip(
        &mut self,
        finalized_block_id: [u8; 32],
        finalized_state_root: [u8; 32],
        finalized_chain_root: [u8; 32],
        finalized_height: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        let subject = format!(
            "{}:{}:{}",
            hex::encode(finalized_block_id),
            hex::encode(finalized_state_root),
            hex::encode(finalized_chain_root)
        );
        self.append(RuntimeEventKindV1::FinalTip, &subject, finalized_height)
    }

    pub fn record_clean_stop(&mut self) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        self.append(
            RuntimeEventKindV1::CleanStop,
            "bounded-run-complete",
            u64::from(std::process::id()),
        )
    }

    pub fn append(
        &mut self,
        kind: RuntimeEventKindV1,
        subject: &str,
        value: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.append_raw(kind.as_str(), subject, value, elapsed)
    }

    fn append_raw(
        &mut self,
        kind: &str,
        subject: &str,
        value: u64,
        monotonic_ns: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        if self.fail_stopped {
            return Err(RuntimeEventErrorV1::FailStopped);
        }
        let result = self.append_raw_inner(kind, subject, value, monotonic_ns);
        if result.is_err() {
            self.fail_stopped = true;
        }
        result
    }

    fn append_raw_inner(
        &mut self,
        kind: &str,
        subject: &str,
        value: u64,
        monotonic_ns: u64,
    ) -> Result<SignedRuntimeEventV1, RuntimeEventErrorV1> {
        if kind.is_empty()
            || kind.len() > 64
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || (kind == "process_start" && self.next_sequence != 0 && monotonic_ns != 0)
        {
            return Err(RuntimeEventErrorV1::Invalid("event kind"));
        }
        let mut event = SignedRuntimeEventV1 {
            schema_version: EVENT_SCHEMA_VERSION,
            run_id: self.context.run_id.clone(),
            validator_id: hex::encode(self.context.validator_id.as_bytes()),
            process_instance: self.process_instance,
            sequence: self.next_sequence,
            monotonic_ns,
            kind: kind.to_owned(),
            subject: subject.to_owned(),
            value,
            coordinator_manifest_sha256: hex::encode(self.context.coordinator_manifest_sha256),
            validator_set_sha256: hex::encode(self.context.validator_set_sha256),
            config_sha256: hex::encode(self.context.config_sha256),
            candidate_source_sha256: hex::encode(self.context.candidate_source_sha256),
            binary_sha256: hex::encode(self.context.binary_sha256),
            previous_event_sha256: hex::encode(self.previous_event_sha256),
            event_sha256: String::new(),
            signature: String::new(),
            production_activation: false,
        };
        let event_hash = event.computed_hash()?;
        event.event_sha256 = hex::encode(event_hash);
        event.signature = hex::encode(
            self.signing_key
                .sign(&signature_root(event_hash))
                .to_bytes(),
        );
        event.validate(
            &self.context,
            self.next_sequence,
            self.process_instance,
            self.previous_event_sha256,
            Some(self.last_monotonic_ns),
        )?;
        let mut candidate_state = self.state.clone();
        candidate_state.observe(&event, &self.context)?;
        let mut line = serde_json::to_vec(&event).map_err(RuntimeEventErrorV1::Json)?;
        line.push(b'\n');
        let current_size = self.file.metadata().map_err(RuntimeEventErrorV1::Io)?.len();
        let target_size = current_size
            .checked_add(u64::try_from(line.len()).map_err(|_| RuntimeEventErrorV1::TooLarge)?)
            .ok_or(RuntimeEventErrorV1::TooLarge)?;
        if target_size > MAX_EVENT_JOURNAL_BYTES
            || usize::try_from(self.next_sequence)
                .ok()
                .is_none_or(|sequence| sequence >= MAX_EVENT_COUNT)
        {
            return Err(RuntimeEventErrorV1::TooLarge);
        }
        self.file
            .seek(SeekFrom::End(0))
            .map_err(RuntimeEventErrorV1::Io)?;
        self.file
            .write_all(&line)
            .map_err(RuntimeEventErrorV1::Io)?;
        self.file.sync_all().map_err(RuntimeEventErrorV1::Io)?;
        let events = read_exact_events(&self.file)?;
        let recovered = validate_event_chain(&events, &self.context)?;
        if events.last() != Some(&event)
            || recovered.next_sequence
                != self
                    .next_sequence
                    .checked_add(1)
                    .ok_or(RuntimeEventErrorV1::Invalid("event sequence overflow"))?
            || recovered.previous_event_sha256 != event_hash
            || recovered.state != candidate_state
        {
            return Err(RuntimeEventErrorV1::Invalid("event fresh readback"));
        }
        self.next_sequence = recovered.next_sequence;
        self.previous_event_sha256 = recovered.previous_event_sha256;
        self.last_monotonic_ns = recovered.last_monotonic_ns;
        self.state = recovered.state;
        Ok(event)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveredJournalV1 {
    process_instance: u64,
    next_sequence: u64,
    previous_event_sha256: [u8; 32],
    last_monotonic_ns: u64,
    state: RuntimeJournalStateV1,
}

fn validate_event_chain(
    events: &[SignedRuntimeEventV1],
    context: &RuntimeEventContextV1,
) -> Result<RecoveredJournalV1, RuntimeEventErrorV1> {
    if events.len() > MAX_EVENT_COUNT {
        return Err(RuntimeEventErrorV1::TooLarge);
    }
    let mut previous = [0; 32];
    let mut instance = 0u64;
    let mut prior_monotonic = None;
    let mut state = RuntimeJournalStateV1::default();
    for (index, event) in events.iter().enumerate() {
        let sequence = u64::try_from(index).map_err(|_| RuntimeEventErrorV1::TooLarge)?;
        if event.kind == "process_start" {
            instance = instance
                .checked_add(1)
                .ok_or(RuntimeEventErrorV1::Invalid("process instance overflow"))?;
            prior_monotonic = Some(0);
        } else if instance == 0 {
            return Err(RuntimeEventErrorV1::Invalid(
                "journal does not begin with process-start",
            ));
        }
        event.validate(context, sequence, instance, previous, prior_monotonic)?;
        state.observe(event, context)?;
        previous = decode_hex::<32>(&event.event_sha256, "event hash")?;
        prior_monotonic = Some(event.monotonic_ns);
    }
    Ok(RecoveredJournalV1 {
        process_instance: instance,
        next_sequence: u64::try_from(events.len()).map_err(|_| RuntimeEventErrorV1::TooLarge)?,
        previous_event_sha256: previous,
        last_monotonic_ns: prior_monotonic.unwrap_or(0),
        state,
    })
}

fn validate_process2_restart_cut_park_ack_predecessor_v1(
    events: &[SignedRuntimeEventV1],
    recovered: &RecoveredJournalV1,
    context: &RuntimeEventContextV1,
    stored: &ReopenedRestartCutParkAckCertificatesV1,
) -> Result<(), RuntimeEventErrorV1> {
    stored.revalidate_fresh_v1()?;
    let journal_witness =
        process1_target_parked_ack_journal_witness_v1(events, recovered, context)?;
    let cut_park = stored.stored_cut_park_v1();
    let body = cut_park.body_v1();
    let identity = body.campaign().identity();
    let fleet_start_sha256: [u8; 32] =
        Sha256::digest(cut_park.fleet_start_certificate_v1().encode()).into();
    if journal_witness != stored.journal_witness
        || recovered.process_instance != 1
        || recovered.state.current_instance != 1
        || recovered.state.last_kind.as_deref() != Some("restart_parked_ack")
        || body.runtime_journal_head_v1()
            != (
                journal_witness.local_witness.predecessor_sequence_v1(),
                journal_witness.local_witness.predecessor_sha256_v1(),
            )
        || body.process_instance() != 1
        || body.target_validator() != context.validator_id
        || body.target_config_sha256() != context.config_sha256
        || body.run_id() != context.run_id
        || body.coordinator_manifest_sha256() != context.coordinator_manifest_sha256
        || body.validator_set_id() != *context.validator_set.id().as_bytes()
        || body.validator_set_sha256() != context.validator_set_sha256
        || identity.candidate_source_sha256() != context.candidate_source_sha256
        || identity.binary_sha256() != context.binary_sha256
        || body.fleet_start_certificate_sha256() != fleet_start_sha256
        || fleet_start_sha256 != journal_witness.fleet_start_certificate_sha256
        || !body.pending_sign_is_none()
        || cut_park.local_role_v1() != RestartParkRoleV1::Target
        || stored.stored_ack_v1().local_witness_v1() != journal_witness.local_witness
        || stored.stored_ack_v1().local_statement_sha256_v1()
            != journal_witness.local_ack_statement_sha256
        || stored.ack_admission_set_sha256_v1() != journal_witness.ack_admission_set_sha256
    {
        return Err(RuntimeEventErrorV1::Invalid(
            "stored Cut/Park/ParkedAck triple lacks its exact target rpa1 process-2 predecessor",
        ));
    }
    stored.revalidate_fresh_v1()
}

/// Independently verifies one copied runtime journal using only the closed
/// observer-public bundle. The verifier opens no validator secret and accepts
/// only a complete `FinalTip` -> `CleanStop` chain.
pub fn verify_runtime_event_journal_v1(
    path: &Path,
    public_context: &PublicReportVerifierContext,
) -> Result<RuntimeJournalVerificationV1, RuntimeEventErrorV1> {
    let context = RuntimeEventContextV1::from_public_context(public_context);
    verify_runtime_event_journal_with_context_v1(path, &context)
}

fn verify_runtime_event_journal_with_context_v1(
    path: &Path,
    context: &RuntimeEventContextV1,
) -> Result<RuntimeJournalVerificationV1, RuntimeEventErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(RuntimeEventErrorV1::Io)?;
    let initial_metadata = file.metadata().map_err(RuntimeEventErrorV1::Io)?;
    if !initial_metadata.is_file()
        || initial_metadata.nlink() != 1
        || initial_metadata.len() == 0
        || initial_metadata.len() > MAX_EVENT_JOURNAL_BYTES
    {
        return Err(RuntimeEventErrorV1::Invalid(
            "observer runtime event journal file",
        ));
    }

    let events = read_exact_events(&file)?;
    let recovered = validate_event_chain(&events, context)?;
    let final_metadata = file.metadata().map_err(RuntimeEventErrorV1::Io)?;
    if initial_metadata.dev() != final_metadata.dev()
        || initial_metadata.ino() != final_metadata.ino()
        || initial_metadata.len() != final_metadata.len()
        || final_metadata.nlink() != 1
    {
        return Err(RuntimeEventErrorV1::Invalid(
            "observer runtime event journal changed while verified",
        ));
    }
    // The legacy observer API receives only a journal and public deployment
    // context, so it cannot authenticate the external N/N RestartCut and
    // RestartPark artifacts. Adjacency is still enforced by the replay
    // grammar, but it is not certificate authority. Fail closed until an
    // artifact-aware public verifier joins FleetStart and both exact bytes.
    if recovered.process_instance > 1 {
        return Err(RuntimeEventErrorV1::Invalid(
            "observer process-2 verification requires authenticated RestartCut and RestartPark artifacts",
        ));
    }

    let [.., final_tip, clean_stop] = events.as_slice() else {
        return Err(RuntimeEventErrorV1::Invalid(
            "observer runtime event journal terminal pair",
        ));
    };
    if final_tip.kind != RuntimeEventKindV1::FinalTip.as_str()
        || clean_stop.kind != RuntimeEventKindV1::CleanStop.as_str()
        || final_tip.sequence.checked_add(1) != Some(clean_stop.sequence)
        || clean_stop.sequence.checked_add(1) != Some(recovered.next_sequence)
        || clean_stop.process_instance != recovered.process_instance
        || decode_hex::<32>(&clean_stop.event_sha256, "clean-stop event hash")?
            != recovered.previous_event_sha256
        || !recovered.state.clean_stop
        || recovered.state.safety_halted
        || recovered.state.fleet_barrier_round.is_none()
        || recovered.state.fleet_ready_event_sequence.is_none()
        || recovered.state.fleet_ready_event_sha256.is_none()
        || recovered
            .state
            .fleet_ready_previous_event_sequence
            .is_none()
        || recovered.state.fleet_ready_previous_event_sha256.is_none()
        || recovered
            .state
            .fleet_ready_previous_event_sequence
            .and_then(|sequence| sequence.checked_add(1))
            != recovered.state.fleet_ready_event_sequence
        || recovered.state.fleet_ready_set_sha256.is_none()
        || recovered.state.fleet_start_certificate_sha256.is_none()
        || !recovered.state.active_faults.is_empty()
        || recovered.state.finalized_height == 0
        || recovered.state.finalized_height != recovered.state.application_height
        || recovered.state.final_tip.as_ref() != Some(&(final_tip.subject.clone(), final_tip.value))
    {
        return Err(RuntimeEventErrorV1::Invalid(
            "observer runtime event journal terminal semantics",
        ));
    }
    let (finalized_block_id, finalized_state_root, finalized_chain_root) =
        decode_final_tip_subject(&final_tip.subject)?;
    let event_count = u64::try_from(events.len()).map_err(|_| RuntimeEventErrorV1::TooLarge)?;
    let recovered_fault_count = u64::try_from(recovered.state.recovered_faults.len())
        .map_err(|_| RuntimeEventErrorV1::TooLarge)?;
    Ok(RuntimeJournalVerificationV1 {
        schema_version: EVENT_SCHEMA_VERSION,
        status: "runtime-journal-signature-and-semantics-verified".to_owned(),
        run_id: context.run_id.clone(),
        validator_id: hex::encode(context.validator_id.as_bytes()),
        validator_set_sha256: hex::encode(context.validator_set_sha256),
        coordinator_manifest_sha256: hex::encode(context.coordinator_manifest_sha256),
        candidate_source_sha256: hex::encode(context.candidate_source_sha256),
        binary_sha256: hex::encode(context.binary_sha256),
        config_sha256: hex::encode(context.config_sha256),
        barrier_round: recovered
            .state
            .fleet_barrier_round
            .expect("terminal semantics require fleet barrier round"),
        fleet_ready_event_sequence: recovered
            .state
            .fleet_ready_event_sequence
            .expect("terminal semantics require fleet Ready sequence"),
        fleet_ready_event_sha256: hex::encode(
            recovered
                .state
                .fleet_ready_event_sha256
                .expect("terminal semantics require fleet Ready hash"),
        ),
        fleet_ready_previous_event_sequence: recovered
            .state
            .fleet_ready_previous_event_sequence
            .expect("terminal semantics require fleet Ready predecessor sequence"),
        fleet_ready_previous_event_sha256: hex::encode(
            recovered
                .state
                .fleet_ready_previous_event_sha256
                .expect("terminal semantics require fleet Ready predecessor hash"),
        ),
        fleet_ready_set_sha256: hex::encode(
            recovered
                .state
                .fleet_ready_set_sha256
                .expect("terminal semantics require fleet Ready"),
        ),
        fleet_start_certificate_sha256: hex::encode(
            recovered
                .state
                .fleet_start_certificate_sha256
                .expect("terminal semantics require fleet Started"),
        ),
        process_instance_count: recovered.process_instance,
        event_count,
        runtime_event_sequence: clean_stop.sequence,
        runtime_event_sha256: clean_stop.event_sha256.clone(),
        finalized_height: final_tip.value,
        finalized_block_id: hex::encode(finalized_block_id),
        finalized_state_root: hex::encode(finalized_state_root),
        finalized_chain_root: hex::encode(finalized_chain_root),
        recovered_fault_count,
        restart_completed: recovered.state.restart_completed_v1(),
        clean_stop: true,
        signature_verified: true,
        semantics_verified: true,
        g3_evidence_complete: false,
        geo_wan_evidence: false,
        production_activation: false,
    })
}

fn open_locked_journal(
    path: &Path,
    create_if_missing: bool,
) -> Result<(PathBuf, File, File), RuntimeEventErrorV1> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(RuntimeEventErrorV1::Invalid("journal path"));
    }
    let parent_path = path
        .parent()
        .ok_or(RuntimeEventErrorV1::Invalid("journal parent"))?
        .canonicalize()
        .map_err(RuntimeEventErrorV1::Io)?;
    let parent_metadata = fs::metadata(&parent_path).map_err(RuntimeEventErrorV1::Io)?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o022 != 0 {
        return Err(RuntimeEventErrorV1::Invalid("journal parent permissions"));
    }
    let target = parent_path.join(
        path.file_name()
            .ok_or(RuntimeEventErrorV1::Invalid("journal file name"))?,
    );
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(&parent_path)
        .map_err(RuntimeEventErrorV1::Io)?;
    let opened_parent_metadata = parent.metadata().map_err(RuntimeEventErrorV1::Io)?;
    if opened_parent_metadata.dev() != parent_metadata.dev()
        || opened_parent_metadata.ino() != parent_metadata.ino()
        || opened_parent_metadata.uid() != parent_metadata.uid()
        || opened_parent_metadata.mode() != parent_metadata.mode()
    {
        return Err(RuntimeEventErrorV1::Invalid(
            "journal parent changed while opened",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(create_if_missing)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&target)
        .map_err(RuntimeEventErrorV1::Io)?;
    file.try_lock_exclusive().map_err(RuntimeEventErrorV1::Io)?;
    let metadata = file.metadata().map_err(RuntimeEventErrorV1::Io)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != opened_parent_metadata.uid()
        || metadata.len() > MAX_EVENT_JOURNAL_BYTES
    {
        return Err(RuntimeEventErrorV1::Invalid("journal file"));
    }
    Ok((target, parent, file))
}

fn read_exact_events(file: &File) -> Result<Vec<SignedRuntimeEventV1>, RuntimeEventErrorV1> {
    let metadata = file.metadata().map_err(RuntimeEventErrorV1::Io)?;
    if metadata.len() > MAX_EVENT_JOURNAL_BYTES {
        return Err(RuntimeEventErrorV1::TooLarge);
    }
    let mut reader = file.try_clone().map_err(RuntimeEventErrorV1::Io)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(RuntimeEventErrorV1::Io)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| RuntimeEventErrorV1::TooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .read_to_end(&mut bytes)
        .map_err(RuntimeEventErrorV1::Io)?;
    if bytes.len() != capacity {
        return Err(RuntimeEventErrorV1::Invalid("journal changed while read"));
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        return Err(RuntimeEventErrorV1::Invalid("partial journal tail"));
    }
    let mut events = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(RuntimeEventErrorV1::Invalid("empty journal record"));
        }
        let event: SignedRuntimeEventV1 =
            serde_json::from_slice(line).map_err(RuntimeEventErrorV1::Json)?;
        if serde_json::to_vec(&event).map_err(RuntimeEventErrorV1::Json)? != line {
            return Err(RuntimeEventErrorV1::Invalid("non-canonical journal JSON"));
        }
        events.push(event);
    }
    Ok(events)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn signature_root(event_hash: [u8; 32]) -> [u8; 32] {
    domain_hash(EVENT_SIGNATURE_DOMAIN, &event_hash)
}

fn decode_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], RuntimeEventErrorV1> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimeEventErrorV1::Invalid(field));
    }
    let bytes = hex::decode(value).map_err(|_| RuntimeEventErrorV1::Invalid(field))?;
    bytes
        .try_into()
        .map_err(|_| RuntimeEventErrorV1::Invalid(field))
}

#[derive(Debug)]
pub enum RuntimeEventErrorV1 {
    Io(std::io::Error),
    Json(serde_json::Error),
    Invalid(&'static str),
    TooLarge,
    FailStopped,
    RestartCutRequiredForProcess2,
    ExternalAuthorityRequired,
}

impl RuntimeEventErrorV1 {
    /// The only recoverable normal-start outcome. Every parse, signature,
    /// ancestry, context, lock, and bounded-profile failure remains distinct
    /// and must be propagated without attempting RestartCut dispatch.
    pub(crate) const fn requires_stored_restart_cut_v1(&self) -> bool {
        matches!(self, Self::RestartCutRequiredForProcess2)
    }
}

impl fmt::Display for RuntimeEventErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "runtime event I/O: {error}"),
            Self::Json(error) => write!(formatter, "runtime event JSON: {error}"),
            Self::Invalid(reason) => write!(formatter, "invalid runtime event: {reason}"),
            Self::TooLarge => formatter.write_str("runtime event journal exceeds its bound"),
            Self::FailStopped => formatter.write_str("runtime event journal is fail-stopped"),
            Self::RestartCutRequiredForProcess2 => formatter.write_str(
                "verified Cut/Park/ParkedAck authority is required before process-2 journal start",
            ),
            Self::ExternalAuthorityRequired => formatter.write_str(
                "ExternalAuthorityRequired: runtime-event signing producer is not injected",
            ),
        }
    }
}

impl std::error::Error for RuntimeEventErrorV1 {}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;
    use trnm_consensus_signer_journal::SignerWatermarkV0;
    use trnm_consensus_types::{
        BlockId, CertificateId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
        GenesisHash, Height, ProtocolVersion, QcRef, StateRoot, Validator, View, VotingPower,
    };

    use crate::{
        consensus_runtime::{
            LocalRestartPeerJournalPreparedOwnerV1, LocalRestartPeerQuiescedOwnerV1,
            LocalRestartTargetPreparedOwnerV1,
        },
        fleet_barrier::{
            CommonCampaignContextV1, CommonChainCutV1, FleetBarrierTransportV1,
            FleetCampaignCapacitiesV1, FleetCampaignIdentityV1, FleetCampaignRequestV1,
            FleetMeshSessionDirectionV1, FleetMeshSessionSetV1, FleetMeshSessionV1,
            FleetReadySetV1, FleetStartCertificateV1, LocalReadyCutV1, SignedFleetReadyV1,
            SignedFleetStartV1,
        },
        frame::{AuthenticatedFrame, FrameKind},
        restart_cut::{
            LocalRestartParkV1, RestartCutBodyV1, RestartCutCertificateV1,
            RestartCutParkStatementV1, RestartCutStateV1, RestartParkCertificateV1,
            RestartParkRoleV1, RestartParkedAckCertificateV1, RestartParkedAckCommonV1,
            SignedLocalRestartParkV1, SignedRestartCutV1, SignedRestartParkedAckV1,
        },
        restart_park_protocol::{
            persist_restart_cut_park_at_test_root_v1, AdmittedRestartCutParkV1,
            AdmittedRestartPrepareV1, OriginatedRestartCutParkV1,
            StoredRestartCutParkCertificatesV1, VerifiedRestartCutParkCertificatesV1,
        },
        restart_parked_ack_store::persist_restart_parked_ack_certificate_v1,
        restart_protocol::{BoundedRestartProtocolIngressV1, RestartProtocolPhaseV1},
    };

    use super::*;

    fn fixture() -> (TempDir, RuntimeEventContextV1, SigningKey) {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = SigningKey::from_bytes(&[0x31; 32]);
        let validator_id = ValidatorId::new([0x41; 32]);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let mut validators = vec![Validator::new(
            validator_id,
            ConsensusPublicKey::new(key.verifying_key().to_bytes()),
            VotingPower::new(1).unwrap(),
        )
        .unwrap()];
        validators.extend((0u8..6).map(|index| {
            let peer_key = SigningKey::from_bytes(&[0x51 + index; 32]);
            Validator::new(
                ValidatorId::new([0x71 + index; 32]),
                ConsensusPublicKey::new(peer_key.verifying_key().to_bytes()),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()
        }));
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0x51; 32]),
            ChainId::new("trnm-poco-g3-runtime-event-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        let context = RuntimeEventContextV1 {
            run_id: "poco-g3-7-20260814T000000Z-1234abcd".to_owned(),
            validator_id,
            validator_set,
            coordinator_manifest_sha256: [0x61; 32],
            validator_set_sha256: [0x62; 32],
            config_sha256: [0x63; 32],
            candidate_source_sha256: [0x64; 32],
            binary_sha256: [0x65; 32],
        };
        (temporary, context, key)
    }

    fn process2_validator_fixture() -> (ValidatorSet, Vec<SigningKey>) {
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
            ChainId::new("trnm-poco-g3-process2-gate-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn process2_campaign(
        set: &ValidatorSet,
        run_id: &str,
        identity_salt: u8,
    ) -> CommonCampaignContextV1 {
        CommonCampaignContextV1::new(
            FleetCampaignIdentityV1::new(
                run_id.to_owned(),
                set.chain_id(),
                *set.genesis_hash().as_bytes(),
                *set.id().as_bytes(),
                [identity_salt; 32],
                [identity_salt + 1; 32],
                [identity_salt + 2; 32],
                [identity_salt + 3; 32],
                [identity_salt + 4; 32],
                [identity_salt + 5; 32],
                [identity_salt + 6; 32],
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

    fn process2_mesh_and_local_cut(
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

    fn process2_fleet_start_certificate(
        set: &ValidatorSet,
        keys: &[SigningKey],
        campaign: &CommonCampaignContextV1,
        event_salt: u8,
    ) -> FleetStartCertificateV1 {
        let ready = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let (mesh, local_cut) = process2_mesh_and_local_cut(set, index);
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

    fn process2_restart_state(
        set: &ValidatorSet,
        runtime_journal_head: (u64, [u8; 32]),
    ) -> RestartCutStateV1 {
        RestartCutStateV1 {
            epoch: Epoch::new(0),
            current_view: View::new(10),
            direct_high_qc: QcRef::new(
                CertificateId::new([0x81; 32]),
                Epoch::new(0),
                View::new(9),
                Height::new(8),
                BlockId::new([0x82; 32]),
                set.id(),
            ),
            proposal_parent_height: Height::new(8),
            proposal_parent_block_id: BlockId::new([0x82; 32]),
            finalized_height: Height::new(6),
            finalized_block_id: BlockId::new([0x83; 32]),
            finalized_chain_root: [0x8f; 32],
            application_height: Height::new(6),
            application_block_id: BlockId::new([0x83; 32]),
            application_state_root: StateRoot::new([0x84; 32]),
            external_checkpoint_generation: 12,
            external_checkpoint_checksum: [0x85; 32],
            safety_revision: 13,
            safety_state_record_checksum: [0x8c; 32],
            safety_record_chain_checksum: [0x8d; 32],
            signer_watermark: SignerWatermarkV0::from_persisted_parts(
                [0x89; 32], [0x8a; 32], 6, [0x8b; 32],
            )
            .unwrap(),
            signer_durable_vote_intent_count: 2,
            signer_durable_timeout_intent_count: 1,
            signer_signed_vote_intent_count: 2,
            signer_signed_timeout_intent_count: 1,
            signer_inventory_digest: [0x8e; 32],
            pending_sign: None,
            replay_archive_context_sha256: [0x86; 32],
            replay_archive_head_sequence: 4,
            replay_archive_head_sha256: [0x87; 32],
            runtime_journal_head_sequence: runtime_journal_head.0,
            runtime_journal_head_sha256: runtime_journal_head.1,
        }
    }

    fn process2_stored_restart_cut_park(
        root: &Path,
        set: &ValidatorSet,
        keys: &[SigningKey],
        campaign: &CommonCampaignContextV1,
        fleet_start: &FleetStartCertificateV1,
        target_index: usize,
        runtime_journal_head: (u64, [u8; 32]),
    ) -> StoredRestartCutParkCertificatesV1 {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let target = set.validators()[target_index].id();
        let target_config_sha256 = fleet_start
            .ready_set()
            .statement(target)
            .unwrap()
            .local_cut()
            .config_sha256();
        let body = RestartCutBodyV1::new(
            campaign.clone(),
            target,
            target_config_sha256,
            1,
            process2_restart_state(set, runtime_journal_head),
            fleet_start,
            set,
        )
        .unwrap();
        let statements = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                SignedRestartCutV1::new(set.validators()[index].id(), body.clone(), set, key)
                    .unwrap()
            })
            .collect();
        let certificate = RestartCutCertificateV1::new(statements, fleet_start, set).unwrap();
        let park_statements = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let local_validator = set.validators()[index].id();
                let local_config_sha256 = fleet_start
                    .ready_set()
                    .statement(local_validator)
                    .unwrap()
                    .local_cut()
                    .config_sha256();
                let role = if local_validator == target {
                    RestartParkRoleV1::Target
                } else {
                    RestartParkRoleV1::Peer
                };
                let local_park = LocalRestartParkV1::new(
                    role,
                    local_validator,
                    local_config_sha256,
                    1,
                    &body,
                    body.state(),
                    fleet_start,
                    set,
                )
                .unwrap();
                let digest = SignedLocalRestartParkV1::signing_digest_for_parts(
                    local_validator,
                    &body,
                    &local_park,
                    fleet_start,
                    set,
                )
                .unwrap();
                SignedLocalRestartParkV1::from_parts(
                    local_validator,
                    &body,
                    local_park,
                    key.sign(&digest).to_bytes(),
                    fleet_start,
                    set,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let park_certificate =
            RestartParkCertificateV1::new(body.clone(), park_statements, fleet_start, set).unwrap();
        persist_restart_cut_park_at_test_root_v1(
            root,
            target,
            target_config_sha256,
            fleet_start,
            set,
            certificate.verify_owned(fleet_start, set).unwrap(),
            park_certificate,
        )
        .unwrap()
    }

    struct Process2GateFixture {
        _temporary: TempDir,
        journal_path: PathBuf,
        context: RuntimeEventContextV1,
        key: SigningKey,
        keys: Vec<SigningKey>,
        campaign: CommonCampaignContextV1,
        fleet_start: FleetStartCertificateV1,
        restart_prepare_head: (u64, [u8; 32]),
        stored: StoredRestartCutParkCertificatesV1,
    }

    struct Process1CutCommitFixture {
        _temporary: TempDir,
        journal: RuntimeEventJournalV1,
        owner: LocalRestartTargetPreparedOwnerV1,
        stored: StoredRestartCutParkCertificatesV1,
    }

    struct AuthenticatedProcess2GateFixture {
        _temporary: TempDir,
        journal: RuntimeEventJournalV1,
        journal_path: PathBuf,
        context: RuntimeEventContextV1,
        key: SigningKey,
        stored_cut_park: StoredRestartCutParkCertificatesV1,
        stored_ack: StoredRestartParkedAckCertificateV1,
        journal_witness: Process1TargetParkedAckJournalWitnessV1,
        ack_admission_set_sha256: [u8; 32],
    }

    fn process1_cut_commit_fixture() -> Process1CutCommitFixture {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (set, keys) = process2_validator_fixture();
        let campaign = process2_campaign(&set, "poco-g3-7-20260814T000000Z-89abcdef", 0x41);
        let fleet_start = process2_fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let target_index = 2;
        let target = set.validators()[target_index].id();
        let identity = campaign.identity();
        let context = RuntimeEventContextV1 {
            run_id: identity.run_id().to_owned(),
            validator_id: target,
            validator_set: set,
            coordinator_manifest_sha256: identity.coordinator_manifest_sha256(),
            validator_set_sha256: identity.validator_set_sha256(),
            config_sha256: fleet_start
                .ready_set()
                .statement(target)
                .unwrap()
                .local_cut()
                .config_sha256(),
            candidate_source_sha256: identity.candidate_source_sha256(),
            binary_sha256: identity.binary_sha256(),
        };
        let key = keys[target_index].clone();
        let journal_root = temporary.path().join("process1-journal");
        fs::create_dir(&journal_root).unwrap();
        fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = journal_root.join("process1-cut-commit-events.jsonl");
        let mut journal =
            RuntimeEventJournalV1::start_with_context(&journal_path, context.clone(), key.clone())
                .unwrap();
        journal
            .append(RuntimeEventKindV1::Finalized, &hex::encode([0x71; 32]), 3)
            .unwrap();
        journal
            .append(
                RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode([0x72; 32]),
                3,
            )
            .unwrap();
        journal
            .record_fleet_ready(fleet_start.ready_set().digest(), 1)
            .unwrap();
        let fleet_start_sha256: [u8; 32] = Sha256::digest(fleet_start.encode()).into();
        journal.record_fleet_started(fleet_start_sha256, 1).unwrap();
        let restart_prepare_monotonic_ns = journal.last_monotonic_ns;
        let restart_prepare = journal
            .append_raw(
                "restart_prepare",
                &hex::encode([0xd1; 32]),
                29,
                restart_prepare_monotonic_ns,
            )
            .unwrap();
        let restart_prepare_head = (
            restart_prepare.sequence,
            decode_hex(&restart_prepare.event_sha256, "restart prepare event hash").unwrap(),
        );
        let stored = process2_stored_restart_cut_park(
            &temporary.path().join("restart-cut-store"),
            &context.validator_set,
            &keys,
            &campaign,
            &fleet_start,
            target_index,
            restart_prepare_head,
        );
        let target_prepare = SignedRestartCutV1::new(
            target,
            stored.body_v1().clone(),
            &context.validator_set,
            &key,
        )
        .unwrap();
        assert!(stored.contains_exact_target_prepare_v1(&target_prepare));
        let owner = LocalRestartTargetPreparedOwnerV1::from_target_prepare_for_journal_test_v1(
            target_prepare,
        )
        .unwrap();
        Process1CutCommitFixture {
            _temporary: temporary,
            journal,
            owner,
            stored,
        }
    }

    fn process2_gate_fixture() -> Process2GateFixture {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (set, keys) = process2_validator_fixture();
        let campaign = process2_campaign(&set, "poco-g3-7-20260814T000000Z-89abcdef", 0x41);
        let fleet_start = process2_fleet_start_certificate(&set, &keys, &campaign, 0xd0);
        let target_index = 2;
        let target = set.validators()[target_index].id();
        let identity = campaign.identity();
        let context = RuntimeEventContextV1 {
            run_id: identity.run_id().to_owned(),
            validator_id: target,
            validator_set: set,
            coordinator_manifest_sha256: identity.coordinator_manifest_sha256(),
            validator_set_sha256: identity.validator_set_sha256(),
            config_sha256: fleet_start
                .ready_set()
                .statement(target)
                .unwrap()
                .local_cut()
                .config_sha256(),
            candidate_source_sha256: identity.candidate_source_sha256(),
            binary_sha256: identity.binary_sha256(),
        };
        let key = keys[target_index].clone();
        let journal_path = temporary.path().join("process2-gate-events.jsonl");
        let mut first =
            RuntimeEventJournalV1::start_with_context(&journal_path, context.clone(), key.clone())
                .unwrap();
        first
            .append(RuntimeEventKindV1::Finalized, &hex::encode([0x71; 32]), 3)
            .unwrap();
        first
            .append(
                RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode([0x72; 32]),
                3,
            )
            .unwrap();
        first
            .record_fleet_ready(fleet_start.ready_set().digest(), 1)
            .unwrap();
        let fleet_start_sha256: [u8; 32] = Sha256::digest(fleet_start.encode()).into();
        first.record_fleet_started(fleet_start_sha256, 1).unwrap();
        let restart_prepare_monotonic_ns = first.last_monotonic_ns;
        let restart_prepare = first
            .append_raw(
                "restart_prepare",
                &hex::encode([0xd1; 32]),
                29,
                restart_prepare_monotonic_ns,
            )
            .unwrap();
        let restart_prepare_head = (
            restart_prepare.sequence,
            decode_hex(&restart_prepare.event_sha256, "restart prepare event hash").unwrap(),
        );
        let stored = process2_stored_restart_cut_park(
            &temporary.path().join("restart-cut-store"),
            &context.validator_set,
            &keys,
            &campaign,
            &fleet_start,
            target_index,
            restart_prepare_head,
        );
        let restart_cut_monotonic_ns = first.last_monotonic_ns;
        let cut_subject = RestartCutParkSubjectV1 {
            cut_artifact_sha256: stored.cut_artifact_sha256_v1(),
            park_artifact_sha256: stored.park_artifact_sha256_v1(),
            body_sha256: stored.body_v1().digest(),
            admission_set_sha256: stored.admission_set_sha256_v1(),
        };
        let park_subject = RestartParkSubjectV1 {
            park_artifact_sha256: cut_subject.park_artifact_sha256,
            local_park_statement_sha256: stored.local_park_statement_sha256_v1(),
        };
        first
            .append_raw(
                "restart_cut",
                &cut_subject.encode(),
                u64::try_from(stored.statement_count_v1()).unwrap(),
                restart_cut_monotonic_ns,
            )
            .unwrap();
        first
            .append_raw(
                "restart_park",
                &park_subject.encode(),
                u64::try_from(stored.statement_count_v1()).unwrap(),
                restart_cut_monotonic_ns,
            )
            .unwrap();
        drop(first);
        Process2GateFixture {
            _temporary: temporary,
            journal_path,
            context,
            key,
            keys,
            campaign,
            fleet_start,
            restart_prepare_head,
            stored,
        }
    }

    fn process2_stored_restart_parked_ack(
        stored: &StoredRestartCutParkCertificatesV1,
        keys: &[SigningKey],
        commit: &LocalRestartParkJournalCommitV1,
    ) -> (StoredRestartParkedAckCertificateV1, [u8; 32]) {
        let validator_set = stored.validator_set_v1();
        let fleet_start = stored.fleet_start_certificate_v1();
        assert_eq!(keys.len(), validator_set.validators().len());
        assert_eq!(commit.local_validator_v1(), stored.local_validator_v1());
        assert_eq!(commit.role_v1(), RestartParkRoleV1::Target);
        let common = RestartParkedAckCommonV1::new(
            fleet_start,
            stored.cut_certificate_v1(),
            stored.park_certificate_v1(),
            stored.admission_set_sha256_v1(),
            validator_set,
        )
        .unwrap();
        let statements = validator_set
            .validators()
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (validator, key))| {
                let origin = validator.id();
                let local_park_statement = stored.park_certificate_v1().statement(origin).unwrap();
                let local_park = local_park_statement.local_park();
                let predecessor_sequence = local_park.local_state().runtime_journal_head_sequence;
                let predecessor_sha256 = local_park.local_state().runtime_journal_head_sha256;
                let restart_cut_event_sequence = predecessor_sequence + 1;
                let restart_park_event_sequence = restart_cut_event_sequence + 1;
                let (restart_cut_event_sha256, restart_park_event_sha256) =
                    if origin == stored.local_validator_v1() {
                        assert_eq!(
                            (predecessor_sequence, predecessor_sha256),
                            (
                                commit.predecessor_sequence_v1(),
                                commit.predecessor_sha256_v1(),
                            )
                        );
                        assert_eq!(
                            restart_cut_event_sequence,
                            commit.restart_cut_event_sequence_v1()
                        );
                        assert_eq!(
                            restart_park_event_sequence,
                            commit.restart_park_event_sequence_v1()
                        );
                        (
                            commit.restart_cut_event_sha256_v1(),
                            commit.restart_park_event_sha256_v1(),
                        )
                    } else {
                        (
                            [0x31 + u8::try_from(index).unwrap(); 32],
                            [0x41 + u8::try_from(index).unwrap(); 32],
                        )
                    };
                let digest = SignedRestartParkedAckV1::signing_digest_for_parts(
                    common,
                    origin,
                    local_park.role(),
                    local_park.local_config_sha256(),
                    local_park_statement.statement_sha256(),
                    predecessor_sequence,
                    predecessor_sha256,
                    restart_cut_event_sequence,
                    restart_cut_event_sha256,
                    restart_park_event_sequence,
                    restart_park_event_sha256,
                    fleet_start,
                    stored.cut_certificate_v1(),
                    stored.park_certificate_v1(),
                    stored.admission_set_sha256_v1(),
                    validator_set,
                )
                .unwrap();
                SignedRestartParkedAckV1::from_parts(
                    common,
                    origin,
                    local_park.role(),
                    local_park.local_config_sha256(),
                    local_park_statement.statement_sha256(),
                    predecessor_sequence,
                    predecessor_sha256,
                    restart_cut_event_sequence,
                    restart_cut_event_sha256,
                    restart_park_event_sequence,
                    restart_park_event_sha256,
                    key.sign(&digest).to_bytes(),
                    fleet_start,
                    stored.cut_certificate_v1(),
                    stored.park_certificate_v1(),
                    stored.admission_set_sha256_v1(),
                    validator_set,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate = RestartParkedAckCertificateV1::new(
            common,
            statements,
            fleet_start,
            stored.cut_certificate_v1(),
            stored.park_certificate_v1(),
            stored.admission_set_sha256_v1(),
            validator_set,
        )
        .unwrap();
        let message_ids = certificate
            .statements()
            .iter()
            .map(|statement| {
                (
                    statement.origin(),
                    restart_protocol_message_id_for_parts_v1(
                        validator_set.id(),
                        statement.origin(),
                        RestartProtocolPhaseV1::ParkedAck,
                        &statement.encode(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let ack_admission_set_sha256 =
            restart_parked_ack_admission_set_sha256_for_ids_v1(&message_ids, validator_set)
                .unwrap();
        let artifact_sha256: [u8; 32] = Sha256::digest(certificate.encode()).into();
        let local_witness = RestartParkedAckLocalWitnessV1::new(
            RestartParkRoleV1::Target,
            commit.local_park_statement_sha256_v1(),
            commit.predecessor_sequence_v1(),
            commit.predecessor_sha256_v1(),
            commit.restart_cut_event_sequence_v1(),
            commit.restart_cut_event_sha256_v1(),
            commit.restart_park_event_sequence_v1(),
            commit.restart_park_event_sha256_v1(),
        )
        .unwrap();
        let stored_ack = persist_restart_parked_ack_certificate_v1(
            stored.cut_path_v1().parent().unwrap(),
            artifact_sha256,
            certificate,
            stored.cut_artifact_sha256_v1(),
            stored.cut_certificate_v1(),
            stored.park_artifact_sha256_v1(),
            stored.park_certificate_v1(),
            stored.admission_set_sha256_v1(),
            stored.local_validator_v1(),
            stored.local_config_sha256_v1(),
            local_witness,
            fleet_start,
            validator_set,
        )
        .unwrap();
        (stored_ack, ack_admission_set_sha256)
    }

    fn authenticated_process2_gate_fixture() -> AuthenticatedProcess2GateFixture {
        let Process1CutCommitFixture {
            _temporary,
            mut journal,
            owner,
            stored,
        } = process1_cut_commit_fixture();
        let journal_path = journal.path().to_owned();
        let context = journal.context.clone();
        let (_set, keys) = process2_validator_fixture();
        let target_index = context
            .validator_set
            .validators()
            .iter()
            .position(|validator| validator.id() == context.validator_id)
            .unwrap();
        let key = keys[target_index].clone();
        let (_cut_event, park_event, commit) = journal
            .record_restart_cut_park_from_owner_v1(&owner, &stored)
            .unwrap();
        let (stored_ack, ack_admission_set_sha256) =
            process2_stored_restart_parked_ack(&stored, &keys, &commit);
        let parked_ack_event = journal
            .record_restart_parked_ack_internal_v1(
                &commit,
                &stored_ack,
                stored.fleet_start_certificate_v1(),
                ack_admission_set_sha256,
            )
            .unwrap();
        assert_eq!(parked_ack_event.sequence, park_event.sequence + 1);
        assert_eq!(
            parked_ack_event.previous_event_sha256,
            park_event.event_sha256
        );
        assert_eq!(
            journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1TargetParkedAcked
        );
        let named_file = journal.reopen_exact_named_journal_v1().unwrap();
        let events = read_exact_events(&named_file).unwrap();
        let recovered = validate_event_chain(&events, &context).unwrap();
        let journal_witness =
            process1_target_parked_ack_journal_witness_v1(&events, &recovered, &context).unwrap();
        assert_eq!(
            journal_witness.ack_admission_set_sha256,
            ack_admission_set_sha256
        );
        assert_eq!(
            journal_witness.ack_artifact_sha256,
            stored_ack.artifact_sha256_v1()
        );
        AuthenticatedProcess2GateFixture {
            _temporary,
            journal,
            journal_path,
            context,
            key,
            stored_cut_park: stored,
            stored_ack,
            journal_witness,
            ack_admission_set_sha256,
        }
    }

    fn rewrite_terminal_restart_cut_authority(
        path: &Path,
        key: &SigningKey,
        stored: &StoredRestartCutParkCertificatesV1,
    ) {
        let file = File::open(path).unwrap();
        let mut events = read_exact_events(&file).unwrap();
        let restart_cut = events
            .iter_mut()
            .rev()
            .find(|event| event.kind == "restart_cut")
            .unwrap();
        assert_eq!(restart_cut.kind, "restart_cut");
        let prior = RestartCutParkSubjectV1::decode(&restart_cut.subject).unwrap();
        restart_cut.subject = RestartCutParkSubjectV1 {
            cut_artifact_sha256: stored.cut_artifact_sha256_v1(),
            body_sha256: stored.body_v1().digest(),
            ..prior
        }
        .encode();
        restart_cut.value = u64::try_from(stored.statement_count_v1()).unwrap();
        rechain_and_resign(&mut events, key);
        write_canonical_events(path, &events);
    }

    fn assert_process2_gate_rejects_without_mutation(
        path: &Path,
        context: RuntimeEventContextV1,
        key: SigningKey,
        stored: StoredRestartCutParkCertificatesV1,
    ) {
        let before = fs::read(path).unwrap();
        assert!(
            RuntimeEventJournalV1::start_process2_with_context_and_stored_restart_cut_v1(
                path, context, key, stored,
            )
            .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), before);
    }

    fn write_canonical_events(path: &Path, events: &[SignedRuntimeEventV1]) {
        let mut bytes = Vec::new();
        for event in events {
            bytes.extend(serde_json::to_vec(event).unwrap());
            bytes.push(b'\n');
        }
        fs::write(path, bytes).unwrap();
    }

    fn rechain_and_resign(events: &mut [SignedRuntimeEventV1], key: &SigningKey) {
        let mut previous = [0; 32];
        for (index, event) in events.iter_mut().enumerate() {
            event.sequence = u64::try_from(index).unwrap();
            event.previous_event_sha256 = hex::encode(previous);
            let hash = event.computed_hash().unwrap();
            event.event_sha256 = hex::encode(hash);
            event.signature = hex::encode(key.sign(&signature_root(hash)).to_bytes());
            previous = hash;
        }
    }

    fn enter_fleet_started(journal: &mut RuntimeEventJournalV1) {
        journal
            .append(RuntimeEventKindV1::Finalized, &hex::encode([0x71; 32]), 3)
            .unwrap();
        journal
            .append(
                RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode([0x72; 32]),
                3,
            )
            .unwrap();
        journal.record_fleet_ready([0x73; 32], 1).unwrap();
        journal.record_fleet_started([0x74; 32], 1).unwrap();
    }

    #[test]
    fn typed_peer_park_prepare_commits_exact_prepare_before_local_park_state_v1() {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (set, keys) = process2_validator_fixture();
        let run_id = "poco-g3-7-20260814T010000Z-1234abcd";
        let campaign = process2_campaign(&set, run_id, 0x31);
        let fleet_start = process2_fleet_start_certificate(&set, &keys, &campaign, 0x41);
        let local_index = 0;
        let target_index = 1;
        let local_validator = set.validators()[local_index].id();
        let target_validator = set.validators()[target_index].id();
        let local_config_sha256 = fleet_start
            .ready_set()
            .statement(local_validator)
            .unwrap()
            .local_cut()
            .config_sha256();
        let target_config_sha256 = fleet_start
            .ready_set()
            .statement(target_validator)
            .unwrap()
            .local_cut()
            .config_sha256();
        let context = RuntimeEventContextV1 {
            run_id: run_id.to_owned(),
            validator_id: local_validator,
            validator_set: set.clone(),
            coordinator_manifest_sha256: [0x51; 32],
            validator_set_sha256: [0x52; 32],
            config_sha256: local_config_sha256,
            candidate_source_sha256: [0x53; 32],
            binary_sha256: [0x54; 32],
        };
        let path = temporary.path().join("typed-peer-park-prepare.jsonl");
        let mut journal = RuntimeEventJournalV1::start_with_context(
            &path,
            context.clone(),
            keys[local_index].clone(),
        )
        .unwrap();
        enter_fleet_started(&mut journal);
        let predecessor = journal.last_event_facts().unwrap();

        let mut state = process2_restart_state(&set, predecessor);
        state.finalized_height = Height::new(3);
        state.application_height = Height::new(3);
        let body = RestartCutBodyV1::new(
            campaign,
            target_validator,
            target_config_sha256,
            1,
            state,
            &fleet_start,
            &set,
        )
        .unwrap();
        let target_prepare =
            SignedRestartCutV1::new(target_validator, body, &set, &keys[target_index]).unwrap();
        let bytes = AuthenticatedFrame {
            sender: target_validator,
            session: [0x55; 32],
            sequence: 0,
            kind: FrameKind::RestartPrepare,
            payload: target_prepare.encode(),
        }
        .encode(run_id, &keys[target_index])
        .unwrap();
        let mut ingress =
            BoundedRestartProtocolIngressV1::new(run_id, local_validator, set.clone()).unwrap();
        let admitted = ingress
            .admit_verified_signed_frame_bytes_v1(&bytes)
            .unwrap()
            .action
            .unwrap()
            .into_admitted_message_v1();
        let admitted = AdmittedRestartPrepareV1::new(admitted, &fleet_start, &set).unwrap();
        let expected_body_sha256 = admitted.body_v1().digest();
        let expected_message_id = admitted.message_id_v1();
        let owner = LocalRestartPeerQuiescedOwnerV1::from_admitted_prepare_for_journal_test_v1(
            admitted,
            local_validator,
            local_config_sha256,
            state,
            predecessor,
        )
        .unwrap();

        let event = journal
            .record_restart_park_prepare_from_owner_v1(&owner)
            .unwrap();
        let subject = RestartParkPrepareSubjectV1::decode(&event.subject).unwrap();
        assert_eq!(subject.target_validator, target_validator);
        assert_eq!(subject.body_sha256, expected_body_sha256);
        assert_eq!(subject.prepare_message_id, expected_message_id);
        assert_eq!(event.value, 3);
        assert_eq!(event.previous_event_sha256, hex::encode(predecessor.1));
        assert_eq!(
            journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParkPreparePending
        );
        let successor = journal.last_event_facts().unwrap();
        assert_eq!(successor.0, event.sequence);
        assert_eq!(hex::encode(successor.1), event.event_sha256);

        let parked_state = owner
            .into_local_state_for_journal_test_v1(successor.0, successor.1)
            .unwrap();
        assert_eq!(
            (
                parked_state.runtime_journal_head_sequence,
                parked_state.runtime_journal_head_sha256,
            ),
            successor
        );
        assert_ne!(successor, predecessor);
    }

    struct TypedPeerSevenWayBarrierFixtureV1 {
        _temporary: TempDir,
        path: PathBuf,
        context: RuntimeEventContextV1,
        journal: RuntimeEventJournalV1,
        prepared_owner: LocalRestartPeerJournalPreparedOwnerV1,
        stored: StoredRestartCutParkCertificatesV1,
        prepare_event: SignedRuntimeEventV1,
        body: RestartCutBodyV1,
        expected_cut_artifact_sha256: [u8; 32],
        expected_park_artifact_sha256: [u8; 32],
        expected_admission_set_sha256: [u8; 32],
        expected_local_park_statement_sha256: [u8; 32],
    }

    fn typed_peer_seven_way_barrier_fixture_v1() -> TypedPeerSevenWayBarrierFixtureV1 {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (set, keys) = process2_validator_fixture();
        assert_eq!(set.validators().len(), 7);
        let run_id = "poco-g3-7-20260818T020000Z-5678abcd";
        let campaign = process2_campaign(&set, run_id, 0x35);
        assert_eq!(
            campaign.request().transport(),
            FleetBarrierTransportV1::Direct
        );
        let fleet_start = process2_fleet_start_certificate(&set, &keys, &campaign, 0x45);
        let local_index = 0;
        let target_index = 1;
        let local_validator = set.validators()[local_index].id();
        let target_validator = set.validators()[target_index].id();
        let local_config_sha256 = fleet_start
            .ready_set()
            .statement(local_validator)
            .unwrap()
            .local_cut()
            .config_sha256();
        let target_config_sha256 = fleet_start
            .ready_set()
            .statement(target_validator)
            .unwrap()
            .local_cut()
            .config_sha256();
        let identity = campaign.identity();
        let context = RuntimeEventContextV1 {
            run_id: run_id.to_owned(),
            validator_id: local_validator,
            validator_set: set.clone(),
            coordinator_manifest_sha256: identity.coordinator_manifest_sha256(),
            validator_set_sha256: identity.validator_set_sha256(),
            config_sha256: local_config_sha256,
            candidate_source_sha256: identity.candidate_source_sha256(),
            binary_sha256: identity.binary_sha256(),
        };
        let path = temporary.path().join("typed-peer-seven-way-barrier.jsonl");
        let mut journal = RuntimeEventJournalV1::start_with_context(
            &path,
            context.clone(),
            keys[local_index].clone(),
        )
        .unwrap();
        journal
            .append(RuntimeEventKindV1::Finalized, &hex::encode([0x71; 32]), 3)
            .unwrap();
        journal
            .append(
                RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode([0x72; 32]),
                3,
            )
            .unwrap();
        journal
            .record_fleet_ready(fleet_start.ready_set().digest(), 1)
            .unwrap();
        let fleet_start_sha256: [u8; 32] = Sha256::digest(fleet_start.encode()).into();
        journal.record_fleet_started(fleet_start_sha256, 1).unwrap();
        let predecessor = journal.last_event_facts().unwrap();

        let mut target_state = process2_restart_state(&set, predecessor);
        target_state.finalized_height = Height::new(3);
        target_state.application_height = Height::new(3);
        let body = RestartCutBodyV1::new(
            campaign,
            target_validator,
            target_config_sha256,
            1,
            target_state,
            &fleet_start,
            &set,
        )
        .unwrap();
        let target_prepare =
            SignedRestartCutV1::new(target_validator, body.clone(), &set, &keys[target_index])
                .unwrap();
        let prepare_bytes = AuthenticatedFrame {
            sender: target_validator,
            session: [0x55; 32],
            sequence: 0,
            kind: FrameKind::RestartPrepare,
            payload: target_prepare.encode(),
        }
        .encode(run_id, &keys[target_index])
        .unwrap();
        let mut ingress =
            BoundedRestartProtocolIngressV1::new(run_id, local_validator, set.clone()).unwrap();
        let admitted_prepare = ingress
            .admit_verified_signed_frame_bytes_v1(&prepare_bytes)
            .unwrap()
            .action
            .unwrap()
            .into_admitted_message_v1();
        let admitted_prepare =
            AdmittedRestartPrepareV1::new(admitted_prepare, &fleet_start, &set).unwrap();
        assert_eq!(admitted_prepare.declaration_v1(), &target_prepare);
        let expected_prepare_message_id = admitted_prepare.message_id_v1();
        let quiesced = LocalRestartPeerQuiescedOwnerV1::from_admitted_prepare_for_journal_test_v1(
            admitted_prepare,
            local_validator,
            local_config_sha256,
            target_state,
            predecessor,
        )
        .unwrap();

        let prepare_event = journal
            .record_restart_park_prepare_from_owner_v1(&quiesced)
            .unwrap();
        let prepare_subject = RestartParkPrepareSubjectV1::decode(&prepare_event.subject).unwrap();
        assert_eq!(
            prepare_subject,
            RestartParkPrepareSubjectV1 {
                target_validator,
                body_sha256: body.digest(),
                prepare_message_id: expected_prepare_message_id,
            }
        );
        assert_eq!(prepare_event.value, 3);
        assert_eq!(
            prepare_event.previous_event_sha256,
            hex::encode(predecessor.1)
        );
        let prepare_successor = journal.last_event_facts().unwrap();
        assert_eq!(prepare_successor.0, prepare_event.sequence);
        assert_eq!(hex::encode(prepare_successor.1), prepare_event.event_sha256);
        assert_eq!(
            journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParkPreparePending
        );
        let (prepared_owner, admitted_prepare) = quiesced
            .into_barrier_parts_for_journal_test_v1(prepare_successor.0, prepare_successor.1)
            .unwrap();
        let local_park_state = prepared_owner.local_state_v1();
        assert_eq!(
            (
                local_park_state.runtime_journal_head_sequence,
                local_park_state.runtime_journal_head_sha256,
            ),
            prepare_successor
        );

        let dual_statements = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let origin = set.validators()[index].id();
                let cut = if origin == target_validator {
                    target_prepare.clone()
                } else {
                    SignedRestartCutV1::new(origin, body.clone(), &set, key).unwrap()
                };
                let role = if origin == target_validator {
                    RestartParkRoleV1::Target
                } else {
                    RestartParkRoleV1::Peer
                };
                let local_state = if origin == local_validator {
                    local_park_state
                } else {
                    target_state
                };
                let config_sha256 = fleet_start
                    .ready_set()
                    .statement(origin)
                    .unwrap()
                    .local_cut()
                    .config_sha256();
                let local_park = LocalRestartParkV1::new(
                    role,
                    origin,
                    config_sha256,
                    1,
                    &body,
                    local_state,
                    &fleet_start,
                    &set,
                )
                .unwrap();
                let park_digest = SignedLocalRestartParkV1::signing_digest_for_parts(
                    origin,
                    &body,
                    &local_park,
                    &fleet_start,
                    &set,
                )
                .unwrap();
                let park = SignedLocalRestartParkV1::from_parts(
                    origin,
                    &body,
                    local_park,
                    key.sign(&park_digest).to_bytes(),
                    &fleet_start,
                    &set,
                )
                .unwrap();
                RestartCutParkStatementV1::new(cut, park, &fleet_start, &set).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(dual_statements.len(), 7);
        assert_eq!(
            dual_statements[target_index].cut(),
            admitted_prepare.declaration_v1()
        );
        let expected_local_park_statement_sha256 =
            dual_statements[local_index].park().statement_sha256();

        let mut originated_local = None;
        let mut admitted_remote = Vec::with_capacity(6);
        for (index, statement) in dual_statements.into_iter().enumerate() {
            let origin = statement.origin();
            let payload = statement.encode();
            if origin == local_validator {
                let reservation = ingress
                    .reserve_originated_statement_v1(RestartProtocolPhaseV1::Cut, &payload, None)
                    .unwrap();
                originated_local = Some(
                    OriginatedRestartCutParkV1::new_test_only(
                        reservation,
                        statement,
                        &fleet_start,
                        &set,
                    )
                    .unwrap(),
                );
            } else {
                let frame = AuthenticatedFrame {
                    sender: origin,
                    session: [0x60 + u8::try_from(index).unwrap(); 32],
                    sequence: if index == target_index { 1 } else { 0 },
                    kind: FrameKind::RestartCut,
                    payload,
                }
                .encode(run_id, &keys[index])
                .unwrap();
                let admitted = ingress
                    .admit_verified_signed_frame_bytes_v1(&frame)
                    .unwrap()
                    .action
                    .unwrap()
                    .into_admitted_message_v1();
                admitted_remote
                    .push(AdmittedRestartCutParkV1::new(admitted, &fleet_start, &set).unwrap());
            }
        }
        assert_eq!(admitted_remote.len(), 6);
        let barrier = VerifiedRestartCutParkCertificatesV1::new_with_originated_cut_v1(
            admitted_prepare,
            admitted_remote,
            originated_local.unwrap(),
            &fleet_start,
            &set,
        )
        .unwrap();
        barrier.revalidate_v1(&fleet_start, &set).unwrap();
        assert_eq!(barrier.body_v1(), &body);
        assert_eq!(barrier.prepare_message_id_v1(), expected_prepare_message_id);
        assert_eq!(barrier.statement_count_v1(), 7);
        for validator in set.validators() {
            assert_ne!(
                barrier.statement_message_id_v1(validator.id()).unwrap(),
                [0; 32]
            );
        }
        let expected_cut_artifact_sha256 = barrier.cut_artifact_sha256_v1();
        let expected_park_artifact_sha256 = barrier.park_artifact_sha256_v1();
        let expected_admission_set_sha256 = barrier.admission_set_sha256_v1();
        assert_ne!(expected_cut_artifact_sha256, [0; 32]);
        assert_ne!(expected_park_artifact_sha256, [0; 32]);
        assert_ne!(expected_admission_set_sha256, [0; 32]);

        let store_root = temporary.path().join("peer-cut-park-store");
        fs::create_dir(&store_root).unwrap();
        fs::set_permissions(&store_root, fs::Permissions::from_mode(0o700)).unwrap();
        let stored = barrier
            .persist_peer_at_test_root_v1(
                &store_root,
                local_validator,
                local_config_sha256,
                &fleet_start,
                &set,
            )
            .unwrap();
        stored.revalidate_fresh_v1().unwrap();
        assert_eq!(stored.body_v1(), &body);
        assert_eq!(stored.local_validator_v1(), local_validator);
        assert_eq!(stored.local_config_sha256_v1(), local_config_sha256);
        assert_eq!(stored.local_role_v1(), RestartParkRoleV1::Peer);
        assert_eq!(stored.local_park_v1().local_state(), local_park_state);
        assert_eq!(stored.prepare_message_id_v1(), expected_prepare_message_id);
        assert_eq!(
            stored.admission_set_sha256_v1(),
            expected_admission_set_sha256
        );
        assert_eq!(
            stored.local_park_statement_sha256_v1(),
            expected_local_park_statement_sha256
        );
        assert_eq!(
            stored.cut_artifact_sha256_v1(),
            expected_cut_artifact_sha256
        );
        assert_eq!(
            stored.park_artifact_sha256_v1(),
            expected_park_artifact_sha256
        );
        assert_eq!(stored.statement_count_v1(), 7);
        assert!(stored.contains_exact_target_prepare_v1(prepared_owner.target_prepare_v1()));
        assert!(stored.cut_path_v1().is_file());
        assert!(stored.park_path_v1().is_file());

        TypedPeerSevenWayBarrierFixtureV1 {
            _temporary: temporary,
            path,
            context,
            journal,
            prepared_owner,
            stored,
            prepare_event,
            body,
            expected_cut_artifact_sha256,
            expected_park_artifact_sha256,
            expected_admission_set_sha256,
            expected_local_park_statement_sha256,
        }
    }

    #[test]
    fn typed_peer_seven_way_barrier_persists_and_commits_exact_parked_chain_v1() {
        let TypedPeerSevenWayBarrierFixtureV1 {
            _temporary,
            path,
            context,
            mut journal,
            prepared_owner,
            stored,
            prepare_event,
            body,
            expected_cut_artifact_sha256,
            expected_park_artifact_sha256,
            expected_admission_set_sha256,
            expected_local_park_statement_sha256,
        } = typed_peer_seven_way_barrier_fixture_v1();

        let (cut_event, park_event, commit) = journal
            .record_peer_restart_cut_park_from_stored_internal_v1(&prepared_owner, &stored)
            .unwrap();
        let expected_cut_subject = RestartCutParkSubjectV1 {
            cut_artifact_sha256: expected_cut_artifact_sha256,
            park_artifact_sha256: expected_park_artifact_sha256,
            body_sha256: body.digest(),
            admission_set_sha256: expected_admission_set_sha256,
        };
        let expected_park_subject = RestartParkSubjectV1 {
            park_artifact_sha256: expected_park_artifact_sha256,
            local_park_statement_sha256: expected_local_park_statement_sha256,
        };
        assert_eq!(cut_event.subject, expected_cut_subject.encode());
        assert_eq!(
            RestartCutParkSubjectV1::decode(&cut_event.subject).unwrap(),
            expected_cut_subject
        );
        assert_eq!(park_event.subject, expected_park_subject.encode());
        assert_eq!(
            RestartParkSubjectV1::decode(&park_event.subject).unwrap(),
            expected_park_subject
        );
        assert_eq!(cut_event.value, 7);
        assert_eq!(park_event.value, 7);
        assert_eq!(cut_event.sequence, prepare_event.sequence + 1);
        assert_eq!(cut_event.previous_event_sha256, prepare_event.event_sha256);
        assert_eq!(park_event.sequence, cut_event.sequence + 1);
        assert_eq!(park_event.previous_event_sha256, cut_event.event_sha256);
        assert_eq!(commit.role_v1(), RestartParkRoleV1::Peer);
        assert_eq!(commit.local_validator_v1(), context.validator_id);
        assert_eq!(commit.restart_cut_event_sequence_v1(), cut_event.sequence);
        assert_eq!(commit.restart_park_event_sequence_v1(), park_event.sequence);
        assert_eq!(
            commit.restart_park_event_sha256_v1(),
            decode_hex(&park_event.event_sha256, "peer park event hash").unwrap()
        );
        assert_eq!(
            journal.last_event_facts(),
            Some((
                park_event.sequence,
                decode_hex(&park_event.event_sha256, "peer park event hash").unwrap(),
            ))
        );
        assert_eq!(
            journal.restart_cut_facts_v1(),
            Some((expected_cut_artifact_sha256, 7))
        );
        assert_eq!(
            journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParked
        );
        stored.revalidate_fresh_v1().unwrap();

        let events = read_exact_events(&File::open(&path).unwrap()).unwrap();
        let recovered = validate_event_chain(&events, &context).unwrap();
        assert_eq!(
            recovered.previous_event_sha256,
            decode_hex(&park_event.event_sha256, "peer park event hash").unwrap()
        );
        assert_eq!(recovered.next_sequence, park_event.sequence + 1);
        assert_eq!(
            recovered.state.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParked
        );
        assert!(matches!(
            recovered.state.restart,
            RuntimeRestartJournalStateV1::Parked(facts)
                if facts.cut_park.preparation.role_v1() == RestartParkRoleV1::Peer
                    && facts.cut_park.subject == expected_cut_subject
                    && facts.subject == expected_park_subject
        ));
    }

    #[test]
    fn typed_peer_seven_way_barrier_rejects_mutated_park_without_journal_append_v1() {
        let mut fixture = typed_peer_seven_way_barrier_fixture_v1();
        let journal_before = fs::read(&fixture.path).unwrap();
        let head_before = fixture.journal.last_event_facts().unwrap();
        assert_eq!(
            fixture.journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParkPreparePending
        );

        let mut park_artifact = fs::read(fixture.stored.park_path_v1()).unwrap();
        let last = park_artifact.last_mut().unwrap();
        *last ^= 0x01;
        fs::write(fixture.stored.park_path_v1(), park_artifact).unwrap();

        let error = fixture
            .journal
            .record_peer_restart_cut_park_from_stored_internal_v1(
                &fixture.prepared_owner,
                &fixture.stored,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            RuntimeEventErrorV1::Invalid(
                "stored peer RestartCut/Park pair failed fresh authentication before journal append"
            )
        ));
        assert_eq!(fs::read(&fixture.path).unwrap(), journal_before);
        assert_eq!(fixture.journal.last_event_facts(), Some(head_before));
        assert_eq!(
            fixture.journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParkPreparePending
        );

        let events = read_exact_events(&File::open(&fixture.path).unwrap()).unwrap();
        let recovered = validate_event_chain(&events, &fixture.context).unwrap();
        assert_eq!(recovered.previous_event_sha256, head_before.1);
        assert_eq!(recovered.next_sequence, head_before.0 + 1);
        assert_eq!(
            recovered.state.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParkPreparePending
        );
    }

    /// The cfg(test) process-2 bypass skips only the durable StoredRestartCut
    /// capability. It deliberately does not weaken the public replay grammar,
    /// so historical two-process tests must still append the exact semantic
    /// RestartPrepare -> dual RestartCut -> RestartPark predecessor chain.
    fn append_test_restart_cut(journal: &mut RuntimeEventJournalV1, nonce: u64) {
        let monotonic_ns = journal.last_monotonic_ns;
        let statement_count =
            u64::try_from(journal.context.validator_set.validators().len()).unwrap();
        let cut = RestartCutParkSubjectV1 {
            cut_artifact_sha256: [0xd2; 32],
            park_artifact_sha256: [0xd3; 32],
            body_sha256: [0xd4; 32],
            admission_set_sha256: [0xd5; 32],
        };
        let park = RestartParkSubjectV1 {
            park_artifact_sha256: cut.park_artifact_sha256,
            local_park_statement_sha256: [0xd6; 32],
        };
        journal
            .append_raw(
                "restart_prepare",
                &hex::encode([0xd1; 32]),
                nonce,
                monotonic_ns,
            )
            .unwrap();
        journal
            .append_raw("restart_cut", &cut.encode(), statement_count, monotonic_ns)
            .unwrap();
        journal
            .append_raw(
                "restart_park",
                &park.encode(),
                statement_count,
                monotonic_ns,
            )
            .unwrap();
    }

    fn start_test_process2(
        path: &Path,
        context: &RuntimeEventContextV1,
        key: &SigningKey,
        nonce: u64,
    ) -> RuntimeEventJournalV1 {
        let mut first =
            RuntimeEventJournalV1::start_with_context(path, context.clone(), key.clone()).unwrap();
        enter_fleet_started(&mut first);
        append_test_restart_cut(&mut first, nonce);
        drop(first);
        RuntimeEventJournalV1::start_with_context(path, context.clone(), key.clone()).unwrap()
    }

    #[test]
    fn journal_park_subjects_and_target_peer_legacy_transitions_are_exact() {
        let park_prepare = RestartParkPrepareSubjectV1 {
            target_validator: ValidatorId::new([0x11; 32]),
            body_sha256: [0x12; 32],
            prepare_message_id: [0x13; 32],
        };
        let cut_park = RestartCutParkSubjectV1 {
            cut_artifact_sha256: [0x21; 32],
            park_artifact_sha256: [0x22; 32],
            body_sha256: park_prepare.body_sha256,
            admission_set_sha256: [0x23; 32],
        };
        let park = RestartParkSubjectV1 {
            park_artifact_sha256: cut_park.park_artifact_sha256,
            local_park_statement_sha256: [0x24; 32],
        };
        let parked_ack = RestartParkedAckSubjectV1 {
            ack_certificate_sha256: [0x25; 32],
            local_ack_statement_sha256: [0x26; 32],
            cut_artifact_sha256: cut_park.cut_artifact_sha256,
            park_artifact_sha256: cut_park.park_artifact_sha256,
            ack_admission_set_sha256: [0x27; 32],
        };
        let zero_delta = RecoveryZeroDeltaSubjectV1 {
            zero_delta_artifact_sha256: [0x31; 32],
            recovery_context_sha256: [0x32; 32],
        };
        let ready = RecoveryReadySubjectV1 {
            ready_set_artifact_sha256: [0x33; 32],
            recovery_context_sha256: zero_delta.recovery_context_sha256,
        };
        let start = RecoveryStartSubjectV1 {
            start_certificate_artifact_sha256: [0x34; 32],
            ready_set_artifact_sha256: ready.ready_set_artifact_sha256,
            recovery_context_sha256: ready.recovery_context_sha256,
        };
        assert_eq!(
            RestartParkPrepareSubjectV1::decode(&park_prepare.encode()).unwrap(),
            park_prepare
        );
        assert_eq!(
            RestartCutParkSubjectV1::decode(&cut_park.encode()).unwrap(),
            cut_park
        );
        assert_eq!(RestartParkSubjectV1::decode(&park.encode()).unwrap(), park);
        assert_eq!(
            RestartParkedAckSubjectV1::decode(&parked_ack.encode()).unwrap(),
            parked_ack
        );
        assert_eq!(
            RecoveryZeroDeltaSubjectV1::decode(&zero_delta.encode()).unwrap(),
            zero_delta
        );
        assert_eq!(
            RecoveryReadySubjectV1::decode(&ready.encode()).unwrap(),
            ready
        );
        assert_eq!(
            RecoveryStartSubjectV1::decode(&start.encode()).unwrap(),
            start
        );
        for malformed in [
            cut_park.encode().to_uppercase(),
            format!("{}:extra", cut_park.encode()),
            "rcp1:1111".to_owned(),
            format!(
                "rcp1:{}:{}:{}:{}",
                hex::encode([0; 32]),
                hex::encode([0x22; 32]),
                hex::encode([0x12; 32]),
                hex::encode([0x23; 32])
            ),
        ] {
            assert!(RestartCutJournalSubjectV1::decode(&malformed).is_err());
        }
        for malformed in [
            parked_ack.encode().to_uppercase(),
            format!("{}:extra", parked_ack.encode()),
            format!(
                "rpa1:{}:{}:{}:{}:{}",
                hex::encode([0x25; 32]),
                hex::encode([0x26; 32]),
                hex::encode([0x21; 32]),
                hex::encode([0x22; 32]),
                hex::encode([0; 32])
            ),
        ] {
            assert!(RestartParkedAckSubjectV1::decode(&malformed).is_err());
        }

        let (temporary, context, key) = fixture();
        let statement_count = u64::try_from(context.validator_set.validators().len()).unwrap();

        let target_path = temporary.path().join("target-parked.jsonl");
        let mut target =
            RuntimeEventJournalV1::start_with_context(&target_path, context.clone(), key.clone())
                .unwrap();
        enter_fleet_started(&mut target);
        append_test_restart_cut(&mut target, 70);
        assert_eq!(
            target.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1TargetParked
        );
        drop(target);
        let target_before = fs::read(&target_path).unwrap();
        let target_restart_error =
            RuntimeEventJournalV1::start_with_context(&target_path, context.clone(), key.clone())
                .unwrap_err();
        assert!(
            matches!(
                &target_restart_error,
                RuntimeEventErrorV1::Invalid(
                    "restart Park must immediately receive the exact N/N parked acknowledgement"
                )
            ),
            "unexpected target restart error: {target_restart_error:?}"
        );
        assert_eq!(fs::read(&target_path).unwrap(), target_before);

        let peer_path = temporary.path().join("peer-parked.jsonl");
        let mut peer =
            RuntimeEventJournalV1::start_with_context(&peer_path, context.clone(), key.clone())
                .unwrap();
        enter_fleet_started(&mut peer);
        let peer_target = context
            .validator_set
            .validators()
            .iter()
            .map(|validator| validator.id())
            .find(|validator| *validator != context.validator_id)
            .unwrap();
        let peer_prepare = RestartParkPrepareSubjectV1 {
            target_validator: peer_target,
            ..park_prepare
        };
        let monotonic_ns = peer.last_monotonic_ns;
        peer.append_raw(
            "restart_park_prepare",
            &peer_prepare.encode(),
            3,
            monotonic_ns,
        )
        .unwrap();
        assert_eq!(
            peer.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParkPreparePending
        );
        peer.append_raw(
            "restart_cut",
            &cut_park.encode(),
            statement_count,
            monotonic_ns,
        )
        .unwrap();
        assert_eq!(
            peer.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1ParkRecordPending
        );
        peer.append_raw(
            "restart_park",
            &park.encode(),
            statement_count,
            monotonic_ns,
        )
        .unwrap();
        assert_eq!(
            peer.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1PeerParked
        );
        let peer_before = fs::read(&peer_path).unwrap();
        assert!(peer
            .append_raw("recovery_zero_delta", &zero_delta.encode(), 3, monotonic_ns)
            .is_err());
        assert_eq!(fs::read(&peer_path).unwrap(), peer_before);

        let legacy_path = temporary.path().join("legacy-unparked.jsonl");
        let mut legacy =
            RuntimeEventJournalV1::start_with_context(&legacy_path, context.clone(), key.clone())
                .unwrap();
        enter_fleet_started(&mut legacy);
        let monotonic_ns = legacy.last_monotonic_ns;
        legacy
            .append_raw(
                "restart_prepare",
                &hex::encode([0x41; 32]),
                71,
                monotonic_ns,
            )
            .unwrap();
        legacy
            .append_raw(
                "restart_cut",
                &hex::encode([0x42; 32]),
                statement_count,
                monotonic_ns,
            )
            .unwrap();
        assert_eq!(
            legacy.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1LegacyUnparked
        );
        let before = fs::read(&legacy_path).unwrap();
        assert!(legacy
            .append_raw(
                "restart_park",
                &park.encode(),
                statement_count,
                monotonic_ns
            )
            .is_err());
        assert_eq!(fs::read(&legacy_path).unwrap(), before);
        drop(legacy);
        assert!(matches!(
            RuntimeEventJournalV1::start_with_context_gate(
                &legacy_path,
                context,
                key,
                ProcessStartGateV1::InitialProcessOnly,
            ),
            Err(RuntimeEventErrorV1::Invalid(
                "legacy RestartCut lacks durable RestartPark authority"
            ))
        ));
        assert_eq!(fs::read(&legacy_path).unwrap(), before);
    }

    #[test]
    fn process_start_rejects_cut_park_without_parked_ack() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("events.jsonl");
        let mut first =
            RuntimeEventJournalV1::start_with_context(&path, context.clone(), key.clone()).unwrap();
        assert_eq!(first.process_instance(), 1);
        enter_fleet_started(&mut first);
        let event = first
            .append(RuntimeEventKindV1::ProposalAdmitted, "block-1", 1)
            .unwrap();
        assert_eq!(event.sequence, 5);
        assert_eq!(
            event.coordinator_manifest_sha256,
            hex::encode(context.coordinator_manifest_sha256)
        );
        append_test_restart_cut(&mut first, 11);
        drop(first);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            RuntimeEventJournalV1::start_with_context(&path, context, key),
            Err(RuntimeEventErrorV1::Invalid(
                "restart Park must immediately receive the exact N/N parked acknowledgement"
            ))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn normal_start_restart_classifier_is_exact_and_non_mutating() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("normal-start-gate-events.jsonl");
        let mut first =
            RuntimeEventJournalV1::start_with_context(&path, context.clone(), key.clone()).unwrap();
        enter_fleet_started(&mut first);
        first
            .append(RuntimeEventKindV1::ProposalAdmitted, "block-1", 1)
            .unwrap();
        append_test_restart_cut(&mut first, 12);
        drop(first);

        let before = fs::read(&path).unwrap();
        let error = RuntimeEventJournalV1::start_with_context_gate(
            &path,
            context.clone(),
            key.clone(),
            ProcessStartGateV1::InitialProcessOnly,
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            RuntimeEventErrorV1::Invalid(
                "process-1 target Park is still waiting for the exact N/N ParkedAck"
            )
        ));
        assert!(!error.requires_stored_restart_cut_v1());
        assert_eq!(fs::read(&path).unwrap(), before);

        let corrupt_path = temporary.path().join("normal-start-corrupt-events.jsonl");
        drop(
            RuntimeEventJournalV1::start_with_context(&corrupt_path, context.clone(), key.clone())
                .unwrap(),
        );
        let mut corrupt = fs::read(&corrupt_path).unwrap();
        corrupt.extend_from_slice(b"{");
        fs::write(&corrupt_path, &corrupt).unwrap();
        let corruption_error = RuntimeEventJournalV1::start_with_context_gate(
            &corrupt_path,
            context,
            key,
            ProcessStartGateV1::InitialProcessOnly,
        )
        .unwrap_err();
        assert!(!corruption_error.requires_stored_restart_cut_v1());
        assert!(matches!(corruption_error, RuntimeEventErrorV1::Invalid(_)));
        assert_eq!(fs::read(&corrupt_path).unwrap(), corrupt);
    }

    #[test]
    fn restart_cut_commit_rejects_mutated_store_without_mutating_journal() {
        let Process1CutCommitFixture {
            _temporary,
            mut journal,
            owner,
            stored,
        } = process1_cut_commit_fixture();
        let journal_path = journal.path().to_owned();
        let before_bytes = fs::read(&journal_path).unwrap();
        let before_events = {
            let file = File::open(&journal_path).unwrap();
            read_exact_events(&file).unwrap()
        };
        let before_head = journal.last_event_facts();
        assert_eq!(before_events.last().unwrap().kind, "restart_prepare");
        assert_eq!(journal.restart_cut_facts_v1(), None);

        let artifact_path = stored.cut_path_v1().to_owned();
        let artifact_inode = fs::metadata(&artifact_path).unwrap().ino();
        fs::write(&artifact_path, b"mutated-after-authenticated-load").unwrap();
        assert_eq!(fs::metadata(&artifact_path).unwrap().ino(), artifact_inode);

        assert!(matches!(
            journal.record_restart_cut_park_from_owner_v1(&owner, &stored),
            Err(RuntimeEventErrorV1::Invalid(
                "stored restart Cut/Park pair failed fresh authentication before journal append"
            ))
        ));
        assert_eq!(fs::read(&journal_path).unwrap(), before_bytes);
        let after_events = {
            let file = File::open(&journal_path).unwrap();
            read_exact_events(&file).unwrap()
        };
        assert_eq!(after_events.len(), before_events.len());
        assert_eq!(after_events, before_events);
        assert_eq!(journal.last_event_facts(), before_head);
        assert_eq!(journal.restart_cut_facts_v1(), None);
    }

    #[test]
    fn target_process1_parked_handoff_rejects_missing_parked_ack_without_mutation_v1() {
        let Process1CutCommitFixture {
            _temporary,
            mut journal,
            owner,
            stored,
        } = process1_cut_commit_fixture();
        let journal_path = journal.path().to_owned();
        let (cut_event, park_event, commit) = journal
            .record_restart_cut_park_from_owner_v1(&owner, &stored)
            .unwrap();
        assert_eq!(
            journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1TargetParked
        );
        assert_eq!(park_event.sequence, cut_event.sequence + 1);
        assert_eq!(park_event.previous_event_sha256, cut_event.event_sha256);
        assert_eq!(commit.role_v1(), RestartParkRoleV1::Target);
        assert_eq!(commit.restart_cut_event_sequence_v1(), cut_event.sequence);
        assert_eq!(commit.restart_park_event_sequence_v1(), park_event.sequence);

        let park_event_sha256 =
            decode_hex(&park_event.event_sha256, "target restart park event hash").unwrap();
        let before_missing_ack = fs::read(&journal_path).unwrap();
        assert!(matches!(
            journal.revalidate_target_process1_parked_handoff_v1(&stored),
            Err(RuntimeEventErrorV1::Invalid(
                "target process-1 handoff requires the exact stored ParkedAck certificate"
            ))
        ));
        assert_eq!(fs::read(&journal_path).unwrap(), before_missing_ack);
        assert_eq!(
            journal.last_event_facts(),
            Some((park_event.sequence, park_event_sha256))
        );

        let events = read_exact_events(&File::open(&journal_path).unwrap()).unwrap();
        assert_eq!(
            events
                .iter()
                .rev()
                .take(3)
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            ["restart_park", "restart_cut", "restart_prepare"]
        );
        assert!(events.iter().all(|event| {
            event.kind != RuntimeEventKindV1::FinalTip.as_str()
                && event.kind != RuntimeEventKindV1::CleanStop.as_str()
                && event.kind != RuntimeEventKindV1::SafetyHalted.as_str()
        }));
        assert!(stored.cut_path_v1().is_file());
        assert!(stored.park_path_v1().is_file());

        let journal_before_mutation = fs::read(&journal_path).unwrap();
        let head_before_mutation = journal.last_event_facts();
        let mut park_artifact = fs::read(stored.park_path_v1()).unwrap();
        *park_artifact.last_mut().unwrap() ^= 0x01;
        fs::write(stored.park_path_v1(), park_artifact).unwrap();

        assert!(matches!(
            journal.revalidate_target_process1_parked_handoff_v1(&stored),
            Err(RuntimeEventErrorV1::Invalid(
                "target process-1 handoff requires the exact stored ParkedAck certificate"
            ))
        ));
        assert_eq!(fs::read(&journal_path).unwrap(), journal_before_mutation);
        assert_eq!(journal.last_event_facts(), head_before_mutation);
        assert_eq!(
            journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1TargetParked
        );
    }

    #[test]
    fn target_process1_parked_handoff_rejects_same_name_journal_replacement_v1() {
        let AuthenticatedProcess2GateFixture {
            _temporary,
            journal,
            journal_path,
            context: _,
            key: _,
            stored_cut_park: _stored_cut_park,
            stored_ack: _stored_ack,
            journal_witness: _journal_witness,
            ack_admission_set_sha256: _,
        } = authenticated_process2_gate_fixture();
        let displaced_path = journal_path.with_extension("held-inode");
        let journal_bytes = fs::read(&journal_path).unwrap();
        let head_before = journal.last_event_facts();

        fs::rename(&journal_path, &displaced_path).unwrap();
        fs::write(&journal_path, &journal_bytes).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        let named_before = fs::read(&journal_path).unwrap();
        let displaced_before = fs::read(&displaced_path).unwrap();

        // The production handoff performs this exact named-inode check after
        // validating the retained durable Ack owner. The fixture has already
        // committed and authenticated the complete rpr1 -> rcp1 -> rpk1 -> rpa1
        // chain, so no synthetic authority constructor is needed here.
        assert!(matches!(
            journal.reopen_exact_named_journal_v1(),
            Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal named file identity changed"
            ))
        ));
        assert_eq!(fs::read(&journal_path).unwrap(), named_before);
        assert_eq!(fs::read(&displaced_path).unwrap(), displaced_before);
        assert_eq!(journal.last_event_facts(), head_before);
        assert_eq!(
            journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1TargetParkedAcked
        );
    }

    #[test]
    fn target_process1_parked_handoff_rejects_named_parent_replacement_v1() {
        let AuthenticatedProcess2GateFixture {
            _temporary,
            journal,
            journal_path,
            context: _,
            key: _,
            stored_cut_park: _stored_cut_park,
            stored_ack: _stored_ack,
            journal_witness: _journal_witness,
            ack_admission_set_sha256: _,
        } = authenticated_process2_gate_fixture();
        let journal_parent = journal_path.parent().unwrap().to_owned();
        let displaced_parent = journal_parent.with_file_name("process1-journal-held-inode");
        let file_name = journal_path.file_name().unwrap().to_owned();
        let journal_bytes = fs::read(&journal_path).unwrap();
        let head_before = journal.last_event_facts();

        fs::rename(&journal_parent, &displaced_parent).unwrap();
        fs::create_dir(&journal_parent).unwrap();
        fs::set_permissions(&journal_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement_path = journal_parent.join(&file_name);
        fs::write(&replacement_path, &journal_bytes).unwrap();
        fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600)).unwrap();
        let displaced_path = displaced_parent.join(&file_name);
        let named_before = fs::read(&replacement_path).unwrap();
        let displaced_before = fs::read(&displaced_path).unwrap();

        assert!(matches!(
            journal.reopen_exact_named_journal_v1(),
            Err(RuntimeEventErrorV1::Invalid(
                "runtime event journal named parent identity changed"
            ))
        ));
        assert_eq!(fs::read(&replacement_path).unwrap(), named_before);
        assert_eq!(fs::read(&displaced_path).unwrap(), displaced_before);
        assert_eq!(journal.last_event_facts(), head_before);
        assert_eq!(
            journal.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1TargetParkedAcked
        );
    }

    #[test]
    fn loaded_restart_cut_park_pair_cannot_open_process2_or_mutate_without_parked_ack() {
        let fixture = process2_gate_fixture();
        let journal_before = fs::read(&fixture.journal_path).unwrap();
        let journal_metadata_before = fs::metadata(&fixture.journal_path).unwrap();
        let events_before = {
            let file = File::open(&fixture.journal_path).unwrap();
            read_exact_events(&file).unwrap()
        };
        let cut_path = fixture.stored.cut_path_v1().to_owned();
        let park_path = fixture.stored.park_path_v1().to_owned();
        let cut_before = fs::read(&cut_path).unwrap();
        let park_before = fs::read(&park_path).unwrap();
        assert!(matches!(
            RuntimeEventJournalV1::start_process2_with_context_and_stored_restart_cut_v1(
                &fixture.journal_path,
                fixture.context,
                fixture.key,
                fixture.stored,
            ),
            Err(RuntimeEventErrorV1::Invalid(
                "legacy Cut/Park-only process-2 gate lacks the stored ParkedAck certificate"
            ))
        ));
        let journal_metadata_after = fs::metadata(&fixture.journal_path).unwrap();
        assert_eq!(fs::read(&fixture.journal_path).unwrap(), journal_before);
        assert_eq!(
            read_exact_events(&File::open(&fixture.journal_path).unwrap()).unwrap(),
            events_before
        );
        assert_eq!(journal_metadata_after.dev(), journal_metadata_before.dev());
        assert_eq!(journal_metadata_after.ino(), journal_metadata_before.ino());
        assert_eq!(journal_metadata_after.len(), journal_metadata_before.len());
        assert_eq!(fs::read(cut_path).unwrap(), cut_before);
        assert_eq!(fs::read(park_path).unwrap(), park_before);
    }

    #[test]
    fn authenticated_cut_park_parked_ack_triple_starts_process2_and_revalidates_unchanged_v1() {
        let AuthenticatedProcess2GateFixture {
            _temporary,
            journal,
            journal_path,
            context,
            key,
            stored_cut_park,
            stored_ack,
            journal_witness,
            ack_admission_set_sha256,
        } = authenticated_process2_gate_fixture();
        let process1_events = read_exact_events(&File::open(&journal_path).unwrap()).unwrap();
        assert_eq!(
            process1_events
                .iter()
                .rev()
                .take(4)
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            [
                "restart_parked_ack",
                "restart_park",
                "restart_cut",
                "restart_prepare",
            ]
        );
        assert_eq!(
            journal_witness.ack_admission_set_sha256,
            ack_admission_set_sha256
        );
        let reopened = ReopenedRestartCutParkAckCertificatesV1 {
            stored_cut_park,
            stored_ack,
            journal_witness,
        };
        reopened.revalidate_fresh_v1().unwrap();
        drop(journal);

        let started = Process2JournalStartedFromRestartCutV1::start_with_context_v1(
            &journal_path,
            context,
            key,
            reopened,
        )
        .unwrap();
        assert_eq!(started.process_instance_v1(), 2);
        assert_eq!(
            started.restart_parked_ack_admission_set_sha256_v1(),
            ack_admission_set_sha256
        );
        assert_eq!(started.restart_prepare_request_sha256_v1(), [0xd1; 32]);
        started.revalidate_unchanged_start_v1().unwrap();

        let process2_events = read_exact_events(&File::open(&journal_path).unwrap()).unwrap();
        assert_eq!(
            process2_events
                .iter()
                .rev()
                .take(3)
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            ["restart", "process_start", "restart_parked_ack"]
        );
        let process_start = &process2_events[process2_events.len() - 2];
        let restart = process2_events.last().unwrap();
        assert_eq!(process_start.process_instance, 2);
        assert_eq!(restart.process_instance, 2);
        assert_eq!(restart.previous_event_sha256, process_start.event_sha256);
    }

    #[test]
    fn authenticated_process2_gate_rejects_ack_store_and_journal_mutants_without_mutation_v1() {
        {
            let AuthenticatedProcess2GateFixture {
                _temporary,
                journal,
                journal_path,
                context,
                key,
                stored_cut_park,
                stored_ack,
                journal_witness,
                ack_admission_set_sha256: _,
            } = authenticated_process2_gate_fixture();
            let before = fs::read(&journal_path).unwrap();
            let mut ack_bytes = fs::read(stored_ack.path_v1()).unwrap();
            *ack_bytes.last_mut().unwrap() ^= 0x01;
            fs::write(stored_ack.path_v1(), ack_bytes).unwrap();
            drop(journal);
            let reopened = ReopenedRestartCutParkAckCertificatesV1 {
                stored_cut_park,
                stored_ack,
                journal_witness,
            };
            assert!(
                Process2JournalStartedFromRestartCutV1::start_with_context_v1(
                    &journal_path,
                    context,
                    key,
                    reopened,
                )
                .is_err()
            );
            assert_eq!(fs::read(&journal_path).unwrap(), before);
        }

        {
            let AuthenticatedProcess2GateFixture {
                _temporary,
                journal,
                journal_path,
                context,
                key,
                stored_cut_park,
                stored_ack,
                journal_witness,
                ack_admission_set_sha256: _,
            } = authenticated_process2_gate_fixture();
            drop(journal);
            let mut events = read_exact_events(&File::open(&journal_path).unwrap()).unwrap();
            let parked_ack = events.last_mut().unwrap();
            assert_eq!(parked_ack.kind, "restart_parked_ack");
            let prior = RestartParkedAckSubjectV1::decode(&parked_ack.subject).unwrap();
            parked_ack.subject = RestartParkedAckSubjectV1 {
                ack_admission_set_sha256: [0xee; 32],
                ..prior
            }
            .encode();
            rechain_and_resign(&mut events, &key);
            write_canonical_events(&journal_path, &events);
            let before = fs::read(&journal_path).unwrap();
            let reopened = ReopenedRestartCutParkAckCertificatesV1 {
                stored_cut_park,
                stored_ack,
                journal_witness,
            };
            assert!(
                Process2JournalStartedFromRestartCutV1::start_with_context_v1(
                    &journal_path,
                    context,
                    key,
                    reopened,
                )
                .is_err()
            );
            assert_eq!(fs::read(&journal_path).unwrap(), before);
        }
    }

    #[test]
    fn public_replay_requires_target_park_immediately_before_process2_start() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("public-replay-process2-gate.jsonl");
        let mut first =
            RuntimeEventJournalV1::start_with_context(&path, context.clone(), key.clone()).unwrap();
        enter_fleet_started(&mut first);
        drop(first);

        let file = File::open(&path).unwrap();
        let mut events = read_exact_events(&file).unwrap();
        let previous = events.last().unwrap().event_sha256.clone();
        let mut process2_start = events.last().unwrap().clone();
        process2_start.process_instance = 2;
        process2_start.sequence = u64::try_from(events.len()).unwrap();
        process2_start.monotonic_ns = 0;
        process2_start.kind = "process_start".to_owned();
        process2_start.subject = "instance-2".to_owned();
        process2_start.value = 4242;
        process2_start.previous_event_sha256 = previous;
        let event_sha256 = process2_start.computed_hash().unwrap();
        process2_start.event_sha256 = hex::encode(event_sha256);
        process2_start.signature = hex::encode(key.sign(&signature_root(event_sha256)).to_bytes());
        events.push(process2_start);

        assert!(matches!(
            validate_event_chain(&events, &context),
            Err(RuntimeEventErrorV1::Invalid(
                "second process does not immediately succeed a target ParkedAck certificate"
            ))
        ));
    }

    #[test]
    #[ignore = "requires an authenticated Cut/Park/ParkedAck process-2 fixture"]
    fn legacy_public_verifier_rejects_process2_without_restart_cut_artifact_authority() {
        let (temporary, context, key) = fixture();
        let path = temporary
            .path()
            .join("public-process2-without-cut-artifact.jsonl");
        let mut second = start_test_process2(&path, &context, &key, 23);
        second
            .record_recovery_zero_delta_for_grammar_test([0x92; 32], 3)
            .unwrap();
        second
            .record_recovery_ready_for_grammar_test(
                [0x93; 32],
                u64::try_from(context.validator_set.validators().len()).unwrap(),
            )
            .unwrap();
        second
            .record_recovery_start_for_grammar_test(
                [0x94; 32],
                u64::try_from(context.validator_set.validators().len()).unwrap(),
            )
            .unwrap();
        second
            .record_final_tip([0xa1; 32], [0xa2; 32], [0xa3; 32], 3)
            .unwrap();
        second.record_clean_stop().unwrap();
        drop(second);

        assert!(matches!(
            verify_runtime_event_journal_with_context_v1(&path, &context),
            Err(RuntimeEventErrorV1::Invalid(
                "observer process-2 verification requires authenticated RestartCut and RestartPark artifacts"
            ))
        ));
    }

    #[test]
    fn process2_gate_rejects_missing_tampered_foreign_wrong_target_and_wrong_head_without_mutation()
    {
        {
            let fixture = process2_gate_fixture();
            let file = File::open(&fixture.journal_path).unwrap();
            let mut events = read_exact_events(&file).unwrap();
            assert_eq!(events.pop().unwrap().kind, "restart_park");
            write_canonical_events(&fixture.journal_path, &events);
            assert_process2_gate_rejects_without_mutation(
                &fixture.journal_path,
                fixture.context.clone(),
                fixture.key.clone(),
                fixture.stored,
            );
        }

        {
            let fixture = process2_gate_fixture();
            fs::write(fixture.stored.cut_path_v1(), b"tampered-after-load").unwrap();
            assert_process2_gate_rejects_without_mutation(
                &fixture.journal_path,
                fixture.context.clone(),
                fixture.key.clone(),
                fixture.stored,
            );
        }

        {
            let fixture = process2_gate_fixture();
            let foreign_campaign = process2_campaign(
                &fixture.context.validator_set,
                "poco-g3-7-20260814T000000Z-fedcba98",
                0xe1,
            );
            let foreign_start = process2_fleet_start_certificate(
                &fixture.context.validator_set,
                &fixture.keys,
                &foreign_campaign,
                0xe8,
            );
            let foreign = process2_stored_restart_cut_park(
                &fixture._temporary.path().join("foreign-restart-cut-store"),
                &fixture.context.validator_set,
                &fixture.keys,
                &foreign_campaign,
                &foreign_start,
                2,
                fixture.restart_prepare_head,
            );
            rewrite_terminal_restart_cut_authority(&fixture.journal_path, &fixture.key, &foreign);
            assert_process2_gate_rejects_without_mutation(
                &fixture.journal_path,
                fixture.context.clone(),
                fixture.key.clone(),
                foreign,
            );
        }

        {
            let fixture = process2_gate_fixture();
            let wrong_target = process2_stored_restart_cut_park(
                &fixture
                    ._temporary
                    .path()
                    .join("wrong-target-restart-cut-store"),
                &fixture.context.validator_set,
                &fixture.keys,
                &fixture.campaign,
                &fixture.fleet_start,
                3,
                fixture.restart_prepare_head,
            );
            rewrite_terminal_restart_cut_authority(
                &fixture.journal_path,
                &fixture.key,
                &wrong_target,
            );
            assert_process2_gate_rejects_without_mutation(
                &fixture.journal_path,
                fixture.context.clone(),
                fixture.key.clone(),
                wrong_target,
            );
        }

        {
            let fixture = process2_gate_fixture();
            let wrong_head = process2_stored_restart_cut_park(
                &fixture
                    ._temporary
                    .path()
                    .join("wrong-head-restart-cut-store"),
                &fixture.context.validator_set,
                &fixture.keys,
                &fixture.campaign,
                &fixture.fleet_start,
                2,
                (fixture.restart_prepare_head.0, [0xee; 32]),
            );
            rewrite_terminal_restart_cut_authority(
                &fixture.journal_path,
                &fixture.key,
                &wrong_head,
            );
            assert_process2_gate_rejects_without_mutation(
                &fixture.journal_path,
                fixture.context.clone(),
                fixture.key.clone(),
                wrong_head,
            );
        }
    }

    #[test]
    fn legacy_restart_cut_is_terminal_and_cannot_open_process2() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("restart-prepare-events.jsonl");
        let mut first =
            RuntimeEventJournalV1::start_with_context(&path, context.clone(), key.clone()).unwrap();
        enter_fleet_started(&mut first);
        let monotonic_ns = first.last_monotonic_ns;
        let event = first
            .append_raw(
                "restart_prepare",
                &hex::encode([0x81; 32]),
                17,
                monotonic_ns,
            )
            .unwrap();
        assert_eq!(event.kind, "restart_prepare");
        assert_eq!(first.observation().restart_prepare_nonce, Some(17));
        let cut = first
            .append_raw(
                "restart_cut",
                &hex::encode([0x82; 32]),
                u64::try_from(context.validator_set.validators().len()).unwrap(),
                monotonic_ns,
            )
            .unwrap();
        assert_eq!(cut.kind, "restart_cut");
        assert_eq!(
            first.restart_cut_facts_v1(),
            Some((
                [0x82; 32],
                u64::try_from(context.validator_set.validators().len()).unwrap(),
            ))
        );
        assert!(first
            .append(RuntimeEventKindV1::ProposalAdmitted, "post-cut", 5)
            .is_err());
        drop(first);

        let before = fs::read(&path).unwrap();
        assert!(matches!(
            RuntimeEventJournalV1::start_with_context_gate(
                &path,
                context,
                key,
                ProcessStartGateV1::InitialProcessOnly,
            ),
            Err(RuntimeEventErrorV1::Invalid(
                "legacy RestartCut lacks durable RestartPark authority"
            ))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn restart_prepare_rejects_intervening_events_and_wrong_cut_count() {
        let (temporary, context, key) = fixture();

        let intervening_path = temporary.path().join("restart-prepare-intervening.jsonl");
        let mut intervening = RuntimeEventJournalV1::start_with_context(
            &intervening_path,
            context.clone(),
            key.clone(),
        )
        .unwrap();
        enter_fleet_started(&mut intervening);
        let monotonic_ns = intervening.last_monotonic_ns;
        intervening
            .append_raw(
                "restart_prepare",
                &hex::encode([0x83; 32]),
                18,
                monotonic_ns,
            )
            .unwrap();
        let before = fs::read(&intervening_path).unwrap();
        assert!(intervening
            .append(RuntimeEventKindV1::ProposalAdmitted, "post-prepare", 5)
            .is_err());
        assert_eq!(fs::read(&intervening_path).unwrap(), before);

        let wrong_count_path = temporary.path().join("restart-cut-wrong-count.jsonl");
        let mut wrong_count =
            RuntimeEventJournalV1::start_with_context(&wrong_count_path, context.clone(), key)
                .unwrap();
        enter_fleet_started(&mut wrong_count);
        let monotonic_ns = wrong_count.last_monotonic_ns;
        wrong_count
            .append_raw(
                "restart_prepare",
                &hex::encode([0x84; 32]),
                19,
                monotonic_ns,
            )
            .unwrap();
        let before = fs::read(&wrong_count_path).unwrap();
        let expected_count = u64::try_from(context.validator_set.validators().len()).unwrap();
        assert!(wrong_count
            .append_raw(
                "restart_cut",
                &hex::encode([0x85; 32]),
                expected_count.checked_add(1).unwrap(),
                monotonic_ns,
            )
            .is_err());
        assert_eq!(fs::read(&wrong_count_path).unwrap(), before);
    }

    #[test]
    fn ordinary_event_and_second_process_before_fleet_started_fail_closed() {
        let (temporary, context, key) = fixture();
        let ordinary_path = temporary.path().join("ordinary-before-start.jsonl");
        let mut ordinary =
            RuntimeEventJournalV1::start_with_context(&ordinary_path, context.clone(), key.clone())
                .unwrap();
        assert!(ordinary
            .append(RuntimeEventKindV1::ProposalAdmitted, "proposal", 4)
            .is_err());

        let restart_path = temporary.path().join("restart-before-start.jsonl");
        drop(
            RuntimeEventJournalV1::start_with_context(&restart_path, context.clone(), key.clone())
                .unwrap(),
        );
        assert!(RuntimeEventJournalV1::start_with_context(&restart_path, context, key).is_err());
    }

    #[test]
    fn foreign_anchor_partial_tail_and_duplicate_json_fail_closed() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("events.jsonl");
        drop(
            RuntimeEventJournalV1::start_with_context(&path, context.clone(), key.clone()).unwrap(),
        );

        let mut foreign = context.clone();
        foreign.coordinator_manifest_sha256 = [0x77; 32];
        assert!(RuntimeEventJournalV1::start_with_context(&path, foreign, key.clone()).is_err());

        let raw = fs::read(&path).unwrap();
        fs::write(&path, [raw.as_slice(), b"{"].concat()).unwrap();
        assert!(
            RuntimeEventJournalV1::start_with_context(&path, context.clone(), key.clone()).is_err()
        );

        let first_line = raw.split(|byte| *byte == b'\n').next().unwrap();
        let duplicate = String::from_utf8(first_line.to_vec()).unwrap().replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        fs::write(&path, format!("{duplicate}\n")).unwrap();
        assert!(RuntimeEventJournalV1::start_with_context(&path, context, key).is_err());
    }

    #[test]
    fn concurrent_owner_is_rejected_by_exclusive_lock() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("events.jsonl");
        let first =
            RuntimeEventJournalV1::start_with_context(&path, context.clone(), key.clone()).unwrap();
        assert!(RuntimeEventJournalV1::start_with_context(&path, context, key).is_err());
        drop(first);
    }

    #[test]
    fn terminal_tip_fault_and_clean_stop_are_native_state_transitions() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("events.jsonl");
        let mut journal =
            RuntimeEventJournalV1::start_with_context(&path, context.clone(), key).unwrap();
        enter_fleet_started(&mut journal);
        let block = [0x81; 32];
        let state = [0x82; 32];
        let chain = [0x83; 32];
        journal
            .append(RuntimeEventKindV1::Finalized, &hex::encode(block), 7)
            .unwrap();
        journal
            .append(
                RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode(state),
                7,
            )
            .unwrap();
        journal
            .record_fault_applied(RuntimeFaultV1::AsymmetricPartition)
            .unwrap();
        journal
            .record_fault_recovered(RuntimeFaultV1::AsymmetricPartition, 7)
            .unwrap();
        journal.record_final_tip(block, state, chain, 7).unwrap();
        let stop = journal.record_clean_stop().unwrap();
        assert_eq!(stop.kind, "clean_stop");
        assert_eq!(stop.subject, "bounded-run-complete");
        let observation = journal.observation();
        assert_eq!(observation.finalized_height, 7);
        assert_eq!(observation.application_height, 7);
        assert!(observation.active_faults.is_empty());
        assert_eq!(
            observation.recovered_faults,
            vec!["asymmetric_partition".to_owned()]
        );
        assert!(observation.final_tip_recorded);
        assert!(observation.clean_stop_recorded);
        let cut = journal.clean_stopped_cut().unwrap();
        assert_eq!(cut.process_instance(), 1);
        assert_eq!(cut.process_id(), std::process::id());
        assert_eq!(cut.event_sequence(), stop.sequence);
        assert_eq!(
            cut.event_sha256(),
            decode_hex(&stop.event_sha256, "test").unwrap()
        );
        assert_eq!(cut.clean_stop_monotonic_ns(), stop.monotonic_ns);
        assert_eq!(cut.finalized_height(), 7);
        assert_eq!(cut.finalized_block_id(), block);
        assert_eq!(cut.finalized_state_root(), state);
        assert_eq!(cut.finalized_chain_root(), chain);
        assert_eq!(cut.run_id(), context.run_id.as_str());
        assert_eq!(cut.validator_id(), context.validator_id);
        assert_eq!(
            cut.validator_set_id(),
            *context.validator_set.id().as_bytes()
        );
        assert_eq!(
            cut.coordinator_manifest_sha256(),
            context.coordinator_manifest_sha256
        );
        assert_eq!(cut.validator_set_sha256(), context.validator_set_sha256);
        assert_eq!(cut.config_sha256(), context.config_sha256);
        assert_eq!(
            cut.candidate_source_sha256(),
            context.candidate_source_sha256
        );
        assert_eq!(cut.binary_sha256(), context.binary_sha256);
        assert_eq!(cut.fleet_start_certificate_sha256(), [0x74; 32]);
        assert_eq!(cut.recovered_faults(), &["asymmetric_partition".to_owned()]);
        assert!(!cut.restart_completed());
        assert!(journal
            .append(RuntimeEventKindV1::ProposalAdmitted, "post-stop", 8)
            .is_err());

        let events = read_exact_events(&journal.file).unwrap();
        let recovered = validate_event_chain(&events, &context).unwrap();
        assert_eq!(recovered.state, journal.state);
    }

    #[test]
    #[ignore = "requires an authenticated Cut/Park/ParkedAck process-2 fixture"]
    fn restarted_process_cannot_consensus_before_exact_zero_delta_or_recovery_start() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("events.jsonl");
        let mut restarted = start_test_process2(&path, &context, &key, 21);
        assert!(restarted.observation().restart_pending_catchup);
        assert!(!restarted.state.restart_catchup_complete_v1());
        assert!(restarted
            .append(RuntimeEventKindV1::ProposalAdmitted, "proposal", 1)
            .is_err());

        let zero_delta_path = temporary.path().join("events-zero-delta.jsonl");
        let mut restarted = start_test_process2(&zero_delta_path, &context, &key, 22);
        restarted
            .record_recovery_zero_delta_for_grammar_test([0x91; 32], 3)
            .unwrap();
        assert_eq!(
            restarted.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process2RecoveryReadyPending
        );
        assert!(restarted
            .append(RuntimeEventKindV1::ProposalAdmitted, "proposal", 3)
            .is_err());
    }

    #[test]
    #[ignore = "requires an authenticated Cut/Park/ParkedAck process-2 fixture"]
    fn zero_delta_still_rejects_every_ordinary_event_before_recovery_start() {
        let cases = [
            (RuntimeEventKindV1::ProposalAdmitted, "proposal", 5),
            (RuntimeEventKindV1::VoteBroadcast, "vote", 5),
            (RuntimeEventKindV1::TimeoutVoteBroadcast, "timeout", 5),
            (
                RuntimeEventKindV1::QuorumCertificateAdmitted,
                "quorum-certificate",
                5,
            ),
            (
                RuntimeEventKindV1::TimeoutCertificateAdmitted,
                "timeout-certificate",
                5,
            ),
            (
                RuntimeEventKindV1::Finalized,
                "9292929292929292929292929292929292929292929292929292929292929292",
                5,
            ),
            (
                RuntimeEventKindV1::ApplicationAcknowledged,
                "9393939393939393939393939393939393939393939393939393939393939393",
                5,
            ),
            (RuntimeEventKindV1::FaultApplied, "leader_loss", 1),
            (
                RuntimeEventKindV1::FinalTip,
                "9494949494949494949494949494949494949494949494949494949494949494:9595959595959595959595959595959595959595959595959595959595959595:9696969696969696969696969696969696969696969696969696969696969696",
                4,
            ),
            (RuntimeEventKindV1::CleanStop, "bounded-run-complete", 1),
        ];
        for (index, (kind, subject, value)) in cases.into_iter().enumerate() {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join(format!("caught-up-{index}.jsonl"));
            let mut restarted =
                start_test_process2(&path, &context, &key, 30 + u64::try_from(index).unwrap());
            restarted
                .record_recovery_zero_delta_for_grammar_test([0x92; 32], 3)
                .unwrap();
            let observation = restarted.observation();
            assert!(!observation.restart_pending_catchup);
            assert!(!observation.restart_completed);
            assert!(restarted.state.restart_catchup_complete_v1());
            assert!(restarted.append(kind, subject, value).is_err(), "{kind:?}");
        }
    }

    #[test]
    #[ignore = "requires an authenticated Cut/Park/ParkedAck process-2 fixture"]
    fn recovery_ready_still_rejects_proposal_vote_and_timeout_before_recovery_start() {
        for (index, kind) in [
            RuntimeEventKindV1::ProposalAdmitted,
            RuntimeEventKindV1::VoteBroadcast,
            RuntimeEventKindV1::TimeoutVoteBroadcast,
        ]
        .into_iter()
        .enumerate()
        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join(format!("ready-{index}.jsonl"));
            let mut restarted =
                start_test_process2(&path, &context, &key, 60 + u64::try_from(index).unwrap());
            let statement_count = u64::try_from(context.validator_set.validators().len()).unwrap();
            restarted
                .record_recovery_zero_delta_for_grammar_test([0x97; 32], 3)
                .unwrap();
            restarted
                .record_recovery_ready_for_grammar_test([0x98; 32], statement_count)
                .unwrap();
            assert_eq!(
                restarted.restart_phase_v1(),
                RuntimeRestartPhaseV1::Process2RecoveryStartPending
            );
            assert!(restarted.append(kind, "ordinary-before-start", 5).is_err());
        }
    }

    #[test]
    #[ignore = "requires an authenticated Cut/Park/ParkedAck process-2 fixture"]
    fn recovery_start_grammar_rejects_missing_replayed_mutated_and_intervening_predecessors() {
        let validator_count = |context: &RuntimeEventContextV1| {
            u64::try_from(context.validator_set.validators().len()).unwrap()
        };

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("start-before-catchup.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 40);
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_start_for_grammar_test([0xa1; 32], validator_count(&context),)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("ready-before-catchup.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 41);
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_ready_for_grammar_test([0xa2; 32], validator_count(&context),)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("non-equal-zero-delta.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 42);
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_zero_delta_for_grammar_test([0xa3; 32], 2)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("ahead-zero-delta.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 43);
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_zero_delta_for_grammar_test([0xa3; 32], 4)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("zero-caught-up-artifact.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 44);
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_zero_delta_for_grammar_test([0; 32], 3)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("replayed-catchup.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 45);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xa4; 32], 3)
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_zero_delta_for_grammar_test([0xa5; 32], 3)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("wrong-ready-count.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 45);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xa6; 32], 3)
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_ready_for_grammar_test([0xa7; 32], validator_count(&context) + 1,)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("zero-ready-artifact.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 46);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xa8; 32], 3)
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_ready_for_grammar_test([0; 32], validator_count(&context))
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("replayed-ready.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 47);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xa9; 32], 3)
                .unwrap();
            restarted
                .record_recovery_ready_for_grammar_test([0xaa; 32], validator_count(&context))
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_ready_for_grammar_test([0xab; 32], validator_count(&context),)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("start-before-ready.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 48);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xac; 32], 3)
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_start_for_grammar_test([0xad; 32], validator_count(&context),)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("wrong-start-count.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 49);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xae; 32], 3)
                .unwrap();
            restarted
                .record_recovery_ready_for_grammar_test([0xaf; 32], validator_count(&context))
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_start_for_grammar_test([0xb0; 32], validator_count(&context) + 1,)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("zero-start-certificate.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 50);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xb1; 32], 3)
                .unwrap();
            restarted
                .record_recovery_ready_for_grammar_test([0xb2; 32], validator_count(&context))
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_start_for_grammar_test([0; 32], validator_count(&context))
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("intervening-session.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 51);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xb3; 32], 3)
                .unwrap();
            restarted
                .record_recovery_ready_for_grammar_test([0xb4; 32], validator_count(&context))
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .append(
                    RuntimeEventKindV1::PeerSessionEstablished,
                    "test-only-recovery-session-change",
                    2,
                )
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }

        {
            let (temporary, context, key) = fixture();
            let path = temporary.path().join("replayed-start.jsonl");
            let mut restarted = start_test_process2(&path, &context, &key, 52);
            restarted
                .record_recovery_zero_delta_for_grammar_test([0xb6; 32], 3)
                .unwrap();
            restarted
                .record_recovery_ready_for_grammar_test([0xb7; 32], validator_count(&context))
                .unwrap();
            restarted
                .record_recovery_start_for_grammar_test([0xb8; 32], validator_count(&context))
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(restarted
                .record_recovery_start_for_grammar_test([0xb8; 32], validator_count(&context),)
                .is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    #[ignore = "requires an authenticated Cut/Park/ParkedAck process-2 fixture"]
    fn observer_replay_distinguishes_all_four_process2_restart_phases() {
        let (temporary, context, key) = fixture();
        let path = temporary.path().join("restart-phases.jsonl");
        let mut restarted = start_test_process2(&path, &context, &key, 53);
        let statement_count = u64::try_from(context.validator_set.validators().len()).unwrap();

        let replay = || {
            let file = File::open(&path).unwrap();
            let events = read_exact_events(&file).unwrap();
            validate_event_chain(&events, &context).unwrap()
        };
        let pending = replay();
        assert!(pending.state.restart_pending_catchup_v1());
        assert!(!pending.state.restart_catchup_complete_v1());
        assert!(!pending.state.restart_recovery_ready_v1());
        assert!(!pending.state.restart_completed_v1());
        assert_eq!(
            pending.state.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process2CatchupPending
        );

        restarted
            .record_recovery_zero_delta_for_grammar_test([0xab; 32], 3)
            .unwrap();
        let ready_pending = replay();
        assert!(!ready_pending.state.restart_pending_catchup_v1());
        assert!(ready_pending.state.restart_catchup_complete_v1());
        assert!(!ready_pending.state.restart_recovery_ready_v1());
        assert!(!ready_pending.state.restart_completed_v1());
        assert_eq!(
            ready_pending.state.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process2RecoveryReadyPending
        );
        assert!(!restarted.observation().restart_pending_catchup);
        assert!(restarted.observation().restart_catchup_complete_v1());
        assert!(restarted
            .observation()
            .restart_recovery_barrier_pending_v1());
        assert!(!restarted.observation().restart_completed);

        restarted
            .record_recovery_ready_for_grammar_test([0xac; 32], statement_count)
            .unwrap();
        let start_pending = replay();
        assert!(!start_pending.state.restart_pending_catchup_v1());
        assert!(start_pending.state.restart_catchup_complete_v1());
        assert!(start_pending.state.restart_recovery_ready_v1());
        assert!(!start_pending.state.restart_completed_v1());
        assert_eq!(
            start_pending.state.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process2RecoveryStartPending
        );
        assert!(restarted
            .observation()
            .restart_recovery_barrier_pending_v1());

        restarted
            .record_recovery_start_for_grammar_test([0xad; 32], statement_count)
            .unwrap();
        let completed = replay();
        assert!(!completed.state.restart_pending_catchup_v1());
        assert!(completed.state.restart_catchup_complete_v1());
        assert!(completed.state.restart_recovery_ready_v1());
        assert!(completed.state.restart_completed_v1());
        assert_eq!(
            completed.state.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process2Completed
        );
        assert!(restarted.observation().restart_completed);
        assert!(!restarted
            .observation()
            .restart_recovery_barrier_pending_v1());
        restarted
            .append(RuntimeEventKindV1::ProposalAdmitted, "post-start", 5)
            .unwrap();
    }

    #[test]
    fn explicit_restart_state_rejects_impossible_process_role_combinations() {
        let fixture = process2_gate_fixture();
        let events = {
            let file = File::open(&fixture.journal_path).unwrap();
            read_exact_events(&file).unwrap()
        };
        let recovered = validate_event_chain(&events, &fixture.context).unwrap();
        let parked = match recovered.state.restart {
            RuntimeRestartJournalStateV1::Parked(facts) => facts,
            other => panic!("expected target parked state, got {other:?}"),
        };
        assert_eq!(
            recovered.state.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1TargetParked
        );
        let parked_ack = RestartParkedAckJournalFactsV1 {
            parked,
            subject: RestartParkedAckSubjectV1 {
                ack_certificate_sha256: [0xa1; 32],
                local_ack_statement_sha256: [0xa2; 32],
                cut_artifact_sha256: parked.cut_park.subject.cut_artifact_sha256,
                park_artifact_sha256: parked.cut_park.subject.park_artifact_sha256,
                ack_admission_set_sha256: [0xa3; 32],
            },
            statement_count: parked.cut_park.statement_count,
        };

        let mut process1_acked = recovered.state.clone();
        process1_acked.restart = RuntimeRestartJournalStateV1::ParkedAcked(parked_ack);
        process1_acked.require_restart_phase_consistent().unwrap();
        assert_eq!(
            process1_acked.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process1TargetParkedAcked
        );

        let mut marker = process1_acked;
        marker.current_instance = 2;
        marker.restart = RuntimeRestartJournalStateV1::Process2RestartMarkerPending(parked_ack);
        marker.require_restart_phase_consistent().unwrap();
        assert_eq!(
            marker.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process2RestartMarkerPending
        );

        let mut process2_parked = marker.clone();
        process2_parked.restart = RuntimeRestartJournalStateV1::ParkedAcked(parked_ack);
        process2_parked.require_restart_phase_consistent().unwrap();
        assert_eq!(
            process2_parked.restart_phase_v1(),
            RuntimeRestartPhaseV1::Process2CatchupPending
        );

        let mut invalid_marker = marker;
        invalid_marker.current_instance = 1;
        assert!(invalid_marker.require_restart_phase_consistent().is_err());
        let mut invalid_idle = RuntimeJournalStateV1 {
            current_instance: 2,
            ..RuntimeJournalStateV1::default()
        };
        assert!(invalid_idle.require_restart_phase_consistent().is_err());
        invalid_idle.current_instance = 3;
        invalid_idle.restart = RuntimeRestartJournalStateV1::ParkedAcked(parked_ack);
        assert!(invalid_idle.require_restart_phase_consistent().is_err());
    }

    #[test]
    fn normal_build_has_no_scalar_zero_delta_ready_or_start_authority() {
        let source = include_str!("process_event.rs");
        for pieces in [
            ["pub fn record_", "recovery_zero_delta"],
            ["pub fn record_", "recovery_ready"],
            ["pub fn record_", "recovery_start"],
        ] {
            let forbidden = pieces.concat();
            assert!(!source.contains(&forbidden), "{forbidden}");
        }

        let enum_start = source
            .find("pub enum RuntimeEventKindV1")
            .expect("runtime event kind remains present");
        let enum_end = source[enum_start..]
            .find("impl RuntimeEventKindV1")
            .map(|offset| enum_start + offset)
            .expect("runtime event enum remains bounded");
        let event_enum = &source[enum_start..enum_end];
        let catchup_variant = ["Catchup", "Complete"].concat();
        let ready_variant = ["Recovery", "Ready"].concat();
        let start_variant = ["Recovery", "Start"].concat();
        assert!(!event_enum.contains(&catchup_variant));
        assert!(!event_enum.contains(&ready_variant));
        assert!(!event_enum.contains(&start_variant));

        for helper in [
            "fn record_recovery_zero_delta_for_grammar_test",
            "fn record_recovery_ready_for_grammar_test",
            "fn record_recovery_start_for_grammar_test",
        ] {
            let position = source.find(helper).expect("grammar helper remains present");
            let prefix = &source[position.saturating_sub(160)..position];
            assert!(prefix.contains("#[cfg(test)]"), "{helper}");
        }

        let zero_delta = source
            .find("\"recovery_zero_delta\" =>")
            .expect("zero-delta replay grammar remains present");
        let ready = source[zero_delta..]
            .find("\"recovery_ready\" =>")
            .map(|offset| zero_delta + offset)
            .expect("RecoveryReady replay grammar remains present");
        let start = source[ready..]
            .find("\"recovery_start\" =>")
            .map(|offset| ready + offset)
            .expect("RecoveryStart replay grammar remains present");
        let fault = source[start..]
            .find("\"fault_applied\" =>")
            .map(|offset| start + offset)
            .expect("RecoveryStart replay grammar remains bounded");
        assert!(
            source[zero_delta..ready].contains("RuntimeRestartJournalStateV1::ZeroDeltaRecorded")
        );
        assert!(
            source[ready..start].contains("RuntimeRestartJournalStateV1::RecoveryReadyRecorded")
        );
        assert!(source[start..fault].contains("RuntimeRestartJournalStateV1::RecoveryCompleted"));
    }

    #[test]
    fn public_observer_replays_complete_journal_and_rejects_all_chain_mutants() {
        let (temporary, context, key) = fixture();
        let journal_path = temporary.path().join("complete.jsonl");
        let block = [0xa1; 32];
        let state = [0xa2; 32];
        let chain = [0xa3; 32];
        let mut journal =
            RuntimeEventJournalV1::start_with_context(&journal_path, context.clone(), key.clone())
                .unwrap();
        enter_fleet_started(&mut journal);
        journal
            .append(RuntimeEventKindV1::Finalized, &hex::encode(block), 9)
            .unwrap();
        journal
            .append(
                RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode(state),
                9,
            )
            .unwrap();
        journal.record_final_tip(block, state, chain, 9).unwrap();
        let clean_stop = journal.record_clean_stop().unwrap();
        drop(journal);

        let verified =
            verify_runtime_event_journal_with_context_v1(&journal_path, &context).unwrap();
        assert_eq!(verified.schema_version, EVENT_SCHEMA_VERSION);
        assert_eq!(
            verified.status,
            "runtime-journal-signature-and-semantics-verified"
        );
        assert_eq!(verified.run_id, context.run_id);
        assert_eq!(
            verified.validator_id,
            hex::encode(context.validator_id.as_bytes())
        );
        assert_eq!(verified.process_instance_count, 1);
        assert_eq!(verified.event_count, 9);
        assert_eq!(verified.runtime_event_sequence, clean_stop.sequence);
        assert_eq!(verified.runtime_event_sha256, clean_stop.event_sha256);
        assert_eq!(verified.finalized_height, 9);
        assert_eq!(verified.finalized_block_id, hex::encode(block));
        assert_eq!(verified.finalized_state_root, hex::encode(state));
        assert_eq!(verified.finalized_chain_root, hex::encode(chain));
        assert_eq!(verified.recovered_fault_count, 0);
        assert!(!verified.restart_completed);
        assert!(verified.clean_stop);
        assert!(verified.signature_verified);
        assert!(verified.semantics_verified);
        assert!(!verified.g3_evidence_complete);
        assert!(!verified.geo_wan_evidence);
        assert!(!verified.production_activation);

        let complete = {
            let file = File::open(&journal_path).unwrap();
            read_exact_events(&file).unwrap()
        };

        let truncated_path = temporary.path().join("truncated.jsonl");
        write_canonical_events(&truncated_path, &complete[..complete.len() - 1]);
        assert!(verify_runtime_event_journal_with_context_v1(&truncated_path, &context).is_err());

        let reordered_path = temporary.path().join("reordered.jsonl");
        let mut reordered = complete.clone();
        reordered.swap(1, 2);
        rechain_and_resign(&mut reordered, &key);
        write_canonical_events(&reordered_path, &reordered);
        assert!(verify_runtime_event_journal_with_context_v1(&reordered_path, &context).is_err());

        let signature_path = temporary.path().join("signature.jsonl");
        let mut bad_signature = complete.clone();
        let replacement = if bad_signature[2].signature.starts_with('0') {
            "1"
        } else {
            "0"
        };
        bad_signature[2].signature.replace_range(0..1, replacement);
        write_canonical_events(&signature_path, &bad_signature);
        assert!(verify_runtime_event_journal_with_context_v1(&signature_path, &context).is_err());

        let mut foreign_context = context.clone();
        foreign_context.config_sha256 = [0xb1; 32];
        assert!(
            verify_runtime_event_journal_with_context_v1(&journal_path, &foreign_context).is_err()
        );

        let terminal_gap_path = temporary.path().join("terminal-gap.jsonl");
        let mut terminal_gap = complete.clone();
        let final_tip_index = terminal_gap.len() - 2;
        let mut gap = terminal_gap[final_tip_index].clone();
        gap.kind = RuntimeEventKindV1::PeerSessionEstablished
            .as_str()
            .to_owned();
        gap.subject = "terminal-gap-peer".to_owned();
        gap.value = 1;
        terminal_gap.insert(final_tip_index + 1, gap);
        rechain_and_resign(&mut terminal_gap, &key);
        write_canonical_events(&terminal_gap_path, &terminal_gap);
        assert!(
            verify_runtime_event_journal_with_context_v1(&terminal_gap_path, &context).is_err()
        );

        let partial_path = temporary.path().join("partial.jsonl");
        let mut partial = fs::read(&journal_path).unwrap();
        partial.pop();
        fs::write(&partial_path, partial).unwrap();
        assert!(verify_runtime_event_journal_with_context_v1(&partial_path, &context).is_err());
    }
}
