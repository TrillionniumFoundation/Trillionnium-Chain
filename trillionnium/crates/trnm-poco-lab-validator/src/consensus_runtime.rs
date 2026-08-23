//! Bounded real-process PoCO-BFT consensus owner for the Stage0 seven-validator LAN lane.
//!
//! The public entry in this module deliberately accepts a one-shot
//! commissioner.  The commissioner is invoked inside the same bounded 32 MiB
//! owner thread which subsequently owns Core, Safety, native application,
//! signer journal, checkpoint, mesh, pacemaker, process journal, and terminal
//! report authority.  This prevents a deep authority graph from being built
//! on a smaller caller stack and moved into the runtime afterwards.
//!
//! The active frozen topology uses direct consensus frames. The 31/100
//! degree-eight ring layouts remain dormant planning code until their durable
//! Core/store capacity profiles are separately verified; runtime preflight
//! rejects both before effects. A successful report from this module is single-LAN
//! validator-run evidence only; it does not set any fault, performance,
//! geo-WAN, G3-complete, or production truth bit.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use trnm_consensus_core::leader_for;
use trnm_consensus_signer_journal::SignerWatermarkV0;
use trnm_consensus_types::{
    BlockId, Epoch, Height, QcRef, QcReferenceV0, QuorumCertificate, RecoveryContextV1,
    RecoveryContextV1Fields, RecoveryModeV1, RecoveryZeroDeltaCutV1, RecoveryZeroDeltaCutV1Fields,
    StateRoot, TimeoutCertificateV0, ValidatorId, View, RECOVERY_PROCESS_INSTANCE_V1,
};
use trnm_poco_node::{
    validate_deployed_lab_core_record_envelope_v0, PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1,
    PocoNodeDeployedLabZeroDeltaRestartCutFieldsV1, PocoNodeDeployedLabZeroDeltaRestartCutV1,
    PocoNodeLabAuthorityPhaseV0, PocoNodeLabOrdinaryProposalRuntimeV0,
};

use crate::{
    bootstrap_material::VerifiedPublicBootstrapInitialCutV1,
    config::{LoadedValidatorConfig, DEPLOYED_CORE_MAX_BLOCKS_V1},
    consensus_mesh::{
        MeshIngressEventV0, PeerDirectionV0, PeerSessionFactsV0, PersistentAuthenticatedPeerMeshV0,
    },
    consensus_report::{
        sign_consensus_run_report_v1, validate_consensus_run_report_target_v1,
        write_consensus_run_report_v1, ConsensusRunBoundsV1, ConsensusRunTerminalFactsV1,
        MAX_CONSENSUS_RUN_BLOCKS_V1, MAX_CONSENSUS_RUN_DURATION_SECONDS_V1,
    },
    continuous_runtime::{
        ContinuousRuntimeFactsV0, ContinuousSignerLifetimeBoundsV0, ContinuousValidatorAuthorityV0,
        CONTINUOUS_RUNTIME_MAXIMUM_SIGNER_INTENTS_V0, CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0,
    },
    crypto::LabFileWatermark,
    fleet_barrier::{
        CommonCampaignContextV1, CommonChainCutV1, FleetBarrierAdmissionMapV1,
        FleetBarrierAdmissionV1, FleetBarrierTransportV1, FleetCampaignCapacitiesV1,
        FleetCampaignIdentityV1, FleetCampaignRequestV1, FleetMeshSessionDirectionV1,
        FleetMeshSessionSetV1, FleetMeshSessionV1, FleetStartCertificateV1, LocalReadyCutV1,
        SignedFleetReadyV1, SignedFleetStartV1, MAX_FLEET_START_CERTIFICATE_BYTES_V1,
    },
    frame::FrameKind,
    loop_driver::RoutedConsensusActionV0,
    p2p_admission::{ExternalPeerLeaseAuthorityV1, RejectingExternalPeerLeaseAuthorityV1},
    pacemaker::GenerationAwarePacemakerV0,
    process_event::{
        LocalRestartParkJournalCommitV1, Process1TargetParkedJournalCutV1,
        Process2JournalStartedFromRestartCutV1, RuntimeEventJournalV1, RuntimeEventKindV1,
        RuntimeRestartPhaseV1,
    },
    recovery_zero_delta_store::{persist_recovery_zero_delta_cut_v1, StoredRecoveryZeroDeltaCutV1},
    relay::{required_ring_relay_hops_v0, ConsensusRelayEnvelopeV0},
    restart_cut::{
        LocalRestartParkV1, RestartCutBodyV1, RestartCutStateV1, RestartParkRoleV1,
        RestartSharedCutV1, SignedRestartCutV1,
    },
    restart_park_protocol::{
        AdmittedRestartCutParkV1, AdmittedRestartPrepareV1, DurablyParkedPeerRestartOwnerV1,
        DurablyParkedTargetRestartOwnerV1, OriginatedRestartCutParkV1, OriginatedRestartPrepareV1,
        StoredRestartCutParkCertificatesV1, VerifiedRestartCutParkCertificatesV1,
    },
    restart_parked_ack_protocol::{
        AdmittedRestartParkedAckV1, DurablyAcknowledgedRestartParkedBarrierV1,
        OriginatedRestartParkedAckV1, VerifiedRestartParkedAckBarrierV1,
    },
    restart_protocol::{
        AdmittedRestartProtocolMessageV1, BoundedRestartProtocolIngressV1,
        RestartProtocolOriginReservationV1, RestartProtocolPhaseV1, RestartRelayAdmissionWindowV1,
        RoutedRestartProtocolActionV1,
    },
    runtime_control::{
        write_runtime_control_status_v1, RuntimeControlPollV1, RuntimeControlServerV1,
        RuntimeRestartPrepareIntentV1,
    },
    runtime_evidence::{
        sign_runtime_final_state_v1, sign_runtime_metrics_v1, write_runtime_final_state_v1,
        write_runtime_metrics_v1, RuntimeFinalStateFactsV1, RuntimeMetricsFactsV1,
    },
    signed_replay_archive::{
        ArchivedDeployedProcess2RecoveryOwnerV1, ArchivedDeployedProcess2ZeroDeltaCaughtUpOwnerV1,
        SignedReplayArchiveBoundsV1, SignedReplayArchiveV1, MAXIMUM_ENTRY_COUNT_V1,
    },
    wire::{
        encode_quorum_certificate, encode_timeout_certificate, encode_timeout_vote, encode_vote,
        UnboundProposalV0,
    },
};

pub const CONSENSUS_RUNTIME_COMMISSIONING_ALLOWANCE_SECONDS_V1: u64 = 300;
/// Upper bound for the coordinator's sequential process-launch skew before
/// every validator has entered its independent commissioning phase.
pub const CONSENSUS_RUNTIME_FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS_V1: u64 = 30;
/// Sizing input for the hard timeout-view cap. This is not evidence of, nor
/// an authority for, physical launch skew between independent host clocks.
/// Safety comes from rejecting every view beyond the derived cap.
pub const CONSENSUS_RUNTIME_TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS_V1: u64 = 30;
/// A fast validator may enter mesh establishment before a later-launched peer
/// begins its complete commissioning allowance. Its wait must therefore
/// cover both bounds rather than a shorter, unrelated socket timeout.
pub const CONSENSUS_RUNTIME_MESH_SETUP_ALLOWANCE_SECONDS_V1: u64 =
    CONSENSUS_RUNTIME_COMMISSIONING_ALLOWANCE_SECONDS_V1
        + CONSENSUS_RUNTIME_FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS_V1;
pub const CONSENSUS_RUNTIME_STARTUP_ALLOWANCE_SECONDS_V1: u64 =
    CONSENSUS_RUNTIME_COMMISSIONING_ALLOWANCE_SECONDS_V1
        + CONSENSUS_RUNTIME_MESH_SETUP_ALLOWANCE_SECONDS_V1;
pub const CONSENSUS_RUNTIME_TERMINAL_DRAIN_ALLOWANCE_SECONDS_V1: u64 = 30;
pub const CONSENSUS_RUNTIME_PACEMAKER_BASE_TIMEOUT_SECONDS_V1: u64 = 2;
pub const CONSENSUS_RUNTIME_FLEET_BARRIER_ROUND_V1: u64 = 1;
pub const CONSENSUS_RUNTIME_FLEET_PROCESS_ALLOWANCE_SECONDS_V1: u64 =
    CONSENSUS_RUNTIME_STARTUP_ALLOWANCE_SECONDS_V1
        + CONSENSUS_RUNTIME_TERMINAL_DRAIN_ALLOWANCE_SECONDS_V1;
pub const MINIMUM_CONSENSUS_RUN_BLOCKS_V1: u64 = 3;
/// Dedicated successful CLI status for the exact process-1 target parked
/// handoff. It is intentionally distinct from both a completed report (`0`)
/// and an error (`2`).
pub const PROCESS1_TARGET_PARKED_EXIT_STATUS_V1: u8 = 75;

/// Public bounded-runtime outcome. A parked handoff is a successful resource
/// shutdown boundary, not a normal terminal consensus report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedConsensusRunOutcomeV1 {
    CompletedReport(PathBuf),
    Process1TargetParked(Process1TargetParkedHandoffV1),
}

/// Data-only descriptor emitted after the target's process-1 control socket,
/// pacemaker, and complete mesh have closed. The owner thread (and therefore
/// the exclusive journal lock) has returned before this value reaches the
/// caller. No field grants signing, restart, process-control, or process-2
/// authority; process 2 must independently reopen and authenticate all gates.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Process1TargetParkedHandoffV1 {
    pub schema_version: u32,
    pub status: String,
    pub run_id: String,
    pub validator_id: String,
    pub process1_pid: u32,
    pub process1_instance: u64,
    pub process2_instance: u64,
    pub restart_park_event_sequence: u64,
    pub restart_park_event_sha256: String,
    pub restart_parked_ack_event_sequence: u64,
    pub restart_parked_ack_event_sha256: String,
    pub restart_cut_artifact_sha256: String,
    pub restart_park_artifact_sha256: String,
    pub restart_parked_ack_artifact_sha256: String,
    pub restart_parked_ack_admission_set_sha256: String,
    pub local_restart_parked_ack_statement_sha256: String,
    pub protocol_authority: bool,
    pub production_activation: bool,
}

const DIRECT_VALIDATOR_COUNT_V1: usize = 7;
const DIRECT_PEER_DEGREE_V1: usize = 6;
const SPARSE_PEER_DEGREE_V1: usize = 8;
const MESH_SETUP_TIMEOUT_V1: Duration =
    Duration::from_secs(CONSENSUS_RUNTIME_MESH_SETUP_ALLOWANCE_SECONDS_V1);
const MESH_IO_TIMEOUT_V1: Duration = Duration::from_secs(2);
const MESH_QUEUE_CAPACITY_V1: usize = 256;
const OWNER_POLL_INTERVAL_V1: Duration = Duration::from_millis(10);
const PACEMAKER_BASE_TIMEOUT_V1: Duration =
    Duration::from_secs(CONSENSUS_RUNTIME_PACEMAKER_BASE_TIMEOUT_SECONDS_V1);
const PACEMAKER_MAXIMUM_TIMEOUT_V1: Duration = Duration::from_secs(30);
const TERMINAL_QUIET_PERIOD_V1: Duration = Duration::from_millis(250);
const MINIMUM_METRICS_INTERVAL_V1: Duration = Duration::from_secs(1);
const TERMINAL_DRAIN_GRACE_V1: Duration =
    Duration::from_secs(CONSENSUS_RUNTIME_TERMINAL_DRAIN_ALLOWANCE_SECONDS_V1);
const MAXIMUM_PENDING_BROADCASTS_V1: usize = 256;
const MAXIMUM_PENDING_BROADCAST_BYTES_V1: usize = 32 * 1024 * 1024;
const MAXIMUM_PENDING_CERTIFICATES_V1: usize = 64;
const MAXIMUM_PENDING_PROPOSALS_V1: usize = 64;
const MAXIMUM_TRACKED_PROPOSAL_TIMESTAMPS_V1: usize = 128;
const RUNTIME_METRICS_FILE_V1: &str = "runtime-metrics.json";
const RUNTIME_FINAL_STATE_FILE_V1: &str = "runtime-final-state.json";
const FLEET_START_CERTIFICATE_FILE_V1: &str = "fleet-start-certificate.bin";
const FLEET_START_CERTIFICATE_NEXT_FILE_V1: &str = "fleet-start-certificate.next";
const FLEET_BARRIER_ROUND_V1: u64 = CONSENSUS_RUNTIME_FLEET_BARRIER_ROUND_V1;
const FLEET_BARRIER_TIMEOUT_V1: Duration =
    Duration::from_secs(CONSENSUS_RUNTIME_FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS_V1);
const MAXIMUM_PRESTART_ORDINARY_INGRESS_V1: usize = 256;
const MAXIMUM_PREPARED_NORMAL_FRAME_DROPS_V1: u64 = 262_144;

/// Exact recovery-bound projection of every RestartCut state field. The
/// finalized-chain-root and runtime-journal coordinates come from the
/// independently re-read carrier consumed by the process-2 start gate; all
/// other fields come from independently reopened recovery owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Process2RestartCutStateProjectionV1 {
    epoch: Epoch,
    current_view: View,
    direct_high_qc: QcRef,
    proposal_parent_height: Height,
    proposal_parent_block_id: BlockId,
    finalized_height: Height,
    finalized_block_id: BlockId,
    finalized_chain_root: [u8; 32],
    application_height: Height,
    application_block_id: BlockId,
    application_state_root: StateRoot,
    external_checkpoint_generation: u64,
    external_checkpoint_checksum: [u8; 32],
    safety_revision: u64,
    safety_state_record_checksum: [u8; 32],
    safety_record_chain_checksum: [u8; 32],
    signer_watermark: SignerWatermarkV0,
    signer_durable_vote_intent_count: u64,
    signer_durable_timeout_intent_count: u64,
    signer_signed_vote_intent_count: u64,
    signer_signed_timeout_intent_count: u64,
    signer_inventory_digest: [u8; 32],
    pending_sign: Option<[u8; 32]>,
    replay_archive_context_sha256: [u8; 32],
    replay_archive_head_sequence: u64,
    replay_archive_head_sha256: [u8; 32],
    runtime_journal_head_sequence: u64,
    runtime_journal_head_sha256: [u8; 32],
}

impl Process2RestartCutStateProjectionV1 {
    #[cfg(test)]
    const fn from_restart_state_for_test_v1(state: RestartCutStateV1) -> Self {
        Self {
            epoch: state.epoch,
            current_view: state.current_view,
            direct_high_qc: state.direct_high_qc,
            proposal_parent_height: state.proposal_parent_height,
            proposal_parent_block_id: state.proposal_parent_block_id,
            finalized_height: state.finalized_height,
            finalized_block_id: state.finalized_block_id,
            finalized_chain_root: state.finalized_chain_root,
            application_height: state.application_height,
            application_block_id: state.application_block_id,
            application_state_root: state.application_state_root,
            external_checkpoint_generation: state.external_checkpoint_generation,
            external_checkpoint_checksum: state.external_checkpoint_checksum,
            safety_revision: state.safety_revision,
            safety_state_record_checksum: state.safety_state_record_checksum,
            safety_record_chain_checksum: state.safety_record_chain_checksum,
            signer_watermark: state.signer_watermark,
            signer_durable_vote_intent_count: state.signer_durable_vote_intent_count,
            signer_durable_timeout_intent_count: state.signer_durable_timeout_intent_count,
            signer_signed_vote_intent_count: state.signer_signed_vote_intent_count,
            signer_signed_timeout_intent_count: state.signer_signed_timeout_intent_count,
            signer_inventory_digest: state.signer_inventory_digest,
            pending_sign: state.pending_sign,
            replay_archive_context_sha256: state.replay_archive_context_sha256,
            replay_archive_head_sequence: state.replay_archive_head_sequence,
            replay_archive_head_sha256: state.replay_archive_head_sha256,
            runtime_journal_head_sequence: state.runtime_journal_head_sequence,
            runtime_journal_head_sha256: state.runtime_journal_head_sha256,
        }
    }
}

fn require_process2_restart_state_projection_v1(
    state: RestartCutStateV1,
    expected: Process2RestartCutStateProjectionV1,
) -> Result<()> {
    let observed = Process2RestartCutStateProjectionV1 {
        epoch: state.epoch,
        current_view: state.current_view,
        direct_high_qc: state.direct_high_qc,
        proposal_parent_height: state.proposal_parent_height,
        proposal_parent_block_id: state.proposal_parent_block_id,
        finalized_height: state.finalized_height,
        finalized_block_id: state.finalized_block_id,
        finalized_chain_root: state.finalized_chain_root,
        application_height: state.application_height,
        application_block_id: state.application_block_id,
        application_state_root: state.application_state_root,
        external_checkpoint_generation: state.external_checkpoint_generation,
        external_checkpoint_checksum: state.external_checkpoint_checksum,
        safety_revision: state.safety_revision,
        safety_state_record_checksum: state.safety_state_record_checksum,
        safety_record_chain_checksum: state.safety_record_chain_checksum,
        signer_watermark: state.signer_watermark,
        signer_durable_vote_intent_count: state.signer_durable_vote_intent_count,
        signer_durable_timeout_intent_count: state.signer_durable_timeout_intent_count,
        signer_signed_vote_intent_count: state.signer_signed_vote_intent_count,
        signer_signed_timeout_intent_count: state.signer_signed_timeout_intent_count,
        signer_inventory_digest: state.signer_inventory_digest,
        pending_sign: state.pending_sign,
        replay_archive_context_sha256: state.replay_archive_context_sha256,
        replay_archive_head_sequence: state.replay_archive_head_sequence,
        replay_archive_head_sha256: state.replay_archive_head_sha256,
        runtime_journal_head_sequence: state.runtime_journal_head_sequence,
        runtime_journal_head_sha256: state.runtime_journal_head_sha256,
    };
    ensure!(
        observed == expected,
        "stored RestartCut state differs from full inert process2 recovery"
    );
    Ok(())
}

/// The only successful output of the T3-A process-2 join.  It retains all
/// three linear inputs: the locked process-2 journal-start owner, the freshly
/// read N/N RestartCut, and the archive-pinned full recovery owner.  The type
/// intentionally has no mesh, RecoveryReady, RecoveryStart, activation,
/// signer, timer, or catch-up transition.
#[must_use = "the joined process-2 owner must remain inert or be consumed into its fail-stop event"]
struct RestartCutJoinedProcess2InertOwnerV1 {
    started: Process2JournalStartedFromRestartCutV1,
    recovered: ArchivedDeployedProcess2RecoveryOwnerV1,
}

impl std::fmt::Debug for RestartCutJoinedProcess2InertOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestartCutJoinedProcess2InertOwnerV1")
            .field("started", &self.started)
            .field(
                "restart_cut_artifact_sha256",
                &hex::encode(self.started.restart_cut_artifact_sha256_v1()),
            )
            .field(
                "restart_park_artifact_sha256",
                &hex::encode(self.started.restart_park_artifact_sha256_v1()),
            )
            .field(
                "restart_parked_ack_artifact_sha256",
                &hex::encode(self.started.restart_parked_ack_artifact_sha256_v1()),
            )
            .field(
                "restart_parked_ack_admission_set_sha256",
                &hex::encode(self.started.restart_parked_ack_admission_set_sha256_v1()),
            )
            .field("archive", &self.recovered.archive_facts_v1())
            .field("process2", &self.recovered.process2_facts_v1())
            .finish_non_exhaustive()
    }
}

impl RestartCutJoinedProcess2InertOwnerV1 {
    /// Consumes the full T3-A owner into Node's exact read-only zero-delta
    /// confirmation while retaining the journal-start, RestartCut, and replay
    /// archive owners.  This does not persist a recovery artifact, sign Ready,
    /// accept Start, clear the replay fence, or activate any authority.
    fn confirm_zero_delta_caught_up_v1(
        self,
        config: &LoadedValidatorConfig,
    ) -> Result<RestartCutJoinedProcess2ZeroDeltaOwnerV1> {
        self.started
            .revalidate_unchanged_start_v1()
            .map_err(|error| {
                anyhow!("revalidate process2 journal before zero-delta join: {error}")
            })?;
        self.recovered
            .revalidate_archive_identity_v1()
            .context("revalidate replay archive before zero-delta Node join")?;
        let state = self.started.restart_cut_body_v1().state();
        let expected = PocoNodeDeployedLabZeroDeltaRestartCutV1::new(
            PocoNodeDeployedLabZeroDeltaRestartCutFieldsV1 {
                restart_cut_artifact_sha256: self.started.restart_cut_artifact_sha256_v1(),
                local_validator: config.local_validator(),
                validator_set_id: config.validator_set().id(),
                epoch: state.epoch,
                current_view: state.current_view,
                direct_high_qc: state.direct_high_qc,
                proposal_parent_height: state.proposal_parent_height.get(),
                proposal_parent_block_id: state.proposal_parent_block_id,
                finalized_height: state.finalized_height.get(),
                finalized_block_id: state.finalized_block_id,
                finalized_chain_root: state.finalized_chain_root,
                application_height: state.application_height.get(),
                application_block_id: state.application_block_id,
                application_state_root: state.application_state_root,
                restart_checkpoint_generation: state.external_checkpoint_generation,
                restart_checkpoint_canonical_sha256: state.external_checkpoint_checksum,
                restart_safety_revision: state.safety_revision,
                restart_safety_state_record_checksum: state.safety_state_record_checksum,
                restart_safety_chain_checksum: state.safety_record_chain_checksum,
                signer_exact_watermark: state.signer_watermark,
                signer_durable_vote_intent_count: state.signer_durable_vote_intent_count,
                signer_durable_timeout_intent_count: state.signer_durable_timeout_intent_count,
                signer_signed_vote_intent_count: state.signer_signed_vote_intent_count,
                signer_signed_timeout_intent_count: state.signer_signed_timeout_intent_count,
                signer_inventory_digest: state.signer_inventory_digest,
            },
        )
        .map_err(|error| anyhow!("construct inert Node zero-delta RestartCut join: {error}"))?;
        let mut recovered = self
            .recovered
            .confirm_zero_delta_caught_up_v1(expected)
            .context("consume archive-pinned Node zero-delta join")?;
        self.started
            .revalidate_unchanged_start_v1()
            .map_err(|error| {
                anyhow!("revalidate process2 journal at zero-delta commit: {error}")
            })?;
        recovered
            .revalidate_zero_delta_caught_up_v1()
            .context("revalidate Node and replay archive at zero-delta join commit")?;
        ensure!(
            recovered
                .zero_delta_facts_v1()
                .restart_cut_v1()
                .fields_v1()
                .restart_cut_artifact_sha256
                == self.started.restart_cut_artifact_sha256_v1(),
            "zero-delta Node owner differs from retained RestartCut"
        );
        Ok(RestartCutJoinedProcess2ZeroDeltaOwnerV1 {
            started: self.started,
            recovered,
        })
    }

    /// Consumes the complete joined owner into the current deliberate
    /// fail-stop event.  Fresh readback and the unchanged journal-start head
    /// are checked again immediately before the only permitted effect.
    fn record_inert_safety_halted_v1(mut self) -> Result<()> {
        self.started
            .revalidate_unchanged_start_v1()
            .map_err(|error| anyhow!("revalidate joined process2 journal start: {error}"))?;
        self.recovered
            .revalidate_archive_identity_v1()
            .context("revalidate joined process2 archive before inert halt")?;
        ensure!(
            self.started.restart_cut_artifact_sha256_v1() != [0; 32]
                && self.started.restart_park_artifact_sha256_v1() != [0; 32]
                && self.started.restart_parked_ack_artifact_sha256_v1() != [0; 32]
                && self
                    .started
                    .restart_parked_ack_admission_set_sha256_v1()
                    != [0; 32]
                && self.started.restart_cut_statement_count_v1() == 7,
            "joined process2 RestartCut/RestartPark/RestartParkedAck triple changed before inert halt"
        );
        let archive = self.recovered.archive_facts_v1();
        let process2 = self.recovered.process2_facts_v1();
        self.started
            .record_joined_inert_safety_halted_v1(
                &format!(
                    "continuous-runtime-restart-cut-joined-process2-inert:{}:{}:{}:{}",
                    archive.sequence_v1(),
                    hex::encode(archive.context_sha256_v1()),
                    hex::encode(archive.record_sha256_v1()),
                    hex::encode(process2.session_id_v0()),
                ),
                process2.replayed_link_count_v0(),
            )
            .context("record RestartCut-joined inert process2 halt")?;
        Ok(())
    }
}

/// Exact T3-B zero-delta owner, still replay-fenced and unable to sign Ready.
#[must_use = "zero-delta join must retain every process2 and archive authority"]
struct RestartCutJoinedProcess2ZeroDeltaOwnerV1 {
    started: Process2JournalStartedFromRestartCutV1,
    recovered: ArchivedDeployedProcess2ZeroDeltaCaughtUpOwnerV1,
}

impl RestartCutJoinedProcess2ZeroDeltaOwnerV1 {
    const fn facts_v1(&self) -> PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1 {
        self.recovered.zero_delta_facts_v1()
    }

    fn revalidate_retained_inputs_v1(&mut self) -> Result<()> {
        self.started
            .revalidate_unchanged_start_v1()
            .map_err(|error| anyhow!("revalidate process2 journal at zero-delta store: {error}"))?;
        self.recovered
            .revalidate_zero_delta_caught_up_v1()
            .context("revalidate Node and replay archive at zero-delta store")
    }

    /// Builds and persists the canonical zero-delta cut while retaining every
    /// journal, RestartCut, replay archive, and Node recovery owner.  This
    /// method is deliberately dormant: the operational process-2 branch must
    /// not call it until it also consumes a future N/N durable park owner.
    fn persist_zero_delta_cut_dormant_v1(
        mut self,
        config: &LoadedValidatorConfig,
    ) -> Result<RestartCutJoinedProcess2PersistedZeroDeltaOwnerV1> {
        self.revalidate_retained_inputs_v1()?;
        let body = self.started.restart_cut_body_v1();
        let state = body.state();
        let facts = self.facts_v1();
        let node_cut = facts.restart_cut_v1().fields_v1();
        let validator_set = config.validator_set();
        ensure!(
            body.campaign().identity().validator_count() == 7
                && body.validator_set_id() == *validator_set.id().as_bytes()
                && body.validator_set_sha256() == config.validator_set_sha256()
                && body.target_validator() == config.local_validator()
                && body.target_config_sha256() == config.config_sha256()
                && body.process_instance() == 1
                && node_cut.restart_cut_artifact_sha256
                    == self.started.restart_cut_artifact_sha256_v1()
                && node_cut.local_validator == body.target_validator()
                && node_cut.validator_set_id == validator_set.id()
                && node_cut.epoch == state.epoch
                && node_cut.finalized_height == state.finalized_height.get()
                && node_cut.finalized_block_id == state.finalized_block_id
                && node_cut.finalized_chain_root == state.finalized_chain_root
                && node_cut.application_height == state.application_height.get()
                && node_cut.application_block_id == state.application_block_id
                && node_cut.application_state_root == state.application_state_root,
            "zero-delta projection differs from retained direct-7 authorities"
        );
        let node_artifact_sha256: [u8; 32] = Sha256::digest(facts.artifact_bytes_v1()).into();
        ensure!(
            node_artifact_sha256 == facts.artifact_sha256_v1(),
            "Node zero-delta helper artifact changed before canonical projection"
        );

        let cut = RecoveryZeroDeltaCutV1::new_direct7(
            RecoveryZeroDeltaCutV1Fields {
                campaign_context_sha256: body.campaign().digest(),
                fleet_start_certificate_sha256: body.fleet_start_certificate_sha256(),
                validator_set_id: validator_set.id(),
                validator_set_artifact_sha256: body.validator_set_sha256(),
                restart_cut_artifact_sha256: self.started.restart_cut_artifact_sha256_v1(),
                restart_park_artifact_sha256: self.started.restart_park_artifact_sha256_v1(),
                restart_parked_ack_artifact_sha256: self
                    .started
                    .restart_parked_ack_artifact_sha256_v1(),
                restart_parked_ack_admission_set_sha256: self
                    .started
                    .restart_parked_ack_admission_set_sha256_v1(),
                target_validator: body.target_validator(),
                process_instance: RECOVERY_PROCESS_INSTANCE_V1,
                recovery_nonce: self.started.restart_prepare_request_sha256_v1(),
                node_facts_sha256: facts.node_facts_sha256_v1(),
                signer_inventory_invariant_sha256: facts.signer_inventory_invariant_sha256_v1(),
                source_epoch: state.epoch,
                source_height: state.finalized_height,
                source_block_id: state.finalized_block_id,
                source_state_root: state.application_state_root,
                source_finalized_chain_root: state.finalized_chain_root,
                terminal_epoch: node_cut.epoch,
                terminal_height: Height::new(node_cut.application_height),
                terminal_block_id: node_cut.application_block_id,
                terminal_state_root: node_cut.application_state_root,
                terminal_finalized_chain_root: node_cut.finalized_chain_root,
                terminal_application_commit_sha256: facts.terminal_application_commit_id_v1(),
                terminal_checkpoint_canonical_sha256: facts
                    .process2_checkpoint_canonical_sha256_v1(),
            },
            validator_set,
        )
        .map_err(|error| anyhow!("construct canonical zero-delta cut: {error}"))?;
        let cut_bytes = cut
            .try_cev1_bytes()
            .map_err(|error| anyhow!("encode canonical zero-delta cut: {error}"))?;
        let cut_artifact_sha256: [u8; 32] = Sha256::digest(&cut_bytes).into();
        let cut_fields = cut.fields();
        let context = RecoveryContextV1::new_direct7(
            RecoveryContextV1Fields {
                mode: RecoveryModeV1::ZeroDelta,
                campaign_context_sha256: cut_fields.campaign_context_sha256,
                fleet_start_certificate_sha256: cut_fields.fleet_start_certificate_sha256,
                validator_set_id: cut_fields.validator_set_id,
                validator_set_artifact_sha256: cut_fields.validator_set_artifact_sha256,
                restart_cut_artifact_sha256: cut_fields.restart_cut_artifact_sha256,
                restart_park_artifact_sha256: cut_fields.restart_park_artifact_sha256,
                restart_parked_ack_artifact_sha256: cut_fields.restart_parked_ack_artifact_sha256,
                restart_parked_ack_admission_set_sha256: cut_fields
                    .restart_parked_ack_admission_set_sha256,
                caught_up_cut_artifact_sha256: cut_artifact_sha256,
                target_validator: cut_fields.target_validator,
                process_instance: cut_fields.process_instance,
                recovery_nonce: cut_fields.recovery_nonce,
                restart_cut_epoch: cut_fields.source_epoch,
                restart_cut_height: cut_fields.source_height,
                restart_cut_block_id: cut_fields.source_block_id,
                restart_cut_state_root: cut_fields.source_state_root,
                restart_cut_chain_root: cut_fields.source_finalized_chain_root,
                terminal_epoch: cut_fields.terminal_epoch,
                terminal_height: cut_fields.terminal_height,
                terminal_block_id: cut_fields.terminal_block_id,
                terminal_state_root: cut_fields.terminal_state_root,
                terminal_chain_root: cut_fields.terminal_finalized_chain_root,
                node_facts_sha256: cut_fields.node_facts_sha256,
            },
            validator_set,
        )
        .map_err(|error| anyhow!("construct zero-delta recovery context: {error}"))?;
        let persisted = persist_recovery_zero_delta_cut_v1(
            config.run_root(),
            cut_artifact_sha256,
            cut,
            &context,
            validator_set,
        )
        .context("persist canonical zero-delta cut")?;
        self.revalidate_retained_inputs_v1()?;
        persisted
            .revalidate_fresh_v1(validator_set)
            .context("revalidate persisted canonical zero-delta cut at commit")?;
        Ok(RestartCutJoinedProcess2PersistedZeroDeltaOwnerV1 {
            joined: self,
            persisted,
        })
    }
}

impl std::fmt::Debug for RestartCutJoinedProcess2ZeroDeltaOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestartCutJoinedProcess2ZeroDeltaOwnerV1")
            .field("journal_start", &self.started)
            .field(
                "restart_cut_artifact_sha256",
                &hex::encode(self.started.restart_cut_artifact_sha256_v1()),
            )
            .field(
                "restart_park_artifact_sha256",
                &hex::encode(self.started.restart_park_artifact_sha256_v1()),
            )
            .field(
                "restart_parked_ack_artifact_sha256",
                &hex::encode(self.started.restart_parked_ack_artifact_sha256_v1()),
            )
            .field(
                "restart_parked_ack_admission_set_sha256",
                &hex::encode(self.started.restart_parked_ack_admission_set_sha256_v1()),
            )
            .field("zero_delta", &self.recovered.zero_delta_facts_v1())
            .finish_non_exhaustive()
    }
}

/// Dormant, non-Clone owner proving that the exact Node-confirmed ZeroDelta
/// cut crossed its private create-new store boundary.  It grants no Ready,
/// Start, activation, signer, timer, mesh, or journal append authority.
#[must_use = "persisted zero-delta authority must remain retained until the N/N park barrier"]
struct RestartCutJoinedProcess2PersistedZeroDeltaOwnerV1 {
    joined: RestartCutJoinedProcess2ZeroDeltaOwnerV1,
    persisted: StoredRecoveryZeroDeltaCutV1,
}

impl std::fmt::Debug for RestartCutJoinedProcess2PersistedZeroDeltaOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestartCutJoinedProcess2PersistedZeroDeltaOwnerV1")
            .field("joined", &self.joined)
            .field(
                "zero_delta_artifact_sha256",
                &hex::encode(self.persisted.artifact_sha256_v1()),
            )
            .finish_non_exhaustive()
    }
}

fn require_process2_full_recovery_join_v1(
    config: &LoadedValidatorConfig,
    started: Process2JournalStartedFromRestartCutV1,
    recovered: ArchivedDeployedProcess2RecoveryOwnerV1,
) -> Result<RestartCutJoinedProcess2InertOwnerV1> {
    started
        .revalidate_unchanged_start_v1()
        .map_err(|error| anyhow!("revalidate process2 journal start before full join: {error}"))?;
    recovered
        .revalidate_archive_identity_v1()
        .context("revalidate process2 archive before full join")?;
    ensure!(
        started.process_instance_v1() == 2
            && started.restart_cut_artifact_sha256_v1() != [0; 32]
            && started.restart_park_artifact_sha256_v1() != [0; 32]
            && started.restart_parked_ack_artifact_sha256_v1() != [0; 32]
            && started.restart_parked_ack_admission_set_sha256_v1() != [0; 32]
            && started.restart_cut_statement_count_v1() == 7
            && started.restart_cut_body_v1().target_validator() == config.local_validator()
            && started.restart_cut_body_v1().target_config_sha256() == config.config_sha256()
            && started.restart_cut_body_v1().process_instance() == 1,
        "fresh process2 RestartCut/RestartPark/RestartParkedAck triple differs from the exact journal-start capability"
    );

    let state = started.restart_cut_body_v1().state();
    let prior = recovered.prior_recovery_facts_v1();
    let checkpoint = prior.checkpoint_v0();
    let checkpoint_fields = checkpoint.fields();
    let archive = recovered.archive_facts_v1();
    let replay = recovered.authenticated_replay_facts_v1();
    let process2 = recovered.process2_facts_v1();
    let replay_count = replay.authenticated_block_count_v0();
    let archive_sequence = replay_count
        .checked_mul(2)
        .context("process2 replay archive sequence overflows")?;
    let final_safety_revision = replay_count
        .checked_mul(2)
        .and_then(|delta| prior.safety_revision_v0().checked_add(delta))
        .context("process2 final safety revision overflows")?;
    let final_checkpoint_generation = checkpoint
        .generation()
        .checked_add(replay_count)
        .context("process2 final checkpoint generation overflows")?;
    let checkpoint_canonical_sha256: [u8; 32] =
        Sha256::digest(checkpoint.encode_canonical()).into();

    ensure!(
        prior.application_applied_block_id_v0() == checkpoint_fields.application_block_id
            && prior.application_applied_height_v0() == checkpoint_fields.application_height
            && prior.safety_revision_v0() == checkpoint_fields.safety_revision
            && prior.safety_state_record_checksum_v0()
                == checkpoint_fields.safety_state_record_checksum
            && prior.safety_chain_checksum_v0() == checkpoint_fields.safety_record_chain_checksum
            && prior.signer_exact_watermark_v0() == checkpoint_fields.signer_exact_watermark
            && replay.safety_revision_v0() == prior.safety_revision_v0()
            && replay.terminal_certificate_id_v0() == prior.high_qc_v0().qc_digest()
            && replay_count > 0
            && archive.sequence_v1() == archive_sequence
            && process2.replayed_link_count_v0() == replay_count
            && process2.final_safety_revision_v0() == final_safety_revision
            && process2.final_safety_chain_checksum_v0() != [0; 32]
            && process2.final_checkpoint_generation_v0() == final_checkpoint_generation
            && process2.final_checkpoint_checksum_v0() != [0; 32]
            && process2.signer_exact_watermark_v1() == prior.signer_exact_watermark_v0()
            && process2.signer_durable_vote_intent_count_v1()
                == state.signer_durable_vote_intent_count
            && process2.signer_durable_timeout_intent_count_v1()
                == state.signer_durable_timeout_intent_count
            && process2.signer_signed_vote_intent_count_v1()
                == state.signer_signed_vote_intent_count
            && process2.signer_signed_timeout_intent_count_v1()
                == state.signer_signed_timeout_intent_count
            && process2.signer_inventory_digest_v1() == state.signer_inventory_digest,
        "old recovery, external checkpoint, replay, and full process2 facts differ"
    );

    require_process2_restart_state_projection_v1(
        state,
        Process2RestartCutStateProjectionV1 {
            epoch: config.validator_set().epoch(),
            current_view: prior.current_view_v0(),
            direct_high_qc: prior.high_qc_v0(),
            proposal_parent_height: prior.high_qc_v0().height(),
            proposal_parent_block_id: prior.high_qc_v0().block_id(),
            finalized_height: Height::new(prior.finalized_height_v0()),
            finalized_block_id: prior.finalized_block_id_v0(),
            finalized_chain_root: started.restart_cut_body_v1().finalized_chain_root_v1(),
            application_height: Height::new(prior.application_applied_height_v0()),
            application_block_id: prior.application_applied_block_id_v0(),
            application_state_root: checkpoint_fields.application_state_root,
            external_checkpoint_generation: checkpoint.generation(),
            external_checkpoint_checksum: checkpoint_canonical_sha256,
            safety_revision: prior.safety_revision_v0(),
            safety_state_record_checksum: prior.safety_state_record_checksum_v0(),
            safety_record_chain_checksum: prior.safety_chain_checksum_v0(),
            signer_watermark: prior.signer_exact_watermark_v0(),
            signer_durable_vote_intent_count: process2.signer_durable_vote_intent_count_v1(),
            signer_durable_timeout_intent_count: process2.signer_durable_timeout_intent_count_v1(),
            signer_signed_vote_intent_count: process2.signer_signed_vote_intent_count_v1(),
            signer_signed_timeout_intent_count: process2.signer_signed_timeout_intent_count_v1(),
            signer_inventory_digest: process2.signer_inventory_digest_v1(),
            pending_sign: None,
            replay_archive_context_sha256: archive.context_sha256_v1(),
            replay_archive_head_sequence: archive.sequence_v1(),
            replay_archive_head_sha256: archive.record_sha256_v1(),
            runtime_journal_head_sequence: started
                .restart_cut_body_v1()
                .state()
                .runtime_journal_head_sequence,
            runtime_journal_head_sha256: started
                .restart_cut_body_v1()
                .state()
                .runtime_journal_head_sha256,
        },
    )?;
    started
        .revalidate_unchanged_start_v1()
        .map_err(|error| anyhow!("revalidate process2 journal at full-join commit: {error}"))?;
    recovered
        .revalidate_archive_identity_v1()
        .context("freshly revalidate process2 archive at full-join commit")?;
    Ok(RestartCutJoinedProcess2InertOwnerV1 { started, recovered })
}

const fn is_restart_protocol_kind_v1(kind: FrameKind) -> bool {
    matches!(
        kind,
        FrameKind::RestartPrepare
            | FrameKind::RestartCut
            | FrameKind::RestartParkedAck
            | FrameKind::RestartRecoveryReady
            | FrameKind::RestartRecoveryStart
    )
}

/// Runs one bounded seven-validator Stage0 consensus process.
///
/// `commission` must consume the already authenticated public bootstrap
/// material and return the exact native h1->h2->h3 ordinary takeover owner.
/// It is called once, inside the bounded owner thread, before the first
/// network effect.  No test fixture is reachable through this normal-build
/// boundary.
/// Normal bounded entry. The default authority remains rejecting until an
/// operator explicitly injects a separately provisioned external fence.
pub fn run_bounded_consensus_v1<C>(
    config: LoadedValidatorConfig,
    duration: Duration,
    max_blocks: u64,
    report_path: PathBuf,
    commission: C,
) -> Result<BoundedConsensusRunOutcomeV1>
where
    C: FnOnce(
            &mut LoadedValidatorConfig,
            ContinuousSignerLifetimeBoundsV0,
        ) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>>
        + Send
        + 'static,
{
    run_bounded_consensus_with_external_fence_v1(
        config,
        duration,
        max_blocks,
        report_path,
        Arc::new(RejectingExternalPeerLeaseAuthorityV1),
        commission,
    )
}

/// Explicit-injection bounded entry. The injected authority is consumed only
/// by the mesh's `establish_with_fence` gate; no default/deployed wrapper can
/// reach this path without an explicit caller argument.
pub fn run_bounded_consensus_with_external_fence_v1<C>(
    config: LoadedValidatorConfig,
    duration: Duration,
    max_blocks: u64,
    report_path: PathBuf,
    external_fence: Arc<dyn ExternalPeerLeaseAuthorityV1>,
    commission: C,
) -> Result<BoundedConsensusRunOutcomeV1>
where
    C: FnOnce(
            &mut LoadedValidatorConfig,
            ContinuousSignerLifetimeBoundsV0,
        ) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>>
        + Send
        + 'static,
{
    run_bounded_consensus_with_authority_builder_v1(
        config,
        duration,
        max_blocks,
        report_path,
        external_fence,
        commission,
        |config, takeover, signer_lifetime| {
            ContinuousValidatorAuthorityV0::from_takeover_runtime_v0(
                config,
                takeover,
                signer_lifetime,
            )
        },
    )
}

/// Explicit authority-composition entry for the bounded runtime.
///
/// The caller must provide both the external peer-lease gate and an authority
/// builder.  The builder is invoked only after the authenticated mesh is
/// established and the h1-h3 runtime has been commissioned, but before the
/// fleet Ready/Start barrier.  This is the narrow seam used to compose an
/// independently administered watermark and remote signer into the real
/// owner; the default deployed wrapper above deliberately installs the
/// fixture producer and remains a separate, closed path.
pub fn run_bounded_consensus_with_authority_builder_v1<C, A>(
    mut config: LoadedValidatorConfig,
    duration: Duration,
    max_blocks: u64,
    report_path: PathBuf,
    external_fence: Arc<dyn ExternalPeerLeaseAuthorityV1>,
    commission: C,
    authority_builder: A,
) -> Result<BoundedConsensusRunOutcomeV1>
where
    C: FnOnce(
            &mut LoadedValidatorConfig,
            ContinuousSignerLifetimeBoundsV0,
        ) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>>
        + Send
        + 'static,
    A: FnOnce(
            &LoadedValidatorConfig,
            PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>,
            ContinuousSignerLifetimeBoundsV0,
        ) -> Result<ContinuousValidatorAuthorityV0>
        + Send
        + 'static,
{
    let preflight = ConsensusRuntimePreflightV1::new(&config, duration, max_blocks, &report_path)?;
    let owner = thread::Builder::new()
        .name("trnm-g3-consensus-owner-v1".to_owned())
        .stack_size(CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0)
        .spawn(move || {
            let event_journal_path = config.run_root().join("runtime-events.jsonl");
            let mut event_journal = match RuntimeEventJournalV1::start(
                &event_journal_path,
                &config,
            ) {
                Ok(event_journal) => event_journal,
                Err(error) if error.requires_stored_restart_cut_v1() => {
                    let started = RuntimeEventJournalV1::start_process2_with_stored_restart_cut_v1(
                        &event_journal_path,
                        &config,
                    )
                    .map_err(|error| anyhow!("start authenticated process2 event journal: {error}"))?;
                    let archive = SignedReplayArchiveV1::open_existing_v1(
                        &config,
                        preflight.archive_bounds,
                    )
                    .context("open process1 signed replay archive")?;
                    let recovered = config
                        .reopen_deployed_ordinary_cut_v1()
                        .context("reopen deployed ordinary cut for archive authentication")?;
                    let authenticated = archive
                        .authenticate_recovery_v1(recovered, &config)
                        .context("authenticate process2 signed replay archive")?;
                    let recovered = authenticated
                        .recover_full_process2_inert_v1(&config)
                        .context("recover complete archive-pinned inert process2 owner")?;
                    let joined = require_process2_full_recovery_join_v1(&config, started, recovered)
                        .context(
                            "consume process2 start, RestartCut/RestartPark, and full inert recovery",
                        )?;
                    joined.record_inert_safety_halted_v1()?;
                    bail!(
                        "continuous consensus RestartCut/RestartPark/RestartParkedAck-joined process2 is inert; authenticated start-catchup, RecoveryReady, and RecoveryStart remain unavailable"
                    );
                }
                Err(error) => return Err(anyhow!("start runtime event journal: {error}")),
            };
            ensure!(
                event_journal.process_instance() == 1,
                "runtime event journal process instance is outside the bounded two-process contract"
            );
            // The archive owner exists before authenticated h1-h3
            // commissioning. Every later ordinary Proposal/QC append is
            // fsynced before its first Core/authority mutation.
            let replay_archive = SignedReplayArchiveV1::initialize_new_v1(
                &config,
                preflight.archive_bounds,
            )
            .context("initialize process1 signed replay archive")?;

            // External fencing is the first live authority gate.  Establishing
            // the authenticated mesh (and acquiring each directed lease) must
            // precede h1-h3 commissioning so a missing/stale fencing backend
            // cannot reach SafetyStore, signer, or Core mutation.
            let mesh = match PersistentAuthenticatedPeerMeshV0::establish_with_fence(
                &config,
                MESH_SETUP_TIMEOUT_V1,
                MESH_IO_TIMEOUT_V1,
                MESH_QUEUE_CAPACITY_V1,
                external_fence,
            )
            .context("establish externally fenced consensus mesh")
            {
                Ok(mesh) => mesh,
                Err(error) => {
                    let _ = event_journal.append(
                        RuntimeEventKindV1::SafetyHalted,
                        "bounded-consensus-external-fence-gate-failed",
                        0,
                    );
                    return Err(error);
                }
            };

            let commissioning_started_at = Instant::now();
            let takeover = match commission(&mut config, preflight.signer_lifetime)
                .context("commission authenticated h1-h3 ordinary runtime")
            {
                Ok(takeover) => takeover,
                Err(error) => {
                    let _ = event_journal.append(
                        RuntimeEventKindV1::SafetyHalted,
                        "bounded-consensus-commissioning-failed",
                        0,
                    );
                    return Err(error);
                }
            };
            if commissioning_started_at.elapsed()
                > Duration::from_secs(CONSENSUS_RUNTIME_COMMISSIONING_ALLOWANCE_SECONDS_V1)
            {
                let _ = event_journal.append(
                    RuntimeEventKindV1::SafetyHalted,
                    "bounded-consensus-commissioning-allowance-exhausted",
                    0,
                );
                bail!("bounded consensus commissioning allowance exhausted");
            }
            let authority = match authority_builder(&config, takeover, preflight.signer_lifetime)
            .context("bind commissioned runtime to continuous authority")
            {
                Ok(authority) => authority,
                Err(error) => {
                    let _ = event_journal.append(
                        RuntimeEventKindV1::SafetyHalted,
                        "bounded-consensus-authority-binding-failed",
                        0,
                    );
                    return Err(error);
                }
            };
            for session in mesh.initial_sessions() {
                record_peer_session_v1(&mut event_journal, *session)?;
            }
            let initial = authority.facts_v0()?;
            record_initial_application_cut_v1(&mut event_journal, initial)?;
            let mut runtime_control = RuntimeControlServerV1::bind(
                &config,
                event_journal.process_instance(),
                &event_journal,
            )
            .context("bind bounded runtime control server")?;
            write_runtime_control_status_v1(&config, &runtime_control, &event_journal)
                .context("write bounded runtime control locator")?;
            let barrier = match run_fleet_barrier_v1(
                &config,
                &authority,
                &mesh,
                &mut event_journal,
                &replay_archive,
                &mut runtime_control,
                &preflight,
            )
            .context("complete N/N fleet Ready/Start barrier")
            {
                Ok(barrier) => barrier,
                Err(error) => {
                    let _ = event_journal.append(
                        RuntimeEventKindV1::SafetyHalted,
                        "bounded-consensus-fleet-barrier-failed",
                        FLEET_BARRIER_ROUND_V1,
                    );
                    return Err(error);
                }
            };
            // Requested duration, OS measurements, pacemaker construction,
            // and ordinary ingress begin only after the complete certificate
            // has been durably re-read and FleetStarted has been fsynced.
            let os_start = RuntimeOsSampleV1::capture_v1()?;
            let mut owner = BoundedConsensusOwnerV1::new(
                config,
                authority,
                mesh,
                event_journal,
                replay_archive,
                runtime_control,
                barrier,
                preflight,
                os_start,
            )?;
            match owner.run_and_finish_v1() {
                Ok(outcome) => Ok(outcome),
                Err(error) => {
                    owner.fail_stop_v1();
                    Err(error)
                }
            }
        })
        .context("spawn bounded consensus owner thread")?;
    owner
        .join()
        .map_err(|_| anyhow!("bounded consensus owner thread panicked"))?
}

/// Normal deployed entry. The once-taken bootstrap carrier is consumed by
/// `LoadedValidatorConfig` inside the bounded owner thread.
pub fn run_deployed_bounded_consensus_v1(
    config: LoadedValidatorConfig,
    duration: Duration,
    max_blocks: u64,
    report_path: PathBuf,
) -> Result<BoundedConsensusRunOutcomeV1> {
    run_bounded_consensus_v1(
        config,
        duration,
        max_blocks,
        report_path,
        |config, _signer_lifetime| config.commission_deployed_ordinary_runtime_v1(),
    )
}

#[derive(Debug, Clone)]
struct ConsensusRuntimePreflightV1 {
    duration: Duration,
    duration_seconds: u64,
    requested_max_blocks: u64,
    target_height: u64,
    report_path: PathBuf,
    peers: Vec<ValidatorId>,
    transport: ConsensusTransportProfileV1,
    signer_lifetime: ContinuousSignerLifetimeBoundsV0,
    archive_bounds: SignedReplayArchiveBoundsV1,
    bootstrap_initial_cut: VerifiedPublicBootstrapInitialCutV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsensusTransportProfileV1 {
    Direct,
    SparseRelay { hop_budget: u8 },
}

impl ConsensusTransportProfileV1 {
    const fn relay_hop_budget_v1(self) -> Option<u8> {
        match self {
            Self::Direct => None,
            Self::SparseRelay { hop_budget } => Some(hop_budget),
        }
    }
}

impl ConsensusRuntimePreflightV1 {
    fn new(
        config: &LoadedValidatorConfig,
        duration: Duration,
        max_blocks: u64,
        report_path: &Path,
    ) -> Result<Self> {
        require_linux_runtime_metrics_v1()?;
        ensure!(
            !duration.is_zero() && duration.subsec_nanos() == 0,
            "bounded consensus duration must be positive whole seconds"
        );
        let duration_seconds = duration.as_secs();
        ensure!(
            duration_seconds <= MAX_CONSENSUS_RUN_DURATION_SECONDS_V1,
            "bounded consensus duration exceeds report profile"
        );
        ensure!(
            (MINIMUM_CONSENSUS_RUN_BLOCKS_V1..=MAX_CONSENSUS_RUN_BLOCKS_V1).contains(&max_blocks),
            "bounded consensus max_blocks cannot produce one ordinary three-chain finality"
        );
        validate_deployed_core_max_blocks_v1(max_blocks)?;
        let validator_count = config.validator_set().validators().len();
        validate_active_validator_count_v1(validator_count)?;
        let core_config = config
            .core_config()
            .context("derive deployed Core capacity preflight")?;
        validate_deployed_lab_core_record_envelope_v0(&core_config)
            .map_err(|error| anyhow!("deployed Core record envelope is invalid: {error}"))?;
        let (expected_degree, transport) = match validator_count {
            DIRECT_VALIDATOR_COUNT_V1 => {
                (DIRECT_PEER_DEGREE_V1, ConsensusTransportProfileV1::Direct)
            }
            31 | 100 => (
                SPARSE_PEER_DEGREE_V1,
                ConsensusTransportProfileV1::SparseRelay {
                    hop_budget: required_ring_relay_hops_v0(validator_count, SPARSE_PEER_DEGREE_V1)
                        .map_err(|error| anyhow!("derive sparse relay hop budget: {error}"))?,
                },
            ),
            _ => bail!("bounded consensus validator count is outside 7/31/100"),
        };
        ensure!(
            config.peers().len() == expected_degree
                && config.incoming_peers().len() == expected_degree,
            "bounded consensus peer degree differs from its frozen topology"
        );

        let outgoing = config
            .peers()
            .iter()
            .map(|peer| peer.validator_id())
            .collect::<Result<BTreeSet<_>>>()?;
        let incoming = config
            .incoming_peers()
            .iter()
            .map(|peer| peer.validator_id())
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            outgoing.len() == expected_degree
                && incoming.len() == expected_degree
                && !outgoing.contains(&config.local_validator())
                && !incoming.contains(&config.local_validator())
                && outgoing
                    .iter()
                    .chain(&incoming)
                    .all(|validator| config.validator_set().validator(*validator).is_some()),
            "bounded consensus peer inventory contains an invalid or duplicate validator"
        );
        if transport == ConsensusTransportProfileV1::Direct {
            let expected_peers = config
                .validator_set()
                .validators()
                .iter()
                .map(|validator| validator.id())
                .filter(|validator| *validator != config.local_validator())
                .collect::<BTreeSet<_>>();
            ensure!(
                outgoing == expected_peers && incoming == expected_peers,
                "seven-validator runtime peer inventory is not the exact direct mesh"
            );
        } else {
            ensure!(
                outgoing.is_disjoint(&incoming),
                "sparse relay topology contains an immediate bidirectional ring edge"
            );
        }

        let target_height = config
            .ordinary_start_height()
            .checked_add(max_blocks - 1)
            .context("bounded consensus target height overflows")?;
        ensure!(
            target_height <= config.workload_corpus().header().max_height,
            "bounded consensus target exceeds the committed workload corpus"
        );
        let signer_lifetime = ContinuousSignerLifetimeBoundsV0::from_campaign_v0(
            max_blocks,
            duration_seconds,
            TERMINAL_DRAIN_GRACE_V1.as_secs(),
            CONSENSUS_RUNTIME_TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS_V1,
            PACEMAKER_BASE_TIMEOUT_V1.as_secs(),
        )?;
        let archive_bounds = SignedReplayArchiveBoundsV1::from_signer_lifetime_v1(signer_lifetime)?;
        let bootstrap_initial_cut = config.verified_public_bootstrap_initial_cut_v1()?;
        let report_path = validate_consensus_run_report_target_v1(report_path)?;
        let metrics_path = config.run_root().join(RUNTIME_METRICS_FILE_V1);
        let final_state_path = config.run_root().join(RUNTIME_FINAL_STATE_FILE_V1);
        let fleet_certificate_path = config.run_root().join(FLEET_START_CERTIFICATE_FILE_V1);
        let fleet_certificate_next = config.run_root().join(FLEET_START_CERTIFICATE_NEXT_FILE_V1);
        ensure!(
            report_path != metrics_path
                && report_path != final_state_path
                && report_path != fleet_certificate_path
                && report_path != fleet_certificate_next,
            "consensus report target aliases required runtime evidence"
        );
        ensure!(
            !metrics_path
                .try_exists()
                .context("inspect runtime metrics target")?
                && !final_state_path
                    .try_exists()
                    .context("inspect runtime final-state target")?,
            "runtime evidence target already exists"
        );
        Ok(Self {
            duration,
            duration_seconds,
            requested_max_blocks: max_blocks,
            target_height,
            report_path,
            peers: config
                .peers()
                .iter()
                .map(|peer| peer.validator_id())
                .collect::<Result<Vec<_>>>()?,
            transport,
            signer_lifetime,
            archive_bounds,
            bootstrap_initial_cut,
        })
    }
}

fn validate_deployed_core_max_blocks_v1(max_blocks: u64) -> Result<usize> {
    let requested = usize::try_from(max_blocks).map_err(|_| {
        anyhow!("bounded consensus max_blocks exceeds the durable Core capacity envelope")
    })?;
    ensure!(
        requested <= DEPLOYED_CORE_MAX_BLOCKS_V1,
        "bounded consensus max_blocks exceeds the durable Core capacity envelope"
    );
    Ok(requested)
}

fn validate_active_validator_count_v1(validator_count: usize) -> Result<()> {
    ensure!(
        validator_count == DIRECT_VALIDATOR_COUNT_V1,
        "active bounded consensus is frozen to the direct seven-validator Stage0 profile"
    );
    Ok(())
}

fn run_fleet_barrier_v1(
    config: &LoadedValidatorConfig,
    authority: &ContinuousValidatorAuthorityV0,
    mesh: &PersistentAuthenticatedPeerMeshV0,
    event_journal: &mut RuntimeEventJournalV1,
    replay_archive: &SignedReplayArchiveV1,
    runtime_control: &mut RuntimeControlServerV1,
    preflight: &ConsensusRuntimePreflightV1,
) -> Result<CompletedFleetBarrierV1> {
    let initial_facts = authority.facts_v0()?;
    require_prestart_authority_cut_v1(initial_facts, replay_archive)?;
    let context = fleet_campaign_context_v1(config, preflight, initial_facts)?;
    let mesh_sessions = fleet_mesh_session_set_v1(config, mesh)?;
    ensure!(
        mesh_sessions.sessions().len()
            == usize::try_from(context.expected_mesh_session_count())
                .context("fleet mesh session count does not fit usize")?,
        "fleet mesh session inventory differs from campaign context"
    );
    let (pre_ready_sequence, pre_ready_sha256) = event_journal
        .last_event_facts()
        .ok_or_else(|| anyhow!("fleet Ready lacks a signed pre-Ready journal head"))?;
    let archive_facts = replay_archive.facts_v1();
    let local_cut = LocalReadyCutV1::new(
        config.local_validator(),
        config.config_sha256(),
        event_journal.process_instance(),
        pre_ready_sequence,
        pre_ready_sha256,
        &mesh_sessions,
        initial_facts.safety_record_checksum_v0(),
        initial_facts.safety_chain_checksum_v0(),
        archive_facts.context_sha256_v1(),
        archive_facts.record_sha256_v1(),
    )
    .map_err(|error| anyhow!("construct local fleet Ready cut: {error}"))?;
    let local_ready = SignedFleetReadyV1::new(
        context.clone(),
        local_cut,
        mesh_sessions,
        config.validator_set(),
        config.consensus_signing_key(),
    )
    .map_err(|error| anyhow!("sign local fleet Ready: {error}"))?;
    let mut admission =
        FleetBarrierAdmissionMapV1::new(context.clone(), config.validator_set().clone())
            .map_err(|error| anyhow!("initialize fleet barrier admission map: {error}"))?;
    ensure!(
        admission
            .admit_ready(local_ready.clone())
            .map_err(|error| anyhow!("admit local fleet Ready: {error}"))?
            == FleetBarrierAdmissionV1::New,
        "fresh fleet barrier treated local Ready as a replay"
    );
    let deadline = Instant::now()
        .checked_add(FLEET_BARRIER_TIMEOUT_V1)
        .ok_or_else(|| anyhow!("fleet barrier deadline overflows"))?;
    let mut barrier = FleetBarrierOwnerV1 {
        config,
        mesh,
        event_journal,
        runtime_control,
        preflight,
        admission,
        pending_starts: BTreeMap::new(),
        outbox: OrderedConsensusOutboxV1::new(preflight.peers.clone()),
        prestarted_ingress: VecDeque::new(),
        deadline,
    };
    barrier.enqueue_originated_v1(FrameKind::FleetReady, local_ready.encode())?;
    barrier.wait_for_ready_set_v1()?;

    let ready_set = barrier
        .admission
        .ready_set()
        .map_err(|error| anyhow!("construct N/N fleet ReadySet: {error}"))?;
    let ready_set_sha256 = ready_set.digest();
    let ready_event = barrier
        .event_journal
        .record_fleet_ready(ready_set_sha256, FLEET_BARRIER_ROUND_V1)
        .map_err(|error| anyhow!("append durable fleet Ready event: {error}"))?;
    let (ready_event_sequence, ready_event_sha256) = barrier
        .event_journal
        .last_event_facts()
        .ok_or_else(|| anyhow!("fleet Ready event lacks a durable journal head"))?;
    ensure!(
        ready_event_sequence == ready_event.sequence,
        "fleet Ready journal head differs from appended event"
    );
    barrier
        .runtime_control
        .refresh_from_journal(barrier.event_journal)
        .context("publish fleet Ready to runtime control")?;
    let local_start = SignedFleetStartV1::new(
        &local_ready,
        &ready_set,
        ready_event_sequence,
        ready_event_sha256,
        config.validator_set(),
        config.consensus_signing_key(),
    )
    .map_err(|error| anyhow!("sign local fleet Start: {error}"))?;
    ensure!(
        barrier
            .admission
            .admit_start(local_start.clone())
            .map_err(|error| anyhow!("admit local fleet Start: {error}"))?
            == FleetBarrierAdmissionV1::New,
        "fresh fleet barrier treated local Start as a replay"
    );
    barrier.enqueue_originated_v1(FrameKind::FleetStart, local_start.encode())?;
    barrier.wait_for_start_certificate_v1()?;
    barrier.drain_available_v1()?;

    let certificate = barrier
        .admission
        .start_certificate()
        .map_err(|error| anyhow!("construct N/N fleet StartCertificate: {error}"))?;
    certificate
        .verify(config.validator_set())
        .map_err(|error| anyhow!("verify N/N fleet StartCertificate: {error}"))?;
    let final_prestart_facts = authority.facts_v0()?;
    require_prestart_authority_cut_v1(final_prestart_facts, replay_archive)?;
    ensure!(
        common_chain_cut_v1(config, final_prestart_facts)? == context.initial_chain_cut(),
        "authority chain cut changed while fleet barrier was closed"
    );
    let certificate_sha256 = write_fleet_start_certificate_v1(config, &certificate)?;
    barrier.drain_available_v1()?;
    ensure!(
        barrier.outbox.is_empty() && barrier.mesh.pending_outbound_bytes_v1()? == 0,
        "fleet barrier acquired a late outbound obligation before FleetStarted"
    );
    barrier
        .event_journal
        .record_fleet_started(certificate_sha256, FLEET_BARRIER_ROUND_V1)
        .map_err(|error| anyhow!("append durable fleet Started event: {error}"))?;
    barrier
        .runtime_control
        .refresh_from_journal(barrier.event_journal)
        .context("publish fleet Started to runtime control")?;
    let observation = barrier.event_journal.observation();
    ensure!(
        observation.barrier_phase == "started"
            && observation.fleet_ready_set_sha256 == Some(ready_set_sha256)
            && observation.fleet_start_certificate_sha256 == Some(certificate_sha256),
        "durable fleet barrier observation differs from certificates"
    );
    Ok(CompletedFleetBarrierV1 {
        admission: barrier.admission,
        start_certificate: certificate,
        prestarted_ingress: barrier.prestarted_ingress,
    })
}

fn require_prestart_authority_cut_v1(
    facts: ContinuousRuntimeFactsV0,
    replay_archive: &SignedReplayArchiveV1,
) -> Result<()> {
    let archive = replay_archive.facts_v1();
    ensure!(
        facts.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready
            && facts.pending_timeout_certificate_id_v0().is_none()
            && facts.signed_vote_intents_v0() == 0
            && facts.signed_timeout_intents_v0() == 0,
        "fleet Ready requires an inert ordinary authority"
    );
    ensure!(
        archive.sequence_v1() == 0
            && archive.context_sha256_v1() != [0; 32]
            && archive.record_sha256_v1() != [0; 32],
        "fleet Ready requires the exact empty signed replay archive"
    );
    Ok(())
}

fn fleet_campaign_context_v1(
    config: &LoadedValidatorConfig,
    preflight: &ConsensusRuntimePreflightV1,
    facts: ContinuousRuntimeFactsV0,
) -> Result<CommonCampaignContextV1> {
    let authority_capacity = facts.capacity_preflight_v0();
    ensure!(
        facts.local_validator_v0() == config.local_validator()
            && authority_capacity.validator_count_v0() == config.validator_set().validators().len()
            && authority_capacity.signer_lifetime_v0() == preflight.signer_lifetime
            && authority_capacity.signer_journal_capacity_v0()
                == CONTINUOUS_RUNTIME_MAXIMUM_SIGNER_INTENTS_V0,
        "fleet campaign context differs from commissioned authority capacity"
    );
    let validator_count = u32::try_from(config.validator_set().validators().len())
        .context("fleet validator count does not fit u32")?;
    let identity = FleetCampaignIdentityV1::new(
        config.run_id().to_owned(),
        config.validator_set().chain_id(),
        *config.validator_set().genesis_hash().as_bytes(),
        *config.validator_set().id().as_bytes(),
        config.validator_set_sha256(),
        config.topology_sha256(),
        config.coordinator_manifest_sha256(),
        config.candidate_source_sha256(),
        config.binary_sha256(),
        config.workload_corpus_sha256(),
        config.workload_policy_sha256(),
        validator_count,
    )
    .map_err(|error| anyhow!("construct fleet campaign identity: {error}"))?;
    let transport = match preflight.transport {
        ConsensusTransportProfileV1::Direct => FleetBarrierTransportV1::Direct,
        ConsensusTransportProfileV1::SparseRelay { hop_budget } => {
            FleetBarrierTransportV1::SparseRelay { hop_budget }
        }
    };
    let request = FleetCampaignRequestV1::new(
        FLEET_BARRIER_ROUND_V1,
        config.ordinary_start_height(),
        preflight.duration_seconds,
        PACEMAKER_BASE_TIMEOUT_V1.as_secs(),
        TERMINAL_DRAIN_GRACE_V1.as_secs(),
        CONSENSUS_RUNTIME_TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS_V1,
        preflight.requested_max_blocks,
        preflight.target_height,
        transport,
    )
    .map_err(|error| anyhow!("construct fleet campaign request: {error}"))?;
    let maximum_consensus_message_view = facts
        .current_view_v0()
        .get()
        .checked_add(
            preflight
                .signer_lifetime
                .maximum_local_vote_intents_v0()
                .checked_sub(1)
                .context("fleet campaign has no Vote view")?,
        )
        .context("fleet maximum consensus view overflows")?;
    let relay_admission_capacity = u64::try_from(authority_capacity.relay_message_capacity_v0())
        .context("fleet relay capacity does not fit u64")?;
    let capacities = FleetCampaignCapacitiesV1::new(
        CONTINUOUS_RUNTIME_MAXIMUM_SIGNER_INTENTS_V0,
        preflight.signer_lifetime.maximum_timeout_view_advances_v0(),
        maximum_consensus_message_view,
        preflight.signer_lifetime.maximum_local_vote_intents_v0(),
        preflight.signer_lifetime.maximum_local_timeout_intents_v0(),
        preflight.signer_lifetime.maximum_total_intents_v0(),
        MAXIMUM_ENTRY_COUNT_V1,
        preflight.archive_bounds.maximum_proposal_entries_v1(),
        preflight
            .archive_bounds
            .maximum_quorum_certificate_entries_v1(),
        preflight.archive_bounds.maximum_archive_entries_v1(),
        relay_admission_capacity,
    )
    .map_err(|error| anyhow!("construct fleet campaign capacities: {error}"))?;
    CommonCampaignContextV1::new(
        identity,
        request,
        capacities,
        common_chain_cut_v1(config, facts)?,
    )
    .map_err(|error| anyhow!("construct common fleet campaign context: {error}"))
}

fn common_chain_cut_v1(
    config: &LoadedValidatorConfig,
    facts: ContinuousRuntimeFactsV0,
) -> Result<CommonChainCutV1> {
    let high_qc = facts.high_qc_v0();
    CommonChainCutV1::new(
        facts.minimum_retained_view_v0().get(),
        facts.current_view_v0().get(),
        config.validator_set().epoch().get(),
        *high_qc.qc_digest().as_bytes(),
        high_qc.view().get(),
        high_qc.height().get(),
        *high_qc.block_id().as_bytes(),
        facts.finalized_height_v0(),
        *facts.finalized_block_id_v0().as_bytes(),
        facts.application_applied_height_v0(),
        *facts.application_applied_block_id_v0().as_bytes(),
        facts.proposal_parent_height_v0(),
        *facts.proposal_parent_block_id_v0().as_bytes(),
        *facts.application_state_root_v0().as_bytes(),
        facts.safety_revision_v0(),
        facts.signer_watermark_sequence_v0(),
        facts.checkpoint_generation_v0(),
    )
    .map_err(|error| anyhow!("construct common fleet chain cut: {error}"))
}

fn fleet_mesh_session_set_v1(
    config: &LoadedValidatorConfig,
    mesh: &PersistentAuthenticatedPeerMeshV0,
) -> Result<FleetMeshSessionSetV1> {
    let sessions = mesh
        .initial_sessions()
        .iter()
        .map(|session| {
            ensure!(
                session.generation() == 1,
                "fleet Ready requires mesh generation one"
            );
            let direction = match session.direction() {
                PeerDirectionV0::Inbound => FleetMeshSessionDirectionV1::Incoming,
                PeerDirectionV0::Outbound => FleetMeshSessionDirectionV1::Outgoing,
            };
            FleetMeshSessionV1::new(direction, session.remote(), session.session_id())
                .map_err(|error| anyhow!("construct fleet mesh session: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    FleetMeshSessionSetV1::new(config.local_validator(), sessions, config.validator_set())
        .map_err(|error| anyhow!("construct fleet mesh session set: {error}"))
}

struct PendingFleetStartV1 {
    statement: SignedFleetStartV1,
    forward: Option<(ValidatorId, ConsensusRelayEnvelopeV0)>,
}

struct FleetBarrierOwnerV1<'a> {
    config: &'a LoadedValidatorConfig,
    mesh: &'a PersistentAuthenticatedPeerMeshV0,
    event_journal: &'a mut RuntimeEventJournalV1,
    runtime_control: &'a mut RuntimeControlServerV1,
    preflight: &'a ConsensusRuntimePreflightV1,
    admission: FleetBarrierAdmissionMapV1,
    pending_starts: BTreeMap<ValidatorId, PendingFleetStartV1>,
    outbox: OrderedConsensusOutboxV1,
    prestarted_ingress: VecDeque<MeshIngressEventV0>,
    deadline: Instant,
}

impl FleetBarrierOwnerV1<'_> {
    fn wait_for_ready_set_v1(&mut self) -> Result<()> {
        let validator_count = self.config.validator_set().validators().len();
        while self.admission.ready_count() != validator_count {
            self.poll_once_v1()?;
        }
        self.drain_pending_starts_v1()?;
        self.admission
            .ready_set()
            .map_err(|error| anyhow!("verify complete fleet ReadySet: {error}"))?;
        Ok(())
    }

    fn wait_for_start_certificate_v1(&mut self) -> Result<()> {
        let validator_count = self.config.validator_set().validators().len();
        while self.admission.start_count() != validator_count
            || !self.outbox.is_empty()
            || self.mesh.pending_outbound_bytes_v1()? != 0
        {
            self.poll_once_v1()?;
        }
        ensure!(
            self.pending_starts.is_empty(),
            "fleet StartCertificate completed with buffered Start statements"
        );
        Ok(())
    }

    fn poll_once_v1(&mut self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "fleet barrier timeout expired"
        );
        self.mesh.ensure_healthy()?;
        self.runtime_control
            .refresh_from_journal(self.event_journal)
            .context("refresh pre-start runtime control")?;
        let _ = self
            .runtime_control
            .poll_once(Duration::ZERO)
            .context("poll pre-start runtime control")?;
        let _ = self.outbox.flush_front_v1(self.mesh)?;
        if let Some(event) = self.mesh.receive_timeout(OWNER_POLL_INTERVAL_V1)? {
            self.handle_event_v1(event)?;
        }
        if self.admission.ready_count() == self.config.validator_set().validators().len() {
            self.drain_pending_starts_v1()?;
        }
        Ok(())
    }

    fn drain_available_v1(&mut self) -> Result<()> {
        self.mesh.ensure_healthy()?;
        while let Some(event) = self.mesh.receive_timeout(Duration::ZERO)? {
            self.handle_event_v1(event)?;
        }
        if self.admission.ready_count() == self.config.validator_set().validators().len() {
            self.drain_pending_starts_v1()?;
        }
        Ok(())
    }

    fn handle_event_v1(&mut self, event: MeshIngressEventV0) -> Result<()> {
        match event {
            MeshIngressEventV0::Frame(inbound) => match self.preflight.transport {
                ConsensusTransportProfileV1::Direct => {
                    let kind = inbound.frame().kind;
                    if matches!(kind, FrameKind::FleetReady | FrameKind::FleetStart) {
                        let origin = inbound.frame().sender;
                        let payload = inbound.frame().payload.clone();
                        self.admit_statement_v1(origin, kind, &payload, None)
                    } else if is_ordinary_consensus_frame_kind_v1(kind) {
                        self.defer_ordinary_ingress_v1(MeshIngressEventV0::Frame(inbound))
                    } else {
                        bail!("direct fleet barrier received a non-barrier transport kind")
                    }
                }
                ConsensusTransportProfileV1::SparseRelay { .. } => {
                    ensure!(
                        inbound.frame().kind == FrameKind::ConsensusRelay,
                        "sparse fleet barrier rejects direct statements"
                    );
                    let envelope = ConsensusRelayEnvelopeV0::decode(
                        &inbound.frame().payload,
                        self.config.validator_set(),
                    )
                    .map_err(|error| anyhow!("decode fleet barrier relay: {error}"))?;
                    if matches!(
                        envelope.inner_kind(),
                        FrameKind::FleetReady | FrameKind::FleetStart
                    ) {
                        self.admit_statement_v1(
                            envelope.origin(),
                            envelope.inner_kind(),
                            envelope.payload(),
                            Some((inbound.remote(), envelope.clone())),
                        )
                    } else if is_ordinary_consensus_frame_kind_v1(envelope.inner_kind()) {
                        self.defer_ordinary_ingress_v1(MeshIngressEventV0::Frame(inbound))
                    } else {
                        bail!("sparse fleet barrier relay contains a non-consensus kind")
                    }
                }
            },
            MeshIngressEventV0::SessionUnavailable(_) => {
                bail!("authenticated mesh session changed during fleet barrier")
            }
            MeshIngressEventV0::SessionReestablished(_) => {
                bail!("authenticated mesh session generation changed during fleet barrier")
            }
        }
    }

    fn admit_statement_v1(
        &mut self,
        origin: ValidatorId,
        kind: FrameKind,
        payload: &[u8],
        forward: Option<(ValidatorId, ConsensusRelayEnvelopeV0)>,
    ) -> Result<()> {
        match kind {
            FrameKind::FleetReady => {
                let statement = SignedFleetReadyV1::decode(payload, self.config.validator_set())
                    .map_err(|error| anyhow!("decode fleet Ready: {error}"))?;
                ensure!(
                    statement.origin() == origin,
                    "fleet Ready origin differs from authenticated origin"
                );
                let admission = self
                    .admission
                    .admit_ready(statement)
                    .map_err(|error| anyhow!("admit fleet Ready: {error}"))?;
                if admission == FleetBarrierAdmissionV1::New {
                    self.enqueue_forward_v1(forward)?;
                }
            }
            FrameKind::FleetStart => {
                let statement = SignedFleetStartV1::decode(payload, self.config.validator_set())
                    .map_err(|error| anyhow!("decode fleet Start: {error}"))?;
                ensure!(
                    statement.origin() == origin,
                    "fleet Start origin differs from authenticated origin"
                );
                if self.admission.ready_count() != self.config.validator_set().validators().len() {
                    self.buffer_start_v1(statement, forward)?;
                } else {
                    let admission = self
                        .admission
                        .admit_start(statement)
                        .map_err(|error| anyhow!("admit fleet Start: {error}"))?;
                    if admission == FleetBarrierAdmissionV1::New {
                        self.enqueue_forward_v1(forward)?;
                    }
                }
            }
            _ => bail!("fleet barrier statement handler received an ordinary kind"),
        }
        Ok(())
    }

    fn buffer_start_v1(
        &mut self,
        statement: SignedFleetStartV1,
        forward: Option<(ValidatorId, ConsensusRelayEnvelopeV0)>,
    ) -> Result<()> {
        let origin = statement.origin();
        if let Some(existing) = self.pending_starts.get(&origin) {
            ensure!(
                existing.statement.statement_sha256() == statement.statement_sha256(),
                "fleet Start origin equivocated before local ReadySet completion"
            );
            return Ok(());
        }
        ensure!(
            self.pending_starts.len() < self.config.validator_set().validators().len(),
            "fleet Start pending buffer exhausted"
        );
        self.pending_starts
            .insert(origin, PendingFleetStartV1 { statement, forward });
        Ok(())
    }

    fn drain_pending_starts_v1(&mut self) -> Result<()> {
        if self.admission.ready_count() != self.config.validator_set().validators().len() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending_starts);
        for (_, pending) in pending {
            let admission = self
                .admission
                .admit_start(pending.statement)
                .map_err(|error| anyhow!("admit buffered fleet Start: {error}"))?;
            if admission == FleetBarrierAdmissionV1::New {
                self.enqueue_forward_v1(pending.forward)?;
            }
        }
        Ok(())
    }

    fn enqueue_originated_v1(&mut self, kind: FrameKind, payload: Vec<u8>) -> Result<()> {
        match self.preflight.transport {
            ConsensusTransportProfileV1::Direct => self.outbox.enqueue(kind, payload),
            ConsensusTransportProfileV1::SparseRelay { hop_budget } => {
                let envelope = ConsensusRelayEnvelopeV0::new(
                    self.config.local_validator(),
                    kind,
                    hop_budget,
                    payload,
                    self.config.validator_set(),
                    self.config.consensus_signing_key(),
                )
                .map_err(|error| anyhow!("construct originated fleet barrier relay: {error}"))?;
                self.outbox
                    .enqueue(FrameKind::ConsensusRelay, envelope.encode())
            }
        }
    }

    fn enqueue_forward_v1(
        &mut self,
        forward: Option<(ValidatorId, ConsensusRelayEnvelopeV0)>,
    ) -> Result<()> {
        let Some((remote, envelope)) = forward else {
            return Ok(());
        };
        if let Some(forwarded) = envelope.forwarded() {
            self.outbox
                .enqueue_except_v1(FrameKind::ConsensusRelay, forwarded.encode(), remote)?;
        }
        Ok(())
    }

    fn defer_ordinary_ingress_v1(&mut self, event: MeshIngressEventV0) -> Result<()> {
        ensure!(
            self.prestarted_ingress.len() < MAXIMUM_PRESTART_ORDINARY_INGRESS_V1,
            "pre-Started ordinary ingress buffer exhausted"
        );
        self.prestarted_ingress.push_back(event);
        Ok(())
    }
}

fn is_ordinary_consensus_frame_kind_v1(kind: FrameKind) -> bool {
    matches!(
        kind,
        FrameKind::Proposal
            | FrameKind::Vote
            | FrameKind::TimeoutVote
            | FrameKind::QuorumCertificate
            | FrameKind::TimeoutCertificate
    )
}

fn write_fleet_start_certificate_v1(
    config: &LoadedValidatorConfig,
    certificate: &FleetStartCertificateV1,
) -> Result<[u8; 32]> {
    let bytes = certificate.encode();
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FLEET_START_CERTIFICATE_BYTES_V1,
        "fleet StartCertificate crosses its durable bound"
    );
    let root_metadata = fs::metadata(config.run_root()).context("stat fleet certificate root")?;
    ensure!(
        root_metadata.is_dir() && root_metadata.permissions().mode() & 0o777 == 0o700,
        "fleet certificate root is not one private directory"
    );
    let target = config.run_root().join(FLEET_START_CERTIFICATE_FILE_V1);
    let next = config.run_root().join(FLEET_START_CERTIFICATE_NEXT_FILE_V1);
    for candidate in [&target, &next] {
        match fs::symlink_metadata(candidate) {
            Ok(_) => bail!(
                "fleet StartCertificate target/sidecar already exists: {}",
                candidate.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect fleet certificate target {}", candidate.display())
                })
            }
        }
    }
    let directory = File::open(config.run_root()).context("open fleet certificate root")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&next)
        .context("create fleet StartCertificate sidecar")?;
    file.write_all(&bytes)
        .context("write fleet StartCertificate sidecar")?;
    file.sync_all()
        .context("sync fleet StartCertificate sidecar")?;
    let next_metadata = file
        .metadata()
        .context("stat fleet StartCertificate sidecar")?;
    ensure!(
        next_metadata.is_file()
            && next_metadata.permissions().mode() & 0o777 == 0o600
            && next_metadata.nlink() == 1
            && next_metadata.uid() == root_metadata.uid()
            && next_metadata.len() == u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        "fleet StartCertificate sidecar identity differs"
    );
    drop(file);
    fs::hard_link(&next, &target).context("publish fleet StartCertificate without replacement")?;
    directory
        .sync_all()
        .context("sync published fleet StartCertificate parent")?;
    fs::remove_file(&next).context("remove published fleet StartCertificate sidecar")?;
    directory
        .sync_all()
        .context("sync fleet StartCertificate parent after sidecar removal")?;
    let mut readback = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&target)
        .context("open published fleet StartCertificate")?;
    let metadata = readback
        .metadata()
        .context("stat published fleet StartCertificate")?;
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == root_metadata.uid()
            && metadata.len() == u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        "published fleet StartCertificate identity differs"
    );
    let mut observed = Vec::with_capacity(bytes.len());
    readback
        .read_to_end(&mut observed)
        .context("read published fleet StartCertificate")?;
    ensure!(
        observed == bytes,
        "published fleet StartCertificate bytes differ"
    );
    let decoded = FleetStartCertificateV1::decode(&observed, config.validator_set())
        .map_err(|error| anyhow!("decode published fleet StartCertificate: {error}"))?;
    ensure!(
        decoded == *certificate && decoded.encode() == observed,
        "published fleet StartCertificate fresh verification differs"
    );
    let expected_sha256 = Sha256::digest(&bytes);
    let observed_sha256 = Sha256::digest(&observed);
    ensure!(
        expected_sha256 == observed_sha256,
        "published fleet StartCertificate content address differs"
    );
    Ok(expected_sha256.into())
}

struct BoundedConsensusOwnerV1 {
    config: LoadedValidatorConfig,
    authority: Option<ContinuousValidatorAuthorityV0>,
    mesh: Option<PersistentAuthenticatedPeerMeshV0>,
    event_journal: RuntimeEventJournalV1,
    replay_archive: SignedReplayArchiveV1,
    runtime_control: Option<RuntimeControlServerV1>,
    fleet_barrier: FleetBarrierAdmissionMapV1,
    fleet_start_certificate: FleetStartCertificateV1,
    restart_ingress: BoundedRestartProtocolIngressV1,
    restart_relay_window: RestartRelayAdmissionWindowV1,
    restart_round: RestartCutRoundV1,
    prestarted_ingress: VecDeque<MeshIngressEventV0>,
    active_connectivity_fault: Option<ObservedConnectivityFaultV1>,
    pacemaker: GenerationAwarePacemakerV0,
    outbox: OrderedConsensusOutboxV1,
    pending_proposals: PendingProposalBufferV1,
    pending_certificates: VecDeque<PendingCertificateV1>,
    known_executions: BTreeSet<(u64, [u8; 32])>,
    proposal_first_seen: BTreeMap<[u8; 32], (u64, Instant)>,
    finality_samples_ms: Vec<f64>,
    applied_qcs: BTreeSet<[u8; 32]>,
    applied_tcs: BTreeSet<[u8; 32]>,
    local_proposal_views: BTreeSet<u64>,
    unavailable_sessions: BTreeSet<(PeerDirectionV0, ValidatorId)>,
    highest_submitted_height: u64,
    post_timeout_rebase_required_finalized_height: Option<u64>,
    initial_consensus_view: u64,
    maximum_archivable_view: u64,
    started_at: Instant,
    nominal_deadline: Instant,
    stopping_since: Option<Instant>,
    terminal_candidate_since: Option<Instant>,
    restart_lifecycle: RestartLifecycleV1,
    prepared_normal_frame_drop_count: u64,
    os_start: RuntimeOsSampleV1,
    network_tx_bytes: u64,
    network_rx_bytes: u64,
    preflight: ConsensusRuntimePreflightV1,
}

struct CompletedFleetBarrierV1 {
    admission: FleetBarrierAdmissionMapV1,
    start_certificate: FleetStartCertificateV1,
    prestarted_ingress: VecDeque<MeshIngressEventV0>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedConnectivityFaultV1 {
    fault: crate::process_event::RuntimeFaultV1,
    remote: ValidatorId,
    applied_finalized_height: u64,
}

#[derive(Debug)]
enum RestartLifecycleV1 {
    Running,
    TargetQuiescing(RuntimeRestartPrepareIntentV1),
    TargetCollecting(LocalRestartTargetCollectingOwnerV1),
    PeerQuiescing(LocalRestartPeerQuiescingOwnerV1),
    PeerCollecting(LocalRestartPeerCollectingOwnerV1),
    PeerBarrier(LocalRestartPeerBarrierOwnerV1),
    PeerParked(LocalRestartPeerParkedOwnerV1),
    PeerAckCollecting(LocalRestartPeerAckCollectingOwnerV1),
    PeerAcked(LocalRestartPeerAckedOwnerV1),
    TargetBarrier(LocalRestartTargetBarrierOwnerV1),
    TargetParked(LocalRestartTargetParkedOwnerV1),
    TargetAckCollecting(LocalRestartTargetAckCollectingOwnerV1),
    TargetAcked(LocalRestartTargetAckedOwnerV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedConsensusLoopOutcomeV1 {
    NormalTerminal,
    Process1TargetParked,
}

impl RestartLifecycleV1 {
    const fn allows_local_proposal_v1(&self) -> bool {
        matches!(self, Self::Running)
    }

    const fn allows_authenticated_drain_v1(&self) -> bool {
        true
    }

    const fn is_running_v1(&self) -> bool {
        matches!(self, Self::Running)
    }

    const fn selects_process1_target_handoff_v1(&self) -> bool {
        matches!(self, Self::TargetAcked(_))
    }

    const fn is_prepared_v1(&self) -> bool {
        matches!(
            self,
            Self::TargetCollecting(_)
                | Self::PeerCollecting(_)
                | Self::PeerBarrier(_)
                | Self::PeerParked(_)
                | Self::PeerAckCollecting(_)
                | Self::PeerAcked(_)
                | Self::TargetBarrier(_)
                | Self::TargetParked(_)
                | Self::TargetAckCollecting(_)
                | Self::TargetAcked(_)
        )
    }

    const fn intent_v1(&self) -> Option<RuntimeRestartPrepareIntentV1> {
        match self {
            Self::Running
            | Self::PeerQuiescing(_)
            | Self::PeerCollecting(_)
            | Self::PeerBarrier(_)
            | Self::PeerParked(_)
            | Self::PeerAckCollecting(_)
            | Self::PeerAcked(_) => None,
            Self::TargetQuiescing(intent) => Some(*intent),
            Self::TargetCollecting(owner) => Some(owner.prepared.prepared.facts.intent),
            Self::TargetBarrier(owner) => Some(owner.prepared.prepared.facts.intent),
            Self::TargetParked(owner) => Some(owner.prepared.prepared.facts.intent),
            Self::TargetAckCollecting(owner) => Some(owner.prepared.prepared.facts.intent),
            Self::TargetAcked(owner) => Some(owner.prepared.prepared.facts.intent),
        }
    }
}

#[derive(Debug, Default)]
struct RestartCutRoundV1 {
    admitted_statements: BTreeMap<ValidatorId, AdmittedRestartCutParkV1>,
    pending_parked_acks: BTreeMap<ValidatorId, AdmittedRestartProtocolMessageV1>,
    admitted_parked_acks: BTreeMap<ValidatorId, AdmittedRestartParkedAckV1>,
}

#[must_use]
struct LocalRestartTargetCollectingOwnerV1 {
    prepared: LocalRestartTargetPreparedOwnerV1,
    originated_prepare: OriginatedRestartPrepareV1,
    originated_cut_park: OriginatedRestartCutParkV1,
}

impl std::fmt::Debug for LocalRestartTargetCollectingOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartTargetCollectingOwnerV1")
            .field("prepared", &self.prepared)
            .finish_non_exhaustive()
    }
}

/// A peer retains the sole authenticated target Prepare while ordinary
/// authenticated obligations drain. There is intentionally no signing
/// method here: a later typed journal writer must consume this owner into a
/// durable peer-park-prepare successor before parking can issue a dual Cut.
#[must_use]
#[derive(Debug)]
struct LocalRestartPeerQuiescingOwnerV1 {
    admitted_prepare: AdmittedRestartPrepareV1,
}

/// Linear proof that a peer reached the target's exact shared cut with no
/// outstanding ordinary obligation, but has not yet made its durable local
/// park marker.  It owns the sole admitted target Prepare and therefore
/// cannot be reconstructed from scalar journal fields.
#[must_use]
pub(crate) struct LocalRestartPeerQuiescedOwnerV1 {
    admitted_prepare: AdmittedRestartPrepareV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_state: RestartCutStateV1,
    journal_predecessor: (u64, [u8; 32]),
}

impl std::fmt::Debug for LocalRestartPeerQuiescedOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartPeerQuiescedOwnerV1")
            .field("local_validator", &self.local_validator)
            .field(
                "target_validator",
                &self.admitted_prepare.body_v1().target_validator(),
            )
            .field("journal_predecessor", &self.journal_predecessor)
            .finish_non_exhaustive()
    }
}

impl LocalRestartPeerQuiescedOwnerV1 {
    #[cfg(test)]
    pub(crate) fn from_admitted_prepare_for_journal_test_v1(
        admitted_prepare: AdmittedRestartPrepareV1,
        local_validator: ValidatorId,
        local_config_sha256: [u8; 32],
        local_state: RestartCutStateV1,
        journal_predecessor: (u64, [u8; 32]),
    ) -> Result<Self> {
        ensure!(
            local_validator != admitted_prepare.body_v1().target_validator()
                && local_config_sha256 != [0; 32]
                && admitted_prepare.body_v1().process_instance() == 1
                && RestartSharedCutV1::from_state(local_state)
                    == admitted_prepare.body_v1().shared_cut_v1()
                && (
                    local_state.runtime_journal_head_sequence,
                    local_state.runtime_journal_head_sha256,
                ) == journal_predecessor,
            "test peer quiesced owner lacks its exact Prepare/shared-cut/journal relation"
        );
        Ok(Self {
            admitted_prepare,
            local_validator,
            local_config_sha256,
            local_state,
            journal_predecessor,
        })
    }

    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.local_validator
    }

    pub(crate) const fn local_config_sha256_v1(&self) -> [u8; 32] {
        self.local_config_sha256
    }

    pub(crate) const fn process_instance_v1(&self) -> u64 {
        self.admitted_prepare.body_v1().process_instance()
    }

    pub(crate) const fn target_validator_v1(&self) -> ValidatorId {
        self.admitted_prepare.body_v1().target_validator()
    }

    pub(crate) fn body_sha256_v1(&self) -> [u8; 32] {
        self.admitted_prepare.body_v1().digest()
    }

    pub(crate) fn prepare_message_id_v1(&self) -> [u8; 32] {
        self.admitted_prepare.message_id_v1()
    }

    pub(crate) const fn shared_cut_height_v1(&self) -> u64 {
        self.admitted_prepare
            .body_v1()
            .shared_cut_v1()
            .finalized_height()
            .get()
    }

    pub(crate) const fn journal_predecessor_v1(&self) -> (u64, [u8; 32]) {
        self.journal_predecessor
    }

    fn into_prepared_v1(
        mut self,
        journal_event_sequence: u64,
        journal_event_sha256: [u8; 32],
    ) -> Result<LocalRestartPeerPreparedOwnerV1> {
        ensure!(
            journal_event_sequence
                == self
                    .journal_predecessor
                    .0
                    .checked_add(1)
                    .context("peer park-prepare journal sequence overflows")?
                && journal_event_sha256 != [0; 32],
            "peer park-prepare journal successor differs from its quiesced owner"
        );
        self.local_state.runtime_journal_head_sequence = journal_event_sequence;
        self.local_state.runtime_journal_head_sha256 = journal_event_sha256;
        Ok(LocalRestartPeerPreparedOwnerV1 {
            admitted_prepare: self.admitted_prepare,
            local_validator: self.local_validator,
            local_config_sha256: self.local_config_sha256,
            local_state: self.local_state,
            journal_successor: (journal_event_sequence, journal_event_sha256),
        })
    }

    #[cfg(test)]
    pub(crate) fn into_local_state_for_journal_test_v1(
        self,
        journal_event_sequence: u64,
        journal_event_sha256: [u8; 32],
    ) -> Result<RestartCutStateV1> {
        self.into_prepared_v1(journal_event_sequence, journal_event_sha256)
            .map(|prepared| prepared.local_state)
    }

    #[cfg(test)]
    pub(crate) fn into_barrier_parts_for_journal_test_v1(
        self,
        journal_event_sequence: u64,
        journal_event_sha256: [u8; 32],
    ) -> Result<(
        LocalRestartPeerJournalPreparedOwnerV1,
        AdmittedRestartPrepareV1,
    )> {
        self.into_prepared_v1(journal_event_sequence, journal_event_sha256)
            .map(LocalRestartPeerPreparedOwnerV1::into_barrier_parts_v1)
    }
}

#[must_use]
struct LocalRestartPeerPreparedOwnerV1 {
    admitted_prepare: AdmittedRestartPrepareV1,
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_state: RestartCutStateV1,
    journal_successor: (u64, [u8; 32]),
}

impl LocalRestartPeerPreparedOwnerV1 {
    fn into_barrier_parts_v1(
        self,
    ) -> (
        LocalRestartPeerJournalPreparedOwnerV1,
        AdmittedRestartPrepareV1,
    ) {
        let target_prepare = self.admitted_prepare.declaration_v1().clone();
        let prepare_message_id = self.admitted_prepare.message_id_v1();
        (
            LocalRestartPeerJournalPreparedOwnerV1 {
                target_prepare,
                prepare_message_id,
                local_validator: self.local_validator,
                local_config_sha256: self.local_config_sha256,
                local_state: self.local_state,
                journal_successor: self.journal_successor,
            },
            self.admitted_prepare,
        )
    }
}

impl std::fmt::Debug for LocalRestartPeerPreparedOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartPeerPreparedOwnerV1")
            .field("local_validator", &self.local_validator)
            .field(
                "target_validator",
                &self.admitted_prepare.body_v1().target_validator(),
            )
            .field("journal_successor", &self.journal_successor)
            .finish_non_exhaustive()
    }
}

/// Inert peer-local predecessor retained after the non-Clone Prepare
/// admission has been consumed into the seven-way barrier. It contains only
/// authenticated signed data and the exact durable marker facts needed by
/// the later store-to-journal join.
#[must_use]
pub(crate) struct LocalRestartPeerJournalPreparedOwnerV1 {
    target_prepare: SignedRestartCutV1,
    prepare_message_id: [u8; 32],
    local_validator: ValidatorId,
    local_config_sha256: [u8; 32],
    local_state: RestartCutStateV1,
    journal_successor: (u64, [u8; 32]),
}

impl LocalRestartPeerJournalPreparedOwnerV1 {
    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.local_validator
    }

    pub(crate) const fn local_config_sha256_v1(&self) -> [u8; 32] {
        self.local_config_sha256
    }

    pub(crate) const fn target_prepare_v1(&self) -> &SignedRestartCutV1 {
        &self.target_prepare
    }

    pub(crate) const fn prepare_message_id_v1(&self) -> [u8; 32] {
        self.prepare_message_id
    }

    pub(crate) const fn local_state_v1(&self) -> RestartCutStateV1 {
        self.local_state
    }

    pub(crate) const fn journal_successor_v1(&self) -> (u64, [u8; 32]) {
        self.journal_successor
    }
}

impl std::fmt::Debug for LocalRestartPeerJournalPreparedOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartPeerJournalPreparedOwnerV1")
            .field("local_validator", &self.local_validator)
            .field(
                "target_validator",
                &self.target_prepare.body().target_validator(),
            )
            .field("journal_successor", &self.journal_successor)
            .finish_non_exhaustive()
    }
}

#[must_use]
struct LocalRestartPeerCollectingOwnerV1 {
    prepared: LocalRestartPeerPreparedOwnerV1,
    originated_cut_park: OriginatedRestartCutParkV1,
}

#[must_use]
struct LocalRestartPeerBarrierOwnerV1 {
    prepared: LocalRestartPeerJournalPreparedOwnerV1,
    barrier: VerifiedRestartCutParkCertificatesV1,
}

#[must_use]
struct LocalRestartPeerParkedOwnerV1 {
    prepared: LocalRestartPeerJournalPreparedOwnerV1,
    parked: DurablyParkedPeerRestartOwnerV1,
    journal_commit: LocalRestartParkJournalCommitV1,
}

#[must_use]
struct LocalRestartPeerAckCollectingOwnerV1 {
    prepared: LocalRestartPeerJournalPreparedOwnerV1,
    originated_ack: OriginatedRestartParkedAckV1,
}

#[must_use]
struct LocalRestartPeerAckedOwnerV1 {
    prepared: LocalRestartPeerJournalPreparedOwnerV1,
    acknowledged: DurablyAcknowledgedRestartParkedBarrierV1,
}

impl std::fmt::Debug for LocalRestartPeerCollectingOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartPeerCollectingOwnerV1")
            .field("prepared", &self.prepared)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalRestartPeerBarrierOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartPeerBarrierOwnerV1")
            .field("prepared", &self.prepared)
            .field("barrier", &self.barrier)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalRestartPeerParkedOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartPeerParkedOwnerV1")
            .field("prepared", &self.prepared)
            .field("parked", &self.parked)
            .field("journal_commit", &self.journal_commit)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalRestartPeerAckCollectingOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartPeerAckCollectingOwnerV1")
            .field("prepared", &self.prepared)
            .field("originated_ack", &self.originated_ack)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalRestartPeerAckedOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartPeerAckedOwnerV1")
            .field("prepared", &self.prepared)
            .field("acknowledged", &self.acknowledged)
            .finish_non_exhaustive()
    }
}

#[must_use]
struct LocalRestartTargetBarrierOwnerV1 {
    prepared: LocalRestartTargetPreparedOwnerV1,
    barrier: VerifiedRestartCutParkCertificatesV1,
}

#[must_use]
struct LocalRestartTargetParkedOwnerV1 {
    prepared: LocalRestartTargetPreparedOwnerV1,
    parked: DurablyParkedTargetRestartOwnerV1,
    journal_commit: LocalRestartParkJournalCommitV1,
}

#[must_use]
struct LocalRestartTargetAckCollectingOwnerV1 {
    prepared: LocalRestartTargetPreparedOwnerV1,
    originated_ack: OriginatedRestartParkedAckV1,
}

#[must_use]
struct LocalRestartTargetAckedOwnerV1 {
    prepared: LocalRestartTargetPreparedOwnerV1,
    acknowledged: DurablyAcknowledgedRestartParkedBarrierV1,
}

impl std::fmt::Debug for LocalRestartTargetParkedOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartTargetParkedOwnerV1")
            .field("prepared", &self.prepared)
            .field("parked", &self.parked)
            .field("journal_commit", &self.journal_commit)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalRestartTargetAckCollectingOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartTargetAckCollectingOwnerV1")
            .field("prepared", &self.prepared)
            .field("originated_ack", &self.originated_ack)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalRestartTargetAckedOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartTargetAckedOwnerV1")
            .field("prepared", &self.prepared)
            .field("acknowledged", &self.acknowledged)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalRestartTargetBarrierOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartTargetBarrierOwnerV1")
            .field("prepared", &self.prepared)
            .field("barrier", &self.barrier)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartQuiescenceSnapshotV1 {
    restart_requested: bool,
    restart_intent_generation: u64,
    restart_intent_nonce: u64,
    restart_intent_request_sha256: [u8; 32],
    normal_stop_in_progress: bool,
    process_instance: u64,
    local_validator: ValidatorId,
    authority_phase: PocoNodeLabAuthorityPhaseV0,
    pending_timeout_certificate: bool,
    outbox_frame_count: usize,
    outbox_payload_bytes: usize,
    pending_proposal_count: usize,
    pending_certificate_count: usize,
    prestarted_ingress_count: usize,
    unavailable_session_count: usize,
    mesh_pending_outbound_bytes: usize,
    post_timeout_rebase_pending: bool,
    active_connectivity_fault: bool,
    expected_control_fault: bool,
    active_journal_fault_count: usize,
    journal_restart_prepare_absent: bool,
    journal_restart_pending_catchup: bool,
    journal_restart_completed: bool,
    journal_final_tip_recorded: bool,
    journal_clean_stop_recorded: bool,
    journal_safety_halted: bool,
    ordinary_start_height: u64,
    current_view: View,
    high_qc: QcRef,
    finalized_height: u64,
    finalized_block_id: BlockId,
    finalized_chain_root: [u8; 32],
    application_height: u64,
    application_block_id: BlockId,
    application_state_root: [u8; 32],
    proposal_parent_height: u64,
    proposal_parent_block_id: BlockId,
    signed_vote_intents: u64,
    signed_timeout_intents: u64,
    signer_durable_vote_intent_count: u64,
    signer_durable_timeout_intent_count: u64,
    signer_signed_vote_intent_count: u64,
    signer_signed_timeout_intent_count: u64,
    signer_inventory_digest: [u8; 32],
    authenticated_signer_inventory_digest: [u8; 32],
    signer_exact_watermark: Option<SignerWatermarkV0>,
    checkpoint_signer_exact_watermark: Option<SignerWatermarkV0>,
    safety_revision: u64,
    safety_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signer_watermark_sequence: u64,
    checkpoint_generation: u64,
    checkpoint_canonical_sha256: [u8; 32],
    runtime_checkpoint_canonical_sha256: [u8; 32],
    replay_archive_context_sha256: [u8; 32],
    replay_archive_head_sequence: u64,
    replay_archive_head_sha256: [u8; 32],
    journal_head_sequence: u64,
    journal_head_sha256: [u8; 32],
    journal_next_sequence: u64,
    journal_finalized_height: u64,
    journal_application_height: u64,
}

/// Pure fail-closed common predicate for one obligation-free restart park.
/// Target control intent is deliberately excluded so a peer can establish
/// the same local cut from an authenticated target Prepare without inventing
/// a local control request.
fn is_restart_common_quiescent_v1(snapshot: &RestartQuiescenceSnapshotV1) -> bool {
    let (Some(signer_exact_watermark), Some(checkpoint_signer_exact_watermark)) = (
        snapshot.signer_exact_watermark,
        snapshot.checkpoint_signer_exact_watermark,
    ) else {
        return false;
    };
    let Some(expected_current_view) = snapshot.high_qc.view().get().checked_add(1) else {
        return false;
    };
    let Some(signed_intent_count) = snapshot
        .signer_signed_vote_intent_count
        .checked_add(snapshot.signer_signed_timeout_intent_count)
    else {
        return false;
    };
    let Some(expected_signer_watermark_sequence) = signed_intent_count.checked_mul(2) else {
        return false;
    };
    let Some(expected_journal_next_sequence) = snapshot.journal_head_sequence.checked_add(1) else {
        return false;
    };
    !snapshot.normal_stop_in_progress
        && snapshot.process_instance == 1
        && !snapshot.local_validator.is_zero()
        && snapshot.authority_phase == PocoNodeLabAuthorityPhaseV0::Ready
        && !snapshot.pending_timeout_certificate
        && snapshot.outbox_frame_count == 0
        && snapshot.outbox_payload_bytes == 0
        && snapshot.pending_proposal_count == 0
        && snapshot.pending_certificate_count == 0
        && snapshot.prestarted_ingress_count == 0
        && snapshot.unavailable_session_count == 0
        && snapshot.mesh_pending_outbound_bytes == 0
        && !snapshot.post_timeout_rebase_pending
        && !snapshot.active_connectivity_fault
        && !snapshot.expected_control_fault
        && snapshot.active_journal_fault_count == 0
        && snapshot.journal_restart_prepare_absent
        && !snapshot.journal_restart_pending_catchup
        && !snapshot.journal_restart_completed
        && !snapshot.journal_final_tip_recorded
        && !snapshot.journal_clean_stop_recorded
        && !snapshot.journal_safety_halted
        && snapshot.ordinary_start_height > 0
        && snapshot.current_view.get() == expected_current_view
        && !snapshot.high_qc.qc_digest().is_zero()
        && !snapshot.high_qc.block_id().is_zero()
        && !snapshot.high_qc.validator_set_id().is_zero()
        && snapshot.finalized_height >= snapshot.ordinary_start_height
        && snapshot.high_qc.height().get() >= snapshot.finalized_height
        && snapshot.proposal_parent_height == snapshot.high_qc.height().get()
        && snapshot.proposal_parent_block_id == snapshot.high_qc.block_id()
        && !snapshot.finalized_block_id.is_zero()
        && snapshot.finalized_chain_root != [0; 32]
        && snapshot.application_height == snapshot.finalized_height
        && snapshot.application_block_id == snapshot.finalized_block_id
        && snapshot.application_state_root != [0; 32]
        && signed_intent_count > 0
        && snapshot.signer_durable_vote_intent_count == snapshot.signer_signed_vote_intent_count
        && snapshot.signer_durable_timeout_intent_count
            == snapshot.signer_signed_timeout_intent_count
        && snapshot.signer_signed_vote_intent_count == snapshot.signed_vote_intents
        && snapshot.signer_signed_timeout_intent_count == snapshot.signed_timeout_intents
        && snapshot.signer_inventory_digest != [0; 32]
        && snapshot.signer_inventory_digest == snapshot.authenticated_signer_inventory_digest
        && signer_exact_watermark == checkpoint_signer_exact_watermark
        && signer_exact_watermark.scope() != [0; 32]
        && signer_exact_watermark.journal_id() != [0; 32]
        && signer_exact_watermark.chain_checksum() != [0; 32]
        && signer_exact_watermark.sequence() == expected_signer_watermark_sequence
        && snapshot.signer_watermark_sequence == expected_signer_watermark_sequence
        && snapshot.safety_revision > 0
        && snapshot.safety_record_checksum != [0; 32]
        && snapshot.safety_chain_checksum != [0; 32]
        && snapshot.checkpoint_generation > 0
        && snapshot.checkpoint_canonical_sha256 != [0; 32]
        && snapshot.checkpoint_canonical_sha256 == snapshot.runtime_checkpoint_canonical_sha256
        && snapshot.replay_archive_context_sha256 != [0; 32]
        && snapshot.replay_archive_head_sequence > 0
        && snapshot.replay_archive_head_sha256 != [0; 32]
        && snapshot.journal_head_sequence > 0
        && snapshot.journal_head_sha256 != [0; 32]
        && snapshot.journal_next_sequence == expected_journal_next_sequence
        && snapshot.journal_finalized_height == snapshot.finalized_height
        && snapshot.journal_application_height == snapshot.application_height
}

/// Target-only extension of the common quiescence predicate. A Ready
/// continuous authority has no resident PendingFinalization owner: certificate
/// admission synchronously drains every such linear owner before restoring
/// the Ready phase. The separate certificate queue check covers work not yet
/// admitted to that authority.
fn is_restart_quiescent_v1(snapshot: &RestartQuiescenceSnapshotV1) -> bool {
    snapshot.restart_requested
        && snapshot.restart_intent_generation > 0
        && snapshot.restart_intent_nonce > 0
        && snapshot.restart_intent_request_sha256 != [0; 32]
        && is_restart_common_quiescent_v1(snapshot)
}

/// A peer below the advertised cut may continue draining already
/// authenticated work. Equality is the only successful outcome; an ahead or
/// same-height-different projection is a fail-closed fork/overshoot.
fn peer_restart_shared_cut_ready_v1(
    snapshot: &RestartQuiescenceSnapshotV1,
    shared_cut: RestartSharedCutV1,
) -> Result<bool> {
    let target_height = shared_cut.finalized_height().get();
    if snapshot.finalized_height < target_height
        && snapshot.application_height < shared_cut.application_height().get()
    {
        return Ok(false);
    }
    ensure!(
        snapshot.finalized_height == target_height
            && snapshot.application_height == shared_cut.application_height().get()
            && snapshot.finalized_block_id == shared_cut.finalized_block_id()
            && snapshot.finalized_chain_root == shared_cut.finalized_chain_root()
            && snapshot.application_block_id == shared_cut.application_block_id()
            && snapshot.application_state_root == *shared_cut.application_state_root().as_bytes(),
        "peer local finalized/application projection is ahead of or differs from the target shared cut"
    );
    Ok(true)
}

fn restart_cut_state_from_quiescent_snapshot_v1(
    snapshot: RestartQuiescenceSnapshotV1,
    epoch: Epoch,
    journal_head: (u64, [u8; 32]),
) -> Result<RestartCutStateV1> {
    let signer_watermark = snapshot
        .signer_exact_watermark
        .ok_or_else(|| anyhow!("quiescent restart state lacks an exact signer watermark"))?;
    ensure!(
        journal_head.0 > 0
            && journal_head.1 != [0; 32]
            && !snapshot.pending_timeout_certificate
            && snapshot.signer_inventory_digest != [0; 32],
        "quiescent restart state lacks its durable journal or signer identity"
    );
    Ok(RestartCutStateV1 {
        epoch,
        current_view: snapshot.current_view,
        direct_high_qc: snapshot.high_qc,
        proposal_parent_height: Height::new(snapshot.proposal_parent_height),
        proposal_parent_block_id: snapshot.proposal_parent_block_id,
        finalized_height: Height::new(snapshot.finalized_height),
        finalized_block_id: snapshot.finalized_block_id,
        finalized_chain_root: snapshot.finalized_chain_root,
        application_height: Height::new(snapshot.application_height),
        application_block_id: snapshot.application_block_id,
        application_state_root: StateRoot::new(snapshot.application_state_root),
        external_checkpoint_generation: snapshot.checkpoint_generation,
        external_checkpoint_checksum: snapshot.checkpoint_canonical_sha256,
        safety_revision: snapshot.safety_revision,
        safety_state_record_checksum: snapshot.safety_record_checksum,
        safety_record_chain_checksum: snapshot.safety_chain_checksum,
        signer_watermark,
        signer_durable_vote_intent_count: snapshot.signer_durable_vote_intent_count,
        signer_durable_timeout_intent_count: snapshot.signer_durable_timeout_intent_count,
        signer_signed_vote_intent_count: snapshot.signer_signed_vote_intent_count,
        signer_signed_timeout_intent_count: snapshot.signer_signed_timeout_intent_count,
        signer_inventory_digest: snapshot.signer_inventory_digest,
        pending_sign: None,
        replay_archive_context_sha256: snapshot.replay_archive_context_sha256,
        replay_archive_head_sequence: snapshot.replay_archive_head_sequence,
        replay_archive_head_sha256: snapshot.replay_archive_head_sha256,
        runtime_journal_head_sequence: journal_head.0,
        runtime_journal_head_sha256: journal_head.1,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalRestartQuiescedFactsV1 {
    intent: RuntimeRestartPrepareIntentV1,
    local_validator: ValidatorId,
    current_view: View,
    high_qc: QcRef,
    finalized_height: u64,
    finalized_block_id: BlockId,
    finalized_chain_root: [u8; 32],
    application_height: u64,
    application_block_id: BlockId,
    application_state_root: [u8; 32],
    proposal_parent_height: u64,
    proposal_parent_block_id: BlockId,
    signed_vote_intents: u64,
    signed_timeout_intents: u64,
    signer_durable_vote_intent_count: u64,
    signer_durable_timeout_intent_count: u64,
    signer_signed_vote_intent_count: u64,
    signer_signed_timeout_intent_count: u64,
    signer_inventory_digest: [u8; 32],
    signer_exact_watermark: SignerWatermarkV0,
    safety_revision: u64,
    safety_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signer_watermark_sequence: u64,
    checkpoint_generation: u64,
    checkpoint_canonical_sha256: [u8; 32],
    replay_archive_context_sha256: [u8; 32],
    replay_archive_head_sequence: u64,
    replay_archive_head_sha256: [u8; 32],
    journal_predecessor_sequence: u64,
    journal_predecessor_sha256: [u8; 32],
}

/// Linear local authority proving that the runtime, not the control caller,
/// observed one strict quiescent cut. It owns no RestartCut signature or
/// process-control authority.
#[must_use]
#[derive(Debug)]
pub(crate) struct LocalRestartQuiescedOwnerV1 {
    facts: LocalRestartQuiescedFactsV1,
}

impl LocalRestartQuiescedOwnerV1 {
    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.facts.local_validator
    }

    pub(crate) const fn process_instance_v1(&self) -> u64 {
        self.facts.intent.process_instance_v1()
    }

    pub(crate) const fn nonce_v1(&self) -> u64 {
        self.facts.intent.nonce_v1()
    }

    pub(crate) const fn request_sha256_v1(&self) -> [u8; 32] {
        self.facts.intent.request_sha256_v1()
    }

    pub(crate) const fn journal_predecessor_v1(&self) -> (u64, [u8; 32]) {
        (
            self.facts.journal_predecessor_sequence,
            self.facts.journal_predecessor_sha256,
        )
    }

    #[allow(dead_code)]
    pub(crate) const fn signer_inventory_v1(&self) -> (u64, u64, u64, u64, [u8; 32]) {
        (
            self.facts.signer_durable_vote_intent_count,
            self.facts.signer_durable_timeout_intent_count,
            self.facts.signer_signed_vote_intent_count,
            self.facts.signer_signed_timeout_intent_count,
            self.facts.signer_inventory_digest,
        )
    }

    #[allow(dead_code)]
    pub(crate) const fn signer_exact_watermark_v1(&self) -> SignerWatermarkV0 {
        self.facts.signer_exact_watermark
    }

    #[allow(dead_code)]
    pub(crate) const fn checkpoint_canonical_sha256_v1(&self) -> [u8; 32] {
        self.facts.checkpoint_canonical_sha256
    }

    fn into_prepared_v1(
        self,
        journal_event_sequence: u64,
        journal_event_sha256: [u8; 32],
    ) -> Result<LocalRestartPreparedOwnerV1> {
        ensure!(
            journal_event_sequence
                == self
                    .facts
                    .journal_predecessor_sequence
                    .checked_add(1)
                    .context("restart prepare journal sequence overflows")?
                && journal_event_sha256 != [0; 32],
            "restart prepare journal successor differs from its quiescent owner"
        );
        Ok(LocalRestartPreparedOwnerV1 {
            facts: LocalRestartPreparedFactsV1 {
                intent: self.facts.intent,
                local_validator: self.facts.local_validator,
                current_view: self.facts.current_view,
                high_qc: self.facts.high_qc,
                finalized_height: self.facts.finalized_height,
                finalized_block_id: self.facts.finalized_block_id,
                finalized_chain_root: self.facts.finalized_chain_root,
                application_height: self.facts.application_height,
                application_block_id: self.facts.application_block_id,
                application_state_root: self.facts.application_state_root,
                proposal_parent_height: self.facts.proposal_parent_height,
                proposal_parent_block_id: self.facts.proposal_parent_block_id,
                signed_vote_intents: self.facts.signed_vote_intents,
                signed_timeout_intents: self.facts.signed_timeout_intents,
                signer_durable_vote_intent_count: self.facts.signer_durable_vote_intent_count,
                signer_durable_timeout_intent_count: self.facts.signer_durable_timeout_intent_count,
                signer_signed_vote_intent_count: self.facts.signer_signed_vote_intent_count,
                signer_signed_timeout_intent_count: self.facts.signer_signed_timeout_intent_count,
                signer_inventory_digest: self.facts.signer_inventory_digest,
                signer_exact_watermark: self.facts.signer_exact_watermark,
                safety_revision: self.facts.safety_revision,
                safety_record_checksum: self.facts.safety_record_checksum,
                safety_chain_checksum: self.facts.safety_chain_checksum,
                signer_watermark_sequence: self.facts.signer_watermark_sequence,
                checkpoint_generation: self.facts.checkpoint_generation,
                checkpoint_canonical_sha256: self.facts.checkpoint_canonical_sha256,
                replay_archive_context_sha256: self.facts.replay_archive_context_sha256,
                replay_archive_head_sequence: self.facts.replay_archive_head_sequence,
                replay_archive_head_sha256: self.facts.replay_archive_head_sha256,
                journal_event_sequence,
                journal_event_sha256,
            },
        })
    }
}

/// Descriptive facts held only after the owner-authenticated RestartPrepare
/// journal successor is durable. They are not an N/N RestartCut certificate.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalRestartPreparedFactsV1 {
    intent: RuntimeRestartPrepareIntentV1,
    local_validator: ValidatorId,
    current_view: View,
    high_qc: QcRef,
    finalized_height: u64,
    finalized_block_id: BlockId,
    finalized_chain_root: [u8; 32],
    application_height: u64,
    application_block_id: BlockId,
    application_state_root: [u8; 32],
    proposal_parent_height: u64,
    proposal_parent_block_id: BlockId,
    signed_vote_intents: u64,
    signed_timeout_intents: u64,
    signer_durable_vote_intent_count: u64,
    signer_durable_timeout_intent_count: u64,
    signer_signed_vote_intent_count: u64,
    signer_signed_timeout_intent_count: u64,
    signer_inventory_digest: [u8; 32],
    signer_exact_watermark: SignerWatermarkV0,
    safety_revision: u64,
    safety_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    signer_watermark_sequence: u64,
    checkpoint_generation: u64,
    checkpoint_canonical_sha256: [u8; 32],
    replay_archive_context_sha256: [u8; 32],
    replay_archive_head_sequence: u64,
    replay_archive_head_sha256: [u8; 32],
    journal_event_sequence: u64,
    journal_event_sha256: [u8; 32],
}

/// Non-Clone local prepared carrier. It exposes neither a signer nor a kill
/// handle. Its sole operational consumption is the exact target-owned
/// RestartPrepare construction below; N/N storage and journaling remain
/// separate linear joins.
#[must_use]
#[derive(Debug)]
pub(crate) struct LocalRestartPreparedOwnerV1 {
    facts: LocalRestartPreparedFactsV1,
}

impl LocalRestartPreparedOwnerV1 {
    #[cfg(test)]
    const fn facts_v1(&self) -> LocalRestartPreparedFactsV1 {
        self.facts
    }

    #[allow(dead_code)]
    pub(crate) const fn signer_exact_watermark_v1(&self) -> SignerWatermarkV0 {
        self.facts.signer_exact_watermark
    }

    #[allow(dead_code)]
    pub(crate) const fn checkpoint_canonical_sha256_v1(&self) -> [u8; 32] {
        self.facts.checkpoint_canonical_sha256
    }

    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.facts.local_validator
    }

    pub(crate) const fn process_instance_v1(&self) -> u64 {
        self.facts.intent.process_instance_v1()
    }

    pub(crate) const fn journal_successor_v1(&self) -> (u64, [u8; 32]) {
        (
            self.facts.journal_event_sequence,
            self.facts.journal_event_sha256,
        )
    }

    /// Consumes the linear prepared owner into a distinct carrier while
    /// issuing exactly one target-authored declaration. The returned carrier
    /// has no method that can sign a second declaration.
    fn into_signed_target_prepare_v1(
        self,
        config: &LoadedValidatorConfig,
        fleet_start_certificate: &FleetStartCertificateV1,
    ) -> Result<LocalRestartTargetPreparedOwnerV1> {
        ensure!(
            self.facts.local_validator == config.local_validator()
                && self.facts.intent.process_instance_v1() == 1
                && self.facts.journal_event_sequence > 0
                && self.facts.journal_event_sha256 != [0; 32]
                && self.facts.signer_watermark_sequence
                    == self.facts.signer_exact_watermark.sequence(),
            "prepared restart owner differs from loaded process-1 config"
        );
        let state = RestartCutStateV1 {
            epoch: config.validator_set().epoch(),
            current_view: self.facts.current_view,
            direct_high_qc: self.facts.high_qc,
            proposal_parent_height: Height::new(self.facts.proposal_parent_height),
            proposal_parent_block_id: self.facts.proposal_parent_block_id,
            finalized_height: Height::new(self.facts.finalized_height),
            finalized_block_id: self.facts.finalized_block_id,
            finalized_chain_root: self.facts.finalized_chain_root,
            application_height: Height::new(self.facts.application_height),
            application_block_id: self.facts.application_block_id,
            application_state_root: StateRoot::new(self.facts.application_state_root),
            external_checkpoint_generation: self.facts.checkpoint_generation,
            external_checkpoint_checksum: self.facts.checkpoint_canonical_sha256,
            safety_revision: self.facts.safety_revision,
            safety_state_record_checksum: self.facts.safety_record_checksum,
            safety_record_chain_checksum: self.facts.safety_chain_checksum,
            signer_watermark: self.facts.signer_exact_watermark,
            signer_durable_vote_intent_count: self.facts.signer_durable_vote_intent_count,
            signer_durable_timeout_intent_count: self.facts.signer_durable_timeout_intent_count,
            signer_signed_vote_intent_count: self.facts.signer_signed_vote_intent_count,
            signer_signed_timeout_intent_count: self.facts.signer_signed_timeout_intent_count,
            signer_inventory_digest: self.facts.signer_inventory_digest,
            pending_sign: None,
            replay_archive_context_sha256: self.facts.replay_archive_context_sha256,
            replay_archive_head_sequence: self.facts.replay_archive_head_sequence,
            replay_archive_head_sha256: self.facts.replay_archive_head_sha256,
            runtime_journal_head_sequence: self.facts.journal_event_sequence,
            runtime_journal_head_sha256: self.facts.journal_event_sha256,
        };
        let body = RestartCutBodyV1::new(
            fleet_start_certificate.ready_set().context().clone(),
            self.facts.local_validator,
            config.config_sha256(),
            self.facts.intent.process_instance_v1(),
            state,
            fleet_start_certificate,
            config.validator_set(),
        )
        .map_err(|error| anyhow!("construct target restart cut body: {error}"))?;
        let declaration = SignedRestartCutV1::new(
            self.facts.local_validator,
            body,
            config.validator_set(),
            config.consensus_signing_key(),
        )
        .map_err(|error| anyhow!("sign target RestartPrepare: {error}"))?;
        ensure!(
            declaration.origin() == declaration.body().target_validator()
                && declaration.body().runtime_journal_head_v1() == self.journal_successor_v1(),
            "issued target RestartPrepare differs from prepared owner"
        );
        Ok(LocalRestartTargetPreparedOwnerV1 {
            prepared: self,
            target_prepare: declaration,
        })
    }
}

/// Linear process-1 target carrier after the sole target RestartPrepare
/// signature exists. It retains the exact prepared journal owner for the
/// later store-to-journal join but exposes no signing operation.
#[must_use]
pub(crate) struct LocalRestartTargetPreparedOwnerV1 {
    prepared: LocalRestartPreparedOwnerV1,
    target_prepare: SignedRestartCutV1,
}

impl std::fmt::Debug for LocalRestartTargetPreparedOwnerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRestartTargetPreparedOwnerV1")
            .field("prepared", &self.prepared)
            .field("target_prepare", &self.target_prepare)
            .finish_non_exhaustive()
    }
}

impl LocalRestartTargetPreparedOwnerV1 {
    #[cfg(test)]
    pub(crate) fn from_target_prepare_for_journal_test_v1(
        target_prepare: SignedRestartCutV1,
    ) -> Result<Self> {
        let body = target_prepare.body();
        let state = body.state();
        let journal_successor = body.runtime_journal_head_v1();
        ensure!(
            target_prepare.origin() == body.target_validator()
                && body.process_instance() == 1
                && journal_successor.0 > 0
                && journal_successor.1 != [0; 32],
            "test target prepare lacks an exact process-1 journal successor"
        );
        let prepared = LocalRestartPreparedOwnerV1 {
            facts: LocalRestartPreparedFactsV1 {
                intent: RuntimeRestartPrepareIntentV1::test_only_v1(
                    body.process_instance(),
                    1,
                    1,
                    [0x91; 32],
                ),
                local_validator: body.target_validator(),
                current_view: state.current_view,
                high_qc: state.direct_high_qc,
                finalized_height: state.finalized_height.get(),
                finalized_block_id: state.finalized_block_id,
                finalized_chain_root: state.finalized_chain_root,
                application_height: state.application_height.get(),
                application_block_id: state.application_block_id,
                application_state_root: *state.application_state_root.as_bytes(),
                proposal_parent_height: state.proposal_parent_height.get(),
                proposal_parent_block_id: state.proposal_parent_block_id,
                signed_vote_intents: state.signer_signed_vote_intent_count,
                signed_timeout_intents: state.signer_signed_timeout_intent_count,
                signer_durable_vote_intent_count: state.signer_durable_vote_intent_count,
                signer_durable_timeout_intent_count: state.signer_durable_timeout_intent_count,
                signer_signed_vote_intent_count: state.signer_signed_vote_intent_count,
                signer_signed_timeout_intent_count: state.signer_signed_timeout_intent_count,
                signer_inventory_digest: state.signer_inventory_digest,
                signer_exact_watermark: state.signer_watermark,
                safety_revision: state.safety_revision,
                safety_record_checksum: state.safety_state_record_checksum,
                safety_chain_checksum: state.safety_record_chain_checksum,
                signer_watermark_sequence: state.signer_watermark.sequence(),
                checkpoint_generation: state.external_checkpoint_generation,
                checkpoint_canonical_sha256: state.external_checkpoint_checksum,
                replay_archive_context_sha256: state.replay_archive_context_sha256,
                replay_archive_head_sequence: state.replay_archive_head_sequence,
                replay_archive_head_sha256: state.replay_archive_head_sha256,
                journal_event_sequence: journal_successor.0,
                journal_event_sha256: journal_successor.1,
            },
        };
        Ok(Self {
            prepared,
            target_prepare,
        })
    }

    pub(crate) const fn local_validator_v1(&self) -> ValidatorId {
        self.prepared.local_validator_v1()
    }

    pub(crate) const fn process_instance_v1(&self) -> u64 {
        self.prepared.process_instance_v1()
    }

    pub(crate) const fn journal_successor_v1(&self) -> (u64, [u8; 32]) {
        self.prepared.journal_successor_v1()
    }

    pub(crate) const fn target_prepare_v1(&self) -> &SignedRestartCutV1 {
        &self.target_prepare
    }
}

impl BoundedConsensusOwnerV1 {
    fn new(
        config: LoadedValidatorConfig,
        authority: ContinuousValidatorAuthorityV0,
        mesh: PersistentAuthenticatedPeerMeshV0,
        event_journal: RuntimeEventJournalV1,
        replay_archive: SignedReplayArchiveV1,
        runtime_control: RuntimeControlServerV1,
        barrier: CompletedFleetBarrierV1,
        preflight: ConsensusRuntimePreflightV1,
        os_start: RuntimeOsSampleV1,
    ) -> Result<Self> {
        ensure!(
            mesh.local_validator() == config.local_validator()
                && authority.local_validator_v0() == config.local_validator(),
            "consensus owner identity differs across config, authority, and mesh"
        );
        let initial = authority.facts_v0()?;
        let observation = event_journal.observation();
        ensure!(
            observation.barrier_phase == "started"
                && observation.fleet_ready_set_sha256.is_some()
                && observation.fleet_start_certificate_sha256.is_some(),
            "consensus owner was constructed before durable FleetStarted"
        );
        let high_qc = initial.high_qc_v0();
        let initial_consensus_view = initial.current_view_v0().get();
        let maximum_archivable_view = initial_consensus_view
            .checked_add(
                preflight
                    .signer_lifetime
                    .maximum_local_vote_intents_v0()
                    .checked_sub(1)
                    .context("bounded consensus has no archivable Proposal view")?,
            )
            .context("bounded consensus maximum view overflows")?;
        let mut known_executions = BTreeSet::new();
        known_executions.insert((high_qc.height().get(), *high_qc.block_id().as_bytes()));
        let mut pacemaker = GenerationAwarePacemakerV0::new(
            PACEMAKER_BASE_TIMEOUT_V1,
            PACEMAKER_MAXIMUM_TIMEOUT_V1,
        )?;
        let started_at = Instant::now();
        let nominal_deadline = started_at
            .checked_add(preflight.duration)
            .ok_or_else(|| anyhow!("bounded consensus deadline overflows"))?;
        pacemaker.arm(
            config.validator_set().epoch(),
            initial.current_view_v0(),
            started_at,
        )?;
        let highest_submitted_height = config
            .ordinary_start_height()
            .checked_sub(1)
            .expect("ordinary start height was validated as positive");
        let reconstructed_start = barrier
            .admission
            .start_certificate()
            .map_err(|error| anyhow!("reconstruct retained fleet StartCertificate: {error}"))?;
        ensure!(
            reconstructed_start == barrier.start_certificate
                && reconstructed_start.encode() == barrier.start_certificate.encode(),
            "retained fleet StartCertificate differs from barrier admission"
        );
        barrier
            .start_certificate
            .verify(config.validator_set())
            .map_err(|error| anyhow!("verify retained fleet StartCertificate: {error}"))?;
        let restart_ingress = BoundedRestartProtocolIngressV1::new(
            config.run_id(),
            config.local_validator(),
            config.validator_set().clone(),
        )
        .map_err(|error| anyhow!("initialize restart ingress: {error}"))?;
        let restart_relay_window = RestartRelayAdmissionWindowV1::new(config.validator_set())
            .map_err(|error| anyhow!("initialize restart relay window: {error}"))?;
        Ok(Self {
            config,
            authority: Some(authority),
            mesh: Some(mesh),
            event_journal,
            replay_archive,
            runtime_control: Some(runtime_control),
            fleet_barrier: barrier.admission,
            fleet_start_certificate: barrier.start_certificate,
            restart_ingress,
            restart_relay_window,
            restart_round: RestartCutRoundV1::default(),
            prestarted_ingress: barrier.prestarted_ingress,
            active_connectivity_fault: None,
            pacemaker,
            outbox: OrderedConsensusOutboxV1::new(preflight.peers.clone()),
            pending_proposals: PendingProposalBufferV1::default(),
            pending_certificates: VecDeque::new(),
            known_executions,
            proposal_first_seen: BTreeMap::new(),
            finality_samples_ms: Vec::new(),
            applied_qcs: BTreeSet::new(),
            applied_tcs: BTreeSet::new(),
            local_proposal_views: BTreeSet::new(),
            unavailable_sessions: BTreeSet::new(),
            highest_submitted_height,
            post_timeout_rebase_required_finalized_height: None,
            initial_consensus_view,
            maximum_archivable_view,
            started_at,
            nominal_deadline,
            stopping_since: None,
            terminal_candidate_since: None,
            restart_lifecycle: RestartLifecycleV1::Running,
            prepared_normal_frame_drop_count: 0,
            os_start,
            network_tx_bytes: 0,
            network_rx_bytes: 0,
            preflight,
        })
    }

    fn run_and_finish_v1(&mut self) -> Result<BoundedConsensusRunOutcomeV1> {
        match self.run_loop_v1()? {
            BoundedConsensusLoopOutcomeV1::NormalTerminal => self
                .finish_v1()
                .map(BoundedConsensusRunOutcomeV1::CompletedReport),
            BoundedConsensusLoopOutcomeV1::Process1TargetParked => self
                .finish_target_process1_handoff_v1()
                .map(BoundedConsensusRunOutcomeV1::Process1TargetParked),
        }
    }

    fn run_loop_v1(&mut self) -> Result<BoundedConsensusLoopOutcomeV1> {
        loop {
            if self.restart_lifecycle.selects_process1_target_handoff_v1() {
                return Ok(BoundedConsensusLoopOutcomeV1::Process1TargetParked);
            }
            if self.restart_lifecycle.is_prepared_v1() {
                self.mesh_v1()?.ensure_healthy()?;
                let control_progress = self.poll_runtime_control_v1()?;
                let outbox_progress = self.flush_outbox_v1()?;
                let event = self.mesh_v1()?.receive_timeout(OWNER_POLL_INTERVAL_V1)?;
                let ingress_progress = event
                    .map(|event| self.handle_mesh_event_v1(event))
                    .transpose()?
                    .unwrap_or(false);
                let cut_progress = self.maybe_complete_restart_cut_v1()?;
                if self.restart_lifecycle.selects_process1_target_handoff_v1() {
                    return Ok(BoundedConsensusLoopOutcomeV1::Process1TargetParked);
                }
                let peer_cut_progress = self.maybe_complete_peer_restart_cut_v1()?;
                let parked_ack_progress = self.maybe_complete_restart_parked_ack_v1()?;
                if !(control_progress
                    || outbox_progress
                    || ingress_progress
                    || cut_progress
                    || peer_cut_progress
                    || parked_ack_progress)
                {
                    thread::sleep(OWNER_POLL_INTERVAL_V1);
                }
                continue;
            }
            ensure!(
                self.restart_lifecycle.allows_authenticated_drain_v1(),
                "prepared restart owner re-entered ordinary consensus drain"
            );
            self.mesh_v1()?.ensure_healthy()?;
            let control_progress = self.poll_runtime_control_v1()?;
            let outbox_progress = self.flush_outbox_v1()?;
            let pending_proposal_progress = self.drain_pending_proposals_v1()?;
            let certificate_progress = self.drain_pending_certificates_v1()?;
            let proposal_progress = self.maybe_propose_v1()?;
            self.refresh_stop_state_v1(Instant::now())?;

            let event = match self.prestarted_ingress.pop_front() {
                Some(event) => Some(event),
                None => self.mesh_v1()?.receive_timeout(OWNER_POLL_INTERVAL_V1)?,
            };
            let mut ingress_progress = match event {
                Some(event) => self.handle_mesh_event_v1(event)?,
                None => false,
            };
            let timeout_progress = self.poll_pacemaker_v1(Instant::now())?;
            ingress_progress |= self.drain_ready_ingress_v1()?;
            let restart_prepare_progress = self.maybe_complete_restart_prepare_v1()?;
            let peer_park_progress = self.maybe_complete_peer_park_v1()?;
            if control_progress
                || outbox_progress
                || pending_proposal_progress
                || certificate_progress
                || proposal_progress
                || ingress_progress
                || timeout_progress
                || restart_prepare_progress
                || peer_park_progress
            {
                self.terminal_candidate_since = None;
            }
            let now = Instant::now();
            self.refresh_stop_state_v1(now)?;
            if self.terminal_ready_v1(now)? {
                return Ok(BoundedConsensusLoopOutcomeV1::NormalTerminal);
            }
            if let Some(stopping_since) = self.stopping_since {
                let drain_deadline = stopping_since
                    .checked_add(TERMINAL_DRAIN_GRACE_V1)
                    .ok_or_else(|| anyhow!("terminal drain deadline overflows"))?;
                if now >= drain_deadline {
                    bail!("bounded consensus could not reach an obligation-free terminal cut");
                }
            }
        }
    }

    fn drain_ready_ingress_v1(&mut self) -> Result<bool> {
        let mut progressed = false;
        loop {
            let event = match self.prestarted_ingress.pop_front() {
                Some(event) => Some(event),
                None => self.mesh_v1()?.receive_timeout(Duration::ZERO)?,
            };
            let Some(event) = event else {
                return Ok(progressed);
            };
            progressed |= self.handle_mesh_event_v1(event)?;
        }
    }

    fn refresh_stop_state_v1(&mut self, now: Instant) -> Result<()> {
        if !self.restart_lifecycle.is_running_v1() {
            return Ok(());
        }
        let facts = self.authority_v1()?.facts_v0()?;
        let positive_ordinary_finality = facts.finalized_height_v0()
            >= self.config.ordinary_start_height()
            && facts.application_applied_height_v0() == facts.finalized_height_v0();
        let reached_height_bound = self.highest_submitted_height >= self.preflight.target_height;
        let reached_duration_bound = now >= self.nominal_deadline;
        if self.stopping_since.is_none()
            && positive_ordinary_finality
            && (reached_height_bound || reached_duration_bound)
        {
            self.stopping_since = Some(now);
            self.pacemaker.cancel();
        }
        if reached_duration_bound && self.stopping_since.is_none() {
            let grace_deadline = self
                .nominal_deadline
                .checked_add(TERMINAL_DRAIN_GRACE_V1)
                .ok_or_else(|| anyhow!("positive-finality drain deadline overflows"))?;
            if now >= grace_deadline {
                bail!("bounded duration elapsed without one positive ordinary finality cut");
            }
        }
        Ok(())
    }

    fn terminal_ready_v1(&mut self, now: Instant) -> Result<bool> {
        if !self.restart_lifecycle.is_running_v1()
            || self.stopping_since.is_none()
            || !self.outbox.is_empty()
            || !self.pending_proposals.is_empty()
            || !self.pending_certificates.is_empty()
            || !self.prestarted_ingress.is_empty()
            || !self.unavailable_sessions.is_empty()
            || self.post_timeout_rebase_required_finalized_height.is_some()
            || self.active_connectivity_fault.is_some()
            || self
                .runtime_control
                .as_ref()
                .is_some_and(|control| control.expected_fault().is_some())
            || !self.event_journal.observation().active_faults.is_empty()
            || self.mesh_v1()?.pending_outbound_bytes_v1()? != 0
        {
            self.terminal_candidate_since = None;
            return Ok(false);
        }
        let facts = self.authority_v1()?.facts_v0()?;
        if facts.phase_v0() != PocoNodeLabAuthorityPhaseV0::Ready
            || facts.pending_timeout_certificate_id_v0().is_some()
            || facts.finalized_height_v0() < self.config.ordinary_start_height()
            || facts.application_applied_height_v0() != facts.finalized_height_v0()
        {
            self.terminal_candidate_since = None;
            return Ok(false);
        }
        let since = *self.terminal_candidate_since.get_or_insert(now);
        Ok(
            now.saturating_duration_since(since) >= TERMINAL_QUIET_PERIOD_V1
                && now.saturating_duration_since(self.started_at) >= MINIMUM_METRICS_INTERVAL_V1,
        )
    }

    fn maybe_propose_v1(&mut self) -> Result<bool> {
        if !self.restart_lifecycle.allows_local_proposal_v1() || self.stopping_since.is_some() {
            return Ok(false);
        }
        let facts = self.authority_v1()?.facts_v0()?;
        if facts.phase_v0() != PocoNodeLabAuthorityPhaseV0::Ready {
            return Ok(false);
        }
        let view = facts.current_view_v0();
        if leader_for(self.config.validator_set(), view) != self.config.local_validator()
            || self.local_proposal_views.contains(&view.get())
        {
            return Ok(false);
        }
        let next_height = facts
            .proposal_parent_height_v0()
            .checked_add(1)
            .context("next proposal height overflows")?;
        if next_height > self.preflight.target_height {
            return Ok(false);
        }

        let authority = self
            .authority
            .as_ref()
            .ok_or_else(|| anyhow!("continuous authority is unavailable"))?;
        let proposal =
            authority.signed_workload_proposal_from_loaded_config_v0(&mut self.config)?;
        let block_id = proposal.block().id();
        let height = proposal.block().header().height().get();
        self.record_proposal_first_seen_v1(block_id, height)?;
        let unbound = UnboundProposalV0::from_signed(&proposal)
            .map_err(|error| anyhow!("project local proposal to wire: {error}"))?;
        self.archive_proposal_before_authority_v1(&unbound)?;
        let encoded = unbound
            .encode()
            .map_err(|error| anyhow!("encode local proposal: {error}"))?;
        self.enqueue_consensus_statement_v1(FrameKind::Proposal, encoded)?;
        let vote = self.authority_v1()?.vote_unbound_proposal_v0(unbound)?;
        self.record_proposal_admitted_v1(block_id, height)?;
        self.known_executions.insert((height, *block_id.as_bytes()));
        self.highest_submitted_height = self.highest_submitted_height.max(height);
        self.local_proposal_views.insert(view.get());
        self.emit_local_vote_v1(vote)?;
        self.drain_pending_certificates_v1()?;
        Ok(true)
    }

    /// Publishes one canonical consensus statement through the exact transport
    /// profile selected before any runtime effect. Sparse statements acquire
    /// their origin signature and process-local relay identity before they can
    /// enter an outbound queue, so a returning copy is never forwarded or
    /// collector-admitted twice.
    fn enqueue_consensus_statement_v1(&mut self, kind: FrameKind, payload: Vec<u8>) -> Result<()> {
        ensure!(
            matches!(
                kind,
                FrameKind::Proposal
                    | FrameKind::Vote
                    | FrameKind::TimeoutVote
                    | FrameKind::QuorumCertificate
                    | FrameKind::TimeoutCertificate
            ),
            "runtime attempted to publish a non-consensus statement"
        );
        let Some(hop_budget) = self.preflight.transport.relay_hop_budget_v1() else {
            return self.outbox.enqueue(kind, payload);
        };
        let envelope = ConsensusRelayEnvelopeV0::new(
            self.config.local_validator(),
            kind,
            hop_budget,
            payload,
            self.config.validator_set(),
            self.config.consensus_signing_key(),
        )
        .map_err(|error| anyhow!("construct originated consensus relay: {error}"))?;
        self.authority_v1()?
            .reserve_originated_consensus_relay_v0(&envelope)?;
        self.outbox
            .enqueue(FrameKind::ConsensusRelay, envelope.encode())
    }

    fn enqueue_restart_statement_v1(
        &mut self,
        phase: RestartProtocolPhaseV1,
        payload: Vec<u8>,
    ) -> Result<RestartProtocolOriginReservationV1> {
        self.require_direct_seven_restart_park_v1()?;
        let reservation = self
            .restart_ingress
            .reserve_originated_statement_v1(phase, &payload, None)
            .map_err(|error| anyhow!("reserve originated restart statement: {error}"))?;
        self.outbox.enqueue(phase.frame_kind(), payload)?;
        Ok(reservation)
    }

    fn require_direct_seven_restart_park_v1(&self) -> Result<()> {
        ensure!(
            self.config.validator_set().validators().len() == 7
                && self.preflight.transport == ConsensusTransportProfileV1::Direct,
            "RestartCut/Park barrier is enabled only for the frozen direct-seven lane"
        );
        Ok(())
    }

    fn restart_parked_ack_stored_v1(&self) -> Option<&StoredRestartCutParkCertificatesV1> {
        match &self.restart_lifecycle {
            RestartLifecycleV1::PeerParked(owner) => Some(owner.parked.stored_v1()),
            RestartLifecycleV1::PeerAckCollecting(owner) => {
                Some(owner.originated_ack.stored_cut_park_v1())
            }
            RestartLifecycleV1::PeerAcked(owner) => Some(owner.acknowledged.stored_cut_park_v1()),
            RestartLifecycleV1::TargetParked(owner) => Some(owner.parked.stored_v1()),
            RestartLifecycleV1::TargetAckCollecting(owner) => {
                Some(owner.originated_ack.stored_cut_park_v1())
            }
            RestartLifecycleV1::TargetAcked(owner) => Some(owner.acknowledged.stored_cut_park_v1()),
            RestartLifecycleV1::Running
            | RestartLifecycleV1::TargetQuiescing(_)
            | RestartLifecycleV1::TargetCollecting(_)
            | RestartLifecycleV1::PeerQuiescing(_)
            | RestartLifecycleV1::PeerCollecting(_)
            | RestartLifecycleV1::PeerBarrier(_)
            | RestartLifecycleV1::TargetBarrier(_) => None,
        }
    }

    fn handle_restart_protocol_action_v1(
        &mut self,
        action: RoutedRestartProtocolActionV1,
    ) -> Result<bool> {
        self.require_direct_seven_restart_park_v1()?;
        let phase = action.phase();
        let admitted = action.into_admitted_message_v1();
        match phase {
            RestartProtocolPhaseV1::Prepare => {
                let prepare = AdmittedRestartPrepareV1::new(
                    admitted,
                    &self.fleet_start_certificate,
                    self.config.validator_set(),
                )
                .map_err(|error| anyhow!("authenticate phase-bound RestartPrepare: {error}"))?;
                ensure!(
                    prepare.body_v1().target_validator() != self.config.local_validator(),
                    "local target Prepare cannot arrive through a remote authenticated slot"
                );
                ensure!(
                    matches!(&self.restart_lifecycle, RestartLifecycleV1::Running),
                    "one local restart lifecycle conflicts with a foreign target Prepare"
                );
                ensure!(
                    self.restart_round
                        .admitted_statements
                        .values()
                        .all(|statement| statement.statement_v1().body() == prepare.body_v1()),
                    "an early Cut/Park statement differs from the admitted target Prepare"
                );
                self.pacemaker.cancel();
                self.restart_lifecycle =
                    RestartLifecycleV1::PeerQuiescing(LocalRestartPeerQuiescingOwnerV1 {
                        admitted_prepare: prepare,
                    });
                self.terminal_candidate_since = None;
                Ok(true)
            }
            RestartProtocolPhaseV1::Cut => {
                let statement = AdmittedRestartCutParkV1::new(
                    admitted,
                    &self.fleet_start_certificate,
                    self.config.validator_set(),
                )
                .map_err(|error| anyhow!("authenticate phase-bound RestartCut/Park: {error}"))?;
                let origin = statement.statement_v1().origin();
                ensure!(
                    origin != self.config.local_validator(),
                    "local Cut/Park cannot arrive through a remote authenticated slot"
                );
                match &self.restart_lifecycle {
                    RestartLifecycleV1::TargetCollecting(owner) => ensure!(
                        statement.statement_v1().body()
                            == owner.prepared.target_prepare_v1().body(),
                        "RestartCut/Park differs from the local target Prepare"
                    ),
                    RestartLifecycleV1::PeerQuiescing(owner) => ensure!(
                        statement.statement_v1().body() == owner.admitted_prepare.body_v1(),
                        "RestartCut/Park differs from the admitted target Prepare"
                    ),
                    RestartLifecycleV1::PeerCollecting(owner) => ensure!(
                        statement.statement_v1().body()
                            == owner.prepared.admitted_prepare.body_v1(),
                        "RestartCut/Park differs from the durably parked peer Prepare"
                    ),
                    RestartLifecycleV1::Running | RestartLifecycleV1::TargetQuiescing(_) => {}
                    RestartLifecycleV1::PeerBarrier(_)
                    | RestartLifecycleV1::PeerParked(_)
                    | RestartLifecycleV1::PeerAckCollecting(_)
                    | RestartLifecycleV1::PeerAcked(_) => {
                        bail!("a fresh Cut/Park slot arrived after the peer barrier completed")
                    }
                    RestartLifecycleV1::TargetBarrier(_)
                    | RestartLifecycleV1::TargetParked(_)
                    | RestartLifecycleV1::TargetAckCollecting(_)
                    | RestartLifecycleV1::TargetAcked(_) => {
                        bail!("a fresh Cut/Park slot arrived after the target barrier completed")
                    }
                }
                ensure!(
                    !self.restart_round.admitted_statements.contains_key(&origin)
                        && self.restart_round.admitted_statements.len() < 6,
                    "remote Cut/Park collector contains a duplicate or exceeds six peers"
                );
                self.restart_round
                    .admitted_statements
                    .insert(origin, statement);
                Ok(true)
            }
            RestartProtocolPhaseV1::ParkedAck => {
                let origin = admitted.origin_v1();
                ensure!(
                    origin != self.config.local_validator(),
                    "local ParkedAck cannot arrive through a remote authenticated slot"
                );
                ensure!(
                    !matches!(
                        self.restart_lifecycle,
                        RestartLifecycleV1::PeerAcked(_) | RestartLifecycleV1::TargetAcked(_)
                    ),
                    "a fresh ParkedAck slot arrived after the N/N Ack barrier committed"
                );
                ensure!(
                    !self.restart_round.pending_parked_acks.contains_key(&origin)
                        && !self
                            .restart_round
                            .admitted_parked_acks
                            .contains_key(&origin)
                        && self.restart_round.pending_parked_acks.len()
                            + self.restart_round.admitted_parked_acks.len()
                            < 6,
                    "remote ParkedAck collector contains a duplicate or exceeds six peers"
                );
                if self.restart_parked_ack_stored_v1().is_some() {
                    let statement = {
                        let stored = self
                            .restart_parked_ack_stored_v1()
                            .expect("checked durable Cut/Park owner remains present");
                        AdmittedRestartParkedAckV1::new(admitted, stored).map_err(|error| {
                            anyhow!("authenticate phase-bound RestartParkedAck: {error}")
                        })?
                    };
                    ensure!(
                        self.restart_round
                            .admitted_parked_acks
                            .insert(origin, statement)
                            .is_none(),
                        "remote ParkedAck collector replaced one authenticated origin"
                    );
                } else {
                    ensure!(
                        self.restart_round
                            .pending_parked_acks
                            .insert(origin, admitted)
                            .is_none(),
                        "early ParkedAck collector replaced one authenticated origin"
                    );
                }
                Ok(true)
            }
            RestartProtocolPhaseV1::RecoveryReady | RestartProtocolPhaseV1::RecoveryStart => {
                bail!("process-1 runtime cannot originate recovery phases")
            }
        }
    }

    fn record_prepared_normal_frame_drop_v1(&mut self) -> Result<()> {
        self.prepared_normal_frame_drop_count = self
            .prepared_normal_frame_drop_count
            .checked_add(1)
            .context("prepared normal-frame drop counter overflows")?;
        ensure!(
            self.prepared_normal_frame_drop_count <= MAXIMUM_PREPARED_NORMAL_FRAME_DROPS_V1,
            "prepared normal-frame drop bound exhausted"
        );
        Ok(())
    }

    fn handle_mesh_event_v1(&mut self, event: MeshIngressEventV0) -> Result<bool> {
        match event {
            MeshIngressEventV0::Frame(inbound) => {
                let remote = inbound.remote();
                let received = authenticated_frame_wire_bytes_v1(
                    self.config.run_id(),
                    inbound.frame().payload.len(),
                )?;
                self.network_rx_bytes = self
                    .network_rx_bytes
                    .checked_add(received)
                    .context("consensus receive-byte counter overflows")?;
                match self.preflight.transport {
                    ConsensusTransportProfileV1::Direct => {
                        let frame = inbound.frame();
                        if matches!(frame.kind, FrameKind::FleetReady | FrameKind::FleetStart) {
                            return self.admit_late_fleet_barrier_statement_v1(
                                frame.sender,
                                frame.kind,
                                &frame.payload,
                            );
                        }
                        if is_restart_protocol_kind_v1(frame.kind) {
                            let routed = self
                                .restart_ingress
                                .admit_authenticated_mesh_frame_v1(inbound)
                                .map_err(|error| anyhow!("admit direct restart frame: {error}"))?;
                            return routed
                                .action
                                .map(|action| self.handle_restart_protocol_action_v1(action))
                                .transpose()
                                .map(|progress| progress.unwrap_or(false));
                        }
                        ensure!(
                            frame.kind != FrameKind::ConsensusRelay,
                            "seven-validator direct runtime rejects relay frames"
                        );
                        if self.restart_lifecycle.is_prepared_v1() {
                            self.record_prepared_normal_frame_drop_v1()?;
                            return Ok(true);
                        }
                        let action = self
                            .authority_v1()?
                            .admit_authenticated_consensus_frame_v0(&frame)?;
                        match action {
                            Some(action) => self.handle_routed_action_v1(action),
                            None => Ok(false),
                        }
                    }
                    ConsensusTransportProfileV1::SparseRelay { .. } => {
                        let frame = inbound.frame();
                        ensure!(
                            frame.kind == FrameKind::ConsensusRelay,
                            "sparse consensus runtime rejects direct consensus frames"
                        );
                        let envelope = ConsensusRelayEnvelopeV0::decode(
                            &frame.payload,
                            self.config.validator_set(),
                        )
                        .map_err(|error| anyhow!("decode sparse consensus relay: {error}"))?;
                        if matches!(
                            envelope.inner_kind(),
                            FrameKind::FleetReady | FrameKind::FleetStart
                        ) {
                            return self.admit_late_fleet_barrier_statement_v1(
                                envelope.origin(),
                                envelope.inner_kind(),
                                envelope.payload(),
                            );
                        }
                        if is_restart_protocol_kind_v1(envelope.inner_kind()) {
                            let (restart_ingress, restart_relay_window) =
                                (&mut self.restart_ingress, &mut self.restart_relay_window);
                            let routed = restart_ingress
                                .admit_restart_relay_frame(inbound, restart_relay_window)
                                .map_err(|error| anyhow!("admit sparse restart relay: {error}"))?;
                            let mut progressed = false;
                            if let Some(forward) = routed.forward {
                                self.outbox.enqueue_except_v1(
                                    FrameKind::ConsensusRelay,
                                    forward.encode(),
                                    remote,
                                )?;
                                progressed = true;
                            }
                            if let Some(action) = routed.action {
                                progressed |= self.handle_restart_protocol_action_v1(action)?;
                            }
                            return Ok(progressed);
                        }
                        if self.restart_lifecycle.is_prepared_v1() {
                            self.record_prepared_normal_frame_drop_v1()?;
                            return Ok(true);
                        }
                        let routed = self
                            .authority_v1()?
                            .admit_authenticated_consensus_relay_frame_v0(&frame)?;
                        let mut progressed = false;
                        if let Some(forward) = routed.forward {
                            self.outbox.enqueue_except_v1(
                                FrameKind::ConsensusRelay,
                                forward.encode(),
                                remote,
                            )?;
                            progressed = true;
                        }
                        if let Some(action) = routed.action {
                            progressed |= self.handle_routed_action_v1(action)?;
                        }
                        Ok(progressed)
                    }
                }
            }
            MeshIngressEventV0::SessionUnavailable(session) => {
                self.unavailable_sessions
                    .insert((session.direction(), session.remote()));
                if !self.restart_lifecycle.is_prepared_v1() {
                    self.reconcile_expected_connectivity_fault_v1()?;
                }
                Ok(true)
            }
            MeshIngressEventV0::SessionReestablished(session) => {
                self.unavailable_sessions
                    .remove(&(session.direction(), session.remote()));
                if !self.restart_lifecycle.is_prepared_v1() {
                    record_peer_session_v1(&mut self.event_journal, session)?;
                    self.reconcile_expected_connectivity_fault_v1()?;
                }
                Ok(true)
            }
        }
    }

    fn admit_late_fleet_barrier_statement_v1(
        &mut self,
        origin: ValidatorId,
        kind: FrameKind,
        payload: &[u8],
    ) -> Result<bool> {
        let admission = match kind {
            FrameKind::FleetReady => {
                let statement = SignedFleetReadyV1::decode(payload, self.config.validator_set())
                    .map_err(|error| anyhow!("decode late fleet Ready: {error}"))?;
                ensure!(
                    statement.origin() == origin,
                    "late fleet Ready origin differs from authenticated origin"
                );
                self.fleet_barrier
                    .admit_ready(statement)
                    .map_err(|error| anyhow!("admit late fleet Ready: {error}"))?
            }
            FrameKind::FleetStart => {
                let statement = SignedFleetStartV1::decode(payload, self.config.validator_set())
                    .map_err(|error| anyhow!("decode late fleet Start: {error}"))?;
                ensure!(
                    statement.origin() == origin,
                    "late fleet Start origin differs from authenticated origin"
                );
                self.fleet_barrier
                    .admit_start(statement)
                    .map_err(|error| anyhow!("admit late fleet Start: {error}"))?
            }
            _ => bail!("late fleet barrier handler received an ordinary frame"),
        };
        ensure!(
            admission == FleetBarrierAdmissionV1::ExactReplay,
            "post-Started fleet barrier admitted a previously absent statement"
        );
        Ok(false)
    }

    fn poll_runtime_control_v1(&mut self) -> Result<bool> {
        let (outcome, restart_intent) = {
            let control = self
                .runtime_control
                .as_mut()
                .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?;
            control
                .refresh_from_journal(&self.event_journal)
                .context("refresh bounded runtime control journal view")?;
            let outcome = control
                .poll_once(Duration::ZERO)
                .context("poll bounded runtime control server")?;
            (outcome, control.restart_prepare_intent_v1())
        };
        let responded = !matches!(outcome, RuntimeControlPollV1::Idle);
        let restart_progress = restart_intent
            .map(|intent| self.observe_restart_prepare_intent_v1(intent))
            .transpose()?
            .unwrap_or(false);
        let fault_progress = if self.restart_lifecycle.is_prepared_v1() {
            ensure!(
                self.runtime_control
                    .as_ref()
                    .is_some_and(|control| control.expected_fault().is_none()),
                "prepared restart owner rejects new fault expectations"
            );
            false
        } else {
            self.reconcile_expected_connectivity_fault_v1()?
        };
        Ok(responded || restart_progress || fault_progress)
    }

    fn observe_restart_prepare_intent_v1(
        &mut self,
        intent: RuntimeRestartPrepareIntentV1,
    ) -> Result<bool> {
        self.require_direct_seven_restart_park_v1()?;
        ensure!(
            intent.process_instance_v1() == self.event_journal.process_instance()
                && intent.process_instance_v1() == 1
                && intent.generation_v1()
                    == self
                        .runtime_control
                        .as_ref()
                        .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
                        .generation(),
            "restart-prepare intent differs from the runtime incarnation"
        );
        match self.restart_lifecycle.intent_v1() {
            None if matches!(&self.restart_lifecycle, RestartLifecycleV1::Running) => {
                self.restart_lifecycle = RestartLifecycleV1::TargetQuiescing(intent);
                self.pacemaker.cancel();
                self.terminal_candidate_since = None;
                Ok(true)
            }
            None => bail!("local target intent conflicts with an admitted peer restart"),
            Some(current) if current == intent => Ok(false),
            Some(_) => bail!("restart-prepare intent changed after runtime admission"),
        }
    }

    fn restart_quiescence_snapshot_v1(&mut self) -> Result<RestartQuiescenceSnapshotV1> {
        let preliminary = self.authority_v1()?.facts_v0()?;
        let signer_inventory = if preliminary.phase_v0() == PocoNodeLabAuthorityPhaseV0::Ready {
            Some(self.authority_v1()?.fresh_ready_signer_inventory_v1()?)
        } else {
            None
        };
        let facts = self.authority_v1()?.facts_v0()?;
        let (
            signer_durable_vote_intent_count,
            signer_durable_timeout_intent_count,
            signer_signed_vote_intent_count,
            signer_signed_timeout_intent_count,
            signer_inventory_digest,
            signer_exact_watermark,
            checkpoint_canonical_sha256,
        ) = signer_inventory.map_or((0, 0, 0, 0, [0; 32], None, [0; 32]), |inventory| {
            (
                inventory.durable_vote_intent_count_v1(),
                inventory.durable_timeout_intent_count_v1(),
                inventory.signed_vote_intent_count_v1(),
                inventory.signed_timeout_intent_count_v1(),
                inventory.inventory_digest_v1(),
                Some(inventory.exact_watermark_v1()),
                inventory.checkpoint_canonical_sha256_v1(),
            )
        });
        let journal = self.event_journal.observation();
        let restart_intent = self.restart_lifecycle.intent_v1();
        let archive = self.replay_archive.facts_v1();
        let journal_head = self
            .event_journal
            .last_event_facts()
            .ok_or_else(|| anyhow!("restart quiescence lacks one journal head"))?;
        let expected_control_fault = self
            .runtime_control
            .as_ref()
            .is_some_and(|control| control.expected_fault().is_some());
        let mesh_pending_outbound_bytes = self.mesh_v1()?.pending_outbound_bytes_v1()?;
        Ok(RestartQuiescenceSnapshotV1 {
            restart_requested: matches!(
                &self.restart_lifecycle,
                RestartLifecycleV1::TargetQuiescing(_)
            ),
            restart_intent_generation: restart_intent.map_or(0, |intent| intent.generation_v1()),
            restart_intent_nonce: restart_intent.map_or(0, |intent| intent.nonce_v1()),
            restart_intent_request_sha256: restart_intent
                .map_or([0; 32], |intent| intent.request_sha256_v1()),
            normal_stop_in_progress: self.stopping_since.is_some(),
            process_instance: self.event_journal.process_instance(),
            local_validator: self.config.local_validator(),
            authority_phase: facts.phase_v0(),
            pending_timeout_certificate: facts.pending_timeout_certificate_id_v0().is_some(),
            outbox_frame_count: self.outbox.pending.len(),
            outbox_payload_bytes: self.outbox.pending_bytes,
            pending_proposal_count: self.pending_proposals.pending.len(),
            pending_certificate_count: self.pending_certificates.len(),
            prestarted_ingress_count: self.prestarted_ingress.len(),
            unavailable_session_count: self.unavailable_sessions.len(),
            mesh_pending_outbound_bytes,
            post_timeout_rebase_pending: self
                .post_timeout_rebase_required_finalized_height
                .is_some(),
            active_connectivity_fault: self.active_connectivity_fault.is_some(),
            expected_control_fault,
            active_journal_fault_count: journal.active_faults.len(),
            journal_restart_prepare_absent: journal.restart_prepare_nonce.is_none(),
            journal_restart_pending_catchup: journal.restart_pending_catchup,
            journal_restart_completed: journal.restart_completed,
            journal_final_tip_recorded: journal.final_tip_recorded,
            journal_clean_stop_recorded: journal.clean_stop_recorded,
            journal_safety_halted: journal.safety_halted,
            ordinary_start_height: self.config.ordinary_start_height(),
            current_view: facts.current_view_v0(),
            high_qc: facts.high_qc_v0(),
            finalized_height: facts.finalized_height_v0(),
            finalized_block_id: facts.finalized_block_id_v0(),
            finalized_chain_root: facts.finalized_chain_root_v0(),
            application_height: facts.application_applied_height_v0(),
            application_block_id: facts.application_applied_block_id_v0(),
            application_state_root: *facts.application_state_root_v0().as_bytes(),
            proposal_parent_height: facts.proposal_parent_height_v0(),
            proposal_parent_block_id: facts.proposal_parent_block_id_v0(),
            signed_vote_intents: facts.signed_vote_intents_v0(),
            signed_timeout_intents: facts.signed_timeout_intents_v0(),
            signer_durable_vote_intent_count,
            signer_durable_timeout_intent_count,
            signer_signed_vote_intent_count,
            signer_signed_timeout_intent_count,
            signer_inventory_digest,
            authenticated_signer_inventory_digest: facts.authenticated_signer_inventory_digest_v1(),
            signer_exact_watermark,
            checkpoint_signer_exact_watermark: signer_inventory
                .map(|_| facts.signer_exact_watermark_v1()),
            safety_revision: facts.safety_revision_v0(),
            safety_record_checksum: facts.safety_record_checksum_v0(),
            safety_chain_checksum: facts.safety_chain_checksum_v0(),
            signer_watermark_sequence: facts.signer_watermark_sequence_v0(),
            checkpoint_generation: facts.checkpoint_generation_v0(),
            checkpoint_canonical_sha256,
            runtime_checkpoint_canonical_sha256: facts.checkpoint_canonical_sha256_v1(),
            replay_archive_context_sha256: archive.context_sha256_v1(),
            replay_archive_head_sequence: archive.sequence_v1(),
            replay_archive_head_sha256: archive.record_sha256_v1(),
            journal_head_sequence: journal_head.0,
            journal_head_sha256: journal_head.1,
            journal_next_sequence: journal.next_sequence,
            journal_finalized_height: journal.finalized_height,
            journal_application_height: journal.application_height,
        })
    }

    fn maybe_complete_restart_prepare_v1(&mut self) -> Result<bool> {
        let Some(intent) = (match &self.restart_lifecycle {
            RestartLifecycleV1::TargetQuiescing(intent) => Some(*intent),
            RestartLifecycleV1::Running
            | RestartLifecycleV1::TargetCollecting(_)
            | RestartLifecycleV1::PeerQuiescing(_)
            | RestartLifecycleV1::PeerCollecting(_)
            | RestartLifecycleV1::PeerBarrier(_)
            | RestartLifecycleV1::PeerParked(_)
            | RestartLifecycleV1::PeerAckCollecting(_)
            | RestartLifecycleV1::PeerAcked(_)
            | RestartLifecycleV1::TargetBarrier(_)
            | RestartLifecycleV1::TargetParked(_)
            | RestartLifecycleV1::TargetAckCollecting(_)
            | RestartLifecycleV1::TargetAcked(_) => None,
        }) else {
            return Ok(false);
        };
        let snapshot = self.restart_quiescence_snapshot_v1()?;
        if !is_restart_quiescent_v1(&snapshot) {
            return Ok(false);
        }
        let signer_exact_watermark = snapshot.signer_exact_watermark.ok_or_else(|| {
            anyhow!("quiescent predicate admitted a missing exact signer watermark")
        })?;
        let journal_predecessor = (snapshot.journal_head_sequence, snapshot.journal_head_sha256);
        let quiesced = LocalRestartQuiescedOwnerV1 {
            facts: LocalRestartQuiescedFactsV1 {
                intent,
                local_validator: self.config.local_validator(),
                current_view: snapshot.current_view,
                high_qc: snapshot.high_qc,
                finalized_height: snapshot.finalized_height,
                finalized_block_id: snapshot.finalized_block_id,
                finalized_chain_root: snapshot.finalized_chain_root,
                application_height: snapshot.application_height,
                application_block_id: snapshot.application_block_id,
                application_state_root: snapshot.application_state_root,
                proposal_parent_height: snapshot.proposal_parent_height,
                proposal_parent_block_id: snapshot.proposal_parent_block_id,
                signed_vote_intents: snapshot.signed_vote_intents,
                signed_timeout_intents: snapshot.signed_timeout_intents,
                signer_durable_vote_intent_count: snapshot.signer_durable_vote_intent_count,
                signer_durable_timeout_intent_count: snapshot.signer_durable_timeout_intent_count,
                signer_signed_vote_intent_count: snapshot.signer_signed_vote_intent_count,
                signer_signed_timeout_intent_count: snapshot.signer_signed_timeout_intent_count,
                signer_inventory_digest: snapshot.signer_inventory_digest,
                signer_exact_watermark,
                safety_revision: snapshot.safety_revision,
                safety_record_checksum: snapshot.safety_record_checksum,
                safety_chain_checksum: snapshot.safety_chain_checksum,
                signer_watermark_sequence: snapshot.signer_watermark_sequence,
                checkpoint_generation: snapshot.checkpoint_generation,
                checkpoint_canonical_sha256: snapshot.checkpoint_canonical_sha256,
                replay_archive_context_sha256: snapshot.replay_archive_context_sha256,
                replay_archive_head_sequence: snapshot.replay_archive_head_sequence,
                replay_archive_head_sha256: snapshot.replay_archive_head_sha256,
                journal_predecessor_sequence: journal_predecessor.0,
                journal_predecessor_sha256: journal_predecessor.1,
            },
        };
        let event = self
            .event_journal
            .record_restart_prepare_from_owner_v1(&quiesced)
            .map_err(|error| anyhow!("append owner-authenticated restart prepare: {error}"))?;
        let journal_successor = self
            .event_journal
            .last_event_facts()
            .ok_or_else(|| anyhow!("restart prepare lost its journal successor"))?;
        ensure!(
            event.sequence == journal_successor.0
                && event.event_sha256 == hex::encode(journal_successor.1)
                && self.event_journal.observation().restart_prepare_nonce
                    == Some(intent.nonce_v1()),
            "restart prepare journal fresh readback differs"
        );
        let prepared = quiesced.into_prepared_v1(journal_successor.0, journal_successor.1)?;
        let prepared =
            prepared.into_signed_target_prepare_v1(&self.config, &self.fleet_start_certificate)?;
        let target_prepare = prepared.target_prepare_v1().clone();
        ensure!(
            self.restart_round
                .admitted_statements
                .values()
                .all(|statement| statement.statement_v1().body() == target_prepare.body()),
            "an early Cut/Park statement differs from the local target Prepare"
        );
        self.runtime_control
            .as_mut()
            .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
            .refresh_from_journal(&self.event_journal)
            .context("refresh control after owner-authenticated restart prepare")?;
        let prepare_reservation = self.enqueue_restart_statement_v1(
            RestartProtocolPhaseV1::Prepare,
            target_prepare.encode(),
        )?;
        let originated_prepare = OriginatedRestartPrepareV1::new(
            prepare_reservation,
            target_prepare.clone(),
            &self.fleet_start_certificate,
            self.config.validator_set(),
        )
        .map_err(|error| anyhow!("join local Prepare to its originated slot: {error}"))?;

        let local_park = LocalRestartParkV1::new(
            RestartParkRoleV1::Target,
            self.config.local_validator(),
            self.config.config_sha256(),
            1,
            target_prepare.body(),
            target_prepare.body().state(),
            &self.fleet_start_certificate,
            self.config.validator_set(),
        )
        .map_err(|error| anyhow!("construct target local park: {error}"))?;
        let authority = self
            .authority
            .take()
            .ok_or_else(|| anyhow!("target restart parking lacks continuous authority"))?;
        let declared = authority
            .into_restart_parked_authority_v1()
            .context("consume target continuous authority into restart park")?
            .into_target_restart_cut_park_v1(
                &self.config,
                target_prepare,
                local_park,
                &self.fleet_start_certificate,
            )
            .context("issue sole target Cut/Park declaration")?;
        let cut_park_payload = declared.statement_v1().encode();
        let cut_park_reservation =
            self.enqueue_restart_statement_v1(RestartProtocolPhaseV1::Cut, cut_park_payload)?;
        let originated_cut_park = OriginatedRestartCutParkV1::new(
            cut_park_reservation,
            declared,
            &self.fleet_start_certificate,
            self.config.validator_set(),
        )
        .map_err(|error| anyhow!("join local Cut/Park to its originated slot: {error}"))?;
        self.restart_lifecycle =
            RestartLifecycleV1::TargetCollecting(LocalRestartTargetCollectingOwnerV1 {
                prepared,
                originated_prepare,
                originated_cut_park,
            });
        ensure!(
            self.authority.is_none(),
            "target restart park retained ordinary continuous authority"
        );
        self.terminal_candidate_since = None;
        Ok(true)
    }

    fn maybe_complete_peer_park_v1(&mut self) -> Result<bool> {
        let shared_cut = match &self.restart_lifecycle {
            RestartLifecycleV1::PeerQuiescing(owner) => {
                owner.admitted_prepare.body_v1().shared_cut_v1()
            }
            RestartLifecycleV1::Running
            | RestartLifecycleV1::TargetQuiescing(_)
            | RestartLifecycleV1::TargetCollecting(_)
            | RestartLifecycleV1::PeerCollecting(_)
            | RestartLifecycleV1::PeerBarrier(_)
            | RestartLifecycleV1::PeerParked(_)
            | RestartLifecycleV1::PeerAckCollecting(_)
            | RestartLifecycleV1::PeerAcked(_)
            | RestartLifecycleV1::TargetBarrier(_)
            | RestartLifecycleV1::TargetParked(_)
            | RestartLifecycleV1::TargetAckCollecting(_)
            | RestartLifecycleV1::TargetAcked(_) => return Ok(false),
        };
        let snapshot = self.restart_quiescence_snapshot_v1()?;
        if !is_restart_common_quiescent_v1(&snapshot)
            || !peer_restart_shared_cut_ready_v1(&snapshot, shared_cut)?
        {
            return Ok(false);
        }
        let lifecycle = std::mem::replace(&mut self.restart_lifecycle, RestartLifecycleV1::Running);
        let peer = match lifecycle {
            RestartLifecycleV1::PeerQuiescing(owner) => owner,
            other => {
                self.restart_lifecycle = other;
                bail!("peer park completed outside its quiescing lifecycle")
            }
        };
        ensure!(
            peer.admitted_prepare.body_v1().shared_cut_v1() == shared_cut
                && peer.admitted_prepare.body_v1().target_validator()
                    != self.config.local_validator()
                && peer.admitted_prepare.body_v1().process_instance() == 1,
            "peer quiescing owner changed before its durable park marker"
        );
        let journal_predecessor = (snapshot.journal_head_sequence, snapshot.journal_head_sha256);
        let local_state = restart_cut_state_from_quiescent_snapshot_v1(
            snapshot,
            self.config.validator_set().epoch(),
            journal_predecessor,
        )?;
        let quiesced = LocalRestartPeerQuiescedOwnerV1 {
            admitted_prepare: peer.admitted_prepare,
            local_validator: self.config.local_validator(),
            local_config_sha256: self.config.config_sha256(),
            local_state,
            journal_predecessor,
        };
        let event = self
            .event_journal
            .record_restart_park_prepare_from_owner_v1(&quiesced)
            .map_err(|error| anyhow!("append owner-authenticated peer park prepare: {error}"))?;
        let journal_successor = self
            .event_journal
            .last_event_facts()
            .ok_or_else(|| anyhow!("peer park prepare lost its journal successor"))?;
        ensure!(
            event.sequence == journal_successor.0
                && event.event_sha256 == hex::encode(journal_successor.1)
                && self.event_journal.restart_phase_v1()
                    == RuntimeRestartPhaseV1::Process1PeerParkPreparePending,
            "peer park-prepare journal fresh readback differs"
        );
        let prepared = quiesced.into_prepared_v1(journal_successor.0, journal_successor.1)?;
        let local_park = LocalRestartParkV1::new(
            RestartParkRoleV1::Peer,
            prepared.local_validator,
            prepared.local_config_sha256,
            1,
            prepared.admitted_prepare.body_v1(),
            prepared.local_state,
            &self.fleet_start_certificate,
            self.config.validator_set(),
        )
        .map_err(|error| anyhow!("construct peer local park: {error}"))?;
        self.runtime_control
            .as_mut()
            .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
            .refresh_from_journal(&self.event_journal)
            .context("refresh control after owner-authenticated peer park prepare")?;
        let authority = self
            .authority
            .take()
            .ok_or_else(|| anyhow!("peer restart parking lacks continuous authority"))?;
        let declared = authority
            .into_restart_parked_authority_v1()
            .context("consume peer continuous authority into restart park")?
            .into_peer_restart_cut_park_v1(
                &self.config,
                prepared.admitted_prepare.declaration_v1(),
                local_park,
                &self.fleet_start_certificate,
            )
            .context("issue sole peer Cut/Park declaration")?;
        let payload = declared.statement_v1().encode();
        let reservation =
            self.enqueue_restart_statement_v1(RestartProtocolPhaseV1::Cut, payload)?;
        let originated_cut_park = OriginatedRestartCutParkV1::new(
            reservation,
            declared,
            &self.fleet_start_certificate,
            self.config.validator_set(),
        )
        .map_err(|error| anyhow!("join peer Cut/Park to its originated slot: {error}"))?;
        self.restart_lifecycle =
            RestartLifecycleV1::PeerCollecting(LocalRestartPeerCollectingOwnerV1 {
                prepared,
                originated_cut_park,
            });
        ensure!(
            self.authority.is_none(),
            "peer restart park retained ordinary continuous authority"
        );
        self.terminal_candidate_since = None;
        Ok(true)
    }

    fn maybe_complete_peer_restart_cut_v1(&mut self) -> Result<bool> {
        if matches!(self.restart_lifecycle, RestartLifecycleV1::PeerBarrier(_)) {
            let lifecycle =
                std::mem::replace(&mut self.restart_lifecycle, RestartLifecycleV1::Running);
            let owner = match lifecycle {
                RestartLifecycleV1::PeerBarrier(owner) => owner,
                other => {
                    self.restart_lifecycle = other;
                    bail!("peer Cut/Park persistence began outside peer barrier lifecycle")
                }
            };
            let parked = owner
                .barrier
                .persist_peer_v1(&self.config, &self.fleet_start_certificate)
                .context("persist phase-bound peer RestartCut/RestartPark pair")?;
            let (_cut_event, park_event, journal_commit) = self
                .event_journal
                .record_peer_restart_cut_park_from_owner_v1(&owner.prepared, &parked)
                .map_err(|error| {
                    anyhow!("append owner-authenticated peer RestartCut/RestartPark chain: {error}")
                })?;
            let stored = parked.stored_v1();
            ensure!(
                self.event_journal
                    .last_event_facts()
                    .is_some_and(|(sequence, sha256)| {
                        sequence == park_event.sequence
                            && hex::encode(sha256) == park_event.event_sha256
                    })
                    && self.event_journal.restart_phase_v1()
                        == RuntimeRestartPhaseV1::Process1PeerParked
                    && self.event_journal.restart_cut_facts_v1()
                        == Some((
                            stored.cut_artifact_sha256_v1(),
                            u64::try_from(stored.statement_count_v1())
                                .context("peer Cut/Park statement count does not fit u64")?,
                        )),
                "peer RestartCut/RestartPark journal fresh observation differs"
            );
            self.runtime_control
                .as_mut()
                .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
                .refresh_from_journal(&self.event_journal)
                .context("refresh control after peer RestartPark commit")?;
            self.restart_lifecycle =
                RestartLifecycleV1::PeerParked(LocalRestartPeerParkedOwnerV1 {
                    prepared: owner.prepared,
                    parked,
                    journal_commit,
                });
            self.terminal_candidate_since = None;
            return Ok(true);
        }
        if matches!(self.restart_lifecycle, RestartLifecycleV1::PeerParked(_)) {
            return Ok(false);
        }
        let RestartLifecycleV1::PeerCollecting(owner) = &self.restart_lifecycle else {
            return Ok(false);
        };
        ensure!(
            owner.prepared.admitted_prepare.body_v1().target_validator()
                != self.config.local_validator()
                && owner.prepared.admitted_prepare.body_v1().process_instance() == 1
                && self.event_journal.restart_phase_v1()
                    == RuntimeRestartPhaseV1::Process1PeerParkPreparePending,
            "peer collector differs from its durable park preparation"
        );
        if self.restart_round.admitted_statements.len() != 6 {
            return Ok(false);
        }
        if !self.outbox.is_empty()
            || !self.unavailable_sessions.is_empty()
            || self.mesh_v1()?.pending_outbound_bytes_v1()? != 0
        {
            return Ok(false);
        }
        ensure!(
            self.config
                .validator_set()
                .validators()
                .iter()
                .filter(|validator| validator.id() != self.config.local_validator())
                .all(|validator| self
                    .restart_round
                    .admitted_statements
                    .contains_key(&validator.id())),
            "peer six-way remote Cut/Park collector has a foreign or missing signer"
        );
        let lifecycle = std::mem::replace(&mut self.restart_lifecycle, RestartLifecycleV1::Running);
        let owner = match lifecycle {
            RestartLifecycleV1::PeerCollecting(owner) => owner,
            other => {
                self.restart_lifecycle = other;
                bail!("peer Cut/Park barrier completed outside peer collector lifecycle")
            }
        };
        let admitted = std::mem::take(&mut self.restart_round.admitted_statements)
            .into_values()
            .collect();
        let (prepared, admitted_prepare) = owner.prepared.into_barrier_parts_v1();
        let barrier = VerifiedRestartCutParkCertificatesV1::new_with_originated_cut_v1(
            admitted_prepare,
            admitted,
            owner.originated_cut_park,
            &self.fleet_start_certificate,
            self.config.validator_set(),
        )
        .map_err(|error| anyhow!("form phase-bound peer N/N RestartCut/Park barrier: {error}"))?;
        barrier
            .revalidate_v1(&self.fleet_start_certificate, self.config.validator_set())
            .map_err(|error| anyhow!("revalidate phase-bound peer Cut/Park barrier: {error}"))?;
        ensure!(
            barrier.statement_count_v1() == 7
                && barrier.body_v1() == prepared.target_prepare_v1().body()
                && barrier.prepare_message_id_v1() == prepared.prepare_message_id_v1(),
            "formed peer Cut/Park barrier differs from its durable preparation"
        );
        self.restart_lifecycle =
            RestartLifecycleV1::PeerBarrier(LocalRestartPeerBarrierOwnerV1 { prepared, barrier });
        self.terminal_candidate_since = None;
        Ok(true)
    }

    fn maybe_complete_restart_cut_v1(&mut self) -> Result<bool> {
        if matches!(self.restart_lifecycle, RestartLifecycleV1::TargetBarrier(_)) {
            let lifecycle =
                std::mem::replace(&mut self.restart_lifecycle, RestartLifecycleV1::Running);
            let owner = match lifecycle {
                RestartLifecycleV1::TargetBarrier(owner) => owner,
                other => {
                    self.restart_lifecycle = other;
                    bail!("RestartCut/Park persistence began outside target barrier lifecycle")
                }
            };
            let parked = owner
                .barrier
                .persist_target_v1(&self.config, &self.fleet_start_certificate)
                .context("persist phase-bound target RestartCut/RestartPark pair")?;
            let stored = parked.stored_v1();
            let (_cut_event, park_event, journal_commit) = self
                .event_journal
                .record_restart_cut_park_from_owner_v1(&owner.prepared, stored)
                .map_err(|error| {
                    anyhow!("append owner-authenticated RestartCut/RestartPark chain: {error}")
                })?;
            ensure!(
                self.event_journal
                    .last_event_facts()
                    .is_some_and(|(sequence, sha256)| {
                        sequence == park_event.sequence
                            && hex::encode(sha256) == park_event.event_sha256
                    })
                    && self.event_journal.restart_cut_facts_v1()
                        == Some((
                            stored.cut_artifact_sha256_v1(),
                            u64::try_from(stored.statement_count_v1())
                                .context("RestartCut/Park statement count does not fit u64")?,
                        )),
                "target RestartCut/RestartPark journal fresh observation differs"
            );
            self.runtime_control
                .as_mut()
                .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
                .refresh_from_journal(&self.event_journal)
                .context("refresh control after target RestartPark commit")?;
            self.restart_lifecycle =
                RestartLifecycleV1::TargetParked(LocalRestartTargetParkedOwnerV1 {
                    prepared: owner.prepared,
                    parked,
                    journal_commit,
                });
            self.terminal_candidate_since = None;
            return Ok(true);
        }
        if matches!(self.restart_lifecycle, RestartLifecycleV1::TargetParked(_)) {
            return Ok(false);
        }
        let RestartLifecycleV1::TargetCollecting(owner) = &self.restart_lifecycle else {
            return Ok(false);
        };
        let target_prepare = owner.prepared.target_prepare_v1();
        ensure!(
            target_prepare.body().target_validator() == self.config.local_validator()
                && target_prepare.body().runtime_journal_head_v1()
                    == owner.prepared.journal_successor_v1(),
            "prepared target owner differs from its originated RestartPrepare"
        );
        if self.restart_round.admitted_statements.len() != 6 {
            return Ok(false);
        }
        if !self.outbox.is_empty()
            || !self.unavailable_sessions.is_empty()
            || self.mesh_v1()?.pending_outbound_bytes_v1()? != 0
        {
            return Ok(false);
        }
        ensure!(
            self.config
                .validator_set()
                .validators()
                .iter()
                .filter(|validator| validator.id() != self.config.local_validator())
                .all(|validator| self
                    .restart_round
                    .admitted_statements
                    .contains_key(&validator.id())),
            "six-way remote Cut/Park collector has a foreign or missing signer"
        );
        let lifecycle = std::mem::replace(&mut self.restart_lifecycle, RestartLifecycleV1::Running);
        let owner = match lifecycle {
            RestartLifecycleV1::TargetCollecting(owner) => owner,
            other => {
                self.restart_lifecycle = other;
                bail!("Cut/Park barrier completed outside target collector lifecycle")
            }
        };
        let admitted = std::mem::take(&mut self.restart_round.admitted_statements)
            .into_values()
            .collect();
        let barrier = VerifiedRestartCutParkCertificatesV1::new_with_originated_prepare_v1(
            owner.originated_prepare,
            admitted,
            owner.originated_cut_park,
            &self.fleet_start_certificate,
            self.config.validator_set(),
        )
        .map_err(|error| anyhow!("form phase-bound N/N RestartCut/Park barrier: {error}"))?;
        barrier
            .revalidate_v1(&self.fleet_start_certificate, self.config.validator_set())
            .map_err(|error| anyhow!("revalidate phase-bound RestartCut/Park barrier: {error}"))?;
        ensure!(
            barrier.statement_count_v1() == 7
                && barrier.body_v1() == owner.prepared.target_prepare_v1().body(),
            "formed RestartCut/Park barrier differs from the local target owner"
        );
        self.restart_lifecycle =
            RestartLifecycleV1::TargetBarrier(LocalRestartTargetBarrierOwnerV1 {
                prepared: owner.prepared,
                barrier,
            });
        self.terminal_candidate_since = None;
        Ok(true)
    }

    /// Strictly decodes ParkedAcks whose authenticated fifth-phase slots
    /// arrived before this process had its exact durable Cut/Park pair. The
    /// ingress owners remain bounded and non-Clone while pending; bytes are
    /// never treated as an Ack until the local stored pair is available.
    fn authenticate_pending_restart_parked_acks_v1(&mut self) -> Result<bool> {
        if self.restart_round.pending_parked_acks.is_empty()
            || self.restart_parked_ack_stored_v1().is_none()
        {
            return Ok(false);
        }
        ensure!(
            self.restart_round.pending_parked_acks.len()
                + self.restart_round.admitted_parked_acks.len()
                <= 6,
            "pending ParkedAck collector exceeds the six remote direct-seven slots"
        );
        let pending = std::mem::take(&mut self.restart_round.pending_parked_acks);
        let authenticated = {
            let stored = self
                .restart_parked_ack_stored_v1()
                .expect("checked durable Cut/Park owner remains present");
            pending
                .into_iter()
                .map(|(origin, admission)| {
                    let statement =
                        AdmittedRestartParkedAckV1::new(admission, stored).map_err(|error| {
                            anyhow!("authenticate early phase-bound RestartParkedAck: {error}")
                        })?;
                    ensure!(
                        statement.statement_v1().origin() == origin,
                        "early ParkedAck map key differs from its authenticated origin"
                    );
                    Ok((origin, statement))
                })
                .collect::<Result<Vec<_>>>()?
        };
        for (origin, statement) in authenticated {
            ensure!(
                self.restart_round
                    .admitted_parked_acks
                    .insert(origin, statement)
                    .is_none(),
                "early ParkedAck replaced one already authenticated remote slot"
            );
        }
        Ok(true)
    }

    fn restart_parked_ack_drain_ready_v1(&self) -> Result<bool> {
        Ok(self.outbox.is_empty()
            && self.unavailable_sessions.is_empty()
            && self.mesh_v1()?.pending_outbound_bytes_v1()? == 0)
    }

    /// Issues the sole local fifth-phase Ack only after `rpk1`, then forms,
    /// stores, and journals the one-local-plus-six-remote direct-seven Ack
    /// barrier. Both Acked lifecycle states remain parked and expose no
    /// RecoveryReady, RecoveryStart, timer, signer, or activation path.
    fn maybe_complete_restart_parked_ack_v1(&mut self) -> Result<bool> {
        if !matches!(
            self.restart_lifecycle,
            RestartLifecycleV1::PeerParked(_)
                | RestartLifecycleV1::PeerAckCollecting(_)
                | RestartLifecycleV1::TargetParked(_)
                | RestartLifecycleV1::TargetAckCollecting(_)
        ) {
            return Ok(false);
        }
        self.require_direct_seven_restart_park_v1()?;
        let mut progressed = self.authenticate_pending_restart_parked_acks_v1()?;

        if matches!(
            self.restart_lifecycle,
            RestartLifecycleV1::PeerParked(_) | RestartLifecycleV1::TargetParked(_)
        ) {
            if !self.restart_parked_ack_drain_ready_v1()? {
                return Ok(progressed);
            }
            let lifecycle =
                std::mem::replace(&mut self.restart_lifecycle, RestartLifecycleV1::Running);
            match lifecycle {
                RestartLifecycleV1::PeerParked(owner) => {
                    self.event_journal
                        .revalidate_local_restart_park_commit_v1(&owner.journal_commit)
                        .map_err(|error| {
                            anyhow!(
                                "freshly revalidate peer rpk1 before ParkedAck signing: {error}"
                            )
                        })?;
                    let declaration = owner
                        .parked
                        .into_parked_ack_declaration_v1(owner.journal_commit, &self.config)
                        .context("issue sole peer RestartParkedAck after durable rpk1")?;
                    self.event_journal
                        .revalidate_local_restart_park_commit_v1(declaration.journal_commit_v1())
                        .map_err(|error| {
                            anyhow!(
                                "freshly revalidate peer rpk1 before ParkedAck enqueue: {error}"
                            )
                        })?;
                    let payload = declaration.statement_v1().encode();
                    let reservation = self
                        .enqueue_restart_statement_v1(RestartProtocolPhaseV1::ParkedAck, payload)?;
                    let originated_ack =
                        OriginatedRestartParkedAckV1::new(reservation, declaration).context(
                            "join peer RestartParkedAck to its originated fifth-phase slot",
                        )?;
                    self.restart_lifecycle = RestartLifecycleV1::PeerAckCollecting(
                        LocalRestartPeerAckCollectingOwnerV1 {
                            prepared: owner.prepared,
                            originated_ack,
                        },
                    );
                }
                RestartLifecycleV1::TargetParked(owner) => {
                    self.event_journal
                        .revalidate_local_restart_park_commit_v1(&owner.journal_commit)
                        .map_err(|error| {
                            anyhow!(
                                "freshly revalidate target rpk1 before ParkedAck signing: {error}"
                            )
                        })?;
                    let declaration = owner
                        .parked
                        .into_parked_ack_declaration_v1(owner.journal_commit, &self.config)
                        .context("issue sole target RestartParkedAck after durable rpk1")?;
                    self.event_journal
                        .revalidate_local_restart_park_commit_v1(declaration.journal_commit_v1())
                        .map_err(|error| {
                            anyhow!(
                                "freshly revalidate target rpk1 before ParkedAck enqueue: {error}"
                            )
                        })?;
                    let payload = declaration.statement_v1().encode();
                    let reservation = self
                        .enqueue_restart_statement_v1(RestartProtocolPhaseV1::ParkedAck, payload)?;
                    let originated_ack =
                        OriginatedRestartParkedAckV1::new(reservation, declaration).context(
                            "join target RestartParkedAck to its originated fifth-phase slot",
                        )?;
                    self.restart_lifecycle = RestartLifecycleV1::TargetAckCollecting(
                        LocalRestartTargetAckCollectingOwnerV1 {
                            prepared: owner.prepared,
                            originated_ack,
                        },
                    );
                }
                other => {
                    self.restart_lifecycle = other;
                    bail!("local ParkedAck issuance began outside one durable parked lifecycle")
                }
            }
            self.terminal_candidate_since = None;
            return Ok(true);
        }

        ensure!(
            self.restart_round.pending_parked_acks.is_empty(),
            "ParkedAck aggregation retained unauthenticated early slots after local durability"
        );
        if self.restart_round.admitted_parked_acks.len() != 6
            || !self.restart_parked_ack_drain_ready_v1()?
        {
            return Ok(progressed);
        }
        ensure!(
            self.config
                .validator_set()
                .validators()
                .iter()
                .filter(|validator| validator.id() != self.config.local_validator())
                .all(|validator| self
                    .restart_round
                    .admitted_parked_acks
                    .contains_key(&validator.id())),
            "six-way remote ParkedAck collector has a foreign or missing signer"
        );
        let admitted = std::mem::take(&mut self.restart_round.admitted_parked_acks)
            .into_values()
            .collect::<Vec<_>>();
        let lifecycle = std::mem::replace(&mut self.restart_lifecycle, RestartLifecycleV1::Running);
        match lifecycle {
            RestartLifecycleV1::PeerAckCollecting(owner) => {
                let barrier = VerifiedRestartParkedAckBarrierV1::new_with_originated_v1(
                    admitted,
                    owner.originated_ack,
                )
                .context("form phase-bound peer N/N RestartParkedAck barrier")?;
                let acknowledged = barrier
                    .persist_v1(&self.config)
                    .context("persist peer N/N RestartParkedAck certificate")?;
                acknowledged
                    .revalidate_fresh_v1()
                    .context("fresh-revalidate peer durable RestartParkedAck composite")?;
                let ack_event = self
                    .event_journal
                    .record_restart_parked_ack_from_owner_v1(&acknowledged)
                    .map_err(|error| {
                        anyhow!("append owner-authenticated peer RestartParkedAck: {error}")
                    })?;
                ensure!(
                    self.event_journal
                        .last_event_facts()
                        .is_some_and(|(sequence, sha256)| {
                            sequence == ack_event.sequence
                                && hex::encode(sha256) == ack_event.event_sha256
                        })
                        && self.event_journal.restart_phase_v1()
                            == RuntimeRestartPhaseV1::Process1PeerParkedAcked
                        && acknowledged.ack_certificate_v1().statement_count() == 7
                        && acknowledged.ack_artifact_sha256_v1() != [0; 32]
                        && acknowledged.ack_admission_set_sha256_v1() != [0; 32],
                    "peer RestartParkedAck journal fresh observation differs"
                );
                self.runtime_control
                    .as_mut()
                    .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
                    .refresh_from_journal(&self.event_journal)
                    .context("refresh control after peer RestartParkedAck commit")?;
                self.restart_lifecycle =
                    RestartLifecycleV1::PeerAcked(LocalRestartPeerAckedOwnerV1 {
                        prepared: owner.prepared,
                        acknowledged,
                    });
            }
            RestartLifecycleV1::TargetAckCollecting(owner) => {
                let barrier = VerifiedRestartParkedAckBarrierV1::new_with_originated_v1(
                    admitted,
                    owner.originated_ack,
                )
                .context("form phase-bound target N/N RestartParkedAck barrier")?;
                let acknowledged = barrier
                    .persist_v1(&self.config)
                    .context("persist target N/N RestartParkedAck certificate")?;
                acknowledged
                    .revalidate_fresh_v1()
                    .context("fresh-revalidate target durable RestartParkedAck composite")?;
                let ack_event = self
                    .event_journal
                    .record_restart_parked_ack_from_owner_v1(&acknowledged)
                    .map_err(|error| {
                        anyhow!("append owner-authenticated target RestartParkedAck: {error}")
                    })?;
                ensure!(
                    self.event_journal
                        .last_event_facts()
                        .is_some_and(|(sequence, sha256)| {
                            sequence == ack_event.sequence
                                && hex::encode(sha256) == ack_event.event_sha256
                        })
                        && self.event_journal.restart_phase_v1()
                            == RuntimeRestartPhaseV1::Process1TargetParkedAcked
                        && acknowledged.ack_certificate_v1().statement_count() == 7
                        && acknowledged.ack_artifact_sha256_v1() != [0; 32]
                        && acknowledged.ack_admission_set_sha256_v1() != [0; 32],
                    "target RestartParkedAck journal fresh observation differs"
                );
                self.runtime_control
                    .as_mut()
                    .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
                    .refresh_from_journal(&self.event_journal)
                    .context("refresh control after target RestartParkedAck commit")?;
                self.restart_lifecycle =
                    RestartLifecycleV1::TargetAcked(LocalRestartTargetAckedOwnerV1 {
                        prepared: owner.prepared,
                        acknowledged,
                    });
            }
            other => {
                self.restart_lifecycle = other;
                bail!("ParkedAck barrier completed outside one Ack-collecting lifecycle")
            }
        }
        progressed = true;
        self.terminal_candidate_since = None;
        Ok(progressed)
    }

    /// Projects only conditions owned by the authenticated peer lifecycle.
    /// A control request merely selects which condition to watch. The signed
    /// journal transition is emitted only after the mesh has independently
    /// reported the exact direction set, and recovery additionally requires
    /// both directions plus later finalized progress.
    fn reconcile_expected_connectivity_fault_v1(&mut self) -> Result<bool> {
        if let Some(active) = self.active_connectivity_fault {
            let still_unavailable = self
                .unavailable_sessions
                .iter()
                .any(|(_, remote)| *remote == active.remote);
            if still_unavailable {
                return Ok(false);
            }
            let finalized_height = self.authority_v1()?.facts_v0()?.finalized_height_v0();
            if finalized_height <= active.applied_finalized_height {
                return Ok(false);
            }
            self.event_journal
                .record_fault_recovered(active.fault, finalized_height)
                .map_err(|error| anyhow!("append observed fault recovery: {error}"))?;
            self.active_connectivity_fault = None;
            self.runtime_control
                .as_mut()
                .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
                .refresh_from_journal(&self.event_journal)
                .context("refresh control after observed fault recovery")?;
            return Ok(true);
        }

        let Some(expected) = self
            .runtime_control
            .as_ref()
            .and_then(RuntimeControlServerV1::expected_fault)
        else {
            return Ok(false);
        };
        let facts = self.authority_v1()?.facts_v0()?;
        let scheduled_leader = leader_for(self.config.validator_set(), facts.current_view_v0());
        let remote = observed_connectivity_fault_subject_v1(
            expected,
            self.config.local_validator(),
            scheduled_leader,
            &self.unavailable_sessions,
        );
        let Some(remote) = remote else {
            // Process kill, bounded delay/loss, storage rollback/snapshot, and
            // epoch handoff have no authoritative observation on this seam.
            // They intentionally remain pending rather than becoming claims.
            return Ok(false);
        };
        self.event_journal
            .record_fault_applied(expected)
            .map_err(|error| anyhow!("append observed fault application: {error}"))?;
        self.active_connectivity_fault = Some(ObservedConnectivityFaultV1 {
            fault: expected,
            remote,
            applied_finalized_height: facts.finalized_height_v0(),
        });
        self.runtime_control
            .as_mut()
            .ok_or_else(|| anyhow!("bounded runtime control owner is unavailable"))?
            .refresh_from_journal(&self.event_journal)
            .context("refresh control after observed fault application")?;
        Ok(true)
    }

    fn handle_routed_action_v1(&mut self, action: RoutedConsensusActionV0) -> Result<bool> {
        match action {
            RoutedConsensusActionV0::Proposal(proposal) => {
                self.queue_or_vote_proposal_v1(*proposal)?;
                Ok(true)
            }
            RoutedConsensusActionV0::Vote { vote, formed_qc } => {
                if let Some(certificate) = formed_qc {
                    if self.is_qc_aggregator_v1(&certificate)? {
                        self.queue_certificate_v1(PendingCertificateV1::Quorum {
                            certificate: *certificate,
                            publish: true,
                        })?;
                        self.drain_pending_certificates_v1()?;
                    }
                }
                let _ = vote;
                Ok(true)
            }
            RoutedConsensusActionV0::TimeoutVote { vote, formed_tc } => {
                if let Some(certificate) = formed_tc {
                    if self.is_tc_aggregator_v1(&certificate)? {
                        self.queue_certificate_v1(PendingCertificateV1::Timeout {
                            certificate: *certificate,
                            publish: true,
                        })?;
                        self.drain_pending_certificates_v1()?;
                    }
                }
                let _ = vote;
                Ok(true)
            }
            RoutedConsensusActionV0::QuorumCertificate(certificate) => {
                self.queue_certificate_v1(PendingCertificateV1::Quorum {
                    certificate: *certificate,
                    publish: false,
                })?;
                self.drain_pending_certificates_v1()?;
                Ok(true)
            }
            RoutedConsensusActionV0::TimeoutCertificate(certificate) => {
                self.queue_certificate_v1(PendingCertificateV1::Timeout {
                    certificate: *certificate,
                    publish: false,
                })?;
                self.drain_pending_certificates_v1()?;
                Ok(true)
            }
        }
    }

    fn queue_or_vote_proposal_v1(&mut self, proposal: UnboundProposalV0) -> Result<()> {
        let block_id = proposal.block().id();
        let height = proposal.block().header().height().get();
        ensure!(
            height <= self.preflight.target_height,
            "proposal exceeds the requested bounded height"
        );
        self.record_proposal_first_seen_v1(block_id, height)?;
        let high_qc = self.authority_v1()?.facts_v0()?.high_qc_v0();
        match self
            .pending_proposals
            .admit_v1(proposal, high_qc, &self.known_executions)?
        {
            PendingProposalAdmissionV1::Vote(proposal) => self.vote_ready_proposal_v1(*proposal),
            PendingProposalAdmissionV1::Buffered => Ok(()),
            PendingProposalAdmissionV1::IgnoreStale(block_id) => {
                forget_proposal_first_seen_v1(&mut self.proposal_first_seen, block_id);
                Ok(())
            }
        }
    }

    fn vote_ready_proposal_v1(&mut self, proposal: UnboundProposalV0) -> Result<()> {
        let block_id = proposal.block().id();
        let height = proposal.block().header().height().get();
        self.archive_proposal_before_authority_v1(&proposal)?;
        let vote = self.authority_v1()?.vote_unbound_proposal_v0(proposal)?;
        self.record_proposal_admitted_v1(block_id, height)?;
        self.known_executions.insert((height, *block_id.as_bytes()));
        self.highest_submitted_height = self.highest_submitted_height.max(height);
        self.emit_local_vote_v1(vote)?;
        self.drain_pending_certificates_v1()?;
        Ok(())
    }

    fn drain_pending_proposals_v1(&mut self) -> Result<bool> {
        let mut progressed = false;
        loop {
            let high_qc = self.authority_v1()?.facts_v0()?.high_qc_v0();
            let Some(admission) = self
                .pending_proposals
                .take_actionable_v1(high_qc, &self.known_executions)
            else {
                break;
            };
            match admission {
                PendingProposalAdmissionV1::Vote(proposal) => {
                    self.vote_ready_proposal_v1(*proposal)?;
                }
                PendingProposalAdmissionV1::IgnoreStale(block_id) => {
                    forget_proposal_first_seen_v1(&mut self.proposal_first_seen, block_id);
                }
                PendingProposalAdmissionV1::Buffered => {
                    unreachable!("only actionable pending proposals are removed")
                }
            }
            progressed = true;
        }
        Ok(progressed)
    }

    fn emit_local_vote_v1(&mut self, vote: trnm_consensus_types::Vote) -> Result<()> {
        self.enqueue_consensus_statement_v1(FrameKind::Vote, encode_vote(&vote))?;
        self.event_journal
            .append(
                RuntimeEventKindV1::VoteBroadcast,
                &hex::encode(vote.block_id().as_bytes()),
                vote.height().get(),
            )
            .map_err(|error| anyhow!("append Vote broadcast event: {error}"))?;
        if let Some(certificate) = self.authority_v1()?.admit_local_vote_v0(vote)? {
            if self.is_qc_aggregator_v1(&certificate)? {
                self.queue_certificate_v1(PendingCertificateV1::Quorum {
                    certificate,
                    publish: true,
                })?;
            }
        }
        Ok(())
    }

    fn poll_pacemaker_v1(&mut self, now: Instant) -> Result<bool> {
        if !self.restart_lifecycle.is_running_v1() || self.stopping_since.is_some() {
            return Ok(false);
        }
        let Some(expiry) = self.pacemaker.poll(now) else {
            return Ok(false);
        };
        let facts = self.authority_v1()?.facts_v0()?;
        ensure!(
            expiry.epoch() == self.config.validator_set().epoch()
                && expiry.view() == facts.current_view_v0()
                && self.pacemaker.validate_generation(
                    expiry.epoch(),
                    expiry.view(),
                    expiry.generation(),
                ),
            "pacemaker expiry differs from authoritative current view"
        );
        let vote = self.authority_v1()?.begin_local_timeout_v0()?;
        self.enqueue_consensus_statement_v1(FrameKind::TimeoutVote, encode_timeout_vote(&vote))?;
        self.event_journal
            .append(
                RuntimeEventKindV1::TimeoutVoteBroadcast,
                &hex::encode(vote.high_qc().qc_digest().as_bytes()),
                vote.view().get(),
            )
            .map_err(|error| anyhow!("append TimeoutVote broadcast event: {error}"))?;
        let formed = self.authority_v1()?.admit_local_timeout_vote_v0(vote)?;
        self.pacemaker.confirm_timeout_emitted(expiry)?;
        if let Some(certificate) = formed {
            if self.is_tc_aggregator_v1(&certificate)? {
                self.queue_certificate_v1(PendingCertificateV1::Timeout {
                    certificate,
                    publish: true,
                })?;
                self.drain_pending_certificates_v1()?;
            }
        }
        Ok(true)
    }

    fn queue_certificate_v1(&mut self, candidate: PendingCertificateV1) -> Result<()> {
        let id = candidate.id_v1();
        if candidate.is_quorum_v1() {
            if self.applied_qcs.contains(&id) {
                return Ok(());
            }
        } else if self.applied_tcs.contains(&id) {
            return Ok(());
        }
        if let Some(existing) = self.pending_certificates.iter_mut().find(|existing| {
            existing.id_v1() == id && existing.is_quorum_v1() == candidate.is_quorum_v1()
        }) {
            existing.merge_publish_v1(candidate.publish_v1());
            return Ok(());
        }
        ensure!(
            self.pending_certificates.len() < MAXIMUM_PENDING_CERTIFICATES_V1,
            "pending certificate buffer exhausted"
        );
        self.pending_certificates.push_back(candidate);
        Ok(())
    }

    fn drain_pending_certificates_v1(&mut self) -> Result<bool> {
        let mut progressed = false;
        loop {
            let mut ready_index = None;
            for (index, candidate) in self.pending_certificates.iter().enumerate() {
                if candidate.ready_v1(self)? {
                    ready_index = Some(index);
                    break;
                }
            }
            let Some(index) = ready_index else {
                break;
            };
            let candidate = self
                .pending_certificates
                .remove(index)
                .expect("pending certificate index was observed");
            match candidate {
                PendingCertificateV1::Quorum {
                    certificate,
                    publish,
                } => self.apply_quorum_certificate_v1(certificate, publish)?,
                PendingCertificateV1::Timeout {
                    certificate,
                    publish,
                } => self.apply_timeout_certificate_v1(certificate, publish)?,
            }
            progressed = true;
        }
        Ok(progressed)
    }

    fn apply_quorum_certificate_v1(
        &mut self,
        certificate: QuorumCertificate,
        publish: bool,
    ) -> Result<()> {
        let id = *certificate.id().as_bytes();
        if self.applied_qcs.contains(&id) {
            return Ok(());
        }
        self.require_archivable_view_v1(certificate.view().get(), false, "quorum certificate")?;
        // The exact certificate is durable before either publication or the
        // first phase-neutral Core/Safety mutation.
        self.replay_archive
            .append_quorum_certificate_v1(&certificate)
            .context("durably archive quorum certificate before authority")?;
        if publish {
            let encoded = encode_quorum_certificate(&certificate)
                .map_err(|error| anyhow!("encode quorum certificate: {error}"))?;
            self.enqueue_consensus_statement_v1(FrameKind::QuorumCertificate, encoded)?;
        }
        let before = self.authority_v1()?.facts_v0()?;
        let after = self
            .authority_v1()?
            .advance_quorum_certificate_v0(certificate.clone())?;
        self.event_journal
            .append(
                RuntimeEventKindV1::QuorumCertificateAdmitted,
                &hex::encode(certificate.id().as_bytes()),
                certificate.height().get(),
            )
            .map_err(|error| anyhow!("append QC admission event: {error}"))?;
        self.record_application_progress_v1(before, after)?;
        self.applied_qcs.insert(id);
        if made_authoritative_progress_v1(before, after) {
            self.rearm_after_progress_v1(after)?;
        }
        Ok(())
    }

    /// Establishes the crash-order gate for one Proposal and any ordinary QC
    /// which its witness can apply before Proposal admission.  Returning from
    /// this method is the sole runtime point immediately preceding the
    /// authority call.
    fn archive_proposal_before_authority_v1(&mut self, proposal: &UnboundProposalV0) -> Result<()> {
        self.require_archivable_view_v1(proposal.block().header().view().get(), true, "Proposal")?;
        self.replay_archive
            .append_proposal_v1(proposal)
            .context("durably archive Proposal before authority")?;
        if let QcReferenceV0::Ordinary(certificate) = proposal.justify_qc() {
            self.require_archivable_view_v1(
                certificate.view().get(),
                false,
                "Proposal justify QC",
            )?;
            self.replay_archive
                .append_quorum_certificate_v1(certificate)
                .context("durably archive Proposal justify QC before authority")?;
        }
        Ok(())
    }

    fn apply_timeout_certificate_v1(
        &mut self,
        certificate: TimeoutCertificateV0,
        publish: bool,
    ) -> Result<()> {
        let id = *certificate.id().as_bytes();
        if self.applied_tcs.contains(&id) {
            return Ok(());
        }
        self.require_archivable_view_v1(
            certificate.timed_out_view().get(),
            true,
            "timeout certificate",
        )?;
        ensure!(
            u64::try_from(self.applied_tcs.len()).context("applied TC count overflows")?
                < self
                    .preflight
                    .signer_lifetime
                    .maximum_timeout_view_advances_v0(),
            "bounded consensus timeout-view advance capacity exhausted"
        );
        if publish {
            let encoded = encode_timeout_certificate(&certificate)
                .map_err(|error| anyhow!("encode timeout certificate: {error}"))?;
            self.enqueue_consensus_statement_v1(FrameKind::TimeoutCertificate, encoded)?;
        }
        let before = self.authority_v1()?.facts_v0()?;
        let after = self
            .authority_v1()?
            .advance_timeout_certificate_v0(certificate.clone())?;
        self.event_journal
            .append(
                RuntimeEventKindV1::TimeoutCertificateAdmitted,
                &hex::encode(certificate.id().as_bytes()),
                certificate.timed_out_view().get(),
            )
            .map_err(|error| anyhow!("append TC admission event: {error}"))?;
        self.record_application_progress_v1(before, after)?;
        self.applied_tcs.insert(id);
        if made_authoritative_progress_v1(before, after) {
            let required = self
                .highest_submitted_height
                .max(self.config.ordinary_start_height());
            self.post_timeout_rebase_required_finalized_height = Some(
                self.post_timeout_rebase_required_finalized_height
                    .map_or(required, |existing| existing.max(required)),
            );
            self.rearm_after_progress_v1(after)?;
        }
        Ok(())
    }

    fn require_archivable_view_v1(
        &self,
        view: u64,
        require_ordinary_view: bool,
        label: &'static str,
    ) -> Result<()> {
        ensure!(
            (!require_ordinary_view || view >= self.initial_consensus_view)
                && view <= self.maximum_archivable_view,
            "{label} view crosses the context-bound consensus lifetime"
        );
        Ok(())
    }

    fn record_application_progress_v1(
        &mut self,
        before: ContinuousRuntimeFactsV0,
        after: ContinuousRuntimeFactsV0,
    ) -> Result<()> {
        if after.finalized_height_v0() > before.finalized_height_v0() {
            if after.finalized_height_v0() >= self.config.ordinary_start_height() {
                let first_seen = self
                    .proposal_first_seen
                    .get(after.finalized_block_id_v0().as_bytes())
                    .map(|(_, observed_at)| *observed_at)
                    .ok_or_else(|| {
                        anyhow!("ordinary finality lacks a locally admitted proposal")
                    })?;
                let sample_ms = Instant::now()
                    .saturating_duration_since(first_seen)
                    .as_secs_f64()
                    * 1_000.0;
                ensure!(
                    sample_ms.is_finite() && sample_ms > 0.0,
                    "finality latency sample is not finite and positive"
                );
                self.finality_samples_ms.push(sample_ms);
            }
            prune_finalized_proposal_timestamps_v1(
                &mut self.proposal_first_seen,
                after.finalized_height_v0(),
            );
            self.event_journal
                .append(
                    RuntimeEventKindV1::Finalized,
                    &hex::encode(after.finalized_block_id_v0().as_bytes()),
                    after.finalized_height_v0(),
                )
                .map_err(|error| anyhow!("append finalization event: {error}"))?;
            if self
                .post_timeout_rebase_required_finalized_height
                .is_some_and(|required| after.finalized_height_v0() >= required)
            {
                self.post_timeout_rebase_required_finalized_height = None;
            }
        }
        if after.application_applied_height_v0() > before.application_applied_height_v0() {
            self.event_journal
                .append(
                    RuntimeEventKindV1::ApplicationAcknowledged,
                    &hex::encode(after.application_state_root_v0().as_bytes()),
                    after.application_applied_height_v0(),
                )
                .map_err(|error| anyhow!("append application acknowledgement event: {error}"))?;
        }
        Ok(())
    }

    fn rearm_after_progress_v1(&mut self, facts: ContinuousRuntimeFactsV0) -> Result<()> {
        self.pacemaker.observe_progress();
        if self.restart_lifecycle.is_running_v1() && self.stopping_since.is_none() {
            self.pacemaker.arm(
                self.config.validator_set().epoch(),
                facts.current_view_v0(),
                Instant::now(),
            )?;
        }
        Ok(())
    }

    fn is_qc_aggregator_v1(&self, certificate: &QuorumCertificate) -> Result<bool> {
        let next_view = certificate
            .view()
            .get()
            .checked_add(1)
            .map(View::new)
            .context("QC next view overflows")?;
        Ok(leader_for(self.config.validator_set(), next_view) == self.config.local_validator())
    }

    fn is_tc_aggregator_v1(&self, certificate: &TimeoutCertificateV0) -> Result<bool> {
        let next_view = certificate
            .timed_out_view()
            .get()
            .checked_add(1)
            .map(View::new)
            .context("TC next view overflows")?;
        Ok(leader_for(self.config.validator_set(), next_view) == self.config.local_validator())
    }

    fn record_proposal_first_seen_v1(&mut self, block_id: BlockId, height: u64) -> Result<()> {
        record_proposal_first_seen_at_v1(
            &mut self.proposal_first_seen,
            block_id,
            height,
            Instant::now(),
        )
    }

    fn record_proposal_admitted_v1(&mut self, block_id: BlockId, height: u64) -> Result<()> {
        self.event_journal
            .append(
                RuntimeEventKindV1::ProposalAdmitted,
                &hex::encode(block_id.as_bytes()),
                height,
            )
            .map_err(|error| anyhow!("append proposal admission event: {error}"))?;
        Ok(())
    }

    fn flush_outbox_v1(&mut self) -> Result<bool> {
        let Some(mesh) = self.mesh.as_ref() else {
            bail!("consensus mesh is unavailable")
        };
        let (queued_payload_bytes, queued_frames) = self.outbox.flush_front_v1(mesh)?;
        if queued_frames == 0 {
            return Ok(false);
        }
        let envelope_bytes = authenticated_frame_envelope_bytes_v1(self.config.run_id())?;
        let complete_wire_bytes = queued_frames
            .checked_mul(envelope_bytes)
            .and_then(|value| value.checked_add(queued_payload_bytes))
            .context("queued consensus wire-byte counter overflows")?;
        self.network_tx_bytes = self
            .network_tx_bytes
            .checked_add(complete_wire_bytes)
            .context("consensus transmit-byte counter overflows")?;
        Ok(true)
    }

    fn revalidate_target_process1_handoff_v1(&self) -> Result<Process1TargetParkedJournalCutV1> {
        let RestartLifecycleV1::TargetAcked(owner) = &self.restart_lifecycle else {
            bail!("process-1 target handoff requires the exact TargetAcked lifecycle")
        };
        let acknowledged = &owner.acknowledged;
        let stored = acknowledged.stored_cut_park_v1();
        let prepared = &owner.prepared;
        let statement_count = u64::try_from(stored.statement_count_v1())
            .context("target handoff RestartCut statement count does not fit u64")?;
        let expected_statement_count =
            u64::try_from(self.config.validator_set().validators().len())
                .context("target handoff validator count does not fit u64")?;
        let journal_cut = self
            .event_journal
            .revalidate_target_process1_parked_ack_handoff_v1(acknowledged)
            .map_err(|error| {
                anyhow!("freshly revalidate target process-1 ParkedAck journal: {error}")
            })?;
        let observation = self.event_journal.observation();
        ensure!(
            self.authority.is_none()
                && self.event_journal.process_instance() == 1
                && self.event_journal.restart_phase_v1()
                    == RuntimeRestartPhaseV1::Process1TargetParkedAcked
                && self.event_journal.last_event_facts()
                    == Some((
                        journal_cut.event_sequence_v1(),
                        journal_cut.event_sha256_v1(),
                    ))
                && observation.process_instance == 1
                && observation.next_sequence
                    == journal_cut
                        .event_sequence_v1()
                        .checked_add(1)
                        .context("target handoff journal sequence overflows")?
                && !observation.final_tip_recorded
                && !observation.clean_stop_recorded
                && !observation.safety_halted
                && observation.active_faults.is_empty()
                && prepared.local_validator_v1() == self.config.local_validator()
                && prepared.process_instance_v1() == 1
                && stored.local_validator_v1() == self.config.local_validator()
                && stored.local_config_sha256_v1() == self.config.config_sha256()
                && stored.local_role_v1() == RestartParkRoleV1::Target
                && stored.body_v1().target_validator() == self.config.local_validator()
                && stored.body_v1().target_config_sha256() == self.config.config_sha256()
                && stored.body_v1().process_instance() == 1
                && stored.body_v1().run_id() == self.config.run_id()
                && stored.body_v1().runtime_journal_head_v1()
                    == prepared.journal_successor_v1()
                && stored.contains_exact_target_prepare_v1(prepared.target_prepare_v1())
                && journal_cut.event_sequence_v1()
                    == prepared
                        .journal_successor_v1()
                        .0
                        .checked_add(3)
                        .context("target ParkedAck suffix sequence overflows")?
                && stored.cut_artifact_sha256_v1() != [0; 32]
                && stored.park_artifact_sha256_v1() != [0; 32]
                && journal_cut.restart_cut_artifact_sha256_v1()
                    == stored.cut_artifact_sha256_v1()
                && journal_cut.restart_park_artifact_sha256_v1()
                    == stored.park_artifact_sha256_v1()
                && journal_cut.restart_parked_ack_artifact_sha256_v1()
                    == acknowledged.ack_artifact_sha256_v1()
                && journal_cut.restart_parked_ack_admission_set_sha256_v1()
                    == acknowledged.ack_admission_set_sha256_v1()
                && journal_cut.local_restart_parked_ack_statement_sha256_v1()
                    == acknowledged.local_statement_v1().statement_sha256()
                && statement_count == expected_statement_count
                && self.event_journal.restart_cut_facts_v1()
                    == Some((stored.cut_artifact_sha256_v1(), statement_count)),
            "target process-1 handoff differs across lifecycle, journal, config, or stored artifacts"
        );
        Ok(journal_cut)
    }

    /// Consumes every live process-1 target runtime surface after the exact
    /// durable `restart_prepare -> restart_cut -> restart_park ->
    /// restart_parked_ack` boundary. No
    /// CleanStop, SafetyHalted, report, metrics, final-state, or replay-archive
    /// terminal seal is created on this successful handoff path.
    fn finish_target_process1_handoff_v1(&mut self) -> Result<Process1TargetParkedHandoffV1> {
        let before = self.revalidate_target_process1_handoff_v1()?;
        ensure!(
            self.outbox.is_empty()
                && self.pending_proposals.is_empty()
                && self.pending_certificates.is_empty()
                && self.prestarted_ingress.is_empty()
                && self.restart_round.admitted_statements.is_empty()
                && self.restart_round.pending_parked_acks.is_empty()
                && self.restart_round.admitted_parked_acks.is_empty()
                && self.unavailable_sessions.is_empty()
                && self.post_timeout_rebase_required_finalized_height.is_none()
                && self.active_connectivity_fault.is_none()
                && self.stopping_since.is_none()
                && self
                    .runtime_control
                    .as_ref()
                    .is_some_and(|control| control.expected_fault().is_none())
                && self.mesh_v1()?.pending_outbound_bytes_v1()? == 0,
            "target process-1 handoff retains an unresolved runtime or outbound obligation"
        );
        self.mesh_v1()?.ensure_healthy()?;
        let control = self
            .runtime_control
            .take()
            .ok_or_else(|| anyhow!("bounded runtime control owner was already consumed"))?;
        control
            .close()
            .context("close target process-1 runtime control server")?;
        self.pacemaker.cancel();
        self.mesh
            .take()
            .ok_or_else(|| anyhow!("target process-1 consensus mesh was already consumed"))?
            .close()
            .context("close target process-1 consensus mesh")?;

        let after = self.revalidate_target_process1_handoff_v1()?;
        ensure!(
            before == after,
            "target process-1 parked boundary changed during resource shutdown"
        );
        let lifecycle = std::mem::replace(&mut self.restart_lifecycle, RestartLifecycleV1::Running);
        let RestartLifecycleV1::TargetAcked(owner) = lifecycle else {
            bail!("target process-1 ParkedAck owner disappeared during handoff")
        };
        let LocalRestartTargetAckedOwnerV1 {
            prepared,
            acknowledged,
        } = owner;
        let stored = acknowledged.stored_cut_park_v1();
        let journal_commit = acknowledged.journal_commit_v1();
        ensure!(
            prepared.local_validator_v1() == self.config.local_validator()
                && stored.cut_artifact_sha256_v1() == after.restart_cut_artifact_sha256_v1()
                && stored.park_artifact_sha256_v1() == after.restart_park_artifact_sha256_v1()
                && acknowledged.ack_artifact_sha256_v1()
                    == after.restart_parked_ack_artifact_sha256_v1()
                && acknowledged.ack_admission_set_sha256_v1()
                    == after.restart_parked_ack_admission_set_sha256_v1(),
            "consumed target process-1 ParkedAck owner differs from its fresh handoff cut"
        );
        Ok(Process1TargetParkedHandoffV1 {
            schema_version: 2,
            status: "process1-target-parked-ack-handoff".to_owned(),
            run_id: self.config.run_id().to_owned(),
            validator_id: hex::encode(self.config.local_validator().as_bytes()),
            process1_pid: std::process::id(),
            process1_instance: 1,
            process2_instance: RECOVERY_PROCESS_INSTANCE_V1,
            restart_park_event_sequence: journal_commit.restart_park_event_sequence_v1(),
            restart_park_event_sha256: hex::encode(journal_commit.restart_park_event_sha256_v1()),
            restart_parked_ack_event_sequence: after.event_sequence_v1(),
            restart_parked_ack_event_sha256: hex::encode(after.event_sha256_v1()),
            restart_cut_artifact_sha256: hex::encode(after.restart_cut_artifact_sha256_v1()),
            restart_park_artifact_sha256: hex::encode(after.restart_park_artifact_sha256_v1()),
            restart_parked_ack_artifact_sha256: hex::encode(
                after.restart_parked_ack_artifact_sha256_v1(),
            ),
            restart_parked_ack_admission_set_sha256: hex::encode(
                after.restart_parked_ack_admission_set_sha256_v1(),
            ),
            local_restart_parked_ack_statement_sha256: hex::encode(
                after.local_restart_parked_ack_statement_sha256_v1(),
            ),
            protocol_authority: false,
            production_activation: false,
        })
    }

    fn finish_v1(&mut self) -> Result<PathBuf> {
        ensure!(
            self.outbox.is_empty(),
            "terminal consensus outbox is not empty"
        );
        ensure!(
            self.pending_proposals.is_empty()
                && self.pending_certificates.is_empty()
                && self.prestarted_ingress.is_empty()
                && self.unavailable_sessions.is_empty()
                && self.active_connectivity_fault.is_none()
                && self.event_journal.observation().active_faults.is_empty(),
            "terminal consensus network state is unresolved"
        );
        let control = self
            .runtime_control
            .take()
            .ok_or_else(|| anyhow!("bounded runtime control owner was already consumed"))?;
        ensure!(
            control.expected_fault().is_none(),
            "terminal consensus control still has a fault expectation"
        );
        control
            .close()
            .context("close bounded runtime control server")?;
        self.pacemaker.cancel();
        self.mesh
            .take()
            .ok_or_else(|| anyhow!("consensus mesh was already consumed"))?
            .close_if_ingress_empty_v1()
            .context("close consensus mesh")?;
        let path = {
            let authority = self
                .authority
                .take()
                .ok_or_else(|| anyhow!("continuous authority was already consumed"))?;
            let terminal = authority.into_terminal_owner_v0()?;
            let facts = *terminal.facts_v0();
            let node = facts.node_v0();
            self.event_journal
                .record_final_tip(
                    *node.finalized_block_id_v0().as_bytes(),
                    node.application_state_root_v0(),
                    facts.finalized_chain_root_v0(),
                    node.finalized_height_v0(),
                )
                .map_err(|error| anyhow!("append final tip event: {error}"))?;
            self.event_journal
                .record_clean_stop()
                .map_err(|error| anyhow!("append clean stop event: {error}"))?;
            let journal_cut = self
                .event_journal
                .clean_stopped_cut()
                .map_err(|error| anyhow!("read clean-stopped event cut: {error}"))?;
            let _archive_terminal_seal_path = self
                .replay_archive
                .write_terminal_seal_v1(
                    &self.config,
                    &journal_cut,
                    self.preflight.bootstrap_initial_cut,
                )
                .context("write validator-signed terminal replay archive seal")?;
            let terminal_facts = ConsensusRunTerminalFactsV1::from_continuous_terminal(&facts)?;
            let report = sign_consensus_run_report_v1(
                &self.config,
                ConsensusRunBoundsV1 {
                    requested_duration_seconds: self.preflight.duration_seconds,
                    requested_max_blocks: self.preflight.requested_max_blocks,
                    pacemaker_base_timeout_seconds: PACEMAKER_BASE_TIMEOUT_V1.as_secs(),
                    terminal_drain_allowance_seconds: TERMINAL_DRAIN_GRACE_V1.as_secs(),
                    timeout_view_budget_allowance_seconds:
                        CONSENSUS_RUNTIME_TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS_V1,
                    signer_journal_capacity: CONTINUOUS_RUNTIME_MAXIMUM_SIGNER_INTENTS_V0,
                    maximum_timeout_view_advances: self
                        .preflight
                        .signer_lifetime
                        .maximum_timeout_view_advances_v0(),
                    maximum_local_vote_intents: self
                        .preflight
                        .signer_lifetime
                        .maximum_local_vote_intents_v0(),
                    maximum_local_timeout_intents: self
                        .preflight
                        .signer_lifetime
                        .maximum_local_timeout_intents_v0(),
                    maximum_total_signer_intents: self
                        .preflight
                        .signer_lifetime
                        .maximum_total_intents_v0(),
                    signed_replay_archive_capacity: MAXIMUM_ENTRY_COUNT_V1,
                    maximum_proposal_archive_entries: self
                        .preflight
                        .archive_bounds
                        .maximum_proposal_entries_v1(),
                    maximum_quorum_certificate_archive_entries: self
                        .preflight
                        .archive_bounds
                        .maximum_quorum_certificate_entries_v1(),
                    maximum_signed_replay_archive_entries: self
                        .preflight
                        .archive_bounds
                        .maximum_archive_entries_v1(),
                },
                terminal_facts,
                &journal_cut,
            )?;
            let path =
                write_consensus_run_report_v1(&self.preflight.report_path, &report, &self.config)?;
            let os_end = RuntimeOsSampleV1::capture_v1()?;
            let os_metrics = self.os_start.finish_v1(os_end)?;
            ensure!(
                !self.finality_samples_ms.is_empty(),
                "terminal runtime lacks a measured ordinary finality sample"
            );
            // Every signed journal event completed one file sync. Journal start
            // additionally synced its parent directory, and the successful report
            // writer completed one file plus one parent-directory sync. Store
            // internals may have completed more syncs; this is the exact observed
            // lower-bound count owned by these three runtime surfaces.
            let fsync_count = journal_cut
                .event_sequence()
                .checked_add(1)
                .and_then(|event_count| event_count.checked_add(1))
                .and_then(|journal_syncs| journal_syncs.checked_add(2))
                .context("runtime durable-sync counter overflows")?;
            let metrics = sign_runtime_metrics_v1(
                &self.config,
                &journal_cut,
                &report,
                RuntimeMetricsFactsV1 {
                    measurement_started_at: os_metrics.measurement_started_at,
                    measurement_ended_at: os_metrics.measurement_ended_at,
                    finality_samples_ms: self.finality_samples_ms.clone(),
                    fsync_count,
                    cpu_seconds: os_metrics.cpu_seconds,
                    peak_rss_bytes: os_metrics.peak_rss_bytes,
                    disk_bytes: os_metrics.disk_bytes,
                    network_tx_bytes: self.network_tx_bytes,
                    network_rx_bytes: self.network_rx_bytes,
                },
            )?;
            write_runtime_metrics_v1(&self.config, &metrics)?;
            let double_sign_events = facts
                .double_vote_count_v0()
                .checked_add(facts.double_timeout_count_v0())
                .context("terminal double-sign counter overflows")?;
            let final_state = sign_runtime_final_state_v1(
                &self.config,
                &journal_cut,
                &report,
                &metrics,
                RuntimeFinalStateFactsV1 {
                    finalized_nonempty_ordinary_block_count: report.finalized_ordinary_block_count,
                    double_sign_events,
                    // Successful typed terminal construction and the exact clean
                    // journal cut are the authority for these zero violation
                    // projections; caller-selected campaign claims never enter.
                    duplicate_apply_events: 0,
                    state_drift_events: 0,
                    safety_halt_violations: u64::from(
                        self.event_journal.observation().safety_halted,
                    ),
                },
            )?;
            write_runtime_final_state_v1(&self.config, &final_state)?;
            path
        };
        Ok(path)
    }

    fn fail_stop_v1(&mut self) {
        self.pacemaker.cancel();
        if let Some(control) = self.runtime_control.take() {
            let _ = control.close();
        }
        if let Some(mesh) = self.mesh.take() {
            let _ = mesh.close();
        }
        if !self.event_journal.observation().safety_halted
            && !self.event_journal.observation().clean_stop_recorded
        {
            let _ = self.event_journal.append(
                RuntimeEventKindV1::SafetyHalted,
                "bounded-consensus-runtime-failed",
                0,
            );
        }
    }

    fn authority_v1(&mut self) -> Result<&mut ContinuousValidatorAuthorityV0> {
        self.authority
            .as_mut()
            .ok_or_else(|| anyhow!("continuous authority is unavailable"))
    }

    fn mesh_v1(&self) -> Result<&PersistentAuthenticatedPeerMeshV0> {
        self.mesh
            .as_ref()
            .ok_or_else(|| anyhow!("consensus mesh is unavailable"))
    }
}

fn observed_connectivity_fault_subject_v1(
    fault: crate::process_event::RuntimeFaultV1,
    local: ValidatorId,
    scheduled_leader: ValidatorId,
    unavailable: &BTreeSet<(PeerDirectionV0, ValidatorId)>,
) -> Option<ValidatorId> {
    use crate::process_event::RuntimeFaultV1;

    let direction_count = |remote: ValidatorId| {
        [PeerDirectionV0::Inbound, PeerDirectionV0::Outbound]
            .into_iter()
            .filter(|direction| unavailable.contains(&(*direction, remote)))
            .count()
    };
    match fault {
        RuntimeFaultV1::LeaderLoss if scheduled_leader != local => {
            (direction_count(scheduled_leader) == 2).then_some(scheduled_leader)
        }
        RuntimeFaultV1::HostLoss => unavailable
            .iter()
            .map(|(_, remote)| *remote)
            .find(|remote| direction_count(*remote) == 2),
        RuntimeFaultV1::AsymmetricPartition => unavailable
            .iter()
            .map(|(_, remote)| *remote)
            .find(|remote| direction_count(*remote) == 1),
        RuntimeFaultV1::LeaderLoss
        | RuntimeFaultV1::ValidatorProcessKill
        | RuntimeFaultV1::BoundedDelayLoss
        | RuntimeFaultV1::StaleSnapshot
        | RuntimeFaultV1::RollbackAttempt
        | RuntimeFaultV1::EpochHandoff => None,
    }
}

#[derive(Debug)]
struct OrderedBroadcastV1 {
    kind: FrameKind,
    payload: Arc<[u8]>,
    remaining_peers: BTreeSet<ValidatorId>,
}

#[derive(Debug)]
struct OrderedConsensusOutboxV1 {
    peers: Vec<ValidatorId>,
    pending: VecDeque<OrderedBroadcastV1>,
    pending_bytes: usize,
}

impl OrderedConsensusOutboxV1 {
    fn new(peers: Vec<ValidatorId>) -> Self {
        Self {
            peers,
            pending: VecDeque::new(),
            pending_bytes: 0,
        }
    }

    fn enqueue(&mut self, kind: FrameKind, payload: Vec<u8>) -> Result<()> {
        self.enqueue_with_excluded_v1(kind, payload, None)
    }

    fn enqueue_except_v1(
        &mut self,
        kind: FrameKind,
        payload: Vec<u8>,
        excluded_peer: ValidatorId,
    ) -> Result<()> {
        self.enqueue_with_excluded_v1(kind, payload, Some(excluded_peer))
    }

    fn enqueue_with_excluded_v1(
        &mut self,
        kind: FrameKind,
        payload: Vec<u8>,
        excluded_peer: Option<ValidatorId>,
    ) -> Result<()> {
        ensure!(!payload.is_empty(), "consensus outbox payload is empty");
        ensure!(
            self.pending.len() < MAXIMUM_PENDING_BROADCASTS_V1,
            "consensus outbox message capacity exhausted"
        );
        let next_bytes = self
            .pending_bytes
            .checked_add(payload.len())
            .context("consensus outbox byte accounting overflows")?;
        ensure!(
            next_bytes <= MAXIMUM_PENDING_BROADCAST_BYTES_V1,
            "consensus outbox byte capacity exhausted"
        );
        self.pending_bytes = next_bytes;
        let mut remaining_peers = self.peers.iter().copied().collect::<BTreeSet<_>>();
        if let Some(excluded_peer) = excluded_peer {
            remaining_peers.remove(&excluded_peer);
        }
        ensure!(
            !remaining_peers.is_empty(),
            "consensus outbox has no eligible destination peer"
        );
        self.pending.push_back(OrderedBroadcastV1 {
            kind,
            payload: Arc::from(payload),
            remaining_peers,
        });
        Ok(())
    }

    fn flush_front_v1(&mut self, mesh: &PersistentAuthenticatedPeerMeshV0) -> Result<(u64, u64)> {
        let Some(front) = self.pending.front_mut() else {
            return Ok((0, 0));
        };
        let peers = front.remaining_peers.iter().copied().collect::<Vec<_>>();
        let mut queued_payload_bytes = 0u64;
        let mut queued_frames = 0u64;
        for peer in peers {
            match mesh.send_shared_to_v0(peer, front.kind, Arc::clone(&front.payload))? {
                crate::consensus_mesh::MeshSendDispositionV0::Queued => {
                    front.remaining_peers.remove(&peer);
                    queued_payload_bytes = queued_payload_bytes
                        .checked_add(
                            u64::try_from(front.payload.len())
                                .context("consensus payload size does not fit u64")?,
                        )
                        .context("queued payload-byte counter overflows")?;
                    queued_frames = queued_frames
                        .checked_add(1)
                        .context("queued frame counter overflows")?;
                }
                crate::consensus_mesh::MeshSendDispositionV0::Backpressured => {}
            }
        }
        if front.remaining_peers.is_empty() {
            let completed = self.pending.pop_front().expect("outbox front was observed");
            self.pending_bytes = self
                .pending_bytes
                .checked_sub(completed.payload.len())
                .expect("outbox byte accounting is monotonic");
        }
        Ok((queued_payload_bytes, queued_frames))
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.pending_bytes == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingProposalDispositionV1 {
    Vote,
    Buffer,
    IgnoreStale,
}

#[derive(Debug)]
enum PendingProposalAdmissionV1 {
    Vote(Box<UnboundProposalV0>),
    Buffered,
    IgnoreStale(BlockId),
}

#[derive(Debug, Default)]
struct PendingProposalBufferV1 {
    pending: VecDeque<UnboundProposalV0>,
}

impl PendingProposalBufferV1 {
    fn admit_v1(
        &mut self,
        proposal: UnboundProposalV0,
        high_qc: QcRef,
        known_executions: &BTreeSet<(u64, [u8; 32])>,
    ) -> Result<PendingProposalAdmissionV1> {
        match proposal_disposition_v1(&proposal, high_qc, known_executions) {
            PendingProposalDispositionV1::Vote => {
                Ok(PendingProposalAdmissionV1::Vote(Box::new(proposal)))
            }
            PendingProposalDispositionV1::IgnoreStale => Ok(
                PendingProposalAdmissionV1::IgnoreStale(proposal.block().id()),
            ),
            PendingProposalDispositionV1::Buffer => {
                let block_id = proposal.block().id();
                if self
                    .pending
                    .iter()
                    .any(|pending| pending.block().id() == block_id)
                {
                    return Ok(PendingProposalAdmissionV1::Buffered);
                }
                ensure!(
                    self.pending.len() < MAXIMUM_PENDING_PROPOSALS_V1,
                    "pending proposal buffer exhausted"
                );
                self.pending.push_back(proposal);
                Ok(PendingProposalAdmissionV1::Buffered)
            }
        }
    }

    fn take_actionable_v1(
        &mut self,
        high_qc: QcRef,
        known_executions: &BTreeSet<(u64, [u8; 32])>,
    ) -> Option<PendingProposalAdmissionV1> {
        let (index, disposition) =
            self.pending
                .iter()
                .enumerate()
                .find_map(|(index, proposal)| {
                    let disposition = proposal_disposition_v1(proposal, high_qc, known_executions);
                    (disposition != PendingProposalDispositionV1::Buffer)
                        .then_some((index, disposition))
                })?;
        let proposal = self
            .pending
            .remove(index)
            .expect("pending proposal index was observed");
        Some(match disposition {
            PendingProposalDispositionV1::Vote => {
                PendingProposalAdmissionV1::Vote(Box::new(proposal))
            }
            PendingProposalDispositionV1::IgnoreStale => {
                PendingProposalAdmissionV1::IgnoreStale(proposal.block().id())
            }
            PendingProposalDispositionV1::Buffer => {
                unreachable!("buffered proposal was selected as actionable")
            }
        })
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    #[cfg(test)]
    fn len_v1(&self) -> usize {
        self.pending.len()
    }
}

fn proposal_disposition_v1(
    proposal: &UnboundProposalV0,
    high_qc: QcRef,
    known_executions: &BTreeSet<(u64, [u8; 32])>,
) -> PendingProposalDispositionV1 {
    let justify = proposal.justify_qc().qc_ref();
    if justify == high_qc {
        return PendingProposalDispositionV1::Vote;
    }
    if justify.height().get() <= high_qc.height().get() {
        return PendingProposalDispositionV1::IgnoreStale;
    }
    if known_executions.contains(&(justify.height().get(), *justify.block_id().as_bytes())) {
        PendingProposalDispositionV1::Vote
    } else {
        PendingProposalDispositionV1::Buffer
    }
}

fn record_proposal_first_seen_at_v1(
    observed: &mut BTreeMap<[u8; 32], (u64, Instant)>,
    block_id: BlockId,
    height: u64,
    at: Instant,
) -> Result<()> {
    let identity = *block_id.as_bytes();
    if let Some((existing_height, _)) = observed.get(&identity) {
        ensure!(
            *existing_height == height,
            "proposal identity was observed at two heights"
        );
        return Ok(());
    }
    ensure!(
        observed.len() < MAXIMUM_TRACKED_PROPOSAL_TIMESTAMPS_V1,
        "proposal first-seen buffer exhausted"
    );
    observed.insert(identity, (height, at));
    Ok(())
}

fn forget_proposal_first_seen_v1(
    observed: &mut BTreeMap<[u8; 32], (u64, Instant)>,
    block_id: BlockId,
) {
    observed.remove(block_id.as_bytes());
}

fn prune_finalized_proposal_timestamps_v1(
    observed: &mut BTreeMap<[u8; 32], (u64, Instant)>,
    finalized_height: u64,
) {
    observed.retain(|_, (height, _)| *height > finalized_height);
}

#[derive(Debug, Clone)]
enum PendingCertificateV1 {
    Quorum {
        certificate: QuorumCertificate,
        publish: bool,
    },
    Timeout {
        certificate: TimeoutCertificateV0,
        publish: bool,
    },
}

impl PendingCertificateV1 {
    fn id_v1(&self) -> [u8; 32] {
        match self {
            Self::Quorum { certificate, .. } => *certificate.id().as_bytes(),
            Self::Timeout { certificate, .. } => *certificate.id().as_bytes(),
        }
    }

    fn is_quorum_v1(&self) -> bool {
        matches!(self, Self::Quorum { .. })
    }

    fn publish_v1(&self) -> bool {
        match self {
            Self::Quorum { publish, .. } | Self::Timeout { publish, .. } => *publish,
        }
    }

    fn merge_publish_v1(&mut self, publish: bool) {
        match self {
            Self::Quorum {
                publish: existing, ..
            }
            | Self::Timeout {
                publish: existing, ..
            } => *existing |= publish,
        }
    }

    fn ready_v1(&self, owner: &BoundedConsensusOwnerV1) -> Result<bool> {
        let facts = owner
            .authority
            .as_ref()
            .ok_or_else(|| anyhow!("continuous authority is unavailable"))?
            .facts_v0()?;
        Ok(match self {
            Self::Quorum { certificate, .. } => {
                certificate.height().get() <= facts.high_qc_v0().height().get()
                    || owner.known_executions.contains(&(
                        certificate.height().get(),
                        *certificate.block_id().as_bytes(),
                    ))
            }
            Self::Timeout { certificate, .. } => certificate
                .referenced_qcs()
                .iter()
                .find(|reference| reference.id() == certificate.selected_high_qc_digest())
                .is_some_and(|selected| {
                    selected.qc_ref().height().get() <= facts.high_qc_v0().height().get()
                        || owner.known_executions.contains(&(
                            selected.qc_ref().height().get(),
                            *selected.qc_ref().block_id().as_bytes(),
                        ))
                }),
        })
    }
}

fn made_authoritative_progress_v1(
    before: ContinuousRuntimeFactsV0,
    after: ContinuousRuntimeFactsV0,
) -> bool {
    after.current_view_v0() > before.current_view_v0()
        || after.high_qc_v0() != before.high_qc_v0()
        || after.finalized_height_v0() > before.finalized_height_v0()
        || after.application_applied_height_v0() > before.application_applied_height_v0()
}

fn record_initial_application_cut_v1(
    journal: &mut RuntimeEventJournalV1,
    facts: ContinuousRuntimeFactsV0,
) -> Result<()> {
    if facts.finalized_height_v0() > 0 {
        journal
            .append(
                RuntimeEventKindV1::Finalized,
                &hex::encode(facts.finalized_block_id_v0().as_bytes()),
                facts.finalized_height_v0(),
            )
            .map_err(|error| anyhow!("append initial finalization event: {error}"))?;
    }
    if facts.application_applied_height_v0() > 0 {
        journal
            .append(
                RuntimeEventKindV1::ApplicationAcknowledged,
                &hex::encode(facts.application_state_root_v0().as_bytes()),
                facts.application_applied_height_v0(),
            )
            .map_err(|error| anyhow!("append initial application event: {error}"))?;
    }
    Ok(())
}

fn record_peer_session_v1(
    journal: &mut RuntimeEventJournalV1,
    session: PeerSessionFactsV0,
) -> Result<()> {
    let subject = format!(
        "{}:{}:{}:{}",
        session.direction().as_str(),
        hex::encode(session.remote().as_bytes()),
        hex::encode(session.session_id()),
        session.generation(),
    );
    journal
        .append(
            RuntimeEventKindV1::PeerSessionEstablished,
            &subject,
            session.generation(),
        )
        .map_err(|error| anyhow!("append peer-session event: {error}"))?;
    Ok(())
}

#[derive(Debug, Clone)]
struct RuntimeOsSampleV1 {
    observed_at: SystemTime,
    process_start_ticks: u64,
    cpu_runtime_ns: u64,
    peak_rss_bytes: u64,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
}

#[derive(Debug, Clone)]
struct RuntimeOsMetricsV1 {
    measurement_started_at: String,
    measurement_ended_at: String,
    cpu_seconds: f64,
    peak_rss_bytes: u64,
    disk_bytes: u64,
}

impl RuntimeOsSampleV1 {
    #[cfg(target_os = "linux")]
    fn capture_v1() -> Result<Self> {
        let stat = fs::read_to_string("/proc/self/stat").context("read /proc/self/stat")?;
        let close = stat
            .rfind(')')
            .context("/proc/self/stat lacks process-name terminator")?;
        let fields = stat
            .get(close + 1..)
            .context("slice /proc/self/stat fields")?
            .split_whitespace()
            .collect::<Vec<_>>();
        let process_start_ticks = fields
            .get(19)
            .context("/proc/self/stat lacks starttime")?
            .parse::<u64>()
            .context("parse /proc/self/stat starttime")?;

        let schedstat =
            fs::read_to_string("/proc/self/schedstat").context("read /proc/self/schedstat")?;
        let cpu_runtime_ns = schedstat
            .split_whitespace()
            .next()
            .context("/proc/self/schedstat lacks runtime")?
            .parse::<u64>()
            .context("parse /proc/self/schedstat runtime")?;

        let status = fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
        let peak_rss_kib = parse_proc_named_u64_v1(&status, "VmHWM:")
            .or_else(|| parse_proc_named_u64_v1(&status, "VmRSS:"))
            .context("/proc/self/status lacks VmHWM/VmRSS")?;
        let peak_rss_bytes = peak_rss_kib
            .checked_mul(1_024)
            .context("/proc/self/status RSS overflows bytes")?;

        let io = fs::read_to_string("/proc/self/io").context("read /proc/self/io")?;
        let disk_read_bytes = parse_proc_named_u64_v1(&io, "read_bytes:")
            .context("/proc/self/io lacks read_bytes")?;
        let disk_write_bytes = parse_proc_named_u64_v1(&io, "write_bytes:")
            .context("/proc/self/io lacks write_bytes")?;
        Ok(Self {
            observed_at: SystemTime::now(),
            process_start_ticks,
            cpu_runtime_ns,
            peak_rss_bytes,
            disk_read_bytes,
            disk_write_bytes,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn capture_v1() -> Result<Self> {
        bail!("bounded consensus runtime metrics require Linux /proc authority")
    }

    fn finish_v1(&self, end: Self) -> Result<RuntimeOsMetricsV1> {
        ensure!(
            end.process_start_ticks == self.process_start_ticks,
            "runtime OS samples belong to different process incarnations"
        );
        let elapsed = end
            .observed_at
            .duration_since(self.observed_at)
            .context("runtime OS sample wall time regresses")?;
        ensure!(
            elapsed >= MINIMUM_METRICS_INTERVAL_V1,
            "runtime OS measurement interval is below one second"
        );
        let cpu_runtime_ns = end
            .cpu_runtime_ns
            .checked_sub(self.cpu_runtime_ns)
            .context("runtime CPU counter regresses")?;
        let cpu_seconds = cpu_runtime_ns as f64 / 1_000_000_000.0;
        ensure!(
            cpu_seconds.is_finite() && cpu_seconds > 0.0,
            "runtime CPU observation is not finite and positive"
        );
        let read_bytes = end
            .disk_read_bytes
            .checked_sub(self.disk_read_bytes)
            .context("runtime disk-read counter regresses")?;
        let write_bytes = end
            .disk_write_bytes
            .checked_sub(self.disk_write_bytes)
            .context("runtime disk-write counter regresses")?;
        let disk_bytes = read_bytes
            .checked_add(write_bytes)
            .context("runtime disk-byte counter overflows")?;
        ensure!(disk_bytes > 0, "runtime disk-byte observation is zero");
        let peak_rss_bytes = self.peak_rss_bytes.max(end.peak_rss_bytes);
        ensure!(peak_rss_bytes > 0, "runtime peak RSS observation is zero");
        let measurement_started_at = canonical_utc_timestamp_v1(self.observed_at)?;
        let measurement_ended_at = canonical_utc_timestamp_v1(end.observed_at)?;
        ensure!(
            measurement_started_at < measurement_ended_at,
            "runtime UTC measurement interval is not strictly ordered"
        );
        Ok(RuntimeOsMetricsV1 {
            measurement_started_at,
            measurement_ended_at,
            cpu_seconds,
            peak_rss_bytes,
            disk_bytes,
        })
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_named_u64_v1(contents: &str, name: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let suffix = line.strip_prefix(name)?;
        suffix.split_whitespace().next()?.parse().ok()
    })
}

#[cfg(target_os = "linux")]
fn require_linux_runtime_metrics_v1() -> Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_linux_runtime_metrics_v1() -> Result<()> {
    bail!("bounded consensus execution is Linux-only; this binary remains verifier-capable")
}

fn authenticated_frame_envelope_bytes_v1(run_id: &str) -> Result<u64> {
    // Four-byte frame length plus the exact authenticated body fields other
    // than the caller-supplied consensus payload.
    157u64
        .checked_add(u64::try_from(run_id.len()).context("run ID length does not fit u64")?)
        .context("authenticated frame envelope size overflows")
}

fn authenticated_frame_wire_bytes_v1(run_id: &str, payload_bytes: usize) -> Result<u64> {
    authenticated_frame_envelope_bytes_v1(run_id)?
        .checked_add(u64::try_from(payload_bytes).context("frame payload does not fit u64")?)
        .context("authenticated frame wire size overflows")
}

fn canonical_utc_timestamp_v1(value: SystemTime) -> Result<String> {
    let epoch_seconds = value
        .duration_since(UNIX_EPOCH)
        .context("UTC measurement predates Unix epoch")?
        .as_secs();
    let epoch_seconds = i64::try_from(epoch_seconds).context("UTC epoch seconds exceed i64")?;
    let days = epoch_seconds / 86_400;
    let seconds_of_day = epoch_seconds % 86_400;
    let (year, month, day) = civil_date_from_unix_days_v1(days)?;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_date_from_unix_days_v1(days: i64) -> Result<(i64, i64, i64)> {
    let shifted = days
        .checked_add(719_468)
        .context("UTC civil-date conversion overflows")?;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted
            .checked_sub(146_096)
            .context("UTC civil-date era underflows")?
    } / 146_097;
    let day_of_era = shifted
        .checked_sub(
            era.checked_mul(146_097)
                .context("UTC civil-date era multiplication overflows")?,
        )
        .context("UTC civil-date day-of-era underflows")?;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era
        .checked_add(
            era.checked_mul(400)
                .context("UTC civil-date year multiplication overflows")?,
        )
        .context("UTC civil-date year overflows")?;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year = year
            .checked_add(1)
            .context("UTC civil-date year increment overflows")?;
    }
    ensure!(
        (1..=9_999).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day),
        "UTC civil-date result is outside canonical RFC3339 range"
    );
    Ok((year, month, day))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockHeader, BlockKind, ChainId, ConsensusParametersV0,
        ConsensusPublicKey, Epoch, EvidenceRoot, GenesisHash, GenesisQcV0, Height,
        ProposalWitnessV0, ProtocolVersion, QcReferenceV0, ReceiptsRoot, SignatureBytes,
        SignedProposalV0, StateRoot, Validator, ValidatorSet, Vote, VotingPower,
    };
    use trnm_poco_node::{
        commission_native_h1_ordinary_lab_test_bundle_v0, DEPLOYED_LAB_MAXIMUM_BLOB_BYTES_V0,
        DEPLOYED_LAB_MAXIMUM_RECORD_BYTES_V0,
    };

    use super::*;
    use crate::{
        collector::ConsensusCertificateCollectorV0,
        continuous_runtime::ContinuousValidatorAuthorityV0, frame::AuthenticatedFrame,
    };

    fn restart_intent_fixture_v1() -> RuntimeRestartPrepareIntentV1 {
        RuntimeRestartPrepareIntentV1::test_only_v1(1, 9, 17, [0x31; 32])
    }

    #[test]
    fn external_fence_gate_precedes_commission_and_signer_authority_v1() {
        let source = include_str!("consensus_runtime.rs");
        let gate = source
            .find("establish externally fenced consensus mesh")
            .expect("runtime has an external fencing mesh gate");
        let commission = source
            .find("commission(&mut config")
            .expect("runtime commissioning call remains explicit");
        assert!(gate < commission);
        assert!(source.contains("bounded-consensus-external-fence-gate-failed"));
        assert!(source.contains("production_activation: false"));
    }

    #[test]
    fn explicit_external_fence_is_only_injection_path_and_default_stays_rejecting_v1() {
        let source = include_str!("consensus_runtime.rs");
        let default_entry = source
            .find("pub fn run_bounded_consensus_v1<C>")
            .expect("default bounded runtime entry remains present");
        let explicit_entry = source
            .find("pub fn run_bounded_consensus_with_external_fence_v1<C>")
            .expect("explicit external-fence entry remains present");
        assert!(default_entry < explicit_entry);

        let default_body = &source[default_entry..explicit_entry];
        assert!(default_body.contains("Arc::new(RejectingExternalPeerLeaseAuthorityV1)"));
        assert!(!default_body.contains("PersistentAuthenticatedPeerMeshV0::establish_with_fence"));

        let explicit_body = &source[explicit_entry..];
        assert!(explicit_body.contains("external_fence: Arc<dyn ExternalPeerLeaseAuthorityV1>"));
        assert!(explicit_body.contains("PersistentAuthenticatedPeerMeshV0::establish_with_fence"));
        let direct_mesh_establish = concat!("PersistentAuthenticatedPeerMeshV0::", "establish(");
        assert!(!source.contains(direct_mesh_establish));
        assert!(source.contains("production_activation: false"));
    }

    fn restart_qc_ref_fixture_v1(
        view: u64,
        height: u64,
        block_id: [u8; 32],
        certificate_id: [u8; 32],
        validator_set_id: [u8; 32],
    ) -> QcRef {
        QcRef::new(
            trnm_consensus_types::CertificateId::new(certificate_id),
            Epoch::new(0),
            View::new(view),
            Height::new(height),
            BlockId::new(block_id),
            trnm_consensus_types::ValidatorSetId::new(validator_set_id),
        )
    }

    fn restart_quiescence_fixture_v1() -> RestartQuiescenceSnapshotV1 {
        let finalized_block_id = BlockId::new([0x41; 32]);
        let signer_exact_watermark =
            SignerWatermarkV0::from_persisted_parts([0x53; 32], [0x54; 32], 4, [0x55; 32]).unwrap();
        RestartQuiescenceSnapshotV1 {
            restart_requested: true,
            restart_intent_generation: 9,
            restart_intent_nonce: 17,
            restart_intent_request_sha256: [0x31; 32],
            normal_stop_in_progress: false,
            process_instance: 1,
            local_validator: ValidatorId::new([0x47; 32]),
            authority_phase: PocoNodeLabAuthorityPhaseV0::Ready,
            pending_timeout_certificate: false,
            outbox_frame_count: 0,
            outbox_payload_bytes: 0,
            pending_proposal_count: 0,
            pending_certificate_count: 0,
            prestarted_ingress_count: 0,
            unavailable_session_count: 0,
            mesh_pending_outbound_bytes: 0,
            post_timeout_rebase_pending: false,
            active_connectivity_fault: false,
            expected_control_fault: false,
            active_journal_fault_count: 0,
            journal_restart_prepare_absent: true,
            journal_restart_pending_catchup: false,
            journal_restart_completed: false,
            journal_final_tip_recorded: false,
            journal_clean_stop_recorded: false,
            journal_safety_halted: false,
            ordinary_start_height: 4,
            current_view: View::new(7),
            high_qc: restart_qc_ref_fixture_v1(
                6,
                4,
                *finalized_block_id.as_bytes(),
                [0x42; 32],
                [0x43; 32],
            ),
            finalized_height: 4,
            finalized_block_id,
            finalized_chain_root: [0x40; 32],
            application_height: 4,
            application_block_id: finalized_block_id,
            application_state_root: [0x44; 32],
            proposal_parent_height: 4,
            proposal_parent_block_id: finalized_block_id,
            signed_vote_intents: 1,
            signed_timeout_intents: 1,
            signer_durable_vote_intent_count: 1,
            signer_durable_timeout_intent_count: 1,
            signer_signed_vote_intent_count: 1,
            signer_signed_timeout_intent_count: 1,
            signer_inventory_digest: [0x56; 32],
            authenticated_signer_inventory_digest: [0x56; 32],
            signer_exact_watermark: Some(signer_exact_watermark),
            checkpoint_signer_exact_watermark: Some(signer_exact_watermark),
            safety_revision: 7,
            safety_record_checksum: [0x45; 32],
            safety_chain_checksum: [0x46; 32],
            signer_watermark_sequence: 4,
            checkpoint_generation: 7,
            checkpoint_canonical_sha256: [0x57; 32],
            runtime_checkpoint_canonical_sha256: [0x57; 32],
            replay_archive_context_sha256: [0x48; 32],
            replay_archive_head_sequence: 2,
            replay_archive_head_sha256: [0x49; 32],
            journal_head_sequence: 8,
            journal_head_sha256: [0x4a; 32],
            journal_next_sequence: 9,
            journal_finalized_height: 4,
            journal_application_height: 4,
        }
    }

    fn quiesced_owner_fixture_v1() -> LocalRestartQuiescedOwnerV1 {
        let snapshot = restart_quiescence_fixture_v1();
        LocalRestartQuiescedOwnerV1 {
            facts: LocalRestartQuiescedFactsV1 {
                intent: restart_intent_fixture_v1(),
                local_validator: snapshot.local_validator,
                current_view: snapshot.current_view,
                high_qc: snapshot.high_qc,
                finalized_height: snapshot.finalized_height,
                finalized_block_id: snapshot.finalized_block_id,
                finalized_chain_root: snapshot.finalized_chain_root,
                application_height: snapshot.application_height,
                application_block_id: snapshot.application_block_id,
                application_state_root: snapshot.application_state_root,
                proposal_parent_height: snapshot.proposal_parent_height,
                proposal_parent_block_id: snapshot.proposal_parent_block_id,
                signed_vote_intents: snapshot.signed_vote_intents,
                signed_timeout_intents: snapshot.signed_timeout_intents,
                signer_durable_vote_intent_count: snapshot.signer_durable_vote_intent_count,
                signer_durable_timeout_intent_count: snapshot.signer_durable_timeout_intent_count,
                signer_signed_vote_intent_count: snapshot.signer_signed_vote_intent_count,
                signer_signed_timeout_intent_count: snapshot.signer_signed_timeout_intent_count,
                signer_inventory_digest: snapshot.signer_inventory_digest,
                signer_exact_watermark: snapshot.signer_exact_watermark.unwrap(),
                safety_revision: snapshot.safety_revision,
                safety_record_checksum: snapshot.safety_record_checksum,
                safety_chain_checksum: snapshot.safety_chain_checksum,
                signer_watermark_sequence: snapshot.signer_watermark_sequence,
                checkpoint_generation: snapshot.checkpoint_generation,
                checkpoint_canonical_sha256: snapshot.checkpoint_canonical_sha256,
                replay_archive_context_sha256: [0x48; 32],
                replay_archive_head_sequence: 2,
                replay_archive_head_sha256: [0x49; 32],
                journal_predecessor_sequence: 8,
                journal_predecessor_sha256: [0x4a; 32],
            },
        }
    }

    fn prepared_owner_fixture_v1() -> LocalRestartPreparedOwnerV1 {
        quiesced_owner_fixture_v1()
            .into_prepared_v1(9, [0x4b; 32])
            .expect("carry exact quiescent signer/checkpoint facts into prepared owner")
    }

    fn restart_cut_state_fixture_v1() -> RestartCutStateV1 {
        let snapshot = restart_quiescence_fixture_v1();
        RestartCutStateV1 {
            epoch: Epoch::new(0),
            current_view: snapshot.current_view,
            direct_high_qc: snapshot.high_qc,
            proposal_parent_height: Height::new(snapshot.proposal_parent_height),
            proposal_parent_block_id: snapshot.proposal_parent_block_id,
            finalized_height: Height::new(snapshot.finalized_height),
            finalized_block_id: snapshot.finalized_block_id,
            finalized_chain_root: snapshot.finalized_chain_root,
            application_height: Height::new(snapshot.application_height),
            application_block_id: snapshot.application_block_id,
            application_state_root: StateRoot::new(snapshot.application_state_root),
            external_checkpoint_generation: snapshot.checkpoint_generation,
            external_checkpoint_checksum: snapshot.checkpoint_canonical_sha256,
            safety_revision: snapshot.safety_revision,
            safety_state_record_checksum: snapshot.safety_record_checksum,
            safety_record_chain_checksum: snapshot.safety_chain_checksum,
            signer_watermark: snapshot.signer_exact_watermark.unwrap(),
            signer_durable_vote_intent_count: snapshot.signer_durable_vote_intent_count,
            signer_durable_timeout_intent_count: snapshot.signer_durable_timeout_intent_count,
            signer_signed_vote_intent_count: snapshot.signer_signed_vote_intent_count,
            signer_signed_timeout_intent_count: snapshot.signer_signed_timeout_intent_count,
            signer_inventory_digest: snapshot.signer_inventory_digest,
            pending_sign: None,
            replay_archive_context_sha256: snapshot.replay_archive_context_sha256,
            replay_archive_head_sequence: snapshot.replay_archive_head_sequence,
            replay_archive_head_sha256: snapshot.replay_archive_head_sha256,
            runtime_journal_head_sequence: snapshot.journal_head_sequence,
            runtime_journal_head_sha256: snapshot.journal_head_sha256,
        }
    }

    #[test]
    fn process2_restart_state_field_mutant_matrix_fails_closed_v1() {
        let baseline = restart_cut_state_fixture_v1();
        let expected =
            Process2RestartCutStateProjectionV1::from_restart_state_for_test_v1(baseline);
        require_process2_restart_state_projection_v1(baseline, expected).unwrap();

        let mut mutants = Vec::new();
        macro_rules! mutate {
            ($field:ident, $value:expr) => {{
                let mut mutant = baseline;
                mutant.$field = $value;
                mutants.push((stringify!($field), mutant));
            }};
        }
        mutate!(epoch, Epoch::new(1));
        mutate!(current_view, View::new(8));
        mutate!(
            direct_high_qc,
            restart_qc_ref_fixture_v1(7, 4, [0x61; 32], [0x62; 32], [0x43; 32])
        );
        mutate!(proposal_parent_height, Height::new(5));
        mutate!(proposal_parent_block_id, BlockId::new([0x63; 32]));
        mutate!(finalized_height, Height::new(5));
        mutate!(finalized_block_id, BlockId::new([0x64; 32]));
        mutate!(finalized_chain_root, [0x72; 32]);
        mutate!(application_height, Height::new(5));
        mutate!(application_block_id, BlockId::new([0x65; 32]));
        mutate!(application_state_root, StateRoot::new([0x66; 32]));
        mutate!(external_checkpoint_generation, 8);
        mutate!(external_checkpoint_checksum, [0x67; 32]);
        mutate!(safety_revision, 8);
        mutate!(safety_state_record_checksum, [0x68; 32]);
        mutate!(safety_record_chain_checksum, [0x69; 32]);
        mutate!(
            signer_watermark,
            SignerWatermarkV0::from_persisted_parts([0x6a; 32], [0x6b; 32], 6, [0x6c; 32]).unwrap()
        );
        mutate!(signer_durable_vote_intent_count, 2);
        mutate!(signer_durable_timeout_intent_count, 2);
        mutate!(signer_signed_vote_intent_count, 2);
        mutate!(signer_signed_timeout_intent_count, 2);
        mutate!(signer_inventory_digest, [0x6d; 32]);
        mutate!(pending_sign, Some([0x6e; 32]));
        mutate!(replay_archive_context_sha256, [0x6f; 32]);
        mutate!(replay_archive_head_sequence, 3);
        mutate!(replay_archive_head_sha256, [0x70; 32]);
        mutate!(runtime_journal_head_sequence, 9);
        mutate!(runtime_journal_head_sha256, [0x71; 32]);

        assert_eq!(mutants.len(), 28);
        for (field, mutant) in mutants {
            assert!(
                require_process2_restart_state_projection_v1(mutant, expected).is_err(),
                "RestartCut {field} mutant crossed the full-recovery join"
            );
        }
    }

    #[test]
    fn durable_target_park_retains_the_consumed_continuous_authority_v1() {
        let protocol = include_str!("restart_park_protocol.rs");
        let owner_start = protocol
            .find("pub(crate) struct DurablyParkedTargetRestartOwnerV1")
            .expect("durably parked target owner remains present");
        let owner_declaration = protocol[..owner_start]
            .rfind("#[must_use")
            .expect("durably parked target owner remains must-use");
        let owner_end = protocol[owner_start..]
            .find("impl DurablyParkedTargetRestartOwnerV1")
            .map(|offset| owner_start + offset)
            .expect("durably parked target owner declaration remains bounded");
        let owner = &protocol[owner_declaration..owner_end];
        assert!(owner.contains("stored: StoredRestartCutParkCertificatesV1"));
        assert!(owner.contains("declared: ContinuousRestartDeclaredParkAuthorityV1"));
        assert!(!owner.contains("derive(Clone"));

        let persist_start = protocol
            .find("pub(crate) fn persist_target_v1(")
            .expect("target persistence entry remains present");
        let persist_end = protocol[persist_start..]
            .find("pub(crate) fn persist_peer_v1(")
            .map(|offset| persist_start + offset)
            .expect("target persistence entry remains bounded");
        let persist = &protocol[persist_start..persist_end];
        assert!(persist.contains(") -> AnyResult<DurablyParkedTargetRestartOwnerV1>"));
        assert!(persist.contains("DurablyParkedTargetRestartOwnerV1 { stored, declared }"));

        let runtime = include_str!("consensus_runtime.rs");
        let lifecycle_start = runtime
            .find("struct LocalRestartTargetParkedOwnerV1")
            .expect("target parked lifecycle owner remains present");
        let lifecycle_end = runtime[lifecycle_start..]
            .find("impl std::fmt::Debug for LocalRestartTargetParkedOwnerV1")
            .map(|offset| lifecycle_start + offset)
            .expect("target parked lifecycle owner remains bounded");
        let lifecycle = &runtime[lifecycle_start..lifecycle_end];
        assert!(lifecycle.contains("parked: DurablyParkedTargetRestartOwnerV1"));
        assert!(!lifecycle.contains("stored: StoredRestartCutParkCertificatesV1"));

        let commit_start = runtime
            .find("fn maybe_complete_restart_cut_v1(&mut self)")
            .expect("target durable barrier transition remains present");
        let commit_end = runtime[commit_start..]
            .find("fn reconcile_expected_connectivity_fault_v1(")
            .map(|offset| commit_start + offset)
            .expect("target durable barrier transition remains bounded");
        let commit = &runtime[commit_start..commit_end];
        assert!(commit.contains("let parked = owner"));
        assert!(commit.contains("let stored = parked.stored_v1()"));
        assert!(commit.contains("parked,"));
    }

    #[test]
    fn durable_peer_park_retains_the_consumed_continuous_authority_v1() {
        let protocol = include_str!("restart_park_protocol.rs");
        let owner_start = protocol
            .find("pub(crate) struct DurablyParkedPeerRestartOwnerV1")
            .expect("durably parked peer owner remains present");
        let owner_declaration = protocol[..owner_start]
            .rfind("#[must_use")
            .expect("durably parked peer owner remains must-use");
        let owner_end = protocol[owner_start..]
            .find("impl DurablyParkedPeerRestartOwnerV1")
            .map(|offset| owner_start + offset)
            .expect("durably parked peer owner declaration remains bounded");
        let owner = &protocol[owner_declaration..owner_end];
        assert!(owner.contains("stored: StoredRestartCutParkCertificatesV1"));
        assert!(owner.contains("declared: ContinuousRestartDeclaredParkAuthorityV1"));
        assert!(!owner.contains("derive(Clone"));

        let persist_start = protocol
            .find("pub(crate) fn persist_peer_v1(")
            .expect("peer persistence entry remains present");
        let persist_end = protocol[persist_start..]
            .find("fn persist_local_role_v1(")
            .map(|offset| persist_start + offset)
            .expect("peer persistence entry remains bounded");
        let persist = &protocol[persist_start..persist_end];
        assert!(persist.contains(") -> AnyResult<DurablyParkedPeerRestartOwnerV1>"));
        assert!(persist.contains("DurablyParkedPeerRestartOwnerV1 { stored, declared }"));

        let runtime = include_str!("consensus_runtime.rs");
        let lifecycle_start = runtime
            .find("struct LocalRestartPeerParkedOwnerV1")
            .expect("peer parked lifecycle owner remains present");
        let lifecycle_end = runtime[lifecycle_start..]
            .find("impl std::fmt::Debug for LocalRestartPeerCollectingOwnerV1")
            .map(|offset| lifecycle_start + offset)
            .expect("peer parked lifecycle owner remains bounded");
        let lifecycle = &runtime[lifecycle_start..lifecycle_end];
        assert!(lifecycle.contains("parked: DurablyParkedPeerRestartOwnerV1"));
        assert!(!lifecycle.contains("stored: StoredRestartCutParkCertificatesV1"));

        let commit_start = runtime
            .find("fn maybe_complete_peer_restart_cut_v1(&mut self)")
            .expect("peer durable barrier transition remains present");
        let commit_end = runtime[commit_start..]
            .find("fn maybe_complete_restart_cut_v1(&mut self)")
            .map(|offset| commit_start + offset)
            .expect("peer durable barrier transition remains bounded");
        let commit = &runtime[commit_start..commit_end];
        assert!(commit.contains("let parked = owner"));
        assert!(commit
            .contains(".record_peer_restart_cut_park_from_owner_v1(&owner.prepared, &parked)"));
        assert!(commit.contains("let stored = parked.stored_v1()"));
        assert!(commit.contains("parked,"));

        let journal = include_str!("process_event.rs");
        let writer_start = journal
            .find("pub(crate) fn record_peer_restart_cut_park_from_owner_v1(")
            .expect("peer journal writer remains present");
        let writer_end = journal[writer_start..]
            .find("fn record_peer_restart_cut_park_from_stored_internal_v1(")
            .map(|offset| writer_start + offset)
            .expect("peer journal writer remains bounded by its private helper");
        let writer = &journal[writer_start..writer_end];
        assert!(writer.contains("parked: &DurablyParkedPeerRestartOwnerV1"));
        assert!(writer.contains("parked.revalidate_fresh_v1()"));
        assert!(writer.contains("parked.stored_v1()"));
        assert!(!journal
            .contains("pub(crate) fn record_peer_restart_cut_park_from_stored_internal_v1("));
    }

    #[test]
    fn target_handoff_requires_the_exact_durable_parked_ack_v1() {
        let runtime = include_str!("consensus_runtime.rs");
        let selector_start = runtime
            .find("const fn selects_process1_target_handoff_v1(&self)")
            .expect("target handoff selector remains present");
        let selector_end = runtime[selector_start..]
            .find("const fn is_prepared_v1")
            .map(|offset| selector_start + offset)
            .expect("target handoff selector remains bounded");
        let selector = &runtime[selector_start..selector_end];
        assert!(selector.contains("matches!(self, Self::TargetAcked(_))"));
        assert!(!selector.contains("matches!(self, Self::TargetParked(_))"));
        assert!(!selector.contains("PeerParked"));

        let loop_start = runtime
            .find("fn run_loop_v1(&mut self) -> Result<BoundedConsensusLoopOutcomeV1>")
            .expect("bounded loop returns a typed completion");
        let loop_end = runtime[loop_start..]
            .find("fn drain_ready_ingress_v1")
            .map(|offset| loop_start + offset)
            .expect("bounded loop remains bounded");
        let run_loop = &runtime[loop_start..loop_end];
        assert!(run_loop.contains("let cut_progress = self.maybe_complete_restart_cut_v1()?"));
        assert!(
            run_loop.contains("let peer_cut_progress = self.maybe_complete_peer_restart_cut_v1()?")
        );
        assert!(run_loop
            .contains("let parked_ack_progress = self.maybe_complete_restart_parked_ack_v1()?"));

        let finish_start = runtime
            .find("fn revalidate_target_process1_handoff_v1")
            .expect("target handoff fresh validator remains present");
        let finish_end = runtime[finish_start..]
            .find("fn finish_v1(&mut self)")
            .map(|offset| finish_start + offset)
            .expect("target handoff finisher remains separate from normal finish");
        let finish = &runtime[finish_start..finish_end];
        for required in [
            "self.authority.is_none()",
            "revalidate_target_process1_parked_ack_handoff_v1",
            "RestartLifecycleV1::TargetAcked",
            "restart_parked_ack_artifact_sha256",
            "restart_parked_ack_admission_set_sha256",
            ".close()",
            "protocol_authority: false",
            "production_activation: false",
        ] {
            assert!(finish.contains(required), "handoff lost {required}");
        }
        for forbidden in [
            "close_if_ingress_empty_v1",
            "record_clean_stop",
            "RuntimeEventKindV1::SafetyHalted",
            "write_consensus_run_report_v1",
            "write_runtime_metrics_v1",
            "write_runtime_final_state_v1",
            "write_terminal_seal_v1",
        ] {
            assert!(
                !finish.contains(forbidden),
                "handoff unexpectedly contains {forbidden}"
            );
        }

        let cli = include_str!("main.rs");
        assert!(cli.contains("ExitCode::from(PROCESS1_TARGET_PARKED_EXIT_STATUS_V1)"));
        assert!(cli.contains("BoundedConsensusRunOutcomeV1::CompletedReport(report_path)"));
        assert!(cli.contains("BoundedConsensusRunOutcomeV1::Process1TargetParked(handoff)"));
        assert!(cli.contains("ExitCode::from(2)"));
        assert!(!cli.contains("std::process::exit"));
        assert_eq!(PROCESS1_TARGET_PARKED_EXIT_STATUS_V1, 75);
    }

    #[test]
    fn bounded_runtime_dispatches_only_typed_restart_requirement_to_stored_process2_path() {
        let source = include_str!("consensus_runtime.rs");
        let entry = source
            .find("pub fn run_bounded_consensus_v1<C>")
            .expect("bounded runtime entry remains present");
        let process2_branch = source[entry..]
            .find("Err(error) if error.requires_stored_restart_cut_v1()")
            .map(|offset| entry + offset)
            .expect("process2 inert branch remains present");
        let process1_guard = source[process2_branch..]
            .find("runtime event journal process instance is outside the bounded two-process contract")
            .map(|offset| process2_branch + offset)
            .expect("process1 guard remains after the inert process2 branch");
        let dispatch = &source[entry..process1_guard];
        let classifier = dispatch
            .find("error.requires_stored_restart_cut_v1()")
            .expect("dispatch uses the typed RestartCut classifier");
        let open = dispatch
            .find("start_process2_with_stored_restart_cut_v1")
            .expect("typed dispatch reopens the journal-selected RestartCut/RestartPark pair");
        assert!(classifier < open);
        assert!(!dispatch.contains("load_local_restart_cut_certificate_v1"));
        assert!(dispatch.contains("Err(error) => return Err(anyhow!"));
        assert!(!dispatch.contains("to_string()"));
        assert!(!dispatch.contains("verified RestartCut is required"));

        let inert_process2 = &source[process2_branch..process1_guard];
        for required in [
            "start authenticated process2 event journal",
            "SignedReplayArchiveV1::open_existing_v1",
            ".authenticate_recovery_v1",
            ".recover_full_process2_inert_v1",
            "require_process2_full_recovery_join_v1",
            "consume process2 start, RestartCut/RestartPark, and full inert recovery",
            "let joined =",
            "joined.record_inert_safety_halted_v1()",
            "RestartCut/RestartPark/RestartParkedAck-joined process2 is inert; authenticated start-catchup, RecoveryReady, and RecoveryStart remain unavailable",
        ] {
            assert!(inert_process2.contains(required), "missing {required}");
        }
        for forbidden in [
            "initialize_new_v1",
            "commission(&mut config",
            "ContinuousValidatorAuthorityV0::from_takeover_runtime_v0",
            "PersistentAuthenticatedPeerMeshV0::",
            "GenerationAwarePacemakerV0::",
            "into_recovered_ordinary_runtime_v1",
            "activate_for_lab_authority_v1",
        ] {
            assert!(
                !inert_process2.contains(forbidden),
                "process2 branch unexpectedly contains {forbidden}"
            );
        }
    }

    #[test]
    fn process1_parked_ack_runtime_is_bounded_durable_and_inert_v1() {
        let runtime = include_str!("consensus_runtime.rs");
        let round_start = runtime
            .find("struct RestartCutRoundV1")
            .expect("restart round remains present");
        let round_end = runtime[round_start..]
            .find("struct LocalRestartTargetCollectingOwnerV1")
            .map(|offset| round_start + offset)
            .expect("restart round remains bounded");
        let round = &runtime[round_start..round_end];
        assert!(round.contains(
            "pending_parked_acks: BTreeMap<ValidatorId, AdmittedRestartProtocolMessageV1>"
        ));
        assert!(round
            .contains("admitted_parked_acks: BTreeMap<ValidatorId, AdmittedRestartParkedAckV1>"));

        let handler_start = runtime
            .find("fn handle_restart_protocol_action_v1(")
            .expect("restart handler remains present");
        let handler_end = runtime[handler_start..]
            .find("fn record_prepared_normal_frame_drop_v1")
            .map(|offset| handler_start + offset)
            .expect("restart handler remains bounded");
        let handler = &runtime[handler_start..handler_end];
        assert!(handler.contains("RestartProtocolPhaseV1::ParkedAck"));
        assert!(handler.contains("AdmittedRestartParkedAckV1::new(admitted, stored)"));
        assert!(handler.contains("pending_parked_acks"));
        assert!(handler.contains("< 6"));

        let ack_start = runtime
            .find("fn maybe_complete_restart_parked_ack_v1(&mut self)")
            .expect("ParkedAck runtime transition remains present");
        let drain_start = runtime[..ack_start]
            .rfind("fn restart_parked_ack_drain_ready_v1(&self)")
            .expect("ParkedAck drain gate remains present");
        let drain = &runtime[drain_start..ack_start];
        assert!(drain.contains("self.outbox.is_empty()"));
        assert!(drain.contains("pending_outbound_bytes_v1()? == 0"));
        let ack_end = runtime[ack_start..]
            .find("fn reconcile_expected_connectivity_fault_v1")
            .map(|offset| ack_start + offset)
            .expect("ParkedAck runtime transition remains bounded");
        let ack = &runtime[ack_start..ack_end];
        for required in [
            ".into_parked_ack_declaration_v1(owner.journal_commit, &self.config)",
            "RestartProtocolPhaseV1::ParkedAck",
            "VerifiedRestartParkedAckBarrierV1::new_with_originated_v1",
            ".persist_v1(&self.config)",
            ".record_restart_parked_ack_from_owner_v1(&acknowledged)",
            "RuntimeRestartPhaseV1::Process1PeerParkedAcked",
            "RuntimeRestartPhaseV1::Process1TargetParkedAcked",
            "RestartLifecycleV1::PeerAcked",
            "RestartLifecycleV1::TargetAcked",
        ] {
            assert!(ack.contains(required), "ParkedAck runtime lost {required}");
        }
        assert!(!ack.contains("RecoveryReady"));
        assert!(!ack.contains("RecoveryStart"));
        assert!(!ack.contains("activate"));
    }

    #[test]
    fn process2_full_recovery_operational_branch_has_no_activation_path_v1() {
        let source = include_str!("consensus_runtime.rs");
        let start = source
            .find("Err(error) if error.requires_stored_restart_cut_v1()")
            .expect("process2 operational branch remains present");
        let end = source[start..]
            .find("runtime event journal process instance is outside the bounded two-process contract")
            .map(|offset| start + offset)
            .expect("process2 operational branch remains bounded");
        let branch = &source[start..end];
        let journal_start = branch
            .find("let started = RuntimeEventJournalV1::start_process2_with_stored_restart_cut_v1")
            .expect("branch reopens the journal-selected pair into the journal-start owner");
        let full = branch
            .find(".recover_full_process2_inert_v1")
            .expect("branch obtains the complete inert process2 owner");
        let join = branch
            .find("require_process2_full_recovery_join_v1")
            .expect("branch consumes the full recovery owners");
        let halt = branch
            .find("joined.record_inert_safety_halted_v1()")
            .expect("branch records only its authenticated inert halt");
        assert!(journal_start < full && full < join && join < halt);
        assert!(branch
            .contains("consume process2 start, RestartCut/RestartPark, and full inert recovery"));
        assert!(!branch.contains("load_local_restart_cut_certificate_v1"));
        for forbidden in [
            "into_recovered_ordinary_runtime_v1",
            "activate_for_lab_authority_v1",
            "PersistentAuthenticatedPeerMeshV0::",
            "GenerationAwarePacemakerV0::",
            "write_runtime_metrics_v1",
            "write_runtime_final_state_v1",
        ] {
            assert!(
                !branch.contains(forbidden),
                "process2 operational branch unexpectedly contains {forbidden}"
            );
        }
    }

    #[test]
    fn zero_delta_projection_store_is_linear_dormant_and_not_an_operational_bypass_v1() {
        let source = include_str!("consensus_runtime.rs");
        let method_start = source
            .find("fn persist_zero_delta_cut_dormant_v1(")
            .expect("dormant zero-delta persistence seam remains present");
        let method_end = source[method_start..]
            .find("impl std::fmt::Debug for RestartCutJoinedProcess2ZeroDeltaOwnerV1")
            .map(|offset| method_start + offset)
            .expect("dormant zero-delta persistence seam remains bounded");
        let method = &source[method_start..method_end];
        for required in [
            "self.revalidate_retained_inputs_v1()?",
            "restart_prepare_request_sha256_v1()",
            "RecoveryZeroDeltaCutV1::new_direct7",
            "Sha256::digest(&cut_bytes)",
            "caught_up_cut_artifact_sha256: cut_artifact_sha256",
            "RecoveryContextV1::new_direct7",
            "persist_recovery_zero_delta_cut_v1",
            ".revalidate_fresh_v1(validator_set)",
            "RestartCutJoinedProcess2PersistedZeroDeltaOwnerV1",
        ] {
            assert!(method.contains(required), "dormant seam lost {required}");
        }
        assert!(!method.contains("cut.digest()"));
        let first_revalidate = method
            .find("self.revalidate_retained_inputs_v1()?")
            .expect("pre-persist retained-owner revalidation remains present");
        let persist = method
            .find("persist_recovery_zero_delta_cut_v1")
            .expect("canonical cut persistence remains present");
        let final_revalidate = method
            .rfind("self.revalidate_retained_inputs_v1()?")
            .expect("commit-point retained-owner revalidation remains present");
        assert!(first_revalidate < persist && persist < final_revalidate);

        let owner_start = source
            .find("struct RestartCutJoinedProcess2PersistedZeroDeltaOwnerV1")
            .expect("persisted zero-delta composite remains present");
        let owner_declaration = source[..owner_start]
            .rfind("#[must_use")
            .expect("persisted zero-delta composite remains must-use");
        let owner_end = source[owner_start..]
            .find("impl std::fmt::Debug for RestartCutJoinedProcess2PersistedZeroDeltaOwnerV1")
            .map(|offset| owner_start + offset)
            .expect("persisted zero-delta composite remains bounded");
        let owner = &source[owner_declaration..owner_end];
        assert!(owner.contains("joined: RestartCutJoinedProcess2ZeroDeltaOwnerV1"));
        assert!(owner.contains("persisted: StoredRecoveryZeroDeltaCutV1"));
        assert!(!owner.contains("derive(Clone"));

        let branch_start = source
            .find("Err(error) if error.requires_stored_restart_cut_v1()")
            .expect("process2 operational branch remains present");
        let branch_end = source[branch_start..]
            .find("runtime event journal process instance is outside the bounded two-process contract")
            .map(|offset| branch_start + offset)
            .expect("process2 operational branch remains bounded");
        let branch = &source[branch_start..branch_end];
        for forbidden in [
            ".confirm_zero_delta_caught_up_v1(",
            ".persist_zero_delta_cut_dormant_v1(",
            "RecoveryZeroDeltaCutV1::new_direct7",
            "persist_recovery_zero_delta_cut_v1",
        ] {
            assert!(
                !branch.contains(forbidden),
                "active process2 branch bypasses the missing N/N park gate via {forbidden}"
            );
        }
    }

    #[test]
    fn process2_full_recovery_join_is_linear_and_facts_cannot_authorize_v1() {
        let source = include_str!("consensus_runtime.rs");
        let obsolete_facts_owner = ["Process2RestartCut", "StartFactsV1"].concat();
        assert!(!source.contains(&obsolete_facts_owner));

        let owner_start = source
            .find("struct RestartCutJoinedProcess2InertOwnerV1")
            .expect("joined process2 owner remains present");
        let owner_declaration = source[..owner_start]
            .rfind("#[must_use")
            .expect("joined process2 owner remains must-use");
        let owner_end = source[owner_start..]
            .find("impl std::fmt::Debug for RestartCutJoinedProcess2InertOwnerV1")
            .map(|offset| owner_start + offset)
            .expect("joined process2 owner debug boundary remains present");
        let owner = &source[owner_declaration..owner_end];
        for retained in [
            "started: Process2JournalStartedFromRestartCutV1",
            "recovered: ArchivedDeployedProcess2RecoveryOwnerV1",
        ] {
            assert!(owner.contains(retained), "joined owner lost {retained}");
        }
        assert!(!owner.contains("StoredRestartCutCertificateV1"));
        assert!(!owner.contains("derive(Clone"));

        let join_start = source
            .find("fn require_process2_full_recovery_join_v1(")
            .expect("consuming process2 join remains present");
        let join_end = source[join_start..]
            .find("const fn is_restart_protocol_kind_v1")
            .map(|offset| join_start + offset)
            .expect("process2 join boundary remains present");
        let join = &source[join_start..join_end];
        for consumed in [
            "started: Process2JournalStartedFromRestartCutV1",
            "recovered: ArchivedDeployedProcess2RecoveryOwnerV1",
            ") -> Result<RestartCutJoinedProcess2InertOwnerV1>",
            "Ok(RestartCutJoinedProcess2InertOwnerV1",
        ] {
            assert!(join.contains(consumed), "join lost {consumed}");
        }
        for borrowed in [
            "started: &Process2JournalStartedFromRestartCutV1",
            "recovered: &ArchivedDeployedProcess2RecoveryOwnerV1",
            ") -> Result<()> ",
        ] {
            assert!(!join.contains(borrowed), "join regressed to {borrowed}");
        }
        assert!(!join.contains("StoredRestartCutCertificateV1"));

        let impl_start = source
            .find("impl RestartCutJoinedProcess2InertOwnerV1")
            .expect("joined process2 owner implementation remains present");
        let impl_end = source[impl_start..]
            .find("fn require_process2_full_recovery_join_v1(")
            .map(|offset| impl_start + offset)
            .expect("joined owner implementation remains bounded");
        let joined_api = &source[impl_start..impl_end];
        assert!(joined_api.contains("fn record_inert_safety_halted_v1(mut self)"));
        for forbidden in [
            "PersistentAuthenticatedPeerMeshV0",
            "RecoveryReady",
            "RecoveryStart",
            "into_recovered_ordinary_runtime_v1",
            "activate_for_lab_authority_v1",
            "GenerationAwarePacemakerV0",
        ] {
            assert!(
                !joined_api.contains(forbidden),
                "joined process2 owner unexpectedly exposes {forbidden}"
            );
        }

        let event_source = include_str!("process_event.rs");
        let started_owner = event_source
            .find("pub(crate) struct Process2JournalStartedFromRestartCutV1")
            .expect("linear process2 journal-start owner remains present");
        let started_declaration = event_source[..started_owner]
            .rfind("#[must_use")
            .expect("linear process2 journal-start owner remains must-use");
        let started_impl = event_source[started_owner..]
            .find("impl Process2JournalStartedFromRestartCutV1")
            .map(|offset| started_owner + offset)
            .expect("journal-start owner implementation remains present");
        assert!(!event_source[started_declaration..started_impl].contains("derive(Clone"));
        assert!(
            event_source[started_owner..started_impl].contains("journal: RuntimeEventJournalV1")
        );
        assert!(event_source[started_owner..started_impl]
            .contains("stored: ReopenedRestartCutParkAckCertificatesV1"));
        assert!(event_source
            .contains(") -> Result<Process2JournalStartedFromRestartCutV1, RuntimeEventErrorV1>"));
        let started_impl_end = event_source[started_impl..]
            .find("#[derive(Clone, Copy)]")
            .map(|offset| started_impl + offset)
            .expect("journal-start owner implementation remains bounded");
        let started_api = &event_source[started_impl..started_impl_end];
        assert!(started_api.contains("record_joined_inert_safety_halted_v1"));
        assert!(started_api.contains("RuntimeEventKindV1::SafetyHalted"));
        for forbidden in [
            "fn into_journal",
            "fn journal_mut",
            "pub(crate) fn append",
            "RuntimeEventKindV1::CatchupComplete",
            "restart_completed",
        ] {
            assert!(
                !started_api.contains(forbidden),
                "journal-start owner unexpectedly exposes {forbidden}"
            );
        }

        assert!(join.contains("revalidate process2 journal at full-join commit"));
        assert!(join.contains("freshly revalidate process2 archive at full-join commit"));
    }

    #[test]
    fn restart_quiescing_stops_local_production_but_preserves_authenticated_drain() {
        let running = RestartLifecycleV1::Running;
        assert!(running.allows_local_proposal_v1());
        assert!(running.allows_authenticated_drain_v1());

        let quiescing = RestartLifecycleV1::TargetQuiescing(restart_intent_fixture_v1());
        assert!(!quiescing.allows_local_proposal_v1());
        assert!(quiescing.allows_authenticated_drain_v1());
        assert!(!quiescing.is_prepared_v1());
        assert_eq!(quiescing.intent_v1(), Some(restart_intent_fixture_v1()));

        let prepared_facts = prepared_owner_fixture_v1().facts_v1();
        assert_eq!(prepared_facts.journal_event_sequence, 9);
        assert_eq!(prepared_facts.signer_durable_vote_intent_count, 1);
        assert_eq!(prepared_facts.signer_durable_timeout_intent_count, 1);
        assert_eq!(prepared_facts.signer_signed_vote_intent_count, 1);
        assert_eq!(prepared_facts.signer_signed_timeout_intent_count, 1);
        assert_ne!(prepared_facts.signer_inventory_digest, [0; 32]);
        assert_eq!(prepared_facts.signer_exact_watermark.sequence(), 4);
        assert_ne!(prepared_facts.checkpoint_canonical_sha256, [0; 32]);
        assert_eq!(prepared_facts.finalized_chain_root, [0x40; 32]);
    }

    #[test]
    fn restart_quiescence_rejects_every_unresolved_obligation() {
        let baseline = restart_quiescence_fixture_v1();
        assert!(is_restart_quiescent_v1(&baseline));
        let rejects = |candidate: RestartQuiescenceSnapshotV1| {
            assert!(!is_restart_quiescent_v1(&candidate));
        };

        let mut candidate = baseline;
        candidate.restart_requested = false;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.normal_stop_in_progress = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.process_instance = 2;
        rejects(candidate);
        for phase in [
            PocoNodeLabAuthorityPhaseV0::VoteSigned,
            PocoNodeLabAuthorityPhaseV0::TimeoutSigned,
        ] {
            let mut candidate = baseline;
            candidate.authority_phase = phase;
            rejects(candidate);
        }
        let mut candidate = baseline;
        candidate.pending_timeout_certificate = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.outbox_frame_count = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.outbox_payload_bytes = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.pending_proposal_count = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.pending_certificate_count = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.prestarted_ingress_count = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.unavailable_session_count = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.mesh_pending_outbound_bytes = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.post_timeout_rebase_pending = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.active_connectivity_fault = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.expected_control_fault = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.active_journal_fault_count = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_restart_prepare_absent = false;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_restart_pending_catchup = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_restart_completed = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_final_tip_recorded = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_clean_stop_recorded = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_safety_halted = true;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.finalized_height = 3;
        candidate.application_height = 3;
        candidate.journal_finalized_height = 3;
        candidate.journal_application_height = 3;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.application_height = 3;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.application_block_id = BlockId::new([0x50; 32]);
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_finalized_height = 3;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_application_height = 3;
        rejects(candidate);
    }

    #[test]
    fn peer_restart_quiescence_needs_no_control_intent_and_requires_exact_shared_cut_v1() {
        let mut baseline = restart_quiescence_fixture_v1();
        baseline.restart_requested = false;
        baseline.restart_intent_generation = 0;
        baseline.restart_intent_nonce = 0;
        baseline.restart_intent_request_sha256 = [0; 32];
        assert!(is_restart_common_quiescent_v1(&baseline));
        assert!(!is_restart_quiescent_v1(&baseline));

        let shared_cut = RestartSharedCutV1::from_state(restart_cut_state_fixture_v1());
        assert!(peer_restart_shared_cut_ready_v1(&baseline, shared_cut).unwrap());

        let mut behind = baseline;
        behind.finalized_height = 3;
        behind.application_height = 3;
        assert!(!peer_restart_shared_cut_ready_v1(&behind, shared_cut).unwrap());

        let mut ahead = baseline;
        ahead.finalized_height = 5;
        ahead.application_height = 5;
        assert!(peer_restart_shared_cut_ready_v1(&ahead, shared_cut).is_err());

        let rejects = |candidate: RestartQuiescenceSnapshotV1| {
            assert!(peer_restart_shared_cut_ready_v1(&candidate, shared_cut).is_err());
        };
        let mut candidate = baseline;
        candidate.finalized_block_id = BlockId::new([0x91; 32]);
        rejects(candidate);
        let mut candidate = baseline;
        candidate.finalized_chain_root = [0x92; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.application_block_id = BlockId::new([0x93; 32]);
        rejects(candidate);
        let mut candidate = baseline;
        candidate.application_state_root = [0x94; 32];
        rejects(candidate);

        let mut different_local_journal = baseline;
        different_local_journal.journal_head_sequence += 1;
        different_local_journal.journal_head_sha256 = [0x95; 32];
        assert!(peer_restart_shared_cut_ready_v1(&different_local_journal, shared_cut).unwrap());
    }

    #[test]
    fn restart_quiescence_rejects_every_inexact_or_zero_cut_coordinate() {
        let baseline = restart_quiescence_fixture_v1();
        assert!(is_restart_quiescent_v1(&baseline));
        assert_eq!(baseline.signer_signed_vote_intent_count, 1);
        assert_eq!(baseline.signer_signed_timeout_intent_count, 1);
        assert_eq!(baseline.signer_exact_watermark.unwrap().sequence(), 4);
        assert_ne!(baseline.checkpoint_canonical_sha256, [0; 32]);
        let rejects = |candidate: RestartQuiescenceSnapshotV1| {
            assert!(!is_restart_quiescent_v1(&candidate));
        };

        let mut candidate = baseline;
        candidate.current_view = View::new(8);
        rejects(candidate);
        let mut candidate = baseline;
        candidate.high_qc = restart_qc_ref_fixture_v1(
            u64::MAX,
            4,
            *baseline.finalized_block_id.as_bytes(),
            [0x42; 32],
            [0x43; 32],
        );
        rejects(candidate);

        let mut candidate = baseline;
        candidate.proposal_parent_height = 5;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.proposal_parent_block_id = BlockId::new([0x51; 32]);
        rejects(candidate);
        let mut candidate = baseline;
        candidate.high_qc = restart_qc_ref_fixture_v1(6, 3, [0x52; 32], [0x42; 32], [0x43; 32]);
        candidate.proposal_parent_height = 3;
        candidate.proposal_parent_block_id = BlockId::new([0x52; 32]);
        rejects(candidate);

        let mut candidate = baseline;
        candidate.signer_watermark_sequence = 3;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.signer_durable_vote_intent_count = 2;
        candidate.signer_signed_vote_intent_count = 2;
        candidate.signer_durable_timeout_intent_count = 0;
        candidate.signer_signed_timeout_intent_count = 0;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.signer_inventory_digest = [0x58; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.signed_vote_intents = 2;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.checkpoint_signer_exact_watermark = Some(
            SignerWatermarkV0::from_persisted_parts([0x53; 32], [0x54; 32], 4, [0x59; 32]).unwrap(),
        );
        rejects(candidate);
        let mut candidate = baseline;
        candidate.signer_exact_watermark = None;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.signer_watermark_sequence = 0;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.signed_vote_intents = 0;
        candidate.signer_watermark_sequence = 0;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.signed_vote_intents = u64::MAX;
        candidate.signed_timeout_intents = 1;
        candidate.signer_watermark_sequence = u64::MAX;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.signed_vote_intents = u64::MAX / 2 + 1;
        candidate.signed_timeout_intents = 0;
        candidate.signer_watermark_sequence = u64::MAX;
        rejects(candidate);

        let mut candidate = baseline;
        candidate.restart_intent_generation = 0;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.restart_intent_nonce = 0;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.restart_intent_request_sha256 = [0; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.local_validator = ValidatorId::new([0; 32]);
        rejects(candidate);
        let mut candidate = baseline;
        candidate.ordinary_start_height = 0;
        rejects(candidate);

        let mut candidate = baseline;
        candidate.high_qc = restart_qc_ref_fixture_v1(
            6,
            4,
            *baseline.finalized_block_id.as_bytes(),
            [0; 32],
            [0x43; 32],
        );
        rejects(candidate);
        let mut candidate = baseline;
        candidate.high_qc = restart_qc_ref_fixture_v1(6, 4, [0; 32], [0x42; 32], [0x43; 32]);
        candidate.proposal_parent_block_id = BlockId::new([0; 32]);
        rejects(candidate);
        let mut candidate = baseline;
        candidate.high_qc = restart_qc_ref_fixture_v1(
            6,
            4,
            *baseline.finalized_block_id.as_bytes(),
            [0x42; 32],
            [0; 32],
        );
        rejects(candidate);
        let mut candidate = baseline;
        candidate.finalized_block_id = BlockId::new([0; 32]);
        candidate.application_block_id = BlockId::new([0; 32]);
        rejects(candidate);
        let mut candidate = baseline;
        candidate.finalized_chain_root = [0; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.application_state_root = [0; 32];
        rejects(candidate);

        let mut candidate = baseline;
        candidate.safety_revision = 0;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.safety_record_checksum = [0; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.safety_chain_checksum = [0; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.checkpoint_generation = 0;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.checkpoint_canonical_sha256 = [0; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.runtime_checkpoint_canonical_sha256 = [0x5a; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.replay_archive_context_sha256 = [0; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.replay_archive_head_sequence = 0;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.replay_archive_head_sha256 = [0; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_head_sequence = 0;
        candidate.journal_next_sequence = 1;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_head_sha256 = [0; 32];
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_next_sequence = 10;
        rejects(candidate);
        let mut candidate = baseline;
        candidate.journal_head_sequence = u64::MAX;
        candidate.journal_next_sequence = 0;
        rejects(candidate);
    }

    #[test]
    fn signer_lifetime_formula_is_bounded_before_runtime_effects() {
        assert_eq!(CONSENSUS_RUNTIME_FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS_V1, 30);
        assert_eq!(
            CONSENSUS_RUNTIME_TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS_V1,
            30
        );
        assert_eq!(CONSENSUS_RUNTIME_MESH_SETUP_ALLOWANCE_SECONDS_V1, 330);
        assert_eq!(CONSENSUS_RUNTIME_STARTUP_ALLOWANCE_SECONDS_V1, 630);
        assert_eq!(CONSENSUS_RUNTIME_FLEET_PROCESS_ALLOWANCE_SECONDS_V1, 660);
        assert_eq!(MINIMUM_CONSENSUS_RUN_BLOCKS_V1, 3);
        assert_eq!(DEPLOYED_CORE_MAX_BLOCKS_V1, 128);
        assert_eq!(validate_deployed_core_max_blocks_v1(128).unwrap(), 128);
        assert!(validate_deployed_core_max_blocks_v1(129).is_err());
        assert!(validate_deployed_core_max_blocks_v1(u64::MAX).is_err());
        assert!(validate_active_validator_count_v1(7).is_ok());
        assert!(validate_active_validator_count_v1(31).is_err());
        assert!(validate_active_validator_count_v1(100).is_err());
        assert_eq!(
            MESH_SETUP_TIMEOUT_V1,
            Duration::from_secs(CONSENSUS_RUNTIME_MESH_SETUP_ALLOWANCE_SECONDS_V1)
        );
        let bounds =
            ContinuousSignerLifetimeBoundsV0::from_campaign_v0(100, 60, 30, 30, 2).unwrap();
        assert_eq!(bounds.requested_max_blocks_v0(), 100);
        assert_eq!(bounds.maximum_timeout_view_advances_v0(), 60);
        assert_eq!(bounds.maximum_local_vote_intents_v0(), 160);
        assert_eq!(bounds.maximum_local_timeout_intents_v0(), 60);
        assert_eq!(bounds.maximum_total_intents_v0(), 220);
        let archive = SignedReplayArchiveBoundsV1::from_signer_lifetime_v1(bounds).unwrap();
        assert_eq!(archive.maximum_timeout_view_advances_v1(), 60);
        assert_eq!(archive.maximum_proposal_entries_v1(), 160);
        assert_eq!(archive.maximum_quorum_certificate_entries_v1(), 161);
        assert_eq!(archive.maximum_archive_entries_v1(), 321);
        assert!(
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(4_094, 2, 4_096, 2,)
                .is_err()
        );
        let signer_only =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(4_096, 0, 4_096, 0)
                .unwrap();
        assert!(SignedReplayArchiveBoundsV1::from_signer_lifetime_v1(signer_only).is_err());
        assert_eq!(
            canonical_utc_timestamp_v1(UNIX_EPOCH).unwrap(),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn deployed_core_capacity_fits_commissioning_record_envelope_v1() {
        let core_config = |validator_count: usize, max_blocks: usize| {
            let parameters = ConsensusParametersV0::reference_shadow_v0();
            let validators = (1..=validator_count)
                .map(|index| {
                    let marker = u8::try_from(index).unwrap();
                    let key = SigningKey::from_bytes(&[marker; 32]);
                    Validator::new(
                        ValidatorId::new([marker; 32]),
                        ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                        VotingPower::new(1).unwrap(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let validator_set = ValidatorSet::new(
                GenesisHash::new([u8::try_from(validator_count).unwrap(); 32]),
                ChainId::new(&format!("trnm-poco-deployed-capacity-{validator_count}")).unwrap(),
                ProtocolVersion::V0,
                Epoch::new(0),
                parameters.hash(),
                validators,
            )
            .unwrap();
            trnm_consensus_core::CoreConfig::new(
                validator_set.validators()[0].id(),
                validator_set,
                parameters,
                0,
                max_blocks,
                validator_count * 64,
            )
            .unwrap()
        };

        for validator_count in [7, 31] {
            let config = core_config(validator_count, DEPLOYED_CORE_MAX_BLOCKS_V1);
            let minimum = trnm_consensus_core::minimum_safety_state_record_limits_v0(&config)
                .expect("derive record-envelope-compatible topology");
            assert!(minimum.maximum_record_bytes() <= DEPLOYED_LAB_MAXIMUM_RECORD_BYTES_V0);
            assert!(minimum.maximum_blob_bytes() <= DEPLOYED_LAB_MAXIMUM_BLOB_BYTES_V0);
            validate_deployed_lab_core_record_envelope_v0(&config)
                .expect("record-envelope-compatible topology fits exact Node envelope");
        }

        let unsupported_hundred = core_config(100, DEPLOYED_CORE_MAX_BLOCKS_V1);
        let unsupported_minimum =
            trnm_consensus_core::minimum_safety_state_record_limits_v0(&unsupported_hundred)
                .expect("derive unsupported hundred-validator envelope");
        assert!(unsupported_minimum.maximum_record_bytes() > DEPLOYED_LAB_MAXIMUM_RECORD_BYTES_V0);
        assert_eq!(
            validate_deployed_lab_core_record_envelope_v0(&unsupported_hundred)
                .unwrap_err()
                .stage_v0(),
            "source.record_capacity"
        );

        let historical_wide = core_config(7, 131_072);
        let historical_minimum =
            trnm_consensus_core::minimum_safety_state_record_limits_v0(&historical_wide)
                .expect("derive historical over-wide record envelope");
        assert!(historical_minimum.maximum_record_bytes() > DEPLOYED_LAB_MAXIMUM_RECORD_BYTES_V0);
        assert!(validate_deployed_lab_core_record_envelope_v0(&historical_wide).is_err());
    }

    #[test]
    fn runtime_fault_projection_requires_exact_peer_direction_evidence() {
        use crate::process_event::RuntimeFaultV1;

        let local = ValidatorId::new([0x11; 32]);
        let leader = ValidatorId::new([0x22; 32]);
        let other = ValidatorId::new([0x33; 32]);
        let mut unavailable = BTreeSet::new();
        unavailable.insert((PeerDirectionV0::Outbound, leader));
        assert_eq!(
            observed_connectivity_fault_subject_v1(
                RuntimeFaultV1::AsymmetricPartition,
                local,
                leader,
                &unavailable,
            ),
            Some(leader)
        );
        assert_eq!(
            observed_connectivity_fault_subject_v1(
                RuntimeFaultV1::LeaderLoss,
                local,
                leader,
                &unavailable,
            ),
            None
        );
        unavailable.insert((PeerDirectionV0::Inbound, leader));
        assert_eq!(
            observed_connectivity_fault_subject_v1(
                RuntimeFaultV1::LeaderLoss,
                local,
                leader,
                &unavailable,
            ),
            Some(leader)
        );
        assert_eq!(
            observed_connectivity_fault_subject_v1(
                RuntimeFaultV1::HostLoss,
                local,
                leader,
                &unavailable,
            ),
            Some(leader)
        );
        unavailable.insert((PeerDirectionV0::Inbound, other));
        assert_eq!(
            observed_connectivity_fault_subject_v1(
                RuntimeFaultV1::AsymmetricPartition,
                local,
                leader,
                &unavailable,
            ),
            Some(other)
        );
        for unsupported in [
            RuntimeFaultV1::ValidatorProcessKill,
            RuntimeFaultV1::BoundedDelayLoss,
            RuntimeFaultV1::StaleSnapshot,
            RuntimeFaultV1::RollbackAttempt,
            RuntimeFaultV1::EpochHandoff,
        ] {
            assert_eq!(
                observed_connectivity_fault_subject_v1(unsupported, local, leader, &unavailable,),
                None
            );
        }
        assert_eq!(
            observed_connectivity_fault_subject_v1(
                RuntimeFaultV1::LeaderLoss,
                local,
                local,
                &unavailable,
            ),
            None
        );
    }

    #[test]
    fn transport_profiles_and_forward_outbox_are_bounded_before_socket_effects() {
        assert_eq!(
            ConsensusTransportProfileV1::Direct.relay_hop_budget_v1(),
            None
        );
        for (validators, expected_hops) in [(31usize, 4u8), (100, 13)] {
            let profile = ConsensusTransportProfileV1::SparseRelay {
                hop_budget: required_ring_relay_hops_v0(validators, SPARSE_PEER_DEGREE_V1)
                    .expect("derive frozen sparse relay bound"),
            };
            assert_eq!(profile.relay_hop_budget_v1(), Some(expected_hops));
        }

        let peers = (1u8..=8)
            .map(|marker| ValidatorId::new([marker; 32]))
            .collect::<Vec<_>>();
        let excluded = peers[3];
        let mut outbox = OrderedConsensusOutboxV1::new(peers.clone());
        outbox
            .enqueue_except_v1(FrameKind::ConsensusRelay, vec![0x51; 128], excluded)
            .expect("queue one forwarded relay without its inbound peer");
        assert_eq!(outbox.pending.len(), 1);
        assert_eq!(outbox.pending_bytes, 128);
        let queued = outbox.pending.front().expect("forwarded relay is queued");
        assert_eq!(queued.kind, FrameKind::ConsensusRelay);
        assert_eq!(queued.payload.len(), 128);
        assert_eq!(queued.remaining_peers.len(), peers.len() - 1);
        assert!(!queued.remaining_peers.contains(&excluded));
    }

    #[test]
    fn pending_proposal_buffer_deduplicates_prunes_stale_and_fails_at_65() {
        let (keys, validator_set, parameters, genesis_high_qc, parent_qc) =
            synthetic_proposal_fixture_v1();
        let known = BTreeSet::new();
        let first = synthetic_future_proposal_v1(1, &keys, &validator_set, parameters, &parent_qc);
        let mut duplicate_buffer = PendingProposalBufferV1::default();
        assert!(matches!(
            duplicate_buffer
                .admit_v1(first.clone(), genesis_high_qc, &known)
                .unwrap(),
            PendingProposalAdmissionV1::Buffered
        ));
        assert!(matches!(
            duplicate_buffer
                .admit_v1(first.clone(), genesis_high_qc, &known)
                .unwrap(),
            PendingProposalAdmissionV1::Buffered
        ));
        assert_eq!(duplicate_buffer.len_v1(), 1);

        let future_high_qc = QcRef::new(
            trnm_consensus_types::CertificateId::new([0xf1; 32]),
            validator_set.epoch(),
            View::new(3),
            Height::new(3),
            BlockId::new([0xf2; 32]),
            validator_set.id(),
        );
        let mut first_seen = BTreeMap::new();
        record_proposal_first_seen_at_v1(
            &mut first_seen,
            first.block().id(),
            first.block().header().height().get(),
            Instant::now(),
        )
        .unwrap();
        let Some(PendingProposalAdmissionV1::IgnoreStale(block_id)) =
            duplicate_buffer.take_actionable_v1(future_high_qc, &known)
        else {
            panic!("high-QC progress must prune the now-stale pending proposal");
        };
        assert_eq!(block_id, first.block().id());
        forget_proposal_first_seen_v1(&mut first_seen, block_id);
        assert!(first_seen.is_empty());
        assert!(duplicate_buffer.is_empty());

        let mut capacity_buffer = PendingProposalBufferV1::default();
        for marker in 1..=u8::try_from(MAXIMUM_PENDING_PROPOSALS_V1).unwrap() {
            let proposal =
                synthetic_future_proposal_v1(marker, &keys, &validator_set, parameters, &parent_qc);
            assert!(matches!(
                capacity_buffer
                    .admit_v1(proposal, genesis_high_qc, &known)
                    .unwrap(),
                PendingProposalAdmissionV1::Buffered
            ));
        }
        assert_eq!(capacity_buffer.len_v1(), MAXIMUM_PENDING_PROPOSALS_V1);
        let overflow = synthetic_future_proposal_v1(
            u8::try_from(MAXIMUM_PENDING_PROPOSALS_V1 + 1).unwrap(),
            &keys,
            &validator_set,
            parameters,
            &parent_qc,
        );
        let error = capacity_buffer
            .admit_v1(overflow, genesis_high_qc, &known)
            .expect_err("the sixty-fifth distinct pending block must fail closed");
        assert!(error
            .to_string()
            .contains("pending proposal buffer exhausted"));

        let now = Instant::now();
        let mut bounded_first_seen = BTreeMap::new();
        for marker in 0..MAXIMUM_TRACKED_PROPOSAL_TIMESTAMPS_V1 {
            let marker = u8::try_from(marker).unwrap();
            record_proposal_first_seen_at_v1(
                &mut bounded_first_seen,
                BlockId::new([marker; 32]),
                u64::from(marker) + 1,
                now,
            )
            .unwrap();
        }
        let error = record_proposal_first_seen_at_v1(
            &mut bounded_first_seen,
            BlockId::new([0xfe; 32]),
            129,
            now,
        )
        .expect_err("the first-seen map must fail closed at its explicit bound");
        assert!(error.to_string().contains("first-seen buffer exhausted"));
        prune_finalized_proposal_timestamps_v1(&mut bounded_first_seen, 64);
        assert_eq!(bounded_first_seen.len(), 64);
    }

    #[test]
    fn real_authority_drains_child_after_late_parent_execution() {
        on_consensus_owner_stack_v1(|| {
            let mut fixture = real_takeover_fixture_v1(4);
            let parent_view = fixture.authorities[0]
                .facts_v0()
                .expect("read initial takeover facts")
                .current_view_v0();
            let parent_leader = leader_for(&fixture.validator_set, parent_view);
            let parent_leader_index = fixture
                .validator_set
                .validators()
                .iter()
                .position(|validator| validator.id() == parent_leader)
                .expect("parent leader belongs to validator set");
            let parent = fixture.authorities[parent_leader_index]
                .proposal_preimage_for_test_v0(
                    fixture.ordinary_start_height,
                    fixture.parent_timestamp_ms,
                    fixture.parent_transactions.clone(),
                )
                .expect("construct exact parent proposal")
                .seal_with_key_v0(&fixture.keys[parent_leader_index])
                .expect("seal exact parent proposal");
            let child_view = View::new(
                parent_view
                    .get()
                    .checked_add(1)
                    .expect("child view overflows"),
            );
            let child_leader = leader_for(&fixture.validator_set, child_view);
            assert_ne!(
                parent_leader, child_leader,
                "focused race requires distinct consecutive proposal senders"
            );
            let child_leader_index = fixture
                .validator_set
                .validators()
                .iter()
                .position(|validator| validator.id() == child_leader)
                .expect("child leader belongs to validator set");
            let target_index = (0..fixture.authorities.len())
                .find(|index| *index != child_leader_index)
                .expect("one authority can miss the parent broadcast");

            let voters = (0..fixture.authorities.len())
                .filter(|index| *index != target_index)
                .map(|index| {
                    fixture.authorities[index]
                        .vote_proposal_v0(parent.clone())
                        .expect("parent voter releases exact Vote")
                })
                .collect::<Vec<_>>();
            let parent_qc = quorum_certificate_v1(&fixture.validator_set, &parent, voters);
            for index in 0..fixture.authorities.len() {
                if index != target_index {
                    fixture.authorities[index]
                        .advance_quorum_certificate_v0(parent_qc.clone())
                        .expect("parent voters advance the exact QC");
                }
            }
            let child = fixture.authorities[child_leader_index]
                .proposal_preimage_for_test_v0(
                    fixture
                        .ordinary_start_height
                        .checked_add(1)
                        .expect("child height overflows"),
                    fixture.child_timestamp_ms,
                    fixture.child_transactions.clone(),
                )
                .expect("construct exact child proposal")
                .seal_with_key_v0(&fixture.keys[child_leader_index])
                .expect("seal exact child proposal");
            assert_eq!(
                child.witness().justify_qc().qc_ref(),
                QcRef::from(&parent_qc)
            );

            let initial = fixture.authorities[target_index]
                .facts_v0()
                .expect("read lagging authority facts");
            let mut known = BTreeSet::from([(
                initial.high_qc_v0().height().get(),
                *initial.high_qc_v0().block_id().as_bytes(),
            )]);
            let mut pending = PendingProposalBufferV1::default();
            let child_frame = AuthenticatedFrame {
                sender: child_leader,
                session: [0xc1; 32],
                sequence: 0,
                kind: FrameKind::Proposal,
                payload: UnboundProposalV0::from_signed(&child)
                    .expect("project child proposal")
                    .encode()
                    .expect("encode child proposal"),
            };
            let Some(RoutedConsensusActionV0::Proposal(child)) = fixture.authorities[target_index]
                .admit_authenticated_consensus_frame_v0(&child_frame)
                .expect("admit child from the next-view sender before its parent")
            else {
                panic!("first child delivery must enter the pending-proposal lane");
            };
            assert!(matches!(
                pending
                    .admit_v1(*child, initial.high_qc_v0(), &known)
                    .unwrap(),
                PendingProposalAdmissionV1::Buffered
            ));

            let parent_frame = AuthenticatedFrame {
                sender: parent_leader,
                session: [0xc2; 32],
                sequence: 0,
                kind: FrameKind::Proposal,
                payload: UnboundProposalV0::from_signed(&parent)
                    .expect("project parent proposal")
                    .encode()
                    .expect("encode parent proposal"),
            };
            let Some(RoutedConsensusActionV0::Proposal(parent_wire)) = fixture.authorities
                [target_index]
                .admit_authenticated_consensus_frame_v0(&parent_frame)
                .expect("admit late parent from its distinct sender")
            else {
                panic!("late parent must remain an actionable exact proposal");
            };
            let parent_vote = fixture.authorities[target_index]
                .vote_unbound_proposal_v0(*parent_wire)
                .expect("lagging authority executes and votes the late parent");
            assert_eq!(parent_vote.block_id(), parent.block().id());
            known.insert((
                parent.block().header().height().get(),
                *parent.block().id().as_bytes(),
            ));
            let lagging_high_qc = fixture.authorities[target_index]
                .facts_v0()
                .expect("read VoteSigned lagging facts")
                .high_qc_v0();
            let PendingProposalAdmissionV1::Vote(child) = pending
                .take_actionable_v1(lagging_high_qc, &known)
                .expect("known parent makes the child actionable")
            else {
                panic!("known parent must drain the pending child for voting");
            };
            let child_block_id = child.block().id();
            let child_vote = fixture.authorities[target_index]
                .vote_unbound_proposal_v0(*child)
                .expect("lagging authority applies parent QC and votes child");
            assert_eq!(child_vote.block_id(), child_block_id);
            assert!(pending.is_empty());
        });
    }

    fn synthetic_proposal_fixture_v1() -> (
        Vec<SigningKey>,
        ValidatorSet,
        ConsensusParametersV0,
        QcRef,
        QuorumCertificate,
    ) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (1u8..=4)
            .map(|marker| SigningKey::from_bytes(&[marker; 32]))
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
            .collect::<Vec<_>>();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0x91; 32]),
            ChainId::new("trnm-poco-pending-proposal-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        let genesis = QcReferenceV0::genesis_anchor(
            GenesisQcV0::new(
                validator_set.genesis_hash(),
                validator_set.chain_id(),
                &validator_set,
            )
            .unwrap(),
        )
        .qc_ref();
        let parent_block = BlockId::new([0xa1; 32]);
        let votes = (0..3)
            .map(|index| {
                signed_vote_v1(
                    &validator_set,
                    &keys[index],
                    index,
                    View::new(1),
                    Height::new(1),
                    parent_block,
                )
            })
            .collect::<Vec<_>>();
        let parent_qc = QuorumCertificate::new(
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            View::new(1),
            Height::new(1),
            parent_block,
            validator_set.id(),
            votes,
            &validator_set,
        )
        .unwrap();
        (keys, validator_set, parameters, genesis, parent_qc)
    }

    fn synthetic_future_proposal_v1(
        marker: u8,
        keys: &[SigningKey],
        validator_set: &ValidatorSet,
        parameters: ConsensusParametersV0,
        parent_qc: &QuorumCertificate,
    ) -> UnboundProposalV0 {
        let view = View::new(2);
        let proposer = leader_for(validator_set, view);
        let proposer_index = validator_set
            .validators()
            .iter()
            .position(|validator| validator.id() == proposer)
            .unwrap();
        let payload = ApplicationPayloadV0::new(vec![vec![marker]]).unwrap();
        let header = BlockHeader::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            view,
            Height::new(2),
            BlockKind::Regular,
            parent_qc.block_id(),
            proposer,
            validator_set.id(),
            parameters.hash(),
            payload.payload_root().unwrap(),
            StateRoot::new([marker; 32]),
            ReceiptsRoot::new([marker.wrapping_add(1); 32]),
            EvidenceRoot::new([marker.wrapping_add(2); 32]),
            2,
            None,
        )
        .unwrap();
        let justify = QcReferenceV0::ordinary(parent_qc.clone());
        let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
        let witness = ProposalWitnessV0::new(
            &header,
            justify,
            None,
            None,
            SignatureBytes::from_array(keys[proposer_index].sign(root.as_bytes()).to_bytes()),
            validator_set,
            None,
            &parameters,
            1,
        )
        .unwrap();
        let proposal = SignedProposalV0::new(
            Block::new(header, payload.try_cev0_bytes().unwrap(), Vec::new()).unwrap(),
            witness,
            validator_set,
            None,
            &parameters,
            1,
        )
        .unwrap();
        UnboundProposalV0::from_signed(&proposal).unwrap()
    }

    fn signed_vote_v1(
        validator_set: &ValidatorSet,
        key: &SigningKey,
        validator_index: usize,
        view: View,
        height: Height,
        block_id: BlockId,
    ) -> Vote {
        let root = Vote::signing_root_for_set(validator_set, view, height, block_id).unwrap();
        Vote::new(
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            view,
            height,
            block_id,
            validator_set.id(),
            validator_set.validators()[validator_index].id(),
            SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes()),
            validator_set,
        )
        .unwrap()
    }

    struct RealTakeoverFixtureV1 {
        validator_set: ValidatorSet,
        keys: Vec<SigningKey>,
        ordinary_start_height: u64,
        parent_timestamp_ms: u64,
        child_timestamp_ms: u64,
        parent_transactions: Vec<Vec<u8>>,
        child_transactions: Vec<Vec<u8>>,
        authorities: Vec<ContinuousValidatorAuthorityV0>,
        _temp: TempDir,
    }

    fn real_takeover_fixture_v1(validator_count: usize) -> RealTakeoverFixtureV1 {
        let temp = tempfile::tempdir().expect("create takeover test root");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("make takeover test root private");
        let signer_lifetime =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(4, 0, 4, 0).unwrap();
        let parent_timestamp_ms = 400;
        let child_timestamp_ms = 401;
        let mut validator_set = None;
        let mut ordinary_start_height = None;
        let mut parent_transactions = None;
        let mut child_transactions = None;
        let mut keys = Vec::with_capacity(validator_count);
        let mut authorities = Vec::with_capacity(validator_count);
        for index in 0..validator_count {
            let authority_root = temp.path().join(format!("authority-{index:03}"));
            let watermark_root = temp.path().join(format!("watermark-{index:03}"));
            fs::create_dir(&authority_root).unwrap();
            fs::create_dir(&watermark_root).unwrap();
            fs::set_permissions(&authority_root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&watermark_root, fs::Permissions::from_mode(0o700)).unwrap();
            let watermark = LabFileWatermark::open(watermark_root.join("signer-watermark.v1"))
                .expect("open takeover signer watermark");
            let bundle = commission_native_h1_ordinary_lab_test_bundle_v0(
                &authority_root,
                watermark,
                validator_count,
                index,
            )
            .expect("commission exact native takeover fixture");
            let start = bundle.ordinary_start_height_v0();
            let parent = bundle
                .ordinary_transactions_v0(start, parent_timestamp_ms)
                .expect("author parent transactions");
            let child = bundle
                .ordinary_transactions_v0(start + 1, child_timestamp_ms)
                .expect("author child transactions");
            if let Some(expected) = validator_set.as_ref() {
                assert_eq!(bundle.validator_set_v0(), expected);
                assert_eq!(ordinary_start_height, Some(start));
                assert_eq!(parent_transactions.as_ref(), Some(&parent));
                assert_eq!(child_transactions.as_ref(), Some(&child));
            } else {
                validator_set = Some(bundle.validator_set_v0().clone());
                ordinary_start_height = Some(start);
                parent_transactions = Some(parent.clone());
                child_transactions = Some(child.clone());
            }
            let (local, set, parameters, signing_key, start, runtime) =
                bundle.into_continuous_runtime_parts_v0();
            keys.push(signing_key.clone());
            authorities.push(
                ContinuousValidatorAuthorityV0::from_takeover_parts_for_test_v0(
                    local,
                    set,
                    parameters,
                    signing_key,
                    start,
                    runtime,
                    signer_lifetime,
                )
                .expect("join takeover runtime to continuous authority"),
            );
        }
        RealTakeoverFixtureV1 {
            validator_set: validator_set.unwrap(),
            keys,
            ordinary_start_height: ordinary_start_height.unwrap(),
            parent_timestamp_ms,
            child_timestamp_ms,
            parent_transactions: parent_transactions.unwrap(),
            child_transactions: child_transactions.unwrap(),
            authorities,
            _temp: temp,
        }
    }

    fn quorum_certificate_v1(
        validator_set: &ValidatorSet,
        proposal: &SignedProposalV0,
        votes: impl IntoIterator<Item = Vote>,
    ) -> QuorumCertificate {
        let mut collector = ConsensusCertificateCollectorV0::new(
            validator_set.clone(),
            MAXIMUM_PENDING_CERTIFICATES_V1,
        )
        .unwrap();
        let mut certificate = None;
        for vote in votes {
            collector.admit_vote(vote).unwrap();
            certificate = collector
                .try_quorum_certificate(
                    proposal.block().header().view(),
                    proposal.block().header().height(),
                    proposal.block().id(),
                )
                .unwrap();
            if certificate.is_some() {
                break;
            }
        }
        certificate.expect("focused votes reach quorum")
    }

    fn on_consensus_owner_stack_v1<T: Send + 'static>(
        body: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let owner = thread::Builder::new()
            .name("pending-proposal-authority-test".to_owned())
            .stack_size(CONTINUOUS_RUNTIME_OWNER_STACK_BYTES_V0)
            .spawn(body)
            .unwrap();
        match owner.join() {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}
