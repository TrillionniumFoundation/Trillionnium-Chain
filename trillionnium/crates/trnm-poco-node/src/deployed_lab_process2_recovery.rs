//! Crash-safe, still-inert process-2 replay for a deployed laboratory cut.
//!
//! This owner never releases Core, signer, timer, ingress, or network
//! authority.  It replays only the signed, QC-closed h3 -> high-QC prefix.
//! Canonical application `P/K` rows outside that prefix remain an explicitly
//! inventoried unconfirmed speculative tail for a later prune/rebase owner.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::Path,
};

use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    decode_safety_state_record_v0_exact, encode_safety_state_record_v0,
    AnchoredOrdinaryArmViewTimerV0, AnchoredOrdinaryCheckpointedLinkClaimV0,
    AnchoredOrdinaryRehydrateChallengeV0, AnchoredOrdinaryRehydrateReconcilerV0,
    AnchoredOrdinaryRehydratedOwnerV0, AnchoredOrdinaryReplayArchivePlanV0,
    AnchoredOrdinarySignedReplayEntryV0, BlockIdOverlayRefV0, Core,
    CoreAcceptedApplicationValidDV0, CoreConfig, Effect, Input, PayloadValidationRouteV0,
    SafetyState, SafetyStateRecordContextV0, StateSyncAnchorOrdinaryRecoveryChallengeV0,
    StateSyncAnchorOrdinaryRecoveryReconcilerV0, ValidatedPayloadArtifactRefV0, ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    SafetyStateStoreProfileV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, PinnedSqliteSignerJournalV0, SignerJournalLifetimeInventoryV1,
    SignerJournalProfileV0, SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{BlockId, Epoch, QcRef, StateRoot, ValidatorId, ValidatorSetId, View};
use trnm_native_application::{ApplicationHeadV0, NativeExecutedBlockV0};
use trnm_native_application_sqlite::{
    ActiveReplaySessionV0, AliasClosedReplayLinkKV0, ConfirmedProposalValidationTerminalAuditV0,
    ConfirmedReplayActivationReadyV0, ConfirmedReplayInventoryV0, CoreDeliveredReplayLinkDV0,
    DurableReplayCompleteV0, DurableReplayLinkStageV0, NonZeroDigestV0, ProposalRouteV0,
    ProposalValidationBindingV0, ProposalValidationOwnerIdV0, ProposalValidationStoreScopeV0,
    ReplayActivationBindingV0, ReplayCheckpointReadRequestV0, ReplayCheckpointReadbackV0,
    ReplayLinkAliasCloseOutcomeV0, ReplayLinkCheckpointOutcomeV0, ReplayLinkDeliveryOutcomeV0,
    ReplayLinkFactsV0, ReplayLinkReservationOutcomeV0, ReplayLinkSafetyOutcomeV0,
    ReplaySessionOpenOutcomeV0, ReplaySessionPlanV0, ReplaySessionPresenceV0,
    ReplaySessionResumeOutcomeV0, ReplaySourceHistoryReadRequestV0, ReplaySourceHistoryReadbackV0,
    ReservedReplayLinkPV0, SafetyClosedReplayLinkCV0, SqliteProposalValidationStoreV0,
    UntrustedReplayCheckpointReadbackV0, UntrustedReplaySourceHistoryReadbackV0,
    ValidationStoreErrorV0, ValidationStoreResultV0,
};
use trnm_native_execution_v0::{
    ConfirmedDurableExecutionHistoryRowV0, DurableExecutionHistoryStatusV0,
    DurableNativeApplicationV0, NativeApplicationConfigV0,
};

use crate::{
    cross_store_lock::CrossStoreLockGuardV0,
    deployed_lab_recovery::{
        existing_paths_v0, hash_v0, reconstruct_empty_anchor_successor_v0,
        reconstruct_high_qc_path_v0, validate_binding_context_v0, validate_checkpoint_join_v0,
        AuthorityPathsV0, PocoNodeDeployedLabReplayBlockV0, PocoNodeDeployedLabSignedReplayEntryV0,
        RecoveredHistoryKV0, MAXIMUM_BLOB_BYTES_V0, MAXIMUM_RECORD_BYTES_V0,
        MAXIMUM_SAFETY_DATABASE_BYTES_V0, MAXIMUM_SIGNER_DATABASE_BYTES_V0,
        MAXIMUM_SIGNER_INTENTS_V0, MAXIMUM_SIGNER_INTENT_BYTES_V0,
        MINIMUM_TAKEOVER_VALIDATION_SEQUENCE_V0, PROPOSAL_OWNER_DOMAIN_V0,
        PROPOSAL_SCOPE_DOMAIN_V0,
    },
    derive_signer_watermark_scope_v0,
    external_node_checkpoint::{
        ExternalNodeCheckpointFieldsV0, ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0,
        SqliteExternalNodeCheckpointStoreV0,
    },
    lab_authority::{clean_signer_lifetime_inventory_v1, PocoNodeLabRetainedExecutionV0},
    native_proposal_p_host::validated_commitments_from_durable_execution_v0,
    PocoNodeLabOrdinaryProposalRuntimeV0, PocoNodeLabProposalJournalConfigV0,
    PocoNodeLabRuntimeFactsV0, SIGNER_JOURNAL_PROFILE_REF_V0,
    STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
};

const PROCESS2_CHECKPOINT_PROFILE_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-checkpoint-profile.v0";
const PROCESS2_ARCHIVE_CONTEXT_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-archive-context.v0";
const PROCESS2_ARCHIVE_RECORD_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-archive-record.v0";
const PROCESS2_PROPOSAL_RECORD_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-proposal-record.v0";
const PROCESS2_RECOVERY_CHALLENGE_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-recovery-challenge.v0";
const PROCESS2_HISTORY_ROW_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-history-row.v0";
const PROCESS2_HISTORY_INVENTORY_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-history-inventory.v0";
const PROCESS2_TAIL_INVENTORY_DOMAIN_V0: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-unconfirmed-tail.v0";
const PROCESS2_ACTIVATION_PREPARED_ROW_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-activation-prepared-row.v1";
const PROCESS2_SELECTED_REPLAY_ACTIVATION_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-selected-replay-activation.v1";
const PROCESS2_ZERO_DELTA_SIGNER_INVARIANT_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-zero-delta-signer-invariant.v1";
const PROCESS2_ZERO_DELTA_NODE_FACTS_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.deployed-lab.process2-zero-delta-node-facts.v1";
const PROCESS2_ZERO_DELTA_ARTIFACT_MAGIC_V1: &[u8; 8] = b"TRNMZD01";
const PROCESS2_ZERO_DELTA_ARTIFACT_VERSION_V1: u16 = 1;

/// This bounded owner closes process-2 replay only.  Pending-sign replay still
/// requires signer/network authority and remains deliberately unavailable.
pub const DEPLOYED_LAB_PROCESS2_CLEAN_CUT_RECOVERY_V0: bool = true;
pub const DEPLOYED_LAB_PROCESS2_PENDING_SIGN_REPLAY_V0: bool = false;
pub const DEPLOYED_LAB_PROCESS2_ACTIVATION_V0: bool = false;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeDeployedLabProcess2RecoveryErrorV0 {
    stage: &'static str,
    detail: String,
}

impl PocoNodeDeployedLabProcess2RecoveryErrorV0 {
    fn from_debug(stage: &'static str, error: impl fmt::Debug) -> Self {
        Self {
            stage,
            detail: format!("{error:?}"),
        }
    }

    fn message(stage: &'static str, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }

    pub const fn stage_v0(&self) -> &'static str {
        self.stage
    }
}

impl fmt::Display for PocoNodeDeployedLabProcess2RecoveryErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "deployed Lab process2 recovery failed at {}: {}",
            self.stage, self.detail
        )
    }
}

impl Error for PocoNodeDeployedLabProcess2RecoveryErrorV0 {}

macro_rules! process2_try {
    ($stage:literal, $expression:expr) => {
        $expression.map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug($stage, error)
        })?
    };
}

/// Descriptive terminal facts.  Authority remains in the non-cloneable owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeDeployedLabProcess2RecoveryFactsV0 {
    session_id: [u8; 32],
    replayed_link_count: u64,
    final_safety_revision: u64,
    final_safety_chain_checksum: [u8; 32],
    final_checkpoint_generation: u64,
    final_checkpoint_checksum: [u8; 32],
    signer_exact_watermark: SignerWatermarkV0,
    signer_durable_vote_intent_count: u64,
    signer_durable_timeout_intent_count: u64,
    signer_signed_vote_intent_count: u64,
    signer_signed_timeout_intent_count: u64,
    signer_inventory_digest: [u8; 32],
    final_progress_checksum: [u8; 32],
    rehydrate_digest: [u8; 32],
    application_history_digest: [u8; 32],
    unconfirmed_speculative_tail_count: u64,
    unconfirmed_speculative_tail_digest: [u8; 32],
}

impl PocoNodeDeployedLabProcess2RecoveryFactsV0 {
    pub const fn session_id_v0(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn replayed_link_count_v0(self) -> u64 {
        self.replayed_link_count
    }

    pub const fn final_safety_revision_v0(self) -> u64 {
        self.final_safety_revision
    }

    pub const fn final_safety_chain_checksum_v0(self) -> [u8; 32] {
        self.final_safety_chain_checksum
    }

    pub const fn final_checkpoint_generation_v0(self) -> u64 {
        self.final_checkpoint_generation
    }

    pub const fn final_checkpoint_checksum_v0(self) -> [u8; 32] {
        self.final_checkpoint_checksum
    }

    pub const fn signer_exact_watermark_v1(self) -> SignerWatermarkV0 {
        self.signer_exact_watermark
    }

    pub const fn signer_durable_vote_intent_count_v1(self) -> u64 {
        self.signer_durable_vote_intent_count
    }

    pub const fn signer_durable_timeout_intent_count_v1(self) -> u64 {
        self.signer_durable_timeout_intent_count
    }

    pub const fn signer_signed_vote_intent_count_v1(self) -> u64 {
        self.signer_signed_vote_intent_count
    }

    pub const fn signer_signed_timeout_intent_count_v1(self) -> u64 {
        self.signer_signed_timeout_intent_count
    }

    pub const fn signer_inventory_digest_v1(self) -> [u8; 32] {
        self.signer_inventory_digest
    }

    pub const fn final_progress_checksum_v0(self) -> [u8; 32] {
        self.final_progress_checksum
    }

    pub const fn rehydrate_digest_v0(self) -> [u8; 32] {
        self.rehydrate_digest
    }

    pub const fn application_history_digest_v0(self) -> [u8; 32] {
        self.application_history_digest
    }

    pub const fn unconfirmed_speculative_tail_count_v0(self) -> u64 {
        self.unconfirmed_speculative_tail_count
    }

    pub const fn unconfirmed_speculative_tail_digest_v0(self) -> [u8; 32] {
        self.unconfirmed_speculative_tail_digest
    }
}

/// Authority-free projection of the exact process-1 RestartCut which a
/// process-2 zero-delta join must reproduce.
///
/// Public fields make construction explicit, but the value grants nothing:
/// only consumption together with [`PocoNodeDeployedLabProcess2RecoveryOwnerV0`]
/// can mint a caught-up owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeDeployedLabZeroDeltaRestartCutFieldsV1 {
    pub restart_cut_artifact_sha256: [u8; 32],
    pub local_validator: ValidatorId,
    pub validator_set_id: ValidatorSetId,
    pub epoch: Epoch,
    pub current_view: View,
    pub direct_high_qc: QcRef,
    pub proposal_parent_height: u64,
    pub proposal_parent_block_id: BlockId,
    pub finalized_height: u64,
    pub finalized_block_id: BlockId,
    pub finalized_chain_root: [u8; 32],
    pub application_height: u64,
    pub application_block_id: BlockId,
    pub application_state_root: StateRoot,
    pub restart_checkpoint_generation: u64,
    pub restart_checkpoint_canonical_sha256: [u8; 32],
    pub restart_safety_revision: u64,
    pub restart_safety_state_record_checksum: [u8; 32],
    pub restart_safety_chain_checksum: [u8; 32],
    pub signer_exact_watermark: SignerWatermarkV0,
    pub signer_durable_vote_intent_count: u64,
    pub signer_durable_timeout_intent_count: u64,
    pub signer_signed_vote_intent_count: u64,
    pub signer_signed_timeout_intent_count: u64,
    pub signer_inventory_digest: [u8; 32],
}

/// Validated, but still inert, zero-delta RestartCut projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeDeployedLabZeroDeltaRestartCutV1 {
    fields: PocoNodeDeployedLabZeroDeltaRestartCutFieldsV1,
}

impl PocoNodeDeployedLabZeroDeltaRestartCutV1 {
    pub fn new(
        fields: PocoNodeDeployedLabZeroDeltaRestartCutFieldsV1,
    ) -> Result<Self, PocoNodeDeployedLabProcess2RecoveryErrorV0> {
        let signed_intent_count = fields
            .signer_signed_vote_intent_count
            .checked_add(fields.signer_signed_timeout_intent_count)
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "zero_delta.expected_signer_count",
                    "RestartCut signer intent count overflows",
                )
            })?;
        let expected_current_view = fields
            .direct_high_qc
            .view()
            .get()
            .checked_add(1)
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "zero_delta.expected_view",
                    "RestartCut high-QC view has no direct successor",
                )
            })?;
        if fields.restart_cut_artifact_sha256 == [0; 32]
            || fields.local_validator.is_zero()
            || fields.validator_set_id.as_bytes() == &[0; 32]
            || fields.current_view.get() != expected_current_view
            || fields.direct_high_qc.epoch() != fields.epoch
            || fields.direct_high_qc.validator_set_id() != fields.validator_set_id
            || fields.direct_high_qc.qc_digest().is_zero()
            || fields.direct_high_qc.block_id().is_zero()
            || fields.proposal_parent_height != fields.direct_high_qc.height().get()
            || fields.proposal_parent_block_id != fields.direct_high_qc.block_id()
            || fields.finalized_height == 0
            || fields.finalized_block_id.is_zero()
            || fields.finalized_chain_root == [0; 32]
            || fields.application_height != fields.finalized_height
            || fields.application_block_id != fields.finalized_block_id
            || fields.application_state_root.as_bytes() == &[0; 32]
            || fields.restart_checkpoint_generation == 0
            || fields.restart_checkpoint_canonical_sha256 == [0; 32]
            || fields.restart_safety_revision == 0
            || fields.restart_safety_state_record_checksum == [0; 32]
            || fields.restart_safety_chain_checksum == [0; 32]
            || fields.signer_exact_watermark.scope() == [0; 32]
            || fields.signer_exact_watermark.journal_id() == [0; 32]
            || fields.signer_exact_watermark.chain_checksum() == [0; 32]
            || fields.signer_durable_vote_intent_count != fields.signer_signed_vote_intent_count
            || fields.signer_durable_timeout_intent_count
                != fields.signer_signed_timeout_intent_count
            || signed_intent_count == 0
            || fields.signer_exact_watermark.sequence()
                != signed_intent_count.checked_mul(2).ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "zero_delta.expected_signer_sequence",
                        "RestartCut signer event count overflows",
                    )
                })?
            || fields.signer_inventory_digest == [0; 32]
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.expected_cut",
                "RestartCut projection is zero, non-direct, or internally inconsistent",
            ));
        }
        Ok(Self { fields })
    }

    pub const fn fields_v1(self) -> PocoNodeDeployedLabZeroDeltaRestartCutFieldsV1 {
        self.fields
    }
}

/// Descriptive output of the exact zero-delta process-2 join.
///
/// `artifact_bytes_v1` is the raw fixed-schema artifact whose SHA-256 is
/// signed by RecoveryReady/RecoveryStart. The non-cloneable caught-up owner,
/// not this copyable projection, retains all authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1 {
    restart_cut: PocoNodeDeployedLabZeroDeltaRestartCutV1,
    process2: PocoNodeDeployedLabProcess2RecoveryFactsV0,
    process2_safety_revision: u64,
    process2_safety_state_record_checksum: [u8; 32],
    process2_safety_chain_checksum: [u8; 32],
    process2_checkpoint_generation: u64,
    process2_checkpoint_checksum: [u8; 32],
    process2_checkpoint_canonical_sha256: [u8; 32],
    terminal_application_commit_id: [u8; 32],
    signer_inventory_invariant_sha256: [u8; 32],
    node_facts_sha256: [u8; 32],
    artifact_sha256: [u8; 32],
}

impl PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1 {
    pub const fn restart_cut_v1(self) -> PocoNodeDeployedLabZeroDeltaRestartCutV1 {
        self.restart_cut
    }

    pub const fn process2_v1(self) -> PocoNodeDeployedLabProcess2RecoveryFactsV0 {
        self.process2
    }

    pub const fn process2_checkpoint_canonical_sha256_v1(self) -> [u8; 32] {
        self.process2_checkpoint_canonical_sha256
    }

    pub const fn terminal_application_commit_id_v1(self) -> [u8; 32] {
        self.terminal_application_commit_id
    }

    pub const fn signer_inventory_invariant_sha256_v1(self) -> [u8; 32] {
        self.signer_inventory_invariant_sha256
    }

    pub const fn node_facts_sha256_v1(self) -> [u8; 32] {
        self.node_facts_sha256
    }

    pub const fn artifact_sha256_v1(self) -> [u8; 32] {
        self.artifact_sha256
    }

    pub fn artifact_bytes_v1(self) -> Vec<u8> {
        zero_delta_artifact_bytes_v1(
            self.restart_cut.fields.restart_cut_artifact_sha256,
            self.node_facts_sha256,
            self.signer_inventory_invariant_sha256,
            self.process2_checkpoint_canonical_sha256,
            self.terminal_application_commit_id,
        )
    }
}

/// Fully joined, process-3-repeatable, but still replay-fenced owner.
///
/// No method exposes the retained Core, Safety persistence binding, signer,
/// timer, ingress, checkpoint writer, or validation cursor.
#[must_use = "the process2 owner pins every durable authority and remains inert"]
pub struct PocoNodeDeployedLabProcess2RecoveryOwnerV0<W: ExternalMonotonicWatermarkV0> {
    facts: PocoNodeDeployedLabProcess2RecoveryFactsV0,
    core_config: CoreConfig,
    paths: AuthorityPathsV0,
    core: AnchoredOrdinaryRehydratedOwnerV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    signer: PinnedSqliteSignerJournalV0<W>,
    restart_checkpoint: ExternalNodeCheckpointV0,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    validation_store: SqliteProposalValidationStoreV0,
    replay_inventory: ConfirmedReplayInventoryV0,
    application_history_rows: Vec<ConfirmedDurableExecutionHistoryRowV0>,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeDeployedLabProcess2RecoveryOwnerV0<W> {
    pub const fn facts_v0(&self) -> PocoNodeDeployedLabProcess2RecoveryFactsV0 {
        self.facts
    }

    /// Consumes the complete process-2 recovery into one exact zero-delta
    /// caught-up owner.
    ///
    /// The supplied RestartCut projection is inert caller data. Authority
    /// comes only from this linear recovery owner. The transition freshly
    /// proves that the replay-fenced Core/application cut is byte-for-byte the
    /// signed logical cut,
    /// that process-2 Safety/checkpoint generations are the unique replay
    /// successors of the process-1 heads, and that the pinned signer inventory
    /// did not change. Core's replay fence is retained; private passive
    /// preparation is deferred until after the exact N/N RecoveryStart is
    /// consumed. It exposes no Core, signer, timer, store, network, or
    /// activation handle.
    pub fn into_zero_delta_caught_up_v1(
        self,
        expected: PocoNodeDeployedLabZeroDeltaRestartCutV1,
    ) -> Result<
        PocoNodeDeployedLabProcess2CaughtUpOwnerV1<W>,
        PocoNodeDeployedLabProcess2RecoveryErrorV0,
    > {
        self.join_zero_delta_restart_cut_v1(expected)
    }

    #[allow(clippy::too_many_lines)]
    fn join_zero_delta_restart_cut_v1(
        mut self,
        expected: PocoNodeDeployedLabZeroDeltaRestartCutV1,
    ) -> Result<
        PocoNodeDeployedLabProcess2CaughtUpOwnerV1<W>,
        PocoNodeDeployedLabProcess2RecoveryErrorV0,
    > {
        let facts = self.confirm_zero_delta_restart_cut_facts_v1(expected)?;
        let caught_up_cut_digest = facts.artifact_sha256_v1();
        Ok(PocoNodeDeployedLabProcess2CaughtUpOwnerV1 {
            recovered: self,
            facts,
            caught_up_cut_digest,
        })
    }

    /// Repeats the complete read-only durable-head join and returns only the
    /// resulting descriptive facts. The mutable borrow is required by the
    /// validation-store audit API; this helper performs no activation, replay
    /// transition, signer mutation, checkpoint write, or authority release.
    #[allow(clippy::too_many_lines)]
    fn confirm_zero_delta_restart_cut_facts_v1(
        &mut self,
        expected: PocoNodeDeployedLabZeroDeltaRestartCutV1,
    ) -> Result<
        PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1,
        PocoNodeDeployedLabProcess2RecoveryErrorV0,
    > {
        let cut = expected.fields;
        let safety = self.core.challenge_v0().safety_state_v0();
        let finalized = safety.finalized();
        let applied = safety.application_applied();
        let high_qc = safety.high_qc().qc_ref();
        let process2 = self.facts;
        if self.core_config.local_validator() != cut.local_validator
            || self.core_config.validator_set().id() != cut.validator_set_id
            || self.core_config.validator_set().epoch() != cut.epoch
            || safety.epoch() != cut.epoch
            || safety.current_view() != cut.current_view
            || high_qc != cut.direct_high_qc
            || finalized.height().get() != cut.finalized_height
            || finalized.block_id() != cut.finalized_block_id
            || applied.height().get() != cut.application_height
            || applied.block_id() != cut.application_block_id
            || self.core.finalized_chain_root_v0().as_bytes() != &cut.finalized_chain_root
            || safety.pending_sign().is_some()
            || safety.pending_finalize().is_some()
            || safety.pending_finalization().is_some()
            || safety.pending_tc_high_qc_sync().is_some()
            || safety.pending_standalone_qc_sync().is_some()
            || safety.safety_halt().is_some()
            || !safety.finalization_queue().is_empty()
            || !safety.payload_validation_obligations().is_empty()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.core_cut",
                "replay-fenced Core differs from the exact zero-delta RestartCut",
            ));
        }

        validate_config_join_v0(&self.core_config, self.application.config_v0())?;
        let committed = process2_try!(
            "zero_delta.application_committed",
            self.application.confirmed_committed_head_v0()
        );
        if committed.height().get() != cut.application_height
            || committed.block_id().as_bytes() != cut.application_block_id.as_bytes()
            || committed.state_root().as_bytes() != cut.application_state_root.as_bytes()
            || cut.application_height != cut.finalized_height
            || cut.application_block_id != cut.finalized_block_id
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.application_cut",
                "fresh committed application head differs from RestartCut finality",
            ));
        }

        let safety_head = process2_try!("zero_delta.safety_head", self.safety_store.head());
        let safety_facts = process2_try!(
            "zero_delta.safety_facts",
            self.safety_store
                .confirm_node_checkpoint_head_exact_v0(safety)
        );
        if safety_head.state() != safety
            || !safety_facts
                .belongs_to_store_at_path_v0(&self.safety_store, &self.paths.target_safety)
            || safety_facts.revision_v0() != process2.final_safety_revision_v0()
            || safety_facts.chain_checksum_v0() != process2.final_safety_chain_checksum_v0()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.safety_join",
                "fresh process2 Safety head differs from its replay-fenced Core",
            ));
        }

        let (validation_scope, validation_owner) =
            deployed_validation_identity_v0(&self.core_config, &self.application)?;
        let terminal_audit = process2_try!(
            "zero_delta.validation_terminal_audit",
            self.validation_store.confirm_terminal_k_audit_v0()
        );
        if !terminal_audit
            .belongs_to_store_at_path_v0(&self.validation_store, &self.paths.validation)
            || terminal_audit.scope_v0() != validation_scope
            || terminal_audit.owner_id_v0() != validation_owner
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.validation_owner",
                "fresh terminal validation inventory lost its deployed owner",
            ));
        }
        let history = build_history_inventory_v0(
            &self.core_config,
            &self.paths,
            &self.application,
            &mut self.validation_store,
            validation_scope,
            validation_owner,
            &terminal_audit,
        )?;
        validate_retained_history_rows_v1(
            &self.application_history_rows,
            &self.application,
            &self.paths.application,
            &history,
        )?;
        if history.application_history_digest != process2.application_history_digest_v0() {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.application_history",
                "fresh application history differs from process2 facts",
            ));
        }

        let fresh_inventory = process2_try!(
            "zero_delta.replay_inventory",
            self.validation_store.confirm_replay_inventory_v0()
        );
        if !self
            .replay_inventory
            .belongs_to_store_at_path_v0(&self.validation_store, &self.paths.validation)
            || !fresh_inventory
                .belongs_to_store_at_path_v0(&self.validation_store, &self.paths.validation)
            || fresh_inventory.session_v0() != self.replay_inventory.session_v0()
            || fresh_inventory.links_v0() != self.replay_inventory.links_v0()
            || !fresh_inventory.session_v0().is_durable_complete_v0()
            || fresh_inventory.session_v0().session_id_v0() != process2.session_id_v0()
            || fresh_inventory.links_v0().len()
                != usize::try_from(process2.replayed_link_count_v0()).map_err(|_| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "zero_delta.replay_count",
                        "process2 replay count does not fit usize",
                    )
                })?
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.replay_fence",
                "zero-delta Ready requires the exact still-DurableComplete replay fence",
            ));
        }
        let replay_session = fresh_inventory.session_v0();
        let restart_checkpoint_canonical_sha256: [u8; 32] =
            Sha256::digest(self.restart_checkpoint.encode_canonical()).into();
        if replay_session.initial_safety_revision_v0() != cut.restart_safety_revision
            || replay_session.initial_safety_state_checksum_v0()
                != cut.restart_safety_state_record_checksum
            || replay_session.initial_safety_chain_checksum_v0()
                != cut.restart_safety_chain_checksum
            || replay_session.initial_checkpoint_generation_v0()
                != cut.restart_checkpoint_generation
            || replay_session.initial_checkpoint_checksum_v0()
                != self.restart_checkpoint.checkpoint_checksum()
            || self.restart_checkpoint.generation() != cut.restart_checkpoint_generation
            || restart_checkpoint_canonical_sha256 != cut.restart_checkpoint_canonical_sha256
            || replay_session.initial_checkpoint_scope_v0() != cut.signer_exact_watermark.scope()
            || replay_session.signer_scope_v0() != cut.signer_exact_watermark.scope()
            || replay_session.signer_journal_id_v0() != cut.signer_exact_watermark.journal_id()
            || replay_session.signer_sequence_v0() != cut.signer_exact_watermark.sequence()
            || replay_session.signer_chain_checksum_v0()
                != cut.signer_exact_watermark.chain_checksum()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.replay_predecessor",
                "replay session predecessor differs from the signed RestartCut heads",
            ));
        }

        let checkpoint = process2_try!(
            "zero_delta.checkpoint_load",
            self.checkpoint_store
                .load(cut.signer_exact_watermark.scope())
        )
        .ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.checkpoint_missing",
                "process2 whole-node checkpoint is absent",
            )
        })?;
        if checkpoint.generation() != process2.final_checkpoint_generation_v0()
            || checkpoint.checkpoint_checksum() != process2.final_checkpoint_checksum_v0()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.checkpoint_facts",
                "fresh process2 checkpoint differs from process2 facts",
            ));
        }

        let signer_facts = process2_try!(
            "zero_delta.signer_facts",
            self.signer.confirm_node_checkpoint_head_exact_v0()
        );
        let signer_inventory =
            clean_signer_lifetime_inventory_v1(&signer_facts).ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "zero_delta.signer_inventory",
                    "zero-delta pinned signer inventory is not clean",
                )
            })?;
        if !signer_facts.belongs_to_pinned_journal_at_path_v0(&self.signer, &self.paths.signer)
            || signer_facts.pending_intent().is_some()
            || signer_facts.exact_watermark() != cut.signer_exact_watermark
            || signer_inventory.durable_vote_intent_count() != cut.signer_durable_vote_intent_count
            || signer_inventory.durable_timeout_intent_count()
                != cut.signer_durable_timeout_intent_count
            || signer_inventory.signed_vote_intent_count() != cut.signer_signed_vote_intent_count
            || signer_inventory.signed_timeout_intent_count()
                != cut.signer_signed_timeout_intent_count
            || signer_inventory.inventory_digest() != cut.signer_inventory_digest
            || signer_facts.exact_watermark() != process2.signer_exact_watermark_v1()
            || signer_inventory.inventory_digest() != process2.signer_inventory_digest_v1()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.signer_join",
                "pinned process2 signer differs from the exact RestartCut inventory",
            ));
        }

        validate_checkpoint_join_v0(
            checkpoint,
            &safety_facts,
            &signer_facts,
            &self.application,
            &committed,
            &self.validation_store,
            &history.recovered,
        )
        .map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug(
                "zero_delta.checkpoint_join",
                error,
            )
        })?;

        let replay_count = process2.replayed_link_count_v0();
        let expected_safety_revision = cut
            .restart_safety_revision
            .checked_add(replay_count.checked_mul(2).ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "zero_delta.safety_delta",
                    "process2 Safety replay delta overflows",
                )
            })?)
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "zero_delta.safety_delta",
                    "process2 Safety successor overflows",
                )
            })?;
        let expected_checkpoint_generation = cut
            .restart_checkpoint_generation
            .checked_add(replay_count)
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "zero_delta.checkpoint_delta",
                    "process2 checkpoint successor overflows",
                )
            })?;
        if process2.final_safety_revision_v0() != expected_safety_revision
            || process2.final_checkpoint_generation_v0() != expected_checkpoint_generation
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.unique_successor",
                "process2 durable heads are not the unique replay successors of RestartCut",
            ));
        }

        let checkpoint_canonical_sha256: [u8; 32] =
            Sha256::digest(checkpoint.encode_canonical()).into();
        let signer_inventory_invariant_sha256 = zero_delta_signer_invariant_v1(
            cut.signer_exact_watermark,
            cut.signer_durable_vote_intent_count,
            cut.signer_durable_timeout_intent_count,
            cut.signer_signed_vote_intent_count,
            cut.signer_signed_timeout_intent_count,
            cut.signer_inventory_digest,
        );
        let node_facts_sha256 = zero_delta_node_facts_v1(
            expected,
            process2,
            safety_facts.revision_v0(),
            safety_facts.state_record_checksum_v0(),
            safety_facts.chain_checksum_v0(),
            checkpoint.generation(),
            checkpoint.checkpoint_checksum(),
            checkpoint_canonical_sha256,
            *committed.commit_id().as_bytes(),
            signer_inventory_invariant_sha256,
        );
        let artifact_bytes = zero_delta_artifact_bytes_v1(
            cut.restart_cut_artifact_sha256,
            node_facts_sha256,
            signer_inventory_invariant_sha256,
            checkpoint_canonical_sha256,
            *committed.commit_id().as_bytes(),
        );
        let artifact_sha256: [u8; 32] = Sha256::digest(&artifact_bytes).into();
        let facts = PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1 {
            restart_cut: expected,
            process2,
            process2_safety_revision: safety_facts.revision_v0(),
            process2_safety_state_record_checksum: safety_facts.state_record_checksum_v0(),
            process2_safety_chain_checksum: safety_facts.chain_checksum_v0(),
            process2_checkpoint_generation: checkpoint.generation(),
            process2_checkpoint_checksum: checkpoint.checkpoint_checksum(),
            process2_checkpoint_canonical_sha256: checkpoint_canonical_sha256,
            terminal_application_commit_id: *committed.commit_id().as_bytes(),
            signer_inventory_invariant_sha256,
            node_facts_sha256,
            artifact_sha256,
        };
        let projected_artifact_sha256: [u8; 32] = Sha256::digest(facts.artifact_bytes_v1()).into();
        if facts.artifact_bytes_v1() != artifact_bytes
            || facts.artifact_sha256_v1() != projected_artifact_sha256
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.artifact",
                "zero-delta artifact encoding is not self-consistent",
            ));
        }
        Ok(facts)
    }

    /// Consumes the inert process2 owner into a signer-pinned passive catch-up
    /// owner.
    ///
    /// This is deliberately the only transition exposed on the recovery
    /// owner. It freshly joins every retained durable namespace, moves the
    /// replay sidecar through its one-way `ActivationReady` CAS, consumes
    /// Core's replay fence, rebinds the exact Safety namespace, and retains
    /// Core's startup timer without converting it into an effect. It does not
    /// activate the signer or construct an ordinary runtime. Those operations
    /// remain behind a separate, currently unconstructible caught-up plus N/N
    /// RecoveryStart join.
    fn prepare_passive_catchup_v1(
        self,
    ) -> Result<
        PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1<W>,
        PocoNodeDeployedLabProcess2RecoveryErrorV0,
    > {
        self.prepare_passive_catchup_inner_v1(None)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_passive_catchup_inner_v1(
        self,
        crash_hook: Option<Process2CrashHookV0>,
    ) -> Result<
        PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1<W>,
        PocoNodeDeployedLabProcess2RecoveryErrorV0,
    > {
        let Self {
            facts,
            core_config,
            paths,
            core,
            safety_store,
            application,
            mut signer,
            restart_checkpoint: _,
            mut checkpoint_store,
            mut validation_store,
            replay_inventory,
            application_history_rows,
        } = self;

        // The activation binding is a paired P/K/Safety/checkpoint/signer
        // snapshot.  Acquire the common authority lock before the first
        // read—not only before the final ActivationReady CAS—so a cooperating
        // native P writer cannot replace the application head after the
        // binding digest was computed and before the sidecar commit.
        let cross_store_lock = CrossStoreLockGuardV0::acquire_exclusive_for_paths_v0(
            &paths.application,
            &paths.validation,
        )
        .map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.cross_store_lock",
                error.to_string(),
            )
        })?;

        validate_config_join_v0(&core_config, application.config_v0())?;
        let core_facts = core.facts_v0();
        let challenge_safety = core.challenge_v0().safety_state_v0().clone();
        if core_facts.session_id_v0() != facts.session_id_v0()
            || core_facts.replayed_link_count_v0() != facts.replayed_link_count_v0()
            || core_facts.safety_revision_v0() != facts.final_safety_revision_v0()
            || core_facts.final_progress_checksum_v0() != facts.final_progress_checksum_v0()
            || core_facts.rehydrate_digest_v0() != facts.rehydrate_digest_v0()
            || core
                .challenge_v0()
                .plan_v0()
                .application_history_digest_v0()
                != facts.application_history_digest_v0()
            || core.challenge_v0().entries_v0().len()
                != usize::try_from(facts.replayed_link_count_v0()).map_err(|_| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "activation.core_count",
                        "replayed-link count does not fit usize",
                    )
                })?
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.core_owner",
                "rehydrated Core differs from its retained process2 facts",
            ));
        }
        validate_process2_safety_shape_v0(&challenge_safety)?;

        let safety_head = process2_try!("activation.safety_head", safety_store.head());
        if safety_head.state() != &challenge_safety {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.safety_core_join",
                "fresh Safety head differs from the rehydrated Core challenge",
            ));
        }
        let safety_facts = process2_try!(
            "activation.safety_facts",
            safety_store.confirm_node_checkpoint_head_exact_v0(&challenge_safety)
        );
        if !safety_facts.belongs_to_store_at_path_v0(&safety_store, &paths.target_safety)
            || safety_facts.revision_v0() != facts.final_safety_revision_v0()
            || safety_facts.chain_checksum_v0() != facts.final_safety_chain_checksum_v0()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.safety_freshness",
                "fresh Safety authority differs from the retained terminal cut",
            ));
        }

        let committed = process2_try!(
            "activation.application_committed",
            application.confirmed_committed_head_v0()
        );
        if committed.block_id().as_bytes()
            != challenge_safety.application_applied().block_id().as_bytes()
            || committed.height().get() != challenge_safety.application_applied().height().get()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.application_applied_join",
                "fresh committed application head differs from Safety application_applied",
            ));
        }

        let (validation_scope, validation_owner) =
            deployed_validation_identity_v0(&core_config, &application)?;
        let terminal_audit = process2_try!(
            "activation.validation_terminal_audit",
            validation_store.confirm_terminal_k_audit_v0()
        );
        if !terminal_audit.belongs_to_store_at_path_v0(&validation_store, &paths.validation)
            || terminal_audit.scope_v0() != validation_scope
            || terminal_audit.owner_id_v0() != validation_owner
            || terminal_audit.store_sequence_v0()
                != terminal_audit
                    .terminal_row_count_v0()
                    .checked_mul(3)
                    .ok_or_else(|| {
                        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                            "activation.validation_sequence",
                            "terminal validation sequence overflowed",
                        )
                    })?
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.validation_owner_join",
                "fresh terminal validation inventory differs from its deployed owner",
            ));
        }
        let history = build_history_inventory_v0(
            &core_config,
            &paths,
            &application,
            &mut validation_store,
            validation_scope,
            validation_owner,
            &terminal_audit,
        )?;
        validate_retained_history_rows_v1(
            &application_history_rows,
            &application,
            &paths.application,
            &history,
        )?;
        if history.application_history_digest != facts.application_history_digest_v0() {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.application_history_digest",
                "fresh application history differs from the process2 inventory",
            ));
        }

        let anchor = challenge_safety.state_sync_anchor().ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.safety_anchor",
                "activated ordinary Safety lacks its permanent h1 anchor",
            )
        })?;
        let high_qc_path = reconstruct_high_qc_path_v0(
            challenge_safety.high_qc().qc_ref(),
            challenge_safety.locked_qc().qc_ref(),
            challenge_safety.finalized(),
            anchor.proof().finalized_block().header().id(),
            anchor.proof().finalized_block().header().view(),
            anchor.proof().grandchild().header().id(),
            &committed,
            &history.recovered,
        )
        .map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug("activation.high_qc_path", error)
        })?;
        let (tail_count, tail_digest) =
            exact_unconfirmed_tail_v0(&high_qc_path, &history.history_checksums)?;
        if tail_count != facts.unconfirmed_speculative_tail_count_v0()
            || tail_digest != facts.unconfirmed_speculative_tail_digest_v0()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.speculative_tail",
                "fresh speculative tail differs from the retained process2 cut",
            ));
        }

        let fresh_inventory = process2_try!(
            "activation.replay_inventory",
            validation_store.confirm_replay_inventory_v0()
        );
        if !replay_inventory.belongs_to_store_at_path_v0(&validation_store, &paths.validation)
            || !fresh_inventory.belongs_to_store_at_path_v0(&validation_store, &paths.validation)
            || replay_inventory.session_v0() != fresh_inventory.session_v0()
            || replay_inventory.links_v0() != fresh_inventory.links_v0()
            || (!fresh_inventory.session_v0().is_durable_complete_v0()
                && !fresh_inventory.session_v0().is_activation_ready_v0())
            || fresh_inventory.session_v0().session_id_v0() != facts.session_id_v0()
            || fresh_inventory.session_v0().application_history_digest_v0()
                != facts.application_history_digest_v0()
            || fresh_inventory.session_v0().previous_progress_checksum_v0()
                != facts.final_progress_checksum_v0()
            || fresh_inventory.links_v0().len()
                != usize::try_from(facts.replayed_link_count_v0()).map_err(|_| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "activation.inventory_count",
                        "replay inventory count does not fit usize",
                    )
                })?
            || fresh_inventory.links_v0().iter().any(|link| {
                link.stage_v0() != DurableReplayLinkStageV0::Checkpointed
                    || link.session_id_v0() != facts.session_id_v0()
            })
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.replay_inventory_join",
                "fresh replay inventory differs from the owner-affined durable completion",
            ));
        }

        let signer_facts = process2_try!(
            "activation.signer_facts",
            signer.confirm_node_checkpoint_head_exact_v0()
        );
        if signer_facts.pending_intent().is_some()
            || !signer_facts.belongs_to_pinned_journal_at_path_v0(&signer, &paths.signer)
            || signer_facts
                .capacity()
                .maximum_safety_revision()
                .is_some_and(|revision| revision > challenge_safety.revision())
            || signer_facts.capacity().maximum_vote_view()
                != challenge_safety.last_voted_view().map(|view| view.get())
            || signer_facts.capacity().maximum_timeout_view()
                != challenge_safety.last_timeout_view().map(|view| view.get())
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.signer_clean_cut",
                "fresh pinned signer differs from the clean Safety cut",
            ));
        }
        let signer_inventory =
            clean_signer_lifetime_inventory_v1(&signer_facts).ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "activation.signer_inventory",
                    "fresh signer Vote/TimeoutVote lifecycles are not individually clean",
                )
            })?;
        if !signer_inventory_matches_recovery_facts_v1(
            facts,
            signer_facts.exact_watermark(),
            signer_inventory,
        ) {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.signer_recovery_join",
                "fresh signer watermark or lifetime inventory differs from process2 facts",
            ));
        }

        let checkpoint = process2_try!(
            "activation.checkpoint_load",
            checkpoint_store.load(signer_facts.exact_watermark().scope())
        )
        .ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.checkpoint_missing",
                "terminal whole-node checkpoint is absent",
            )
        })?;
        validate_checkpoint_join_v0(
            checkpoint,
            &safety_facts,
            &signer_facts,
            &application,
            &committed,
            &validation_store,
            &history.recovered,
        )
        .map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug(
                "activation.checkpoint_join",
                error,
            )
        })?;
        if checkpoint.generation() != facts.final_checkpoint_generation_v0()
            || checkpoint.checkpoint_checksum() != facts.final_checkpoint_checksum_v0()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.checkpoint_facts",
                "fresh whole-node checkpoint differs from process2 terminal facts",
            ));
        }

        let pending_executions =
            rebuild_prepared_executions_v1(&application, &paths.application, &history)?;
        let (application_head, application_overlay_ref) = select_high_qc_application_parent_v1(
            &challenge_safety,
            &committed,
            &pending_executions,
        )?;
        let prepared_execution_count = u64::try_from(pending_executions.len()).map_err(|_| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.prepared_count",
                "prepared execution count does not fit u64",
            )
        })?;
        let selected_replay_digest = selected_replay_activation_digest_v1(
            facts,
            &challenge_safety,
            &committed,
            &application_head,
            application_overlay_ref,
            prepared_execution_count,
            &pending_executions,
        );
        let binding = process2_try!(
            "activation.binding",
            ReplayActivationBindingV0::new(
                nonzero_v0(facts.session_id_v0())?,
                nonzero_v0(facts.rehydrate_digest_v0())?,
                safety_facts.revision_v0(),
                nonzero_v0(safety_facts.chain_checksum_v0())?,
                nonzero_v0(facts.application_history_digest_v0())?,
                application_head.height().get(),
                nonzero_v0(*application_head.block_id().as_bytes())?,
                nonzero_v0(*application_head.state_root().as_bytes())?,
                nonzero_v0(*application_head.commit_id().as_bytes())?,
                checkpoint.generation(),
                nonzero_v0(checkpoint.checkpoint_checksum())?,
                nonzero_v0(signer_facts.exact_watermark().scope())?,
                nonzero_v0(signer_facts.exact_watermark().journal_id())?,
                signer_facts.exact_watermark().sequence(),
                nonzero_v0(signer_facts.exact_watermark().chain_checksum())?,
                nonzero_v0(signer_inventory.inventory_digest())?,
                nonzero_v0(selected_replay_digest)?,
            )
        );
        #[cfg(feature = "lab-validator-runtime-test-support")]
        if crash_hook == Some(Process2CrashHookV0::ActivationReadyCommitted) {
            validation_store.inject_replay_activation_applied_ack_loss_for_test_v0();
        }
        let activation_ready = process2_try!(
            "activation.sidecar_cas",
            validation_store.confirm_replay_activation_ready_v0(replay_inventory, binding)
        );
        if activation_ready.binding_v0() != binding
            || !activation_ready.belongs_to_store_at_path_v0(&validation_store, &paths.validation)
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.sidecar_readback",
                "ActivationReady readback lost its exact live-store binding",
            ));
        }
        let post_cas_signer_facts = process2_try!(
            "activation.signer_post_cas_facts",
            signer.confirm_node_checkpoint_head_exact_v0()
        );
        let post_cas_signer_inventory = clean_signer_lifetime_inventory_v1(&post_cas_signer_facts)
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "activation.signer_post_cas_inventory",
                    "ActivationReady CAS left a non-clean signer inventory",
                )
            })?;
        if !post_cas_signer_facts.belongs_to_pinned_journal_at_path_v0(&signer, &paths.signer)
            || post_cas_signer_facts.journal_id() != signer_facts.journal_id()
            || post_cas_signer_facts.profile_checksum() != signer_facts.profile_checksum()
            || post_cas_signer_facts.identity() != signer_facts.identity()
            || post_cas_signer_facts.exact_watermark() != signer_facts.exact_watermark()
            || post_cas_signer_facts.capacity() != signer_facts.capacity()
            || post_cas_signer_inventory != signer_inventory
            || post_cas_signer_facts.tail() != signer_facts.tail()
            || post_cas_signer_facts.pending_intent() != signer_facts.pending_intent()
            || binding.signer_inventory_digest_v1() != post_cas_signer_inventory.inventory_digest()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.signer_post_cas_join",
                "ActivationReady changed the exact signer head or lifetime inventory",
            ));
        }
        trigger_test_crash_v0(crash_hook, Process2CrashHookV0::ActivationReadyCommitted)?;

        let activated_core = process2_try!(
            "activation.core_replay_fence",
            core.reconcile_and_activate_checkpointed_ordinary_v0(&StrictEd25519Verifier)
        );
        if activated_core.facts_v0() != core_facts {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.core_facts",
                "Core activation changed the authenticated rehydrate facts",
            ));
        }
        let (core, startup_timer) = activated_core.into_parts_v0();
        if core.config() != &core_config
            || core.safety_state() != &challenge_safety
            || startup_timer.epoch_v0() != challenge_safety.epoch()
            || startup_timer.view_v0() != challenge_safety.current_view()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.core_timer_join",
                "activated Core or its exact retained timer differs from the durable cut",
            ));
        }

        // The replay driver bound the retained store to its now-retired Core.
        // Reopen the same pinned namespace after the durable ActivationReady
        // fence, then bind it once to the newly activated Core affinity.
        drop(safety_store);
        let limits = process2_try!(
            "activation.safety_record_limits",
            trnm_consensus_core::SafetyStateRecordLimitsV0::new(
                MAXIMUM_RECORD_BYTES_V0,
                MAXIMUM_BLOB_BYTES_V0,
            )
        );
        let safety_profile = process2_try!(
            "activation.safety_profile",
            SafetyStateStoreProfileV0::new(
                core_config,
                STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
                limits,
                MAXIMUM_SAFETY_DATABASE_BYTES_V0,
            )
        );
        let mut safety_store = process2_try!(
            "activation.safety_reopen",
            SqliteSafetyStateStoreV0::open_existing(
                &paths.target_safety,
                safety_profile,
                StrictEd25519Verifier,
            )
        );
        let rebound_head = process2_try!("activation.safety_reopen_head", safety_store.head());
        let rebound_facts = process2_try!(
            "activation.safety_reopen_facts",
            safety_store.confirm_node_checkpoint_head_exact_v0(core.safety_state())
        );
        if rebound_head.state() != core.safety_state()
            || !rebound_facts.belongs_to_store_at_path_v0(&safety_store, &paths.target_safety)
            || rebound_facts.revision_v0() != safety_facts.revision_v0()
            || rebound_facts.chain_checksum_v0() != safety_facts.chain_checksum_v0()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.safety_reopen_join",
                "reopened Safety owner differs from the activated Core",
            ));
        }
        process2_try!(
            "activation.safety_bind_core",
            safety_store.bind_core_v0(core.safety_state_persistence_binding_v0())
        );

        let passive_facts = PocoNodeDeployedLabProcess2PassiveCatchupFactsV1 {
            recovery: facts,
            activation_binding_digest: binding.binding_digest_v0(),
            activation_row_revision: activation_ready.row_revision_v0(),
            activation_row_checksum: *activation_ready.row_checksum_v0().as_bytes(),
            application_parent_block_id: BlockId::new(*application_head.block_id().as_bytes()),
            application_parent_height: application_head.height().get(),
            prepared_execution_count,
            signer_exact_watermark: signer_facts.exact_watermark(),
            signer_durable_vote_intent_count: signer_inventory.durable_vote_intent_count(),
            signer_durable_timeout_intent_count: signer_inventory.durable_timeout_intent_count(),
            signer_signed_vote_intent_count: signer_inventory.signed_vote_intent_count(),
            signer_signed_timeout_intent_count: signer_inventory.signed_timeout_intent_count(),
            signer_inventory_digest: signer_inventory.inventory_digest(),
            selected_replay_digest,
            startup_timer_epoch: startup_timer.epoch_v0(),
            startup_timer_view: startup_timer.view_v0(),
        };
        cross_store_lock.validate_identity_v0().map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.cross_store_lock_final_identity",
                error.to_string(),
            )
        })?;
        Ok(PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1 {
            facts: passive_facts,
            paths,
            core,
            startup_timer,
            safety_store,
            application,
            signer,
            checkpoint_store,
            validation_store,
            activation_ready,
            checkpoint,
            committed,
            application_head,
            application_overlay_ref,
            pending_executions,
            history,
        })
    }
}

/// Descriptive source-cut facts retained by the signer-pinned passive owner.
///
/// These values carry no Core, signer, timer, application, checkpoint, or
/// recovery-start authority. The type remains private because the next tranche
/// must bind it to the durable provider bundle before any caught-up owner can
/// exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PocoNodeDeployedLabProcess2PassiveCatchupFactsV1 {
    recovery: PocoNodeDeployedLabProcess2RecoveryFactsV0,
    activation_binding_digest: [u8; 32],
    activation_row_revision: u64,
    activation_row_checksum: [u8; 32],
    application_parent_block_id: BlockId,
    application_parent_height: u64,
    prepared_execution_count: u64,
    signer_exact_watermark: SignerWatermarkV0,
    signer_durable_vote_intent_count: u64,
    signer_durable_timeout_intent_count: u64,
    signer_signed_vote_intent_count: u64,
    signer_signed_timeout_intent_count: u64,
    signer_inventory_digest: [u8; 32],
    selected_replay_digest: [u8; 32],
    startup_timer_epoch: Epoch,
    startup_timer_view: View,
}

/// Private, non-cloneable owner after Core replay completion but before any
/// provider catch-up or signer activation.
///
/// There is deliberately no parts accessor, raw Core accessor, timer accessor,
/// signer accessor, activation method, or ordinary-runtime transition. The
/// future catch-up driver must consume this whole owner into the separate
/// caught-up owner below.
#[must_use = "the passive process2 owner must remain signer-pinned through catch-up"]
struct PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1<W: ExternalMonotonicWatermarkV0> {
    facts: PocoNodeDeployedLabProcess2PassiveCatchupFactsV1,
    paths: AuthorityPathsV0,
    core: Core,
    startup_timer: AnchoredOrdinaryArmViewTimerV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    signer: PinnedSqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    validation_store: SqliteProposalValidationStoreV0,
    activation_ready: ConfirmedReplayActivationReadyV0,
    checkpoint: ExternalNodeCheckpointV0,
    committed: ApplicationHeadV0,
    application_head: ApplicationHeadV0,
    application_overlay_ref: Option<BlockIdOverlayRefV0>,
    pending_executions: BTreeMap<BlockId, PocoNodeDeployedLabProcess2RetainedExecutionV1>,
    history: Process2HistoryInventoryV0,
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug
    for PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1<W>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// Exact zero-delta process-2 authority, still behind Core's replay fence.
///
/// The sole normal-build constructor consumes the complete recovery owner and
/// freshly confirms every RestartCut projection without writing
/// `ActivationReady`, clearing Core's replay fence, activating the signer, or
/// releasing a timer/network handle.  Copied facts grant no authority.
#[must_use = "caught-up process2 authority must await the exact N/N RecoveryStart"]
pub struct PocoNodeDeployedLabProcess2CaughtUpOwnerV1<W: ExternalMonotonicWatermarkV0> {
    recovered: PocoNodeDeployedLabProcess2RecoveryOwnerV0<W>,
    facts: PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1,
    caught_up_cut_digest: [u8; 32],
}

/// Future typed N/N RecoveryStart authority.
///
/// It has no normal-build constructor in this tranche. The scheduler tranche
/// must create it only from a freshly persisted certificate whose target cut
/// equals the caught-up owner.
#[allow(dead_code)]
#[must_use = "RecoveryStart must be consumed together with its caught-up owner"]
struct PocoNodeDeployedLabProcess2RecoveryStartAuthorityV1 {
    caught_up_cut_digest: [u8; 32],
    certificate_sha256: [u8; 32],
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeDeployedLabProcess2CaughtUpOwnerV1<W> {
    pub const fn facts_v1(&self) -> PocoNodeDeployedLabZeroDeltaCaughtUpFactsV1 {
        self.facts
    }

    /// Freshly re-audits every retained Core, Safety, application, validation,
    /// replay-session, checkpoint, and signer head against the exact caught-up
    /// facts. This is a borrowed read-only gate: it neither clears the replay
    /// fence nor exposes or mutates any retained authority.
    pub fn revalidate_zero_delta_caught_up_v1(
        &mut self,
    ) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
        let fresh = self
            .recovered
            .confirm_zero_delta_restart_cut_facts_v1(self.facts.restart_cut_v1())?;
        if fresh != self.facts
            || self.caught_up_cut_digest != self.facts.artifact_sha256_v1()
            || fresh.artifact_sha256_v1() != self.caught_up_cut_digest
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "zero_delta.fresh_revalidation",
                "fresh durable zero-delta facts differ from the retained caught-up owner",
            ));
        }
        Ok(())
    }

    /// The sole post-catch-up activation boundary.
    ///
    /// Signer activation occurs only after consuming both the caught-up owner
    /// and the matching typed N/N RecoveryStart authority. No recovery owner or
    /// passive owner can call this method. The current tranche intentionally
    /// has no normal-build path that constructs either input.
    #[allow(dead_code, clippy::too_many_lines)]
    fn activate_after_recovery_start_v1(
        self,
        recovery_start: PocoNodeDeployedLabProcess2RecoveryStartAuthorityV1,
    ) -> Result<
        PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W>,
        PocoNodeDeployedLabProcess2RecoveryErrorV0,
    > {
        let Self {
            recovered,
            facts,
            caught_up_cut_digest,
        } = self;
        if caught_up_cut_digest == [0; 32]
            || caught_up_cut_digest != facts.artifact_sha256_v1()
            || recovery_start.certificate_sha256 == [0; 32]
            || recovery_start.caught_up_cut_digest != caught_up_cut_digest
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.recovery_start_join",
                "RecoveryStart differs from the exact caught-up cut",
            ));
        }
        let passive = recovered.prepare_passive_catchup_v1()?;
        activate_passive_after_recovery_start_v1(passive)
    }
}

#[allow(clippy::too_many_lines)]
fn activate_passive_after_recovery_start_v1<W: ExternalMonotonicWatermarkV0>(
    passive: PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1<W>,
) -> Result<
    PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W>,
    PocoNodeDeployedLabProcess2RecoveryErrorV0,
> {
    let PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1 {
        facts,
        paths,
        core,
        startup_timer,
        safety_store,
        application,
        mut signer,
        mut checkpoint_store,
        validation_store,
        activation_ready,
        checkpoint,
        committed,
        application_head,
        application_overlay_ref,
        pending_executions,
        history,
    } = passive;

    let rebound_facts = process2_try!(
        "activation.safety_post_catchup_facts",
        safety_store.confirm_node_checkpoint_head_exact_v0(core.safety_state())
    );
    if !rebound_facts.belongs_to_store_at_path_v0(&safety_store, &paths.target_safety) {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.safety_post_catchup_join",
            "caught-up Safety owner lost its exact path affinity",
        ));
    }
    let signer_facts = process2_try!(
        "activation.signer_pre_activate_facts",
        signer.confirm_node_checkpoint_head_exact_v0()
    );
    let signer_inventory = clean_signer_lifetime_inventory_v1(&signer_facts).ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.signer_pre_activate_inventory",
            "caught-up pinned signer inventory is not clean",
        )
    })?;
    if !signer_facts.belongs_to_pinned_journal_at_path_v0(&signer, &paths.signer)
        || signer_facts.pending_intent().is_some()
        || signer_facts.exact_watermark() != facts.signer_exact_watermark
        || signer_inventory.durable_vote_intent_count() != facts.signer_durable_vote_intent_count
        || signer_inventory.durable_timeout_intent_count()
            != facts.signer_durable_timeout_intent_count
        || signer_inventory.signed_vote_intent_count() != facts.signer_signed_vote_intent_count
        || signer_inventory.signed_timeout_intent_count()
            != facts.signer_signed_timeout_intent_count
        || signer_inventory.inventory_digest() != facts.signer_inventory_digest
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.signer_pre_activate_join",
            "caught-up pinned signer differs from the retained passive cut",
        ));
    }

    let signer = signer.activate_v0().map_err(|failure| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug(
            "activation.signer_activate",
            failure.into_error(),
        )
    })?;
    let mut signer = signer;
    let operational_signer_facts = process2_try!(
        "activation.signer_operational_facts",
        signer.confirm_node_checkpoint_head_exact_v0()
    );
    let operational_signer_inventory =
        clean_signer_lifetime_inventory_v1(&operational_signer_facts).ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.signer_operational_inventory",
                "activated signer Vote/TimeoutVote lifecycles are not individually clean",
            )
        })?;
    if !operational_signer_facts.belongs_to_operational_journal_at_path_v0(&signer, &paths.signer)
        || operational_signer_facts.journal_id() != signer_facts.journal_id()
        || operational_signer_facts.profile_checksum() != signer_facts.profile_checksum()
        || operational_signer_facts.identity() != signer_facts.identity()
        || operational_signer_facts.exact_watermark() != signer_facts.exact_watermark()
        || operational_signer_facts.capacity() != signer_facts.capacity()
        || operational_signer_inventory != signer_inventory
        || operational_signer_facts.tail() != signer_facts.tail()
        || operational_signer_facts.pending_intent() != signer_facts.pending_intent()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.signer_operational_join",
            "operational signer differs from the exact pinned clean cut",
        ));
    }

    let final_checkpoint = process2_try!(
        "activation.checkpoint_final_load",
        checkpoint_store.load(operational_signer_facts.exact_watermark().scope())
    )
    .ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.checkpoint_final_missing",
            "whole-node checkpoint disappeared after signer activation",
        )
    })?;
    let final_committed = process2_try!(
        "activation.application_final_committed",
        application.confirmed_committed_head_v0()
    );
    validate_checkpoint_join_v0(
        final_checkpoint,
        &rebound_facts,
        &operational_signer_facts,
        &application,
        &final_committed,
        &validation_store,
        &history.recovered,
    )
    .map_err(|error| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug(
            "activation.checkpoint_final_join",
            error,
        )
    })?;
    if final_checkpoint != checkpoint || final_committed != committed {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.final_cut_changed",
            "durable checkpoint or committed application changed during activation",
        ));
    }

    let activated_facts = PocoNodeDeployedLabProcess2ActivatedFactsV1 {
        recovery: facts.recovery,
        activation_binding_digest: facts.activation_binding_digest,
        activation_row_revision: facts.activation_row_revision,
        activation_row_checksum: facts.activation_row_checksum,
        application_parent_block_id: facts.application_parent_block_id,
        application_parent_height: facts.application_parent_height,
        prepared_execution_count: facts.prepared_execution_count,
        signer_exact_watermark: operational_signer_facts.exact_watermark(),
        signer_durable_vote_intent_count: operational_signer_inventory.durable_vote_intent_count(),
        signer_durable_timeout_intent_count: operational_signer_inventory
            .durable_timeout_intent_count(),
        signer_signed_vote_intent_count: operational_signer_inventory.signed_vote_intent_count(),
        signer_signed_timeout_intent_count: operational_signer_inventory
            .signed_timeout_intent_count(),
        signer_inventory_digest: operational_signer_inventory.inventory_digest(),
        selected_replay_digest: facts.selected_replay_digest,
        startup_timer_epoch: startup_timer.epoch_v0(),
        startup_timer_view: startup_timer.view_v0(),
    };
    let activated = PocoNodeDeployedLabProcess2ActivatedOwnerV1 {
        facts: activated_facts,
        parts: PocoNodeDeployedLabProcess2RuntimePartsV1 {
            core,
            startup_timer,
            safety_store,
            application,
            signer,
            checkpoint_store,
            validation_store,
            activation_ready,
            checkpoint: final_checkpoint,
            application_head,
            application_overlay_ref,
            pending_executions,
        },
    };
    activated.into_recovered_ordinary_runtime_after_recovery_start_v1()
}

/// Read-only projection of one exact process2 activation join.
///
/// This value is descriptive only.  Core, the retained startup timer, the
/// activated signer, every durable namespace, and all speculative execution
/// artifacts remain in [`PocoNodeDeployedLabProcess2ActivatedOwnerV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeDeployedLabProcess2ActivatedFactsV1 {
    recovery: PocoNodeDeployedLabProcess2RecoveryFactsV0,
    activation_binding_digest: [u8; 32],
    activation_row_revision: u64,
    activation_row_checksum: [u8; 32],
    application_parent_block_id: BlockId,
    application_parent_height: u64,
    prepared_execution_count: u64,
    signer_exact_watermark: SignerWatermarkV0,
    signer_durable_vote_intent_count: u64,
    signer_durable_timeout_intent_count: u64,
    signer_signed_vote_intent_count: u64,
    signer_signed_timeout_intent_count: u64,
    signer_inventory_digest: [u8; 32],
    selected_replay_digest: [u8; 32],
    startup_timer_epoch: Epoch,
    startup_timer_view: View,
}

impl PocoNodeDeployedLabProcess2ActivatedFactsV1 {
    pub const fn recovery_v0(self) -> PocoNodeDeployedLabProcess2RecoveryFactsV0 {
        self.recovery
    }

    pub const fn activation_binding_digest_v1(self) -> [u8; 32] {
        self.activation_binding_digest
    }

    pub const fn activation_row_revision_v1(self) -> u64 {
        self.activation_row_revision
    }

    pub const fn activation_row_checksum_v1(self) -> [u8; 32] {
        self.activation_row_checksum
    }

    pub const fn application_parent_block_id_v1(self) -> BlockId {
        self.application_parent_block_id
    }

    pub const fn application_parent_height_v1(self) -> u64 {
        self.application_parent_height
    }

    pub const fn prepared_execution_count_v1(self) -> u64 {
        self.prepared_execution_count
    }

    pub const fn signer_exact_watermark_v1(self) -> SignerWatermarkV0 {
        self.signer_exact_watermark
    }

    pub const fn signer_durable_vote_intent_count_v1(self) -> u64 {
        self.signer_durable_vote_intent_count
    }

    pub const fn signer_durable_timeout_intent_count_v1(self) -> u64 {
        self.signer_durable_timeout_intent_count
    }

    pub const fn signer_signed_vote_intent_count_v1(self) -> u64 {
        self.signer_signed_vote_intent_count
    }

    pub const fn signer_signed_timeout_intent_count_v1(self) -> u64 {
        self.signer_signed_timeout_intent_count
    }

    pub const fn signer_inventory_digest_v1(self) -> [u8; 32] {
        self.signer_inventory_digest
    }

    pub const fn selected_replay_digest_v1(self) -> [u8; 32] {
        self.selected_replay_digest
    }

    pub const fn startup_timer_epoch_v1(self) -> Epoch {
        self.startup_timer_epoch
    }

    pub const fn startup_timer_view_v1(self) -> View {
        self.startup_timer_view
    }
}

/// Descriptive projection of the exact process2-to-ordinary bridge.
///
/// These values carry no Core, signer, application, timer, or networking
/// authority.  In particular, the startup epoch/view cannot construct or arm
/// Core's retained [`AnchoredOrdinaryArmViewTimerV0`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeDeployedLabRecoveredOrdinaryRuntimeFactsV1 {
    activation: PocoNodeDeployedLabProcess2ActivatedFactsV1,
    runtime: PocoNodeLabRuntimeFactsV0,
    proposal_validation_scope: [u8; 32],
    proposal_validation_store_id: [u8; 32],
    proposal_validation_owner_id: [u8; 32],
    proposal_validation_durable_sequence: u64,
    startup_timer_epoch: Epoch,
    startup_timer_view: View,
}

impl PocoNodeDeployedLabRecoveredOrdinaryRuntimeFactsV1 {
    pub const fn activation_v1(self) -> PocoNodeDeployedLabProcess2ActivatedFactsV1 {
        self.activation
    }

    pub const fn runtime_v1(self) -> PocoNodeLabRuntimeFactsV0 {
        self.runtime
    }

    pub const fn proposal_validation_scope_v1(self) -> [u8; 32] {
        self.proposal_validation_scope
    }

    pub const fn proposal_validation_store_id_v1(self) -> [u8; 32] {
        self.proposal_validation_store_id
    }

    pub const fn proposal_validation_owner_id_v1(self) -> [u8; 32] {
        self.proposal_validation_owner_id
    }

    pub const fn proposal_validation_durable_sequence_v1(self) -> u64 {
        self.proposal_validation_durable_sequence
    }

    pub const fn startup_timer_epoch_v1(self) -> Epoch {
        self.startup_timer_epoch
    }

    pub const fn startup_timer_view_v1(self) -> View {
        self.startup_timer_view
    }
}

#[derive(Debug)]
pub(crate) struct PocoNodeDeployedLabProcess2RetainedExecutionV1 {
    pub(crate) binding: ProposalValidationBindingV0,
    pub(crate) executed: NativeExecutedBlockV0,
    pub(crate) view: View,
    pub(crate) source_artifact_checksum: [u8; 32],
    pub(crate) validation_row_checksum: [u8; 32],
    pub(crate) overlay_ref: BlockIdOverlayRefV0,
    pub(crate) speculative_head: ApplicationHeadV0,
}

pub(crate) struct PocoNodeDeployedLabProcess2RuntimePartsV1<W: ExternalMonotonicWatermarkV0> {
    core: Core,
    startup_timer: AnchoredOrdinaryArmViewTimerV0,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application: DurableNativeApplicationV0,
    signer: SqliteSignerJournalV0<W>,
    checkpoint_store: SqliteExternalNodeCheckpointStoreV0,
    validation_store: SqliteProposalValidationStoreV0,
    activation_ready: ConfirmedReplayActivationReadyV0,
    checkpoint: ExternalNodeCheckpointV0,
    application_head: ApplicationHeadV0,
    application_overlay_ref: Option<BlockIdOverlayRefV0>,
    pending_executions: BTreeMap<BlockId, PocoNodeDeployedLabProcess2RetainedExecutionV1>,
}

/// Linear owner of a locally activation-ready process2 cut.
///
/// It deliberately exposes only inert facts.  The consuming parts transition
/// is crate-private for the later laboratory authority join, so copied facts
/// or a raw SQLite row cannot construct a live signer/Core pair.
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeDeployedLabProcess2ActivatedOwnerV1;
/// fn require_clone<T: Clone>() {}
/// fn check<W: trnm_consensus_signer_journal::ExternalMonotonicWatermarkV0>() {
///     require_clone::<PocoNodeDeployedLabProcess2ActivatedOwnerV1<W>>();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeDeployedLabProcess2ActivatedOwnerV1;
/// fn bypass_public_recovery<W: trnm_consensus_signer_journal::ExternalMonotonicWatermarkV0>(
///     owner: PocoNodeDeployedLabProcess2ActivatedOwnerV1<W>,
/// ) {
///     let _ = owner.into_recovered_ordinary_runtime_after_recovery_start_v1();
/// }
/// ```
#[must_use = "the activated process2 authorities must remain linear"]
pub struct PocoNodeDeployedLabProcess2ActivatedOwnerV1<W: ExternalMonotonicWatermarkV0> {
    facts: PocoNodeDeployedLabProcess2ActivatedFactsV1,
    parts: PocoNodeDeployedLabProcess2RuntimePartsV1<W>,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeDeployedLabProcess2ActivatedOwnerV1<W> {
    pub const fn facts_v1(&self) -> PocoNodeDeployedLabProcess2ActivatedFactsV1 {
        self.facts
    }

    /// Consumes the activation-ready cut into the ordinary laboratory runtime
    /// while retaining Core's unique startup timer as a separate typed owner.
    ///
    /// This transition performs fresh owner-affinity joins for Safety,
    /// application P/K history, signer, checkpoint, and proposal journal;
    /// obtains the exact Core-issued seal/finalization authorities; and proves
    /// that the selected native application parent is Core's high QC.  It does
    /// not convert the timer into an effect and therefore cannot arm an
    /// external pacemaker.
    fn into_recovered_ordinary_runtime_after_recovery_start_v1(
        self,
    ) -> Result<
        PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W>,
        PocoNodeDeployedLabProcess2RecoveryErrorV0,
    > {
        let Self { facts, parts } = self;
        let PocoNodeDeployedLabProcess2RuntimePartsV1 {
            core,
            startup_timer,
            safety_store,
            application,
            mut signer,
            mut checkpoint_store,
            mut validation_store,
            activation_ready,
            checkpoint,
            application_head,
            application_overlay_ref,
            pending_executions,
        } = parts;

        let safety = core.safety_state();
        let high_qc = safety.high_qc().qc_ref();
        if startup_timer.epoch_v0() != safety.epoch()
            || startup_timer.view_v0() != safety.current_view()
            || safety.pending_sign().is_some()
            || safety.pending_finalize().is_some()
            || safety.pending_tc_high_qc_sync().is_some()
            || safety.pending_standalone_qc_sync().is_some()
            || !safety.finalization_queue().is_empty()
            || safety.finalized() != safety.application_applied()
            || application_head.block_id().as_bytes() != high_qc.block_id().as_bytes()
            || application_head.height().get() != high_qc.height().get()
            || safety.current_view() <= high_qc.view()
            || facts.application_parent_block_id_v1() != high_qc.block_id()
            || facts.application_parent_height_v1() != high_qc.height().get()
            || facts.startup_timer_epoch_v1() != startup_timer.epoch_v0()
            || facts.startup_timer_view_v1() != startup_timer.view_v0()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "runtime_bridge.core_parent",
                "activated Core, selected application parent, or retained timer differs",
            ));
        }

        let safety_facts = process2_try!(
            "runtime_bridge.safety_facts",
            safety_store.confirm_node_checkpoint_head_exact_v0(safety)
        );
        let signer_facts = process2_try!(
            "runtime_bridge.signer_facts",
            signer.confirm_node_checkpoint_head_exact_v0()
        );
        let observed_checkpoint = process2_try!(
            "runtime_bridge.checkpoint_load",
            checkpoint_store.load(checkpoint.scope())
        );
        if !safety_facts.belongs_to_store_at_path_v0(&safety_store, safety_store.path())
            || !signer_facts.belongs_to_operational_journal_at_path_v0(&signer, signer.path())
            || signer_facts.pending_intent().is_some()
            || observed_checkpoint != Some(checkpoint)
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "runtime_bridge.durable_heads",
                "Safety, signer, or checkpoint lost exact owner affinity",
            ));
        }
        let signer_inventory =
            clean_signer_lifetime_inventory_v1(&signer_facts).ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "runtime_bridge.signer_inventory",
                    "bridged signer Vote/TimeoutVote lifecycles are not individually clean",
                )
            })?;
        if !signer_inventory_matches_recovery_facts_v1(
            facts.recovery_v0(),
            signer_facts.exact_watermark(),
            signer_inventory,
        ) || facts.signer_exact_watermark_v1() != signer_facts.exact_watermark()
            || facts.signer_durable_vote_intent_count_v1()
                != signer_inventory.durable_vote_intent_count()
            || facts.signer_durable_timeout_intent_count_v1()
                != signer_inventory.durable_timeout_intent_count()
            || facts.signer_signed_vote_intent_count_v1()
                != signer_inventory.signed_vote_intent_count()
            || facts.signer_signed_timeout_intent_count_v1()
                != signer_inventory.signed_timeout_intent_count()
            || facts.signer_inventory_digest_v1() != signer_inventory.inventory_digest()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "runtime_bridge.signer_facts_join",
                "bridged signer head/inventory differs from recovery or activated facts",
            ));
        }

        let activation_binding = activation_ready.binding_v0();
        if !activation_ready.belongs_to_store_at_path_v0(&validation_store, validation_store.path())
            || activation_binding.binding_digest_v0() != facts.activation_binding_digest_v1()
            || activation_ready.row_revision_v0() != facts.activation_row_revision_v1()
            || activation_ready.row_checksum_v0().as_bytes() != &facts.activation_row_checksum_v1()
            || activation_binding.session_id_v0() != facts.recovery_v0().session_id_v0()
            || activation_binding.core_rehydrate_digest_v0()
                != facts.recovery_v0().rehydrate_digest_v0()
            || activation_binding.safety_revision_v0() != safety_facts.revision_v0()
            || activation_binding.safety_chain_checksum_v0() != safety_facts.chain_checksum_v0()
            || activation_binding.application_parent_block_id_v0()
                != *application_head.block_id().as_bytes()
            || activation_binding.application_parent_height_v0() != application_head.height().get()
            || activation_binding.application_parent_state_root_v0()
                != *application_head.state_root().as_bytes()
            || activation_binding.application_parent_commit_id_v0()
                != *application_head.commit_id().as_bytes()
            || activation_binding.checkpoint_generation_v0() != checkpoint.generation()
            || activation_binding.checkpoint_checksum_v0() != checkpoint.checkpoint_checksum()
            || activation_binding.signer_scope_v0() != signer_facts.exact_watermark().scope()
            || activation_binding.signer_journal_id_v0() != signer_facts.journal_id()
            || activation_binding.signer_sequence_v0() != signer_facts.exact_watermark().sequence()
            || activation_binding.signer_chain_checksum_v0()
                != signer_facts.exact_watermark().chain_checksum()
            || activation_binding.signer_inventory_digest_v1()
                != signer_inventory.inventory_digest()
            || activation_binding.selected_replay_digest_v0() != facts.selected_replay_digest_v1()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "runtime_bridge.activation_join",
                "ActivationReady differs from the exact Core/Safety/App/signer/checkpoint cut",
            ));
        }

        let terminal_audit = process2_try!(
            "runtime_bridge.proposal_terminal_audit",
            validation_store.confirm_terminal_k_audit_v0()
        );
        let proposal_sequence = process2_try!(
            "runtime_bridge.proposal_sequence",
            validation_store.durable_sequence_v0()
        );
        if !terminal_audit.belongs_to_store_at_path_v0(&validation_store, validation_store.path())
            || terminal_audit.scope_v0() != validation_store.scope_v0()
            || terminal_audit.store_id_v0() != validation_store.store_id_v0()
            || terminal_audit.store_sequence_v0() != proposal_sequence
            || proposal_sequence
                != terminal_audit
                    .terminal_row_count_v0()
                    .checked_mul(3)
                    .ok_or_else(|| {
                        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                            "runtime_bridge.proposal_sequence_overflow",
                            "proposal terminal sequence overflowed",
                        )
                    })?
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "runtime_bridge.proposal_owner",
                "proposal-validation journal differs from its complete terminal inventory",
            ));
        }

        let mut retained = BTreeMap::new();
        for (block_id, value) in pending_executions {
            let confirmed_p = process2_try!(
                "runtime_bridge.application_p",
                application.confirm_durable_p_v0(&value.executed)
            );
            let confirmed_k = process2_try!(
                "runtime_bridge.proposal_k",
                validation_store
                    .confirm_proposal_validation_checkpoint_facts_exact_v0(&value.binding)
            );
            if !confirmed_p.belongs_to_application_at_path_v0(&application, application.path())
                || !confirmed_k
                    .belongs_to_store_at_path_v0(&validation_store, validation_store.path())
                || confirmed_k.owner_id_v0() != terminal_audit.owner_id_v0()
                || confirmed_k.row_checksum_v0().as_bytes() != &value.validation_row_checksum
                || confirmed_p.block_id_v0() != *block_id.as_bytes()
                || confirmed_p.parent_block_id_v0() != *value.binding.parent().block_id().as_bytes()
                || confirmed_p.target_height_v0() != value.binding.height().get()
                || confirmed_p.source_artifact_checksum_v0() != value.source_artifact_checksum
                || confirmed_p.overlay_checksum_v0() != value.overlay_ref.overlay_checksum()
                || value.overlay_ref.block_id() != block_id
                || value.speculative_head.block_id().as_bytes() != block_id.as_bytes()
                || value.speculative_head.height() != value.binding.height()
                || value.view != View::new(value.binding.view())
            {
                return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "runtime_bridge.prepared_join",
                    "prepared application P differs from its exact terminal proposal K",
                ));
            }
            let value = PocoNodeLabRetainedExecutionV0 {
                binding: value.binding,
                executed: value.executed,
                view: value.view,
                source_artifact_checksum: value.source_artifact_checksum,
                validation_row_checksum: value.validation_row_checksum,
                overlay_ref: value.overlay_ref,
                speculative_head: value.speculative_head,
            };
            if retained.insert(block_id, value).is_some() {
                return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "runtime_bridge.prepared_duplicate",
                    "prepared application inventory contains a duplicate BlockId",
                ));
            }
        }
        if u64::try_from(retained.len()).ok() != Some(facts.prepared_execution_count_v1())
            || application_overlay_ref.is_none()
            || !retained.contains_key(&high_qc.block_id())
            || retained[&high_qc.block_id()].overlay_ref != application_overlay_ref.unwrap()
            || retained[&high_qc.block_id()].speculative_head != application_head
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "runtime_bridge.high_qc_execution",
                "selected high-QC execution is absent or differs from the retained overlay",
            ));
        }

        let proposal_journal = process2_try!(
            "runtime_bridge.proposal_config",
            PocoNodeLabProposalJournalConfigV0::new(
                validation_store.path().to_path_buf(),
                *validation_store.scope_v0().as_bytes(),
                *terminal_audit.owner_id_v0().as_bytes(),
                proposal_sequence,
            )
        );
        let proposal_scope = *validation_store.scope_v0().as_bytes();
        let proposal_store_id = validation_store.store_id_v0();
        let proposal_owner_id = *terminal_audit.owner_id_v0().as_bytes();
        drop(activation_ready);
        drop(validation_store);

        let seal_authority = process2_try!(
            "runtime_bridge.seal_authority",
            core.issue_application_seal_authority_v0()
        );
        let finalization_authority = process2_try!(
            "runtime_bridge.finalization_authority",
            core.issue_application_finalization_apply_authority_v0()
        );
        if !seal_authority.matches_application_finalization_authority_v0(&finalization_authority) {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "runtime_bridge.application_authority",
                "Core-issued application seal and finalization authorities differ",
            ));
        }

        let runtime = PocoNodeLabOrdinaryProposalRuntimeV0 {
            core,
            seal_authority,
            finalization_authority,
            safety_store,
            application,
            signer_journal: signer,
            checkpoint_store,
            checkpoint,
            application_head,
            application_overlay: application_overlay_ref,
            pending_executions: retained,
            proposal_journal,
        };
        let binding = process2_try!(
            "runtime_bridge.proposal_binding",
            runtime.proposal_binding_v0()
        );
        if binding.current_view_v0() != startup_timer.view_v0()
            || binding.high_qc_v0().qc_ref() != high_qc
            || binding
                .parent_v0()
                .application_head_v0()
                .block_id()
                .as_bytes()
                != high_qc.block_id().as_bytes()
            || binding.parent_v0().application_head_v0().height().get() != high_qc.height().get()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "runtime_bridge.proposal_binding_join",
                "ordinary runtime proposal binding differs from retained Core high-QC/timer",
            ));
        }
        let runtime_facts = runtime.facts_v0();
        let bridge_facts = PocoNodeDeployedLabRecoveredOrdinaryRuntimeFactsV1 {
            activation: facts,
            runtime: runtime_facts,
            proposal_validation_scope: proposal_scope,
            proposal_validation_store_id: proposal_store_id,
            proposal_validation_owner_id: proposal_owner_id,
            proposal_validation_durable_sequence: proposal_sequence,
            startup_timer_epoch: startup_timer.epoch_v0(),
            startup_timer_view: startup_timer.view_v0(),
        };
        Ok(PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1 {
            runtime,
            startup_timer,
            facts: bridge_facts,
        })
    }
}

/// Linear process2-recovered ordinary runtime plus Core's sole startup timer.
///
/// The timer remains private and unconsumed: constructing this owner never
/// calls `AnchoredOrdinaryArmViewTimerV0::into_effect_v0`.  A later typed
/// RecoveryStart transition must consume the entire owner before it can arm an
/// external pacemaker.
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1;
/// fn require_clone<T: Clone>() {}
/// fn check<W: trnm_consensus_signer_journal::ExternalMonotonicWatermarkV0>() {
///     require_clone::<PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W>>();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1;
/// fn steal_timer<W: trnm_consensus_signer_journal::ExternalMonotonicWatermarkV0>(
///     owner: PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W>,
/// ) {
///     let _ = owner.startup_timer;
/// }
/// ```
#[must_use = "the recovered runtime and startup timer must remain linear"]
pub struct PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W: ExternalMonotonicWatermarkV0> {
    runtime: PocoNodeLabOrdinaryProposalRuntimeV0<W>,
    // Intentionally retained and unread until a later typed N/N
    // RecoveryStart transition can consume the entire owner and arm last.
    #[allow(dead_code)]
    startup_timer: AnchoredOrdinaryArmViewTimerV0,
    facts: PocoNodeDeployedLabRecoveredOrdinaryRuntimeFactsV1,
}

impl<W: ExternalMonotonicWatermarkV0> PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W> {
    pub const fn facts_v1(&self) -> PocoNodeDeployedLabRecoveredOrdinaryRuntimeFactsV1 {
        self.facts
    }

    pub fn runtime_facts_v1(&self) -> PocoNodeLabRuntimeFactsV0 {
        self.runtime.facts_v0()
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug
    for PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug
    for PocoNodeDeployedLabProcess2ActivatedOwnerV1<W>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeDeployedLabProcess2ActivatedOwnerV1")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl<W: ExternalMonotonicWatermarkV0> fmt::Debug for PocoNodeDeployedLabProcess2RecoveryOwnerV0<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeDeployedLabProcess2RecoveryOwnerV0")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

fn validate_retained_history_rows_v1(
    retained_rows: &[ConfirmedDurableExecutionHistoryRowV0],
    application: &DurableNativeApplicationV0,
    application_path: &Path,
    fresh: &Process2HistoryInventoryV0,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if retained_rows.len() != fresh.recovered.len() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.retained_history_count",
            "retained and fresh application-history inventories differ in size",
        ));
    }
    let mut seen = BTreeSet::new();
    for row in retained_rows {
        let parent = process2_try!("activation.retained_history_parent", row.parent_head_v0());
        let target = process2_try!("activation.retained_history_target", row.target_head_v0());
        let block_id = BlockId::new(*target.block_id().as_bytes());
        let recovered = fresh.recovered.get(&block_id).ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.retained_history_block",
                "retained history row is absent from the fresh terminal inventory",
            )
        })?;
        if !seen.insert(block_id)
            || !row.belongs_to_application_at_path_v0(application, application_path)
            || row.store_id_v0() != application.config_v0().store_id()
            || parent != *recovered.binding.parent()
            || target != recovered.application_head
            || row.status_v0() != recovered.status
            || row.p_sequence_v0() != recovered.history_row.p_sequence_v0()
            || row.artifact_digest_v0() != recovered.history_row.artifact_digest_v0()
            || row.overlay_digest_v0() != recovered.history_row.overlay_digest_v0()
            || row.p_digest_v0() != recovered.history_row.p_digest_v0()
            || row.commit_sequence_v0() != recovered.history_row.commit_sequence_v0()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.retained_history_join",
                "retained application-history authority differs from fresh readback",
            ));
        }
    }
    Ok(())
}

fn rebuild_prepared_executions_v1(
    application: &DurableNativeApplicationV0,
    application_path: &Path,
    history: &Process2HistoryInventoryV0,
) -> Result<
    BTreeMap<BlockId, PocoNodeDeployedLabProcess2RetainedExecutionV1>,
    PocoNodeDeployedLabProcess2RecoveryErrorV0,
> {
    let mut prepared = BTreeMap::new();
    for (block_id, recovered) in &history.recovered {
        if recovered.status != DurableExecutionHistoryStatusV0::Prepared {
            continue;
        }
        let executed = history.executed.get(block_id).ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.prepared_artifact",
                "prepared history row lacks its exact execution artifact",
            )
        })?;
        let confirmed = process2_try!(
            "activation.prepared_confirm",
            application.confirm_durable_p_v0(executed)
        );
        let speculative_head = process2_try!(
            "activation.prepared_head",
            confirmed.overlay_parent_head_v0()
        );
        if !confirmed.belongs_to_application_at_path_v0(application, application_path)
            || confirmed.store_id_v0() != application.config_v0().store_id()
            || confirmed.block_id_v0() != *recovered.binding.block_id().as_bytes()
            || confirmed.parent_block_id_v0() != *recovered.binding.parent().block_id().as_bytes()
            || confirmed.target_height_v0() != recovered.binding.height().get()
            || confirmed.source_artifact_checksum_v0()
                != history.source_artifact_checksums[block_id]
            || confirmed.overlay_checksum_v0() != recovered.history_row.overlay_digest_v0()
            || speculative_head != recovered.application_head
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.prepared_join",
                "fresh durable P differs from its exact terminal K/history binding",
            ));
        }
        let retained = PocoNodeDeployedLabProcess2RetainedExecutionV1 {
            binding: recovered.binding.clone(),
            executed: executed.clone(),
            view: View::new(recovered.binding.view()),
            source_artifact_checksum: confirmed.source_artifact_checksum_v0(),
            validation_row_checksum: recovered.validation_row_checksum,
            overlay_ref: BlockIdOverlayRefV0::new(
                *block_id,
                BlockId::new(confirmed.parent_block_id_v0()),
                confirmed.overlay_checksum_v0(),
            ),
            speculative_head,
        };
        if prepared.insert(*block_id, retained).is_some() {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.prepared_duplicate",
                "prepared execution inventory contains a duplicate BlockId",
            ));
        }
    }
    Ok(prepared)
}

fn select_high_qc_application_parent_v1(
    safety: &SafetyState,
    committed: &ApplicationHeadV0,
    pending: &BTreeMap<BlockId, PocoNodeDeployedLabProcess2RetainedExecutionV1>,
) -> Result<
    (ApplicationHeadV0, Option<BlockIdOverlayRefV0>),
    PocoNodeDeployedLabProcess2RecoveryErrorV0,
> {
    let high_qc = safety.high_qc().qc_ref();
    if committed.block_id().as_bytes() == high_qc.block_id().as_bytes()
        && committed.height().get() == high_qc.height().get()
    {
        if pending.contains_key(&high_qc.block_id()) {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "activation.application_parent_duplicate",
                "committed high-QC parent is also retained as prepared",
            ));
        }
        return Ok((committed.clone(), None));
    }
    let retained = pending.get(&high_qc.block_id()).ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.application_parent_missing",
            "selected high-QC lacks its freshly confirmed prepared execution",
        )
    })?;
    if retained.speculative_head.block_id().as_bytes() != high_qc.block_id().as_bytes()
        || retained.speculative_head.height().get() != high_qc.height().get()
        || retained.view != high_qc.view()
        || retained.overlay_ref.block_id() != high_qc.block_id()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "activation.application_parent_join",
            "selected prepared application parent differs from Safety high-QC",
        ));
    }
    Ok((
        retained.speculative_head.clone(),
        Some(retained.overlay_ref),
    ))
}

fn zero_delta_signer_invariant_v1(
    watermark: SignerWatermarkV0,
    durable_vote_intent_count: u64,
    durable_timeout_intent_count: u64,
    signed_vote_intent_count: u64,
    signed_timeout_intent_count: u64,
    inventory_digest: [u8; 32],
) -> [u8; 32] {
    let sequence = watermark.sequence().to_be_bytes();
    let durable_vote = durable_vote_intent_count.to_be_bytes();
    let durable_timeout = durable_timeout_intent_count.to_be_bytes();
    let signed_vote = signed_vote_intent_count.to_be_bytes();
    let signed_timeout = signed_timeout_intent_count.to_be_bytes();
    hash_v0(
        PROCESS2_ZERO_DELTA_SIGNER_INVARIANT_DOMAIN_V1,
        &[
            &watermark.scope(),
            &watermark.journal_id(),
            &sequence,
            &watermark.chain_checksum(),
            &durable_vote,
            &durable_timeout,
            &signed_vote,
            &signed_timeout,
            &inventory_digest,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn zero_delta_node_facts_v1(
    restart_cut: PocoNodeDeployedLabZeroDeltaRestartCutV1,
    process2: PocoNodeDeployedLabProcess2RecoveryFactsV0,
    process2_safety_revision: u64,
    process2_safety_state_record_checksum: [u8; 32],
    process2_safety_chain_checksum: [u8; 32],
    process2_checkpoint_generation: u64,
    process2_checkpoint_checksum: [u8; 32],
    process2_checkpoint_canonical_sha256: [u8; 32],
    terminal_application_commit_id: [u8; 32],
    signer_inventory_invariant_sha256: [u8; 32],
) -> [u8; 32] {
    let cut = restart_cut.fields;
    let epoch = cut.epoch.get().to_be_bytes();
    let current_view = cut.current_view.get().to_be_bytes();
    let high_qc_epoch = cut.direct_high_qc.epoch().get().to_be_bytes();
    let high_qc_view = cut.direct_high_qc.view().get().to_be_bytes();
    let high_qc_height = cut.direct_high_qc.height().get().to_be_bytes();
    let proposal_parent_height = cut.proposal_parent_height.to_be_bytes();
    let finalized_height = cut.finalized_height.to_be_bytes();
    let application_height = cut.application_height.to_be_bytes();
    let restart_checkpoint_generation = cut.restart_checkpoint_generation.to_be_bytes();
    let restart_safety_revision = cut.restart_safety_revision.to_be_bytes();
    let signer_sequence = cut.signer_exact_watermark.sequence().to_be_bytes();
    let signer_durable_vote = cut.signer_durable_vote_intent_count.to_be_bytes();
    let signer_durable_timeout = cut.signer_durable_timeout_intent_count.to_be_bytes();
    let signer_signed_vote = cut.signer_signed_vote_intent_count.to_be_bytes();
    let signer_signed_timeout = cut.signer_signed_timeout_intent_count.to_be_bytes();
    let process2_replayed = process2.replayed_link_count_v0().to_be_bytes();
    let process2_safety_revision = process2_safety_revision.to_be_bytes();
    let process2_checkpoint_generation = process2_checkpoint_generation.to_be_bytes();
    let process2_signer_sequence = process2
        .signer_exact_watermark_v1()
        .sequence()
        .to_be_bytes();
    let process2_durable_vote = process2.signer_durable_vote_intent_count_v1().to_be_bytes();
    let process2_durable_timeout = process2
        .signer_durable_timeout_intent_count_v1()
        .to_be_bytes();
    let process2_signed_vote = process2.signer_signed_vote_intent_count_v1().to_be_bytes();
    let process2_signed_timeout = process2
        .signer_signed_timeout_intent_count_v1()
        .to_be_bytes();
    let process2_tail_count = process2
        .unconfirmed_speculative_tail_count_v0()
        .to_be_bytes();
    hash_v0(
        PROCESS2_ZERO_DELTA_NODE_FACTS_DOMAIN_V1,
        &[
            &cut.restart_cut_artifact_sha256,
            cut.local_validator.as_bytes(),
            cut.validator_set_id.as_bytes(),
            &epoch,
            &current_view,
            cut.direct_high_qc.qc_digest().as_bytes(),
            &high_qc_epoch,
            &high_qc_view,
            &high_qc_height,
            cut.direct_high_qc.block_id().as_bytes(),
            cut.direct_high_qc.validator_set_id().as_bytes(),
            &proposal_parent_height,
            cut.proposal_parent_block_id.as_bytes(),
            &finalized_height,
            cut.finalized_block_id.as_bytes(),
            &cut.finalized_chain_root,
            &application_height,
            cut.application_block_id.as_bytes(),
            cut.application_state_root.as_bytes(),
            &restart_checkpoint_generation,
            &cut.restart_checkpoint_canonical_sha256,
            &restart_safety_revision,
            &cut.restart_safety_state_record_checksum,
            &cut.restart_safety_chain_checksum,
            &cut.signer_exact_watermark.scope(),
            &cut.signer_exact_watermark.journal_id(),
            &signer_sequence,
            &cut.signer_exact_watermark.chain_checksum(),
            &signer_durable_vote,
            &signer_durable_timeout,
            &signer_signed_vote,
            &signer_signed_timeout,
            &cut.signer_inventory_digest,
            &process2.session_id_v0(),
            &process2_replayed,
            &process2_safety_revision,
            &process2_safety_state_record_checksum,
            &process2_safety_chain_checksum,
            &process2_checkpoint_generation,
            &process2_checkpoint_checksum,
            &process2_checkpoint_canonical_sha256,
            &process2.signer_exact_watermark_v1().scope(),
            &process2.signer_exact_watermark_v1().journal_id(),
            &process2_signer_sequence,
            &process2.signer_exact_watermark_v1().chain_checksum(),
            &process2_durable_vote,
            &process2_durable_timeout,
            &process2_signed_vote,
            &process2_signed_timeout,
            &process2.signer_inventory_digest_v1(),
            &process2.final_progress_checksum_v0(),
            &process2.rehydrate_digest_v0(),
            &process2.application_history_digest_v0(),
            &process2_tail_count,
            &process2.unconfirmed_speculative_tail_digest_v0(),
            &terminal_application_commit_id,
            &signer_inventory_invariant_sha256,
        ],
    )
}

fn zero_delta_artifact_bytes_v1(
    restart_cut_artifact_sha256: [u8; 32],
    node_facts_sha256: [u8; 32],
    signer_inventory_invariant_sha256: [u8; 32],
    process2_checkpoint_canonical_sha256: [u8; 32],
    terminal_application_commit_id: [u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + 2 + 32 * 5);
    bytes.extend_from_slice(PROCESS2_ZERO_DELTA_ARTIFACT_MAGIC_V1);
    bytes.extend_from_slice(&PROCESS2_ZERO_DELTA_ARTIFACT_VERSION_V1.to_be_bytes());
    bytes.extend_from_slice(&restart_cut_artifact_sha256);
    bytes.extend_from_slice(&node_facts_sha256);
    bytes.extend_from_slice(&signer_inventory_invariant_sha256);
    bytes.extend_from_slice(&process2_checkpoint_canonical_sha256);
    bytes.extend_from_slice(&terminal_application_commit_id);
    bytes
}

fn selected_replay_activation_digest_v1(
    facts: PocoNodeDeployedLabProcess2RecoveryFactsV0,
    safety: &SafetyState,
    committed: &ApplicationHeadV0,
    selected: &ApplicationHeadV0,
    selected_overlay: Option<BlockIdOverlayRefV0>,
    pending_count: u64,
    pending: &BTreeMap<BlockId, PocoNodeDeployedLabProcess2RetainedExecutionV1>,
) -> [u8; 32] {
    let mut row_digests = Vec::with_capacity(pending.len());
    for (block_id, retained) in pending {
        row_digests.push(hash_v0(
            PROCESS2_ACTIVATION_PREPARED_ROW_DOMAIN_V1,
            &[
                block_id.as_bytes(),
                retained.binding.validation_id().as_bytes(),
                &[retained.binding.route() as u8],
                &retained.binding.generation().to_be_bytes(),
                &retained.view.get().to_be_bytes(),
                retained.binding.parent().block_id().as_bytes(),
                &retained.binding.parent().height().get().to_be_bytes(),
                retained.speculative_head.block_id().as_bytes(),
                &retained.speculative_head.height().get().to_be_bytes(),
                retained.speculative_head.state_root().as_bytes(),
                retained.speculative_head.commit_id().as_bytes(),
                &retained.source_artifact_checksum,
                &retained.validation_row_checksum,
                &retained.overlay_ref.overlay_checksum(),
            ],
        ));
    }
    let row_parts = row_digests
        .iter()
        .map(|digest| digest.as_slice())
        .collect::<Vec<_>>();
    let prepared_digest = hash_v0(PROCESS2_ACTIVATION_PREPARED_ROW_DOMAIN_V1, &row_parts);
    let (overlay_tag, overlay_block, overlay_parent, overlay_checksum) = selected_overlay
        .map(|overlay| {
            (
                1_u8,
                *overlay.block_id().as_bytes(),
                *overlay.parent_block_id().as_bytes(),
                overlay.overlay_checksum(),
            )
        })
        .unwrap_or((0_u8, [0; 32], [0; 32], [0; 32]));
    let high_qc = safety.high_qc().qc_ref();
    hash_v0(
        PROCESS2_SELECTED_REPLAY_ACTIVATION_DOMAIN_V1,
        &[
            &facts.session_id_v0(),
            &facts.rehydrate_digest_v0(),
            &facts.final_progress_checksum_v0(),
            &facts.application_history_digest_v0(),
            &facts.signer_exact_watermark_v1().scope(),
            &facts.signer_exact_watermark_v1().journal_id(),
            &facts.signer_exact_watermark_v1().sequence().to_be_bytes(),
            &facts.signer_exact_watermark_v1().chain_checksum(),
            &facts.signer_durable_vote_intent_count_v1().to_be_bytes(),
            &facts.signer_durable_timeout_intent_count_v1().to_be_bytes(),
            &facts.signer_signed_vote_intent_count_v1().to_be_bytes(),
            &facts.signer_signed_timeout_intent_count_v1().to_be_bytes(),
            &facts.signer_inventory_digest_v1(),
            &safety.revision().to_be_bytes(),
            high_qc.block_id().as_bytes(),
            &high_qc.height().get().to_be_bytes(),
            &high_qc.view().get().to_be_bytes(),
            committed.block_id().as_bytes(),
            &committed.height().get().to_be_bytes(),
            committed.state_root().as_bytes(),
            committed.commit_id().as_bytes(),
            selected.block_id().as_bytes(),
            &selected.height().get().to_be_bytes(),
            selected.state_root().as_bytes(),
            selected.commit_id().as_bytes(),
            &[overlay_tag],
            &overlay_block,
            &overlay_parent,
            &overlay_checksum,
            &pending_count.to_be_bytes(),
            &prepared_digest,
        ],
    )
}

fn signer_inventory_matches_recovery_facts_v1(
    facts: PocoNodeDeployedLabProcess2RecoveryFactsV0,
    watermark: SignerWatermarkV0,
    inventory: SignerJournalLifetimeInventoryV1,
) -> bool {
    facts.signer_exact_watermark_v1() == watermark
        && facts.signer_durable_vote_intent_count_v1() == inventory.durable_vote_intent_count()
        && facts.signer_durable_timeout_intent_count_v1()
            == inventory.durable_timeout_intent_count()
        && facts.signer_signed_vote_intent_count_v1() == inventory.signed_vote_intent_count()
        && facts.signer_signed_timeout_intent_count_v1() == inventory.signed_timeout_intent_count()
        && facts.signer_inventory_digest_v1() == inventory.inventory_digest()
}

struct Process2HistoryInventoryV0 {
    recovered: BTreeMap<BlockId, RecoveredHistoryKV0>,
    executed: BTreeMap<BlockId, NativeExecutedBlockV0>,
    history_checksums: BTreeMap<BlockId, [u8; 32]>,
    source_artifact_checksums: BTreeMap<BlockId, [u8; 32]>,
    application_history_digest: [u8; 32],
}

enum Process2FrontierV0 {
    Ready(ActiveReplaySessionV0),
    Reserved(ReservedReplayLinkPV0),
    CoreDelivered(CoreDeliveredReplayLinkDV0),
    SafetyClosed(SafetyClosedReplayLinkCV0),
    AliasClosed(AliasClosedReplayLinkKV0),
    Complete(DurableReplayCompleteV0),
    ActivationReady {
        expected_count: u64,
        final_progress: NonZeroDigestV0,
    },
}

impl From<ReplaySessionResumeOutcomeV0> for Process2FrontierV0 {
    fn from(value: ReplaySessionResumeOutcomeV0) -> Self {
        match value {
            ReplaySessionResumeOutcomeV0::Ready(value) => Self::Ready(value),
            ReplaySessionResumeOutcomeV0::Reserved(value) => Self::Reserved(value),
            ReplaySessionResumeOutcomeV0::CoreDelivered(value) => Self::CoreDelivered(value),
            ReplaySessionResumeOutcomeV0::SafetyClosed(value) => Self::SafetyClosed(value),
            ReplaySessionResumeOutcomeV0::AliasClosed(value) => Self::AliasClosed(value),
            ReplaySessionResumeOutcomeV0::DurableReplayComplete(value) => Self::Complete(value),
        }
    }
}

fn frontier_requires_obligation_persistence_v0(
    frontier: &Process2FrontierV0,
    cursor: u64,
) -> Result<bool, PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let (observed_cursor, required) = match frontier {
        Process2FrontierV0::Ready(session) => (session.next_cursor_v0(), true),
        Process2FrontierV0::Reserved(link) => (link.cursor_v0(), true),
        // A durable replay D can only be minted after Core's obligation was
        // persisted and acknowledged.  Replaying that process-local Core
        // edge must therefore acknowledge the reconstructed obligation
        // without rewriting it; Safety may already be either the exact
        // obligation predecessor of C or the exact C target after a crash
        // between Safety persistence and sidecar closure.
        Process2FrontierV0::CoreDelivered(link) => (link.cursor_v0(), false),
        Process2FrontierV0::SafetyClosed(link) => (link.cursor_v0(), false),
        Process2FrontierV0::AliasClosed(link) => (link.cursor_v0(), false),
        Process2FrontierV0::Complete(_) | Process2FrontierV0::ActivationReady { .. } => {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "replay.frontier_complete_early",
                "durable replay completed before Core replay reached the same cursor",
            ));
        }
    };
    if observed_cursor != cursor {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.frontier_cursor",
            "durable replay frontier differs from the Core replay cursor",
        ));
    }
    Ok(required)
}

struct ExactAnchorOrdinaryReconcilerV0 {
    safety: SafetyState,
    child: trnm_consensus_types::SignedProposalV0,
    grandchild: trnm_consensus_types::SignedProposalV0,
    calls: usize,
}

impl StateSyncAnchorOrdinaryRecoveryReconcilerV0 for ExactAnchorOrdinaryReconcilerV0 {
    fn reconcile_state_sync_anchor_ordinary_v0(
        &mut self,
        challenge: &StateSyncAnchorOrdinaryRecoveryChallengeV0,
    ) -> bool {
        self.calls = self.calls.saturating_add(1);
        challenge.safety_state() == &self.safety
            && challenge.child() == &self.child
            && challenge.grandchild() == &self.grandchild
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Process2CrashHookV0 {
    SessionOpened,
    LinkReserved,
    CoreDelivered,
    SafetyPersisted,
    SafetyClosed,
    AliasClosed,
    ExternalCheckpointAdvanced,
    Checkpointed,
    ActivationReadyCommitted,
}

/// Opens or resumes the exact process-2 sidecar and returns only after every
/// signed high-QC-prefix cursor is checkpoint-complete and Core has repeated
/// the same replay into its inert bulk-rehydrated owner.
pub fn recover_deployed_lab_process2_v0<W, F, E>(
    authority_root: impl AsRef<Path>,
    core_config: CoreConfig,
    application_config: NativeApplicationConfigV0,
    entries: Vec<PocoNodeDeployedLabSignedReplayEntryV0>,
    open_watermark: F,
) -> Result<PocoNodeDeployedLabProcess2RecoveryOwnerV0<W>, PocoNodeDeployedLabProcess2RecoveryErrorV0>
where
    W: ExternalMonotonicWatermarkV0,
    F: FnOnce(&Path) -> Result<W, E>,
    E: fmt::Debug,
{
    recover_deployed_lab_process2_inner_v0(
        authority_root,
        core_config,
        application_config,
        entries,
        open_watermark,
        None,
    )
}

fn recover_deployed_lab_process2_inner_v0<W, F, E>(
    authority_root: impl AsRef<Path>,
    core_config: CoreConfig,
    application_config: NativeApplicationConfigV0,
    entries: Vec<PocoNodeDeployedLabSignedReplayEntryV0>,
    open_watermark: F,
    crash_hook: Option<Process2CrashHookV0>,
) -> Result<PocoNodeDeployedLabProcess2RecoveryOwnerV0<W>, PocoNodeDeployedLabProcess2RecoveryErrorV0>
where
    W: ExternalMonotonicWatermarkV0,
    F: FnOnce(&Path) -> Result<W, E>,
    E: fmt::Debug,
{
    validate_config_join_v0(&core_config, &application_config)?;
    let paths = existing_paths_v0(authority_root.as_ref()).map_err(|error| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug("filesystem.paths", error)
    })?;
    let limits = process2_try!(
        "safety.record_limits",
        trnm_consensus_core::SafetyStateRecordLimitsV0::new(
            MAXIMUM_RECORD_BYTES_V0,
            MAXIMUM_BLOB_BYTES_V0,
        )
    );
    let safety_profile = process2_try!(
        "safety.profile",
        SafetyStateStoreProfileV0::new(
            core_config.clone(),
            STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
            limits,
            MAXIMUM_SAFETY_DATABASE_BYTES_V0,
        )
    );
    let mut safety_store = process2_try!(
        "safety.open_existing",
        SqliteSafetyStateStoreV0::open_existing(
            &paths.target_safety,
            safety_profile,
            StrictEd25519Verifier,
        )
    );
    let current_safety_head = process2_try!("safety.head", safety_store.head());
    let current_safety = current_safety_head.state().clone();
    if current_safety.pending_sign().is_some() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.pending_sign_requires_network_replay",
            "process2 cannot clear or rebroadcast a durable pending signature",
        ));
    }
    validate_process2_safety_shape_v0(&current_safety)?;

    let anchor = current_safety.state_sync_anchor().ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.anchor",
            "process2 requires the permanent deployed h1 anchor",
        )
    })?;
    let child = reconstruct_empty_anchor_successor_v0(
        anchor.proof().child(),
        core_config.validator_set(),
        core_config.consensus_parameters(),
        anchor.proof().finalized_block().header().timestamp_ms(),
    )
    .map_err(|error| PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug("core.h2", error))?;
    let grandchild = reconstruct_empty_anchor_successor_v0(
        anchor.proof().grandchild(),
        core_config.validator_set(),
        core_config.consensus_parameters(),
        anchor.proof().child().header().timestamp_ms(),
    )
    .map_err(|error| PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug("core.h3", error))?;

    let application = process2_try!(
        "application.open_existing",
        DurableNativeApplicationV0::open(&paths.application, application_config)
    );
    let committed = process2_try!(
        "application.committed_head",
        application.confirmed_committed_head_v0()
    );
    if committed.block_id().as_bytes() != current_safety.application_applied().block_id().as_bytes()
        || committed.height().get() != current_safety.application_applied().height().get()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "application.applied_join",
            "native committed head differs from Safety application_applied",
        ));
    }

    let (validation_scope, validation_owner) =
        deployed_validation_identity_v0(&core_config, &application)?;
    let mut validation_store = process2_try!(
        "validation.open_existing",
        SqliteProposalValidationStoreV0::open(
            &paths.validation,
            validation_scope,
            MINIMUM_TAKEOVER_VALIDATION_SEQUENCE_V0,
        )
    );
    let terminal_audit = process2_try!(
        "validation.terminal_audit",
        validation_store.confirm_terminal_k_audit_v0()
    );
    if !terminal_audit.belongs_to_store_at_path_v0(&validation_store, &paths.validation)
        || terminal_audit.scope_v0() != validation_scope
        || terminal_audit.owner_id_v0() != validation_owner
        || terminal_audit.store_id_v0() == [0; 32]
        || terminal_audit.store_sequence_v0()
            != terminal_audit
                .terminal_row_count_v0()
                .checked_mul(3)
                .ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "validation.sequence",
                        "terminal inventory sequence overflowed",
                    )
                })?
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "validation.owner_join",
            "canonical terminal K inventory differs from the deployed owner",
        ));
    }
    let canonical_store_sequence = terminal_audit.store_sequence_v0();
    let canonical_terminal_digest = *terminal_audit.terminal_audit_digest_v0().as_bytes();
    let history = build_history_inventory_v0(
        &core_config,
        &paths,
        &application,
        &mut validation_store,
        validation_scope,
        validation_owner,
        &terminal_audit,
    )?;

    let high_qc_path = reconstruct_high_qc_path_v0(
        current_safety.high_qc().qc_ref(),
        current_safety.locked_qc().qc_ref(),
        current_safety.finalized(),
        anchor.proof().finalized_block().header().id(),
        anchor.proof().finalized_block().header().view(),
        anchor.proof().grandchild().header().id(),
        &committed,
        &history.recovered,
    )
    .map_err(|error| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug("replay.high_qc_path", error)
    })?;
    authenticate_archive_v0(
        &core_config,
        current_safety.high_qc().qc_ref(),
        &high_qc_path,
        &history,
        &entries,
    )?;
    if entries.is_empty() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.not_required",
            "process2 requires at least one ordinary post-h3 replay link",
        ));
    }

    let (tail_count, tail_digest) =
        exact_unconfirmed_tail_v0(&high_qc_path, &history.history_checksums)?;
    let expected_count = u64::try_from(entries.len()).map_err(|_| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.count",
            "replay entry count does not fit u64",
        )
    })?;
    let archive_sequence = expected_count.checked_mul(2).ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.archive_sequence",
            "archive sequence overflowed",
        )
    })?;

    let presence = process2_try!(
        "validation.replay_presence",
        validation_store.replay_session_presence_v0()
    );
    let existing_inventory = match presence {
        ReplaySessionPresenceV0::None => None,
        _ => Some(process2_try!(
            "validation.replay_inventory",
            validation_store.confirm_replay_inventory_v0()
        )),
    };
    if existing_inventory.is_none() {
        let replay_blocks = entries
            .iter()
            .map(|entry| entry.proposal_v0().block().id())
            .collect::<BTreeSet<_>>();
        let lost_sidecar_is_visible =
            current_safety
                .payload_validation_obligations()
                .iter()
                .any(|obligation| {
                    obligation.route() == PayloadValidationRouteV0::Synced
                        && replay_blocks.contains(&obligation.id().block_id())
                })
                || current_safety
                    .payload_validation_completions()
                    .iter()
                    .any(|completion| {
                        completion.route() == PayloadValidationRouteV0::Synced
                            && replay_blocks.contains(&completion.id().block_id())
                    });
        if lost_sidecar_is_visible {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "validation.one_sided_sidecar_rollback",
                "Safety retains ordinary Synced replay facts but the replay sidecar is absent",
            ));
        }
    }
    let initial_revision = existing_inventory
        .as_ref()
        .map(|inventory| inventory.session_v0().initial_safety_revision_v0())
        .unwrap_or(current_safety.revision());
    let initial_safety =
        reconstruct_initial_safety_v0(&core_config, &current_safety, initial_revision, &entries)?;
    let archive_context_digest = archive_context_digest_v0(&initial_safety, &high_qc_path);
    let archive_record_digest = archive_record_digest_v0(&entries)?;
    let recovery_challenge_digest = recovery_challenge_digest_v0(
        &initial_safety,
        archive_context_digest,
        archive_record_digest,
        tail_count,
        tail_digest,
    );
    let initial_state_checksum = safety_state_checksum_v0(&core_config, limits, &initial_safety)?;
    let current_safety_facts = process2_try!(
        "safety.current_facts",
        safety_store.confirm_node_checkpoint_head_exact_v0(&current_safety)
    );

    let watermark = process2_try!("watermark.open", open_watermark(&paths.watermark));
    let signer_profile = process2_try!(
        "signer.profile",
        SignerJournalProfileV0::new(
            core_config.validator_set().clone(),
            core_config.local_validator(),
            SIGNER_JOURNAL_PROFILE_REF_V0,
            derive_signer_watermark_scope_v0(&core_config),
            MAXIMUM_SIGNER_INTENTS_V0,
            MAXIMUM_SIGNER_INTENT_BYTES_V0,
            MAXIMUM_SIGNER_DATABASE_BYTES_V0,
        )
    );
    let mut signer = process2_try!(
        "signer.pin_existing",
        SqliteSignerJournalV0::pin_existing_v0(&paths.signer, signer_profile, watermark)
    );
    let signer_facts = process2_try!(
        "signer.confirm_exact",
        signer.confirm_node_checkpoint_head_exact_v0()
    );
    if signer_facts.pending_intent().is_some()
        || !signer_facts.belongs_to_pinned_journal_at_path_v0(&signer, &paths.signer)
        || signer_facts
            .capacity()
            .maximum_safety_revision()
            .is_some_and(|revision| revision > current_safety.revision())
        || signer_facts.capacity().maximum_vote_view()
            != current_safety.last_voted_view().map(|view| view.get())
        || signer_facts.capacity().maximum_timeout_view()
            != current_safety.last_timeout_view().map(|view| view.get())
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "signer.clean_cut",
            "signer journal differs from the clean Safety cut",
        ));
    }
    let signer_inventory = clean_signer_lifetime_inventory_v1(&signer_facts).ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "signer.lifetime_inventory",
            "signer Vote/TimeoutVote lifecycles are not individually clean",
        )
    })?;

    let mut checkpoint_store = process2_try!(
        "checkpoint.open_existing",
        SqliteExternalNodeCheckpointStoreV0::open_existing(&paths.checkpoint)
    );
    let current_checkpoint = process2_try!(
        "checkpoint.load",
        checkpoint_store.load(signer_facts.exact_watermark().scope())
    )
    .ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "checkpoint.missing",
            "whole-node checkpoint is absent",
        )
    })?;
    let checkpoint_profile_ref = hash_v0(
        PROCESS2_CHECKPOINT_PROFILE_DOMAIN_V0,
        &[
            &current_safety_facts.core_config_ref_v0(),
            validation_scope.as_bytes(),
            &signer_facts.profile_checksum(),
        ],
    );
    validate_current_checkpoint_for_replay_v0(
        current_checkpoint,
        existing_inventory.as_ref(),
        checkpoint_profile_ref,
        &current_safety_facts,
        &signer_facts,
        &application,
        &committed,
        &validation_store,
        &history.recovered,
    )?;
    let session_facts = existing_inventory
        .as_ref()
        .map(ConfirmedReplayInventoryV0::session_v0);
    let (
        initial_chain_checksum,
        initial_checkpoint_scope,
        initial_checkpoint_profile_ref,
        initial_checkpoint_generation,
        initial_checkpoint_checksum,
    ) = if let Some(session) = session_facts {
        (
            session.initial_safety_chain_checksum_v0(),
            session.initial_checkpoint_scope_v0(),
            session.initial_checkpoint_profile_ref_v0(),
            session.initial_checkpoint_generation_v0(),
            session.initial_checkpoint_checksum_v0(),
        )
    } else {
        (
            current_safety_facts.chain_checksum_v0(),
            current_checkpoint.scope(),
            checkpoint_profile_ref,
            current_checkpoint.generation(),
            current_checkpoint.checkpoint_checksum(),
        )
    };
    if initial_checkpoint_scope != signer_facts.exact_watermark().scope()
        || initial_checkpoint_profile_ref != checkpoint_profile_ref
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "checkpoint.initial_identity",
            "replay session changed the independently derived checkpoint identity",
        ));
    }
    validate_existing_session_facts_v0(
        session_facts,
        current_safety_facts.core_config_ref_v0(),
        validation_scope,
        validation_store.store_id_v0(),
        recovery_challenge_digest,
        archive_context_digest,
        archive_sequence,
        archive_record_digest,
        expected_count,
        canonical_store_sequence,
        canonical_terminal_digest,
        history.application_history_digest,
        initial_revision,
        initial_state_checksum,
        initial_chain_checksum,
        initial_checkpoint_scope,
        initial_checkpoint_profile_ref,
        initial_checkpoint_generation,
        initial_checkpoint_checksum,
        signer_facts.exact_watermark(),
    )?;
    let replay_plan = process2_try!(
        "validation.replay_plan",
        ReplaySessionPlanV0::new(
            nonzero_v0(current_safety_facts.core_config_ref_v0())?,
            nonzero_v0(recovery_challenge_digest)?,
            nonzero_v0(archive_context_digest)?,
            archive_sequence,
            nonzero_v0(archive_record_digest)?,
            expected_count,
            nonzero_v0(history.application_history_digest)?,
            initial_revision,
            nonzero_v0(initial_state_checksum)?,
            nonzero_v0(initial_chain_checksum)?,
            nonzero_v0(initial_checkpoint_scope)?,
            nonzero_v0(initial_checkpoint_profile_ref)?,
            initial_checkpoint_generation,
            nonzero_v0(initial_checkpoint_checksum)?,
            nonzero_v0(signer_facts.exact_watermark().scope())?,
            nonzero_v0(signer_facts.exact_watermark().journal_id())?,
            signer_facts.exact_watermark().sequence(),
            nonzero_v0(signer_facts.exact_watermark().chain_checksum())?,
        )
    );

    let (mut frontier, already_checkpointed) = open_or_resume_session_v0(
        &mut validation_store,
        &paths.application,
        &paths.validation,
        replay_plan,
        existing_inventory.as_ref(),
    )?;
    trigger_test_crash_v0(crash_hook, Process2CrashHookV0::SessionOpened)?;
    let (mut core, child, grandchild) =
        recover_initial_replay_core_v0(&core_config, initial_safety.clone(), child, grandchild)?;
    process2_try!(
        "safety.bind_core",
        safety_store.bind_core_v0(core.safety_state_persistence_binding_v0())
    );
    let seal = process2_try!(
        "core.application_seal",
        core.issue_application_seal_authority_v0()
    );

    for (index, entry) in entries.iter().enumerate() {
        let cursor = u64::try_from(index).map_err(|_| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "replay.cursor",
                "cursor does not fit u64",
            )
        })?;
        let source = history
            .recovered
            .get(&entry.proposal_v0().block().id())
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "replay.source",
                    "authenticated proposal lacks canonical source K",
                )
            })?;
        let before = core.safety_state().clone();
        let effects = process2_try!(
            "core.synced_proposal",
            core.step(
                Input::SyncedProposal(Box::new(entry.proposal_v0().clone())),
                &StrictEd25519Verifier,
            )
        );
        let obligation = exact_persistence_effect_v0(effects, "core.synced_obligation")?;
        if cursor >= already_checkpointed
            && frontier_requires_obligation_persistence_v0(&frontier, cursor)?
        {
            persist_expected_request_v0(
                &mut safety_store,
                &before,
                &obligation,
                &SafetyTransitionContextV0::ordinary(),
            )?;
        }
        let request_effects = process2_try!(
            "core.synced_obligation_ack",
            core.step(
                Input::StorageAck {
                    barrier: obligation.barrier(),
                },
                &StrictEd25519Verifier,
            )
        );
        let request = match request_effects.as_slice() {
            [Effect::ValidateSyncedPayload(request)] => request.clone(),
            _ => {
                return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "core.synced_request",
                    "obligation ack did not emit exactly one Synced validation request",
                ));
            }
        };
        let claimed = request.try_claim().map_err(|_| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "core.request_claim",
                "exact Synced request was already claimed",
            )
        })?;
        let (route, validation_id, block, parent, permit) = claimed.into_parts();
        if route != PayloadValidationRouteV0::Synced
            || block != *entry.proposal_v0().block()
            || validation_id.block_id() != block.id()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "core.request_binding",
                "Core request differs from the authenticated replay entry",
            ));
        }
        let target_binding = replay_target_binding_v0(source.binding.clone(), validation_id)?;
        validate_core_parent_binding_v0(&target_binding, &parent)?;

        let executed = history
            .executed
            .get(&block.id())
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "application.executed",
                    "source application artifact is absent",
                )
            })?
            .clone();
        let confirmed_p = process2_try!(
            "application.confirm_p",
            application.confirm_durable_p_v0(&executed)
        );
        let commitments = validated_commitments_from_durable_execution_v0(
            &block,
            &executed,
            core_config.consensus_parameters(),
            core_config.validator_set(),
            &StrictEd25519Verifier,
        )
        .map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug("application.commitments", error)
        })?;
        let artifact_ref = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(
                block.id(),
                block.header().parent_id(),
                confirmed_p.overlay_checksum_v0(),
            ),
            confirmed_p.source_artifact_checksum_v0(),
        );
        let sealed = seal.seal_after_application_store_commit_v0(permit, commitments, artifact_ref);
        let completion_predecessor = core.safety_state().clone();
        let accepted = process2_try!(
            "core.synced_valid",
            core.step_application_sealed_valid_to_delivery_v0(&sealed, &StrictEd25519Verifier)
        );

        if cursor < already_checkpointed {
            let inventory = existing_inventory.as_ref().ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "replay.prior_inventory",
                    "checkpointed cursor lacks its owner-affined inventory",
                )
            })?;
            verify_checkpointed_link_against_live_v0(
                &mut validation_store,
                inventory,
                cursor,
                source,
                &target_binding,
                &accepted,
                confirmed_p.source_artifact_checksum_v0(),
                history.history_checksums[&block.id()],
                &core_config,
                limits,
            )?;
            let effects = process2_try!(
                "core.prior_completion_ack",
                core.step(
                    Input::StorageAck {
                        barrier: accepted.barrier_v0(),
                    },
                    &StrictEd25519Verifier,
                )
            );
            require_no_authority_effects_v0(&effects, "core.prior_completion_ack")?;
            continue;
        }

        frontier = drive_live_cursor_v0(
            frontier,
            cursor,
            replay_plan,
            source,
            &target_binding,
            validation_owner,
            history.history_checksums[&block.id()],
            &executed,
            &accepted,
            &completion_predecessor,
            &mut safety_store,
            &paths,
            &application,
            &mut validation_store,
            &mut checkpoint_store,
            &mut signer,
            checkpoint_profile_ref,
            history.application_history_digest,
            crash_hook,
        )?;
        let effects = process2_try!(
            "core.completion_ack",
            core.step(
                Input::StorageAck {
                    barrier: accepted.barrier_v0(),
                },
                &StrictEd25519Verifier,
            )
        );
        require_no_authority_effects_v0(&effects, "core.completion_ack")?;
    }
    let (complete_expected_count, final_progress) = match frontier {
        Process2FrontierV0::Complete(value) => (
            value.expected_count_v0(),
            value.final_progress_checksum_v0(),
        ),
        Process2FrontierV0::ActivationReady {
            expected_count,
            final_progress,
        } => (expected_count, final_progress),
        _ => {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "replay.incomplete",
                "all authenticated entries did not reach durable checkpoint completion",
            ));
        }
    };
    if complete_expected_count != expected_count {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.complete_count",
            "durable replay completion count differs",
        ));
    }

    let final_safety_head = process2_try!("safety.final_head", safety_store.head());
    if final_safety_head.state() != core.safety_state() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.final_core_join",
            "final Safety head differs from the replayed Core",
        ));
    }
    let final_safety = final_safety_head.state().clone();
    let final_safety_facts = process2_try!(
        "safety.final_facts",
        safety_store.confirm_node_checkpoint_head_exact_v0(&final_safety)
    );
    let final_inventory = process2_try!(
        "validation.final_inventory",
        validation_store.confirm_replay_inventory_v0()
    );
    verify_complete_inventory_v0(
        &final_inventory,
        replay_plan,
        final_progress,
        expected_count,
        tail_count,
        tail_digest,
        &high_qc_path,
        &history.history_checksums,
    )?;
    let final_checkpoint = process2_try!(
        "checkpoint.final_load",
        checkpoint_store.load(initial_checkpoint_scope)
    )
    .ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "checkpoint.final_missing",
            "terminal replay checkpoint is absent",
        )
    })?;
    let final_signer_facts = process2_try!(
        "signer.final_facts",
        signer.confirm_node_checkpoint_head_exact_v0()
    );
    if !final_signer_facts.belongs_to_pinned_journal_at_path_v0(&signer, &paths.signer) {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "signer.final_owner",
            "final signer inventory lost its exact pinned owner affinity",
        ));
    }
    let final_signer_inventory = clean_signer_lifetime_inventory_v1(&final_signer_facts)
        .ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "signer.final_inventory",
                "final signer Vote/TimeoutVote lifecycles are not individually clean",
            )
        })?;
    if final_signer_facts.journal_id() != signer_facts.journal_id()
        || final_signer_facts.profile_checksum() != signer_facts.profile_checksum()
        || final_signer_facts.identity() != signer_facts.identity()
        || final_signer_facts.exact_watermark() != signer_facts.exact_watermark()
        || final_signer_facts.capacity() != signer_facts.capacity()
        || final_signer_inventory != signer_inventory
        || final_signer_facts.tail() != signer_facts.tail()
        || final_signer_facts.pending_intent() != signer_facts.pending_intent()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "signer.replay_stability",
            "process2 replay changed the exact signer head or lifetime inventory",
        ));
    }
    validate_checkpoint_join_v0(
        final_checkpoint,
        &final_safety_facts,
        &final_signer_facts,
        &application,
        &committed,
        &validation_store,
        &history.recovered,
    )
    .map_err(|error| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug("checkpoint.final_join", error)
    })?;

    let final_history_rows =
        refresh_all_history_rows_v0(&application, &paths.application, &history)?;
    let (core_plan, core_entries) =
        core_rehydrate_material_v0(&final_inventory, &entries, &history, final_progress)?;
    let successor_bundle = process2_try!(
        "core.final_successor_bundle",
        Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            &core_config,
            &final_safety,
            child.clone(),
            grandchild.clone(),
            &StrictEd25519Verifier,
        )
    );
    let recovery_session = process2_try!(
        "core.final_recovery",
        Core::begin_state_sync_anchor_ordinary_recovery_v0(
            core_config.clone(),
            final_safety.clone(),
            successor_bundle,
            &StrictEd25519Verifier,
        )
    );
    let mut anchor_reconciler = ExactAnchorOrdinaryReconcilerV0 {
        safety: final_safety.clone(),
        child,
        grandchild,
        calls: 0,
    };
    let rehydrate_session = process2_try!(
        "core.bulk_rehydrate",
        recovery_session.begin_checkpointed_ordinary_rehydrate_v0(
            &mut anchor_reconciler,
            core_plan,
            core_entries.clone(),
            &StrictEd25519Verifier,
        )
    );
    if anchor_reconciler.calls != 1 {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "core.anchor_reconciler_calls",
            "anchor reconciler was not called exactly once",
        ));
    }
    let expected_rehydrate_digest = rehydrate_session.challenge_v0().rehydrate_digest_v0();
    let mut final_reconciler = ExactProcess2RehydrateReconcilerV0 {
        expected_safety: &final_safety,
        expected_plan: core_plan,
        expected_entries: &core_entries,
        inventory: &final_inventory,
        validation_store: &validation_store,
        validation_path: &paths.validation,
        application: &application,
        application_path: &paths.application,
        application_history_rows: &final_history_rows,
        calls: 0,
    };
    let inert_core = process2_try!(
        "core.final_owner",
        rehydrate_session.reconcile_checkpointed_links_v0(&mut final_reconciler)
    );
    if final_reconciler.calls != 1
        || inert_core.facts_v0().rehydrate_digest_v0() != expected_rehydrate_digest
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "core.final_reconciler_calls",
            "checkpointed-link reconciler did not join exactly once",
        ));
    }

    let facts = PocoNodeDeployedLabProcess2RecoveryFactsV0 {
        session_id: final_inventory.session_v0().session_id_v0(),
        replayed_link_count: expected_count,
        final_safety_revision: final_safety.revision(),
        final_safety_chain_checksum: final_safety_facts.chain_checksum_v0(),
        final_checkpoint_generation: final_checkpoint.generation(),
        final_checkpoint_checksum: final_checkpoint.checkpoint_checksum(),
        signer_exact_watermark: final_signer_facts.exact_watermark(),
        signer_durable_vote_intent_count: final_signer_inventory.durable_vote_intent_count(),
        signer_durable_timeout_intent_count: final_signer_inventory.durable_timeout_intent_count(),
        signer_signed_vote_intent_count: final_signer_inventory.signed_vote_intent_count(),
        signer_signed_timeout_intent_count: final_signer_inventory.signed_timeout_intent_count(),
        signer_inventory_digest: final_signer_inventory.inventory_digest(),
        final_progress_checksum: *final_progress.as_bytes(),
        rehydrate_digest: inert_core.facts_v0().rehydrate_digest_v0(),
        application_history_digest: history.application_history_digest,
        unconfirmed_speculative_tail_count: tail_count,
        unconfirmed_speculative_tail_digest: tail_digest,
    };
    Ok(PocoNodeDeployedLabProcess2RecoveryOwnerV0 {
        facts,
        core_config,
        paths,
        core: inert_core,
        safety_store,
        application,
        signer,
        restart_checkpoint: current_checkpoint,
        checkpoint_store,
        validation_store,
        replay_inventory: final_inventory,
        application_history_rows: final_history_rows,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_current_checkpoint_for_replay_v0(
    checkpoint: ExternalNodeCheckpointV0,
    inventory: Option<&ConfirmedReplayInventoryV0>,
    checkpoint_profile_ref: [u8; 32],
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
    application: &DurableNativeApplicationV0,
    committed: &ApplicationHeadV0,
    validation_store: &SqliteProposalValidationStoreV0,
    history: &BTreeMap<BlockId, RecoveredHistoryKV0>,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let Some(inventory) = inventory else {
        return validate_checkpoint_join_v0(
            checkpoint,
            safety,
            signer,
            application,
            committed,
            validation_store,
            history,
        )
        .map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug("checkpoint.initial_join", error)
        });
    };
    let session = inventory.session_v0();
    if session.is_durable_complete_v0() || session.is_activation_ready_v0() {
        return validate_checkpoint_join_v0(
            checkpoint,
            safety,
            signer,
            application,
            committed,
            validation_store,
            history,
        )
        .map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug(
                "checkpoint.complete_join",
                error,
            )
        });
    }

    let (expected_generation, expected_checksum, expected_safety_revision, expected_record) =
        if session.next_cursor_v0() == 0 {
            (
                session.initial_checkpoint_generation_v0(),
                session.initial_checkpoint_checksum_v0(),
                session.initial_safety_revision_v0(),
                session.initial_safety_state_checksum_v0(),
            )
        } else {
            let prior_cursor = session.next_cursor_v0().checked_sub(1).ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "checkpoint.prior_cursor",
                    "active replay cursor underflowed",
                )
            })?;
            let prior = inventory
                .links_v0()
                .iter()
                .find(|link| link.cursor_v0() == prior_cursor)
                .ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "checkpoint.prior_link",
                        "active replay session lacks its checkpointed predecessor link",
                    )
                })?;
            if prior.stage_v0() != DurableReplayLinkStageV0::Checkpointed {
                return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "checkpoint.prior_stage",
                    "active replay predecessor is not checkpoint-complete",
                ));
            }
            (
                prior.checkpoint_generation_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "checkpoint.prior_generation",
                        "checkpointed predecessor lacks its generation",
                    )
                })?,
                prior.checkpoint_checksum_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "checkpoint.prior_checksum",
                        "checkpointed predecessor lacks its checksum",
                    )
                })?,
                prior.safety_revision_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "checkpoint.prior_safety",
                        "checkpointed predecessor lacks its Safety revision",
                    )
                })?,
                prior.safety_record_digest_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "checkpoint.prior_record",
                        "checkpointed predecessor lacks its Safety record digest",
                    )
                })?,
            )
        };
    let safety_span = safety
        .revision_v0()
        .checked_sub(expected_safety_revision)
        .ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "checkpoint.safety_rollback",
                "durable Safety is behind the replay checkpoint predecessor",
            )
        })?;
    let active_link = inventory
        .links_v0()
        .iter()
        .find(|link| link.cursor_v0() == session.next_cursor_v0());
    let active_stage = active_link.map(ReplayLinkFactsV0::stage_v0);
    let span_is_exact = match active_stage {
        None => safety_span <= 1,
        Some(DurableReplayLinkStageV0::Reserved) => safety_span == 1,
        Some(DurableReplayLinkStageV0::CoreDelivered) => (1..=2).contains(&safety_span),
        Some(DurableReplayLinkStageV0::SafetyClosed)
        | Some(DurableReplayLinkStageV0::AliasClosed) => safety_span == 2,
        Some(DurableReplayLinkStageV0::Checkpointed) => false,
    };
    let fields = checkpoint.fields();
    let checkpoint_ahead_after_alias_cas = active_stage
        == Some(DurableReplayLinkStageV0::AliasClosed)
        && checkpoint.scope() == session.initial_checkpoint_scope_v0()
        && checkpoint.generation()
            == expected_generation.checked_add(1).ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "checkpoint.active_successor_generation",
                    "active replay checkpoint generation overflowed",
                )
            })?
        && checkpoint.predecessor_checksum() == expected_checksum
        && fields.safety_revision == safety.revision_v0()
        && fields.safety_state_record_checksum == safety.state_record_checksum_v0()
        && fields.safety_record_chain_checksum == safety.chain_checksum_v0()
        && fields.signer_journal_id == signer.journal_id()
        && fields.signer_profile_checksum == signer.profile_checksum()
        && fields.signer_exact_watermark == signer.exact_watermark();
    if checkpoint_ahead_after_alias_cas {
        return Ok(());
    }
    if checkpoint.scope() != session.initial_checkpoint_scope_v0()
        || checkpoint_profile_ref != session.initial_checkpoint_profile_ref_v0()
        || checkpoint.generation() != expected_generation
        || checkpoint.checkpoint_checksum() != expected_checksum
        || fields.safety_revision != expected_safety_revision
        || fields.safety_state_record_checksum != expected_record
        || fields.scope != signer.exact_watermark().scope()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.signer_exact_watermark != signer.exact_watermark()
        || !span_is_exact
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "checkpoint.active_predecessor_join",
            "active replay checkpoint is not the exact sidecar predecessor",
        ));
    }
    Ok(())
}

fn validate_config_join_v0(
    core: &CoreConfig,
    application: &NativeApplicationConfigV0,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if core.authenticated_genesis_application_parent_v0().is_some()
        || application.validator_set_v0() != core.validator_set()
        || application.consensus_parameters_v0() != core.consensus_parameters()
        || application.chain_id_v0() != core.validator_set().chain_id().as_str()
        || application.genesis_hash_v0() != *core.validator_set().genesis_hash().as_bytes()
        || application.initial_block_id_v0() != *core.genesis_block_id().as_bytes()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "context",
            "Core and native application configurations differ",
        ));
    }
    Ok(())
}

fn validate_process2_safety_shape_v0(
    safety: &SafetyState,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if safety.revision() <= 5
        || safety.state_sync_anchor().is_none()
        || safety.safety_halt().is_some()
        || safety.pending_finalize().is_some()
        || safety.pending_finalization().is_some()
        || safety.pending_tc_high_qc_sync().is_some()
        || safety.pending_standalone_qc_sync().is_some()
        || !safety.finalization_queue().is_empty()
        || safety.finalized() != safety.application_applied()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.clean_process2_cut",
            "process2 requires a promoted, finalization-clean, replay-fenced cut",
        ));
    }
    Ok(())
}

fn deployed_validation_identity_v0(
    core: &CoreConfig,
    application: &DurableNativeApplicationV0,
) -> Result<
    (ProposalValidationStoreScopeV0, ProposalValidationOwnerIdV0),
    PocoNodeDeployedLabProcess2RecoveryErrorV0,
> {
    let chain_facts = application.config_v0().chain_genesis_facts_v0();
    let scope = hash_v0(
        PROPOSAL_SCOPE_DOMAIN_V0,
        &[
            core.validator_set().id().as_bytes(),
            core.local_validator().as_bytes(),
        ],
    );
    let owner = hash_v0(
        PROPOSAL_OWNER_DOMAIN_V0,
        &[
            &chain_facts.chain_descriptor_hash_v0(),
            core.local_validator().as_bytes(),
        ],
    );
    Ok((
        process2_try!(
            "validation.scope",
            ProposalValidationStoreScopeV0::new(scope)
        ),
        process2_try!("validation.owner", ProposalValidationOwnerIdV0::new(owner)),
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_history_inventory_v0(
    core: &CoreConfig,
    paths: &AuthorityPathsV0,
    application: &DurableNativeApplicationV0,
    validation_store: &mut SqliteProposalValidationStoreV0,
    validation_scope: ProposalValidationStoreScopeV0,
    validation_owner: ProposalValidationOwnerIdV0,
    terminal_audit: &ConfirmedProposalValidationTerminalAuditV0,
) -> Result<Process2HistoryInventoryV0, PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let mut recovered = BTreeMap::new();
    let mut executed_by_block = BTreeMap::new();
    let mut history_checksums = BTreeMap::new();
    let mut source_artifact_checksums = BTreeMap::new();
    let mut row_digests = Vec::new();
    for binding in terminal_audit.terminal_bindings_v0() {
        validate_binding_context_v0(binding, core).map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::from_debug(
                "validation.binding_context",
                error,
            )
        })?;
        let row = process2_try!(
            "validation.source_k",
            validation_store.confirm_proposal_validation_checkpoint_facts_exact_v0(binding)
        );
        let executed = process2_try!(
            "validation.source_artifact",
            validation_store.read_artifact_exact_v0(binding)
        );
        let history = process2_try!(
            "application.history",
            application.confirm_durable_execution_history_row_v0(&executed)
        );
        let parent = process2_try!("application.history_parent", history.parent_head_v0());
        let target = process2_try!("application.history_target", history.target_head_v0());
        if row.binding_v0() != binding
            || row.scope_v0() != validation_scope
            || row.store_id_v0() != validation_store.store_id_v0()
            || row.owner_id_v0() != validation_owner
            || row.store_sequence_v0() != terminal_audit.store_sequence_v0()
            || !row.belongs_to_store_at_path_v0(validation_store, &paths.validation)
            || !history.belongs_to_application_at_path_v0(application, &paths.application)
            || &parent != binding.parent()
            || target.block_id() != binding.block_id()
            || target.height() != binding.height()
            || target.state_root() != binding.commitments().post_state_root()
            || executed.request().block_id() != binding.block_id()
            || executed.request().expected() != binding.commitments()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "application.pk_join",
                "terminal K differs from its fresh native application history row",
            ));
        }
        let block_id = BlockId::new(*binding.block_id().as_bytes());
        let history_checksum = history_row_digest_v0(binding, &history)?;
        let source_artifact_checksum = history.artifact_digest_v0();
        row_digests.push(history_checksum);
        history_checksums.insert(block_id, history_checksum);
        source_artifact_checksums.insert(block_id, source_artifact_checksum);
        executed_by_block.insert(block_id, executed);
        if recovered
            .insert(
                block_id,
                RecoveredHistoryKV0 {
                    binding: binding.clone(),
                    application_head: target,
                    validation_row_checksum: *row.row_checksum_v0().as_bytes(),
                    status: history.status_v0(),
                    history_row: history,
                },
            )
            .is_some()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "application.duplicate_history",
                "terminal inventory contains duplicate block ids",
            ));
        }
    }
    row_digests.sort_unstable();
    let parts = row_digests
        .iter()
        .map(|digest| digest.as_slice())
        .collect::<Vec<_>>();
    let application_history_digest = hash_v0(PROCESS2_HISTORY_INVENTORY_DOMAIN_V0, &parts);
    Ok(Process2HistoryInventoryV0 {
        recovered,
        executed: executed_by_block,
        history_checksums,
        source_artifact_checksums,
        application_history_digest,
    })
}

fn history_row_digest_v0(
    binding: &ProposalValidationBindingV0,
    history: &ConfirmedDurableExecutionHistoryRowV0,
) -> Result<[u8; 32], PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let parent = process2_try!("history.digest_parent", history.parent_head_v0());
    let target = process2_try!("history.digest_target", history.target_head_v0());
    let status = match history.status_v0() {
        DurableExecutionHistoryStatusV0::Prepared => 1_u8,
        DurableExecutionHistoryStatusV0::Committed => 2_u8,
    };
    let commit_sequence = history.commit_sequence_v0().unwrap_or(u64::MAX);
    Ok(hash_v0(
        PROCESS2_HISTORY_ROW_DOMAIN_V0,
        &[
            binding.validation_id().as_bytes(),
            &[binding.route() as u8],
            &binding.generation().to_be_bytes(),
            &history.store_id_v0(),
            &history.p_sequence_v0().to_be_bytes(),
            &[status],
            &parent.height().get().to_be_bytes(),
            parent.block_id().as_bytes(),
            parent.state_root().as_bytes(),
            parent.commit_id().as_bytes(),
            &target.height().get().to_be_bytes(),
            target.block_id().as_bytes(),
            target.state_root().as_bytes(),
            target.commit_id().as_bytes(),
            &history.artifact_digest_v0(),
            &history.overlay_digest_v0(),
            &history.p_digest_v0(),
            &commit_sequence.to_be_bytes(),
        ],
    ))
}

fn authenticate_archive_v0(
    core: &CoreConfig,
    expected_high_qc: trnm_consensus_types::QcRef,
    path: &[PocoNodeDeployedLabReplayBlockV0],
    history: &Process2HistoryInventoryV0,
    entries: &[PocoNodeDeployedLabSignedReplayEntryV0],
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let required = path
        .iter()
        .filter(|coordinate| coordinate.height_v0() > 3)
        .collect::<Vec<_>>();
    if required.len() != entries.len() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "archive.exact_coverage",
            "signed archive does not exactly cover h3 through durable high QC",
        ));
    }
    let h3 = path
        .iter()
        .find(|value| value.height_v0() == 3)
        .ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "archive.h3",
                "high-QC path lacks its anchored h3 coordinate",
            )
        })?;
    let mut previous_id = h3.block_id_v0();
    let mut previous_view = h3.view_v0();
    let mut previous_timestamp = h3.timestamp_ms_v0();
    let mut previous_qc = None;
    let mut certificate_ids = BTreeSet::new();
    for (coordinate, entry) in required.into_iter().zip(entries) {
        let proposal = entry.proposal_v0();
        let certificate = entry.certificate_v0();
        let block = proposal.block();
        let header = block.header();
        let retained = history
            .recovered
            .get(&coordinate.block_id_v0())
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "archive.source_k",
                    "signed replay block lacks its exact source K",
                )
            })?;
        if block.id() != coordinate.block_id_v0()
            || header.parent_id() != previous_id
            || coordinate.parent_block_id_v0() != previous_id
            || header.height().get() != coordinate.height_v0()
            || header.view() != coordinate.view_v0()
            || header.timestamp_ms() != coordinate.timestamp_ms_v0()
            || proposal.witness().justify_qc().qc_ref().block_id() != previous_id
            || proposal.witness().justify_qc().qc_ref().view() != previous_view
            || retained.binding.route() != ProposalRouteV0::Proposal
            || retained.binding.block_id().as_bytes() != block.id().as_bytes()
            || retained.binding.parent().block_id().as_bytes() != header.parent_id().as_bytes()
            || retained.binding.height().get() != header.height().get()
            || retained.binding.view() != header.view().get()
            || retained.binding.timestamp_ms() != header.timestamp_ms()
            || retained.binding.commitments().payload_root().as_bytes()
                != header.payload_root().as_bytes()
            || retained.binding.commitments().post_state_root().as_bytes()
                != header.state_root().as_bytes()
            || retained.binding.commitments().receipts_root().as_bytes()
                != header.receipts_root().as_bytes()
            || retained.binding.commitments().evidence_root().as_bytes()
                != header.evidence_root().as_bytes()
            || coordinate.post_state_root_v0().as_bytes() != header.state_root().as_bytes()
            || certificate.block_id() != block.id()
            || certificate.height() != header.height()
            || certificate.view() != header.view()
            || previous_qc
                .is_some_and(|expected| proposal.witness().justify_qc().qc_ref() != expected)
            || !certificate_ids.insert(certificate.id())
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "archive.coordinate_join",
                "signed Proposal/QC differs from its exact high-QC path and source K",
            ));
        }
        process2_try!(
            "archive.proposal_signature",
            proposal.verify(
                core.validator_set(),
                None,
                core.consensus_parameters(),
                previous_timestamp,
                &StrictEd25519Verifier,
            )
        );
        process2_try!(
            "archive.qc_signature",
            certificate.verify(core.validator_set(), &StrictEd25519Verifier)
        );
        previous_id = block.id();
        previous_view = header.view();
        previous_timestamp = header.timestamp_ms();
        previous_qc = Some(trnm_consensus_types::QcRef::from(certificate));
    }
    if previous_qc != Some(expected_high_qc) {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "archive.terminal_high_qc",
            "the final signed archive certificate is not the durable high QC",
        ));
    }
    Ok(())
}

fn exact_unconfirmed_tail_v0(
    high_qc_path: &[PocoNodeDeployedLabReplayBlockV0],
    history: &BTreeMap<BlockId, [u8; 32]>,
) -> Result<(u64, [u8; 32]), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let certified = high_qc_path
        .iter()
        .map(|block| block.block_id_v0())
        .collect::<BTreeSet<_>>();
    let mut tail = history
        .iter()
        .filter(|(block_id, _)| !certified.contains(block_id))
        .map(|(_, digest)| *digest)
        .collect::<Vec<_>>();
    tail.sort_unstable();
    let count = u64::try_from(tail.len()).map_err(|_| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "tail.count",
            "speculative tail count does not fit u64",
        )
    })?;
    let count_bytes = count.to_be_bytes();
    let mut parts = vec![count_bytes.as_slice()];
    parts.extend(tail.iter().map(|digest| digest.as_slice()));
    Ok((count, hash_v0(PROCESS2_TAIL_INVENTORY_DOMAIN_V0, &parts)))
}

fn archive_context_digest_v0(
    safety: &SafetyState,
    path: &[PocoNodeDeployedLabReplayBlockV0],
) -> [u8; 32] {
    let high = safety.high_qc().qc_ref();
    let locked = safety.locked_qc().qc_ref();
    let mut digests = vec![
        high.qc_digest().as_bytes().to_vec(),
        locked.qc_digest().as_bytes().to_vec(),
        safety.finalized().block_id().as_bytes().to_vec(),
        safety.revision().to_be_bytes().to_vec(),
    ];
    for coordinate in path {
        let mut value = Vec::with_capacity(120);
        value.extend_from_slice(coordinate.block_id_v0().as_bytes());
        value.extend_from_slice(coordinate.parent_block_id_v0().as_bytes());
        value.extend_from_slice(&coordinate.height_v0().to_be_bytes());
        value.extend_from_slice(&coordinate.view_v0().get().to_be_bytes());
        value.extend_from_slice(&coordinate.timestamp_ms_v0().to_be_bytes());
        value.extend_from_slice(coordinate.post_state_root_v0().as_bytes());
        digests.push(value);
    }
    let parts = digests.iter().map(Vec::as_slice).collect::<Vec<_>>();
    hash_v0(PROCESS2_ARCHIVE_CONTEXT_DOMAIN_V0, &parts)
}

fn archive_record_digest_v0(
    entries: &[PocoNodeDeployedLabSignedReplayEntryV0],
) -> Result<[u8; 32], PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let mut records = Vec::with_capacity(entries.len().saturating_mul(2));
    for entry in entries {
        records.push(proposal_record_digest_v0(entry.proposal_v0())?.to_vec());
        records.push(process2_try!(
            "archive.qc_encode",
            entry.certificate_v0().try_cev0_bytes()
        ));
    }
    let parts = records.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Ok(hash_v0(PROCESS2_ARCHIVE_RECORD_DOMAIN_V0, &parts))
}

fn proposal_record_digest_v0(
    proposal: &trnm_consensus_types::SignedProposalV0,
) -> Result<[u8; 32], PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let header = process2_try!(
        "archive.proposal_header_encode",
        proposal.block().header().try_cev0_bytes()
    );
    let witness = proposal.witness();
    let signing_root = process2_try!(
        "archive.proposal_signing_root",
        witness.signing_root_for_header(proposal.block().header())
    );
    let justify_id = witness.justify_qc().id();
    let timeout_id = witness
        .timeout_certificate()
        .map(|certificate| certificate.id().as_bytes().to_vec())
        .unwrap_or_default();
    let epoch_anchor_id = witness
        .epoch_anchor_authorization()
        .map(|authorization| authorization.handoff_certificate().id().as_bytes().to_vec())
        .unwrap_or_default();
    let mut parts = vec![
        header.as_slice(),
        proposal.block().application_payload(),
        signing_root.as_bytes().as_slice(),
        justify_id.as_bytes().as_slice(),
        timeout_id.as_slice(),
        epoch_anchor_id.as_slice(),
        witness.proposer_signature().as_bytes().as_slice(),
    ];
    parts.extend(
        proposal
            .block()
            .evidence_objects()
            .iter()
            .map(Vec::as_slice),
    );
    Ok(hash_v0(PROCESS2_PROPOSAL_RECORD_DOMAIN_V0, &parts))
}

fn recovery_challenge_digest_v0(
    safety: &SafetyState,
    archive_context_digest: [u8; 32],
    archive_record_digest: [u8; 32],
    tail_count: u64,
    tail_digest: [u8; 32],
) -> [u8; 32] {
    hash_v0(
        PROCESS2_RECOVERY_CHALLENGE_DOMAIN_V0,
        &[
            &archive_context_digest,
            &archive_record_digest,
            &safety.revision().to_be_bytes(),
            &tail_count.to_be_bytes(),
            &tail_digest,
        ],
    )
}

fn reconstruct_initial_safety_v0(
    core: &CoreConfig,
    current: &SafetyState,
    initial_revision: u64,
    entries: &[PocoNodeDeployedLabSignedReplayEntryV0],
) -> Result<SafetyState, PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if initial_revision > current.revision() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.initial_revision",
            "session initial revision is ahead of the durable Safety head",
        ));
    }
    let replay_ids = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let cursor = u64::try_from(index).map_err(|_| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "safety.replay_id",
                    "cursor does not fit u64",
                )
            })?;
            let generation = initial_revision
                .checked_add(cursor.checked_mul(2).ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "safety.replay_id",
                        "replay generation overflowed",
                    )
                })?)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "safety.replay_id",
                        "replay generation overflowed",
                    )
                })?;
            Ok(ValidationId::new(
                entry.proposal_v0().block().id(),
                entry.proposal_v0().block().header().view(),
                generation,
            ))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let obligations = current
        .payload_validation_obligations()
        .iter()
        .filter(|obligation| {
            !(obligation.route() == PayloadValidationRouteV0::Synced
                && replay_ids.contains(&obligation.id()))
        })
        .cloned()
        .collect::<Vec<_>>();
    let completions = current
        .payload_validation_completions()
        .iter()
        .filter(|completion| {
            !(completion.route() == PayloadValidationRouteV0::Synced
                && replay_ids.contains(&completion.id()))
        })
        .cloned()
        .collect::<Vec<_>>();
    if !obligations.is_empty() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.foreign_obligation",
            "Safety contains an obligation outside the exact process2 frontier",
        ));
    }
    let initial = SafetyState::from_persisted_parts_v13(
        current.schema_version(),
        current.chain_id(),
        current.protocol_version(),
        current.epoch(),
        current.validator_set_id(),
        current.genesis_block_id(),
        current
            .authenticated_genesis_application_parent_v0()
            .copied(),
        current.current_view(),
        current.last_voted_view(),
        current.last_timeout_view(),
        current.high_qc().clone(),
        current.locked_qc().clone(),
        current.finalized(),
        initial_revision,
        current.durable_observed_qcs().to_vec(),
        current.payload_terminal_facts().to_vec(),
        obligations,
        completions,
        current.pending_tc_high_qc_sync().cloned(),
        current.pending_standalone_qc_sync().cloned(),
        current.pending_sign().cloned(),
        current.last_finalization().cloned(),
        current.state_sync_anchor().cloned(),
        current.application_applied(),
        current.finalization_queue().to_vec(),
        current.pending_finalize(),
        current.safety_halt().cloned(),
    );
    process2_try!(
        "safety.initial_validate",
        Core::validate_persisted_state_v0(core, &initial, &StrictEd25519Verifier)
    );
    Ok(initial)
}

fn safety_state_checksum_v0(
    core: &CoreConfig,
    limits: trnm_consensus_core::SafetyStateRecordLimitsV0,
    state: &SafetyState,
) -> Result<[u8; 32], PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let context = process2_try!(
        "safety.record_context",
        SafetyStateRecordContextV0::new(core, STRICT_ED25519_VERIFIER_PROFILE_REF_V0, limits,)
    );
    let encoded = process2_try!(
        "safety.record_encode",
        encode_safety_state_record_v0(state, &context)
    );
    let decoded = process2_try!(
        "safety.record_decode",
        decode_safety_state_record_v0_exact(&encoded, &context)
    );
    if decoded.state() != state {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.record_roundtrip",
            "initial Safety record did not round-trip exactly",
        ));
    }
    Ok(decoded.record_checksum())
}

#[allow(clippy::too_many_arguments)]
fn validate_existing_session_facts_v0(
    session: Option<trnm_native_application_sqlite::ReplaySessionFactsV0>,
    core_config_ref: [u8; 32],
    validation_scope: ProposalValidationStoreScopeV0,
    validation_store_id: [u8; 32],
    recovery_challenge_digest: [u8; 32],
    archive_context_digest: [u8; 32],
    archive_sequence: u64,
    archive_record_digest: [u8; 32],
    expected_count: u64,
    canonical_store_sequence: u64,
    canonical_terminal_digest: [u8; 32],
    application_history_digest: [u8; 32],
    initial_revision: u64,
    initial_state_checksum: [u8; 32],
    initial_chain_checksum: [u8; 32],
    initial_checkpoint_scope: [u8; 32],
    initial_checkpoint_profile_ref: [u8; 32],
    initial_checkpoint_generation: u64,
    initial_checkpoint_checksum: [u8; 32],
    signer: trnm_consensus_signer_journal::SignerWatermarkV0,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let Some(session) = session else {
        return Ok(());
    };
    if session.core_config_ref_v0() != core_config_ref
        || session.validation_scope_v0() != *validation_scope.as_bytes()
        || session.validation_store_id_v0() != validation_store_id
        || session.recovery_challenge_digest_v0() != recovery_challenge_digest
        || session.archive_context_digest_v0() != archive_context_digest
        || session.archive_sequence_v0() != archive_sequence
        || session.archive_record_digest_v0() != archive_record_digest
        || session.expected_count_v0() != expected_count
        || session.canonical_store_sequence_v0() != canonical_store_sequence
        || session.canonical_terminal_audit_digest_v0() != canonical_terminal_digest
        || session.application_history_digest_v0() != application_history_digest
        || session.initial_safety_revision_v0() != initial_revision
        || session.initial_safety_state_checksum_v0() != initial_state_checksum
        || session.initial_safety_chain_checksum_v0() != initial_chain_checksum
        || session.initial_checkpoint_scope_v0() != initial_checkpoint_scope
        || session.initial_checkpoint_profile_ref_v0() != initial_checkpoint_profile_ref
        || session.initial_checkpoint_generation_v0() != initial_checkpoint_generation
        || session.initial_checkpoint_checksum_v0() != initial_checkpoint_checksum
        || session.signer_scope_v0() != signer.scope()
        || session.signer_journal_id_v0() != signer.journal_id()
        || session.signer_sequence_v0() != signer.sequence()
        || session.signer_chain_checksum_v0() != signer.chain_checksum()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "validation.session_substitution",
            "durable replay session differs from the exact archive or live owners",
        ));
    }
    Ok(())
}

fn nonzero_v0(
    value: [u8; 32],
) -> Result<NonZeroDigestV0, PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    Ok(process2_try!("digest.nonzero", NonZeroDigestV0::new(value)))
}

fn open_or_resume_session_v0(
    store: &mut SqliteProposalValidationStoreV0,
    application_path: &Path,
    validation_path: &Path,
    plan: ReplaySessionPlanV0,
    inventory: Option<&ConfirmedReplayInventoryV0>,
) -> Result<(Process2FrontierV0, u64), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    // Session O/resume is a K-side mutation even before the first replay
    // cursor.  Resolve and lock the common root from both canonical paths so
    // this opening CAS cannot race a native P writer.
    let cross_store_lock =
        CrossStoreLockGuardV0::acquire_exclusive_for_paths_v0(application_path, validation_path)
            .map_err(|error| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "validation.session_cross_store_lock",
                    error.to_string(),
                )
            })?;
    let already_checkpointed = inventory
        .map(|value| value.session_v0().next_cursor_v0())
        .unwrap_or(0);
    if let Some(inventory) = inventory {
        if !inventory.belongs_to_store_at_path_v0(store, validation_path)
            || store.path() != validation_path
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "validation.inventory_affinity",
                "replay inventory is not affined to the live validation store",
            ));
        }
        let session = inventory.session_v0();
        if session.is_activation_ready_v0() {
            let final_progress = nonzero_v0(session.previous_progress_checksum_v0())?;
            if session.next_cursor_v0() != session.expected_count_v0()
                || session.activation_binding_digest_v0().is_none()
                || session.activation_source_row_revision_v0().is_none()
                || session.activation_source_row_checksum_v0().is_none()
                || inventory.links_v0().len()
                    != usize::try_from(session.expected_count_v0()).map_err(|_| {
                        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                            "validation.activation_ready_count",
                            "ActivationReady link count does not fit usize",
                        )
                    })?
                || inventory
                    .links_v0()
                    .iter()
                    .any(|link| link.stage_v0() != DurableReplayLinkStageV0::Checkpointed)
            {
                return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "validation.activation_ready_shape",
                    "ActivationReady session lost its complete predecessor closure",
                ));
            }
            cross_store_lock.validate_identity_v0().map_err(|error| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "validation.session_cross_store_lock_final_identity",
                    error.to_string(),
                )
            })?;
            return Ok((
                Process2FrontierV0::ActivationReady {
                    expected_count: session.expected_count_v0(),
                    final_progress,
                },
                already_checkpointed,
            ));
        }
        let frontier = resume_frontier_v0(store, plan)?;
        cross_store_lock.validate_identity_v0().map_err(|error| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "validation.session_cross_store_lock_final_identity",
                error.to_string(),
            )
        })?;
        return Ok((frontier, already_checkpointed));
    }
    for _ in 0..4 {
        let terminal = process2_try!(
            "validation.open_terminal",
            store.confirm_terminal_k_audit_v0()
        );
        match process2_try!(
            "validation.open_session",
            store.begin_replay_session_v0(terminal, plan)
        ) {
            ReplaySessionOpenOutcomeV0::Applied(session)
            | ReplaySessionOpenOutcomeV0::Existing(session) => {
                cross_store_lock.validate_identity_v0().map_err(|error| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "validation.session_cross_store_lock_final_identity",
                        error.to_string(),
                    )
                })?;
                return Ok((Process2FrontierV0::Ready(session), 0));
            }
            ReplaySessionOpenOutcomeV0::NotApplied => {}
        }
    }
    Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
        "validation.open_retry_exhausted",
        "replay session O did not become durable after bounded exact retries",
    ))
}

fn resume_frontier_v0(
    store: &mut SqliteProposalValidationStoreV0,
    plan: ReplaySessionPlanV0,
) -> Result<Process2FrontierV0, PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let terminal = process2_try!(
        "validation.resume_terminal",
        store.confirm_terminal_k_audit_v0()
    );
    Ok(process2_try!(
        "validation.resume_session",
        store.resume_replay_session_v0(terminal, plan)
    )
    .into())
}

fn recover_initial_replay_core_v0(
    config: &CoreConfig,
    safety: SafetyState,
    child: trnm_consensus_types::SignedProposalV0,
    grandchild: trnm_consensus_types::SignedProposalV0,
) -> Result<
    (
        Core,
        trnm_consensus_types::SignedProposalV0,
        trnm_consensus_types::SignedProposalV0,
    ),
    PocoNodeDeployedLabProcess2RecoveryErrorV0,
> {
    let bundle = process2_try!(
        "core.initial_successor_bundle",
        Core::prepare_h1_state_sync_anchor_successor_bundle_v0(
            config,
            &safety,
            child.clone(),
            grandchild.clone(),
            &StrictEd25519Verifier,
        )
    );
    let session = process2_try!(
        "core.initial_recovery",
        Core::begin_state_sync_anchor_ordinary_recovery_v0(
            config.clone(),
            safety.clone(),
            bundle,
            &StrictEd25519Verifier,
        )
    );
    let mut reconciler = ExactAnchorOrdinaryReconcilerV0 {
        safety,
        child: child.clone(),
        grandchild: grandchild.clone(),
        calls: 0,
    };
    let activation = process2_try!(
        "core.initial_reconcile",
        session.reconcile_and_activate_v0(&mut reconciler, &StrictEd25519Verifier)
    );
    if reconciler.calls != 1 || !activation.effects().is_empty() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "core.initial_effects",
            "process2 initial Core emitted startup authority",
        ));
    }
    let (core, effects) = activation.into_parts_v0();
    if !effects.is_empty() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "core.initial_effects",
            "process2 retained a startup effect",
        ));
    }
    Ok((core, child, grandchild))
}

fn exact_persistence_effect_v0(
    effects: Vec<Effect>,
    stage: &'static str,
) -> Result<trnm_consensus_core::SafetyStatePersistenceV0, PocoNodeDeployedLabProcess2RecoveryErrorV0>
{
    match effects.as_slice() {
        [Effect::PersistSafetyState(_)] => match effects.into_iter().next() {
            Some(Effect::PersistSafetyState(request)) => Ok(request),
            _ => unreachable!("effect shape was checked"),
        },
        _ => Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            stage,
            "Core did not emit exactly one Safety persistence request",
        )),
    }
}

fn persist_expected_request_v0(
    store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    predecessor: &SafetyState,
    request: &trnm_consensus_core::SafetyStatePersistenceV0,
    context: &SafetyTransitionContextV0,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let observed = process2_try!("safety.pre_persist_head", store.head());
    if observed.state() != predecessor && observed.state() != request.state() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.one_sided_rollback",
            "Safety head is neither the exact predecessor nor exact retry target",
        ));
    }
    process2_try!("safety.persist", store.persist_exact_v0(request, context));
    let fresh = process2_try!("safety.persist_readback", store.head());
    if fresh.state() != request.state() || fresh.transition_context() != context {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "safety.persist_readback",
            "Safety persistence did not fresh-read the exact target and context",
        ));
    }
    Ok(())
}

fn replay_target_binding_v0(
    source: ProposalValidationBindingV0,
    id: ValidationId,
) -> Result<ProposalValidationBindingV0, PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if id.block_id().as_bytes() != source.block_id().as_bytes() || id.view().get() != source.view()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "validation.target_core_id",
            "Core Synced id differs from the canonical source edge",
        ));
    }
    Ok(process2_try!(
        "validation.target_binding",
        ProposalValidationBindingV0::new(
            source.chain_id().clone(),
            source.genesis_hash(),
            source.parent().clone(),
            source.block_id(),
            source.height(),
            source.timestamp_ms(),
            source.active_validator_set_id(),
            source.view(),
            id.generation(),
            ProposalRouteV0::Synced,
            source.commitments(),
        )
    ))
}

fn validate_core_parent_binding_v0(
    binding: &ProposalValidationBindingV0,
    parent: &trnm_consensus_core::PayloadValidationParentV0,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let tip = parent.tip();
    let exact = parent.exact_header().ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "core.parent_header",
            "ordinary process2 request lacks an exact parent header",
        )
    })?;
    if tip.block_id().as_bytes() != binding.parent().block_id().as_bytes()
        || tip.height().get() != binding.parent().height().get()
        || exact.state_root().as_bytes() != binding.parent().state_root().as_bytes()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "core.parent_binding",
            "Core request parent differs from the canonical application parent",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_checkpointed_link_against_live_v0(
    validation_store: &mut SqliteProposalValidationStoreV0,
    inventory: &ConfirmedReplayInventoryV0,
    cursor: u64,
    source: &RecoveredHistoryKV0,
    target_binding: &ProposalValidationBindingV0,
    accepted: &CoreAcceptedApplicationValidDV0,
    source_artifact_checksum: [u8; 32],
    source_history_checksum: [u8; 32],
    core_config: &CoreConfig,
    limits: trnm_consensus_core::SafetyStateRecordLimitsV0,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let link = inventory
        .links_v0()
        .iter()
        .find(|link| link.cursor_v0() == cursor)
        .ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "replay.prior_link_missing",
                "checkpointed Core replay cursor lacks its durable sidecar link",
            )
        })?;
    let core_delivery = process2_try!(
        "replay.prior_core_delivery",
        validation_store.confirm_checkpointed_replay_core_delivery_v0(
            inventory,
            cursor,
            target_binding,
        )
    );
    let safety_record = safety_state_checksum_v0(
        core_config,
        limits,
        accepted.persistence_request_v0().state(),
    )?;
    let nonzero_options = [
        link.core_state_digest_v0(),
        link.accepted_validation_digest_v0(),
        link.safety_core_delivery_digest_v0(),
        link.safety_record_digest_v0(),
        link.no_sign_closure_digest_v0(),
        link.alias_closure_checksum_v0(),
        link.checkpoint_scope_v0(),
        link.checkpoint_profile_ref_v0(),
        link.checkpoint_predecessor_checksum_v0(),
        link.checkpoint_checksum_v0(),
        link.progress_checksum_v0(),
    ]
    .into_iter()
    .all(|value| value.is_some_and(|digest| digest != [0; 32]));
    if source_artifact_checksum == [0; 32]
        || source_history_checksum == [0; 32]
        || link.stage_v0() != DurableReplayLinkStageV0::Checkpointed
        || link.session_id_v0() != inventory.session_v0().session_id_v0()
        || link.source_validation_id_v0() != source.binding.validation_id()
        || link.target_binding_v0() != target_binding
        || link.owner_id_v0().as_bytes() == &[0; 32]
        || link.source_store_sequence_v0() == 0
        || link.source_row_revision_v0() == 0
        || link.source_row_checksum_v0() != source.validation_row_checksum
        || link.source_application_history_checksum_v0() != source_history_checksum
        || link.artifact_digest_v0() == [0; 32]
        || core_delivery.validation_id() != target_binding.validation_id()
        || core_delivery.core_revision() != accepted.completion_revision_v0()
        || core_delivery.core_state_digest().as_bytes() != &accepted.delivery_digest_v0()
        || core_delivery.accepted_validation_digest().as_bytes()
            != &accepted.valid_result_checksum_v0()
        || link.core_revision_v0() != Some(accepted.completion_revision_v0())
        || link.core_state_digest_v0() != Some(accepted.delivery_digest_v0())
        || link.accepted_validation_digest_v0() != Some(accepted.valid_result_checksum_v0())
        || link.safety_core_delivery_digest_v0() != Some(*core_delivery.digest().as_bytes())
        || link.safety_revision_v0() != Some(accepted.completion_revision_v0())
        || link.safety_record_digest_v0() != Some(safety_record)
        || link.checkpoint_generation_v0().is_none()
        || link.row_revision_v0() == 0
        || link.row_checksum_v0() == [0; 32]
        || !nonzero_options
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.prior_link_substitution",
            "checkpointed sidecar link differs from the repeated live Core/application edge",
        ));
    }
    Ok(())
}

fn require_no_authority_effects_v0(
    effects: &[Effect],
    stage: &'static str,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if !effects.is_empty() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            stage,
            "replay completion released an effect outside the inert recovery owner",
        ));
    }
    Ok(())
}

struct ExactReplaySourceHistoryReadbackV0<'a> {
    application: &'a DurableNativeApplicationV0,
    application_path: &'a Path,
    binding: &'a ProposalValidationBindingV0,
    executed: &'a NativeExecutedBlockV0,
    validation_artifact_digest: [u8; 32],
    expected_history_checksum: [u8; 32],
}

impl ReplaySourceHistoryReadbackV0 for ExactReplaySourceHistoryReadbackV0<'_> {
    fn read_exact_replay_source_history_v0(
        &mut self,
        request: ReplaySourceHistoryReadRequestV0,
    ) -> ValidationStoreResultV0<UntrustedReplaySourceHistoryReadbackV0> {
        if request.source_validation_id_v0() != self.binding.validation_id()
            || request.artifact_digest_v0().as_bytes() != &self.validation_artifact_digest
            || request.expected_history_checksum_v0().as_bytes() != &self.expected_history_checksum
        {
            return Err(validation_adapter_error_v0());
        }
        let history = self
            .application
            .confirm_durable_execution_history_row_v0(self.executed)
            .map_err(|_| validation_adapter_error_v0())?;
        let parent = history
            .parent_head_v0()
            .map_err(|_| validation_adapter_error_v0())?;
        let target = history
            .target_head_v0()
            .map_err(|_| validation_adapter_error_v0())?;
        let checksum = history_row_digest_v0(self.binding, &history)
            .map_err(|_| validation_adapter_error_v0())?;
        if !history.belongs_to_application_at_path_v0(self.application, self.application_path)
            || parent != *self.binding.parent()
            || target.block_id() != self.binding.block_id()
            || target.height() != self.binding.height()
            || target.state_root() != self.binding.commitments().post_state_root()
            || checksum != self.expected_history_checksum
        {
            return Err(validation_adapter_error_v0());
        }
        Ok(UntrustedReplaySourceHistoryReadbackV0::new(
            request.source_validation_id_v0(),
            request.artifact_digest_v0(),
            request.expected_history_checksum_v0(),
        ))
    }
}

struct ExactReplayCheckpointReadbackV0<'a, W: ExternalMonotonicWatermarkV0> {
    store: &'a mut SqliteExternalNodeCheckpointStoreV0,
    safety: &'a SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    safety_path: &'a Path,
    signer: &'a mut PinnedSqliteSignerJournalV0<W>,
    signer_path: &'a Path,
    expected_profile_ref: [u8; 32],
    application_history_digest: [u8; 32],
    crash_hook: Option<Process2CrashHookV0>,
}

impl<W: ExternalMonotonicWatermarkV0> ReplayCheckpointReadbackV0
    for ExactReplayCheckpointReadbackV0<'_, W>
{
    fn read_or_advance_exact_replay_checkpoint_v0(
        &mut self,
        request: ReplayCheckpointReadRequestV0,
    ) -> ValidationStoreResultV0<UntrustedReplayCheckpointReadbackV0> {
        let safety_head = self
            .safety
            .head()
            .map_err(|_| validation_adapter_error_v0())?;
        let safety = self
            .safety
            .confirm_node_checkpoint_head_exact_v0(safety_head.state())
            .map_err(|_| validation_adapter_error_v0())?;
        let signer = self
            .signer
            .confirm_node_checkpoint_head_exact_v0()
            .map_err(|_| validation_adapter_error_v0())?;
        if !safety.belongs_to_store_at_path_v0(self.safety, self.safety_path)
            || !signer.belongs_to_pinned_journal_at_path_v0(self.signer, self.signer_path)
            || safety.revision_v0() != request.safety_revision_v0()
            || request.expected_profile_ref_v0().as_bytes() != &self.expected_profile_ref
            || request.application_history_digest_v0().as_bytes()
                != &self.application_history_digest
            || request.signer_scope_v0().as_bytes() != &signer.exact_watermark().scope()
            || request.signer_journal_id_v0().as_bytes() != &signer.journal_id()
            || request.signer_sequence_v0() != signer.exact_watermark().sequence()
            || request.signer_chain_checksum_v0().as_bytes()
                != &signer.exact_watermark().chain_checksum()
            || signer.pending_intent().is_some()
        {
            return Err(validation_adapter_error_v0());
        }

        let scope = *request.expected_scope_v0().as_bytes();
        let observed = self
            .store
            .load(scope)
            .map_err(|_| validation_adapter_error_v0())?
            .ok_or_else(validation_adapter_error_v0)?;
        let next_generation = request
            .expected_predecessor_generation_v0()
            .checked_add(1)
            .ok_or_else(validation_adapter_error_v0)?;
        let target = if observed.generation() == request.expected_predecessor_generation_v0()
            && observed.checkpoint_checksum()
                == *request.expected_predecessor_checksum_v0().as_bytes()
        {
            let fields = checkpoint_successor_fields_v0(&observed, &safety, &signer)
                .ok_or_else(validation_adapter_error_v0)?;
            let target =
                ExternalNodeCheckpointV0::new(fields).map_err(|_| validation_adapter_error_v0())?;
            let _ = self.store.compare_and_advance(Some(observed), target);
            let fresh = self
                .store
                .load(scope)
                .map_err(|_| validation_adapter_error_v0())?
                .ok_or_else(validation_adapter_error_v0)?;
            if fresh != target {
                return Err(validation_adapter_error_v0());
            }
            fresh
        } else if observed.generation() == next_generation
            && observed.predecessor_checksum()
                == *request.expected_predecessor_checksum_v0().as_bytes()
        {
            let expected = ExternalNodeCheckpointV0::new(
                checkpoint_target_fields_from_existing_v0(&observed, &safety, &signer),
            )
            .map_err(|_| validation_adapter_error_v0())?;
            if observed != expected {
                return Err(validation_adapter_error_v0());
            }
            observed
        } else {
            return Err(validation_adapter_error_v0());
        };
        if target.scope() != scope
            || target.generation() != next_generation
            || target.predecessor_checksum()
                != *request.expected_predecessor_checksum_v0().as_bytes()
        {
            return Err(validation_adapter_error_v0());
        }
        if self.crash_hook == Some(Process2CrashHookV0::ExternalCheckpointAdvanced) {
            return Err(validation_adapter_error_v0());
        }
        UntrustedReplayCheckpointReadbackV0::new(
            request.preimage_digest_v0(),
            request.expected_scope_v0(),
            request.expected_profile_ref_v0(),
            request.expected_predecessor_checksum_v0(),
            target.generation(),
            NonZeroDigestV0::new(target.checkpoint_checksum())?,
        )
    }
}

fn checkpoint_successor_fields_v0(
    predecessor: &ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) -> Option<ExternalNodeCheckpointFieldsV0> {
    let mut fields = *predecessor.fields();
    fields.generation = predecessor.generation().checked_add(1)?;
    fields.predecessor_checksum = predecessor.checkpoint_checksum();
    apply_checkpoint_terminal_heads_v0(&mut fields, safety, signer);
    Some(fields)
}

fn checkpoint_target_fields_from_existing_v0(
    existing: &ExternalNodeCheckpointV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) -> ExternalNodeCheckpointFieldsV0 {
    let mut fields = *existing.fields();
    apply_checkpoint_terminal_heads_v0(&mut fields, safety, signer);
    fields
}

fn apply_checkpoint_terminal_heads_v0(
    fields: &mut ExternalNodeCheckpointFieldsV0,
    safety: &trnm_consensus_safety_store::ConfirmedSafetyNodeCheckpointFactsV0,
    signer: &trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0,
) {
    fields.safety_journal_id = safety.journal_id_v0();
    fields.safety_verifier_profile_ref = safety.verifier_profile_ref_v0();
    fields.safety_revision = safety.revision_v0();
    fields.safety_state_record_checksum = safety.state_record_checksum_v0();
    fields.safety_record_chain_checksum = safety.chain_checksum_v0();
    fields.signer_journal_id = signer.journal_id();
    fields.signer_profile_checksum = signer.profile_checksum();
    fields.signer_exact_watermark = signer.exact_watermark();
}

fn validation_adapter_error_v0() -> ValidationStoreErrorV0 {
    NonZeroDigestV0::new([0; 32]).expect_err("zero digest must remain rejected")
}

fn trigger_test_crash_v0(
    configured: Option<Process2CrashHookV0>,
    reached: Process2CrashHookV0,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if configured == Some(reached) {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "test.process_loss",
            format!("injected process loss after {reached:?}"),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drive_live_cursor_v0<W: ExternalMonotonicWatermarkV0>(
    mut frontier: Process2FrontierV0,
    cursor: u64,
    replay_plan: ReplaySessionPlanV0,
    source: &RecoveredHistoryKV0,
    target_binding: &ProposalValidationBindingV0,
    validation_owner: ProposalValidationOwnerIdV0,
    source_history_checksum: [u8; 32],
    executed: &NativeExecutedBlockV0,
    accepted: &CoreAcceptedApplicationValidDV0,
    completion_predecessor: &SafetyState,
    safety_store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    paths: &AuthorityPathsV0,
    application: &DurableNativeApplicationV0,
    validation_store: &mut SqliteProposalValidationStoreV0,
    checkpoint_store: &mut SqliteExternalNodeCheckpointStoreV0,
    signer: &mut PinnedSqliteSignerJournalV0<W>,
    checkpoint_profile_ref: [u8; 32],
    application_history_digest: [u8; 32],
    crash_hook: Option<Process2CrashHookV0>,
) -> Result<Process2FrontierV0, PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    // Process-2 replay mutates the validation K sidecar through several
    // monotonic stages (reserve -> deliver -> safety-close -> alias-close ->
    // checkpoint).  Keep the entire cursor transaction under one authority
    // root lock so no P-only rewrite can interleave between those stages or
    // between the final K/checkpoint readbacks.  This is deliberately a
    // cooperating-owner fence; it does not claim a distributed lock or turn
    // the laboratory replay into a production activation path.
    let _cross_store_lock = CrossStoreLockGuardV0::acquire_exclusive_for_paths_v0(
        &paths.application,
        &paths.validation,
    )
    .map_err(|error| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.cross_store_lock",
            error.to_string(),
        )
    })?;
    let source_k = process2_try!(
        "replay.live_source_k",
        validation_store.confirm_proposal_validation_checkpoint_facts_exact_v0(&source.binding)
    );
    if !source_k.belongs_to_store_at_path_v0(validation_store, &paths.validation)
        || source_k.binding_v0() != &source.binding
        || source_k.owner_id_v0() != validation_owner
        || source_k.row_checksum_v0().as_bytes() != &source.validation_row_checksum
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.live_source_k_join",
            "live cursor source K differs from the recovered canonical history",
        ));
    }
    let validation_artifact_digest = *source_k.artifact_digest_v0().as_bytes();
    drop(source_k);

    for _ in 0..16 {
        frontier = match frontier {
            Process2FrontierV0::Ready(session) => {
                if session.next_cursor_v0() != cursor {
                    return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "replay.live_ready_cursor",
                        "ready sidecar cursor differs from Core",
                    ));
                }
                let source_k = process2_try!(
                    "replay.reserve_source_k",
                    validation_store
                        .confirm_proposal_validation_checkpoint_facts_exact_v0(&source.binding)
                );
                match process2_try!(
                    "replay.reserve_p",
                    validation_store.reserve_synced_replay_link_v0(
                        session,
                        source_k,
                        nonzero_v0(source_history_checksum)?,
                        target_binding,
                        validation_owner,
                    )
                ) {
                    ReplayLinkReservationOutcomeV0::Applied(link)
                    | ReplayLinkReservationOutcomeV0::Existing(link) => {
                        trigger_test_crash_v0(crash_hook, Process2CrashHookV0::LinkReserved)?;
                        Process2FrontierV0::Reserved(link)
                    }
                    ReplayLinkReservationOutcomeV0::NotApplied => {
                        resume_frontier_v0(validation_store, replay_plan)?
                    }
                }
            }
            Process2FrontierV0::Reserved(link) => {
                validate_reserved_frontier_v0(
                    &link,
                    cursor,
                    source.binding.validation_id(),
                    target_binding.validation_id(),
                    validation_artifact_digest,
                )?;
                let replayed = process2_try!(
                    "replay.read_p",
                    validation_store.read_replay_artifact_exact_v0(&link, target_binding)
                );
                if &replayed != executed {
                    return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "replay.artifact_substitution",
                        "sidecar P did not recover the exact source application artifact",
                    ));
                }
                match process2_try!(
                    "replay.deliver_d",
                    validation_store.deliver_replay_core_accepted_v0(
                        link,
                        target_binding,
                        accepted,
                    )
                ) {
                    ReplayLinkDeliveryOutcomeV0::Applied(link) => {
                        trigger_test_crash_v0(crash_hook, Process2CrashHookV0::CoreDelivered)?;
                        Process2FrontierV0::CoreDelivered(link)
                    }
                    ReplayLinkDeliveryOutcomeV0::NotApplied(link) => {
                        Process2FrontierV0::Reserved(link)
                    }
                }
            }
            Process2FrontierV0::CoreDelivered(link) => {
                validate_delivered_frontier_v0(
                    &link,
                    cursor,
                    source.binding.validation_id(),
                    target_binding.validation_id(),
                    validation_owner,
                    validation_artifact_digest,
                )?;
                let context = process2_try!(
                    "replay.native_valid_context",
                    validation_store.replay_native_valid_transition_context_exact_v0(
                        target_binding,
                        &link,
                        accepted,
                    )
                );
                persist_expected_request_v0(
                    safety_store,
                    completion_predecessor,
                    accepted.persistence_request_v0(),
                    &context,
                )?;
                trigger_test_crash_v0(crash_hook, Process2CrashHookV0::SafetyPersisted)?;
                match process2_try!(
                    "replay.close_c",
                    validation_store.close_replay_safety_c_v0(
                        link,
                        target_binding,
                        accepted,
                        safety_store,
                        &paths.target_safety,
                    )
                ) {
                    ReplayLinkSafetyOutcomeV0::Applied(link) => {
                        trigger_test_crash_v0(crash_hook, Process2CrashHookV0::SafetyClosed)?;
                        Process2FrontierV0::SafetyClosed(link)
                    }
                    ReplayLinkSafetyOutcomeV0::NotApplied(link) => {
                        Process2FrontierV0::CoreDelivered(link)
                    }
                }
            }
            Process2FrontierV0::SafetyClosed(link) => {
                validate_safety_closed_frontier_v0(
                    &link,
                    cursor,
                    source.binding.validation_id(),
                    target_binding.validation_id(),
                    validation_owner,
                    validation_artifact_digest,
                    accepted,
                    safety_store,
                )?;
                let mut history_readback = ExactReplaySourceHistoryReadbackV0 {
                    application,
                    application_path: &paths.application,
                    binding: &source.binding,
                    executed,
                    validation_artifact_digest,
                    expected_history_checksum: source_history_checksum,
                };
                match process2_try!(
                    "replay.close_alias_k",
                    validation_store.close_replay_alias_k_v0(
                        link,
                        target_binding,
                        &mut history_readback,
                    )
                ) {
                    ReplayLinkAliasCloseOutcomeV0::Applied(link) => {
                        trigger_test_crash_v0(crash_hook, Process2CrashHookV0::AliasClosed)?;
                        Process2FrontierV0::AliasClosed(link)
                    }
                    ReplayLinkAliasCloseOutcomeV0::NotApplied(link) => {
                        Process2FrontierV0::SafetyClosed(link)
                    }
                }
            }
            Process2FrontierV0::AliasClosed(link) => {
                validate_alias_closed_frontier_v0(
                    &link,
                    cursor,
                    source.binding.validation_id(),
                    target_binding.validation_id(),
                    validation_owner,
                    validation_artifact_digest,
                    accepted,
                    safety_store,
                )?;
                let mut checkpoint_readback = ExactReplayCheckpointReadbackV0 {
                    store: checkpoint_store,
                    safety: safety_store,
                    safety_path: &paths.target_safety,
                    signer,
                    signer_path: &paths.signer,
                    expected_profile_ref: checkpoint_profile_ref,
                    application_history_digest,
                    crash_hook,
                };
                match process2_try!(
                    "replay.checkpoint",
                    validation_store.checkpoint_replay_alias_k_v0(link, &mut checkpoint_readback)
                ) {
                    ReplayLinkCheckpointOutcomeV0::AppliedNext { link, session } => {
                        validate_checkpointed_token_v0(&link, cursor, target_binding)?;
                        trigger_test_crash_v0(crash_hook, Process2CrashHookV0::Checkpointed)?;
                        return Ok(Process2FrontierV0::Ready(session));
                    }
                    ReplayLinkCheckpointOutcomeV0::AppliedComplete { link, session } => {
                        validate_checkpointed_token_v0(&link, cursor, target_binding)?;
                        trigger_test_crash_v0(crash_hook, Process2CrashHookV0::Checkpointed)?;
                        return Ok(Process2FrontierV0::Complete(session));
                    }
                    ReplayLinkCheckpointOutcomeV0::NotApplied(link) => {
                        Process2FrontierV0::AliasClosed(link)
                    }
                }
            }
            Process2FrontierV0::Complete(session) => {
                return Ok(Process2FrontierV0::Complete(session));
            }
            Process2FrontierV0::ActivationReady { .. } => {
                return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "replay.activation_ready_frontier",
                    "an activation-ready session cannot re-enter the live replay cursor driver",
                ));
            }
        };
    }
    Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
        "replay.live_retry_exhausted",
        "one replay cursor did not close after bounded exact retries",
    ))
}

fn validate_reserved_frontier_v0(
    link: &ReservedReplayLinkPV0,
    cursor: u64,
    source_id: trnm_native_application_sqlite::ValidationIdV0,
    target_id: trnm_native_application_sqlite::ValidationIdV0,
    artifact_digest: [u8; 32],
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if link.cursor_v0() != cursor
        || link.source_validation_id_v0() != source_id
        || link.target_validation_id_v0() != target_id
        || link.artifact_digest_v0().as_bytes() != &artifact_digest
        || link.row_revision_v0() == 0
        || link.row_checksum_v0().as_bytes() == &[0; 32]
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.reserved_frontier",
            "durable replay P differs from the exact live cursor",
        ));
    }
    Ok(())
}

fn validate_delivered_frontier_v0(
    link: &CoreDeliveredReplayLinkDV0,
    cursor: u64,
    source_id: trnm_native_application_sqlite::ValidationIdV0,
    target_id: trnm_native_application_sqlite::ValidationIdV0,
    owner: ProposalValidationOwnerIdV0,
    artifact_digest: [u8; 32],
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if link.cursor_v0() != cursor
        || link.source_validation_id_v0() != source_id
        || link.target_validation_id_v0() != target_id
        || link.owner_id_v0() != owner
        || link.artifact_digest_v0().as_bytes() != &artifact_digest
        || link.row_revision_v0() == 0
        || link.row_checksum_v0().as_bytes() == &[0; 32]
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.delivered_frontier",
            "durable replay D differs from the exact live cursor",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_safety_closed_frontier_v0(
    link: &SafetyClosedReplayLinkCV0,
    cursor: u64,
    source_id: trnm_native_application_sqlite::ValidationIdV0,
    target_id: trnm_native_application_sqlite::ValidationIdV0,
    owner: ProposalValidationOwnerIdV0,
    artifact_digest: [u8; 32],
    accepted: &CoreAcceptedApplicationValidDV0,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let head = process2_try!("replay.safety_closed_head", safety_store.head());
    if link.cursor_v0() != cursor
        || link.source_validation_id_v0() != source_id
        || link.target_validation_id_v0() != target_id
        || link.owner_id_v0() != owner
        || link.artifact_digest_v0().as_bytes() != &artifact_digest
        || link.safety_revision_v0() != accepted.completion_revision_v0()
        || link.safety_record_digest_v0().as_bytes() == &[0; 32]
        || link.no_sign_closure_digest_v0().as_bytes() == &[0; 32]
        || head.state() != accepted.persistence_request_v0().state()
        || head.state().pending_sign().is_some()
        || !head.state().payload_validation_obligations().is_empty()
        || link.row_revision_v0() == 0
        || link.row_checksum_v0().as_bytes() == &[0; 32]
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.safety_closed_frontier",
            "durable replay C differs from the exact no-sign Safety head",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_alias_closed_frontier_v0(
    link: &AliasClosedReplayLinkKV0,
    cursor: u64,
    source_id: trnm_native_application_sqlite::ValidationIdV0,
    target_id: trnm_native_application_sqlite::ValidationIdV0,
    owner: ProposalValidationOwnerIdV0,
    artifact_digest: [u8; 32],
    accepted: &CoreAcceptedApplicationValidDV0,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let head = process2_try!("replay.alias_closed_head", safety_store.head());
    if link.cursor_v0() != cursor
        || link.source_validation_id_v0() != source_id
        || link.target_validation_id_v0() != target_id
        || link.owner_id_v0() != owner
        || link.artifact_digest_v0().as_bytes() != &artifact_digest
        || link.safety_revision_v0() != accepted.completion_revision_v0()
        || link.alias_closure_checksum_v0().as_bytes() == &[0; 32]
        || head.state() != accepted.persistence_request_v0().state()
        || head.state().pending_sign().is_some()
        || !head.state().payload_validation_obligations().is_empty()
        || link.row_revision_v0() == 0
        || link.row_checksum_v0().as_bytes() == &[0; 32]
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.alias_closed_frontier",
            "durable replay alias K differs from the exact application/Safety join",
        ));
    }
    Ok(())
}

fn validate_checkpointed_token_v0(
    link: &trnm_native_application_sqlite::CheckpointedReplayLinkV0,
    cursor: u64,
    target: &ProposalValidationBindingV0,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    if link.cursor_v0() != cursor
        || link.target_validation_id_v0() != target.validation_id()
        || link.checkpoint_generation_v0() == 0
        || link.checkpoint_scope_v0().as_bytes() == &[0; 32]
        || link.checkpoint_profile_ref_v0().as_bytes() == &[0; 32]
        || link.checkpoint_predecessor_checksum_v0().as_bytes() == &[0; 32]
        || link.checkpoint_checksum_v0().as_bytes() == &[0; 32]
        || link.row_revision_v0() == 0
        || link.row_checksum_v0().as_bytes() == &[0; 32]
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.checkpointed_token",
            "checkpointed replay token differs from the exact cursor",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_complete_inventory_v0(
    inventory: &ConfirmedReplayInventoryV0,
    _plan: ReplaySessionPlanV0,
    final_progress: NonZeroDigestV0,
    expected_count: u64,
    tail_count: u64,
    tail_digest: [u8; 32],
    high_qc_path: &[PocoNodeDeployedLabReplayBlockV0],
    history_checksums: &BTreeMap<BlockId, [u8; 32]>,
) -> Result<(), PocoNodeDeployedLabProcess2RecoveryErrorV0> {
    let session = inventory.session_v0();
    let link_count = u64::try_from(inventory.links_v0().len()).map_err(|_| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.inventory_count",
            "replay link inventory length does not fit u64",
        )
    })?;
    let recomputed_tail = exact_unconfirmed_tail_v0(high_qc_path, history_checksums)?;
    if (!session.is_durable_complete_v0() && !session.is_activation_ready_v0())
        || session.expected_count_v0() != expected_count
        || session.next_cursor_v0() != expected_count
        || link_count != expected_count
        || session.previous_progress_checksum_v0() != *final_progress.as_bytes()
        || recomputed_tail != (tail_count, tail_digest)
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.complete_inventory",
            "durable replay session is not exactly complete",
        ));
    }

    let mut prior_progress = None;
    let mut prior_checkpoint = session.initial_checkpoint_checksum_v0();
    let mut sources = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for (index, link) in inventory.links_v0().iter().enumerate() {
        let cursor = u64::try_from(index).map_err(|_| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "replay.inventory_cursor",
                "replay inventory cursor does not fit u64",
            )
        })?;
        let expected_safety_revision = session
            .initial_safety_revision_v0()
            .checked_add(cursor.checked_mul(2).ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "replay.inventory_safety",
                    "replay Safety span overflowed",
                )
            })?)
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "replay.inventory_safety",
                    "replay Safety revision overflowed",
                )
            })?;
        let expected_generation = session
            .initial_checkpoint_generation_v0()
            .checked_add(cursor)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "replay.inventory_checkpoint",
                    "replay checkpoint generation overflowed",
                )
            })?;
        let progress = link.progress_checksum_v0().ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "replay.inventory_progress",
                "checkpointed replay link lacks progress",
            )
        })?;
        let expected_previous_progress =
            prior_progress.unwrap_or_else(|| link.previous_progress_checksum_v0());
        if link.session_id_v0() != session.session_id_v0()
            || link.cursor_v0() != cursor
            || link.stage_v0() != DurableReplayLinkStageV0::Checkpointed
            || link.target_binding_v0().route() != ProposalRouteV0::Synced
            || link.target_binding_v0().generation().checked_add(1)
                != Some(expected_safety_revision)
            || link.safety_revision_v0() != Some(expected_safety_revision)
            || link.checkpoint_scope_v0() != Some(session.initial_checkpoint_scope_v0())
            || link.checkpoint_profile_ref_v0() != Some(session.initial_checkpoint_profile_ref_v0())
            || link.checkpoint_generation_v0() != Some(expected_generation)
            || link.checkpoint_predecessor_checksum_v0() != Some(prior_checkpoint)
            || link.previous_progress_checksum_v0() != expected_previous_progress
            || link.row_revision_v0() == 0
            || link.row_checksum_v0() == [0; 32]
            || !sources.insert(*link.source_validation_id_v0().as_bytes())
            || !targets.insert(*link.target_binding_v0().validation_id().as_bytes())
            || link.source_validation_id_v0() == link.target_binding_v0().validation_id()
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "replay.inventory_link",
                "checkpointed replay link chain is incomplete or forked",
            ));
        }
        prior_progress = Some(progress);
        prior_checkpoint = link.checkpoint_checksum_v0().ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "replay.inventory_checkpoint",
                "checkpointed replay link lacks its checksum",
            )
        })?;
    }
    if prior_progress != Some(*final_progress.as_bytes()) {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "replay.inventory_final_progress",
            "checkpoint progress chain differs from the durable completion",
        ));
    }
    Ok(())
}

fn core_rehydrate_material_v0(
    inventory: &ConfirmedReplayInventoryV0,
    signed_entries: &[PocoNodeDeployedLabSignedReplayEntryV0],
    history: &Process2HistoryInventoryV0,
    final_progress: NonZeroDigestV0,
) -> Result<
    (
        AnchoredOrdinaryReplayArchivePlanV0,
        Vec<AnchoredOrdinarySignedReplayEntryV0>,
    ),
    PocoNodeDeployedLabProcess2RecoveryErrorV0,
> {
    let session = inventory.session_v0();
    let first = inventory.links_v0().first().ok_or_else(|| {
        PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "core.rehydrate_first_link",
            "complete replay inventory has no first link",
        )
    })?;
    let rehydrate_session_row_checksum = if session.is_activation_ready_v0() {
        let source_revision = session.activation_source_row_revision_v0().ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "core.rehydrate_activation_source_revision",
                "ActivationReady session lacks its DurableComplete predecessor revision",
            )
        })?;
        if source_revision.checked_add(1) != Some(session.row_revision_v0()) {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "core.rehydrate_activation_source_revision",
                "ActivationReady predecessor is not the exact row revision",
            ));
        }
        session.activation_source_row_checksum_v0().ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "core.rehydrate_activation_source_checksum",
                "ActivationReady session lacks its DurableComplete predecessor checksum",
            )
        })?
    } else {
        session.row_checksum_v0()
    };
    let plan = process2_try!(
        "core.rehydrate_plan",
        AnchoredOrdinaryReplayArchivePlanV0::new(
            session.core_config_ref_v0(),
            session.recovery_challenge_digest_v0(),
            session.archive_context_digest_v0(),
            session.archive_sequence_v0(),
            session.archive_record_digest_v0(),
            session.session_id_v0(),
            session.validation_store_id_v0(),
            session.expected_count_v0(),
            session.canonical_store_sequence_v0(),
            session.application_history_digest_v0(),
            session.initial_safety_revision_v0(),
            session.initial_safety_state_checksum_v0(),
            session.initial_safety_chain_checksum_v0(),
            session.initial_checkpoint_scope_v0(),
            session.initial_checkpoint_profile_ref_v0(),
            session.initial_checkpoint_generation_v0(),
            session.initial_checkpoint_checksum_v0(),
            first.previous_progress_checksum_v0(),
            *final_progress.as_bytes(),
            rehydrate_session_row_checksum,
        )
    );
    if signed_entries.len() != inventory.links_v0().len() {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "core.rehydrate_entry_count",
            "signed archive and checkpointed-link inventory lengths differ",
        ));
    }
    let mut entries = Vec::with_capacity(signed_entries.len());
    for (signed, link) in signed_entries.iter().zip(inventory.links_v0()) {
        let binding = link.target_binding_v0();
        if signed.proposal_v0().block().id().as_bytes() != binding.block_id().as_bytes() {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "core.rehydrate_entry_binding",
                "signed archive entry differs from its checkpointed link",
            ));
        }
        let block_id = BlockId::new(*binding.block_id().as_bytes());
        let source_artifact_checksum = *history
            .source_artifact_checksums
            .get(&block_id)
            .ok_or_else(|| {
                PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "core.rehydrate_source_artifact",
                    "checkpointed link lacks its fresh application artifact checksum",
                )
            })?;
        let target_core_id =
            ValidationId::new(block_id, View::new(binding.view()), binding.generation());
        let claim = process2_try!(
            "core.rehydrate_claim",
            AnchoredOrdinaryCheckpointedLinkClaimV0::new(
                link.session_id_v0(),
                link.cursor_v0(),
                *link.source_validation_id_v0().as_bytes(),
                *binding.validation_id().as_bytes(),
                target_core_id,
                *link.owner_id_v0().as_bytes(),
                link.source_store_sequence_v0(),
                link.source_row_revision_v0(),
                link.source_row_checksum_v0(),
                source_artifact_checksum,
                link.source_application_history_checksum_v0(),
                link.safety_revision_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "core.rehydrate_safety_revision",
                        "checkpointed link lacks Safety revision",
                    )
                })?,
                link.alias_closure_checksum_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "core.rehydrate_alias",
                        "checkpointed link lacks alias closure",
                    )
                })?,
                link.checkpoint_scope_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "core.rehydrate_checkpoint_scope",
                        "checkpointed link lacks scope",
                    )
                })?,
                link.checkpoint_profile_ref_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "core.rehydrate_checkpoint_profile",
                        "checkpointed link lacks profile",
                    )
                })?,
                link.checkpoint_predecessor_checksum_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "core.rehydrate_checkpoint_predecessor",
                        "checkpointed link lacks predecessor checksum",
                    )
                })?,
                link.checkpoint_generation_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "core.rehydrate_checkpoint_generation",
                        "checkpointed link lacks checkpoint generation",
                    )
                })?,
                link.checkpoint_checksum_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "core.rehydrate_checkpoint_checksum",
                        "checkpointed link lacks checkpoint checksum",
                    )
                })?,
                link.previous_progress_checksum_v0(),
                link.progress_checksum_v0().ok_or_else(|| {
                    PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                        "core.rehydrate_progress",
                        "checkpointed link lacks progress checksum",
                    )
                })?,
                link.row_revision_v0(),
                link.row_checksum_v0(),
            )
        );
        entries.push(AnchoredOrdinarySignedReplayEntryV0::new(
            signed.proposal_v0().clone(),
            signed.certificate_v0().clone(),
            claim,
        ));
    }
    Ok((plan, entries))
}

struct ExactProcess2RehydrateReconcilerV0<'a> {
    expected_safety: &'a SafetyState,
    expected_plan: AnchoredOrdinaryReplayArchivePlanV0,
    expected_entries: &'a [AnchoredOrdinarySignedReplayEntryV0],
    inventory: &'a ConfirmedReplayInventoryV0,
    validation_store: &'a SqliteProposalValidationStoreV0,
    validation_path: &'a Path,
    application: &'a DurableNativeApplicationV0,
    application_path: &'a Path,
    application_history_rows: &'a [ConfirmedDurableExecutionHistoryRowV0],
    calls: usize,
}

impl AnchoredOrdinaryRehydrateReconcilerV0 for ExactProcess2RehydrateReconcilerV0<'_> {
    fn reconcile_checkpointed_ordinary_replay_v0(
        &mut self,
        challenge: &AnchoredOrdinaryRehydrateChallengeV0,
    ) -> bool {
        self.calls = self.calls.saturating_add(1);
        challenge.safety_state_v0() == self.expected_safety
            && challenge.plan_v0() == self.expected_plan
            && challenge.entries_v0() == self.expected_entries
            && self
                .inventory
                .belongs_to_store_at_path_v0(self.validation_store, self.validation_path)
            && u64::try_from(self.application_history_rows.len()).ok()
                == Some(
                    self.inventory
                        .session_v0()
                        .canonical_terminal_row_count_v0(),
                )
            && self.application_history_rows.iter().all(|row| {
                row.belongs_to_application_at_path_v0(self.application, self.application_path)
            })
            && challenge
                .entries_v0()
                .iter()
                .zip(self.inventory.links_v0())
                .all(|(entry, link)| claim_matches_link_v0(entry.checkpointed_link_v0(), link))
    }
}

fn claim_matches_link_v0(
    claim: AnchoredOrdinaryCheckpointedLinkClaimV0,
    link: &ReplayLinkFactsV0,
) -> bool {
    let binding = link.target_binding_v0();
    let id = claim.target_core_validation_id_v0();
    claim.session_id_v0() == link.session_id_v0()
        && claim.cursor_v0() == link.cursor_v0()
        && claim.source_validation_store_id_v0() == *link.source_validation_id_v0().as_bytes()
        && claim.target_validation_store_id_v0() == *binding.validation_id().as_bytes()
        && id.block_id().as_bytes() == binding.block_id().as_bytes()
        && id.view().get() == binding.view()
        && id.generation() == binding.generation()
        && claim.owner_id_v0() == *link.owner_id_v0().as_bytes()
        && claim.source_store_sequence_v0() == link.source_store_sequence_v0()
        && claim.source_row_revision_v0() == link.source_row_revision_v0()
        && claim.source_row_checksum_v0() == link.source_row_checksum_v0()
        && claim.source_artifact_checksum_v0() != [0; 32]
        && claim.source_application_history_checksum_v0()
            == link.source_application_history_checksum_v0()
        && Some(claim.safety_revision_v0()) == link.safety_revision_v0()
        && Some(claim.alias_closure_checksum_v0()) == link.alias_closure_checksum_v0()
        && Some(claim.checkpoint_scope_v0()) == link.checkpoint_scope_v0()
        && Some(claim.checkpoint_profile_ref_v0()) == link.checkpoint_profile_ref_v0()
        && Some(claim.checkpoint_predecessor_checksum_v0())
            == link.checkpoint_predecessor_checksum_v0()
        && Some(claim.checkpoint_generation_v0()) == link.checkpoint_generation_v0()
        && Some(claim.checkpoint_checksum_v0()) == link.checkpoint_checksum_v0()
        && claim.previous_progress_checksum_v0() == link.previous_progress_checksum_v0()
        && Some(claim.progress_checksum_v0()) == link.progress_checksum_v0()
        && claim.link_row_revision_v0() == link.row_revision_v0()
        && claim.link_row_checksum_v0() == link.row_checksum_v0()
}

fn refresh_all_history_rows_v0(
    application: &DurableNativeApplicationV0,
    application_path: &Path,
    history: &Process2HistoryInventoryV0,
) -> Result<Vec<ConfirmedDurableExecutionHistoryRowV0>, PocoNodeDeployedLabProcess2RecoveryErrorV0>
{
    if history.recovered.len() != history.executed.len()
        || history.recovered.len() != history.history_checksums.len()
        || history.recovered.len() != history.source_artifact_checksums.len()
    {
        return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
            "application.history_inventory_shape",
            "application history maps have different cardinalities",
        ));
    }
    let mut rows = Vec::with_capacity(history.recovered.len());
    for (block_id, recovered) in &history.recovered {
        let executed = history.executed.get(block_id).ok_or_else(|| {
            PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "application.history_executed",
                "fresh history inventory lacks its execution artifact",
            )
        })?;
        let row = process2_try!(
            "application.history_refresh",
            application.confirm_durable_execution_history_row_v0(executed)
        );
        let parent = process2_try!("application.history_refresh_parent", row.parent_head_v0());
        let target = process2_try!("application.history_refresh_target", row.target_head_v0());
        let checksum = history_row_digest_v0(&recovered.binding, &row)?;
        if !row.belongs_to_application_at_path_v0(application, application_path)
            || row.store_id_v0() != application.config_v0().store_id()
            || parent != *recovered.binding.parent()
            || target != recovered.application_head
            || row.status_v0() != recovered.status
            || checksum != history.history_checksums[block_id]
            || row.artifact_digest_v0() != history.source_artifact_checksums[block_id]
        {
            return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                "application.history_refresh_join",
                "fresh application history differs from the frozen complete inventory",
            ));
        }
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(all(test, feature = "lab-validator-runtime-test-support"))]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::{tempdir, TempDir};
    use trnm_consensus_core::leader_for;
    use trnm_consensus_external_watermark::ReplayBoundTimeoutProducer;
    use trnm_consensus_signer_journal::{
        ExternalWatermarkErrorV0, SignatureProducerErrorV0, SignatureProducerV0,
        SignatureRequestV0, SignerWatermarkV0,
    };
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockHeader, BlockKind, EvidenceRoot, Height, PayloadDigest,
        ProposalWitnessV0, QcReferenceV0, QuorumCertificate, ReceiptsRoot, SignatureBytes,
        StateRoot, TimeoutCertificateV0, TimeoutEntryV0, TimeoutVote, Vote,
    };
    use trnm_native_execution_v0::{
        AuthorizedSignerV0, CanonicalLabNativeApplicationConfigInputsV0,
    };

    use super::*;

    #[test]
    fn inert_process2_owner_has_no_public_activation_bypass_v1() {
        let source = include_str!("deployed_lab_process2_recovery.rs");
        let normal_source = source
            .split("#[cfg(all(test, feature = \"lab-validator-runtime-test-support\"))]")
            .next()
            .expect("normal-build source precedes the test module");
        let public_bypass = ["pub fn into_recovered_ordinary_", "runtime_v1"].concat();
        assert!(!normal_source.contains(&public_bypass));
        assert!(!normal_source.contains("activate_for_lab_authority_v1"));
        assert!(normal_source.contains("fn prepare_passive_catchup_v1"));
        assert!(normal_source.contains("struct PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1"));
        assert!(normal_source.contains("struct PocoNodeDeployedLabProcess2CaughtUpOwnerV1"));
        assert!(normal_source.contains("pub fn revalidate_zero_delta_caught_up_v1("));
        assert!(normal_source.contains("fn activate_after_recovery_start_v1("));
        let zero_delta_join = normal_source
            .find("fn join_zero_delta_restart_cut_v1(")
            .expect("normal build contains the exact zero-delta consuming join");
        let passive_prepare_entry = normal_source
            .find("fn prepare_passive_catchup_v1(")
            .expect("normal build contains the private passive transition");
        assert!(zero_delta_join < passive_prepare_entry);
        let zero_delta_join_source = &normal_source[zero_delta_join..passive_prepare_entry];
        for forbidden in [
            "prepare_passive_catchup_v1",
            "confirm_replay_activation_ready_v0",
            "reconcile_and_activate_checkpointed_ordinary_v0",
            ".activate_v0()",
        ] {
            assert!(!zero_delta_join_source.contains(forbidden));
        }
        let prepare = normal_source
            .find("fn prepare_passive_catchup_inner_v1(")
            .expect("passive preparation remains present");
        let passive_owner = normal_source
            .find("struct PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1")
            .expect("passive owner remains present");
        let post_start = normal_source
            .find("fn activate_after_recovery_start_v1(")
            .expect("post-RecoveryStart activation remains present");
        let activated_facts = normal_source
            .find("pub struct PocoNodeDeployedLabProcess2ActivatedFactsV1")
            .expect("activated facts remain after the private post-start boundary");
        assert!(
            prepare < passive_owner && passive_owner < post_start && post_start < activated_facts
        );
        assert!(!normal_source[prepare..passive_owner].contains(".activate_v0()"));
        assert!(normal_source[post_start..activated_facts].contains("signer.activate_v0()"));
        let caught_up_owner_source = &normal_source[passive_owner..post_start];
        assert!(caught_up_owner_source.contains("recovered:"));
        assert!(caught_up_owner_source.contains("facts:"));
        assert!(!caught_up_owner_source.contains("passive:"));
        let borrowed_revalidation = caught_up_owner_source
            .find("pub fn revalidate_zero_delta_caught_up_v1(")
            .expect("caught-up owner retains a borrowed durable-head audit");
        let borrowed_revalidation = &caught_up_owner_source[borrowed_revalidation..];
        assert!(borrowed_revalidation.contains("confirm_zero_delta_restart_cut_facts_v1"));
        for forbidden in [
            "prepare_passive_catchup_v1",
            "confirm_replay_activation_ready_v0",
            "signer.activate_v0()",
            "into_parts_v0",
        ] {
            assert!(!borrowed_revalidation.contains(forbidden));
        }
        let post_start_source = &normal_source[post_start..activated_facts];
        let recovery_start_join = post_start_source
            .find("recovery_start.caught_up_cut_digest != caught_up_cut_digest")
            .expect("RecoveryStart digest is checked");
        let passive_after_start = post_start_source
            .find("recovered.prepare_passive_catchup_v1()")
            .expect("passive preparation occurs only inside the post-Start boundary");
        let signer_after_start = post_start_source
            .find("signer.activate_v0()")
            .expect("signer activation remains inside the post-Start boundary");
        assert!(
            recovery_start_join < passive_after_start && passive_after_start < signer_after_start
        );
        for forbidden in [
            "pub fn into_parts",
            "pub(crate) fn into_parts",
            "pub fn core",
            "pub fn signer",
            "pub fn startup_timer",
            "impl Clone for PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1",
        ] {
            assert!(!normal_source[passive_owner..post_start].contains(forbidden));
        }
        assert!(!DEPLOYED_LAB_PROCESS2_ACTIVATION_V0);
    }

    struct TestOnlyPassiveCaughtUpOwnerV1<W: ExternalMonotonicWatermarkV0> {
        passive: PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1<W>,
        caught_up_cut_digest: [u8; 32],
    }

    impl<W: ExternalMonotonicWatermarkV0> TestOnlyPassiveCaughtUpOwnerV1<W> {
        fn activate_after_recovery_start_v1(
            self,
            recovery_start: PocoNodeDeployedLabProcess2RecoveryStartAuthorityV1,
        ) -> Result<
            PocoNodeDeployedLabRecoveredOrdinaryRuntimeV1<W>,
            PocoNodeDeployedLabProcess2RecoveryErrorV0,
        > {
            if self.caught_up_cut_digest == [0; 32]
                || recovery_start.certificate_sha256 == [0; 32]
                || recovery_start.caught_up_cut_digest != self.caught_up_cut_digest
            {
                return Err(PocoNodeDeployedLabProcess2RecoveryErrorV0::message(
                    "activation.recovery_start_join",
                    "test-only RecoveryStart differs from the passive cut",
                ));
            }
            activate_passive_after_recovery_start_v1(self.passive)
        }
    }

    fn zero_delta_caught_up_and_recovery_start_for_test_v1<W: ExternalMonotonicWatermarkV0>(
        passive: PocoNodeDeployedLabProcess2PassiveCatchupOwnerV1<W>,
    ) -> (
        TestOnlyPassiveCaughtUpOwnerV1<W>,
        PocoNodeDeployedLabProcess2RecoveryStartAuthorityV1,
    ) {
        let cut_digest = hash_v0(
            b"trnm.poco-node.test-only.process2-zero-delta-caught-up.v1",
            &[
                &passive.facts.activation_binding_digest,
                &passive.facts.activation_row_checksum,
                &passive.checkpoint.checkpoint_checksum(),
            ],
        );
        let certificate_sha256 = hash_v0(
            b"trnm.poco-node.test-only.process2-recovery-start.v1",
            &[&cut_digest],
        );
        (
            TestOnlyPassiveCaughtUpOwnerV1 {
                passive,
                caught_up_cut_digest: cut_digest,
            },
            PocoNodeDeployedLabProcess2RecoveryStartAuthorityV1 {
                caught_up_cut_digest: cut_digest,
                certificate_sha256,
            },
        )
    }

    #[derive(Debug, Clone, Default)]
    struct SharedWatermarkV0 {
        value: Arc<Mutex<Option<SignerWatermarkV0>>>,
    }

    impl ExternalMonotonicWatermarkV0 for SharedWatermarkV0 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            let value = *self
                .value
                .lock()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            let mut value = self
                .value
                .lock()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            if *value != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            match expected {
                None if target.sequence() == 0 => {}
                Some(previous)
                    if previous.scope() == target.scope()
                        && previous.journal_id() == target.journal_id()
                        && previous.sequence().checked_add(1) == Some(target.sequence()) => {}
                _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
            }
            *value = Some(target);
            Ok(())
        }
    }

    struct ExactProducerV0(SigningKey);

    impl SignatureProducerV0 for ExactProducerV0 {
        fn sign(
            &mut self,
            request: SignatureRequestV0<'_>,
        ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
            Ok(SignatureBytes::from_array(
                self.0.sign(request.signing_root().as_bytes()).to_bytes(),
            ))
        }
    }

    struct Process2FixtureV0 {
        directory: TempDir,
        watermark: SharedWatermarkV0,
        core_config: CoreConfig,
        entries: Vec<PocoNodeDeployedLabSignedReplayEntryV0>,
    }

    #[test]
    fn clean_cut_process2_repeats_as_the_same_inert_process3_owner_v0() {
        run_large_stack_test_v0(
            "deployed-lab-process2-repeat",
            assert_clean_cut_process2_repeats_as_the_same_inert_process3_owner_v0,
        );
    }

    fn assert_clean_cut_process2_repeats_as_the_same_inert_process3_owner_v0() {
        let fixture = process2_fixture_v0(false, true);
        let first_application_config = process2_application_config_v0(&fixture.core_config);
        let first = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            first_application_config,
            fixture.entries.clone(),
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark.clone()),
        )
        .expect("close exact process2 replay");
        let first_facts = first.facts_v0();
        assert_eq!(first_facts.replayed_link_count_v0(), 1);
        assert_eq!(first_facts.unconfirmed_speculative_tail_count_v0(), 0);
        assert_ne!(first_facts.rehydrate_digest_v0(), [0; 32]);
        assert_one_vote_one_timeout_inventory_v1(first_facts);
        drop(first);

        let process3_application_config = process2_application_config_v0(&fixture.core_config);
        let process3 = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config,
            process3_application_config,
            fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark),
        )
        .expect("process3 re-enters the same fully checkpointed inert owner");
        assert_eq!(process3.facts_v0(), first_facts);
        assert!(DEPLOYED_LAB_PROCESS2_CLEAN_CUT_RECOVERY_V0);
        assert!(!DEPLOYED_LAB_PROCESS2_PENDING_SIGN_REPLAY_V0);
        assert!(!DEPLOYED_LAB_PROCESS2_ACTIVATION_V0);
    }

    #[test]
    fn process2_zero_delta_restart_cut_join_is_read_only_and_replay_fenced_v1() {
        run_large_stack_test_v0(
            "deployed-lab-process2-zero-delta-join-v1",
            assert_process2_zero_delta_restart_cut_join_is_read_only_and_replay_fenced_v1,
        );
    }

    fn assert_process2_zero_delta_restart_cut_join_is_read_only_and_replay_fenced_v1() {
        let fixture = process2_fixture_v0(false, false);
        let recovered = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark),
        )
        .expect("close exact process2 replay");
        let expected = zero_delta_restart_cut_for_recovered_v1(&recovered);
        let expected_fields = expected.fields_v1();
        let mut caught_up = recovered
            .into_zero_delta_caught_up_v1(expected)
            .expect("freshly confirm the exact zero-delta RestartCut");
        let facts = caught_up.facts_v1();
        caught_up
            .revalidate_zero_delta_caught_up_v1()
            .expect("fresh borrowed zero-delta audit remains read-only");
        assert_eq!(caught_up.facts_v1(), facts);
        assert_eq!(facts.restart_cut_v1(), expected);
        assert_eq!(facts.process2_v1().replayed_link_count_v0(), 1);
        assert_ne!(facts.node_facts_sha256_v1(), [0; 32]);
        assert_ne!(facts.signer_inventory_invariant_sha256_v1(), [0; 32]);
        assert_eq!(
            facts.artifact_sha256_v1(),
            <[u8; 32]>::from(Sha256::digest(facts.artifact_bytes_v1()))
        );
        assert_eq!(
            caught_up
                .recovered
                .validation_store
                .replay_session_presence_v0()
                .expect("inspect still-fenced replay session"),
            ReplaySessionPresenceV0::DurableReplayComplete {
                session_id: facts.process2_v1().session_id_v0(),
                expected_count: facts.process2_v1().replayed_link_count_v0(),
            }
        );
        let signer_facts = caught_up
            .recovered
            .signer
            .confirm_node_checkpoint_head_exact_v0()
            .expect("signer remains pinned before RecoveryStart");
        assert!(signer_facts.belongs_to_pinned_journal_at_path_v0(
            &caught_up.recovered.signer,
            &caught_up.recovered.paths.signer,
        ));
        assert_eq!(
            signer_facts.exact_watermark(),
            expected_fields.signer_exact_watermark
        );
        assert!(!DEPLOYED_LAB_PROCESS2_ACTIVATION_V0);
    }

    #[test]
    fn process2_recovered_ordinary_runtime_v1_joins_all_owners_without_driving_startup_timer() {
        run_large_stack_test_v0(
            "deployed-lab-process2-runtime-bridge-v1",
            assert_process2_recovered_ordinary_runtime_v1_joins_all_owners_without_driving_startup_timer,
        );
    }

    fn assert_process2_recovered_ordinary_runtime_v1_joins_all_owners_without_driving_startup_timer(
    ) {
        let fixture = process2_fixture_v0(false, true);
        let recovered = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark),
        )
        .expect("close exact process2 replay");
        let recovery_facts = recovered.facts_v0();
        let mut passive = recovered
            .prepare_passive_catchup_v1()
            .expect("freshly join exact process2 cut without activating signer");
        let passive_facts = passive.facts;
        assert_eq!(passive_facts.recovery, recovery_facts);
        assert_one_vote_one_timeout_inventory_v1(recovery_facts);
        assert_eq!(
            passive_facts.signer_exact_watermark,
            recovery_facts.signer_exact_watermark_v1()
        );
        assert_eq!(
            passive_facts.signer_inventory_digest,
            recovery_facts.signer_inventory_digest_v1()
        );
        assert_eq!(passive_facts.signer_durable_vote_intent_count, 1);
        assert_eq!(passive_facts.signer_durable_timeout_intent_count, 1);
        assert_eq!(passive_facts.signer_signed_vote_intent_count, 1);
        assert_eq!(passive_facts.signer_signed_timeout_intent_count, 1);
        assert_ne!(passive_facts.activation_binding_digest, [0; 32]);
        assert_ne!(passive_facts.activation_row_checksum, [0; 32]);
        assert!(passive_facts.activation_row_revision > 0);
        assert_eq!(
            passive_facts.application_parent_height,
            passive_facts
                .recovery
                .replayed_link_count_v0()
                .checked_add(3)
                .expect("fixture height")
        );

        {
            let parts = &mut passive;
            assert_eq!(
                parts.startup_timer.epoch_v0(),
                parts.core.safety_state().epoch()
            );
            assert_eq!(
                parts.startup_timer.view_v0(),
                parts.core.safety_state().current_view()
            );
            assert_eq!(
                parts.application_head.block_id().as_bytes(),
                parts
                    .core
                    .safety_state()
                    .high_qc()
                    .qc_ref()
                    .block_id()
                    .as_bytes()
            );
            assert_eq!(
                parts.application_head.height().get(),
                parts.core.safety_state().high_qc().qc_ref().height().get()
            );
            assert_eq!(
                u64::try_from(parts.pending_executions.len()).expect("prepared count"),
                passive_facts.prepared_execution_count
            );
            assert!(parts.application_overlay_ref.is_some_and(|overlay| {
                overlay.block_id() == parts.core.safety_state().high_qc().qc_ref().block_id()
            }));
            assert_eq!(
                parts.checkpoint.generation(),
                passive_facts.recovery.final_checkpoint_generation_v0()
            );
            assert_eq!(
                parts.checkpoint.checkpoint_checksum(),
                passive_facts.recovery.final_checkpoint_checksum_v0()
            );
            assert!(parts.activation_ready.belongs_to_store_at_path_v0(
                &parts.validation_store,
                parts.validation_store.path()
            ));
            assert_eq!(
                parts
                    .validation_store
                    .replay_session_presence_v0()
                    .expect("inspect ActivationReady"),
                ReplaySessionPresenceV0::ActivationReady {
                    session_id: recovery_facts.session_id_v0(),
                    expected_count: recovery_facts.replayed_link_count_v0(),
                }
            );

            // Exact retry is readback-only: it returns the same row and does not
            // change the retained startup timer or signer head.
            let binding = parts.activation_ready.binding_v0();
            let row_revision = parts.activation_ready.row_revision_v0();
            let row_checksum = parts.activation_ready.row_checksum_v0();
            let retry_inventory = parts
                .validation_store
                .confirm_replay_inventory_v0()
                .expect("fresh ActivationReady inventory");
            let retry = parts
                .validation_store
                .confirm_replay_activation_ready_v0(retry_inventory, binding)
                .expect("exact ActivationReady retry");
            assert_eq!(retry.row_revision_v0(), row_revision);
            assert_eq!(retry.row_checksum_v0(), row_checksum);
            // The signer-journal layer proves that swapping Vote/TimeoutVote
            // kind counts with the same total changes this digest.  This join
            // proves that any such different authenticated digest cannot
            // replace the already committed ActivationReady cut.
            let inventory_conflicting_binding = readdress_activation_binding_v1(
                binding,
                digest_distinct_from_v1(binding.signer_inventory_digest_v1()),
                NonZeroDigestV0::new(binding.selected_replay_digest_v0())
                    .expect("selected replay digest"),
            );
            let inventory_conflict_source = parts
                .validation_store
                .confirm_replay_inventory_v0()
                .expect("fresh inventory before signer-inventory conflict");
            assert_eq!(
                parts
                    .validation_store
                    .confirm_replay_activation_ready_v0(
                        inventory_conflict_source,
                        inventory_conflicting_binding,
                    )
                    .expect_err("foreign signer-inventory digest must fail closed")
                    .code(),
                trnm_native_application_sqlite::ValidationStoreErrorCodeV0::Duplicate
            );
            let conflicting_binding = readdress_activation_binding_v1(
                binding,
                NonZeroDigestV0::new(binding.signer_inventory_digest_v1())
                    .expect("signer inventory digest"),
                digest_distinct_from_v1(binding.selected_replay_digest_v0()),
            );
            let conflict_inventory = parts
                .validation_store
                .confirm_replay_inventory_v0()
                .expect("fresh inventory before selected-replay conflict");
            assert_eq!(
                parts
                    .validation_store
                    .confirm_replay_activation_ready_v0(conflict_inventory, conflicting_binding)
                    .expect_err("different selected replay digest must fail closed")
                    .code(),
                trnm_native_application_sqlite::ValidationStoreErrorCodeV0::Duplicate
            );
            let signer_facts = parts
                .signer
                .confirm_node_checkpoint_head_exact_v0()
                .expect("signer remains pinned after passive preparation");
            assert!(signer_facts
                .belongs_to_pinned_journal_at_path_v0(&parts.signer, parts.signer.path(),));
            assert_eq!(
                parts.startup_timer.view_v0(),
                passive_facts.startup_timer_view,
                "the typed timer remains retained and was never converted into an effect",
            );
        }

        let (caught_up, recovery_start) =
            zero_delta_caught_up_and_recovery_start_for_test_v1(passive);
        let recovered_runtime = caught_up
            .activate_after_recovery_start_v1(recovery_start)
            .expect("test-only caught-up plus RecoveryStart join activates last");
        let bridge_facts = recovered_runtime.facts_v1();
        let activated_facts = bridge_facts.activation_v1();
        assert_eq!(activated_facts.recovery_v0(), recovery_facts);
        assert_eq!(bridge_facts.activation_v1(), activated_facts);
        assert_eq!(
            bridge_facts.runtime_v1(),
            recovered_runtime.runtime_facts_v1()
        );
        assert_eq!(
            recovered_runtime.startup_timer.epoch_v0(),
            activated_facts.startup_timer_epoch_v1()
        );
        assert_eq!(
            recovered_runtime.startup_timer.view_v0(),
            activated_facts.startup_timer_view_v1()
        );
        let proposal_binding = recovered_runtime
            .runtime
            .proposal_binding_v0()
            .expect("bridge retains one exact ready proposal binding");
        assert_eq!(
            proposal_binding.current_view_v0(),
            recovered_runtime.startup_timer.view_v0()
        );
        assert_eq!(
            proposal_binding.high_qc_v0().qc_ref().block_id(),
            bridge_facts.runtime_v1().proposal_parent_block_id_v0()
        );
        assert!(!DEPLOYED_LAB_PROCESS2_ACTIVATION_V0);
    }

    #[test]
    fn process2_recovered_ordinary_runtime_v1_rejects_foreign_activation_owner() {
        run_large_stack_test_v0(
            "deployed-lab-process2-runtime-foreign-owner-v1",
            assert_process2_recovered_ordinary_runtime_v1_rejects_foreign_activation_owner,
        );
    }

    fn assert_process2_recovered_ordinary_runtime_v1_rejects_foreign_activation_owner() {
        let first_fixture = process2_fixture_v0(false, true);
        let second_fixture = process2_fixture_v0(false, true);
        let first_recovered = recover_deployed_lab_process2_v0(
            first_fixture.directory.path(),
            first_fixture.core_config.clone(),
            process2_application_config_v0(&first_fixture.core_config),
            first_fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(first_fixture.watermark),
        )
        .expect("close first exact process2 replay");
        let second_recovered = recover_deployed_lab_process2_v0(
            second_fixture.directory.path(),
            second_fixture.core_config.clone(),
            process2_application_config_v0(&second_fixture.core_config),
            second_fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(second_fixture.watermark),
        )
        .expect("close second exact process2 replay");
        let mut first = first_recovered
            .prepare_passive_catchup_v1()
            .expect("prepare first exact passive process2 cut");
        let mut second = second_recovered
            .prepare_passive_catchup_v1()
            .expect("prepare second exact passive process2 cut");
        std::mem::swap(&mut first.activation_ready, &mut second.activation_ready);

        let (caught_up, recovery_start) =
            zero_delta_caught_up_and_recovery_start_for_test_v1(first);
        let error = caught_up
            .activate_after_recovery_start_v1(recovery_start)
            .expect_err("a foreign ActivationReady owner must fail closed");
        assert_eq!(error.stage_v0(), "runtime_bridge.activation_join");
    }

    #[test]
    fn process2_recovered_ordinary_runtime_v1_rejects_selected_overlay_mutant() {
        run_large_stack_test_v0(
            "deployed-lab-process2-runtime-overlay-mutant-v1",
            assert_process2_recovered_ordinary_runtime_v1_rejects_selected_overlay_mutant,
        );
    }

    fn assert_process2_recovered_ordinary_runtime_v1_rejects_selected_overlay_mutant() {
        let fixture = process2_fixture_v0(false, true);
        let recovered = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark),
        )
        .expect("close exact process2 replay");
        let mut passive = recovered
            .prepare_passive_catchup_v1()
            .expect("prepare exact passive process2 cut");
        passive.application_overlay_ref = None;

        let (caught_up, recovery_start) =
            zero_delta_caught_up_and_recovery_start_for_test_v1(passive);
        let error = caught_up
            .activate_after_recovery_start_v1(recovery_start)
            .expect_err("a selected-overlay mutant must fail closed");
        assert_eq!(error.stage_v0(), "runtime_bridge.high_qc_execution");
    }

    #[test]
    fn process2_activation_v1_process_loss_after_cas_exactly_resumes() {
        run_large_stack_test_v0(
            "deployed-lab-process2-activation-resume-v1",
            assert_process2_activation_v1_process_loss_after_cas_exactly_resumes,
        );
    }

    fn assert_process2_activation_v1_process_loss_after_cas_exactly_resumes() {
        let fixture = process2_fixture_v0(false, true);
        let first = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries.clone(),
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark.clone()),
        )
        .expect("close exact process2 replay before activation crash");
        let first_facts = first.facts_v0();
        assert_one_vote_one_timeout_inventory_v1(first_facts);
        let error = first
            .prepare_passive_catchup_inner_v1(Some(Process2CrashHookV0::ActivationReadyCommitted))
            .expect_err("process loss after ActivationReady CAS must stop before Core/signer");
        assert_eq!(error.stage_v0(), "test.process_loss");

        let reopened = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark),
        )
        .expect("ActivationReady predecessor must rehydrate the same inert owner");
        assert_eq!(reopened.facts_v0(), first_facts);
        let activation_session = reopened.replay_inventory.session_v0();
        assert!(activation_session.is_activation_ready_v0());
        let expected_binding_digest = activation_session
            .activation_binding_digest_v0()
            .expect("ActivationReady binding digest");
        let expected_row_revision = activation_session.row_revision_v0();
        assert_eq!(
            activation_session
                .activation_source_row_revision_v0()
                .and_then(|revision| revision.checked_add(1)),
            Some(expected_row_revision)
        );
        assert_ne!(
            activation_session
                .activation_source_row_checksum_v0()
                .expect("ActivationReady predecessor checksum"),
            [0; 32]
        );

        let mut passive = reopened.prepare_passive_catchup_v1().expect(
            "same selected replay binding must resume idempotently without signer activation",
        );
        assert_eq!(
            passive.facts.activation_binding_digest,
            expected_binding_digest
        );
        assert_eq!(
            passive.facts.activation_row_revision, expected_row_revision,
            "exact ActivationReady retry must not advance the row again",
        );
        assert_eq!(
            passive.facts.signer_exact_watermark,
            first_facts.signer_exact_watermark_v1(),
            "ack-loss resume must preserve the exact signer watermark",
        );
        assert_eq!(
            passive.facts.signer_inventory_digest,
            first_facts.signer_inventory_digest_v1(),
            "ack-loss resume must preserve the signer lifetime inventory",
        );
        let signer_facts = passive
            .signer
            .confirm_node_checkpoint_head_exact_v0()
            .expect("resumed passive signer remains pinned");
        assert!(signer_facts
            .belongs_to_pinned_journal_at_path_v0(&passive.signer, passive.signer.path(),));
    }

    #[test]
    fn process2_activation_v1_predecessor_checksum_tamper_fails_reopen() {
        run_large_stack_test_v0(
            "deployed-lab-process2-activation-predecessor-tamper-v1",
            assert_process2_activation_v1_predecessor_checksum_tamper_fails_reopen,
        );
    }

    fn assert_process2_activation_v1_predecessor_checksum_tamper_fails_reopen() {
        let fixture = process2_fixture_v0(false, true);
        let first = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries.clone(),
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark.clone()),
        )
        .expect("close exact process2 replay before predecessor tamper");
        first
            .prepare_passive_catchup_inner_v1(Some(Process2CrashHookV0::ActivationReadyCommitted))
            .expect_err("stop after durable ActivationReady CAS");
        let paths = existing_paths_v0(fixture.directory.path()).expect("resolve exact paths");
        let connection = rusqlite::Connection::open(&paths.validation)
            .expect("open validation database for single-field mutant");
        assert_eq!(
            connection
                .execute(
                    "UPDATE proposal_validation_replay_session_v0
                     SET activation_source_row_checksum = ?1 WHERE singleton = 1",
                    rusqlite::params![[0xD7_u8; 32].as_slice()],
                )
                .expect("mutate only the predecessor checksum"),
            1
        );
        drop(connection);

        let error = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark),
        )
        .expect_err("row-checksum-bound predecessor substitution must fail closed");
        assert_eq!(error.stage_v0(), "validation.open_existing");
    }

    #[test]
    fn every_process2_cursor_reopens_after_exact_process_loss_v0() {
        run_large_stack_test_v0(
            "deployed-lab-process2-cursor-reopen",
            assert_every_process2_cursor_reopens_after_exact_process_loss_v0,
        );
    }

    fn assert_every_process2_cursor_reopens_after_exact_process_loss_v0() {
        let fixture = process2_fixture_v0(false, true);
        for hook in [
            Process2CrashHookV0::SessionOpened,
            Process2CrashHookV0::LinkReserved,
            Process2CrashHookV0::CoreDelivered,
            Process2CrashHookV0::SafetyPersisted,
            Process2CrashHookV0::SafetyClosed,
            Process2CrashHookV0::AliasClosed,
            Process2CrashHookV0::ExternalCheckpointAdvanced,
            Process2CrashHookV0::Checkpointed,
        ] {
            let error = recover_deployed_lab_process2_inner_v0(
                fixture.directory.path(),
                fixture.core_config.clone(),
                process2_application_config_v0(&fixture.core_config),
                fixture.entries.clone(),
                |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark.clone()),
                Some(hook),
            )
            .expect_err("injected process loss must stop before owner release");
            assert_eq!(
                error.stage_v0(),
                if hook == Process2CrashHookV0::ExternalCheckpointAdvanced {
                    "replay.checkpoint"
                } else {
                    "test.process_loss"
                },
                "unexpected exact-reopen stage after {hook:?}",
            );
        }
        let recovered = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark),
        )
        .expect("fully checkpointed cursor reopens after every durable stage");
        assert_eq!(recovered.facts_v0().replayed_link_count_v0(), 1);
        assert_ne!(recovered.facts_v0().final_checkpoint_checksum_v0(), [0; 32]);
    }

    #[test]
    fn process2_rejects_pending_sign_without_modifying_replay_sidecar_v0() {
        run_large_stack_test_v0(
            "deployed-lab-process2-pending-sign",
            assert_process2_rejects_pending_sign_without_modifying_replay_sidecar_v0,
        );
    }

    fn assert_process2_rejects_pending_sign_without_modifying_replay_sidecar_v0() {
        let fixture = process2_fixture_v0(true, true);
        let error = recover_deployed_lab_process2_v0(
            fixture.directory.path(),
            fixture.core_config.clone(),
            process2_application_config_v0(&fixture.core_config),
            fixture.entries,
            |_path| Ok::<_, ExternalWatermarkErrorV0>(fixture.watermark),
        )
        .expect_err("pending-sign cut must remain fail-closed");
        assert_eq!(
            error.stage_v0(),
            "safety.pending_sign_requires_network_replay"
        );
        let paths = existing_paths_v0(fixture.directory.path()).expect("reopen exact paths");
        let scope = ProposalValidationStoreScopeV0::new(hash_v0(
            PROPOSAL_SCOPE_DOMAIN_V0,
            &[
                fixture.core_config.validator_set().id().as_bytes(),
                fixture.core_config.local_validator().as_bytes(),
            ],
        ))
        .expect("derive exact validation scope");
        let mut validation = SqliteProposalValidationStoreV0::open(
            &paths.validation,
            scope,
            MINIMUM_TAKEOVER_VALIDATION_SEQUENCE_V0,
        )
        .expect("reopen untouched validation store");
        assert_eq!(
            validation
                .replay_session_presence_v0()
                .expect("inspect untouched replay sidecar"),
            ReplaySessionPresenceV0::None
        );
    }

    fn run_large_stack_test_v0(name: &str, test: fn()) {
        let result = std::thread::Builder::new()
            .name(name.to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(test)
            .expect("spawn bounded large-stack process2 test")
            .join();
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn process2_application_config_v0(core: &CoreConfig) -> NativeApplicationConfigV0 {
        let operator = SigningKey::from_bytes(&[0x51; 32]);
        let signer = AuthorizedSignerV0::new(
            "did:operator:anchor-test",
            "operator",
            hex_v0(&operator.verifying_key().to_bytes()),
        )
        .expect("construct deterministic independent application signer");
        let inputs = CanonicalLabNativeApplicationConfigInputsV0::new(
            "anchor-takeover-test-001",
            [0x91; 32],
            [0x92; 32],
            [0x93; 32],
            [0x94; 32],
            core.local_validator(),
            core.validator_set().clone(),
            *core.consensus_parameters(),
            vec![signer],
            "did:operator:anchor-test",
        )
        .expect("construct exact deterministic application inputs");
        NativeApplicationConfigV0::from_canonical_lab_inputs_v0(inputs)
            .expect("derive exact recovery application config")
    }

    fn zero_delta_restart_cut_for_recovered_v1<W: ExternalMonotonicWatermarkV0>(
        recovered: &PocoNodeDeployedLabProcess2RecoveryOwnerV0<W>,
    ) -> PocoNodeDeployedLabZeroDeltaRestartCutV1 {
        let safety = recovered.core.challenge_v0().safety_state_v0();
        let finalized = safety.finalized();
        let applied = safety.application_applied();
        let high_qc = safety.high_qc().qc_ref();
        let committed = recovered
            .application
            .confirmed_committed_head_v0()
            .expect("read exact committed application cut");
        let session = recovered.replay_inventory.session_v0();
        let process2 = recovered.facts_v0();
        let fields = PocoNodeDeployedLabZeroDeltaRestartCutFieldsV1 {
            restart_cut_artifact_sha256: [0xa5; 32],
            local_validator: recovered.core_config.local_validator(),
            validator_set_id: recovered.core_config.validator_set().id(),
            epoch: safety.epoch(),
            current_view: safety.current_view(),
            direct_high_qc: high_qc,
            proposal_parent_height: high_qc.height().get(),
            proposal_parent_block_id: high_qc.block_id(),
            finalized_height: finalized.height().get(),
            finalized_block_id: finalized.block_id(),
            finalized_chain_root: *recovered.core.finalized_chain_root_v0().as_bytes(),
            application_height: applied.height().get(),
            application_block_id: applied.block_id(),
            application_state_root: StateRoot::new(*committed.state_root().as_bytes()),
            restart_checkpoint_generation: session.initial_checkpoint_generation_v0(),
            restart_checkpoint_canonical_sha256: Sha256::digest(
                recovered.restart_checkpoint.encode_canonical(),
            )
            .into(),
            restart_safety_revision: session.initial_safety_revision_v0(),
            restart_safety_state_record_checksum: session.initial_safety_state_checksum_v0(),
            restart_safety_chain_checksum: session.initial_safety_chain_checksum_v0(),
            signer_exact_watermark: process2.signer_exact_watermark_v1(),
            signer_durable_vote_intent_count: process2.signer_durable_vote_intent_count_v1(),
            signer_durable_timeout_intent_count: process2.signer_durable_timeout_intent_count_v1(),
            signer_signed_vote_intent_count: process2.signer_signed_vote_intent_count_v1(),
            signer_signed_timeout_intent_count: process2.signer_signed_timeout_intent_count_v1(),
            signer_inventory_digest: process2.signer_inventory_digest_v1(),
        };
        PocoNodeDeployedLabZeroDeltaRestartCutV1::new(fields).unwrap_or_else(|error| {
            panic!(
                "construct exact authority-free RestartCut projection: {error:?}; fields={fields:?}"
            )
        })
    }

    fn hex_v0(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        value
    }

    fn digest_distinct_from_v1(mut value: [u8; 32]) -> NonZeroDigestV0 {
        value[0] ^= 0x80;
        if value == [0; 32] {
            value[0] = 1;
        }
        NonZeroDigestV0::new(value).expect("mutant digest remains nonzero")
    }

    fn assert_one_vote_one_timeout_inventory_v1(facts: PocoNodeDeployedLabProcess2RecoveryFactsV0) {
        assert_eq!(facts.signer_durable_vote_intent_count_v1(), 1);
        assert_eq!(facts.signer_durable_timeout_intent_count_v1(), 1);
        assert_eq!(facts.signer_signed_vote_intent_count_v1(), 1);
        assert_eq!(facts.signer_signed_timeout_intent_count_v1(), 1);
        assert_eq!(facts.signer_exact_watermark_v1().sequence(), 4);
        assert_ne!(facts.signer_inventory_digest_v1(), [0; 32]);
    }

    fn readdress_activation_binding_v1(
        binding: ReplayActivationBindingV0,
        signer_inventory_digest: NonZeroDigestV0,
        selected_replay_digest: NonZeroDigestV0,
    ) -> ReplayActivationBindingV0 {
        ReplayActivationBindingV0::new(
            NonZeroDigestV0::new(binding.session_id_v0()).expect("session digest"),
            NonZeroDigestV0::new(binding.core_rehydrate_digest_v0()).expect("rehydrate digest"),
            binding.safety_revision_v0(),
            NonZeroDigestV0::new(binding.safety_chain_checksum_v0()).expect("Safety chain digest"),
            NonZeroDigestV0::new(binding.application_history_digest_v0())
                .expect("application history digest"),
            binding.application_parent_height_v0(),
            NonZeroDigestV0::new(binding.application_parent_block_id_v0())
                .expect("application parent BlockId"),
            NonZeroDigestV0::new(binding.application_parent_state_root_v0())
                .expect("application parent state root"),
            NonZeroDigestV0::new(binding.application_parent_commit_id_v0())
                .expect("application parent commit id"),
            binding.checkpoint_generation_v0(),
            NonZeroDigestV0::new(binding.checkpoint_checksum_v0()).expect("checkpoint digest"),
            NonZeroDigestV0::new(binding.signer_scope_v0()).expect("signer scope"),
            NonZeroDigestV0::new(binding.signer_journal_id_v0()).expect("signer journal id"),
            binding.signer_sequence_v0(),
            NonZeroDigestV0::new(binding.signer_chain_checksum_v0()).expect("signer chain digest"),
            signer_inventory_digest,
            selected_replay_digest,
        )
        .expect("readdress activation binding")
    }

    fn process2_fixture_v0(leave_pending_sign: bool, include_timeout: bool) -> Process2FixtureV0 {
        let directory = tempdir().expect("create process2 test root");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect process2 test root");
        let watermark = SharedWatermarkV0::default();
        let bundle = crate::commission_native_h1_ordinary_lab_test_bundle_v0(
            directory.path(),
            watermark.clone(),
            4,
            3,
        )
        .expect("commission exact deployed h1-h3 process2 fixture");
        let validator_set = bundle.validator_set_v0().clone();
        let parameters = *bundle.consensus_parameters_v0();
        let height = bundle.ordinary_start_height_v0();
        let timestamp_ms = 400;
        let transactions = bundle
            .ordinary_transactions_v0(height, timestamp_ms)
            .expect("author exact h4 application transaction");
        let binding = bundle
            .runtime_v0()
            .proposal_binding_v0()
            .expect("read exact h4 proposal binding");
        let (parent, preview) = bundle
            .runtime_v0()
            .preview_next_nonempty_v0(transactions.clone(), timestamp_ms)
            .expect("preview exact h4 transition");
        let payload = ApplicationPayloadV0::new(transactions).expect("construct h4 payload");
        let proposer = leader_for(&validator_set, binding.current_view_v0());
        assert_eq!(proposer, bundle.local_validator_v0());
        let header = BlockHeader::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            binding.current_view_v0(),
            Height::new(height),
            BlockKind::Regular,
            BlockId::new(*parent.application_head_v0().block_id().as_bytes()),
            proposer,
            validator_set.id(),
            parameters.hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            timestamp_ms,
            None,
        )
        .expect("construct exact h4 header");
        let block = Block::new(
            header,
            payload.try_cev0_bytes().expect("encode exact h4 payload"),
            Vec::new(),
        )
        .expect("construct exact h4 block");
        let proposal_root =
            ProposalWitnessV0::signing_root_for(block.header(), binding.high_qc_v0(), None, None)
                .expect("derive exact h4 proposal root");
        let witness = ProposalWitnessV0::new(
            block.header(),
            binding.high_qc_v0().clone(),
            None,
            None,
            bundle
                .sign_consensus_root_v0(proposer, proposal_root)
                .expect("sign exact h4 proposal root"),
            &validator_set,
            None,
            &parameters,
            parent.authenticated_parent_timestamp_ms_v0(),
        )
        .expect("construct exact h4 proposal witness");
        let proposal = trnm_consensus_types::SignedProposalV0::new(
            block,
            witness,
            &validator_set,
            None,
            &parameters,
            parent.authenticated_parent_timestamp_ms_v0(),
        )
        .expect("construct exact signed h4 proposal");
        let replay_proposal = proposal.clone();
        let h4_id = proposal.block().id();
        let votes = validator_set
            .validators()
            .iter()
            .map(|validator| {
                let root = Vote::signing_root_for_set(
                    &validator_set,
                    proposal.block().header().view(),
                    proposal.block().header().height(),
                    h4_id,
                )
                .expect("derive exact h4 Vote root");
                Vote::new(
                    validator_set.chain_id(),
                    validator_set.protocol_version(),
                    validator_set.epoch(),
                    proposal.block().header().view(),
                    proposal.block().header().height(),
                    h4_id,
                    validator_set.id(),
                    validator.id(),
                    bundle
                        .sign_consensus_root_v0(validator.id(), root)
                        .expect("sign exact h4 Vote root"),
                    &validator_set,
                )
                .expect("construct exact h4 Vote")
            })
            .collect::<Vec<_>>();
        let h4_qc = QuorumCertificate::new(
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            proposal.block().header().view(),
            proposal.block().header().height(),
            h4_id,
            validator_set.id(),
            votes,
            &validator_set,
        )
        .expect("construct exact h4 QC");
        let timeout_view = View::new(
            h4_qc
                .view()
                .get()
                .checked_add(1)
                .expect("fixture timeout view"),
        );
        let timeout_high_qc = QcReferenceV0::ordinary(h4_qc.clone());
        let timeout_high_ref = timeout_high_qc.qc_ref();
        let timeout_entries = validator_set
            .validators()
            .iter()
            .map(|validator| {
                let root = TimeoutVote::signing_root_for_set(
                    &validator_set,
                    timeout_view,
                    timeout_high_ref,
                )
                .expect("derive exact post-h4 TimeoutVote root");
                let vote = TimeoutVote::new(
                    validator_set.chain_id(),
                    validator_set.protocol_version(),
                    validator_set.epoch(),
                    timeout_view,
                    validator_set.id(),
                    timeout_high_ref,
                    validator.id(),
                    bundle
                        .sign_consensus_root_v0(validator.id(), root)
                        .expect("sign exact post-h4 TimeoutVote root"),
                    &validator_set,
                )
                .expect("construct exact post-h4 TimeoutVote");
                TimeoutEntryV0::new(validator.id(), timeout_high_ref, *vote.signature())
                    .expect("construct exact post-h4 timeout entry")
            })
            .collect::<Vec<_>>();
        let timeout_certificate = TimeoutCertificateV0::new(
            timeout_view,
            timeout_entries,
            vec![timeout_high_qc.clone()],
            timeout_high_qc.id(),
            &validator_set,
        )
        .expect("construct exact post-h4 timeout certificate");
        let timeout_signing_key = bundle.signing_key_v0().clone();
        let mut producer = ExactProducerV0(bundle.signing_key_v0().clone());
        let (core_config, _application_config, runtime) = bundle.into_recovery_test_parts_v0();
        if leave_pending_sign {
            let pending = runtime
                .drive_one_to_inert_request_v0(proposal)
                .expect("persist exact h4 pending-sign cut");
            drop(pending);
            Process2FixtureV0 {
                directory,
                watermark,
                core_config,
                entries: Vec::new(),
            }
        } else {
            let signed = runtime
                .drive_one_to_inert_request_v0(proposal)
                .expect("drive exact h4 through P/D/C/K")
                .sign_exact_vote_v0(&mut producer)
                .expect("journal and release exact local h4 Vote");
            let mut advance = signed
                .advance_quorum_certificate_v0(h4_qc.clone())
                .expect("advance exact h4 QC");
            let runtime = loop {
                match advance {
                    crate::PocoNodeLabCertificateAdvanceV0::Ready(runtime) => break *runtime,
                    crate::PocoNodeLabCertificateAdvanceV0::PendingFinalization(owner) => {
                        advance = owner
                            .apply_and_ack_finalization_v0()
                            .expect("apply exact post-h4 finalization")
                    }
                }
            };
            if !include_timeout {
                drop(runtime);
                return Process2FixtureV0 {
                    directory,
                    watermark,
                    core_config,
                    entries: vec![PocoNodeDeployedLabSignedReplayEntryV0::new(
                        replay_proposal,
                        h4_qc,
                    )],
                };
            }
            assert_eq!(
                runtime
                    .proposal_binding_v0()
                    .expect("read exact post-h4 proposal binding")
                    .current_view_v0(),
                timeout_view,
                "timeout fixture must target Core's exact post-QC view",
            );
            // This is deliberately a test-only/inert integration.  The Lab
            // owner still owns Core, SafetyStore, and the signer journal, but
            // the producer boundary is the durable response-replay wrapper
            // from the external-watermark slice.  The response namespace is
            // kept outside the seven deployed authority namespaces so the
            // process-2 recovery inventory remains exact.
            let response_binding_directory =
                tempdir().expect("create timeout response-binding namespace");
            std::fs::set_permissions(
                response_binding_directory.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("protect timeout response-binding namespace");
            let mut replay_bound_timeout = ReplayBoundTimeoutProducer::open(
                response_binding_directory
                    .path()
                    .join("timeout-response-binding.log"),
                ExactProducerV0(timeout_signing_key),
            )
            .expect("open durable timeout response-binding wrapper");
            let signed_timeout = runtime
                .begin_local_timeout_v0()
                .expect("persist exact post-h4 timeout intent")
                .sign_exact_timeout_v0(&mut replay_bound_timeout)
                .expect("journal and release exact post-h4 TimeoutVote through replay binding");
            let mut advance = signed_timeout
                .advance_timeout_certificate_v0(timeout_certificate)
                .expect("advance exact post-h4 timeout certificate");
            let runtime = loop {
                match advance {
                    crate::PocoNodeLabCertificateAdvanceV0::Ready(runtime) => break *runtime,
                    crate::PocoNodeLabCertificateAdvanceV0::PendingFinalization(owner) => {
                        advance = owner
                            .apply_and_ack_finalization_v0()
                            .expect("drain unexpected post-timeout finalization")
                    }
                }
            };
            drop(runtime);
            Process2FixtureV0 {
                directory,
                watermark,
                core_config,
                entries: vec![PocoNodeDeployedLabSignedReplayEntryV0::new(
                    replay_proposal,
                    h4_qc,
                )],
            }
        }
    }
}
