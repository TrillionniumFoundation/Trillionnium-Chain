//! Private default-built splice from a Core-issued ordinary Proposal request
//! to the native application's durable complete execution artifact `P`.
//!
//! The splice consumes Core's unique request carrier, decodes and binds the
//! complete non-empty canonical payload, invokes one Node-owned
//! [`NativeApplicationV0`], and stores the exact successful execution artifact
//! in [`SqliteProposalValidationStoreV0`]. A fresh connection inside the store
//! verifies the commit target before `P` is returned; a later store open can
//! reconstruct the same artifact for restart readback.
//!
//! This module intentionally has no public API and no production constructor.
//! Its private typestate can join a confirmed durable P to Core's live Valid
//! permit and application-seal authority, persist the opaque Core-accepted D
//! carrier, close real Safety C and application K, and fresh-confirm one
//! independent whole-node successor CAS. Only then may it submit the exact Core
//! StorageAck and retain the sole RequestSignature as private inert data;
//! signer-journal submission, signature production, and transport remain
//! unreachable. Legacy synthetic-genesis parents are admitted only as
//! binding-stage comparison input and are rejected before the P-to-D authority
//! transition.

#[cfg(any(test, feature = "lab-validator-runtime"))]
use std::path::PathBuf;
use std::{error::Error, fmt};

use trnm_consensus_core::{
    BlockIdOverlayRefV0, ClaimedPayloadValidationRequestV0, Core, CoreAcceptedApplicationValidDV0,
    CoreError, CoreIssuedApplicationSealAuthorityV0, CoreIssuedValidPermitV0,
    PayloadValidationParentProvenanceV0, PayloadValidationRouteV0,
    StateSyncAnchorSuccessorReplayV0, ValidatedPayloadArtifactRefV0, ValidationId,
};
use trnm_consensus_safety_store::{
    SafetyPersistDispositionV0, SafetyStoreErrorV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{ExternalMonotonicWatermarkV0, SqliteSignerJournalV0};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, decode_double_vote_evidence_v0_exact,
    validate_root_bound_regular_body_v0, ApplicationPayloadV0, Block, BlockBodyV0, BlockId,
    BlockKind, CanonicalSignIntentV0, CanonicalSignPreimageV0, ConsensusParametersV0,
    ExecutionEventAttributeV0, ExecutionEventV0, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0,
    SignatureVerifier, ValidatorSet,
};
use trnm_native_application::{
    ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0,
    NativeApplicationV0, NativeBlockExecutionRequestV0, NativeBlockExecutionResultV0,
    NativeExpectedBlockCommitmentsV0, ReceiptsRootV0, StateRootV0, ValidatorSetIdV0,
};
#[cfg(any(test, feature = "lab-validator-runtime"))]
use trnm_native_application_sqlite::ProposalValidationStoreScopeV0;
use trnm_native_application_sqlite::{
    AckTransitionOutcomeV0, AckedValidationV0, ConfirmedProposalValidationCheckpointFactsV0,
    DeliverTransitionOutcomeV0, DeliveredValidationV0, DurableValidationStageV0, ProposalRouteV0,
    ProposalValidationBindingV0, ProposalValidationFactV0, ProposalValidationOwnerIdV0,
    ReservationOutcomeV0, ReservedValidationV0, SqliteProposalValidationStoreV0,
    ValidationStoreErrorV0,
};
use trnm_native_execution_v0::{ConfirmedDurableExecutionPV0, DurableNativeApplicationV0};

use crate::external_node_checkpoint::{
    advance_native_k_whole_node_checkpoint_v0, ConfirmedNativeKNodeCheckpointV0,
    ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0, NativeKNodeCheckpointAdvanceErrorV0,
    NATIVE_K_SUCCESSOR_CHECKPOINT_CAS_INTEGRATION_V0,
};

const NATIVE_RECEIPT_COMMITMENT_DOMAIN_V0: &str = "trnm.native-application.execution-receipt.v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PocoNodeNativeProposalPHostStatusV0 {
    Ready,
    Persisted,
    CoreAcceptedDeliveryPending,
    CoreDelivered,
    SafetyConfirmedApplicationAckPending,
    ApplicationAcked,
    WholeNodeCheckpointed,
    InertRequestSignature,
    FailStopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PocoNodeNativeSafetyClosureModeV0 {
    OrdinaryVote,
    AnchorSuccessorNoSign,
}

/// Machine-readable position of the default-built ordinary-Proposal splice.
///
/// `DurableExecutionArtifactP` and `CoreAcceptedDeliveryD` are constructible.
/// Later discriminants document the monotonic protocol order without
/// pretending that inert digests can recreate missing Safety authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum PocoNodeNativeProposalClosureStageV0 {
    DurableExecutionArtifactP = 1,
    CoreAcceptedDeliveryD = 2,
    SafetyConfirmedC = 3,
    ApplicationAcknowledgedK = 4,
    WholeNodeCheckpointedK = 5,
    InertRequestSignature = 6,
}

impl PocoNodeNativeProposalClosureStageV0 {
    pub(super) const fn code(self) -> u8 {
        self as u8
    }
}

/// Exact next authority required after the generic P-only splice.
///
/// Only the concrete durable application can fresh-confirm the overlay, and
/// only the issuing Core can supply its non-cloneable application seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum PocoNodeNativeProposalNextAuthorityV0 {
    DurableSpeculativeOverlayAndCoreAffinedApplicationSeal = 1,
}

impl PocoNodeNativeProposalNextAuthorityV0 {
    pub(super) const fn code(self) -> u8 {
        self as u8
    }
}

/// Private linear join of Core's request permit and App's durable `P` token.
///
/// No method exposes either authority. A future `D/C/K` tranche must extend
/// this Node-owned typestate instead of reconstructing either half from inert
/// digests.
pub(super) struct PocoNodeNativePersistedProposalPV0 {
    binding: ProposalValidationBindingV0,
    reserved: ReservedValidationV0,
    core_valid_permit: CoreIssuedValidPermitV0,
    parent_authority_complete: bool,
    block: Block,
    executed: trnm_native_application::NativeExecutedBlockV0,
}

impl fmt::Debug for PocoNodeNativePersistedProposalPV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PocoNodeNativePersistedProposalPV0")
            .field("validation_id", &self.binding.validation_id())
            .field("row_revision", &self.reserved.row_revision())
            .field("parent_authority_complete", &self.parent_authority_complete)
            .finish_non_exhaustive()
    }
}

/// Node-private join after Core accepts Valid but before SQLite proves `D`.
///
/// This carrier exists only for the exact commit-not-applied branch. It keeps
/// the Core authority, reservation, and durable P together so the same D can
/// be retried without replaying the Core callback.
pub(super) struct PocoNodeNativeCoreDPendingV0 {
    binding: ProposalValidationBindingV0,
    reserved: ReservedValidationV0,
    core_accepted: CoreAcceptedApplicationValidDV0,
    confirmed_p: ConfirmedDurableExecutionPV0,
    executed: trnm_native_application::NativeExecutedBlockV0,
}

/// Node-private terminal point of this tranche: real durable P, Core-accepted
/// Valid, and exact SQLite D are joined, while Safety C remains absent.
pub(super) struct PocoNodeNativeCoreAcceptedDV0 {
    binding: ProposalValidationBindingV0,
    core_accepted: CoreAcceptedApplicationValidDV0,
    delivered: DeliveredValidationV0,
    confirmed_p: ConfirmedDurableExecutionPV0,
    executed: trnm_native_application::NativeExecutedBlockV0,
}

impl PocoNodeNativeCoreAcceptedDV0 {
    pub(super) fn core_accepted_v0(&self) -> &CoreAcceptedApplicationValidDV0 {
        &self.core_accepted
    }

    pub(super) fn delivered_v0(&self) -> &DeliveredValidationV0 {
        &self.delivered
    }

    pub(super) fn confirmed_p_v0(&self) -> &ConfirmedDurableExecutionPV0 {
        &self.confirmed_p
    }
}

/// Node-private join after real Safety persistence but before the application
/// K transaction is proven applied.
pub(super) struct PocoNodeNativeSafetyConfirmedCPendingKV0 {
    binding: ProposalValidationBindingV0,
    core_accepted: CoreAcceptedApplicationValidDV0,
    delivered: DeliveredValidationV0,
    confirmed_p: ConfirmedDurableExecutionPV0,
    executed: trnm_native_application::NativeExecutedBlockV0,
}

/// Terminal point before whole-node CAS: P, Core-D, real Safety-C, and K are
/// all durable, but Core StorageAck has deliberately not been submitted.
pub(super) struct PocoNodeNativeApplicationAckedKV0 {
    binding: ProposalValidationBindingV0,
    core_accepted: CoreAcceptedApplicationValidDV0,
    acked: AckedValidationV0,
    confirmed_p: ConfirmedDurableExecutionPV0,
    executed: trnm_native_application::NativeExecutedBlockV0,
}

pub(super) struct PocoNodeNativeAnchoredSuccessorCompletedV0 {
    binding: ProposalValidationBindingV0,
    application_head: ApplicationHeadV0,
    overlay: BlockIdOverlayRefV0,
    safety_revision: u64,
}

impl PocoNodeNativeAnchoredSuccessorCompletedV0 {
    pub(super) fn from_reconciled_terminal_k_v0(
        binding: ProposalValidationBindingV0,
        application_head: ApplicationHeadV0,
        overlay: BlockIdOverlayRefV0,
        safety_revision: u64,
    ) -> Option<Self> {
        if !matches!(safety_revision, 2 | 4)
            || binding.route() != ProposalRouteV0::Synced
            || binding.block_id().as_bytes() != overlay.block_id().as_bytes()
            || binding.parent().block_id().as_bytes() != overlay.parent_block_id().as_bytes()
            || application_head.height() != binding.height()
            || application_head.block_id() != binding.block_id()
            || application_head.state_root() != binding.commitments().post_state_root()
        {
            return None;
        }
        Some(Self {
            binding,
            application_head,
            overlay,
            safety_revision,
        })
    }

    pub(super) const fn binding_v0(&self) -> &ProposalValidationBindingV0 {
        &self.binding
    }

    pub(super) const fn application_head_v0(&self) -> &ApplicationHeadV0 {
        &self.application_head
    }

    pub(super) const fn overlay_v0(&self) -> BlockIdOverlayRefV0 {
        self.overlay
    }

    pub(super) const fn safety_revision_v0(&self) -> u64 {
        self.safety_revision
    }
}

/// Terminal point of the current native authority tranche. P/D/C/K and the
/// independent whole-node successor are exact and durable, but Core has not
/// received StorageAck and therefore cannot release RequestSignature.
pub(super) struct PocoNodeNativeWholeNodeCheckpointedKV0 {
    acked: PocoNodeNativeApplicationAckedKV0,
    checkpoint: ConfirmedNativeKNodeCheckpointV0,
}

impl PocoNodeNativeWholeNodeCheckpointedKV0 {
    pub(super) const fn checkpoint_v0(&self) -> &ExternalNodeCheckpointV0 {
        self.checkpoint.checkpoint_v0()
    }

    pub(super) const fn application_store_sequence_v0(&self) -> u64 {
        self.checkpoint.application_store_sequence_v0()
    }

    pub(super) const fn application_row_checksum_v0(&self) -> [u8; 32] {
        self.checkpoint.application_row_checksum_v0()
    }

    pub(super) const fn closure_stage_v0(&self) -> PocoNodeNativeProposalClosureStageV0 {
        PocoNodeNativeProposalClosureStageV0::WholeNodeCheckpointedK
    }
}

pub(super) enum PocoNodeNativeWholeNodeCheckpointOutcomeV0 {
    Applied(Box<PocoNodeNativeWholeNodeCheckpointedKV0>),
    NotApplied(Box<PocoNodeNativeApplicationAckedKV0>),
}

/// Private terminal carrier after the CAS-authorized Core StorageAck.
///
/// The canonical intent is inert: this type exposes no signer journal,
/// producer, transport, or Core `SignatureReady` path and is neither Clone nor
/// serializable.
pub(super) struct PocoNodeNativeInertRequestSignatureV0 {
    checkpointed: PocoNodeNativeWholeNodeCheckpointedKV0,
    intent: CanonicalSignIntentV0,
}

impl PocoNodeNativeInertRequestSignatureV0 {
    pub(super) const fn binding_v0(&self) -> &ProposalValidationBindingV0 {
        &self.checkpointed.acked.binding
    }

    pub(super) const fn intent_v0(&self) -> &CanonicalSignIntentV0 {
        &self.intent
    }

    pub(super) const fn checkpoint_v0(&self) -> &ExternalNodeCheckpointV0 {
        self.checkpointed.checkpoint_v0()
    }

    pub(super) const fn application_store_sequence_v0(&self) -> u64 {
        self.checkpointed.application_store_sequence_v0()
    }

    pub(super) const fn application_row_checksum_v0(&self) -> [u8; 32] {
        self.checkpointed.application_row_checksum_v0()
    }

    /// Inert speculative application parent produced by the exact durable P.
    /// This is sufficient for read-only preview of a child body, but carries
    /// no Core permit, Safety authority, finality, or signing capability.
    pub(super) fn overlay_parent_head_v0(
        &self,
    ) -> Result<ApplicationHeadV0, trnm_native_execution_v0::NativeApplicationExecutionErrorV0>
    {
        self.checkpointed.acked.confirmed_p.overlay_parent_head_v0()
    }

    /// Exact Core-comparable speculative overlay produced by the durable P.
    /// The value is inert and deliberately remains joined to this private
    /// owner until the laboratory runtime moves it into the next proposal
    /// parent configuration.
    pub(super) const fn overlay_ref_v0(&self) -> BlockIdOverlayRefV0 {
        BlockIdOverlayRefV0::new(
            BlockId::new(self.checkpointed.acked.confirmed_p.block_id_v0()),
            BlockId::new(self.checkpointed.acked.confirmed_p.parent_block_id_v0()),
            self.checkpointed.acked.confirmed_p.overlay_checksum_v0(),
        )
    }

    /// Exact execution artifact retained for a later application finalization
    /// commit. This method is Node-private; the feature-gated public owner
    /// never exposes the artifact or a commit capability.
    pub(super) fn executed_for_finalization_v0(
        &self,
    ) -> trnm_native_application::NativeExecutedBlockV0 {
        self.checkpointed.acked.executed.clone()
    }

    /// Canonical digest of the durable execution artifact which Core retained
    /// in the exact Valid completion.  This is comparison data only: it is
    /// intentionally exposed only inside the Node crate and carries no
    /// callback, commit, finality, Safety, or signing authority.
    pub(super) const fn source_artifact_checksum_v0(&self) -> [u8; 32] {
        self.checkpointed
            .acked
            .confirmed_p
            .source_artifact_checksum_v0()
    }

    pub(super) const fn closure_stage_v0(&self) -> PocoNodeNativeProposalClosureStageV0 {
        PocoNodeNativeProposalClosureStageV0::InertRequestSignature
    }
}

pub(super) enum PocoNodeNativeKOutcomeV0 {
    Applied(Box<PocoNodeNativeApplicationAckedKV0>),
    NotApplied(Box<PocoNodeNativeSafetyConfirmedCPendingKV0>),
}

pub(super) enum PocoNodeNativeCoreDOutcomeV0 {
    Applied(Box<PocoNodeNativeCoreAcceptedDV0>),
    NotApplied(Box<PocoNodeNativeCoreDPendingV0>),
}

impl PocoNodeNativePersistedProposalPV0 {
    pub(super) const fn validation_id(&self) -> ValidationId {
        self.core_valid_permit.id()
    }

    pub(super) const fn parent_authority_complete(&self) -> bool {
        self.parent_authority_complete
    }

    pub(super) const fn closure_stage_v0(&self) -> PocoNodeNativeProposalClosureStageV0 {
        PocoNodeNativeProposalClosureStageV0::DurableExecutionArtifactP
    }

    pub(super) const fn next_required_authority_v0(&self) -> PocoNodeNativeProposalNextAuthorityV0 {
        PocoNodeNativeProposalNextAuthorityV0::DurableSpeculativeOverlayAndCoreAffinedApplicationSeal
    }

    #[cfg(test)]
    fn binding_for_test_v0(&self) -> &ProposalValidationBindingV0 {
        &self.binding
    }
}

/// Node-private owner of one native application and one exact durable-P store.
pub(super) struct PocoNodeNativeProposalPHostV0<A> {
    application: A,
    store: SqliteProposalValidationStoreV0,
    owner_id: ProposalValidationOwnerIdV0,
    authenticated_application_head: ApplicationHeadV0,
    authenticated_application_overlay: Option<BlockIdOverlayRefV0>,
    consensus_parameters: ConsensusParametersV0,
    validator_set: ValidatorSet,
    status: PocoNodeNativeProposalPHostStatusV0,
}

#[cfg(any(test, feature = "lab-validator-runtime"))]
pub(crate) struct PocoNodeNativeProposalPHostConfigV0 {
    pub(crate) store_path: PathBuf,
    pub(crate) scope: ProposalValidationStoreScopeV0,
    pub(crate) minimum_durable_sequence: u64,
    pub(crate) owner_id: ProposalValidationOwnerIdV0,
    pub(crate) authenticated_application_head: ApplicationHeadV0,
    /// Exact Core-accepted speculative overlay when the application parent is
    /// not yet finalized. `None` means the parent must carry finalized
    /// provenance. This is comparison material only; it cannot mint a Core
    /// request or application authority.
    pub(crate) authenticated_application_overlay: Option<BlockIdOverlayRefV0>,
    pub(crate) consensus_parameters: ConsensusParametersV0,
    pub(crate) validator_set: ValidatorSet,
}

impl<A: NativeApplicationV0> PocoNodeNativeProposalPHostV0<A> {
    pub(super) fn from_open_store_v0(
        application: A,
        store: SqliteProposalValidationStoreV0,
        owner_id: ProposalValidationOwnerIdV0,
        authenticated_application_head: ApplicationHeadV0,
        authenticated_application_overlay: Option<BlockIdOverlayRefV0>,
        consensus_parameters: ConsensusParametersV0,
        validator_set: ValidatorSet,
    ) -> Self {
        Self {
            application,
            store,
            owner_id,
            authenticated_application_head,
            authenticated_application_overlay,
            consensus_parameters,
            validator_set,
            status: PocoNodeNativeProposalPHostStatusV0::Ready,
        }
    }

    /// Test-only construction until startup authenticates App/Safety/Signer and
    /// whole-node rollback watermarks as one recovery cut.
    #[cfg(test)]
    fn open_for_test_v0(
        application: A,
        config: PocoNodeNativeProposalPHostConfigV0,
    ) -> Result<Self, PocoNodeNativeProposalPHostErrorV0<A::Error>> {
        Self::open_exact_v0(application, config)
    }

    #[cfg(feature = "lab-validator-runtime")]
    pub(crate) fn open_for_lab_v0(
        application: A,
        config: PocoNodeNativeProposalPHostConfigV0,
    ) -> Result<Self, PocoNodeNativeProposalPHostErrorV0<A::Error>> {
        Self::open_exact_v0(application, config)
    }

    #[cfg(any(test, feature = "lab-validator-runtime"))]
    fn open_exact_v0(
        application: A,
        config: PocoNodeNativeProposalPHostConfigV0,
    ) -> Result<Self, PocoNodeNativeProposalPHostErrorV0<A::Error>> {
        let store = SqliteProposalValidationStoreV0::open(
            &config.store_path,
            config.scope,
            config.minimum_durable_sequence,
        )
        .map_err(PocoNodeNativeProposalPHostErrorV0::Store)?;
        Ok(Self {
            application,
            store,
            owner_id: config.owner_id,
            authenticated_application_head: config.authenticated_application_head,
            authenticated_application_overlay: config.authenticated_application_overlay,
            consensus_parameters: config.consensus_parameters,
            validator_set: config.validator_set,
            status: PocoNodeNativeProposalPHostStatusV0::Ready,
        })
    }

    pub(super) const fn status_v0(&self) -> PocoNodeNativeProposalPHostStatusV0 {
        self.status
    }

    /// Executes and durably stores exactly one ordinary non-empty Proposal.
    ///
    /// Success stops at `P`. The returned carrier cannot be converted into a
    /// Core callback or signing request by this module.
    pub(super) fn execute_and_persist_p_v0(
        &mut self,
        claimed: ClaimedPayloadValidationRequestV0,
    ) -> Result<PocoNodeNativePersistedProposalPV0, PocoNodeNativeProposalPHostErrorV0<A::Error>>
    {
        if self.status != PocoNodeNativeProposalPHostStatusV0::Ready {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        // Claiming a Core request is irreversible. Keep every early-return
        // path fail-closed; only a fully read-back durable P transitions this
        // owner to `Persisted` below.
        self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;

        let (route, core_id, block, parent, core_valid_permit) = claimed.into_parts();
        let header = block.header();
        if header.block_kind() != BlockKind::Regular
            || core_id.block_id() != block.id()
            || core_id.view() != header.view()
            || core_id.generation() == 0
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::CoreBindingMismatch);
        }

        let tip = parent.tip();
        if tip.height().get() != self.authenticated_application_head.height().get()
            || tip.block_id().as_bytes()
                != self.authenticated_application_head.block_id().as_bytes()
            || header.parent_id() != tip.block_id()
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::ParentBindingMismatch);
        }
        let parent_authority_complete = match (parent.exact_header(), parent.provenance()) {
            (Some(parent_header), PayloadValidationParentProvenanceV0::Finalized)
                if self.authenticated_application_overlay.is_none()
                    && parent_header.state_root().as_bytes()
                        == self.authenticated_application_head.state_root().as_bytes() =>
            {
                true
            }
            (
                Some(parent_header),
                PayloadValidationParentProvenanceV0::Speculative(core_overlay),
            ) if self.authenticated_application_overlay == Some(core_overlay)
                && core_overlay.block_id() == tip.block_id()
                && core_overlay.parent_block_id() == parent_header.parent_id()
                && parent_header.state_root().as_bytes()
                    == self.authenticated_application_head.state_root().as_bytes() =>
            {
                true
            }
            (Some(_), _) => {
                return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::ParentBindingMismatch);
            }
            (None, _) if parent.is_legacy_trusted_genesis_v0() => false,
            (None, _) => {
                return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::ParentBindingMismatch);
            }
        };

        let root_bound = validate_root_bound_regular_body_v0(
            &block,
            &self.validator_set,
            &self.consensus_parameters,
        )
        .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)?;
        let payload = decode_application_payload_v0_exact(
            block.application_payload(),
            &self.consensus_parameters,
        )
        .map_err(|_| PocoNodeNativeProposalPHostErrorV0::PayloadDecode)?;
        if root_bound.transaction_count() != payload.transaction_count() {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::EmptyOrMismatchedPayload);
        }

        let native_request = NativeBlockExecutionRequestV0::new(
            ChainIdV0::new(header.chain_id().as_str())
                .map_err(|_| PocoNodeNativeProposalPHostErrorV0::NativeBoundary("chain_id"))?,
            GenesisHashV0::new(*header.genesis_hash().as_bytes())
                .map_err(|_| PocoNodeNativeProposalPHostErrorV0::NativeBoundary("genesis_hash"))?,
            self.authenticated_application_head.clone(),
            BlockIdV0::new(*block.id().as_bytes())
                .map_err(|_| PocoNodeNativeProposalPHostErrorV0::NativeBoundary("block_id"))?,
            HeightV0::new(header.height().get()),
            header.timestamp_ms(),
            ValidatorSetIdV0::new(*header.validator_set_id().as_bytes()).map_err(|_| {
                PocoNodeNativeProposalPHostErrorV0::NativeBoundary("validator_set_id")
            })?,
            payload.transactions().to_vec(),
            NativeExpectedBlockCommitmentsV0::new(
                Hash32V0::new(*header.payload_root().as_bytes()),
                StateRootV0::new(*header.state_root().as_bytes()).map_err(|_| {
                    PocoNodeNativeProposalPHostErrorV0::NativeBoundary("state_root")
                })?,
                ReceiptsRootV0::new(*header.receipts_root().as_bytes()).map_err(|_| {
                    PocoNodeNativeProposalPHostErrorV0::NativeBoundary("receipts_root")
                })?,
                Hash32V0::new(*header.evidence_root().as_bytes()),
            )
            .map_err(|_| PocoNodeNativeProposalPHostErrorV0::NativeBoundary("commitments"))?,
        )
        .map_err(|_| PocoNodeNativeProposalPHostErrorV0::NativeBoundary("request"))?;

        let executed = match self.application.execute_block(native_request.clone()) {
            Ok(NativeBlockExecutionResultV0::Valid(executed))
                if executed.request() == &native_request =>
            {
                *executed
            }
            Ok(NativeBlockExecutionResultV0::Valid(_)) => {
                return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::ApplicationSubstitution);
            }
            Ok(NativeBlockExecutionResultV0::DeterministicallyInvalid(_)) => {
                return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::DeterministicallyInvalid);
            }
            Ok(NativeBlockExecutionResultV0::Unavailable(_)) => {
                return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::Unavailable);
            }
            Err(error) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
                return Err(PocoNodeNativeProposalPHostErrorV0::Application(error));
            }
        };

        let binding = ProposalValidationBindingV0::new(
            native_request.chain_id().clone(),
            native_request.genesis_hash(),
            native_request.parent().clone(),
            native_request.block_id(),
            native_request.height(),
            native_request.timestamp_ms(),
            native_request.active_validator_set_id(),
            core_id.view().get(),
            core_id.generation(),
            match route {
                PayloadValidationRouteV0::Proposal => ProposalRouteV0::Proposal,
                PayloadValidationRouteV0::Synced => ProposalRouteV0::Synced,
            },
            native_request.expected(),
        )
        .map_err(PocoNodeNativeProposalPHostErrorV0::Store)?;

        let reserved = match self.store.reserve_v0(&binding, self.owner_id, &executed) {
            Ok(ReservationOutcomeV0::Applied(reserved)) => reserved,
            Ok(ReservationOutcomeV0::NotApplied) => {
                return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::StoreNotApplied);
            }
            Err(error) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
                return Err(PocoNodeNativeProposalPHostErrorV0::Store(error));
            }
        };
        let readback = self
            .store
            .read_artifact_exact_v0(&binding)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Store)?;
        if readback != executed {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::ArtifactReadbackMismatch);
        }
        self.status = PocoNodeNativeProposalPHostStatusV0::Persisted;
        Ok(PocoNodeNativePersistedProposalPV0 {
            binding,
            reserved,
            core_valid_permit,
            parent_authority_complete,
            block,
            executed,
        })
    }

    pub(super) fn inspect_p_v0(
        &mut self,
        persisted: &PocoNodeNativePersistedProposalPV0,
    ) -> Result<ProposalValidationFactV0, PocoNodeNativeProposalPHostErrorV0<A::Error>> {
        let fact = self
            .store
            .inspect_exact_v0(&persisted.binding)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Store)?;
        if fact.stage() != DurableValidationStageV0::Reserved
            || fact.validation_id() != persisted.binding.validation_id()
            || fact.row_revision() != persisted.reserved.row_revision()
            || fact.outbox_present()
        {
            return Err(PocoNodeNativeProposalPHostErrorV0::ArtifactReadbackMismatch);
        }
        Ok(fact)
    }

    fn fail_v0<T>(
        &mut self,
        error: PocoNodeNativeProposalPHostErrorV0<A::Error>,
    ) -> Result<T, PocoNodeNativeProposalPHostErrorV0<A::Error>> {
        self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
        Err(error)
    }
}

impl PocoNodeNativeProposalPHostV0<DurableNativeApplicationV0> {
    /// Rejoins a crash-surviving exact durable P row to Core's newly replayed
    /// Synced request permit. Neither the inert binding nor the artifact can
    /// mint a callback without this live Core-issued request.
    pub(super) fn recover_anchor_successor_p_v0(
        &mut self,
        claimed: ClaimedPayloadValidationRequestV0,
        binding: ProposalValidationBindingV0,
    ) -> Result<
        PocoNodeNativePersistedProposalPV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::Ready {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
        let (route, core_id, block, parent, core_valid_permit) = claimed.into_parts();
        let header = block.header();
        let expected_route = ProposalRouteV0::Synced;
        let expected_commitments = NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new(*header.payload_root().as_bytes()),
            StateRootV0::new(*header.state_root().as_bytes())
                .map_err(|_| PocoNodeNativeProposalPHostErrorV0::NativeBoundary("state_root"))?,
            ReceiptsRootV0::new(*header.receipts_root().as_bytes())
                .map_err(|_| PocoNodeNativeProposalPHostErrorV0::NativeBoundary("receipts_root"))?,
            Hash32V0::new(*header.evidence_root().as_bytes()),
        )
        .map_err(|_| PocoNodeNativeProposalPHostErrorV0::NativeBoundary("commitments"))?;
        if route != PayloadValidationRouteV0::Synced
            || core_id.block_id() != block.id()
            || core_id.view() != header.view()
            || core_id.generation() == 0
            || binding.chain_id().as_str() != header.chain_id().as_str()
            || binding.genesis_hash().as_bytes() != header.genesis_hash().as_bytes()
            || binding.parent() != &self.authenticated_application_head
            || binding.block_id().as_bytes() != block.id().as_bytes()
            || binding.height().get() != header.height().get()
            || binding.timestamp_ms() != header.timestamp_ms()
            || binding.active_validator_set_id().as_bytes() != header.validator_set_id().as_bytes()
            || binding.view() != core_id.view().get()
            || binding.generation() != core_id.generation()
            || binding.route() != expected_route
            || binding.commitments() != expected_commitments
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::CoreBindingMismatch);
        }
        let tip = parent.tip();
        let parent_authority_complete = match (parent.exact_header(), parent.provenance()) {
            (Some(parent_header), PayloadValidationParentProvenanceV0::Finalized)
                if self.authenticated_application_overlay.is_none()
                    && parent_header.state_root().as_bytes()
                        == self.authenticated_application_head.state_root().as_bytes()
                    && tip.block_id().as_bytes()
                        == self.authenticated_application_head.block_id().as_bytes() =>
            {
                true
            }
            (
                Some(parent_header),
                PayloadValidationParentProvenanceV0::Speculative(core_overlay),
            ) if self.authenticated_application_overlay == Some(core_overlay)
                && core_overlay.block_id() == tip.block_id()
                && parent_header.state_root().as_bytes()
                    == self.authenticated_application_head.state_root().as_bytes() =>
            {
                true
            }
            _ => false,
        };
        if !parent_authority_complete {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::ParentBindingMismatch);
        }
        let executed = self
            .store
            .read_artifact_exact_v0(&binding)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Store)?;
        let reserved = self
            .store
            .recover_reserved_exact_v0(&binding, self.owner_id)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Store)?;
        self.status = PocoNodeNativeProposalPHostStatusV0::Persisted;
        Ok(PocoNodeNativePersistedProposalPV0 {
            binding,
            reserved,
            core_valid_permit,
            parent_authority_complete,
            block,
            executed,
        })
    }

    /// Consumes the completed one-proposal host and returns only its native
    /// application owner. The proposal-validation store closes as part of the
    /// move; a subsequent runtime must reopen it through the same configured
    /// namespace and a fresh owner capability.
    pub(super) fn into_application_after_inert_v0(
        self,
    ) -> Result<
        DurableNativeApplicationV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::InertRequestSignature {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        Ok(self.application)
    }

    /// Joins one real durable P to the issuing Core's application seal, then
    /// persists only the exact opaque Core D carrier.
    ///
    /// A header-less legacy genesis parent is rejected before the Valid permit
    /// or application-seal authority is consumed. Success deliberately stops
    /// before Safety persistence, StorageAck, RequestSignature, signing, or
    /// broadcast.
    pub(super) fn seal_valid_and_deliver_core_d_v0<V: SignatureVerifier>(
        &mut self,
        persisted: PocoNodeNativePersistedProposalPV0,
        core: &mut Core,
        seal_authority: &CoreIssuedApplicationSealAuthorityV0,
        verifier: &V,
    ) -> Result<
        PocoNodeNativeCoreDOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::Persisted {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        if !persisted.parent_authority_complete {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::IncompleteParentAuthority);
        }

        let confirmed_p = self
            .application
            .confirm_durable_p_v0(&persisted.executed)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Application)?;
        if confirmed_p.block_id_v0() != *persisted.block.id().as_bytes()
            || confirmed_p.parent_block_id_v0() != *persisted.block.header().parent_id().as_bytes()
            || confirmed_p.target_height_v0() != persisted.block.header().height().get()
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::ArtifactReadbackMismatch);
        }
        let commitments = validated_commitments_from_durable_execution_v0(
            &persisted.block,
            &persisted.executed,
            &self.consensus_parameters,
            &self.validator_set,
            verifier,
        )?;
        let artifact_ref = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(
                persisted.block.id(),
                persisted.block.header().parent_id(),
                confirmed_p.overlay_checksum_v0(),
            ),
            confirmed_p.source_artifact_checksum_v0(),
        );
        let proof = seal_authority.seal_after_application_store_commit_v0(
            persisted.core_valid_permit,
            commitments,
            artifact_ref,
        );
        let core_accepted = core
            .step_application_sealed_valid_to_delivery_v0(&proof, verifier)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Core)?;
        self.deliver_core_d_v0(
            persisted.binding,
            persisted.reserved,
            persisted.executed,
            core_accepted,
            confirmed_p,
        )
    }

    /// Anchored-successor variant of the P-to-D join.  Only the narrow replay
    /// owner can accept the sealed Synced callback.
    pub(super) fn seal_anchor_successor_valid_and_deliver_core_d_v0<V: SignatureVerifier>(
        &mut self,
        persisted: PocoNodeNativePersistedProposalPV0,
        replay: &mut StateSyncAnchorSuccessorReplayV0,
        seal_authority: &CoreIssuedApplicationSealAuthorityV0,
        verifier: &V,
    ) -> Result<
        PocoNodeNativeCoreDOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::Persisted {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        if !persisted.parent_authority_complete
            || persisted.binding.route() != ProposalRouteV0::Synced
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::IncompleteParentAuthority);
        }
        let confirmed_p = self
            .application
            .confirm_durable_p_v0(&persisted.executed)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Application)?;
        if confirmed_p.block_id_v0() != *persisted.block.id().as_bytes()
            || confirmed_p.parent_block_id_v0() != *persisted.block.header().parent_id().as_bytes()
            || confirmed_p.target_height_v0() != persisted.block.header().height().get()
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::ArtifactReadbackMismatch);
        }
        let commitments = validated_commitments_from_durable_execution_v0(
            &persisted.block,
            &persisted.executed,
            &self.consensus_parameters,
            &self.validator_set,
            verifier,
        )?;
        let artifact_ref = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(
                persisted.block.id(),
                persisted.block.header().parent_id(),
                confirmed_p.overlay_checksum_v0(),
            ),
            confirmed_p.source_artifact_checksum_v0(),
        );
        let proof = seal_authority.seal_after_application_store_commit_v0(
            persisted.core_valid_permit,
            commitments,
            artifact_ref,
        );
        let core_accepted = replay
            .step_application_sealed_valid_to_delivery_v0(&proof, verifier)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Core)?;
        self.deliver_core_d_v0(
            persisted.binding,
            persisted.reserved,
            persisted.executed,
            core_accepted,
            confirmed_p,
        )
    }

    fn deliver_core_d_v0(
        &mut self,
        binding: ProposalValidationBindingV0,
        reserved: ReservedValidationV0,
        executed: trnm_native_application::NativeExecutedBlockV0,
        core_accepted: CoreAcceptedApplicationValidDV0,
        confirmed_p: ConfirmedDurableExecutionPV0,
    ) -> Result<
        PocoNodeNativeCoreDOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        self.status = PocoNodeNativeProposalPHostStatusV0::CoreAcceptedDeliveryPending;
        match self
            .store
            .deliver_core_accepted_v0(reserved, &binding, &core_accepted)
        {
            Ok(DeliverTransitionOutcomeV0::Applied(delivered)) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::CoreDelivered;
                Ok(PocoNodeNativeCoreDOutcomeV0::Applied(Box::new(
                    PocoNodeNativeCoreAcceptedDV0 {
                        binding,
                        core_accepted,
                        delivered,
                        confirmed_p,
                        executed,
                    },
                )))
            }
            Ok(DeliverTransitionOutcomeV0::NotApplied(reserved)) => Ok(
                PocoNodeNativeCoreDOutcomeV0::NotApplied(Box::new(PocoNodeNativeCoreDPendingV0 {
                    binding,
                    reserved,
                    core_accepted,
                    confirmed_p,
                    executed,
                })),
            ),
            Err(error) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
                Err(PocoNodeNativeProposalPHostErrorV0::Store(error))
            }
        }
    }

    /// Retries only the exact D commit proven not applied. Core Valid is never
    /// replayed and every authority remains in the pending carrier.
    pub(super) fn retry_core_d_v0(
        &mut self,
        pending: PocoNodeNativeCoreDPendingV0,
    ) -> Result<
        PocoNodeNativeCoreDOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::CoreAcceptedDeliveryPending {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        match self.store.deliver_core_accepted_v0(
            pending.reserved,
            &pending.binding,
            &pending.core_accepted,
        ) {
            Ok(DeliverTransitionOutcomeV0::Applied(delivered)) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::CoreDelivered;
                Ok(PocoNodeNativeCoreDOutcomeV0::Applied(Box::new(
                    PocoNodeNativeCoreAcceptedDV0 {
                        binding: pending.binding,
                        core_accepted: pending.core_accepted,
                        delivered,
                        confirmed_p: pending.confirmed_p,
                        executed: pending.executed,
                    },
                )))
            }
            Ok(DeliverTransitionOutcomeV0::NotApplied(reserved)) => Ok(
                PocoNodeNativeCoreDOutcomeV0::NotApplied(Box::new(PocoNodeNativeCoreDPendingV0 {
                    reserved,
                    ..pending
                })),
            ),
            Err(error) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
                Err(PocoNodeNativeProposalPHostErrorV0::Store(error))
            }
        }
    }

    /// Persists the exact Core-owned NativeValid Safety transition, fresh-
    /// confirms the real SafetyStore head, and then closes application K.
    ///
    /// Success deliberately stops before whole-node checkpoint CAS and Core
    /// StorageAck. Consequently it cannot release RequestSignature, sign, or
    /// broadcast even though the Vote intent is now durably present in C.
    pub(super) fn persist_safety_c_and_ack_k_v0<V: SignatureVerifier>(
        &mut self,
        accepted_d: PocoNodeNativeCoreAcceptedDV0,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &std::path::Path,
    ) -> Result<
        PocoNodeNativeKOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        self.persist_safety_c_and_ack_k_inner_v0(
            accepted_d,
            safety_store,
            expected_safety_path,
            PocoNodeNativeSafetyClosureModeV0::OrdinaryVote,
            || {},
        )
    }

    pub(super) fn persist_anchor_successor_safety_c_and_ack_k_v0<V: SignatureVerifier>(
        &mut self,
        accepted_d: PocoNodeNativeCoreAcceptedDV0,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &std::path::Path,
    ) -> Result<
        PocoNodeNativeKOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        self.persist_safety_c_and_ack_k_inner_v0(
            accepted_d,
            safety_store,
            expected_safety_path,
            PocoNodeNativeSafetyClosureModeV0::AnchorSuccessorNoSign,
            || {},
        )
    }

    /// Laboratory-only observation seam invoked strictly after the exact
    /// Safety-C head has been freshly confirmed and before application K is
    /// attempted. The callback receives no authority and cannot influence the
    /// transition. The default path above uses a no-op callback.
    #[cfg(feature = "lab-validator-runtime")]
    pub(super) fn persist_safety_c_and_ack_k_observed_v0<V: SignatureVerifier, F: FnOnce()>(
        &mut self,
        accepted_d: PocoNodeNativeCoreAcceptedDV0,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &std::path::Path,
        on_confirmed_safety_c: F,
    ) -> Result<
        PocoNodeNativeKOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        self.persist_safety_c_and_ack_k_inner_v0(
            accepted_d,
            safety_store,
            expected_safety_path,
            PocoNodeNativeSafetyClosureModeV0::OrdinaryVote,
            on_confirmed_safety_c,
        )
    }

    fn persist_safety_c_and_ack_k_inner_v0<V: SignatureVerifier, F: FnOnce()>(
        &mut self,
        accepted_d: PocoNodeNativeCoreAcceptedDV0,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &std::path::Path,
        closure_mode: PocoNodeNativeSafetyClosureModeV0,
        on_confirmed_safety_c: F,
    ) -> Result<
        PocoNodeNativeKOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::CoreDelivered {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        if safety_store.path() != expected_safety_path {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::SafetyPathMismatch);
        }
        let context = self
            .store
            .native_valid_transition_context_exact_v0(
                &accepted_d.binding,
                &accepted_d.delivered,
                &accepted_d.core_accepted,
            )
            .map_err(PocoNodeNativeProposalPHostErrorV0::Store)?;
        let preflight = safety_store
            .preflight_bound_native_valid_persistence_v0(
                accepted_d.core_accepted.persistence_request_v0(),
            )
            .map_err(PocoNodeNativeProposalPHostErrorV0::Safety)?;
        if preflight.revision_v0() != accepted_d.core_accepted.completion_revision_v0()
            || preflight.post_ack_action_v0()
                != accepted_d
                    .core_accepted
                    .persistence_request_v0()
                    .native_valid_post_ack_action_v0()
                    .expect("Core-D construction requires the action")
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::SafetyBindingMismatch);
        }
        match safety_store
            .persist_exact_v0(accepted_d.core_accepted.persistence_request_v0(), &context)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Safety)?
        {
            SafetyPersistDispositionV0::Inserted
            | SafetyPersistDispositionV0::Existing
            | SafetyPersistDispositionV0::ConfirmedAfterCommitError => {}
        }
        let confirmed = safety_store
            .confirmed_native_valid_head_exact_v0(
                accepted_d.core_accepted.persistence_request_v0().state(),
                &context,
            )
            .map_err(PocoNodeNativeProposalPHostErrorV0::Safety)?;
        if !confirmed.belongs_to_store_at_path_v0(safety_store, expected_safety_path)
            || confirmed.revision() != accepted_d.core_accepted.completion_revision_v0()
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::SafetyBindingMismatch);
        }
        drop(confirmed);
        self.status = PocoNodeNativeProposalPHostStatusV0::SafetyConfirmedApplicationAckPending;
        on_confirmed_safety_c();
        let outcome = match closure_mode {
            PocoNodeNativeSafetyClosureModeV0::OrdinaryVote => {
                self.store.acknowledge_confirmed_safety_v0(
                    accepted_d.delivered,
                    &accepted_d.binding,
                    &accepted_d.core_accepted,
                    safety_store,
                    expected_safety_path,
                )
            }
            PocoNodeNativeSafetyClosureModeV0::AnchorSuccessorNoSign => {
                self.store.acknowledge_confirmed_anchor_successor_safety_v0(
                    accepted_d.delivered,
                    &accepted_d.binding,
                    &accepted_d.core_accepted,
                    safety_store,
                    expected_safety_path,
                )
            }
        };
        match outcome {
            Ok(AckTransitionOutcomeV0::Applied(acked)) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::ApplicationAcked;
                Ok(PocoNodeNativeKOutcomeV0::Applied(Box::new(
                    PocoNodeNativeApplicationAckedKV0 {
                        binding: accepted_d.binding,
                        core_accepted: accepted_d.core_accepted,
                        acked,
                        confirmed_p: accepted_d.confirmed_p,
                        executed: accepted_d.executed,
                    },
                )))
            }
            Ok(AckTransitionOutcomeV0::NotApplied(delivered)) => {
                Ok(PocoNodeNativeKOutcomeV0::NotApplied(Box::new(
                    PocoNodeNativeSafetyConfirmedCPendingKV0 {
                        binding: accepted_d.binding,
                        core_accepted: accepted_d.core_accepted,
                        delivered,
                        confirmed_p: accepted_d.confirmed_p,
                        executed: accepted_d.executed,
                    },
                )))
            }
            Err(error) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
                Err(PocoNodeNativeProposalPHostErrorV0::Store(error))
            }
        }
    }

    /// Retries only a K commit proven not applied. Safety persistence and the
    /// Core callback are never replayed.
    pub(super) fn retry_ack_k_v0<V: SignatureVerifier>(
        &mut self,
        pending: PocoNodeNativeSafetyConfirmedCPendingKV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &std::path::Path,
    ) -> Result<
        PocoNodeNativeKOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        self.retry_ack_k_inner_v0(
            pending,
            safety_store,
            expected_safety_path,
            PocoNodeNativeSafetyClosureModeV0::OrdinaryVote,
        )
    }

    pub(super) fn retry_anchor_successor_ack_k_v0<V: SignatureVerifier>(
        &mut self,
        pending: PocoNodeNativeSafetyConfirmedCPendingKV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &std::path::Path,
    ) -> Result<
        PocoNodeNativeKOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        self.retry_ack_k_inner_v0(
            pending,
            safety_store,
            expected_safety_path,
            PocoNodeNativeSafetyClosureModeV0::AnchorSuccessorNoSign,
        )
    }

    fn retry_ack_k_inner_v0<V: SignatureVerifier>(
        &mut self,
        pending: PocoNodeNativeSafetyConfirmedCPendingKV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &std::path::Path,
        closure_mode: PocoNodeNativeSafetyClosureModeV0,
    ) -> Result<
        PocoNodeNativeKOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::SafetyConfirmedApplicationAckPending
        {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        let outcome = match closure_mode {
            PocoNodeNativeSafetyClosureModeV0::OrdinaryVote => {
                self.store.acknowledge_confirmed_safety_v0(
                    pending.delivered,
                    &pending.binding,
                    &pending.core_accepted,
                    safety_store,
                    expected_safety_path,
                )
            }
            PocoNodeNativeSafetyClosureModeV0::AnchorSuccessorNoSign => {
                self.store.acknowledge_confirmed_anchor_successor_safety_v0(
                    pending.delivered,
                    &pending.binding,
                    &pending.core_accepted,
                    safety_store,
                    expected_safety_path,
                )
            }
        };
        match outcome {
            Ok(AckTransitionOutcomeV0::Applied(acked)) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::ApplicationAcked;
                Ok(PocoNodeNativeKOutcomeV0::Applied(Box::new(
                    PocoNodeNativeApplicationAckedKV0 {
                        binding: pending.binding,
                        core_accepted: pending.core_accepted,
                        acked,
                        confirmed_p: pending.confirmed_p,
                        executed: pending.executed,
                    },
                )))
            }
            Ok(AckTransitionOutcomeV0::NotApplied(delivered)) => {
                Ok(PocoNodeNativeKOutcomeV0::NotApplied(Box::new(
                    PocoNodeNativeSafetyConfirmedCPendingKV0 {
                        delivered,
                        ..pending
                    },
                )))
            }
            Err(error) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
                Err(PocoNodeNativeProposalPHostErrorV0::Store(error))
            }
        }
    }

    pub(super) fn confirm_anchor_successor_k_checkpoint_facts_v0(
        &mut self,
        acked: &PocoNodeNativeApplicationAckedKV0,
    ) -> Result<
        ConfirmedProposalValidationCheckpointFactsV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::ApplicationAcked
            || acked.binding.route() != ProposalRouteV0::Synced
            || acked.acked.validation_id() != acked.binding.validation_id()
        {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        self.store
            .confirm_proposal_validation_checkpoint_facts_exact_v0(&acked.binding)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Store)
    }

    pub(super) fn reconfirm_anchor_successor_k_checkpoint_facts_v0(
        &mut self,
        binding: &ProposalValidationBindingV0,
    ) -> Result<
        ConfirmedProposalValidationCheckpointFactsV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::Ready
            || binding.route() != ProposalRouteV0::Synced
        {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        self.store
            .confirm_proposal_validation_checkpoint_facts_exact_v0(binding)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Store)
    }

    /// Releases the anchored Core completion ACK only after the caller has
    /// durably joined this exact K row into the independent node checkpoint.
    /// The post-ack effect set must remain empty.  Success then advances this
    /// private host's speculative parent for the next proof-named successor.
    pub(super) fn acknowledge_anchor_successor_checkpointed_k_v0<V: SignatureVerifier>(
        &mut self,
        acked: PocoNodeNativeApplicationAckedKV0,
        replay: &mut StateSyncAnchorSuccessorReplayV0,
        verifier: &V,
    ) -> Result<
        PocoNodeNativeAnchoredSuccessorCompletedV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::ApplicationAcked
            || acked.binding.route() != ProposalRouteV0::Synced
            || acked.core_accepted.route_v0() != PayloadValidationRouteV0::Synced
            || acked
                .core_accepted
                .persistence_request_v0()
                .native_valid_post_ack_action_v0()
                != Some(trnm_consensus_core::NativeValidPostAckActionV0::None)
        {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        let effects = replay
            .step_storage_ack_v0(acked.core_accepted.barrier_v0(), verifier)
            .map_err(PocoNodeNativeProposalPHostErrorV0::Core)?;
        if !effects.is_empty() {
            return self
                .fail_v0(PocoNodeNativeProposalPHostErrorV0::UnexpectedPostCheckpointEffect);
        }
        let application_head = acked
            .confirmed_p
            .overlay_parent_head_v0()
            .map_err(PocoNodeNativeProposalPHostErrorV0::Application)?;
        let overlay = BlockIdOverlayRefV0::new(
            BlockId::new(acked.confirmed_p.block_id_v0()),
            BlockId::new(acked.confirmed_p.parent_block_id_v0()),
            acked.confirmed_p.overlay_checksum_v0(),
        );
        let completed = PocoNodeNativeAnchoredSuccessorCompletedV0 {
            binding: acked.binding,
            application_head: application_head.clone(),
            overlay,
            safety_revision: acked.core_accepted.completion_revision_v0(),
        };
        self.authenticated_application_head = application_head;
        self.authenticated_application_overlay = Some(overlay);
        self.status = PocoNodeNativeProposalPHostStatusV0::Ready;
        Ok(completed)
    }

    pub(super) fn application_store_path_v0(&self) -> &std::path::Path {
        self.store.path()
    }

    pub(super) const fn application_v0(&self) -> &DurableNativeApplicationV0 {
        &self.application
    }

    pub(super) fn application_and_validation_store_v0(
        &mut self,
    ) -> (
        &DurableNativeApplicationV0,
        &mut SqliteProposalValidationStoreV0,
    ) {
        (&self.application, &mut self.store)
    }

    pub(super) const fn validation_store_v0(&self) -> &SqliteProposalValidationStoreV0 {
        &self.store
    }

    pub(super) fn into_anchor_ordinary_parts_v0(
        self,
    ) -> Result<
        (
            DurableNativeApplicationV0,
            SqliteProposalValidationStoreV0,
            ProposalValidationOwnerIdV0,
        ),
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::Ready
            || self.authenticated_application_overlay.is_none()
        {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        Ok((self.application, self.store, self.owner_id))
    }

    /// Freshly joins terminal K to the real Safety and operational signer
    /// heads, then advances the independent whole-node checkpoint by one exact
    /// successor.
    ///
    /// An exact source readback after CAS failure returns the unconsumed K
    /// carrier for retry. Exact target readback returns a private checkpoint
    /// capability. Neither outcome calls Core StorageAck or exposes any
    /// RequestSignature/signing authority.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn checkpoint_k_whole_node_v0<V, W, S>(
        &mut self,
        acked: PocoNodeNativeApplicationAckedKV0,
        checkpoint_store: &mut S,
        expected_external: ExternalNodeCheckpointV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_safety_path: &std::path::Path,
        signer_journal: &mut SqliteSignerJournalV0<W>,
        expected_signer_path: &std::path::Path,
    ) -> Result<
        PocoNodeNativeWholeNodeCheckpointOutcomeV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    >
    where
        V: SignatureVerifier,
        W: ExternalMonotonicWatermarkV0,
        S: ExternalNodeCheckpointStoreV0,
    {
        if !NATIVE_K_SUCCESSOR_CHECKPOINT_CAS_INTEGRATION_V0
            || self.status != PocoNodeNativeProposalPHostStatusV0::ApplicationAcked
        {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        let application_path = self.store.path().to_path_buf();
        match advance_native_k_whole_node_checkpoint_v0(
            checkpoint_store,
            expected_external,
            safety_store,
            expected_safety_path,
            &mut self.store,
            &application_path,
            &acked.binding,
            signer_journal,
            expected_signer_path,
        ) {
            Ok(checkpoint) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::WholeNodeCheckpointed;
                Ok(PocoNodeNativeWholeNodeCheckpointOutcomeV0::Applied(
                    Box::new(PocoNodeNativeWholeNodeCheckpointedKV0 { acked, checkpoint }),
                ))
            }
            Err(error) if error.is_compare_not_applied_v0() => Ok(
                PocoNodeNativeWholeNodeCheckpointOutcomeV0::NotApplied(Box::new(acked)),
            ),
            Err(error) => {
                self.status = PocoNodeNativeProposalPHostStatusV0::FailStopped;
                Err(PocoNodeNativeProposalPHostErrorV0::WholeNodeCheckpoint(
                    error,
                ))
            }
        }
    }

    /// Submits Core StorageAck only after the exact whole-node successor has
    /// been durably CASed and freshly read back, then captures the sole
    /// RequestSignature effect as inert private data.
    pub(super) fn release_inert_request_signature_v0<V: SignatureVerifier>(
        &mut self,
        checkpointed: PocoNodeNativeWholeNodeCheckpointedKV0,
        core: &mut Core,
        verifier: &V,
    ) -> Result<
        PocoNodeNativeInertRequestSignatureV0,
        PocoNodeNativeProposalPHostErrorV0<
            trnm_native_execution_v0::NativeApplicationExecutionErrorV0,
        >,
    > {
        if self.status != PocoNodeNativeProposalPHostStatusV0::WholeNodeCheckpointed {
            return Err(PocoNodeNativeProposalPHostErrorV0::NotReady);
        }
        let accepted = &checkpointed.acked.core_accepted;
        let binding = &checkpointed.acked.binding;
        if accepted.barrier_v0().get() != checkpointed.checkpoint_v0().fields().safety_revision
            || accepted.completion_revision_v0()
                != checkpointed.checkpoint_v0().fields().safety_revision
        {
            return self.fail_v0(PocoNodeNativeProposalPHostErrorV0::WholeNodeCheckpointBinding);
        }
        let effects = core
            .step(
                trnm_consensus_core::Input::StorageAck {
                    barrier: accepted.barrier_v0(),
                },
                verifier,
            )
            .map_err(PocoNodeNativeProposalPHostErrorV0::Core)?;
        let [trnm_consensus_core::Effect::RequestSignature { intent }] = effects.as_slice() else {
            return self
                .fail_v0(PocoNodeNativeProposalPHostErrorV0::UnexpectedPostCheckpointEffect);
        };
        let CanonicalSignPreimageV0::Vote(vote) = intent.preimage() else {
            return self
                .fail_v0(PocoNodeNativeProposalPHostErrorV0::UnexpectedPostCheckpointEffect);
        };
        if intent.authorizing_safety_revision() != accepted.completion_revision_v0()
            || vote.block_id().as_bytes() != binding.block_id().as_bytes()
            || vote.height().get() != binding.height().get()
            || vote.view().get() != binding.view()
            || intent.signing_root().as_bytes()
                != checkpointed
                    .acked
                    .acked
                    .request_bound_safety_confirmation()
                    .vote_intent_digest()
                    .as_bytes()
        {
            return self
                .fail_v0(PocoNodeNativeProposalPHostErrorV0::UnexpectedPostCheckpointEffect);
        }
        self.status = PocoNodeNativeProposalPHostStatusV0::InertRequestSignature;
        Ok(PocoNodeNativeInertRequestSignatureV0 {
            checkpointed,
            intent: intent.clone(),
        })
    }
}

pub(super) fn validated_commitments_from_durable_execution_v0<V: SignatureVerifier>(
    block: &Block,
    executed: &trnm_native_application::NativeExecutedBlockV0,
    parameters: &ConsensusParametersV0,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> Result<
    trnm_consensus_types::ValidatedBlockCommitmentsV0,
    PocoNodeNativeProposalPHostErrorV0<trnm_native_execution_v0::NativeApplicationExecutionErrorV0>,
> {
    if executed.request().block_id().as_bytes() != block.id().as_bytes() {
        return Err(PocoNodeNativeProposalPHostErrorV0::ApplicationSubstitution);
    }
    let payload = decode_application_payload_v0_exact(block.application_payload(), parameters)
        .map_err(|_| PocoNodeNativeProposalPHostErrorV0::PayloadDecode)?;
    let mut evidence = Vec::with_capacity(block.evidence_objects().len());
    for encoded in block.evidence_objects() {
        evidence.push(
            decode_double_vote_evidence_v0_exact(encoded, validator_set)
                .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)?,
        );
    }
    let body = BlockBodyV0::new(payload.clone(), evidence)
        .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)?;
    let receipts = consensus_receipts_from_native_v0(&payload, executed)?;
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        parameters,
        validator_set,
        verifier,
    )
    .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)
}

fn consensus_receipts_from_native_v0(
    payload: &ApplicationPayloadV0,
    executed: &trnm_native_application::NativeExecutedBlockV0,
) -> Result<
    ExecutionReceiptsV0,
    PocoNodeNativeProposalPHostErrorV0<trnm_native_execution_v0::NativeApplicationExecutionErrorV0>,
> {
    let mut receipts = Vec::with_capacity(executed.receipts().len());
    for native in executed.receipts() {
        let mut events = Vec::with_capacity(native.events().len());
        for event in native.events() {
            let mut attributes = Vec::with_capacity(event.attributes().len());
            for attribute in event.attributes() {
                attributes.push(
                    ExecutionEventAttributeV0::new(
                        attribute.key().as_bytes().to_vec(),
                        attribute.value().as_bytes().to_vec(),
                    )
                    .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)?,
                );
            }
            events.push(
                ExecutionEventV0::new(event.kind().as_bytes().to_vec(), attributes)
                    .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)?,
            );
        }
        let receipt = ExecutionReceiptCommitmentV0::for_transaction(
            payload,
            native.transaction_index(),
            native.gas_used(),
            native.fee_charged(),
            events,
        )
        .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)?;
        let encoded = receipt
            .try_cev0_bytes()
            .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)?;
        if native.transaction_digest().as_bytes() != receipt.payload_leaf_hash()
            || native.commitment().as_bytes()
                != &domain_hash_v0(NATIVE_RECEIPT_COMMITMENT_DOMAIN_V0, &[&encoded])
        {
            return Err(PocoNodeNativeProposalPHostErrorV0::ApplicationSubstitution);
        }
        receipts.push(receipt);
    }
    ExecutionReceiptsV0::new(payload, receipts)
        .map_err(|_| PocoNodeNativeProposalPHostErrorV0::BodyBindingMismatch)
}

fn domain_hash_v0(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[derive(Debug)]
pub(super) enum PocoNodeNativeProposalPHostErrorV0<E> {
    NotReady,
    UnsupportedRoute,
    CoreBindingMismatch,
    ParentBindingMismatch,
    BodyBindingMismatch,
    PayloadDecode,
    EmptyOrMismatchedPayload,
    NativeBoundary(&'static str),
    ApplicationSubstitution,
    DeterministicallyInvalid,
    Unavailable,
    StoreNotApplied,
    ArtifactReadbackMismatch,
    IncompleteParentAuthority,
    SafetyPathMismatch,
    SafetyBindingMismatch,
    WholeNodeCheckpointBinding,
    UnexpectedPostCheckpointEffect,
    WholeNodeCheckpoint(NativeKNodeCheckpointAdvanceErrorV0),
    Application(E),
    Store(ValidationStoreErrorV0),
    Safety(SafetyStoreErrorV0),
    Core(CoreError),
}

impl<E: fmt::Display> fmt::Display for PocoNodeNativeProposalPHostErrorV0<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => formatter.write_str("native proposal-P host is not ready"),
            Self::UnsupportedRoute => {
                formatter.write_str("native proposal-P host accepts only Proposal")
            }
            Self::CoreBindingMismatch => {
                formatter.write_str("Core validation identity differs from the exact block")
            }
            Self::ParentBindingMismatch => {
                formatter.write_str("Core parent differs from the native application parent")
            }
            Self::BodyBindingMismatch => {
                formatter.write_str("canonical block body does not bind the header roots")
            }
            Self::PayloadDecode => {
                formatter.write_str("application payload is not exact canonical CEV0")
            }
            Self::EmptyOrMismatchedPayload => {
                formatter.write_str("ordinary proposal payload is empty or count-mismatched")
            }
            Self::NativeBoundary(field) => write!(formatter, "native boundary rejected {field}"),
            Self::ApplicationSubstitution => {
                formatter.write_str("native application substituted the execution request")
            }
            Self::DeterministicallyInvalid => {
                formatter.write_str("native application rejected the block deterministically")
            }
            Self::Unavailable => formatter.write_str("native application is unavailable"),
            Self::StoreNotApplied => formatter.write_str("durable P commit was proven not applied"),
            Self::ArtifactReadbackMismatch => {
                formatter.write_str("durable P readback differs from the exact artifact")
            }
            Self::IncompleteParentAuthority => formatter
                .write_str("durable P parent lacks authenticated application-state authority"),
            Self::SafetyPathMismatch => {
                formatter.write_str("SafetyStore path differs from the pinned node authority")
            }
            Self::SafetyBindingMismatch => formatter
                .write_str("SafetyStore confirmation differs from the exact Core-D transition"),
            Self::WholeNodeCheckpointBinding => {
                formatter.write_str("whole-node checkpoint differs from the exact Core-D barrier")
            }
            Self::UnexpectedPostCheckpointEffect => formatter.write_str(
                "CAS-authorized Core StorageAck did not return one exact inert RequestSignature",
            ),
            Self::WholeNodeCheckpoint(error) => {
                write!(formatter, "whole-node checkpoint failed: {error}")
            }
            Self::Application(error) => write!(formatter, "native application failed: {error}"),
            Self::Store(error) => write!(formatter, "native proposal-P store failed: {error}"),
            Self::Safety(error) => write!(formatter, "SafetyStore failed: {error}"),
            Self::Core(error) => {
                write!(formatter, "Core rejected application-sealed Valid: {error}")
            }
        }
    }
}

impl<E: Error + 'static> Error for PocoNodeNativeProposalPHostErrorV0<E> {}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fs, path::PathBuf};

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;
    use trnm_consensus_core::{leader_for, Core, CoreConfig, Effect, Input};
    use trnm_consensus_crypto::StrictEd25519Verifier;
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, ChainId, ConsensusPublicKey, Epoch,
        ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height,
        ProposalWitnessV0, ProtocolVersion, QcReferenceV0, SignatureBytes, SignedProposalV0,
        StateRoot, Validator, ValidatorId, ValidatorSet, View, VotingPower,
    };
    use trnm_native_application::{
        ApplicationCommitIdV0, NativeApplicationCommitRequestV0, NativeApplicationCommitResultV0,
        NativeApplicationGenesisRequestV0, NativeApplicationGenesisResultV0,
        NativeApplicationRecoveryRequestV0, NativeApplicationRecoveryResultV0,
        NativeExecutedBlockV0, NativeExecutionReceiptV0, NativeSnapshotManifestV0,
        NativeSnapshotRequestV0, NativeStateProofRequestV0, NativeStateProofV0,
    };

    use super::*;

    const TEST_CHAIN: ChainId = ChainId::from_static("trnm-native-p-host-test");

    struct FixtureV0 {
        keys: Vec<(ValidatorId, SigningKey)>,
        parameters: ConsensusParametersV0,
        validator_set: ValidatorSet,
        config: CoreConfig,
    }

    impl FixtureV0 {
        fn new() -> Self {
            let parameters = ConsensusParametersV0::reference_shadow_v0();
            let keys = (1_u8..=4)
                .map(|index| {
                    (
                        ValidatorId::new([index; 32]),
                        SigningKey::from_bytes(&[index.saturating_add(40); 32]),
                    )
                })
                .collect::<Vec<_>>();
            let validators = keys
                .iter()
                .map(|(id, key)| {
                    Validator::new(
                        *id,
                        ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                        VotingPower::new(1).expect("positive power"),
                    )
                    .expect("valid validator")
                })
                .collect();
            let validator_set = ValidatorSet::new(
                GenesisHash::new([0xa5; 32]),
                TEST_CHAIN,
                ProtocolVersion::V0,
                Epoch::new(0),
                parameters.hash(),
                validators,
            )
            .expect("valid validator set");
            let config = CoreConfig::new(keys[0].0, validator_set.clone(), parameters, 0, 32, 64)
                .expect("valid Core config");
            Self {
                keys,
                parameters,
                validator_set,
                config,
            }
        }

        fn genesis_qc(&self) -> GenesisQcV0 {
            GenesisQcV0::new(
                self.validator_set.genesis_hash(),
                self.validator_set.chain_id(),
                &self.validator_set,
            )
            .expect("valid genesis QC")
        }

        fn proposal(&self, transaction: &[u8]) -> SignedProposalV0 {
            let payload = ApplicationPayloadV0::new(vec![transaction.to_vec()])
                .expect("non-empty canonical payload");
            let receipts = ExecutionReceiptsV0::new(
                &payload,
                vec![
                    ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 0, 0, Vec::new())
                        .expect("canonical receipt"),
                ],
            )
            .expect("receipt set");
            let body = BlockBodyV0::new(payload, Vec::new()).expect("canonical body");
            let view = View::new(1);
            let proposer = leader_for(&self.validator_set, view);
            let header = BlockHeader::new(
                self.validator_set.genesis_hash(),
                self.validator_set.chain_id(),
                self.validator_set.protocol_version(),
                self.validator_set.epoch(),
                view,
                Height::new(1),
                BlockKind::Regular,
                trnm_consensus_types::BlockId::new(*self.validator_set.genesis_hash().as_bytes()),
                proposer,
                self.validator_set.id(),
                self.validator_set.consensus_parameters_hash(),
                body.payload_root().expect("payload root"),
                StateRoot::new([0x71; 32]),
                receipts.receipts_root().expect("receipts root"),
                body.evidence_root().expect("evidence root"),
                100,
                None,
            )
            .expect("valid header");
            let block = Block::new(
                header,
                body.application_payload()
                    .try_cev0_bytes()
                    .expect("payload bytes"),
                Vec::new(),
            )
            .expect("valid block");
            let justify = QcReferenceV0::genesis_anchor(self.genesis_qc());
            let root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
                .expect("proposal root");
            let key = self
                .keys
                .iter()
                .find_map(|(id, key)| (*id == proposer).then_some(key))
                .expect("proposer key");
            let witness = ProposalWitnessV0::new(
                block.header(),
                justify,
                None,
                None,
                SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes()),
                &self.validator_set,
                None,
                &self.parameters,
                0,
            )
            .expect("valid witness");
            SignedProposalV0::new(
                block,
                witness,
                &self.validator_set,
                None,
                &self.parameters,
                0,
            )
            .expect("valid proposal")
        }

        fn claimed_request(&self) -> ClaimedPayloadValidationRequestV0 {
            let mut core = Core::new(
                self.config.clone(),
                self.genesis_qc(),
                &StrictEd25519Verifier,
            )
            .expect("fresh Core");
            let effects = core
                .step(
                    Input::Proposal(Box::new(self.proposal(b"non-empty-native-transaction"))),
                    &StrictEd25519Verifier,
                )
                .expect("proposal accepted");
            let [Effect::PersistSafetyState(persistence)] = effects.as_slice() else {
                panic!("expected proposal obligation persistence: {effects:?}");
            };
            let released = core
                .step(
                    Input::StorageAck {
                        barrier: persistence.barrier(),
                    },
                    &StrictEd25519Verifier,
                )
                .expect("release exact request in test fixture");
            let request = released.into_iter().find_map(|effect| match effect {
                Effect::ValidatePayload(request) => Some(request),
                _ => None,
            });
            request
                .expect("one Core-issued Proposal validation request")
                .try_claim()
                .expect("claim exact request")
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock error")
        }
    }

    impl Error for MockError {}

    struct ExactApplicationV0 {
        observed_nonempty: RefCell<bool>,
    }

    impl NativeApplicationV0 for ExactApplicationV0 {
        type Error = MockError;

        fn initialize(
            &self,
            _: NativeApplicationGenesisRequestV0,
        ) -> Result<NativeApplicationGenesisResultV0, Self::Error> {
            unreachable!()
        }

        fn execute_block(
            &self,
            request: NativeBlockExecutionRequestV0,
        ) -> Result<NativeBlockExecutionResultV0, Self::Error> {
            *self.observed_nonempty.borrow_mut() = !request.transactions().is_empty();
            let receipts = request
                .transactions()
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    NativeExecutionReceiptV0::new(
                        index as u32,
                        Hash32V0::new([0x81; 32]),
                        0,
                        0,
                        Vec::new(),
                        Hash32V0::new([0x82; 32]),
                    )
                    .expect("mock receipt")
                })
                .collect();
            let expected = request.expected();
            Ok(NativeBlockExecutionResultV0::valid(
                NativeExecutedBlockV0::new(
                    request,
                    expected.payload_root(),
                    expected.post_state_root(),
                    expected.receipts_root(),
                    expected.evidence_root(),
                    receipts,
                )
                .expect("exact execution"),
            ))
        }

        fn commit_block(
            &self,
            _: NativeApplicationCommitRequestV0,
        ) -> Result<NativeApplicationCommitResultV0, Self::Error> {
            unreachable!()
        }

        fn state_proof(
            &self,
            _: NativeStateProofRequestV0,
        ) -> Result<NativeStateProofV0, Self::Error> {
            unreachable!()
        }

        fn snapshot(
            &self,
            _: NativeSnapshotRequestV0,
        ) -> Result<NativeSnapshotManifestV0, Self::Error> {
            unreachable!()
        }

        fn recover(
            &self,
            _: NativeApplicationRecoveryRequestV0,
        ) -> Result<NativeApplicationRecoveryResultV0, Self::Error> {
            unreachable!()
        }
    }

    fn protected_store_path() -> (TempDir, PathBuf) {
        let root = TempDir::new().expect("temporary root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("protect root");
        }
        let parent = root.path().join("p");
        fs::create_dir(&parent).expect("store parent");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                .expect("protect store parent");
        }
        let path = parent.join("proposal-p.sqlite3");
        (root, path)
    }

    fn genesis_application_head(fixture: &FixtureV0) -> ApplicationHeadV0 {
        ApplicationHeadV0::new(
            HeightV0::GENESIS,
            BlockIdV0::new(*fixture.validator_set.genesis_hash().as_bytes())
                .expect("genesis block id"),
            StateRootV0::new([0x61; 32]).expect("genesis app state"),
            ApplicationCommitIdV0::new([0x62; 32]).expect("genesis app commit"),
        )
    }

    #[test]
    fn core_issued_nonempty_proposal_reaches_only_durable_p_and_reopens_exactly() {
        let fixture = FixtureV0::new();
        let claimed = fixture.claimed_request();
        let (root, path) = protected_store_path();
        let scope = ProposalValidationStoreScopeV0::new([0x91; 32]).expect("scope");
        let owner = ProposalValidationOwnerIdV0::new([0x92; 32]).expect("owner");
        let application = ExactApplicationV0 {
            observed_nonempty: RefCell::new(false),
        };
        let mut host = PocoNodeNativeProposalPHostV0::open_for_test_v0(
            application,
            PocoNodeNativeProposalPHostConfigV0 {
                store_path: path.clone(),
                scope,
                minimum_durable_sequence: 0,
                owner_id: owner,
                authenticated_application_head: genesis_application_head(&fixture),
                authenticated_application_overlay: None,
                consensus_parameters: fixture.parameters,
                validator_set: fixture.validator_set.clone(),
            },
        )
        .expect("open private P host");

        let persisted = host
            .execute_and_persist_p_v0(claimed)
            .expect("persist exact P");
        assert_eq!(
            host.status_v0(),
            PocoNodeNativeProposalPHostStatusV0::Persisted
        );
        assert!(!persisted.parent_authority_complete());
        assert_eq!(
            persisted.closure_stage_v0(),
            PocoNodeNativeProposalClosureStageV0::DurableExecutionArtifactP
        );
        assert_eq!(persisted.closure_stage_v0().code(), 1);
        assert_eq!(
            persisted.next_required_authority_v0(),
            PocoNodeNativeProposalNextAuthorityV0::DurableSpeculativeOverlayAndCoreAffinedApplicationSeal
        );
        assert_eq!(persisted.next_required_authority_v0().code(), 1);
        let fact = host.inspect_p_v0(&persisted).expect("inspect exact P");
        assert_eq!(fact.stage(), DurableValidationStageV0::Reserved);
        assert!(!fact.outbox_present());
        let core_id = persisted.validation_id();
        assert_eq!(
            core_id.block_id().as_bytes(),
            persisted.binding.block_id().as_bytes()
        );

        drop(host);
        let mut reopened =
            SqliteProposalValidationStoreV0::open(&path, scope, fact.store_sequence())
                .expect("reopen exact P store");
        let reopened_fact = reopened
            .inspect_exact_v0(persisted.binding_for_test_v0())
            .expect("reopen exact binding");
        assert_eq!(reopened_fact, fact);
        let artifact = reopened
            .read_artifact_exact_v0(persisted.binding_for_test_v0())
            .expect("reconstruct exact artifact after reopen");
        assert_eq!(
            artifact.request().transactions(),
            &[b"non-empty-native-transaction".to_vec()]
        );
        assert_eq!(artifact.request().block_id(), persisted.binding.block_id());
        let _ = root;
    }

    #[test]
    fn private_p_host_never_reuses_one_core_request_or_emits_an_outbox() {
        let fixture = FixtureV0::new();
        let claimed = fixture.claimed_request();
        let (_root, path) = protected_store_path();
        let mut host = PocoNodeNativeProposalPHostV0::open_for_test_v0(
            ExactApplicationV0 {
                observed_nonempty: RefCell::new(false),
            },
            PocoNodeNativeProposalPHostConfigV0 {
                store_path: path,
                scope: ProposalValidationStoreScopeV0::new([0xa1; 32]).expect("scope"),
                minimum_durable_sequence: 0,
                owner_id: ProposalValidationOwnerIdV0::new([0xa2; 32]).expect("owner"),
                authenticated_application_head: genesis_application_head(&fixture),
                authenticated_application_overlay: None,
                consensus_parameters: fixture.parameters,
                validator_set: fixture.validator_set.clone(),
            },
        )
        .expect("open private P host");
        let persisted = host
            .execute_and_persist_p_v0(claimed)
            .expect("persist exact P");
        assert!(matches!(
            host.execute_and_persist_p_v0(fixture.claimed_request()),
            Err(PocoNodeNativeProposalPHostErrorV0::NotReady)
        ));
        let fact = host.inspect_p_v0(&persisted).expect("P remains exact");
        assert_eq!(fact.stage(), DurableValidationStageV0::Reserved);
        assert!(!fact.outbox_present());
    }
}
