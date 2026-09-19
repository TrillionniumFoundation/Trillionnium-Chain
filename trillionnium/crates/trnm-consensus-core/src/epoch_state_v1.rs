//! Epoch-qualified persistence facts and the distinct consensus ancestry base.
use crate::{CoreError, FinalizedTip, Result, ValidatedPayloadArtifactRefV0};
use alloc::{boxed::Box, sync::Arc};
use trnm_consensus_crypto::{
    recover_epoch_activation_authority_strict_v0, StrictEpochRuntimeContextV1,
};
use trnm_consensus_types::{
    BlockHeader, Cev0AdmissionBudgetV0, ConsensusParametersHash, ConsensusParametersV0, Epoch,
    EpochActivationEvidenceBytesV0, QcReferenceV0, ValidatorSet, ValidatorSetId, View,
};

/// Inert complete scope for a real finalized/application tip. No view from a
/// different epoch may be ordered numerically against this tip's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualifiedFinalizedTipV1 {
    epoch: Epoch,
    validator_set: ValidatorSetId,
    parameters: ConsensusParametersHash,
    tip: FinalizedTip,
}
impl QualifiedFinalizedTipV1 {
    pub fn from_header(header: &BlockHeader) -> Self {
        Self {
            epoch: header.epoch(),
            validator_set: header.validator_set_id(),
            parameters: header.consensus_parameters_hash(),
            tip: FinalizedTip::new(
                header.height(),
                header.view(),
                header.id(),
                header.timestamp_ms(),
            ),
        }
    }
    pub(crate) const fn from_scope(set: &ValidatorSet, tip: FinalizedTip) -> Self {
        Self {
            epoch: set.epoch(),
            validator_set: set.id(),
            parameters: set.consensus_parameters_hash(),
            tip,
        }
    }
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }
    pub const fn validator_set_id(self) -> ValidatorSetId {
        self.validator_set
    }
    pub const fn parameters_hash(self) -> ConsensusParametersHash {
        self.parameters
    }
    pub const fn tip(self) -> FinalizedTip {
        self.tip
    }
}

/// The graph root used for parent/lock traversal. `EpochAnchor` is not a finality
/// certificate and does not update the separately retained real applied tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusAncestryBaseV1 {
    Finalized(QualifiedFinalizedTipV1),
    EpochAnchor {
        terminal_old_header: Box<BlockHeader>,
        new_epoch_reference: QcReferenceV0,
        activation_binding: [u8; 32],
    },
}
impl ConsensusAncestryBaseV1 {
    /// Internal graph comparison only. In the anchor case view zero belongs to
    /// the new synthetic reference; the actual old header remains unchanged.
    pub(crate) fn comparison_tip(&self) -> FinalizedTip {
        match self {
            Self::Finalized(tip) => tip.tip(),
            Self::EpochAnchor {
                terminal_old_header,
                new_epoch_reference,
                ..
            } => {
                let reference = new_epoch_reference.qc_ref();
                FinalizedTip::new(
                    reference.height(),
                    reference.view(),
                    reference.block_id(),
                    terminal_old_header.timestamp_ms(),
                )
            }
        }
    }
}

/// Bounded old/new evidence retained by full schema14. The private constructor
/// consumes strict evidence; decoding reconstructs only inert fields and must
/// reverify them before creating a live owner. This is not a custody lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCoreStateV1 {
    owner_generation: u64,
    old_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    evidence: Arc<EpochActivationEvidenceBytesV0>,
    binding: [u8; 32],
    checkpoint: BlockHeader,
    terminal: BlockHeader,
    anchor: QcReferenceV0,
    checkpoint_artifact: ValidatedPayloadArtifactRefV0,
}
impl EpochCoreStateV1 {
    pub(crate) fn from_strict(
        context: &StrictEpochRuntimeContextV1,
        checkpoint_artifact: ValidatedPayloadArtifactRefV0,
        owner_generation: u64,
    ) -> Result<Self> {
        let activation = context.activation();
        let checkpoint = activation
            .old_checkpoint_finality()
            .finalized_block()
            .header();
        if owner_generation == 0
            || checkpoint_artifact.overlay().block_id() != checkpoint.id()
            || checkpoint_artifact.overlay().parent_block_id() != checkpoint.parent_id()
            || checkpoint_artifact.source_artifact_checksum() == [0; 32]
            || checkpoint_artifact.overlay().overlay_checksum() == [0; 32]
        {
            return Err(CoreError::InvalidRecovery(
                "epoch checkpoint artifact or generation",
            ));
        }
        Ok(Self {
            owner_generation,
            old_set: activation.old_validator_set().clone(),
            old_parameters: *activation.old_consensus_parameters(),
            evidence: Arc::new(context.evidence_bytes().clone()),
            binding: *activation.binding_ref().as_bytes(),
            checkpoint: checkpoint.clone(),
            terminal: activation.terminal_old_header().clone(),
            anchor: context.anchor_reference().clone(),
            checkpoint_artifact,
        })
    }
    pub const fn owner_generation(&self) -> u64 {
        self.owner_generation
    }
    pub const fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_set
    }
    pub const fn old_parameters(&self) -> &ConsensusParametersV0 {
        &self.old_parameters
    }
    pub fn evidence_bytes(&self) -> &EpochActivationEvidenceBytesV0 {
        &self.evidence
    }
    pub const fn activation_binding(&self) -> [u8; 32] {
        self.binding
    }
    pub const fn checkpoint_header(&self) -> &BlockHeader {
        &self.checkpoint
    }
    pub const fn terminal_old_header(&self) -> &BlockHeader {
        &self.terminal
    }
    pub const fn anchor_reference(&self) -> &QcReferenceV0 {
        &self.anchor
    }
    pub const fn checkpoint_artifact(&self) -> ValidatedPayloadArtifactRefV0 {
        self.checkpoint_artifact
    }
    pub fn strict_context(&self) -> Result<StrictEpochRuntimeContextV1> {
        let mut budget = Cev0AdmissionBudgetV0::for_parameters(&self.old_parameters);
        let activation = recover_epoch_activation_authority_strict_v0(
            self.evidence.as_preimages(),
            &self.old_set,
            &self.old_parameters,
            self.binding,
            &mut budget,
        )
        .map_err(|_| {
            CoreError::InvalidRecovery("full epoch evidence failed strict reconstruction")
        })?;
        let context = StrictEpochRuntimeContextV1::from_activation_v1(activation)?;
        let reconstructed =
            Self::from_strict(&context, self.checkpoint_artifact, self.owner_generation)?;
        if &reconstructed != self {
            return Err(CoreError::InvalidRecovery(
                "full epoch evidence field substitution",
            ));
        }
        Ok(context)
    }
    pub(crate) fn ancestry_base(
        &self,
        finalized: QualifiedFinalizedTipV1,
    ) -> Result<ConsensusAncestryBaseV1> {
        if finalized.tip().block_id() == self.checkpoint.id() {
            if finalized != QualifiedFinalizedTipV1::from_header(&self.checkpoint)
                || self.anchor.qc_ref().view() != View::new(0)
            {
                return Err(CoreError::InvalidRecovery(
                    "epoch ancestry checkpoint scope",
                ));
            }
            Ok(ConsensusAncestryBaseV1::EpochAnchor {
                terminal_old_header: Box::new(self.terminal.clone()),
                new_epoch_reference: self.anchor.clone(),
                activation_binding: self.binding,
            })
        } else {
            Ok(ConsensusAncestryBaseV1::Finalized(finalized))
        }
    }
}
