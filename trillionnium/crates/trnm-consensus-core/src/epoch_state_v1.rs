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

#[cfg(test)]
std::thread_local! {
    static STRICT_CONTEXT_CALLS_V1: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn count_strict_context_calls_v1<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let before = STRICT_CONTEXT_CALLS_V1.with(core::cell::Cell::get);
    let result = operation();
    let after = STRICT_CONTEXT_CALLS_V1.with(core::cell::Cell::get);
    (result, after - before)
}

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
    provenance: EpochProvenanceV2,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum EpochProvenanceV2 {
    LegacyV1,
    PrefixV2 {
        record: Arc<crate::EpochPreparationRecordV2>,
        root_set: Arc<ValidatorSet>,
        root_parameters: Arc<ConsensusParametersV0>,
    },
}
impl EpochCoreStateV1 {
    pub(crate) fn from_strict(
        context: &StrictEpochRuntimeContextV1,
        checkpoint_artifact: ValidatedPayloadArtifactRefV0,
        owner_generation: u64,
    ) -> Result<Self> {
        crate::epoch_preparation::validate_legacy_epoch_evidence_v1(context.activation())
            .map_err(|_| CoreError::InvalidRecovery("codec1 cannot retain contextual evidence"))?;
        Self::from_context_fields(
            context,
            checkpoint_artifact,
            owner_generation,
            EpochProvenanceV2::LegacyV1,
        )
    }
    fn from_context_fields(
        context: &StrictEpochRuntimeContextV1,
        checkpoint_artifact: ValidatedPayloadArtifactRefV0,
        owner_generation: u64,
        provenance: EpochProvenanceV2,
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
            provenance,
        })
    }
    pub(crate) fn from_preparation_v2(
        preparation: crate::EpochPreparationV2,
        checkpoint_artifact: ValidatedPayloadArtifactRefV0,
        owner_generation: u64,
    ) -> Result<(Self, StrictEpochRuntimeContextV1)> {
        let parts = preparation.into_parts_v2();
        let context = StrictEpochRuntimeContextV1::from_activation_v1(*parts.authority)?;
        let provenance = EpochProvenanceV2::PrefixV2 {
            record: Arc::new(parts.record),
            root_set: Arc::new(parts.root_set),
            root_parameters: Arc::new(parts.root_parameters),
        };
        let state =
            Self::from_context_fields(&context, checkpoint_artifact, owner_generation, provenance)?;
        Ok((state, context))
    }
    pub fn preparation_record_v2(&self) -> Option<&crate::EpochPreparationRecordV2> {
        match &self.provenance {
            EpochProvenanceV2::LegacyV1 => None,
            EpochProvenanceV2::PrefixV2 { record, .. } => Some(record),
        }
    }
    /// Strictly reconstruct the complete preparation from this privately
    /// retained root trust and exact provenance. The caller's existing work
    /// charges and narrower admission limits remain effective. This returns
    /// no journal freshness, native receipt, signer lease or live Core.
    pub fn recover_preparation_v2(
        &self,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<crate::EpochPreparationV2> {
        let EpochProvenanceV2::PrefixV2 {
            record,
            root_set,
            root_parameters,
        } = &self.provenance
        else {
            return Err(CoreError::InvalidRecovery(
                "legacy epoch lacks complete preparation provenance",
            ));
        };
        crate::recover_epoch_preparation_v2(
            record.as_bytes_v2(),
            root_set,
            root_parameters,
            record.root_binding_v2(),
            self.binding,
            record.digest_v2(),
            budget,
        )
        .map_err(|_| {
            CoreError::InvalidRecovery("complete epoch provenance failed strict reconstruction")
        })
    }
    pub(crate) fn check_predecessor_provenance_v2(&self, previous: Option<&Self>) -> Result<()> {
        let EpochProvenanceV2::PrefixV2 {
            record,
            root_set,
            root_parameters,
        } = &self.provenance
        else {
            return Err(CoreError::InvalidRecovery(
                "codec2 target lacks complete provenance",
            ));
        };
        let valid = match previous {
            None => record.entry_count_v2() == 1,
            Some(previous) => match &previous.provenance {
                EpochProvenanceV2::LegacyV1 => {
                    root_set.as_ref() == &previous.old_set
                        && root_parameters.as_ref() == &previous.old_parameters
                        && record
                            .extends_legacy_v1(previous.binding, previous.evidence.as_preimages())
                            .map_err(|_| CoreError::InvalidRecovery("legacy provenance framing"))?
                }
                EpochProvenanceV2::PrefixV2 {
                    record: prior,
                    root_set: prior_set,
                    root_parameters: prior_parameters,
                } => {
                    root_set == prior_set
                        && root_parameters == prior_parameters
                        && record.extends_record_v2(prior).map_err(|_| {
                            CoreError::InvalidRecovery("provenance extension framing")
                        })?
                }
            },
        };
        if !valid {
            return Err(CoreError::InvalidRecovery(
                "epoch provenance is not an exact one-entry extension",
            ));
        }
        Ok(())
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
        #[cfg(test)]
        STRICT_CONTEXT_CALLS_V1.with(|calls| calls.set(calls.get() + 1));
        let context = match &self.provenance {
            EpochProvenanceV2::LegacyV1 => {
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
                StrictEpochRuntimeContextV1::from_activation_v1(activation)?
            }
            EpochProvenanceV2::PrefixV2 { .. } => {
                // One bounded meter for the complete retained prefix. Every
                // entry still enforces authenticated outgoing byte limits.
                let mut budget = Cev0AdmissionBudgetV0::with_limits(
                    trnm_consensus_types::MAX_CEV0_ROOT_BYTES_V0,
                    trnm_consensus_types::MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0,
                    trnm_consensus_types::MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES,
                );
                let preparation = self.recover_preparation_v2(&mut budget)?;
                StrictEpochRuntimeContextV1::from_activation_v1(
                    *preparation.into_parts_v2().authority,
                )?
            }
        };
        let reconstructed = Self::from_context_fields(
            &context,
            self.checkpoint_artifact,
            self.owner_generation,
            self.provenance.clone(),
        )?;
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

#[cfg(test)]
#[path = "epoch_provenance_tests_v2.rs"]
mod epoch_provenance_tests_v2;
