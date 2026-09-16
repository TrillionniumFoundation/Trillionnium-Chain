//! Retained outgoing-set checkpoint/seal state. This cannot install a new epoch.
use crate::{CoreError, PayloadValidationParentV0, Result, SafetyState};
use alloc::vec::Vec;
use trnm_consensus_types::{
    validate_empty_epoch_seal_v1, BlockKind, ConsensusParametersV0, SignedProposalV0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OldEpochBoundaryPhaseV1 {
    Running,
    CheckpointPrepared,
    CheckpointCertified,
    Seal1Certified,
    CheckpointApplied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOldEpochCheckpointV1 {
    proposal: SignedProposalV0,
    parent: PayloadValidationParentV0,
}
impl PreparedOldEpochCheckpointV1 {
    pub const fn proposal(&self) -> &SignedProposalV0 {
        &self.proposal
    }
    pub const fn parent(&self) -> &PayloadValidationParentV0 {
        &self.parent
    }
}

/// The active CoreConfig scopes every retained coordinate to the unchanged
/// outgoing epoch. This owner has no new-set configuration and cannot reset
/// signing views. Multiple prepared forks are retained: a local execution is
/// not a finality decision. All collections have the existing Core count and
/// aggregate resource bounds; no peer can grow a separate unmetered cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OldEpochBoundaryStateV1 {
    owner_generation: u64,
    checkpoints: Vec<PreparedOldEpochCheckpointV1>,
    seals: Vec<SignedProposalV0>,
}
impl OldEpochBoundaryStateV1 {
    pub(crate) fn new(owner_generation: u64) -> Result<Self> {
        if owner_generation == 0 {
            return Err(CoreError::InvalidRecovery(
                "epoch owner generation must be positive",
            ));
        }
        Ok(Self {
            owner_generation,
            checkpoints: Vec::new(),
            seals: Vec::new(),
        })
    }
    pub const fn owner_generation(&self) -> u64 {
        self.owner_generation
    }
    pub fn checkpoints(&self) -> &[PreparedOldEpochCheckpointV1] {
        &self.checkpoints
    }
    pub fn seals(&self) -> &[SignedProposalV0] {
        &self.seals
    }
    pub fn phase(&self, state: &SafetyState) -> OldEpochBoundaryPhaseV1 {
        if self
            .checkpoints
            .iter()
            .any(|c| state.application_applied().block_id() == c.proposal.block().id())
        {
            OldEpochBoundaryPhaseV1::CheckpointApplied
        } else if self
            .seals
            .iter()
            .any(|s| s.block().header().block_kind() == BlockKind::EpochSeal2)
        {
            OldEpochBoundaryPhaseV1::Seal1Certified
        } else if !self.seals.is_empty() {
            OldEpochBoundaryPhaseV1::CheckpointCertified
        } else if !self.checkpoints.is_empty() {
            OldEpochBoundaryPhaseV1::CheckpointPrepared
        } else {
            OldEpochBoundaryPhaseV1::Running
        }
    }
    pub(crate) fn record_checkpoint(
        &mut self,
        proposal: &SignedProposalV0,
        parent: PayloadValidationParentV0,
        maximum: usize,
    ) -> Result<()> {
        if proposal.block().header().block_kind() != BlockKind::EpochCheckpoint {
            return Err(CoreError::UnsupportedBlockKind);
        }
        if let Some(existing) = self
            .checkpoints
            .iter()
            .find(|c| c.proposal.block().id() == proposal.block().id())
        {
            return if existing.proposal == *proposal && existing.parent == parent {
                Ok(())
            } else {
                Err(CoreError::ConflictingBlock(proposal.block().id()))
            };
        }
        self.check_capacity(proposal, maximum)?;
        self.checkpoints.push(PreparedOldEpochCheckpointV1 {
            proposal: proposal.clone(),
            parent,
        });
        self.checkpoints.sort_by_key(|c| c.proposal.block().id());
        Ok(())
    }
    pub(crate) fn record_seal(
        &mut self,
        proposal: &SignedProposalV0,
        parameters: &ConsensusParametersV0,
        maximum: usize,
    ) -> Result<()> {
        if self.seals.iter().any(|s| s == proposal) {
            return Ok(());
        }
        if self
            .seals
            .iter()
            .any(|s| s.block().id() == proposal.block().id())
        {
            return Err(CoreError::ConflictingBlock(proposal.block().id()));
        }
        let parent_id = proposal.block().header().parent_id();
        let parent = self
            .checkpoints
            .iter()
            .map(|c| &c.proposal)
            .chain(self.seals.iter())
            .find(|p| p.block().id() == parent_id)
            .ok_or(CoreError::MissingBlock(parent_id))?;
        validate_empty_epoch_seal_v1(proposal, parent.block().header(), parameters)?;
        self.check_capacity(proposal, maximum)?;
        self.seals.push(proposal.clone());
        self.seals
            .sort_by_key(|s| (s.block().header().height(), s.block().id()));
        Ok(())
    }
    pub(crate) fn validate<V: trnm_consensus_types::SignatureVerifier>(
        &self,
        config: &crate::CoreConfig,
        state: &SafetyState,
        verifier: &V,
    ) -> Result<()> {
        use trnm_consensus_types::{validate_root_bound_epoch_body_v1, EpochGeometryV0};
        if self.owner_generation == 0
            || state.schema_version() != 14
            || self
                .checkpoints
                .windows(2)
                .any(|p| p[0].proposal.block().id() >= p[1].proposal.block().id())
            || self.seals.windows(2).any(|p| {
                (p[0].block().header().height(), p[0].block().id())
                    >= (p[1].block().header().height(), p[1].block().id())
            })
        {
            return Err(CoreError::InvalidRecovery(
                "invalid or unsorted outgoing epoch record",
            ));
        }
        if state.payload_validation_obligations().iter().any(|o| {
            matches!(
                o.proposal().block().header().block_kind(),
                BlockKind::EpochSeal1 | BlockKind::EpochSeal2
            )
        }) {
            return Err(CoreError::InvalidRecovery(
                "seal may not create an application validation obligation",
            ));
        }
        let geometry = EpochGeometryV0::new(
            config.validator_set().epoch(),
            config.consensus_parameters(),
        )?;
        if state.finalized().height() > geometry.checkpoint_height()
            || state.application_applied().height() > geometry.checkpoint_height()
        {
            return Err(CoreError::InvalidRecovery(
                "outgoing epoch cannot finalize or apply a seal",
            ));
        }
        let mut rebuilt = Self::new(self.owner_generation)?;
        for checkpoint in &self.checkpoints {
            let p = &checkpoint.proposal;
            let h = p.block().header();
            let parent = checkpoint
                .parent
                .exact_header()
                .ok_or(CoreError::InvalidRecovery(
                    "checkpoint needs its exact authenticated parent header",
                ))?;
            if h.block_kind() != BlockKind::EpochCheckpoint
                || h.height() != geometry.checkpoint_height()
                || h.parent_id() != parent.id()
                || parent.height().checked_next()? != h.height()
                || p.witness().justify_qc().qc_ref().block_id() != parent.id()
                || p.witness().justify_qc().qc_ref().view() != parent.view()
                || p.witness().justify_qc().qc_ref().height() != parent.height()
                || parent.epoch() != h.epoch()
                || parent.validator_set_id() != h.validator_set_id()
                || checkpoint.parent.tip().block_id() != parent.id()
                || !state.payload_terminal_fact(h.id()).is_some_and(|f| {
                    f.valid_overlay().is_some_and(|o| {
                        o.block_id() == h.id() && o.parent_block_id() == parent.id()
                    })
                })
            {
                return Err(CoreError::InvalidRecovery(
                    "checkpoint differs from authenticated parent or actual application Valid fact",
                ));
            }
            validate_root_bound_epoch_body_v1(
                p.block(),
                config.validator_set(),
                config.consensus_parameters(),
            )
            .map_err(|_| {
                CoreError::InvalidRecovery("checkpoint retained body differs from its signed roots")
            })?;
            p.verify(
                config.validator_set(),
                None,
                config.consensus_parameters(),
                parent.timestamp_ms(),
                verifier,
            )?;
            rebuilt.record_checkpoint(
                p,
                checkpoint.parent.clone(),
                config.max_observed_messages(),
            )?;
        }
        for seal in &self.seals {
            let parent = self
                .checkpoints
                .iter()
                .map(|c| &c.proposal)
                .chain(self.seals.iter())
                .find(|p| p.block().id() == seal.block().header().parent_id())
                .ok_or(CoreError::MissingBlock(seal.block().header().parent_id()))?;
            seal.verify(
                config.validator_set(),
                None,
                config.consensus_parameters(),
                parent.block().header().timestamp_ms(),
                verifier,
            )?;
            if state.payload_terminal_fact(seal.block().id()).is_some()
                || state
                    .payload_validation_obligations()
                    .iter()
                    .any(|o| o.proposal().block().id() == seal.block().id())
            {
                return Err(CoreError::InvalidRecovery(
                    "consensus seal has an application record",
                ));
            }
            rebuilt.record_seal(
                seal,
                config.consensus_parameters(),
                config.max_observed_messages(),
            )?;
        }
        if rebuilt != *self {
            return Err(CoreError::InvalidRecovery(
                "outgoing epoch record is not canonical",
            ));
        }
        Ok(())
    }

    fn check_capacity(&self, proposal: &SignedProposalV0, maximum: usize) -> Result<()> {
        if self
            .checkpoints
            .len()
            .checked_add(self.seals.len())
            .is_none_or(|n| n >= maximum)
        {
            return Err(CoreError::InvalidRecovery(
                "retained epoch boundary evidence exceeds count bound",
            ));
        }
        let mut bytes = proposal.durable_validation_resource_size_v0()?;
        for p in self
            .checkpoints
            .iter()
            .map(|c| &c.proposal)
            .chain(self.seals.iter())
        {
            bytes = bytes
                .checked_add(p.durable_validation_resource_size_v0()?)
                .ok_or(CoreError::ArithmeticOverflow(
                    "retained epoch evidence bytes",
                ))?;
        }
        if bytes > crate::CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1 {
            return Err(CoreError::InvalidRecovery(
                "retained epoch boundary evidence exceeds byte bound",
            ));
        }
        Ok(())
    }
}
