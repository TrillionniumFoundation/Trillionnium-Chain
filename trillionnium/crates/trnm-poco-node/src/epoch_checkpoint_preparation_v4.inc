/// One checkpoint execution and Vote from the exact settled cutoff owner.
/// No finality, retirement, recovery, signer or Core capability is exposed.
#[must_use]
pub struct EpochCheckpointPreparationRuntimeV4<
    W: ExternalSignerRetirementV1,
    N: ExternalMonotonicWatermarkV0,
> {
    inner: Option<Box<FirstEpochFinalizationRuntimeV2<W, N>>>,
    vote_released: bool,
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
    EpochOrdinaryContinuationRuntimeV3<W, N>
{
    pub fn into_checkpoint_preparation_v4(
        mut self,
    ) -> Result<EpochCheckpointPreparationRuntimeV4<W, N>> {
        self.settled_cutoff_checkpoint_v3()?;
        let geometry = trnm_consensus_types::EpochGeometryV0::new(
            self.inner.runtime.driver.config().validator_set().epoch(),
            self.inner.runtime.driver.config().consensus_parameters(),
        )
        .map_err(|e| anyhow::anyhow!("checkpoint geometry: {e:?}"))?;
        let mut parent = BlockId::new(self.inner.runtime.checkpoint.fields().application.block_id);
        for (index, p) in self.inner.prepared.iter().enumerate() {
            let confirmed = self
                .inner
                .runtime
                .application
                .confirm_prepared_epoch_execution_v1(&p.prepared)?;
            let header = confirmed.prepared().header()?;
            ensure!(
                confirmed.commit_sequence().is_none()
                    && header.block_kind() == BlockKind::Regular
                    && header.parent_id() == parent
                    && header.height().get() == self.cutoff_height + index as u64 + 1,
                "checkpoint lookahead lineage changed"
            );
            parent = header.id();
        }
        ensure!(
            self.inner
                .prepared
                .last()
                .context("checkpoint parent missing")?
                .prepared
                .header()?
                .height()
                .checked_next()
                .ok()
                == Some(geometry.checkpoint_height()),
            "checkpoint preparation needs the exact preceding lookahead"
        );
        self.inner.finality_observed = false;
        self.inner.applied = false;
        Ok(EpochCheckpointPreparationRuntimeV4 {
            inner: Some(Box::new(self.inner)),
            vote_released: false,
        })
    }
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
    EpochCheckpointPreparationRuntimeV4<W, N>
{
    /// Invalid read-only selection comparisons leave this owner available.
    /// Once mutation starts, any failure consumes its private live capability.
    pub fn execute_checkpoint_proposal_v4(&mut self, proposal: SignedProposalV0) -> Result<()> {
        let inner = self.inner.as_mut().context("checkpoint owner is fenced")?;
        ensure!(
            !self.vote_released
                && inner.prepared.len() == 2
                && inner.runtime.pending_epoch_commit.is_none(),
            "checkpoint preparation phase"
        );
        inner.require_collecting()?;
        let parent = inner
            .prepared
            .last()
            .context("checkpoint parent missing")?
            .prepared
            .header()?;
        let header = proposal.block().header();
        ensure!(
            header.block_kind() == BlockKind::EpochCheckpoint
                && header.parent_id() == parent.id()
                && parent.height().checked_next().ok() == Some(header.height()),
            "checkpoint proposal does not extend its exact Prepared parent"
        );
        let commitment = confirm_checkpoint_selection_v4(
            &inner.runtime.application,
            &inner.runtime.edge,
            &inner.runtime.checkpoint,
            header,
        )?;
        let inner = self.inner.take().context("checkpoint owner missing")?;
        let executed = (*inner).execute_application_child_v4(proposal, Some(commitment))?;
        self.inner = Some(Box::new(executed));
        Ok(())
    }

    pub fn sign_checkpoint_vote_v4<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        let mut inner = self.inner.take().context("checkpoint owner is fenced")?;
        ensure!(
            !self.vote_released && inner.prepared.len() == 2,
            "checkpoint Vote phase"
        );
        inner.runtime.confirm_current_cut_v1()?;
        let pending = inner
            .runtime
            .pending_epoch_commit
            .as_ref()
            .context("checkpoint Vote lacks P")?;
        let header = pending.prepared.header()?;
        let parent = inner
            .prepared
            .last()
            .context("checkpoint parent missing")?
            .prepared
            .header()?;
        ensure!(
            header.block_kind() == BlockKind::EpochCheckpoint
                && header.parent_id() == parent.id()
                && parent.height().checked_next().ok() == Some(header.height()),
            "checkpoint Vote parent changed"
        );
        confirm_checkpoint_selection_v4(
            &inner.runtime.application,
            &inner.runtime.edge,
            &inner.runtime.checkpoint,
            &header,
        )?;
        let (mut runtime, vote) = (*inner.runtime).finish_pending_application_vote_v3(producer)?;
        inner.prepared.push(
            runtime
                .pending_epoch_commit
                .take()
                .context("signed checkpoint P missing")?,
        );
        inner.runtime = Box::new(runtime);
        self.inner = Some(inner);
        self.vote_released = true;
        Ok((self, vote))
    }

    /// Inert comparison cut after the checkpoint Vote; no finality is implied.
    pub fn prepared_checkpoint_cut_v4(&mut self) -> Result<EpochNodeCheckpointV1> {
        let inner = self.inner.as_mut().context("checkpoint owner is fenced")?;
        ensure!(
            self.vote_released && inner.prepared.len() == 3,
            "checkpoint Vote not released"
        );
        inner.runtime.confirm_current_cut_v1()?;
        for p in &inner.prepared {
            ensure!(
                inner
                    .runtime
                    .application
                    .confirm_prepared_epoch_execution_v1(&p.prepared)?
                    .commit_sequence()
                    .is_none(),
                "checkpoint window unexpectedly committed"
            );
        }
        Ok(inner.runtime.checkpoint)
    }
}

// Inert selection is independently reproduced from the real active cutoff.
// This is also called after external callbacks on both sides of the key call.
fn confirm_checkpoint_selection_v4(
    application: &DurableNativeApplicationV0,
    edge: &AuthenticatedEpochApplicationEdgeV1,
    checkpoint: &EpochNodeCheckpointV1,
    header: &trnm_consensus_types::BlockHeader,
) -> Result<trnm_consensus_types::NextEpochCommitmentHash> {
    confirm_checkpoint_selection_at_active_cut_v4(
        application,
        checkpoint,
        header,
        edge.new_validator_set(),
        edge.new_parameters(),
    )
}

// Both the first and subsequent epoch owners consume this same comparison.
// The set and parameters come from the live Core, never from the proposal.
fn confirm_checkpoint_selection_at_active_cut_v4(
    application: &DurableNativeApplicationV0,
    checkpoint: &EpochNodeCheckpointV1,
    header: &trnm_consensus_types::BlockHeader,
    active_set: &trnm_consensus_types::ValidatorSet,
    active_parameters: &trnm_consensus_types::ConsensusParametersV0,
) -> Result<trnm_consensus_types::NextEpochCommitmentHash> {
    let geometry = trnm_consensus_types::EpochGeometryV0::new(
        active_set.epoch(),
        active_parameters,
    )
    .map_err(|e| anyhow::anyhow!("checkpoint selection geometry: {e:?}"))?;
    let cutoff = geometry
        .checkpoint_height()
        .get()
        .checked_sub(active_parameters.snapshot_lead_blocks())
        .context("checkpoint cutoff underflow")?;
    let selection = application
        .compute_later_epoch_selection_v1(trnm_native_application::HeightV0::new(cutoff))?;
    let app = &checkpoint.fields().application;
    let head = selection.cutoff_head();
    ensure!(
        app.height == cutoff
            && head.height().get() == cutoff
            && head.block_id().as_bytes() == &app.block_id
            && head.state_root().as_bytes() == &app.state_root
            && head.commit_id().as_bytes() == &app.native_commit_id
            && selection.cutoff_p_digest() == app.p_digest
            && selection.cutoff_p_sequence() == app.p_sequence
            && selection.cutoff_commit_sequence() == app.commit_sequence
            && header.block_kind() == BlockKind::EpochCheckpoint
            && header.height() == geometry.checkpoint_height()
            && header.epoch() == active_set.epoch()
            && header.validator_set_id() == active_set.id()
            && header.consensus_parameters_hash() == active_parameters.hash(),
        "checkpoint selection differs from the independent cutoff"
    );
    let commitment = selection.next_epoch_commitment().id();
    ensure!(
        header.next_epoch_commitment_hash() == Some(commitment),
        "checkpoint commitment differs from actual cutoff selection"
    );
    Ok(commitment)
}
