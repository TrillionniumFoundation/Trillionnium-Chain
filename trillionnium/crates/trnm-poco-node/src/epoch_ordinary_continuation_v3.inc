/// Explicit same-owner ordinary continuation through the authenticated cutoff.
/// It retains a bounded genuine Prepared window and exposes no Core, signer,
/// application capability, or conversion back to the first-new owner.
#[must_use]
pub struct EpochOrdinaryContinuationRuntimeV3<
    W: ExternalSignerRetirementV1,
    N: ExternalMonotonicWatermarkV0,
> {
    inner: FirstEpochFinalizationRuntimeV2<W, N>,
    cutoff_height: u64,
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
    FirstEpochFinalizationRuntimeV2<W, N>
{
    /// Consume the completed first settlement while preserving its two exact
    /// speculative children and every original process owner.
    pub fn into_ordinary_continuation_v3(
        mut self,
    ) -> Result<EpochOrdinaryContinuationRuntimeV3<W, N>> {
        self.settled_checkpoint_v2()?;
        ensure!(
            self.prepared.len() == 3,
            "ordinary continuation initial P window"
        );
        let geometry = trnm_consensus_types::EpochGeometryV0::new(
            self.runtime.driver.config().validator_set().epoch(),
            self.runtime.driver.config().consensus_parameters(),
        )
        .map_err(|e| anyhow::anyhow!("ordinary cutoff geometry: {e:?}"))?;
        let cutoff_height = geometry
            .checkpoint_height()
            .get()
            .checked_sub(
                self.runtime
                    .driver
                    .config()
                    .consensus_parameters()
                    .snapshot_lead_blocks(),
            )
            .context("ordinary cutoff underflow")?;
        ensure!(
            cutoff_height
                .checked_add(2)
                .is_some_and(|height| height < geometry.checkpoint_height().get()),
            "ordinary cutoff needs two pre-checkpoint lookahead blocks"
        );
        let head = self.runtime.application.confirmed_committed_head_v0()?;
        ensure!(
            head.height().get() < cutoff_height,
            "ordinary cutoff is already reached"
        );
        for (index, retained) in self.prepared.iter().enumerate() {
            let p = self
                .runtime
                .application
                .confirm_prepared_epoch_execution_v1(&retained.prepared)?;
            let header = p.prepared().header()?;
            ensure!(
                header.height().get()
                    == head
                        .height()
                        .get()
                        .checked_add(index as u64)
                        .context("P window height overflow")?
                    && p.prepared().p_digest() == retained.prepared.p_digest()
                    && (index == 0) == p.commit_sequence().is_some(),
                "ordinary initial P window changed"
            );
            if index == 0 {
                ensure!(
                    p.prepared().overlay_parent_head()? == head,
                    "ordinary initial head changed"
                );
            } else {
                let parent = &self.prepared[index - 1].prepared;
                ensure!(
                    header.block_kind() == BlockKind::Regular
                        && header.parent_id() == parent.header()?.id()
                        && p.prepared().application_parent() == &parent.overlay_parent_head()?,
                    "ordinary initial P lineage changed"
                );
            }
        }
        self.prepared.remove(0);
        self.finality_observed = false;
        self.applied = false;
        Ok(EpochOrdinaryContinuationRuntimeV3 {
            inner: self,
            cutoff_height,
        })
    }
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
    EpochOrdinaryContinuationRuntimeV3<W, N>
{
    fn require_below_cutoff_v3(&self) -> Result<()> {
        ensure!(
            self.inner.runtime.checkpoint.fields().application.height < self.cutoff_height,
            "ordinary cutoff continuation is complete"
        );
        Ok(())
    }

    /// Execute one real ordinary lookahead proposal; this cannot call the key.
    pub fn execute_ordinary_proposal_v3(mut self, proposal: SignedProposalV0) -> Result<Self> {
        self.require_below_cutoff_v3()?;
        ensure!(
            self.inner.prepared.len() == 2
                && proposal.block().header().height().get()
                    <= self
                        .cutoff_height
                        .checked_add(2)
                        .context("ordinary lookahead overflow")?,
            "ordinary continuation lookahead bound"
        );
        self.inner = self.inner.execute_child_proposal_v2(proposal)?;
        Ok(self)
    }

    /// Release only the exact real application's persisted Vote obligation.
    pub fn sign_ordinary_vote_v3<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        self.require_below_cutoff_v3()?;
        ensure!(
            !self.inner.finality_observed && !self.inner.applied && self.inner.prepared.len() == 2,
            "ordinary continuation signing phase"
        );
        self.inner.runtime.confirm_current_cut_v1()?;
        let pending = self
            .inner
            .runtime
            .pending_epoch_commit
            .as_ref()
            .context("ordinary Vote lacks executed P")?;
        let header = pending.prepared.header()?;
        let parent = self
            .inner
            .prepared
            .last()
            .context("ordinary Vote parent missing")?
            .prepared
            .header()?;
        ensure!(
            header.block_kind() == BlockKind::Regular
                && header.parent_id() == parent.id()
                && parent.height().checked_next().ok() == Some(header.height()),
            "ordinary Vote does not extend its exact retained parent"
        );
        let (mut runtime, vote) =
            (*self.inner.runtime).finish_pending_application_vote_v3(producer)?;
        let prepared = runtime
            .pending_epoch_commit
            .take()
            .context("ordinary signed P missing")?;
        self.inner.prepared.push(prepared);
        self.inner.runtime = Box::new(runtime);
        Ok((self, vote))
    }

    /// Authenticate the exact lookahead QC and retain Core's own queue front.
    pub fn observe_ordinary_finality_qc_v3(
        mut self,
        certificate: trnm_consensus_types::QuorumCertificate,
    ) -> Result<Self> {
        self.require_below_cutoff_v3()?;
        self.inner = self.inner.observe_first_finality_qc_v2(certificate)?;
        Ok(self)
    }

    /// Commit and acknowledge the exact Core front, then advance the window.
    pub fn apply_ordinary_front_v3(
        mut self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        self.require_below_cutoff_v3()?;
        let first = self
            .inner
            .prepared
            .first()
            .context("ordinary application front missing")?
            .prepared
            .header()?;
        ensure!(
            first.block_kind() == BlockKind::Regular && first.height().get() <= self.cutoff_height,
            "ordinary application front is outside the cutoff"
        );
        self.inner = self.inner.apply_first_finalization_v2(budget)?;
        self.inner.prepared.remove(0);
        if first.height().get() < self.cutoff_height {
            self.inner.finality_observed = false;
            self.inner.applied = false;
        }
        Ok(self)
    }

    /// Comparison cut only; this cannot retire custody or activate an epoch.
    pub fn settled_cutoff_checkpoint_v3(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(
            self.inner.runtime.checkpoint.fields().application.height == self.cutoff_height
                && self.inner.prepared.len() == 2,
            "ordinary application cutoff is not settled"
        );
        let checkpoint = self.inner.settled_checkpoint_v2()?;
        for retained in &self.inner.prepared {
            ensure!(
                self.inner
                    .runtime
                    .application
                    .confirm_prepared_epoch_execution_v1(&retained.prepared)?
                    .commit_sequence()
                    .is_none(),
                "ordinary cutoff lookahead unexpectedly committed"
            );
        }
        Ok(checkpoint)
    }
}
