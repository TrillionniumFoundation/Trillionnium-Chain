use super::*;

/// Inert deterministic selection from one freshly audited committed cutoff.
/// No execution, signer, finality, or activation capability is returned.
#[derive(Debug)]
pub struct ComputedLaterEpochSelectionV1 {
    cutoff_head: ApplicationHeadV0,
    cutoff_p_digest: [u8; 32],
    cutoff_p_sequence: u64,
    cutoff_commit_sequence: u64,
    observed_context_digest: [u8; 32],
    commitment: trnm_consensus_types::NextEpochCommitmentV0,
    new_validator_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
}

impl ComputedLaterEpochSelectionV1 {
    pub fn cutoff_head(&self) -> &ApplicationHeadV0 {
        &self.cutoff_head
    }
    pub const fn cutoff_p_digest(&self) -> [u8; 32] {
        self.cutoff_p_digest
    }
    pub const fn cutoff_p_sequence(&self) -> u64 {
        self.cutoff_p_sequence
    }
    pub const fn cutoff_commit_sequence(&self) -> u64 {
        self.cutoff_commit_sequence
    }
    pub const fn observed_context_digest(&self) -> [u8; 32] {
        self.observed_context_digest
    }
    pub fn next_epoch_commitment(&self) -> &trnm_consensus_types::NextEpochCommitmentV0 {
        &self.commitment
    }
    pub fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_validator_set
    }
    pub const fn new_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_parameters
    }
}

impl DurableNativeApplicationV0 {
    /// Calculate the current epoch's next configuration from its committed
    /// cutoff. The result is comparison data, never a live permission. Every
    /// downstream execution still verifies its original native state.
    pub fn compute_later_epoch_selection_v1(
        &self,
        cutoff_height: HeightV0,
    ) -> Result<ComputedLaterEpochSelectionV1> {
        let before = self.inspect_later_epoch_checkpoint_context_v1()?;
        ensure!(
            cutoff_height.get() == before.cutoff_height().get()
                && cutoff_height.get() <= before.application_head().height().get(),
            "later selection requires the current committed cutoff"
        );
        let cutoff = self.read_finalized_by_height_v1(cutoff_height)?;
        ensure!(
            cutoff.confirmed_head_v1() == before.application_head()
                && cutoff.row.target_set
                    == before
                        .old_validator_set()
                        .try_cev0_bytes()
                        .map_err(|error| anyhow::anyhow!("later selection set: {error:?}"))?
                && cutoff.row.target_parameters == before.old_parameters().canonical_bytes()
                && decode_lineage(&cutoff.row.lineage)? == before.lineage(),
            "later selection cutoff differs from the active epoch context"
        );
        let computed = cutoff.derive_next_epoch_v1(self)?;
        let cutoff_head = cutoff.finalized_head_v1()?;
        ensure!(
            computed.commitment.fields().old_epoch == before.epoch()
                && computed.commitment.fields().snapshot_cutoff_height.get() == cutoff_height.get()
                && computed.commitment.fields().snapshot_state_root.as_bytes()
                    == cutoff_head.state_root().as_bytes(),
            "later selection differs from authenticated cutoff geometry"
        );
        let after = self.inspect_later_epoch_checkpoint_context_v1()?;
        ensure!(
            after.context_digest() == before.context_digest()
                && after.application_head() == before.application_head()
                && after.lineage() == before.lineage(),
            "later selection active context changed during computation"
        );
        Ok(ComputedLaterEpochSelectionV1 {
            cutoff_head,
            cutoff_p_digest: cutoff.row.p_digest,
            cutoff_p_sequence: cutoff.row.p_sequence,
            cutoff_commit_sequence: cutoff
                .row
                .commit_sequence
                .context("cutoff commit missing")?,
            observed_context_digest: before.context_digest(),
            commitment: computed.commitment,
            new_validator_set: computed.new_validator_set,
            new_parameters: computed.new_parameters,
        })
    }
}
