//! Read-only strict composition for a checkpoint in an already activated epoch.
//!
//! The first epoch checkpoint path is backed by the private preparation and
//! handoff capabilities in `poco_checkpoint`.  A later epoch cannot reuse
//! those epoch-0 capabilities: its active configuration comes from the
//! committed epoch context and its next configuration is supplied as an
//! authenticated preimage.  This module therefore exposes only a strict,
//! owner-affine observation.  It does not write SQLite, reserve a preparation
//! slot, consume a seal, or create an activation/signing authority.

use std::collections::BTreeSet;

use anyhow::{ensure, Result};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_consensus_parameters_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact,
    verify_same_version_joint_handoff_kernel_v0, BlockHeader, BlockKind, Cev0AdmissionBudgetV0,
    ConsensusParametersV0, EpochActivationEvidencePreimagesV0, EpochAnchorAuthorizationKernelV0,
    FinalityProofV0, JointHandoffKernelV0, NextEpochCommitmentV0, ValidatorSet,
};

use crate::{DurableNativeApplicationV0, LaterEpochCheckpointContextV1};

/// Strict facts for one later-epoch checkpoint/two-seal/handoff composition.
///
/// This type is intentionally neither `Clone` nor `Copy`.  It is an inert
/// read-only observation and cannot be converted into a durable edge or a
/// signing/activation capability.  The owner token prevents a result from
/// being used with another native application instance.
#[must_use = "later checkpoint finality must stay attached to its owner"]
pub struct LaterEpochCheckpointFinalityV1 {
    context: LaterEpochCheckpointContextV1,
    checkpoint_parent_header: BlockHeader,
    checkpoint_header: BlockHeader,
    checkpoint_finality: FinalityProofV0,
    commitment: NextEpochCommitmentV0,
    new_validator_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
    anchor_certificate_kernel: EpochAnchorAuthorizationKernelV0,
    joint_handoff: JointHandoffKernelV0,
}

impl LaterEpochCheckpointFinalityV1 {
    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        self.context.belongs_to_application(application)
    }

    pub const fn context_digest(&self) -> [u8; 32] {
        self.context.context_digest()
    }

    pub fn lineage(&self) -> &[[u8; 32]] {
        self.context.lineage()
    }

    pub const fn checkpoint_header(&self) -> &BlockHeader {
        &self.checkpoint_header
    }

    pub const fn checkpoint_parent_header(&self) -> &BlockHeader {
        &self.checkpoint_parent_header
    }

    pub const fn checkpoint_finality(&self) -> &FinalityProofV0 {
        &self.checkpoint_finality
    }

    pub const fn commitment(&self) -> &NextEpochCommitmentV0 {
        &self.commitment
    }

    pub const fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_validator_set
    }

    pub const fn new_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_parameters
    }

    pub const fn anchor_certificate_kernel(&self) -> &EpochAnchorAuthorizationKernelV0 {
        &self.anchor_certificate_kernel
    }

    pub const fn joint_handoff(&self) -> &JointHandoffKernelV0 {
        &self.joint_handoff
    }
}

/// Verify one later checkpoint against a freshly inspected context.
///
/// The commitment, validator set, and parameter bytes are all independent
/// caller inputs because a commitment contains hashes, not the new-set or
/// parameter preimages.  Requiring those preimages here lets the strict
/// anchor-kernel decoder verify both handoff signer roles without trusting a
/// caller-supplied hash or a legacy epoch-0 configuration.
#[allow(clippy::too_many_arguments)]
impl DurableNativeApplicationV0 {
    pub fn verify_later_epoch_checkpoint_finality_v1(
        &self,
        context: LaterEpochCheckpointContextV1,
        raw_checkpoint_parent_header_cev0: &[u8],
        raw_checkpoint_header_cev0: &[u8],
        raw_checkpoint_two_seal_finality_cev0: &[u8],
        raw_anchor_certificate_kernel_cev0: &[u8],
        raw_next_epoch_commitment_cev0: &[u8],
        raw_new_validator_set_cev0: &[u8],
        raw_new_consensus_parameters_cev0: &[u8],
    ) -> Result<LaterEpochCheckpointFinalityV1> {
        let application = self;
        ensure!(
            context.belongs_to_application(application),
            "later checkpoint context belongs to another owner"
        );
        let fresh = application.inspect_later_epoch_checkpoint_context_v1()?;
        ensure_context_fresh(&context, &fresh)?;

        ensure!(
            !context.lineage().is_empty(),
            "later checkpoint lineage is empty"
        );
        ensure!(
            context.lineage().last() == Some(&context.predecessor_edge()),
            "later checkpoint lineage does not end at its predecessor edge"
        );
        let mut seen = BTreeSet::new();
        ensure!(
            context
                .lineage()
                .iter()
                .all(|binding| *binding != [0; 32] && seen.insert(*binding)),
            "later checkpoint lineage contains a zero or duplicate edge"
        );

        let old_validator_set = context.old_validator_set();
        let old_parameters = context.old_parameters();
        old_validator_set
            .validate_against_parameters(old_parameters)
            .map_err(|error| anyhow::anyhow!("later context old configuration: {error:?}"))?;

        let commitment = decode_next_epoch_commitment_v0_exact(raw_next_epoch_commitment_cev0)
            .map_err(|error| anyhow::anyhow!("decode later next-epoch commitment: {error:?}"))?;
        let commitment_fields = commitment.fields();
        ensure!(
            commitment_fields.old_epoch == context.epoch()
                && commitment_fields.new_epoch
                    == context
                        .epoch()
                        .checked_next()
                        .map_err(|e| anyhow::anyhow!("later epoch overflow: {e:?}"))?
                && commitment_fields.genesis_hash == old_validator_set.genesis_hash()
                && commitment_fields.chain_id == old_validator_set.chain_id(),
            "later commitment does not name the context epoch or chain"
        );

        let cutoff = application.read_finalized_by_height_v1(
            trnm_native_application::HeightV0::new(context.cutoff_height().get()),
        )?;
        ensure!(
            commitment_fields.snapshot_cutoff_height == context.cutoff_height()
                && commitment_fields.snapshot_state_root.as_bytes()
                    == cutoff.finalized_head_v1()?.state_root().as_bytes(),
            "later commitment cutoff differs from committed native history"
        );

        let new_validator_set = decode_validator_set_v0_exact(raw_new_validator_set_cev0)
            .map_err(|error| anyhow::anyhow!("decode later new validator set: {error:?}"))?;
        let new_parameters =
            decode_consensus_parameters_v0_exact(raw_new_consensus_parameters_cev0)
                .map_err(|error| anyhow::anyhow!("decode later new parameters: {error:?}"))?;
        commitment
            .validate_same_version_context(
                old_validator_set,
                old_parameters,
                &new_validator_set,
                &new_parameters,
            )
            .map_err(|error| anyhow::anyhow!("later commitment context: {error:?}"))?;

        let checkpoint_parent_header =
            decode_block_header_v0_exact(raw_checkpoint_parent_header_cev0)
                .map_err(|error| anyhow::anyhow!("decode later checkpoint parent: {error:?}"))?;
        let checkpoint_header = decode_block_header_v0_exact(raw_checkpoint_header_cev0)
            .map_err(|error| anyhow::anyhow!("decode later checkpoint header: {error:?}"))?;
        ensure_checkpoint_geometry(
            &context,
            old_validator_set,
            old_parameters,
            &commitment,
            &checkpoint_parent_header,
            &checkpoint_header,
        )?;
        let parent_read = application.read_finalized_by_height_v1(
            trnm_native_application::HeightV0::new(checkpoint_parent_header.height().get()),
        )?;
        let parent_head = parent_read.finalized_head_v1()?;
        ensure!(
            parent_head.height().get() == checkpoint_parent_header.height().get()
                && parent_head.block_id().as_bytes() == checkpoint_parent_header.id().as_bytes()
                && parent_head.state_root().as_bytes()
                    == checkpoint_parent_header.state_root().as_bytes(),
            "later checkpoint parent is not the exact durable finalized old-epoch block"
        );

        // Reuse the bounded aggregate decoder so both the complete evidence size
        // and signature work are limited before strict verification. It also
        // binds the parent header to the checkpoint's ordinary justify QC.
        let old_set_bytes = old_validator_set
            .try_cev0_bytes()
            .map_err(|error| anyhow::anyhow!("encode later old validator set: {error:?}"))?;
        let old_parameters_bytes = old_parameters.canonical_bytes();
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let decoded = trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
            EpochActivationEvidencePreimagesV0 {
                old_checkpoint_finality: raw_checkpoint_two_seal_finality_cev0,
                next_epoch_commitment: raw_next_epoch_commitment_cev0,
                authorization_kernel: raw_anchor_certificate_kernel_cev0,
                old_validator_set: &old_set_bytes,
                old_consensus_parameters: &old_parameters_bytes,
                new_validator_set: raw_new_validator_set_cev0,
                new_consensus_parameters: raw_new_consensus_parameters_cev0,
                authenticated_checkpoint_parent_header: raw_checkpoint_parent_header_cev0,
            },
            old_validator_set,
            old_parameters,
            &mut budget,
        )
        .map_err(|error| anyhow::anyhow!("decode later checkpoint joint evidence: {error:?}"))?;
        let checkpoint_finality = decoded.old_checkpoint_finality().clone();
        let anchor_certificate_kernel = decoded.authorization_kernel().clone();
        ensure!(
            checkpoint_finality.finalized_block().header() == &checkpoint_header,
            "later two-seal proof names a different checkpoint header"
        );
        trnm_consensus_crypto::validate_validator_set_strict_ed25519_v0(old_validator_set)
            .map_err(|error| anyhow::anyhow!("strict later old validator keys: {error:?}"))?;
        trnm_consensus_crypto::validate_validator_set_strict_ed25519_v0(&new_validator_set)
            .map_err(|error| anyhow::anyhow!("strict later new validator keys: {error:?}"))?;

        let joint_handoff = verify_same_version_joint_handoff_kernel_v0(
            &checkpoint_finality,
            &commitment,
            &anchor_certificate_kernel,
            old_validator_set,
            old_parameters,
            &new_validator_set,
            &new_parameters,
            checkpoint_parent_header.timestamp_ms(),
            &StrictEd25519Verifier,
        )
        .map_err(|error| anyhow::anyhow!("strict later joint handoff: {error}"))?;
        ensure!(
            joint_handoff.checkpoint_height() == context.checkpoint_height()
                && joint_handoff.checkpoint_block_id() == checkpoint_header.id()
                && joint_handoff.next_epoch_commitment_digest() == commitment.id()
                && joint_handoff.old_epoch() == context.epoch()
                && joint_handoff.new_epoch()
                    == context
                        .epoch()
                        .checked_next()
                        .map_err(|e| anyhow::anyhow!("later epoch overflow: {e:?}"))?
                && joint_handoff.old_validator_set_hash() == old_validator_set.id()
                && joint_handoff.old_consensus_parameters_hash() == old_parameters.hash()
                && joint_handoff.new_validator_set_hash() == new_validator_set.id()
                && joint_handoff.new_consensus_parameters_hash() == new_parameters.hash()
                && joint_handoff.terminal_old_height() == context.seal_2_height()
                && joint_handoff.activation_height() == context.first_application_height(),
            "later joint handoff does not match context geometry or configuration"
        );
        ensure!(
            anchor_certificate_kernel.terminal_old_header()
                == checkpoint_finality.grandchild().header()
                && anchor_certificate_kernel.terminal_old_qc()
                    == checkpoint_finality.grandchild().certifying_qc(),
            "later anchor terminal evidence differs from seal-2"
        );

        // No durable write occurs here.  Re-open the owner context after all
        // cryptographic work so a concurrent epoch-context change invalidates the
        // observation instead of returning a proof joined to stale lineage.
        let after = application.inspect_later_epoch_checkpoint_context_v1()?;
        ensure_context_fresh(&context, &after)?;
        Ok(LaterEpochCheckpointFinalityV1 {
            context,
            checkpoint_parent_header,
            checkpoint_header,
            checkpoint_finality,
            commitment,
            new_validator_set,
            new_parameters,
            anchor_certificate_kernel,
            joint_handoff,
        })
    }
}

fn ensure_context_fresh(
    supplied: &LaterEpochCheckpointContextV1,
    fresh: &LaterEpochCheckpointContextV1,
) -> Result<()> {
    ensure!(
        supplied.context_digest() == fresh.context_digest()
            && supplied.application_head() == fresh.application_head()
            && supplied.predecessor_edge() == fresh.predecessor_edge()
            && supplied.lineage() == fresh.lineage()
            && supplied.old_validator_set() == fresh.old_validator_set()
            && supplied.old_parameters() == fresh.old_parameters()
            && supplied.epoch() == fresh.epoch()
            && supplied.checkpoint_height() == fresh.checkpoint_height()
            && supplied.seal_1_height() == fresh.seal_1_height()
            && supplied.seal_2_height() == fresh.seal_2_height()
            && supplied.first_application_height() == fresh.first_application_height()
            && supplied.cutoff_height() == fresh.cutoff_height(),
        "later checkpoint context is stale or substituted"
    );
    Ok(())
}

fn ensure_checkpoint_geometry(
    context: &LaterEpochCheckpointContextV1,
    old_validator_set: &ValidatorSet,
    old_parameters: &ConsensusParametersV0,
    commitment: &NextEpochCommitmentV0,
    parent: &BlockHeader,
    checkpoint: &BlockHeader,
) -> Result<()> {
    ensure!(
        parent.genesis_hash() == old_validator_set.genesis_hash()
            && parent.chain_id() == old_validator_set.chain_id()
            && parent.protocol_version() == old_validator_set.protocol_version()
            && parent.epoch() == context.epoch()
            && parent.validator_set_id() == old_validator_set.id()
            && parent.consensus_parameters_hash() == old_parameters.hash()
            && parent.block_kind() == BlockKind::Regular
            && parent.next_epoch_commitment_hash().is_none(),
        "later checkpoint parent does not match active old context"
    );
    ensure!(
        parent
            .height()
            .get()
            .checked_add(1)
            .is_some_and(|height| height == context.checkpoint_height().get()),
        "later checkpoint parent is not immediately before checkpoint"
    );
    // The context head is normally the authenticated snapshot/cutoff (C-3);
    // C-1 and C-2 must be ordinary old-epoch application blocks committed
    // after that cutoff.  Join the raw C-1 header to the durable finalized
    // readback instead of assuming that the context head is already C-1.
    ensure!(
        checkpoint.genesis_hash() == old_validator_set.genesis_hash()
            && checkpoint.chain_id() == old_validator_set.chain_id()
            && checkpoint.protocol_version() == old_validator_set.protocol_version()
            && checkpoint.epoch() == context.epoch()
            && checkpoint.validator_set_id() == old_validator_set.id()
            && checkpoint.consensus_parameters_hash() == old_parameters.hash()
            && checkpoint.block_kind() == BlockKind::EpochCheckpoint
            && checkpoint.height() == context.checkpoint_height()
            && checkpoint.parent_id() == parent.id()
            && checkpoint.next_epoch_commitment_hash() == Some(commitment.id()),
        "later checkpoint header does not match context, parent, or commitment"
    );
    ensure!(
        context.seal_1_height()
            == context
                .checkpoint_height()
                .checked_next()
                .map_err(|e| anyhow::anyhow!("seal-1 overflow: {e:?}"))?
            && context.seal_2_height()
                == context
                    .seal_1_height()
                    .checked_next()
                    .map_err(|e| anyhow::anyhow!("seal-2 overflow: {e:?}"))?
            && context.first_application_height()
                == context
                    .seal_2_height()
                    .checked_next()
                    .map_err(|e| anyhow::anyhow!("first application overflow: {e:?}"))?,
        "later checkpoint context geometry is not contiguous"
    );
    Ok(())
}
