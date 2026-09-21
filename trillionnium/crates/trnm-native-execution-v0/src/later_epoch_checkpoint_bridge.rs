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
    pub(crate) fn has_owner_v1(&self, application: &DurableNativeApplicationV0) -> bool {
        self.context.belongs_to_application(application)
    }

    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        self.context.belongs_to_application(application)
            && application
                .inspect_later_epoch_checkpoint_context_v1()
                .is_ok_and(|fresh| ensure_context_fresh(&self.context, &fresh).is_ok())
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

    /// Canonical CEV0 preimages retained by the durable later-checkpoint
    /// ledger. Only the owner can consume this crate-private carrier.
    pub(crate) fn durable_preimages_v1(&self) -> Result<LaterEpochFinalityPreimagesV1> {
        Ok(LaterEpochFinalityPreimagesV1 {
            context_digest: self.context_digest(),
            predecessor_edge: self.context.predecessor_edge(),
            checkpoint_parent_header: self
                .checkpoint_parent_header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("encode later checkpoint parent: {e:?}"))?,
            checkpoint_header: self
                .checkpoint_header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("encode later checkpoint: {e:?}"))?,
            checkpoint_finality: self
                .checkpoint_finality
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("encode later finality: {e:?}"))?,
            anchor_kernel: self
                .anchor_certificate_kernel
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("encode later anchor: {e:?}"))?,
            next_epoch_commitment: self
                .commitment
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("encode later commitment: {e:?}"))?,
            new_validator_set: self
                .new_validator_set
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("encode later validator set: {e:?}"))?,
            new_parameters: self.new_parameters.canonical_bytes(),
        })
    }
}

pub(crate) struct LaterEpochFinalityPreimagesV1 {
    pub(crate) context_digest: [u8; 32],
    pub(crate) predecessor_edge: [u8; 32],
    pub(crate) checkpoint_parent_header: Vec<u8>,
    pub(crate) checkpoint_header: Vec<u8>,
    pub(crate) checkpoint_finality: Vec<u8>,
    pub(crate) anchor_kernel: Vec<u8>,
    pub(crate) next_epoch_commitment: Vec<u8>,
    pub(crate) new_validator_set: Vec<u8>,
    pub(crate) new_parameters: Vec<u8>,
}

/// Verify one later checkpoint against a freshly inspected context.
///
/// The commitment, validator set, and parameter bytes are all independent
/// caller inputs because a commitment contains hashes, not the new-set or
/// parameter preimages.  Requiring those preimages here lets the strict
/// anchor-kernel decoder verify both handoff signer roles without trusting a
/// caller-supplied hash or a legacy epoch-0 configuration.
impl DurableNativeApplicationV0 {
    #[allow(clippy::too_many_arguments)]
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
        // A cryptographically valid header is not enough to authorize a
        // native checkpoint.  Join it to the real owner-prepared P row and
        // let the durable validator re-audit its artifact, snapshot, lineage,
        // target configuration, and digest.  This is read-only and remains
        // before any finality/commit transition.
        let prepared_checkpoint =
            application.reopen_prepared_epoch_execution_v1(*checkpoint_header.id().as_bytes())?;
        ensure!(
            prepared_checkpoint.header()? == checkpoint_header,
            "later checkpoint header differs from the owner-prepared native P"
        );
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

#[cfg(all(test, feature = "test-fixtures"))]
mod tests {
    use super::*;
    use crate::poco_checkpoint::native_checkpoint_fixture_v1::{
        build_native_checkpoint_fixture_v1, epoch_first_finality,
        native_checkpoint_fixture_config_v1, ordinary_epoch_finality,
    };
    use crate::NativeBlockPreviewRequestV0;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;
    use trnm_consensus_types::{
        BlockId, CertifiedHeaderV0, Epoch, EpochAnchorAuthorizationKernelV0, EpochFallbackReasonV0,
        EvidenceRoot, FinalityProofV0, HandoffCertificateV0, HandoffDescriptorV0,
        HandoffDescriptorV0Fields, Height, NextEpochCommitmentV0Fields, OrderedRootV0,
        PayloadDigest, ProposalWitnessV0, ProtocolVersion, QcReferenceV0, QuorumCertificate,
        ReceiptsRoot, RootKind, Signature64, SignatureShareV0, StateRoot, Validator, ValidatorSet,
        View, Vote, SCHEMA_VERSION_V0,
    };
    use trnm_native_application::{
        BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0, NativeBlockExecutionRequestV0,
        NativeEpochBlockExecutionRequestV1, NativeEpochBlockPreviewRequestV1,
        NativeExpectedBlockCommitmentsV0,
    };

    include!("later_epoch_descendant_tests.rs");
    include!("later_epoch_repeated_tests.rs");

    fn key(index: usize) -> SigningKey {
        SigningKey::from_bytes(&[20 + index as u8; 32])
    }

    fn qc(header: &BlockHeader, set: &ValidatorSet) -> QuorumCertificate {
        let root =
            Vote::signing_root_for_set(set, header.view(), header.height(), header.id()).unwrap();
        let votes = set
            .validators()
            .iter()
            .map(|validator| {
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    header.view(),
                    header.height(),
                    header.id(),
                    set.id(),
                    validator.id(),
                    trnm_consensus_types::SignatureBytes::from_array(
                        key(set
                            .validators()
                            .iter()
                            .position(|v| v.id() == validator.id())
                            .unwrap())
                        .sign(root.as_bytes())
                        .to_bytes(),
                    ),
                    set,
                )
                .unwrap()
            })
            .collect();
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            header.view(),
            header.height(),
            header.id(),
            set.id(),
            votes,
            set,
        )
        .unwrap()
    }

    fn certified(
        header: BlockHeader,
        justify: QuorumCertificate,
        set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        parent_timestamp_ms: u64,
    ) -> trnm_consensus_types::CertifiedHeaderV0 {
        let justify_ref = QcReferenceV0::ordinary(justify);
        let root = ProposalWitnessV0::signing_root_for(&header, &justify_ref, None, None).unwrap();
        let proposer = set
            .validators()
            .iter()
            .position(|validator| validator.id() == header.proposer_id())
            .unwrap();
        trnm_consensus_types::CertifiedHeaderV0::new(
            header.clone(),
            justify_ref,
            None,
            None,
            Signature64::from_array(key(proposer).sign(root.as_bytes()).to_bytes()),
            qc(&header, set),
            set,
            None,
            parameters,
            parent_timestamp_ms,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn checkpoint_like_header(
        set: &ValidatorSet,
        kind: BlockKind,
        height: u64,
        parent: BlockId,
        state_root: StateRoot,
        commitment: Option<trnm_consensus_types::NextEpochCommitmentHash>,
        timestamp_ms: u64,
        payload_root: PayloadDigest,
        receipts_root: ReceiptsRoot,
        evidence_root: EvidenceRoot,
    ) -> BlockHeader {
        let view = if kind == BlockKind::EpochHandoff {
            1
        } else {
            height - 10
        };
        checkpoint_like_header_at_view(
            set,
            kind,
            height,
            parent,
            state_root,
            commitment,
            timestamp_ms,
            payload_root,
            receipts_root,
            evidence_root,
            view,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn checkpoint_like_header_at_view(
        set: &ValidatorSet,
        kind: BlockKind,
        height: u64,
        parent: BlockId,
        state_root: StateRoot,
        commitment: Option<trnm_consensus_types::NextEpochCommitmentHash>,
        timestamp_ms: u64,
        payload_root: PayloadDigest,
        receipts_root: ReceiptsRoot,
        evidence_root: EvidenceRoot,
        view: u64,
    ) -> BlockHeader {
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            kind,
            parent,
            set.validators()[((view - 1) as usize) % set.validators().len()].id(),
            set.id(),
            set.consensus_parameters_hash(),
            payload_root,
            state_root,
            receipts_root,
            evidence_root,
            timestamp_ms,
            commitment,
        )
        .unwrap()
    }

    fn empty_roots() -> (PayloadDigest, ReceiptsRoot, EvidenceRoot) {
        (
            PayloadDigest::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Payload, &[])
                    .unwrap()
                    .digest(),
            ),
            ReceiptsRoot::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Receipts, &[])
                    .unwrap()
                    .digest(),
            ),
            EvidenceRoot::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Evidence, &[])
                    .unwrap()
                    .digest(),
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn later_epoch_first_finality(
        old_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
        old_set_bytes: &[u8],
        new_set_bytes: &[u8],
        new_parameters_bytes: &[u8],
        checkpoint_parent_header: &[u8],
        checkpoint_finality: &[u8],
        anchor_kernel: &[u8],
        next_epoch_commitment: &[u8],
        headers: &[BlockHeader],
    ) -> Vec<u8> {
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let decoded = trnm_consensus_types::decode_epoch_activation_evidence_v0_exact(
            EpochActivationEvidencePreimagesV0 {
                old_checkpoint_finality: checkpoint_finality,
                next_epoch_commitment,
                authorization_kernel: anchor_kernel,
                old_validator_set: old_set_bytes,
                old_consensus_parameters: &old_parameters.canonical_bytes(),
                new_validator_set: new_set_bytes,
                new_consensus_parameters: new_parameters_bytes,
                authenticated_checkpoint_parent_header: checkpoint_parent_header,
            },
            old_set,
            old_parameters,
            &mut budget,
        )
        .unwrap();
        let activation =
            trnm_consensus_crypto::verify_same_version_epoch_activation_authority_strict_v0(
                decoded.old_checkpoint_finality(),
                decoded.next_epoch_commitment(),
                decoded.authorization_kernel(),
                old_set,
                old_parameters,
                decoded.new_validator_set(),
                decoded.new_consensus_parameters(),
                decoded.authenticated_checkpoint_parent_header(),
            )
            .unwrap();
        let set = decoded.new_validator_set();
        let parameters = decoded.new_consensus_parameters();
        let common = || {
            let mut bytes = 0u16.to_be_bytes().to_vec();
            bytes.extend(set.genesis_hash().as_bytes());
            bytes.extend((set.chain_id().as_bytes().len() as u16).to_be_bytes());
            bytes.extend(set.chain_id().as_bytes());
            bytes.extend(set.protocol_version().get().to_be_bytes());
            bytes.extend(set.epoch().get().to_be_bytes());
            bytes.extend(set.id().as_bytes());
            bytes
        };
        let mut bytes = common();
        bytes.extend(parameters.hash().as_bytes());
        let mut anchor = common();
        anchor.extend(0u64.to_be_bytes());
        anchor.extend(
            activation
                .authorization_kernel()
                .terminal_old_header()
                .height()
                .get()
                .to_be_bytes(),
        );
        anchor.extend(
            activation
                .authorization_kernel()
                .terminal_old_header()
                .id()
                .as_bytes(),
        );
        anchor.extend(0u32.to_be_bytes());
        for (index, header) in headers.iter().enumerate() {
            let key_index = set
                .validators()
                .iter()
                .position(|v| v.id() == header.proposer_id())
                .unwrap();
            if index == 0 {
                let root = trnm_consensus_types::epoch_first_proposal_signing_root_v0(
                    header,
                    activation.authorization_kernel(),
                    old_set,
                    set,
                    parameters,
                )
                .unwrap();
                bytes.extend(header.try_cev0_bytes().unwrap());
                bytes.extend(&anchor);
                bytes.push(0);
                bytes.push(1);
                bytes.extend(activation.authorization_cev0_bytes().unwrap());
                bytes.extend(key(key_index).sign(root.as_bytes()).to_bytes());
                bytes.extend(qc(header, set).try_cev0_bytes().unwrap());
            } else {
                let justify = QcReferenceV0::ordinary(qc(&headers[index - 1], set));
                let witness = ProposalWitnessV0::new(
                    header,
                    justify.clone(),
                    None,
                    None,
                    Signature64::from_array([1; 64]),
                    set,
                    None,
                    parameters,
                    headers[index - 1].timestamp_ms(),
                )
                .unwrap();
                let signature = Signature64::from_array(
                    key(key_index)
                        .sign(witness.signing_root_for_header(header).unwrap().as_bytes())
                        .to_bytes(),
                );
                let certified = trnm_consensus_types::CertifiedHeaderV0::new(
                    header.clone(),
                    justify,
                    None,
                    None,
                    signature,
                    qc(header, set),
                    set,
                    None,
                    parameters,
                    headers[index - 1].timestamp_ms(),
                )
                .unwrap();
                bytes.extend(certified.try_cev0_bytes().unwrap());
            }
        }
        bytes
    }

    fn rehash_record(sql: &rusqlite::Connection) {
        use sha2::{Digest, Sha256};
        let mut values: Vec<Vec<u8>> = sql
            .query_row(
                "SELECT checkpoint_block,p_digest,commit_sequence,context_digest,predecessor_edge,
                    checkpoint_parent_header,checkpoint_header,checkpoint_finality,anchor_kernel,
                    next_epoch_commitment,new_validator_set,new_parameters
             FROM native_later_epoch_finality_v1",
                [],
                |row| (0..12).map(|i| row.get(i)).collect(),
            )
            .unwrap();
        for value in &mut values[5..] {
            *value = Sha256::digest(&*value).to_vec();
        }
        values.insert(0, native_checkpoint_fixture_config_v1().store_id().to_vec());
        let parts = values.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let digest = trnm_finality_types::hash_domain(
            "trnm.native-application.later-epoch-finality-record.v1",
            &parts,
        );
        sql.execute(
            "UPDATE native_later_epoch_finality_v1 SET record_digest=?",
            [digest.as_slice()],
        )
        .unwrap();
    }

    fn assert_later_application_ledger_recovery(path: &std::path::Path) {
        let sql = rusqlite::Connection::open(path).unwrap();
        let [block, p_digest, sequence, edge, original, original_digest, original_record]:
            [Vec<u8>; 7] = sql.query_row(
            "SELECT block_id,p_digest,commit_sequence,edge_binding,proof,proof_digest,record_digest
             FROM native_later_epoch_application_finality_v1",
            [],
            |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?]),
        ).unwrap();
        // Preserve valid framing and all local hashes while corrupting the
        // final signature. Only strict cryptographic recovery can reject it.
        let mut forged = original.clone();
        *forged.last_mut().unwrap() ^= 1;
        let forged_digest = sha2::Sha256::digest(&forged);
        let forged_record = trnm_finality_types::hash_domain(
            "trnm.native-application.later-epoch-application-finality.v1",
            &[
                &native_checkpoint_fixture_config_v1().store_id(),
                &block,
                &p_digest,
                &sequence,
                &edge,
                &forged_digest,
            ],
        );
        sql.execute(
            "UPDATE native_later_epoch_application_finality_v1 SET proof=?,proof_digest=?,record_digest=?",
            rusqlite::params![forged, forged_digest.as_slice(), forged_record.as_slice()],
        ).unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err(),
            "a rehashed forged C+3 signature must fail cold recovery"
        );
        sql.execute(
            "UPDATE native_later_epoch_application_finality_v1 SET proof=?,proof_digest=?,record_digest=?",
            rusqlite::params![original, original_digest, original_record],
        ).unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_ok()
        );
        sql.execute_batch("CREATE TEMP TABLE saved_application_finality AS SELECT * FROM native_later_epoch_application_finality_v1; DELETE FROM native_later_epoch_application_finality_v1;").unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err(),
            "every consumed successor requires its retained application proof"
        );
        sql.execute_batch("INSERT INTO native_later_epoch_application_finality_v1 SELECT * FROM saved_application_finality;").unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_ok()
        );
    }

    struct LaterDescendantFixture {
        application: DurableNativeApplicationV0,
        prepared: crate::PreparedNativeEpochExecutionV1,
        checkpoint_header: BlockHeader,
        first_header: BlockHeader,
        c22_header: BlockHeader,
        c23_header: BlockHeader,
        c24_header: BlockHeader,
        c23_request: NativeBlockPreviewRequestV0,
        c22_proof: Vec<u8>,
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
        predecessor: [u8; 32],
        trust_anchor: trnm_state_sync_v0::NativeTrustAnchorV1,
        other_trust_anchor: trnm_state_sync_v0::NativeTrustAnchorV1,
    }

    // One authentic construction feeds both normal acceptance and the seeded
    // crash harness. No child reconstructs genesis/checkpoint history.
    #[inline(never)]
    fn build_later_descendant_fixture(path: &std::path::Path) -> Box<LaterDescendantFixture> {
        let fixture = build_native_checkpoint_fixture_v1(path);
        let app = fixture.application;
        let confirmed = app
            .confirm_poco_checkpoint_v0(
                fixture.pre_handoff_preparation,
                &fixture.checkpoint_finality_bytes,
                &fixture.handoff_anchor_bytes,
            )
            .unwrap();
        let edge = confirmed.into_epoch_application_edge_v1().unwrap();
        app.upgrade_epoch_schema_v1(edge.application_parent())
            .unwrap();

        let epoch_request = edge.preview_request_v1(11_000, Vec::new()).unwrap();
        let epoch_preview = app.preview_epoch_block_v1(&edge, &epoch_request).unwrap();
        let first_header = checkpoint_like_header(
            edge.new_validator_set(),
            BlockKind::EpochHandoff,
            11,
            edge.consensus_parent().id(),
            StateRoot::new(*epoch_preview.post_state_root().as_bytes()),
            None,
            epoch_request.timestamp_ms(),
            PayloadDigest::new(*epoch_preview.payload_root().as_bytes()),
            ReceiptsRoot::new(*epoch_preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*epoch_preview.evidence_root().as_bytes()),
        );
        let first_request = NativeEpochBlockExecutionRequestV1::new(
            epoch_request,
            BlockIdV0::new(*first_header.id().as_bytes()).unwrap(),
            NativeExpectedBlockCommitmentsV0::new(
                epoch_preview.payload_root(),
                epoch_preview.post_state_root(),
                epoch_preview.receipts_root(),
                epoch_preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut prepared = vec![app
            .execute_epoch_block_v1(&edge, first_request, &first_header)
            .unwrap()];
        let mut headers = vec![first_header];
        for height in 12..=17 {
            let parent = prepared.last().unwrap().overlay_parent_head().unwrap();
            let request = NativeBlockPreviewRequestV0::new(
                ChainIdV0::new(edge.consensus_parent().chain_id().as_str()).unwrap(),
                trnm_native_application::GenesisHashV0::new(
                    *edge.consensus_parent().genesis_hash().as_bytes(),
                )
                .unwrap(),
                parent,
                HeightV0::new(height),
                height * 1_000,
                trnm_native_application::ValidatorSetIdV0::new(
                    *edge.new_validator_set().id().as_bytes(),
                )
                .unwrap(),
                Vec::new(),
            )
            .unwrap();
            let preview = app
                .preview_epoch_descendant_v1(prepared.last().unwrap(), &request)
                .unwrap();
            let header = checkpoint_like_header(
                edge.new_validator_set(),
                BlockKind::Regular,
                height,
                BlockId::new(*request.parent().block_id().as_bytes()),
                StateRoot::new(*preview.post_state_root().as_bytes()),
                None,
                request.timestamp_ms(),
                PayloadDigest::new(*preview.payload_root().as_bytes()),
                ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
                EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            );
            let execution = NativeBlockExecutionRequestV0::new(
                request.chain_id().clone(),
                request.genesis_hash(),
                request.parent().clone(),
                BlockIdV0::new(*header.id().as_bytes()).unwrap(),
                request.height(),
                request.timestamp_ms(),
                request.active_validator_set_id(),
                Vec::new(),
                NativeExpectedBlockCommitmentsV0::new(
                    preview.payload_root(),
                    preview.post_state_root(),
                    preview.receipts_root(),
                    preview.evidence_root(),
                )
                .unwrap(),
            )
            .unwrap();
            prepared.push(
                app.execute_epoch_descendant_v1(prepared.last().unwrap(), execution, &header)
                    .unwrap(),
            );
            headers.push(header);
        }
        for index in 0..=4 {
            let proof = if index == 0 {
                epoch_first_finality(&edge, &headers[index..index + 3])
            } else {
                ordinary_epoch_finality(&edge, &headers[index - 1], &headers[index..index + 3])
            };
            let _ = app
                .commit_epoch_finality_bytes_v1(
                    &prepared[index],
                    &proof,
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
        }

        let cutoff = app
            .read_finalized_by_height_v1(HeightV0::new(15))
            .unwrap()
            .finalized_head_v1()
            .unwrap();
        let old_set = edge.new_validator_set().clone();
        let old_parameters = *edge.new_parameters();
        let new_set = ValidatorSet::new(
            old_set.genesis_hash(),
            old_set.chain_id(),
            old_set.protocol_version(),
            Epoch::new(2),
            old_parameters.hash(),
            old_set
                .validators()
                .iter()
                .map(|validator| {
                    Validator::new(
                        validator.id(),
                        validator.consensus_key(),
                        validator.voting_power(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let geometry =
            trnm_consensus_types::EpochGeometryV0::new(old_set.epoch(), &old_parameters).unwrap();
        let commitment = NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields {
            schema_version: SCHEMA_VERSION_V0,
            genesis_hash: old_set.genesis_hash(),
            chain_id: old_set.chain_id(),
            old_epoch: old_set.epoch(),
            new_epoch: new_set.epoch(),
            snapshot_cutoff_height: Height::new(15),
            snapshot_state_root: StateRoot::new(*cutoff.state_root().as_bytes()),
            new_protocol_version: ProtocolVersion::V0,
            new_validator_set_hash: new_set.id(),
            new_consensus_parameters_hash: old_parameters.hash(),
            rollout_phase: old_parameters.rollout_phase(),
            upgrade_plan_hash: None,
            fallback_used: false,
            fallback_reason: EpochFallbackReasonV0::None,
            activation_height: geometry.epoch_end().checked_next().unwrap(),
        })
        .unwrap();

        let parent = prepared[6].overlay_parent_head().unwrap();
        let request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(edge.consensus_parent().chain_id().as_str()).unwrap(),
            trnm_native_application::GenesisHashV0::new(
                *edge.consensus_parent().genesis_hash().as_bytes(),
            )
            .unwrap(),
            parent,
            HeightV0::new(18),
            18_000,
            trnm_native_application::ValidatorSetIdV0::new(*old_set.id().as_bytes()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let preview = app
            .preview_epoch_descendant_v1(&prepared[6], &request)
            .unwrap();
        let checkpoint_header = checkpoint_like_header(
            &old_set,
            BlockKind::EpochCheckpoint,
            18,
            BlockId::new(*request.parent().block_id().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            Some(commitment.id()),
            request.timestamp_ms(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        );
        let checkpoint_request = NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            BlockIdV0::new(*checkpoint_header.id().as_bytes()).unwrap(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            Vec::new(),
            NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let _checkpoint_p = app
            .execute_epoch_descendant_v1(&prepared[6], checkpoint_request, &checkpoint_header)
            .unwrap();
        let (empty_payload, empty_receipts, empty_evidence) = empty_roots();
        let seal_1 = checkpoint_like_header(
            &old_set,
            BlockKind::EpochSeal1,
            19,
            checkpoint_header.id(),
            checkpoint_header.state_root(),
            Some(commitment.id()),
            19_000,
            empty_payload,
            empty_receipts,
            empty_evidence,
        );
        let proof_16 = ordinary_epoch_finality(
            &edge,
            &headers[4],
            &[
                headers[5].clone(),
                headers[6].clone(),
                checkpoint_header.clone(),
            ],
        );
        let _ = app
            .commit_epoch_finality_bytes_v1(
                &prepared[5],
                &proof_16,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        let proof_17 = ordinary_epoch_finality(
            &edge,
            &headers[5],
            &[
                headers[6].clone(),
                checkpoint_header.clone(),
                seal_1.clone(),
            ],
        );
        let _ = app
            .commit_epoch_finality_bytes_v1(
                &prepared[6],
                &proof_17,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        let seal_2 = checkpoint_like_header(
            &old_set,
            BlockKind::EpochSeal2,
            20,
            seal_1.id(),
            checkpoint_header.state_root(),
            Some(commitment.id()),
            20_000,
            empty_payload,
            empty_receipts,
            empty_evidence,
        );
        let checkpoint_finality = FinalityProofV0::new(
            certified(
                checkpoint_header.clone(),
                qc(&headers[6], &old_set),
                &old_set,
                &old_parameters,
                headers[6].timestamp_ms(),
            ),
            certified(
                seal_1.clone(),
                qc(&checkpoint_header, &old_set),
                &old_set,
                &old_parameters,
                checkpoint_header.timestamp_ms(),
            ),
            certified(
                seal_2.clone(),
                qc(&seal_1, &old_set),
                &old_set,
                &old_parameters,
                seal_1.timestamp_ms(),
            ),
            &old_set,
            None,
            &old_parameters,
            headers[6].timestamp_ms(),
        )
        .unwrap();
        let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
            genesis_hash: old_set.genesis_hash(),
            chain_id: old_set.chain_id(),
            old_epoch: old_set.epoch(),
            new_epoch: new_set.epoch(),
            old_protocol_version: old_set.protocol_version(),
            new_protocol_version: new_set.protocol_version(),
            old_validator_set_hash: old_set.id(),
            new_validator_set_hash: new_set.id(),
            old_consensus_parameters_hash: old_parameters.hash(),
            new_consensus_parameters_hash: old_parameters.hash(),
            checkpoint_height: checkpoint_header.height(),
            checkpoint_block_id: checkpoint_header.id(),
            checkpoint_state_root: checkpoint_header.state_root(),
            next_epoch_commitment_digest: commitment.id(),
            terminal_old_height: seal_2.height(),
            terminal_old_block_id: seal_2.id(),
            terminal_old_qc_digest: qc(&seal_2, &old_set).id(),
            terminal_old_view: seal_2.view(),
            activation_height: geometry.epoch_end().checked_next().unwrap(),
            initial_new_view: View::new(1),
        })
        .unwrap();
        let old_root = descriptor.old_set_signing_root();
        let new_root = descriptor.new_set_signing_root();
        let shares = |set: &ValidatorSet, root: trnm_consensus_types::SigningRoot| {
            set.validators()
                .iter()
                .take(3)
                .map(|validator| {
                    let index = set
                        .validators()
                        .iter()
                        .position(|item| item.id() == validator.id())
                        .unwrap();
                    SignatureShareV0::new(
                        validator.id(),
                        Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                    )
                    .unwrap()
                })
                .collect()
        };
        let handoff = HandoffCertificateV0::new(
            descriptor,
            shares(&old_set, old_root),
            shares(&new_set, new_root),
            &old_set,
            &new_set,
        )
        .unwrap();
        let anchor = EpochAnchorAuthorizationKernelV0::from_parts_v0(
            seal_2.clone(),
            qc(&seal_2, &old_set),
            handoff,
            &old_set,
            &new_set,
        )
        .unwrap();
        let parent_bytes = headers[6].try_cev0_bytes().unwrap();
        let checkpoint_bytes = checkpoint_header.try_cev0_bytes().unwrap();
        let finality_bytes = checkpoint_finality.try_cev0_bytes().unwrap();
        let anchor_bytes = anchor.try_cev0_bytes().unwrap();
        let commitment_bytes = commitment.try_cev0_bytes().unwrap();
        let new_set_bytes = new_set.try_cev0_bytes().unwrap();
        let new_parameters_bytes = old_parameters.canonical_bytes();
        let mut mutated_commitment = commitment_bytes.clone();
        let last_commitment_byte = mutated_commitment.len() - 1;
        mutated_commitment[last_commitment_byte] ^= 1;
        assert!(app
            .verify_later_epoch_checkpoint_finality_v1(
                app.inspect_later_epoch_checkpoint_context_v1().unwrap(),
                &parent_bytes,
                &checkpoint_bytes,
                &finality_bytes,
                &anchor_bytes,
                &mutated_commitment,
                &new_set_bytes,
                &new_parameters_bytes,
            )
            .is_err());
        let context = app.inspect_later_epoch_checkpoint_context_v1().unwrap();
        let observed = app
            .verify_later_epoch_checkpoint_finality_v1(
                context,
                &parent_bytes,
                &checkpoint_bytes,
                &finality_bytes,
                &anchor_bytes,
                &commitment_bytes,
                &new_set_bytes,
                &new_parameters_bytes,
            )
            .unwrap();
        assert!(observed.belongs_to_application(&app));
        assert_eq!(observed.checkpoint_header(), &checkpoint_header);
        assert_eq!(
            observed.joint_handoff().terminal_old_height(),
            Height::new(20)
        );
        assert!(
            app.commit_later_epoch_checkpoint_finality_v1(&observed)
                .is_err(),
            "schema4 cannot silently enter the later commit path"
        );
        let expected_parent = app.confirmed_committed_head_v0().unwrap();
        // The strict observation is now consumed by the explicit schema-8
        // owner.  The migration itself is opt-in and preserves the schema-4
        // rows; commit/retry must survive a fresh owner reopen.
        app.upgrade_later_epoch_schema_v1(&app.confirmed_committed_head_v0().unwrap())
            .unwrap();
        app.upgrade_later_epoch_schema_v1(&expected_parent).unwrap();
        if std::env::var_os("TRNM_LATER_EPOCH_CRASH_STORE").is_some() {
            std::fs::write(
                path.with_extension("later-proof"),
                serde_json::to_vec(&vec![
                    parent_bytes.clone(),
                    checkpoint_bytes.clone(),
                    finality_bytes.clone(),
                    anchor_bytes.clone(),
                    commitment_bytes.clone(),
                    new_set_bytes.clone(),
                    new_parameters_bytes.clone(),
                ])
                .unwrap(),
            )
            .unwrap();
        }
        let committed = app
            .commit_later_epoch_checkpoint_finality_v1(&observed)
            .unwrap();
        assert_eq!(
            committed.head().block_id().as_bytes(),
            checkpoint_header.id().as_bytes()
        );
        assert_eq!(
            app.confirmed_committed_head_v0().unwrap(),
            *committed.head()
        );
        let retried = app
            .commit_later_epoch_checkpoint_finality_v1(&observed)
            .unwrap();
        assert_eq!(retried.commit_sequence(), committed.commit_sequence());
        drop(app);
        let config = native_checkpoint_fixture_config_v1();
        let reopened = DurableNativeApplicationV0::open(path, config).unwrap();
        assert_eq!(
            reopened
                .confirmed_committed_head_v0()
                .unwrap()
                .block_id()
                .as_bytes(),
            checkpoint_header.id().as_bytes()
        );
        let record_count: i64 = rusqlite::Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM native_later_epoch_finality_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(record_count, 1);
        // A pre-commit-id schema-8 image must fail closed. The compact edge
        // row cannot safely invent the committed application commit identity;
        // operators must rebuild it through an explicit migration.
        let legacy_path = path.with_extension("legacy-edge.sqlite3");
        std::fs::copy(path, &legacy_path).unwrap();
        let legacy = rusqlite::Connection::open(&legacy_path).unwrap();
        legacy
            .execute_batch(
                "ALTER TABLE native_later_epoch_edge_v1 RENAME TO native_later_epoch_edge_v1_old;
                 CREATE TABLE native_later_epoch_edge_v1 (
                   successor_binding BLOB PRIMARY KEY CHECK(length(successor_binding)=32),
                   predecessor_edge BLOB NOT NULL UNIQUE CHECK(length(predecessor_edge)=32),
                   checkpoint_block BLOB NOT NULL UNIQUE CHECK(length(checkpoint_block)=32),
                   checkpoint_p_digest BLOB NOT NULL CHECK(length(checkpoint_p_digest)=32),
                   checkpoint_commit_sequence BLOB NOT NULL CHECK(length(checkpoint_commit_sequence)=8),
                   checkpoint_height BLOB NOT NULL CHECK(length(checkpoint_height)=8),
                   checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root)=32),
                   terminal_height BLOB NOT NULL CHECK(length(terminal_height)=8),
                   terminal_block BLOB NOT NULL CHECK(length(terminal_block)=32),
                   first_height BLOB NOT NULL CHECK(length(first_height)=8),
                   proof_context_digest BLOB NOT NULL CHECK(length(proof_context_digest)=32),
                   successor_context_digest BLOB NOT NULL CHECK(length(successor_context_digest)=32),
                   authority_digest BLOB NOT NULL CHECK(length(authority_digest)=32),
                   phase INTEGER NOT NULL CHECK(phase IN (0,1)),
                   consumed_block BLOB, consumed_sequence BLOB,
                   record_digest BLOB NOT NULL CHECK(length(record_digest)=32),
                   CHECK((phase=0 AND consumed_block IS NULL AND consumed_sequence IS NULL) OR
                     (phase=1 AND length(consumed_block)=32 AND length(consumed_sequence)=8))
                 );
                 INSERT INTO native_later_epoch_edge_v1
                   SELECT successor_binding,predecessor_edge,checkpoint_block,checkpoint_p_digest,
                          checkpoint_commit_sequence,checkpoint_height,checkpoint_root,terminal_height,
                          terminal_block,first_height,proof_context_digest,successor_context_digest,
                          authority_digest,phase,consumed_block,consumed_sequence,record_digest
                     FROM native_later_epoch_edge_v1_old;
                 DROP TABLE native_later_epoch_edge_v1_old;",
            )
            .unwrap();
        let legacy_error = match DurableNativeApplicationV0::open(
            &legacy_path,
            native_checkpoint_fixture_config_v1(),
        ) {
            Ok(_) => panic!("legacy successor schema unexpectedly opened"),
            Err(error) => error,
        };
        assert!(
            legacy_error.to_string().contains("schema.exact"),
            "legacy schema error: {legacy_error:#}"
        );
        drop(legacy);
        std::fs::remove_file(&legacy_path).unwrap();
        assert!(
            reopened
                .commit_later_epoch_checkpoint_finality_v1(&observed)
                .is_err(),
            "old owner observation cannot authorize a reopened owner"
        );
        let recovered = reopened
            .recover_later_epoch_checkpoint_commit_v1(*checkpoint_header.id().as_bytes())
            .unwrap();
        assert_eq!(recovered.commit_sequence(), committed.commit_sequence());

        // Schema 8 durably proves C18, retains the H17 predecessor, and
        // installs a separately checksummed C18 -> C21 successor-edge row.
        // Inspect the exact successor requirements before reopening that
        // owner-affine capability; the request/header-based C+3 seam below
        // is the only candidate execution path and remains independently
        // gated from the legacy edge-only API.
        let requirements = reopened
            .inspect_later_epoch_application_edge_requirements_v1(
                *checkpoint_header.id().as_bytes(),
            )
            .unwrap();
        assert!(requirements.belongs_to_application(&reopened));
        assert_eq!(requirements.checkpoint_height(), 18);
        assert_eq!(requirements.terminal_height(), 20);
        assert_ne!(requirements.terminal_block(), [0; 32]);
        assert_eq!(requirements.first_application_height(), 21);
        assert_ne!(requirements.proof_context_digest(), [0; 32]);
        assert_ne!(requirements.successor_context_digest(), [0; 32]);
        assert_ne!(
            requirements.proof_context_digest(),
            requirements.successor_context_digest()
        );
        assert_ne!(requirements.successor_binding(), [0; 32]);
        assert_ne!(
            requirements.successor_binding(),
            requirements.predecessor_edge()
        );
        let stored_predecessor: [u8; 32] = rusqlite::Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT predecessor_edge FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?",
                [checkpoint_header.id().as_bytes().as_slice()],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
                },
            )
            .unwrap();
        assert_eq!(requirements.predecessor_edge(), stored_predecessor);
        let successor = reopened
            .require_later_epoch_application_edge_v1(&requirements)
            .unwrap();
        let reopened_successor = reopened
            .recover_later_epoch_application_edge_v1(&requirements)
            .unwrap();
        assert!(successor.belongs_to_application(&reopened));
        assert_eq!(
            reopened_successor.record_digest(),
            successor.record_digest()
        );
        assert_eq!(
            successor.successor_binding(),
            requirements.successor_binding()
        );
        assert_eq!(
            successor.predecessor_edge(),
            requirements.predecessor_edge()
        );
        assert_eq!(
            successor.checkpoint_block(),
            requirements.checkpoint_block()
        );
        assert_eq!(successor.checkpoint_height(), 18);
        assert_eq!(successor.terminal_height(), 20);
        assert_eq!(successor.first_application_height(), 21);
        let coordinates = successor.coordinates_v1();
        coordinates.validate().unwrap();
        assert_eq!(successor.application_parent_v1().height().get(), 18);
        assert_ne!(successor.authority_digest(), [0; 32]);
        assert_ne!(successor.record_digest(), [0; 32]);
        let first_request = NativeEpochBlockPreviewRequestV1::new(
            ChainIdV0::new(new_set.chain_id().as_str()).unwrap(),
            GenesisHashV0::new(*new_set.genesis_hash().as_bytes()).unwrap(),
            successor.application_parent_v1(),
            BlockIdV0::new(successor.terminal_block()).unwrap(),
            HeightV0::new(successor.terminal_height()),
            Hash32V0::new(successor.successor_binding()),
            HeightV0::new(successor.first_application_height()),
            21_000,
            trnm_native_application::ValidatorSetIdV0::new(*new_set.id().as_bytes()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let first_preview = reopened
            .preview_later_epoch_block_v1(&successor, &first_request)
            .unwrap();
        let first_header = checkpoint_like_header(
            &new_set,
            BlockKind::EpochHandoff,
            successor.first_application_height(),
            BlockId::new(successor.terminal_block()),
            StateRoot::new(*first_preview.post_state_root().as_bytes()),
            None,
            first_request.timestamp_ms(),
            PayloadDigest::new(*first_preview.payload_root().as_bytes()),
            ReceiptsRoot::new(*first_preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*first_preview.evidence_root().as_bytes()),
        );
        let first_execution = NativeEpochBlockExecutionRequestV1::new(
            first_request.clone(),
            BlockIdV0::new(*first_header.id().as_bytes()).unwrap(),
            NativeExpectedBlockCommitmentsV0::new(
                first_preview.payload_root(),
                first_preview.post_state_root(),
                first_preview.receipts_root(),
                first_preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let prepared_first = reopened
            .prepare_later_epoch_first_new_block_v1(&successor, first_execution, &first_header)
            .unwrap();
        let reopened_first = reopened
            .reopen_prepared_epoch_execution_v1(*first_header.id().as_bytes())
            .unwrap();
        assert_eq!(reopened_first.p_digest(), prepared_first.p_digest());
        let second_header = checkpoint_like_header_at_view(
            &new_set,
            BlockKind::Regular,
            successor.first_application_height() + 1,
            first_header.id(),
            StateRoot::new(*first_preview.post_state_root().as_bytes()),
            None,
            22_000,
            PayloadDigest::new(*first_preview.payload_root().as_bytes()),
            ReceiptsRoot::new(*first_preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*first_preview.evidence_root().as_bytes()),
            2,
        );
        let third_header = checkpoint_like_header_at_view(
            &new_set,
            BlockKind::Regular,
            successor.first_application_height() + 2,
            second_header.id(),
            StateRoot::new(*first_preview.post_state_root().as_bytes()),
            None,
            23_000,
            PayloadDigest::new(*first_preview.payload_root().as_bytes()),
            ReceiptsRoot::new(*first_preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*first_preview.evidence_root().as_bytes()),
            3,
        );
        let later_first_proof = later_epoch_first_finality(
            &old_set,
            &old_parameters,
            &old_set.try_cev0_bytes().unwrap(),
            &new_set_bytes,
            &new_parameters_bytes,
            &parent_bytes,
            &finality_bytes,
            &anchor_bytes,
            &commitment_bytes,
            &[first_header.clone(), second_header, third_header],
        );
        // The C+3 crash harness records the exact first-new header and
        // finality bytes before entering the durable commit boundary.  The
        // subprocess is killed at the requested boundary and the parent test
        // reopens this same owner to exercise the retry path.
        if let Some(crash_store) = std::env::var_os("TRNM_LATER_APPLICATION_CRASH_STORE") {
            std::fs::write(
                std::path::PathBuf::from(crash_store).with_extension("later-application-proof"),
                serde_json::to_vec(&vec![
                    first_header.try_cev0_bytes().unwrap(),
                    later_first_proof.clone(),
                ])
                .unwrap(),
            )
            .unwrap();
        }
        let committed_first = reopened
            .commit_epoch_finality_bytes_v1(
                &prepared_first,
                &later_first_proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(committed_first.head().height().get(), 21);
        let retry_first = reopened
            .commit_epoch_finality_bytes_v1(
                &prepared_first,
                &later_first_proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(
            retry_first.commit_sequence(),
            committed_first.commit_sequence()
        );
        let c21 = reopened
            .reopen_prepared_epoch_execution_v1(*first_header.id().as_bytes())
            .unwrap();
        let c22_parent = c21.overlay_parent_head().unwrap();
        let c22_request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(new_set.chain_id().as_str()).unwrap(),
            GenesisHashV0::new(*new_set.genesis_hash().as_bytes()).unwrap(),
            c22_parent,
            HeightV0::new(22),
            22_000,
            trnm_native_application::ValidatorSetIdV0::new(*new_set.id().as_bytes()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let c22_preview = reopened
            .preview_epoch_descendant_v1(&c21, &c22_request)
            .expect("C+4 preview must resolve mixed later lineage");
        let c22_header = checkpoint_like_header_at_view(
            &new_set,
            BlockKind::Regular,
            22,
            BlockId::new(*c22_request.parent().block_id().as_bytes()),
            StateRoot::new(*c22_preview.post_state_root().as_bytes()),
            None,
            c22_request.timestamp_ms(),
            PayloadDigest::new(*c22_preview.payload_root().as_bytes()),
            ReceiptsRoot::new(*c22_preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*c22_preview.evidence_root().as_bytes()),
            2,
        );
        let c22_execution = NativeBlockExecutionRequestV0::new(
            c22_request.chain_id().clone(),
            c22_request.genesis_hash(),
            c22_request.parent().clone(),
            BlockIdV0::new(*c22_header.id().as_bytes()).unwrap(),
            c22_request.height(),
            c22_request.timestamp_ms(),
            c22_request.active_validator_set_id(),
            Vec::new(),
            NativeExpectedBlockCommitmentsV0::new(
                c22_preview.payload_root(),
                c22_preview.post_state_root(),
                c22_preview.receipts_root(),
                c22_preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let c22 = reopened
            .execute_epoch_descendant_v1(&c21, c22_execution, &c22_header)
            .expect("C+4 prepare must inherit the later target configuration");
        drop((c21, c22));
        drop(reopened);
        let reopened =
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).unwrap();
        let c22 = reopened
            .reopen_prepared_epoch_execution_v1(*c22_header.id().as_bytes())
            .unwrap();
        assert_ne!(c22.p_digest(), [0; 32]);

        let c23_parent = c22.overlay_parent_head().unwrap();
        let c23_request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(new_set.chain_id().as_str()).unwrap(),
            GenesisHashV0::new(*new_set.genesis_hash().as_bytes()).unwrap(),
            c23_parent,
            HeightV0::new(23),
            23_000,
            trnm_native_application::ValidatorSetIdV0::new(*new_set.id().as_bytes()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let c23_preview = reopened
            .preview_epoch_descendant_v1(&c22, &c23_request)
            .expect("C+4 second block preview must retain mixed lineage");
        let c23_header = checkpoint_like_header_at_view(
            &new_set,
            BlockKind::Regular,
            23,
            BlockId::new(*c23_request.parent().block_id().as_bytes()),
            StateRoot::new(*c23_preview.post_state_root().as_bytes()),
            None,
            c23_request.timestamp_ms(),
            PayloadDigest::new(*c23_preview.payload_root().as_bytes()),
            ReceiptsRoot::new(*c23_preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*c23_preview.evidence_root().as_bytes()),
            3,
        );
        let c23 = reopened
            .execute_epoch_descendant_v1(
                &c22,
                NativeBlockExecutionRequestV0::new(
                    c23_request.chain_id().clone(),
                    c23_request.genesis_hash(),
                    c23_request.parent().clone(),
                    BlockIdV0::new(*c23_header.id().as_bytes()).unwrap(),
                    c23_request.height(),
                    c23_request.timestamp_ms(),
                    c23_request.active_validator_set_id(),
                    Vec::new(),
                    NativeExpectedBlockCommitmentsV0::new(
                        c23_preview.payload_root(),
                        c23_preview.post_state_root(),
                        c23_preview.receipts_root(),
                        c23_preview.evidence_root(),
                    )
                    .unwrap(),
                )
                .unwrap(),
                &c23_header,
            )
            .expect("C+4 second block prepare must succeed");
        let c24_parent = c23.overlay_parent_head().unwrap();
        let c24_request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(new_set.chain_id().as_str()).unwrap(),
            GenesisHashV0::new(*new_set.genesis_hash().as_bytes()).unwrap(),
            c24_parent,
            HeightV0::new(24),
            24_000,
            trnm_native_application::ValidatorSetIdV0::new(*new_set.id().as_bytes()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let c24_preview = reopened
            .preview_epoch_descendant_v1(&c23, &c24_request)
            .expect("C+4 third block preview must retain mixed lineage");
        let c24_header = checkpoint_like_header_at_view(
            &new_set,
            BlockKind::Regular,
            24,
            BlockId::new(*c24_request.parent().block_id().as_bytes()),
            StateRoot::new(*c24_preview.post_state_root().as_bytes()),
            None,
            c24_request.timestamp_ms(),
            PayloadDigest::new(*c24_preview.payload_root().as_bytes()),
            ReceiptsRoot::new(*c24_preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*c24_preview.evidence_root().as_bytes()),
            4,
        );
        let _c24 = reopened
            .execute_epoch_descendant_v1(
                &c23,
                NativeBlockExecutionRequestV0::new(
                    c24_request.chain_id().clone(),
                    c24_request.genesis_hash(),
                    c24_request.parent().clone(),
                    BlockIdV0::new(*c24_header.id().as_bytes()).unwrap(),
                    c24_request.height(),
                    c24_request.timestamp_ms(),
                    c24_request.active_validator_set_id(),
                    Vec::new(),
                    NativeExpectedBlockCommitmentsV0::new(
                        c24_preview.payload_root(),
                        c24_preview.post_state_root(),
                        c24_preview.receipts_root(),
                        c24_preview.evidence_root(),
                    )
                    .unwrap(),
                )
                .unwrap(),
                &c24_header,
            )
            .expect("C+4 third block prepare must succeed");
        let certify = |header: &BlockHeader, parent: &BlockHeader| {
            let justify = QcReferenceV0::ordinary(qc(parent, &new_set));
            let root = ProposalWitnessV0::signing_root_for(header, &justify, None, None).unwrap();
            let proposer = new_set
                .validators()
                .iter()
                .position(|validator| validator.id() == header.proposer_id())
                .unwrap();
            CertifiedHeaderV0::new(
                header.clone(),
                justify,
                None,
                None,
                Signature64::from_array(key(proposer).sign(root.as_bytes()).to_bytes()),
                qc(header, &new_set),
                &new_set,
                None,
                &old_parameters,
                parent.timestamp_ms(),
            )
            .unwrap()
        };
        let c22_proof = FinalityProofV0::new(
            certify(&c22_header, &first_header),
            certify(&c23_header, &c22_header),
            certify(&c24_header, &c23_header),
            &new_set,
            None,
            &old_parameters,
            first_header.timestamp_ms(),
        )
        .unwrap()
        .try_cev0_bytes()
        .unwrap();
        // Pin the locally generated C18/epoch1 configuration before producing
        // any untrusted export. The receiving test never derives trust from it.
        let anchor_header = checkpoint_header.try_cev0_bytes().unwrap();
        let anchor_set = old_set.try_cev0_bytes().unwrap();
        let anchor_parameters = old_parameters.canonical_bytes();
        let anchor_pin = trnm_state_sync_v0::native_trust_anchor_pin_v1(
            &anchor_header,
            &anchor_set,
            &anchor_parameters,
        )
        .unwrap();
        let trust_anchor = trnm_state_sync_v0::NativeTrustAnchorV1::from_pinned_bytes(
            &anchor_header,
            &anchor_set,
            &anchor_parameters,
            anchor_pin,
        )
        .unwrap();
        let other_anchor_header = headers[6].try_cev0_bytes().unwrap();
        assert_eq!(headers[6].height().get(), 17);
        let other_anchor_pin = trnm_state_sync_v0::native_trust_anchor_pin_v1(
            &other_anchor_header,
            &anchor_set,
            &anchor_parameters,
        )
        .unwrap();
        let other_trust_anchor = trnm_state_sync_v0::NativeTrustAnchorV1::from_pinned_bytes(
            &other_anchor_header,
            &anchor_set,
            &anchor_parameters,
            other_anchor_pin,
        )
        .unwrap();
        Box::new(LaterDescendantFixture {
            application: reopened,
            prepared: c22,
            checkpoint_header,
            first_header,
            c22_header,
            c23_header,
            c24_header,
            c23_request,
            c22_proof,
            validator_set: new_set,
            parameters: old_parameters,
            predecessor: *observed.lineage().last().unwrap(),
            trust_anchor,
            other_trust_anchor,
        })
    }

    #[test]
    fn later_checkpoint_bridge_accepts_real_h17_c18_s19_s20_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let path = std::env::var_os("TRNM_LATER_EPOCH_CRASH_STORE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| directory.path().join("application.sqlite3"));
        let fixture = build_later_descendant_fixture(&path);
        assert_later_descendant_fixture(&path, fixture);
    }

    #[inline(never)]
    fn assert_later_descendant_fixture(
        path: &std::path::Path,
        fixture: Box<LaterDescendantFixture>,
    ) {
        assert_schema9_prepared_descendant_migration(path);
        let LaterDescendantFixture {
            application: reopened,
            prepared: c22,
            checkpoint_header,
            first_header,
            c22_header,
            c23_header,
            c24_header,
            c23_request,
            c22_proof,
            validator_set: new_set,
            parameters,
            predecessor,
            ..
        } = *fixture;
        assert_signature_mutant_is_canonical(
            &c22_proof,
            &first_header,
            &c22_header,
            &new_set,
            &parameters,
        );
        let wrong_authority =
            wrong_descendant_authority_proofs(&first_header, &new_set, &parameters);
        for (name, proof) in &wrong_authority {
            assert!(
                reopened
                    .commit_epoch_finality_bytes_v1(
                        &c22,
                        proof,
                        &mut Cev0AdmissionBudgetV0::protocol_v0()
                    )
                    .is_err(),
                "signed wrong {name} proof must not commit prepared C22"
            );
            assert_eq!(
                reopened
                    .confirmed_committed_head_v0()
                    .unwrap()
                    .height()
                    .get(),
                21
            );
        }
        let committed_c22 = reopened
            .commit_epoch_finality_bytes_v1(
                &c22,
                &c22_proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .expect("C+4 strict ordinary finality must commit");
        let retried_c22 = reopened
            .commit_epoch_finality_bytes_v1(
                &c22,
                &c22_proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .expect("C+4 strict ordinary finality retry must be exact");
        assert_eq!(
            retried_c22.commit_sequence(),
            committed_c22.commit_sequence()
        );
        let alternate_c24 = later_regular_header(&new_set, &c23_header, 24_001);
        let alternate_proof = ordinary_later_proof(
            &first_header,
            &[c22_header.clone(), c23_header.clone(), alternate_c24],
            &new_set,
            &parameters,
        );
        assert_ne!(alternate_proof, c22_proof);
        assert_valid_ordinary_later_proof(
            &alternate_proof,
            &first_header,
            &c22_header,
            &new_set,
            &parameters,
        );
        let error = match reopened.commit_epoch_finality_bytes_v1(
            &c22,
            &alternate_proof,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        ) {
            Ok(_) => panic!("different valid proof must not replace the original C22 proof"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("later descendant conflicting retry"),
            "{error:#}"
        );
        let c25_header = later_regular_header(&new_set, &c24_header, 25_000);
        let c23_proof = ordinary_later_proof(
            &c22_header,
            &[c23_header.clone(), c24_header.clone(), c25_header],
            &new_set,
            &parameters,
        );
        let c23 = reopened
            .reopen_prepared_epoch_execution_v1(*c23_header.id().as_bytes())
            .unwrap();
        let committed_c23 = reopened
            .commit_epoch_finality_bytes_v1(
                &c23,
                &c23_proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .expect("C23 must advance the ordinary head");
        assert_eq!(committed_c23.head().height().get(), 23);
        let later_retry = reopened
            .commit_epoch_finality_bytes_v1(
                &c22,
                &c22_proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .expect("C22 exact retry must survive a later committed head");
        assert_eq!(
            later_retry.commit_sequence(),
            committed_c22.commit_sequence()
        );
        assert_schema9_committed_descendant_migration_refused(path);
        drop(reopened);
        let reopened =
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).unwrap();
        let cold_head = reopened
            .confirmed_committed_head_v0()
            .expect("C+4 committed row must cold-recover");
        assert_eq!(cold_head.height().get(), c23_header.height().get());
        assert_eq!(cold_head.block_id().as_bytes(), c23_header.id().as_bytes());
        let sql = rusqlite::Connection::open(path).unwrap();
        let proof_count: i64 = sql
            .query_row(
                "SELECT COUNT(*) FROM native_later_epoch_application_finality_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(proof_count, 1, "C+4 must not mint a second handoff proof");
        let consumed_block: Vec<u8> = sql
            .query_row(
                "SELECT consumed_block FROM native_later_epoch_edge_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(consumed_block, first_header.id().as_bytes());
        // A schema-8 image cannot represent a consumed C+3 edge without the
        // schema-9 application proof ledger. Migration must fail closed
        // instead of creating an empty ledger and blessing phase=1.
        let legacy_path = path.with_extension("consumed-schema8.sqlite3");
        std::fs::copy(path, &legacy_path).unwrap();
        let source_sidecar =
            crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(path);
        let legacy_sidecar =
            crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&legacy_path);
        std::fs::copy(source_sidecar, &legacy_sidecar).unwrap();
        let copied_app =
            DurableNativeApplicationV0::open(&legacy_path, native_checkpoint_fixture_config_v1())
                .unwrap();
        let copied_c22 = copied_app
            .reopen_prepared_epoch_execution_v1(*c22_header.id().as_bytes())
            .unwrap();
        let legacy_sql = rusqlite::Connection::open(&legacy_path).unwrap();
        legacy_sql.execute_batch("DROP TABLE native_later_epoch_descendant_finality_v1; DROP TABLE native_later_epoch_application_finality_v1;").unwrap();
        legacy_sql
            .execute(
                "UPDATE native_application_metadata_v0 SET schema_version=? WHERE singleton=1",
                [8_u64.to_be_bytes().as_slice()],
            )
            .unwrap();
        drop(legacy_sql);
        let preview_error = copied_app
            .preview_epoch_descendant_v1(&copied_c22, &c23_request)
            .unwrap_err();
        assert!(
            preview_error
                .to_string()
                .contains("later descendant authority requires schema10 ordinary finality"),
            "schema-8 C+4 preview error: {preview_error:#}"
        );
        let prepare_error = copied_app
            .execute_epoch_descendant_v1(
                &copied_c22,
                descendant_execution_request(&c23_request, &c23_header),
                &c23_header,
            )
            .err()
            .expect("schema8 later descendant execution must reject");
        assert!(
            prepare_error
                .to_string()
                .contains("later descendant authority requires schema10 ordinary finality"),
            "{prepare_error:#}"
        );
        let commit_error = match copied_app.commit_epoch_finality_bytes_v1(
            &copied_c22,
            &c22_proof,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        ) {
            Ok(_) => panic!("schema-8 C+4 commit unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(
            commit_error
                .to_string()
                .contains("later descendant commit requires schema10 ordinary finality"),
            "schema-8 C+4 commit error: {commit_error:#}"
        );
        drop(copied_app);
        let legacy_app =
            DurableNativeApplicationV0::open(&legacy_path, native_checkpoint_fixture_config_v1())
                .unwrap();
        assert!(
            legacy_app
                .upgrade_later_epoch_schema_v1(&legacy_app.confirmed_committed_head_v0().unwrap())
                .is_err(),
            "schema-8 consumed successor must require a retained C+3 proof"
        );
        drop(legacy_app);
        std::fs::remove_file(&legacy_path).unwrap();
        std::fs::remove_file(legacy_sidecar).unwrap();
        let requirements = reopened
            .inspect_later_epoch_application_edge_requirements_v1(
                *checkpoint_header.id().as_bytes(),
            )
            .unwrap();
        let successor = reopened
            .require_later_epoch_application_edge_v1(&requirements)
            .unwrap();
        assert!(reopened
            .execute_later_epoch_first_new_block_v1(&successor)
            .is_err());
        let successor_count: i64 = rusqlite::Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM native_later_epoch_edge_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(successor_count, 1);
        let old_edge = reopened
            .recover_epoch_application_edge_v1(requirements.predecessor_edge())
            .unwrap();
        assert!(
            reopened.open_epoch_checkpoint_store_v1(&old_edge).is_err(),
            "the H17 edge cannot execute C21 after the C18 checkpoint commit"
        );
        drop(reopened);
        assert_descendant_ledger_recovery(
            path,
            c22_header.id().as_bytes(),
            &c23_proof,
            &wrong_authority,
        );
        assert_later_application_ledger_recovery(path);
        let sql = rusqlite::Connection::open(path).unwrap();
        let original_successor_record: Vec<u8> = sql
            .query_row(
                "SELECT record_digest FROM native_later_epoch_edge_v1 WHERE checkpoint_block=?",
                [checkpoint_header.id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        sql.execute(
            "UPDATE native_later_epoch_edge_v1 SET record_digest=zeroblob(32) WHERE checkpoint_block=?",
            [checkpoint_header.id().as_bytes().as_slice()],
        )
        .unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err(),
            "successor edge checksum mutation must fail cold open"
        );
        sql.execute(
            "UPDATE native_later_epoch_edge_v1 SET record_digest=? WHERE checkpoint_block=?",
            rusqlite::params![
                original_successor_record,
                checkpoint_header.id().as_bytes().as_slice()
            ],
        )
        .unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_ok()
        );
        let original_finality: Vec<u8> = sql
            .query_row(
                "SELECT checkpoint_finality FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?",
                [checkpoint_header.id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        sql.execute(
            "UPDATE native_later_epoch_finality_v1 SET checkpoint_finality=zeroblob(length(checkpoint_finality)) WHERE checkpoint_block=?",
            [checkpoint_header.id().as_bytes().as_slice()],
        )
        .unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err()
        );
        sql.execute(
            "UPDATE native_later_epoch_finality_v1 SET checkpoint_finality=? WHERE checkpoint_block=?",
            rusqlite::params![original_finality, checkpoint_header.id().as_bytes().as_slice()],
        )
        .unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_ok()
        );
        // Corrupt a signature and recompute the complete local checksum. The
        // cryptographic verifier, not the checksum, must reject cold recovery.
        let original: Vec<u8> = sql
            .query_row(
                "SELECT checkpoint_finality FROM native_later_epoch_finality_v1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut bad_signature = original.clone();
        *bad_signature.last_mut().unwrap() ^= 1;
        sql.execute(
            "UPDATE native_later_epoch_finality_v1 SET checkpoint_finality=?",
            [&bad_signature],
        )
        .unwrap();
        rehash_record(&sql);
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err()
        );
        sql.execute(
            "UPDATE native_later_epoch_finality_v1 SET checkpoint_finality=?",
            [&original],
        )
        .unwrap();
        rehash_record(&sql);
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_ok()
        );
        // A later proof cannot advance from an edge that was rolled back to
        // the installed phase. The phase mutation is made SQL-valid by
        // clearing its consumed target, then restored byte-for-byte.
        let (consumed_block, consumed_sequence): (Vec<u8>, Vec<u8>) = sql
            .query_row(
                "SELECT consumed_block,consumed_sequence FROM native_epoch_edge_v1 WHERE binding=?",
                [predecessor.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        sql.execute(
            "UPDATE native_epoch_edge_v1 SET phase=0,consumed_block=NULL,consumed_sequence=NULL WHERE binding=?",
            [predecessor.as_slice()],
        )
        .unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err(),
            "later proof must reject an unconsumed predecessor edge"
        );
        sql.execute(
            "UPDATE native_epoch_edge_v1 SET phase=1,consumed_block=?,consumed_sequence=? WHERE binding=?",
            rusqlite::params![consumed_block, consumed_sequence, predecessor.as_slice()],
        )
        .unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_ok()
        );
        // Every committed checkpoint needs its retained strict record even
        // when all of its native execution data are otherwise unchanged.
        sql.execute_batch("CREATE TEMP TABLE saved_later AS SELECT * FROM native_later_epoch_finality_v1; DELETE FROM native_later_epoch_finality_v1;").unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err()
        );
        sql.execute_batch("INSERT INTO native_later_epoch_finality_v1 SELECT * FROM saved_later;")
            .unwrap();
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_ok()
        );
    }
    #[cfg(unix)]
    #[test]
    fn later_checkpoint_sigkill_commit_cuts_recover_exact_native_and_proof_record() {
        for stage in [
            "later_epoch_before_commit",
            "later_epoch_after_commit",
            "later_epoch_after_fsync",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("application.sqlite3");
            let marker = directory.path().join("ready");
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "later_epoch_checkpoint_bridge::tests::later_checkpoint_bridge_accepts_real_h17_c18_s19_s20_evidence", "--nocapture"])
                .env("TRNM_LATER_EPOCH_CRASH_STORE", &path)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE", stage)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER", &marker)
                .spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
            while !marker.exists() && std::time::Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !marker.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("later checkpoint child did not reach {stage}");
            }
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            let bytes: Vec<Vec<u8>> =
                serde_json::from_slice(&std::fs::read(path.with_extension("later-proof")).unwrap())
                    .unwrap();
            let app =
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .unwrap();
            let checkpoint = decode_block_header_v0_exact(&bytes[1]).unwrap();
            assert_eq!(
                app.confirmed_committed_head_v0().unwrap().height().get(),
                if stage == "later_epoch_before_commit" {
                    17
                } else {
                    18
                }
            );
            if stage == "later_epoch_before_commit" {
                assert!(app
                    .recover_later_epoch_checkpoint_commit_v1(*checkpoint.id().as_bytes())
                    .is_err());
                let proof = app
                    .verify_later_epoch_checkpoint_finality_v1(
                        app.inspect_later_epoch_checkpoint_context_v1().unwrap(),
                        &bytes[0],
                        &bytes[1],
                        &bytes[2],
                        &bytes[3],
                        &bytes[4],
                        &bytes[5],
                        &bytes[6],
                    )
                    .unwrap();
                let _ = app
                    .commit_later_epoch_checkpoint_finality_v1(&proof)
                    .unwrap();
            }
            let committed = app
                .recover_later_epoch_checkpoint_commit_v1(*checkpoint.id().as_bytes())
                .unwrap();
            assert_eq!(committed.head().height().get(), 18);
            let requirements = app
                .inspect_later_epoch_application_edge_requirements_v1(*checkpoint.id().as_bytes())
                .unwrap();
            let successor = app
                .require_later_epoch_application_edge_v1(&requirements)
                .unwrap();
            assert_eq!(successor.first_application_height(), 21);
            let successor_count: i64 = rusqlite::Connection::open(&path)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM native_later_epoch_edge_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(successor_count, 1);
            let sequence = committed.commit_sequence();
            drop(app);
            let app =
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .unwrap();
            assert_eq!(
                app.recover_later_epoch_checkpoint_commit_v1(*checkpoint.id().as_bytes())
                    .unwrap()
                    .commit_sequence(),
                sequence
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn later_application_c21_sigkill_commit_cuts_recover_exact_p_and_proof() {
        for stage in [
            "later_application_before_commit",
            "later_application_after_commit",
            "later_application_after_fsync",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("application.sqlite3");
            let marker = directory.path().join("ready");
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "later_epoch_checkpoint_bridge::tests::later_checkpoint_bridge_accepts_real_h17_c18_s19_s20_evidence",
                    "--nocapture",
                ])
                .env("TRNM_LATER_EPOCH_CRASH_STORE", &path)
                .env("TRNM_LATER_APPLICATION_CRASH_STORE", &path)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE", stage)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER", &marker)
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
            while !marker.exists() && std::time::Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                marker.exists(),
                "C21 child did not reach {stage} before exiting"
            );
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());

            let encoded: Vec<Vec<u8>> = serde_json::from_slice(
                &std::fs::read(path.with_extension("later-application-proof")).unwrap(),
            )
            .unwrap();
            let first_header = decode_block_header_v0_exact(&encoded[0]).unwrap();
            let first_block = *first_header.id().as_bytes();
            let app =
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .unwrap();
            let head = app.confirmed_committed_head_v0().unwrap();
            assert_eq!(
                head.height().get(),
                if stage == "later_application_before_commit" {
                    18
                } else {
                    21
                },
                "C21 crash cut committed head"
            );

            // A prepared row can always be reconstructed after a kill.  The
            // caller re-submits the exact proof bytes captured before commit;
            // phase-1 cuts must accept only the same durable proof record.
            let prepared = app.reopen_prepared_epoch_execution_v1(first_block).unwrap();
            let committed = app
                .commit_epoch_finality_bytes_v1(
                    &prepared,
                    &encoded[1],
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert_eq!(committed.head().height().get(), 21);
            let retry = app
                .commit_epoch_finality_bytes_v1(
                    &prepared,
                    &encoded[1],
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert_eq!(retry.commit_sequence(), committed.commit_sequence());

            let sql = rusqlite::Connection::open(&path).unwrap();
            let (proof, proof_digest, record_digest): (Vec<u8>, Vec<u8>, Vec<u8>) = sql
                .query_row(
                    "SELECT proof,proof_digest,record_digest
                       FROM native_later_epoch_application_finality_v1
                      WHERE block_id=?",
                    [first_block.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(proof, encoded[1]);
            assert_eq!(proof_digest, sha2::Sha256::digest(&encoded[1]).to_vec());
            assert_eq!(record_digest.len(), 32);
            drop(app);
            sql.execute(
                "UPDATE native_later_epoch_application_finality_v1
                    SET proof=zeroblob(length(proof)) WHERE block_id=?",
                [first_block.as_slice()],
            )
            .unwrap();
            assert!(
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .is_err(),
                "mutated C21 proof must fail closed on cold reopen"
            );
            sql.execute(
                "UPDATE native_later_epoch_application_finality_v1 SET proof=? WHERE block_id=?",
                rusqlite::params![proof, first_block.as_slice()],
            )
            .unwrap();
            assert!(
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .is_ok(),
                "C21 P/proof record must survive cold reopen"
            );
        }
    }
}
