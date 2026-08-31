//! Private H3b2b3b checkpoint/two-seal/joint-handoff authorization.
//!
//! This is the first layer that joins one durably bound native checkpoint
//! header to raw checkpoint/two-seal finality and raw terminal-old/handoff
//! evidence. Every peer object is freshly exact-decoded and every signature is
//! freshly checked with [`StrictEd25519Verifier`]. The commitment, old/new
//! configurations, cutoff tuple, checkpoint roots, and checkpoint block ID
//! can only come from the nested H3b2b3a/pre-header capability.
//!
//! The result is deliberately crate-private and has no aggregate wire object,
//! digest, or domain. It does not construct field 13, authorize activation or
//! signing, map a CometBFT hash to a native [`BlockId`], or remove the Core
//! epoch-transition fence.

use anyhow::{ensure, Context, Result};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_checkpoint_finality_proof_v0_exact,
    decode_epoch_anchor_authorization_kernel_v0_exact, verify_same_version_joint_handoff_kernel_v0,
    BlockHeader, BlockId, BlockKind, CertificateId, ConsensusParametersHash,
    EpochAnchorAuthorizationKernelV0, EvidenceRoot, FinalityProofV0, Height, JointHandoffKernelV0,
    NextEpochCommitmentHash, PayloadDigest, ReceiptsRoot, StateRoot, ValidatorSetId,
};
use trnm_finality_types::hash_domain;

use crate::poco_checkpoint_header::{
    AuthorizedPocoCheckpointHeaderV0, DurablyBoundPocoCheckpointHeaderV0,
};

/// Application-private result seal. This is not a protocol aggregate proof,
/// wire object, or epoch-anchor digest; restart recovery must re-run all raw
/// verification before comparing it.
const AUTHORIZATION_DOMAIN_V0: &str = "trnm.poco-bft.authorized-checkpoint-joint-handoff.v0";

/// Exact H3b2b3b facts retained by the private capability.
///
/// Protocol v0 freezes no aggregate handoff proof. The authorization ID below
/// is only a private application replay seal over the exact independently
/// encoded inputs; it must never be serialized as a protocol proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PocoJointHandoffBoundFactsV0 {
    checkpoint_header_authorization_id: [u8; 32],
    checkpoint_preparation_id: [u8; 32],
    checkpoint_execution_authorization_id: [u8; 32],
    commitment_authorization_id: [u8; 32],
    scheduled_cutoff_authorization_id: [u8; 32],
    old_validator_set_id: ValidatorSetId,
    old_consensus_parameters_hash: ConsensusParametersHash,
    new_validator_set_id: ValidatorSetId,
    new_consensus_parameters_hash: ConsensusParametersHash,
    cutoff_height: Height,
    cutoff_state_root: StateRoot,
    cutoff_entries_root: [u8; 32],
    cutoff_entry_count: u32,
    checkpoint_height: Height,
    checkpoint_native_block_id: BlockId,
    checkpoint_payload_root: PayloadDigest,
    checkpoint_state_root: StateRoot,
    checkpoint_receipts_root: ReceiptsRoot,
    checkpoint_evidence_root: EvidenceRoot,
    next_epoch_commitment_hash: NextEpochCommitmentHash,
    checkpoint_finality_proof_id: CertificateId,
    terminal_old_block_id: BlockId,
    terminal_old_qc_digest: CertificateId,
    handoff_descriptor_digest: CertificateId,
    handoff_certificate_digest: CertificateId,
}

impl PocoJointHandoffBoundFactsV0 {
    pub(crate) const fn checkpoint_native_block_id(self) -> BlockId {
        self.checkpoint_native_block_id
    }

    pub(crate) const fn checkpoint_preparation_id(self) -> [u8; 32] {
        self.checkpoint_preparation_id
    }

    pub(crate) const fn checkpoint_header_authorization_id(self) -> [u8; 32] {
        self.checkpoint_header_authorization_id
    }

    pub(crate) const fn checkpoint_execution_authorization_id(self) -> [u8; 32] {
        self.checkpoint_execution_authorization_id
    }

    pub(crate) const fn commitment_authorization_id(self) -> [u8; 32] {
        self.commitment_authorization_id
    }

    pub(crate) const fn scheduled_cutoff_authorization_id(self) -> [u8; 32] {
        self.scheduled_cutoff_authorization_id
    }

    pub(crate) const fn checkpoint_finality_proof_id(self) -> CertificateId {
        self.checkpoint_finality_proof_id
    }

    pub(crate) const fn handoff_certificate_digest(self) -> CertificateId {
        self.handoff_certificate_digest
    }
}

/// Private authorization of one exact native checkpoint, its two seals, the
/// terminal old-set QC, and both old/new handoff quorums.
///
/// The decoded objects are retained to prevent a later caller from replacing
/// an exact input with an earlier inert token. No accessor yields an epoch
/// anchor or an activation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizedPocoJointHandoffV0 {
    checkpoint_header: BlockHeader,
    checkpoint_parent_header: BlockHeader,
    checkpoint_finality: FinalityProofV0,
    anchor_certificate_kernel: EpochAnchorAuthorizationKernelV0,
    joint_kernel: JointHandoffKernelV0,
    bound_facts: PocoJointHandoffBoundFactsV0,
    authorization_id: [u8; 32],
}

impl AuthorizedPocoJointHandoffV0 {
    pub(crate) const fn checkpoint_header(&self) -> &BlockHeader {
        &self.checkpoint_header
    }

    pub(crate) const fn checkpoint_parent_header(&self) -> &BlockHeader {
        &self.checkpoint_parent_header
    }

    pub(crate) const fn bound_facts(&self) -> PocoJointHandoffBoundFactsV0 {
        self.bound_facts
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }
}

/// Fresh-verifies and joins the raw H3b2b3b evidence to one exact durably
/// bound native checkpoint. Consuming the durable capability makes sidecar
/// reservation and exact-header binding a mandatory production gate.
///
/// `raw_anchor_certificate_kernel_cev0` is the frozen canonical concatenation
/// of the terminal old header, its ordinary QC, and the handoff certificate.
/// It is not an aggregate protocol object or digest. No generic verifier,
/// timestamp, commitment, root, validator set, or parameter preimage is a
/// caller input.
pub(crate) fn authorize_poco_checkpoint_joint_handoff_v0(
    checkpoint_header: DurablyBoundPocoCheckpointHeaderV0,
    raw_checkpoint_parent_header_cev0: &[u8],
    raw_checkpoint_two_seal_finality_cev0: &[u8],
    raw_anchor_certificate_kernel_cev0: &[u8],
) -> Result<AuthorizedPocoJointHandoffV0> {
    authorize_poco_checkpoint_joint_handoff_from_authorized_v0(
        checkpoint_header.authorized(),
        raw_checkpoint_parent_header_cev0,
        raw_checkpoint_two_seal_finality_cev0,
        raw_anchor_certificate_kernel_cev0,
    )
}

/// Test-only raw composition seam for isolated fixture authoring. Production
/// code can only enter through [`authorize_poco_checkpoint_joint_handoff_v0`].
#[cfg(test)]
pub(crate) fn authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
    checkpoint_header: AuthorizedPocoCheckpointHeaderV0,
    raw_checkpoint_parent_header_cev0: &[u8],
    raw_checkpoint_two_seal_finality_cev0: &[u8],
    raw_anchor_certificate_kernel_cev0: &[u8],
) -> Result<AuthorizedPocoJointHandoffV0> {
    authorize_poco_checkpoint_joint_handoff_from_authorized_v0(
        &checkpoint_header,
        raw_checkpoint_parent_header_cev0,
        raw_checkpoint_two_seal_finality_cev0,
        raw_anchor_certificate_kernel_cev0,
    )
}

fn authorize_poco_checkpoint_joint_handoff_from_authorized_v0(
    checkpoint_header: &AuthorizedPocoCheckpointHeaderV0,
    raw_checkpoint_parent_header_cev0: &[u8],
    raw_checkpoint_two_seal_finality_cev0: &[u8],
    raw_anchor_certificate_kernel_cev0: &[u8],
) -> Result<AuthorizedPocoJointHandoffV0> {
    let commitment_authority = checkpoint_header.prepared().commitment_authority();
    let old_validator_set = commitment_authority.old_validator_set();
    let old_parameters = commitment_authority.old_parameters();
    let new_validator_set = commitment_authority.new_validator_set();
    let new_parameters = commitment_authority.new_parameters();
    let commitment = commitment_authority.commitment();
    let scheduled_cutoff = commitment_authority.scheduled_cutoff();
    let authenticated_cutoff = commitment_authority.finalized_cutoff();

    // The pre-header capability must still be internally identical to its
    // scheduled-cutoff source when the later raw evidence is consumed.
    ensure!(
        scheduled_cutoff.old_validator_set() == old_validator_set
            && scheduled_cutoff.old_parameters() == old_parameters,
        "pre-header configuration differs from scheduled-cutoff authority"
    );
    ensure!(
        scheduled_cutoff.epoch() == old_validator_set.epoch()
            && scheduled_cutoff.checkpoint_height() == checkpoint_header.header().height()
            && scheduled_cutoff.cutoff_height() == authenticated_cutoff.cutoff_height()
            && scheduled_cutoff.cutoff_state_root() == authenticated_cutoff.cutoff_state_root()
            && scheduled_cutoff.cutoff_entries_root() == authenticated_cutoff.entries_root()
            && scheduled_cutoff.cutoff_entry_count() == authenticated_cutoff.entry_count(),
        "authenticated H2 cutoff differs from scheduled-cutoff authority"
    );
    ensure!(
        authenticated_cutoff.epoch() == old_validator_set.epoch()
            && authenticated_cutoff.absence_count() == 0,
        "authenticated H2 cutoff is outside the authorized old epoch or contains unsealed absences"
    );
    let commitment_fields = commitment.fields();
    ensure!(
        commitment_fields.snapshot_cutoff_height == scheduled_cutoff.cutoff_height()
            && commitment_fields.snapshot_state_root == scheduled_cutoff.cutoff_state_root()
            && commitment_fields.new_validator_set_hash == new_validator_set.id()
            && commitment_fields.new_consensus_parameters_hash == new_parameters.hash(),
        "b3a commitment differs from the scheduled cutoff or authenticated new configuration"
    );

    let checkpoint_parent_header = decode_block_header_v0_exact(raw_checkpoint_parent_header_cev0)
        .map_err(|error| anyhow::anyhow!("decode exact checkpoint parent header: {error:?}"))?;
    ensure!(
        &checkpoint_parent_header == commitment_authority.checkpoint_parent().header(),
        "raw checkpoint parent differs from the exact certified H1 grandchild"
    );
    ensure!(
        checkpoint_parent_header.genesis_hash() == old_validator_set.genesis_hash()
            && checkpoint_parent_header.chain_id() == old_validator_set.chain_id()
            && checkpoint_parent_header.protocol_version() == old_validator_set.protocol_version()
            && checkpoint_parent_header.epoch() == old_validator_set.epoch()
            && checkpoint_parent_header.validator_set_id() == old_validator_set.id()
            && checkpoint_parent_header.consensus_parameters_hash() == old_parameters.hash(),
        "checkpoint parent header differs from authenticated old context"
    );
    ensure!(
        checkpoint_parent_header.id() == checkpoint_header.header().parent_id()
            && checkpoint_parent_header
                .height()
                .get()
                .checked_add(1)
                .is_some_and(|height| height == checkpoint_header.header().height().get())
            && checkpoint_parent_header.block_kind() == BlockKind::Regular
            && checkpoint_parent_header
                .next_epoch_commitment_hash()
                .is_none(),
        "checkpoint parent header is not the exact parent of the authorized checkpoint"
    );

    // Timestamp is derived only from the exact authenticated parent header.
    let checkpoint_finality = decode_checkpoint_finality_proof_v0_exact(
        raw_checkpoint_two_seal_finality_cev0,
        old_validator_set,
        old_parameters,
        &commitment,
        checkpoint_parent_header.timestamp_ms(),
    )
    .map_err(|error| anyhow::anyhow!("decode exact checkpoint/two-seal proof: {error:?}"))?;
    let finalized_checkpoint = checkpoint_finality.finalized_block();
    ensure!(
        finalized_checkpoint.header() == checkpoint_header.header(),
        "raw checkpoint/two-seal proof does not contain the exact authorized checkpoint header"
    );
    let checkpoint_justify = finalized_checkpoint
        .justify_qc()
        .as_ordinary()
        .context("checkpoint justify must be an ordinary QC")?;
    ensure!(
        checkpoint_justify.block_id() == checkpoint_parent_header.id()
            && checkpoint_justify.height() == checkpoint_parent_header.height()
            && checkpoint_justify.view() == checkpoint_parent_header.view(),
        "checkpoint parent header differs from the exact checkpoint justify QC"
    );

    let anchor_certificate_kernel = decode_epoch_anchor_authorization_kernel_v0_exact(
        raw_anchor_certificate_kernel_cev0,
        old_validator_set,
        new_validator_set,
    )
    .map_err(|error| anyhow::anyhow!("decode exact terminal/handoff kernel: {error:?}"))?;

    // B2-F re-runs B2-E plus terminal-QC and both handoff signature roles.
    // Supplying the strict verifier here is not caller-configurable.
    let joint_kernel = verify_same_version_joint_handoff_kernel_v0(
        &checkpoint_finality,
        &commitment,
        &anchor_certificate_kernel,
        old_validator_set,
        old_parameters,
        new_validator_set,
        new_parameters,
        checkpoint_parent_header.timestamp_ms(),
        &StrictEd25519Verifier,
    )
    .map_err(|error| anyhow::anyhow!("strict same-version joint handoff: {error}"))?;
    ensure!(
        anchor_certificate_kernel.terminal_old_header()
            == checkpoint_finality.grandchild().header()
            && anchor_certificate_kernel.terminal_old_qc()
                == checkpoint_finality.grandchild().certifying_qc(),
        "anchor terminal header/QC are not the exact seal-2 certified object"
    );

    let validated_checkpoint = checkpoint_header.validated_commitments();
    let expected_checkpoint = CheckpointBindingV0 {
        height: checkpoint_header.header().height(),
        block_id: validated_checkpoint.block_id(),
        payload_root: validated_checkpoint.payload_root(),
        state_root: validated_checkpoint.state_root(),
        receipts_root: validated_checkpoint.receipts_root(),
        evidence_root: validated_checkpoint.evidence_root(),
        commitment_hash: validated_checkpoint.next_epoch_commitment_hash(),
        old_validator_set_id: old_validator_set.id(),
        old_parameters_hash: old_parameters.hash(),
        new_validator_set_id: new_validator_set.id(),
        new_parameters_hash: new_parameters.hash(),
    };
    let observed_checkpoint = CheckpointBindingV0 {
        height: joint_kernel.checkpoint_height(),
        block_id: joint_kernel.checkpoint_block_id(),
        payload_root: finalized_checkpoint.header().payload_root(),
        state_root: joint_kernel.checkpoint_state_root(),
        receipts_root: finalized_checkpoint.header().receipts_root(),
        evidence_root: finalized_checkpoint.header().evidence_root(),
        commitment_hash: joint_kernel.next_epoch_commitment_digest(),
        old_validator_set_id: joint_kernel.old_validator_set_hash(),
        old_parameters_hash: joint_kernel.old_consensus_parameters_hash(),
        new_validator_set_id: joint_kernel.new_validator_set_hash(),
        new_parameters_hash: joint_kernel.new_consensus_parameters_hash(),
    };
    ensure_same_checkpoint_binding_v0(expected_checkpoint, observed_checkpoint)?;

    ensure!(
        joint_kernel.checkpoint_finality_proof_id() == checkpoint_finality.id()
            && joint_kernel.terminal_old_block_id()
                == anchor_certificate_kernel.terminal_old_header().id()
            && joint_kernel.terminal_old_qc_digest()
                == anchor_certificate_kernel.terminal_old_qc().id(),
        "joint kernel evidence identifiers differ from the freshly decoded raw objects"
    );

    let bound_facts = PocoJointHandoffBoundFactsV0 {
        checkpoint_header_authorization_id: checkpoint_header.authorization_id(),
        checkpoint_preparation_id: checkpoint_header.prepared().preparation_id(),
        checkpoint_execution_authorization_id: checkpoint_header
            .prepared()
            .native_execution_authorization_id(),
        commitment_authorization_id: commitment_authority.authorization_id(),
        scheduled_cutoff_authorization_id: scheduled_cutoff.authorization_id(),
        old_validator_set_id: old_validator_set.id(),
        old_consensus_parameters_hash: old_parameters.hash(),
        new_validator_set_id: new_validator_set.id(),
        new_consensus_parameters_hash: new_parameters.hash(),
        cutoff_height: scheduled_cutoff.cutoff_height(),
        cutoff_state_root: scheduled_cutoff.cutoff_state_root(),
        cutoff_entries_root: scheduled_cutoff.cutoff_entries_root(),
        cutoff_entry_count: scheduled_cutoff.cutoff_entry_count(),
        checkpoint_height: expected_checkpoint.height,
        checkpoint_native_block_id: expected_checkpoint.block_id,
        checkpoint_payload_root: expected_checkpoint.payload_root,
        checkpoint_state_root: expected_checkpoint.state_root,
        checkpoint_receipts_root: expected_checkpoint.receipts_root,
        checkpoint_evidence_root: expected_checkpoint.evidence_root,
        next_epoch_commitment_hash: expected_checkpoint.commitment_hash,
        checkpoint_finality_proof_id: joint_kernel.checkpoint_finality_proof_id(),
        terminal_old_block_id: joint_kernel.terminal_old_block_id(),
        terminal_old_qc_digest: joint_kernel.terminal_old_qc_digest(),
        handoff_descriptor_digest: joint_kernel.handoff_descriptor_digest(),
        handoff_certificate_digest: joint_kernel.handoff_certificate_digest(),
    };
    let authorization_id = poco_joint_handoff_authorization_id_v0(
        checkpoint_header,
        raw_checkpoint_parent_header_cev0,
        raw_checkpoint_two_seal_finality_cev0,
        raw_anchor_certificate_kernel_cev0,
    )?;

    Ok(AuthorizedPocoJointHandoffV0 {
        checkpoint_header: checkpoint_header.header().clone(),
        checkpoint_parent_header,
        checkpoint_finality,
        anchor_certificate_kernel,
        joint_kernel,
        bound_facts,
        authorization_id,
    })
}

fn poco_joint_handoff_authorization_id_v0(
    checkpoint_header: &AuthorizedPocoCheckpointHeaderV0,
    raw_checkpoint_parent_header_cev0: &[u8],
    raw_checkpoint_two_seal_finality_cev0: &[u8],
    raw_anchor_certificate_kernel_cev0: &[u8],
) -> Result<[u8; 32]> {
    let commitment_authority = checkpoint_header.prepared().commitment_authority();
    let old_set = commitment_authority
        .old_validator_set()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode joint old validator set: {error:?}"))?;
    let new_set = commitment_authority
        .new_validator_set()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode joint new validator set: {error:?}"))?;
    let old_parameters = commitment_authority.old_parameters().canonical_bytes();
    let new_parameters = commitment_authority.new_parameters().canonical_bytes();
    let commitment = commitment_authority
        .commitment()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode joint next-epoch commitment: {error:?}"))?;
    let checkpoint_header_cev0 = checkpoint_header
        .header()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode authorized checkpoint header: {error:?}"))?;
    let checkpoint_header_authorization_id = checkpoint_header.authorization_id();
    let checkpoint_preparation_id = checkpoint_header.prepared().preparation_id();
    let checkpoint_execution_authorization_id = checkpoint_header
        .prepared()
        .native_execution_authorization_id();
    let commitment_authorization_id = commitment_authority.authorization_id();
    let cutoff_authorization_id = commitment_authority.scheduled_cutoff().authorization_id();
    Ok(hash_domain(
        AUTHORIZATION_DOMAIN_V0,
        &[
            &checkpoint_execution_authorization_id,
            &checkpoint_preparation_id,
            &checkpoint_header_authorization_id,
            &commitment_authorization_id,
            &cutoff_authorization_id,
            raw_checkpoint_parent_header_cev0,
            &checkpoint_header_cev0,
            raw_checkpoint_two_seal_finality_cev0,
            &old_set,
            &old_parameters,
            &new_set,
            &new_parameters,
            &commitment,
            raw_anchor_certificate_kernel_cev0,
        ],
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CheckpointBindingV0 {
    height: Height,
    block_id: BlockId,
    payload_root: PayloadDigest,
    state_root: StateRoot,
    receipts_root: ReceiptsRoot,
    evidence_root: EvidenceRoot,
    commitment_hash: NextEpochCommitmentHash,
    old_validator_set_id: ValidatorSetId,
    old_parameters_hash: ConsensusParametersHash,
    new_validator_set_id: ValidatorSetId,
    new_parameters_hash: ConsensusParametersHash,
}

fn ensure_same_checkpoint_binding_v0(
    expected: CheckpointBindingV0,
    observed: CheckpointBindingV0,
) -> Result<()> {
    ensure!(
        expected == observed,
        "checkpoint finality/handoff facts differ from the authorized native checkpoint, roots, commitment, or configuration"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> CheckpointBindingV0 {
        CheckpointBindingV0 {
            height: Height::new(28),
            block_id: BlockId::new([1; 32]),
            payload_root: PayloadDigest::new([2; 32]),
            state_root: StateRoot::new([3; 32]),
            receipts_root: ReceiptsRoot::new([4; 32]),
            evidence_root: EvidenceRoot::new([5; 32]),
            commitment_hash: NextEpochCommitmentHash::new([6; 32]),
            old_validator_set_id: ValidatorSetId::new([7; 32]),
            old_parameters_hash: ConsensusParametersHash::new([8; 32]),
            new_validator_set_id: ValidatorSetId::new([9; 32]),
            new_parameters_hash: ConsensusParametersHash::new([10; 32]),
        }
    }

    #[test]
    fn exact_checkpoint_binding_rejects_native_root_and_configuration_splices() {
        let expected = binding();
        ensure_same_checkpoint_binding_v0(expected, expected).unwrap();

        for observed in [
            CheckpointBindingV0 {
                block_id: BlockId::new([11; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                height: Height::new(29),
                ..expected
            },
            CheckpointBindingV0 {
                payload_root: PayloadDigest::new([12; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                state_root: StateRoot::new([13; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                receipts_root: ReceiptsRoot::new([14; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                evidence_root: EvidenceRoot::new([15; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                commitment_hash: NextEpochCommitmentHash::new([16; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                old_parameters_hash: ConsensusParametersHash::new([17; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                old_validator_set_id: ValidatorSetId::new([19; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                new_validator_set_id: ValidatorSetId::new([18; 32]),
                ..expected
            },
            CheckpointBindingV0 {
                new_parameters_hash: ConsensusParametersHash::new([20; 32]),
                ..expected
            },
        ] {
            ensure_same_checkpoint_binding_v0(expected, observed)
                .expect_err("binding substitution must fail closed");
        }
    }
}
