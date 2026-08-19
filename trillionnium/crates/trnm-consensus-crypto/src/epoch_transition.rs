use alloc::vec::Vec;

use trnm_consensus_types::{
    validate_checkpoint_parent_header_v0, verify_same_version_epoch_transition_proof_kernel_v0,
    verify_same_version_joint_handoff_kernel_v0, BlockHeader, BlockId, CertificateId,
    ConsensusParametersV0, Epoch, EpochAnchorAuthorizationKernelV0, FinalityProofV0,
    HandoffCertificateV0, Height, JointHandoffKernelError, JointHandoffKernelV0,
    NextEpochCommitmentV0, QuorumCertificate, SameVersionEpochTransitionKernelError,
    SameVersionEpochTransitionKernelV0, StateRoot, ValidatorSet, View,
};

use crate::StrictEd25519Verifier;

/// Strict-Ed25519 authority for the exact pre-first-block epoch anchor.
///
/// The private fields bind the complete old checkpoint/two-seal finality
/// proof, the exact next-epoch commitment and old/new validator/parameter
/// preimages, the terminal seal-2 header/QC, both handoff quorums, the exact
/// authenticated checkpoint-parent header, and the exact authorization bytes.
/// Construction re-runs [`verify_same_version_joint_handoff_kernel_v0`] with
/// [`StrictEd25519Verifier`]; certificate-only validation cannot construct
/// this value.
///
/// No `EpochAnchorQcV0` or `QcReferenceV0` is released from this boundary.
/// Future proposal admission must consume this complete authority directly;
/// the generic-verifier structural token remains permanently inert.
///
/// This is cryptographic pre-first-block authority only. It neither grants a
/// signer lease nor mutates Core, SafetyState, timers, ingress, application
/// state, or durable epoch state. Those later boundaries remain fail closed.
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<StrictSameVersionEpochActivationAuthorityV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0;
///
/// fn cannot_release_bare_anchor(authority: StrictSameVersionEpochActivationAuthorityV0) {
///     let _ = authority.epoch_anchor_qc();
/// }
/// ```
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0;
///
/// let _ = StrictSameVersionEpochActivationAuthorityV0 {
///     joint_handoff: todo!(),
///     old_checkpoint_finality: todo!(),
///     next_epoch_commitment: todo!(),
///     old_validator_set: todo!(),
///     old_consensus_parameters: todo!(),
///     new_validator_set: todo!(),
///     new_consensus_parameters: todo!(),
///     authenticated_checkpoint_parent_header: todo!(),
///     authorization_kernel: todo!(),
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct StrictSameVersionEpochActivationAuthorityV0 {
    joint_handoff: JointHandoffKernelV0,
    old_checkpoint_finality: FinalityProofV0,
    next_epoch_commitment: NextEpochCommitmentV0,
    old_validator_set: ValidatorSet,
    old_consensus_parameters: ConsensusParametersV0,
    new_validator_set: ValidatorSet,
    new_consensus_parameters: ConsensusParametersV0,
    authenticated_checkpoint_parent_header: BlockHeader,
    authorization_kernel: EpochAnchorAuthorizationKernelV0,
}

impl StrictSameVersionEpochActivationAuthorityV0 {
    pub const fn joint_handoff(&self) -> &JointHandoffKernelV0 {
        &self.joint_handoff
    }

    pub const fn old_checkpoint_finality(&self) -> &FinalityProofV0 {
        &self.old_checkpoint_finality
    }

    pub const fn next_epoch_commitment(&self) -> &NextEpochCommitmentV0 {
        &self.next_epoch_commitment
    }

    pub const fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_validator_set
    }

    pub const fn old_consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.old_consensus_parameters
    }

    pub const fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_validator_set
    }

    pub const fn new_consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_consensus_parameters
    }

    pub const fn authenticated_checkpoint_parent_header(&self) -> &BlockHeader {
        &self.authenticated_checkpoint_parent_header
    }

    pub fn authenticated_checkpoint_parent_block_id(&self) -> BlockId {
        self.authenticated_checkpoint_parent_header.id()
    }

    pub const fn authenticated_checkpoint_parent_timestamp_ms(&self) -> u64 {
        self.authenticated_checkpoint_parent_header.timestamp_ms()
    }

    pub const fn authorization_kernel(&self) -> &EpochAnchorAuthorizationKernelV0 {
        &self.authorization_kernel
    }

    pub fn authorization_cev0_bytes(&self) -> trnm_consensus_types::Result<Vec<u8>> {
        self.authorization_kernel.try_cev0_bytes()
    }

    pub const fn terminal_old_header(&self) -> &BlockHeader {
        self.authorization_kernel.terminal_old_header()
    }

    pub const fn terminal_old_qc(&self) -> &QuorumCertificate {
        self.authorization_kernel.terminal_old_qc()
    }

    pub const fn handoff_certificate(&self) -> &HandoffCertificateV0 {
        self.authorization_kernel.handoff_certificate()
    }
}

/// Verifies and binds the complete v0 -> v0 pre-first-block authorization
/// using strict RFC-8032 Ed25519 verification for the old checkpoint/two-seal
/// QCs, terminal old QC, and both old/new handoff roles.
///
/// The returned private-field authority owns the exact verified preimages.
/// It does not activate Core or signing and does not verify any first-new-epoch
/// proposal; those operations remain outside this commit boundary.
#[allow(clippy::too_many_arguments)]
pub fn verify_same_version_epoch_activation_authority_strict_v0(
    old_checkpoint_finality: &FinalityProofV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    anchor_certificate_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
    authenticated_checkpoint_parent_header: &BlockHeader,
) -> Result<StrictSameVersionEpochActivationAuthorityV0, JointHandoffKernelError> {
    validate_checkpoint_parent_header_v0(
        old_checkpoint_finality,
        authenticated_checkpoint_parent_header,
    )?;
    let joint_handoff = verify_same_version_joint_handoff_kernel_v0(
        old_checkpoint_finality,
        next_epoch_commitment,
        anchor_certificate_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        authenticated_checkpoint_parent_header.timestamp_ms(),
        &StrictEd25519Verifier,
    )?;

    Ok(StrictSameVersionEpochActivationAuthorityV0 {
        joint_handoff,
        old_checkpoint_finality: old_checkpoint_finality.clone(),
        next_epoch_commitment: *next_epoch_commitment,
        old_validator_set: old_validator_set.clone(),
        old_consensus_parameters: *old_consensus_parameters,
        new_validator_set: new_validator_set.clone(),
        new_consensus_parameters: *new_consensus_parameters,
        authenticated_checkpoint_parent_header: authenticated_checkpoint_parent_header.clone(),
        authorization_kernel: anchor_certificate_kernel.clone(),
    })
}

/// Strict-Ed25519 observation of one bounded same-version epoch transition.
///
/// Private fields and the absence of `Clone`/`Copy` prevent callers from
/// fabricating or casually duplicating this observation.  It remains inert:
/// it cannot construct a Core, mutate SafetyState, authorize a signature, or
/// activate the new epoch.
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictSameVersionEpochTransitionV0;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<StrictSameVersionEpochTransitionV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictSameVersionEpochTransitionV0;
///
/// let _ = StrictSameVersionEpochTransitionV0 { kernel: todo!() };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct StrictSameVersionEpochTransitionV0 {
    kernel: SameVersionEpochTransitionKernelV0,
}

impl StrictSameVersionEpochTransitionV0 {
    pub const fn old_epoch(&self) -> Epoch {
        self.kernel.joint_handoff().old_epoch()
    }

    pub const fn new_epoch(&self) -> Epoch {
        self.kernel.joint_handoff().new_epoch()
    }

    pub const fn old_checkpoint_finality_proof_id(&self) -> CertificateId {
        self.kernel.joint_handoff().checkpoint_finality_proof_id()
    }

    pub const fn handoff_certificate_digest(&self) -> CertificateId {
        self.kernel.joint_handoff().handoff_certificate_digest()
    }

    pub const fn terminal_old_block_id(&self) -> BlockId {
        self.kernel.joint_handoff().terminal_old_block_id()
    }

    pub const fn terminal_old_height(&self) -> Height {
        self.kernel.joint_handoff().terminal_old_height()
    }

    pub const fn first_new_epoch_finality_proof_id(&self) -> CertificateId {
        self.kernel.first_new_epoch_finality_proof_id()
    }

    pub const fn first_new_epoch_block_id(&self) -> BlockId {
        self.kernel.first_new_epoch_block_id()
    }

    pub const fn first_new_epoch_height(&self) -> Height {
        self.kernel.first_new_epoch_height()
    }

    pub const fn first_new_epoch_state_root(&self) -> StateRoot {
        self.kernel.first_new_epoch_state_root()
    }

    pub const fn observed_new_epoch_tip_block_id(&self) -> BlockId {
        self.kernel.observed_new_epoch_tip_block_id()
    }

    pub const fn observed_new_epoch_tip_height(&self) -> Height {
        self.kernel.observed_new_epoch_tip_height()
    }

    pub const fn observed_new_epoch_tip_view(&self) -> View {
        self.kernel.observed_new_epoch_tip_view()
    }
}

/// Verifies one exact next-view-only v0 -> v0 transition using strict
/// RFC-8032 Ed25519 verification for every old-finality, handoff-role, and
/// first-new-epoch signature.
///
/// Success returns observation facts only.  The function does not admit the
/// first handoff proposal into generic Core and never emits signing or
/// persistence authority.
#[allow(clippy::too_many_arguments)]
pub fn verify_same_version_epoch_transition_strict_v0(
    old_checkpoint_finality: &FinalityProofV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    anchor_certificate_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
    authenticated_checkpoint_parent_timestamp_ms: u64,
    first_new_epoch_finality: &FinalityProofV0,
) -> Result<StrictSameVersionEpochTransitionV0, SameVersionEpochTransitionKernelError> {
    let kernel = verify_same_version_epoch_transition_proof_kernel_v0(
        old_checkpoint_finality,
        next_epoch_commitment,
        anchor_certificate_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        authenticated_checkpoint_parent_timestamp_ms,
        first_new_epoch_finality,
        &StrictEd25519Verifier,
    )?;
    Ok(StrictSameVersionEpochTransitionV0 { kernel })
}
