use trnm_consensus_types::{
    verify_same_version_epoch_transition_proof_kernel_v0, BlockId, CertificateId,
    ConsensusParametersV0, Epoch, EpochAnchorAuthorizationKernelV0, FinalityProofV0, Height,
    NextEpochCommitmentV0, SameVersionEpochTransitionKernelError,
    SameVersionEpochTransitionKernelV0, StateRoot, ValidatorSet, View,
};

use crate::StrictEd25519Verifier;

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
