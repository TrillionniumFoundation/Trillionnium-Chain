//! Read-only laboratory proof observation for one frozen-v0 epoch handoff.
//!
//! This module deliberately joins an already committed last-pre-checkpoint
//! laboratory runtime to a separately verified checkpoint/two-seal, dual
//! quorum, and first-new-epoch three-chain proof.  It does not execute the
//! checkpoint locally and does not activate a new generic Core or signer
//! namespace.  Success is therefore evidence observation, not transition
//! authority.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};
use trnm_consensus_crypto::{
    verify_same_version_epoch_transition_strict_v0, StrictSameVersionEpochTransitionV0,
};
use trnm_consensus_signer_journal::ExternalMonotonicWatermarkV0;
use trnm_consensus_types::{
    BlockId, CertificateId, ConsensusParametersV0, Epoch, EpochAnchorAuthorizationKernelV0,
    EpochGeometryV0, FinalityProofV0, Height, NextEpochCommitmentV0,
    SameVersionEpochTransitionKernelError, StateRoot, ValidatorSet, View,
};

use crate::{lab_authority::PocoNodeLabAuthorityErrorV0, PocoNodeLabOrdinaryProposalRuntimeV0};

const OBSERVATION_DOMAIN_V0: &[u8] = b"trnm.poco-node.lab.epoch-transition-observation.v0";

/// One non-forgeable laboratory observation of a same-version epoch proof.
///
/// Private fields and the absence of `Clone`/`Copy` prevent external
/// construction or casual duplication.  The value has no conversion to Core,
/// Safety, signer, or network authority.
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeLabVerifiedEpochTransitionObservationV0;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<PocoNodeLabVerifiedEpochTransitionObservationV0>();
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::PocoNodeLabVerifiedEpochTransitionObservationV0;
///
/// let _ = PocoNodeLabVerifiedEpochTransitionObservationV0 {
///     observation_checksum: [0; 32],
///     ..todo!()
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct PocoNodeLabVerifiedEpochTransitionObservationV0 {
    local_checkpoint_generation: u64,
    local_checkpoint_checksum: [u8; 32],
    committed_parent_block_id: BlockId,
    committed_parent_height: Height,
    committed_parent_state_root: StateRoot,
    committed_parent_view: View,
    committed_parent_timestamp_ms: u64,
    old_epoch: Epoch,
    new_epoch: Epoch,
    old_checkpoint_finality_proof_id: CertificateId,
    handoff_certificate_digest: CertificateId,
    first_new_epoch_finality_proof_id: CertificateId,
    terminal_old_block_id: BlockId,
    terminal_old_height: Height,
    first_new_epoch_block_id: BlockId,
    first_new_epoch_height: Height,
    first_new_epoch_state_root: StateRoot,
    observed_new_epoch_tip_block_id: BlockId,
    observed_new_epoch_tip_height: Height,
    observed_new_epoch_tip_view: View,
    observation_checksum: [u8; 32],
}

impl PocoNodeLabVerifiedEpochTransitionObservationV0 {
    pub const fn local_checkpoint_generation_v0(&self) -> u64 {
        self.local_checkpoint_generation
    }

    pub const fn local_checkpoint_checksum_v0(&self) -> [u8; 32] {
        self.local_checkpoint_checksum
    }

    pub const fn committed_parent_block_id_v0(&self) -> BlockId {
        self.committed_parent_block_id
    }

    pub const fn committed_parent_height_v0(&self) -> Height {
        self.committed_parent_height
    }

    pub const fn committed_parent_state_root_v0(&self) -> StateRoot {
        self.committed_parent_state_root
    }

    pub const fn committed_parent_view_v0(&self) -> View {
        self.committed_parent_view
    }

    pub const fn committed_parent_timestamp_ms_v0(&self) -> u64 {
        self.committed_parent_timestamp_ms
    }

    pub const fn old_epoch_v0(&self) -> Epoch {
        self.old_epoch
    }

    pub const fn new_epoch_v0(&self) -> Epoch {
        self.new_epoch
    }

    pub const fn old_checkpoint_finality_proof_id_v0(&self) -> CertificateId {
        self.old_checkpoint_finality_proof_id
    }

    pub const fn handoff_certificate_digest_v0(&self) -> CertificateId {
        self.handoff_certificate_digest
    }

    pub const fn first_new_epoch_finality_proof_id_v0(&self) -> CertificateId {
        self.first_new_epoch_finality_proof_id
    }

    pub const fn terminal_old_block_id_v0(&self) -> BlockId {
        self.terminal_old_block_id
    }

    pub const fn terminal_old_height_v0(&self) -> Height {
        self.terminal_old_height
    }

    pub const fn first_new_epoch_block_id_v0(&self) -> BlockId {
        self.first_new_epoch_block_id
    }

    pub const fn first_new_epoch_height_v0(&self) -> Height {
        self.first_new_epoch_height
    }

    pub const fn first_new_epoch_state_root_v0(&self) -> StateRoot {
        self.first_new_epoch_state_root
    }

    pub const fn observed_new_epoch_tip_block_id_v0(&self) -> BlockId {
        self.observed_new_epoch_tip_block_id
    }

    pub const fn observed_new_epoch_tip_height_v0(&self) -> Height {
        self.observed_new_epoch_tip_height
    }

    pub const fn observed_new_epoch_tip_view_v0(&self) -> View {
        self.observed_new_epoch_tip_view
    }

    pub const fn observation_checksum_v0(&self) -> [u8; 32] {
        self.observation_checksum
    }
}

#[derive(Debug)]
pub enum PocoNodeLabEpochTransitionObservationErrorV0 {
    Runtime(PocoNodeLabAuthorityErrorV0),
    InvalidLocalContext(&'static str),
    InvalidTransition(SameVersionEpochTransitionKernelError),
}

impl fmt::Display for PocoNodeLabEpochTransitionObservationErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "laboratory runtime error: {error}"),
            Self::InvalidLocalContext(message) => {
                write!(
                    formatter,
                    "invalid local epoch-observation context: {message}"
                )
            }
            Self::InvalidTransition(error) => write!(formatter, "invalid epoch proof: {error}"),
        }
    }
}

impl Error for PocoNodeLabEpochTransitionObservationErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::InvalidTransition(error) => Some(error),
            Self::InvalidLocalContext(_) => None,
        }
    }
}

/// Joins one live, fully committed last-pre-checkpoint laboratory cut to an
/// exact strict-Ed25519 same-version transition proof.
///
/// The authenticated parent timestamp is taken from the live application/Core
/// join rather than from the caller.  A fresh whole-node checkpoint readback
/// must equal the runtime-retained checkpoint before proof verification.
/// Generic Core admission remains fail-closed at the epoch boundary.
#[allow(clippy::too_many_arguments)]
pub fn verify_poco_node_lab_same_version_epoch_transition_v0<W: ExternalMonotonicWatermarkV0>(
    runtime: &mut PocoNodeLabOrdinaryProposalRuntimeV0<W>,
    old_checkpoint_finality: &FinalityProofV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    anchor_certificate_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
    first_new_epoch_finality: &FinalityProofV0,
) -> Result<
    PocoNodeLabVerifiedEpochTransitionObservationV0,
    PocoNodeLabEpochTransitionObservationErrorV0,
> {
    let (live_set, live_parameters) = runtime.consensus_context_for_epoch_observation_v0();
    if live_set != old_validator_set || live_parameters != old_consensus_parameters {
        return Err(
            PocoNodeLabEpochTransitionObservationErrorV0::InvalidLocalContext(
                "live Core validator/parameter context differs from the old proof context",
            ),
        );
    }
    let geometry = EpochGeometryV0::new(old_validator_set.epoch(), old_consensus_parameters)
        .map_err(|_| {
            PocoNodeLabEpochTransitionObservationErrorV0::InvalidLocalContext(
                "old epoch geometry is invalid",
            )
        })?;
    let expected_parent_height = geometry.last_pre_checkpoint_height().map_err(|_| {
        PocoNodeLabEpochTransitionObservationErrorV0::InvalidLocalContext(
            "last pre-checkpoint height is invalid",
        )
    })?;
    let facts = runtime.facts_v0();
    let parent = runtime
        .proposal_parent_v0()
        .map_err(PocoNodeLabEpochTransitionObservationErrorV0::Runtime)?;
    let fresh_checkpoint = runtime
        .fresh_checkpoint_for_epoch_observation_v0()
        .map_err(PocoNodeLabEpochTransitionObservationErrorV0::Runtime)?;
    let checkpoint_fields = fresh_checkpoint.fields();
    let checkpoint_header = old_checkpoint_finality.finalized_block().header();
    let parent_head = parent.application_head_v0();
    let expected_parent_block_id = checkpoint_header.parent_id();
    let expected_parent_block_bytes = expected_parent_block_id.as_bytes();

    if checkpoint_header.height() != geometry.checkpoint_height()
        || facts.finalized_height_v0() != expected_parent_height.get()
        || facts.application_applied_height_v0() != expected_parent_height.get()
        || facts.proposal_parent_height_v0() != expected_parent_height.get()
        || parent_head.height().get() != expected_parent_height.get()
        || facts.finalized_block_id_v0() != expected_parent_block_id
        || facts.application_applied_block_id_v0() != expected_parent_block_id
        || facts.proposal_parent_block_id_v0() != expected_parent_block_id
        || parent_head.block_id().as_bytes() != expected_parent_block_bytes
        || checkpoint_fields.application_block_id != expected_parent_block_id
        || checkpoint_fields.application_height != expected_parent_height.get()
        || checkpoint_fields.application_state_root.as_bytes()
            != parent_head.state_root().as_bytes()
        || checkpoint_fields.application_view != facts.finalized_view_v0().get()
        || checkpoint_fields.application_timestamp_ms
            != parent.authenticated_parent_timestamp_ms_v0()
        || facts.checkpoint_v0() != fresh_checkpoint
    {
        return Err(
            PocoNodeLabEpochTransitionObservationErrorV0::InvalidLocalContext(
                "live Core/App/checkpoint cut differs from the proof checkpoint parent",
            ),
        );
    }

    let strict = verify_same_version_epoch_transition_strict_v0(
        old_checkpoint_finality,
        next_epoch_commitment,
        anchor_certificate_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        parent.authenticated_parent_timestamp_ms_v0(),
        first_new_epoch_finality,
    )
    .map_err(PocoNodeLabEpochTransitionObservationErrorV0::InvalidTransition)?;

    Ok(observation_v0(
        &strict,
        fresh_checkpoint.generation(),
        fresh_checkpoint.checkpoint_checksum(),
        expected_parent_block_id,
        expected_parent_height,
        checkpoint_fields.application_state_root,
        facts.finalized_view_v0(),
        checkpoint_fields.application_timestamp_ms,
    ))
}

#[allow(clippy::too_many_arguments)]
fn observation_v0(
    strict: &StrictSameVersionEpochTransitionV0,
    local_checkpoint_generation: u64,
    local_checkpoint_checksum: [u8; 32],
    committed_parent_block_id: BlockId,
    committed_parent_height: Height,
    committed_parent_state_root: StateRoot,
    committed_parent_view: View,
    committed_parent_timestamp_ms: u64,
) -> PocoNodeLabVerifiedEpochTransitionObservationV0 {
    let mut observation = PocoNodeLabVerifiedEpochTransitionObservationV0 {
        local_checkpoint_generation,
        local_checkpoint_checksum,
        committed_parent_block_id,
        committed_parent_height,
        committed_parent_state_root,
        committed_parent_view,
        committed_parent_timestamp_ms,
        old_epoch: strict.old_epoch(),
        new_epoch: strict.new_epoch(),
        old_checkpoint_finality_proof_id: strict.old_checkpoint_finality_proof_id(),
        handoff_certificate_digest: strict.handoff_certificate_digest(),
        first_new_epoch_finality_proof_id: strict.first_new_epoch_finality_proof_id(),
        terminal_old_block_id: strict.terminal_old_block_id(),
        terminal_old_height: strict.terminal_old_height(),
        first_new_epoch_block_id: strict.first_new_epoch_block_id(),
        first_new_epoch_height: strict.first_new_epoch_height(),
        first_new_epoch_state_root: strict.first_new_epoch_state_root(),
        observed_new_epoch_tip_block_id: strict.observed_new_epoch_tip_block_id(),
        observed_new_epoch_tip_height: strict.observed_new_epoch_tip_height(),
        observed_new_epoch_tip_view: strict.observed_new_epoch_tip_view(),
        observation_checksum: [0; 32],
    };
    observation.observation_checksum = observation_checksum_v0(&observation);
    observation
}

fn observation_checksum_v0(
    observation: &PocoNodeLabVerifiedEpochTransitionObservationV0,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OBSERVATION_DOMAIN_V0);
    hasher.update(observation.local_checkpoint_generation.to_be_bytes());
    hasher.update(observation.local_checkpoint_checksum);
    hasher.update(observation.committed_parent_block_id.as_bytes());
    hasher.update(observation.committed_parent_height.get().to_be_bytes());
    hasher.update(observation.committed_parent_state_root.as_bytes());
    hasher.update(observation.committed_parent_view.get().to_be_bytes());
    hasher.update(observation.committed_parent_timestamp_ms.to_be_bytes());
    hasher.update(observation.old_epoch.get().to_be_bytes());
    hasher.update(observation.new_epoch.get().to_be_bytes());
    hasher.update(observation.old_checkpoint_finality_proof_id.as_bytes());
    hasher.update(observation.handoff_certificate_digest.as_bytes());
    hasher.update(observation.first_new_epoch_finality_proof_id.as_bytes());
    hasher.update(observation.terminal_old_block_id.as_bytes());
    hasher.update(observation.terminal_old_height.get().to_be_bytes());
    hasher.update(observation.first_new_epoch_block_id.as_bytes());
    hasher.update(observation.first_new_epoch_height.get().to_be_bytes());
    hasher.update(observation.first_new_epoch_state_root.as_bytes());
    hasher.update(observation.observed_new_epoch_tip_block_id.as_bytes());
    hasher.update(
        observation
            .observed_new_epoch_tip_height
            .get()
            .to_be_bytes(),
    );
    hasher.update(observation.observed_new_epoch_tip_view.get().to_be_bytes());
    hasher.finalize().into()
}
