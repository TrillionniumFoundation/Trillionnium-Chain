//! Exact loading of the existing pre-first-block epoch evidence roots.
//!
//! This is an inert storage/recovery composition, not a new protocol wire
//! object or digest domain. Decoding neither verifies signatures nor grants
//! epoch-anchor, signing, application, or Core activation authority. A strict
//! consumer must independently authenticate every signature and the source of
//! its expected persisted binding before recovering any live capability.

use alloc::vec::Vec;
use core::fmt;

use crate::{
    decode_block_header_v0_exact, decode_checkpoint_finality_proof_v0_exact_with_budget,
    decode_consensus_parameters_v0_exact, decode_epoch_anchor_authorization_kernel_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact,
    validate_checkpoint_parent_header_v0, BlockHeader, Cev0AdmissionBudgetV0,
    ConsensusParametersV0, DecodeError, EpochAnchorAuthorizationKernelV0, FinalityProofV0,
    JointHandoffKernelError, NextEpochCommitmentV0, ValidationError, ValidatorSet,
};

/// Borrowed, independently encoded CEV0 roots in strict activation-binding order.
///
/// These slices are untrusted evidence, including the embedded old context.
/// Callers must supply the independently trusted old context to the loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochActivationEvidencePreimagesV0<'a> {
    pub old_checkpoint_finality: &'a [u8],
    pub next_epoch_commitment: &'a [u8],
    pub authorization_kernel: &'a [u8],
    pub old_validator_set: &'a [u8],
    pub old_consensus_parameters: &'a [u8],
    pub new_validator_set: &'a [u8],
    pub new_consensus_parameters: &'a [u8],
    pub authenticated_checkpoint_parent_header: &'a [u8],
}

impl<'a> EpochActivationEvidencePreimagesV0<'a> {
    fn components(self) -> [(EpochActivationEvidenceComponentV0, &'a [u8]); 8] {
        use EpochActivationEvidenceComponentV0 as Component;
        [
            (
                Component::OldCheckpointFinality,
                self.old_checkpoint_finality,
            ),
            (Component::NextEpochCommitment, self.next_epoch_commitment),
            (Component::AuthorizationKernel, self.authorization_kernel),
            (Component::OldValidatorSet, self.old_validator_set),
            (
                Component::OldConsensusParameters,
                self.old_consensus_parameters,
            ),
            (Component::NewValidatorSet, self.new_validator_set),
            (
                Component::NewConsensusParameters,
                self.new_consensus_parameters,
            ),
            (
                Component::AuthenticatedCheckpointParentHeader,
                self.authenticated_checkpoint_parent_header,
            ),
        ]
    }
}

/// Owned canonical roots for persistence; these bytes do not preserve authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochActivationEvidenceBytesV0 {
    pub old_checkpoint_finality: Vec<u8>,
    pub next_epoch_commitment: Vec<u8>,
    pub authorization_kernel: Vec<u8>,
    pub old_validator_set: Vec<u8>,
    pub old_consensus_parameters: Vec<u8>,
    pub new_validator_set: Vec<u8>,
    pub new_consensus_parameters: Vec<u8>,
    pub authenticated_checkpoint_parent_header: Vec<u8>,
}

impl EpochActivationEvidenceBytesV0 {
    pub fn as_preimages(&self) -> EpochActivationEvidencePreimagesV0<'_> {
        EpochActivationEvidencePreimagesV0 {
            old_checkpoint_finality: &self.old_checkpoint_finality,
            next_epoch_commitment: &self.next_epoch_commitment,
            authorization_kernel: &self.authorization_kernel,
            old_validator_set: &self.old_validator_set,
            old_consensus_parameters: &self.old_consensus_parameters,
            new_validator_set: &self.new_validator_set,
            new_consensus_parameters: &self.new_consensus_parameters,
            authenticated_checkpoint_parent_header: &self.authenticated_checkpoint_parent_header,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochActivationEvidenceComponentV0 {
    Aggregate,
    OldCheckpointFinality,
    NextEpochCommitment,
    AuthorizationKernel,
    OldValidatorSet,
    OldConsensusParameters,
    NewValidatorSet,
    NewConsensusParameters,
    AuthenticatedCheckpointParentHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochActivationEvidenceErrorV0 {
    Decode {
        component: EpochActivationEvidenceComponentV0,
        error: DecodeError,
    },
    Validation {
        component: EpochActivationEvidenceComponentV0,
        error: ValidationError,
    },
    Context {
        component: EpochActivationEvidenceComponentV0,
        reason: &'static str,
    },
    CheckpointParent {
        error: JointHandoffKernelError,
    },
}

impl fmt::Display for EpochActivationEvidenceErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { component, error } => {
                write!(
                    formatter,
                    "epoch activation evidence {component:?}: {error}"
                )
            }
            Self::Validation { component, error } => {
                write!(
                    formatter,
                    "epoch activation evidence {component:?}: {error}"
                )
            }
            Self::Context { component, reason } => {
                write!(
                    formatter,
                    "epoch activation evidence {component:?}: {reason}"
                )
            }
            Self::CheckpointParent { error } => {
                write!(
                    formatter,
                    "epoch activation checkpoint-parent binding: {error}"
                )
            }
        }
    }
}

impl core::error::Error for EpochActivationEvidenceErrorV0 {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode { error, .. } => Some(error),
            Self::Validation { .. } => None,
            Self::CheckpointParent { error } => Some(error),
            Self::Context { .. } => None,
        }
    }
}

/// Structurally joined evidence with no cryptographic or activation authority.
///
/// Fields are private so successful loading is distinguishable from arbitrary
/// caller-assembled parts. No anchor, live Core, or signing permit is exposed.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedEpochActivationEvidenceV0 {
    old_checkpoint_finality: FinalityProofV0,
    next_epoch_commitment: NextEpochCommitmentV0,
    authorization_kernel: EpochAnchorAuthorizationKernelV0,
    old_validator_set: ValidatorSet,
    old_consensus_parameters: ConsensusParametersV0,
    new_validator_set: ValidatorSet,
    new_consensus_parameters: ConsensusParametersV0,
    authenticated_checkpoint_parent_header: BlockHeader,
}

impl DecodedEpochActivationEvidenceV0 {
    pub const fn old_checkpoint_finality(&self) -> &FinalityProofV0 {
        &self.old_checkpoint_finality
    }

    pub const fn next_epoch_commitment(&self) -> &NextEpochCommitmentV0 {
        &self.next_epoch_commitment
    }

    pub const fn authorization_kernel(&self) -> &EpochAnchorAuthorizationKernelV0 {
        &self.authorization_kernel
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

    /// Re-encodes the eight existing roots without defining an aggregate wire
    /// format. A persisted result must pass decoding and strict verification
    /// again; restoring these bytes alone cannot restore authority.
    pub fn canonical_preimages_v0(&self) -> crate::Result<EpochActivationEvidenceBytesV0> {
        Ok(EpochActivationEvidenceBytesV0 {
            old_checkpoint_finality: self.old_checkpoint_finality.try_cev0_bytes()?,
            next_epoch_commitment: self.next_epoch_commitment.try_cev0_bytes()?,
            authorization_kernel: self.authorization_kernel.try_cev0_bytes()?,
            old_validator_set: self.old_validator_set.try_cev0_bytes()?,
            old_consensus_parameters: self.old_consensus_parameters.canonical_bytes(),
            new_validator_set: self.new_validator_set.try_cev0_bytes()?,
            new_consensus_parameters: self.new_consensus_parameters.canonical_bytes(),
            authenticated_checkpoint_parent_header: self
                .authenticated_checkpoint_parent_header
                .try_cev0_bytes()?,
        })
    }
}

/// Decodes and structurally joins the exact pre-first-block evidence roots.
///
/// The sum of all eight roots must fit the caller's root budget before any
/// decoding allocation. Signature-work charges include the checkpoint proof,
/// the independently supplied terminal QC, and both handoff signer lists.
/// Every failure leaves `budget` unchanged. The committed work charge bounds
/// the later strict verifier; it does not attest that signatures are valid.
pub fn decode_epoch_activation_evidence_v0_exact(
    preimages: EpochActivationEvidencePreimagesV0<'_>,
    trusted_old_set: &ValidatorSet,
    trusted_old_params: &ConsensusParametersV0,
    budget: &mut Cev0AdmissionBudgetV0,
) -> core::result::Result<DecodedEpochActivationEvidenceV0, EpochActivationEvidenceErrorV0> {
    use EpochActivationEvidenceComponentV0 as Component;

    let mut staged_budget = *budget;
    let total_bytes = preimages
        .components()
        .iter()
        .try_fold(0usize, |total, (_, bytes)| {
            total.checked_add(bytes.len()).ok_or_else(|| {
                context_error(Component::Aggregate, "combined evidence length overflow")
            })
        })?;
    staged_budget
        .admit_root_bytes(total_bytes)
        .map_err(|error| decode_error(Component::Aggregate, error))?;

    let old_consensus_parameters =
        decode_consensus_parameters_v0_exact(preimages.old_consensus_parameters)
            .map_err(|error| decode_error(Component::OldConsensusParameters, error))?;
    if &old_consensus_parameters != trusted_old_params {
        return Err(context_error(
            Component::OldConsensusParameters,
            "embedded old parameters differ from the independently trusted preimage",
        ));
    }
    let old_validator_set = decode_validator_set_v0_exact(preimages.old_validator_set)
        .map_err(|error| decode_error(Component::OldValidatorSet, error))?;
    if &old_validator_set != trusted_old_set {
        return Err(context_error(
            Component::OldValidatorSet,
            "embedded old validator set differs from the independently trusted preimage",
        ));
    }
    old_validator_set
        .validate_against_parameters(&old_consensus_parameters)
        .map_err(|error| validation_error(Component::OldValidatorSet, error))?;

    let new_consensus_parameters =
        decode_consensus_parameters_v0_exact(preimages.new_consensus_parameters)
            .map_err(|error| decode_error(Component::NewConsensusParameters, error))?;
    let new_validator_set = decode_validator_set_v0_exact(preimages.new_validator_set)
        .map_err(|error| decode_error(Component::NewValidatorSet, error))?;
    new_validator_set
        .validate_against_parameters(&new_consensus_parameters)
        .map_err(|error| validation_error(Component::NewValidatorSet, error))?;
    let next_epoch_commitment =
        decode_next_epoch_commitment_v0_exact(preimages.next_epoch_commitment)
            .map_err(|error| decode_error(Component::NextEpochCommitment, error))?;
    next_epoch_commitment
        .validate_same_version_context(
            &old_validator_set,
            &old_consensus_parameters,
            &new_validator_set,
            &new_consensus_parameters,
        )
        .map_err(|error| validation_error(Component::NextEpochCommitment, error))?;

    let authenticated_checkpoint_parent_header =
        decode_block_header_v0_exact(preimages.authenticated_checkpoint_parent_header)
            .map_err(|error| decode_error(Component::AuthenticatedCheckpointParentHeader, error))?;
    let old_checkpoint_finality = decode_checkpoint_finality_proof_v0_exact_with_budget(
        preimages.old_checkpoint_finality,
        &old_validator_set,
        &old_consensus_parameters,
        &next_epoch_commitment,
        authenticated_checkpoint_parent_header.timestamp_ms(),
        &mut staged_budget,
    )
    .map_err(|error| decode_error(Component::OldCheckpointFinality, error))?;
    validate_checkpoint_parent_header_v0(
        &old_checkpoint_finality,
        &authenticated_checkpoint_parent_header,
    )
    .map_err(|error| EpochActivationEvidenceErrorV0::CheckpointParent { error })?;

    let authorization_kernel = decode_epoch_anchor_authorization_kernel_v0_exact(
        preimages.authorization_kernel,
        &old_validator_set,
        &new_validator_set,
    )
    .map_err(|error| decode_error(Component::AuthorizationKernel, error))?;
    staged_budget
        .charge_qc(authorization_kernel.terminal_old_qc())
        .map_err(|error| decode_error(Component::AuthorizationKernel, error))?;
    let handoff = authorization_kernel.handoff_certificate();
    staged_budget
        .charge_signature_work(handoff.old_signatures().len())
        .map_err(|error| decode_error(Component::AuthorizationKernel, error))?;
    staged_budget
        .charge_signature_work(handoff.new_signatures().len())
        .map_err(|error| decode_error(Component::AuthorizationKernel, error))?;

    let decoded = DecodedEpochActivationEvidenceV0 {
        old_checkpoint_finality,
        next_epoch_commitment,
        authorization_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        authenticated_checkpoint_parent_header,
    };
    validate_composition(&decoded)?;
    let canonical = decoded
        .canonical_preimages_v0()
        .map_err(|error| validation_error(Component::Aggregate, error))?;
    for ((component, supplied), (_, reencoded)) in preimages
        .components()
        .into_iter()
        .zip(canonical.as_preimages().components())
    {
        if supplied != reencoded {
            return Err(context_error(
                component,
                "evidence root is not its exact canonical preimage",
            ));
        }
    }
    *budget = staged_budget;
    Ok(decoded)
}

fn validate_composition(
    evidence: &DecodedEpochActivationEvidenceV0,
) -> core::result::Result<(), EpochActivationEvidenceErrorV0> {
    use EpochActivationEvidenceComponentV0 as Component;
    let descriptor = evidence
        .authorization_kernel
        .handoff_certificate()
        .descriptor()
        .fields();
    let commitment = evidence.next_epoch_commitment.fields();
    let checkpoint = evidence.old_checkpoint_finality.finalized_block().header();
    let terminal = evidence.old_checkpoint_finality.grandchild();

    if descriptor.genesis_hash != commitment.genesis_hash
        || descriptor.chain_id != commitment.chain_id
        || descriptor.old_epoch != commitment.old_epoch
        || descriptor.new_epoch != commitment.new_epoch
        || descriptor.old_protocol_version != evidence.old_validator_set.protocol_version()
        || descriptor.old_validator_set_hash != evidence.old_validator_set.id()
        || descriptor.old_consensus_parameters_hash != evidence.old_consensus_parameters.hash()
        || descriptor.new_protocol_version != commitment.new_protocol_version
        || descriptor.new_validator_set_hash != commitment.new_validator_set_hash
        || descriptor.new_consensus_parameters_hash != commitment.new_consensus_parameters_hash
        || descriptor.next_epoch_commitment_digest != evidence.next_epoch_commitment.id()
        || descriptor.activation_height != commitment.activation_height
        || descriptor.checkpoint_height != checkpoint.height()
        || descriptor.checkpoint_block_id != checkpoint.id()
        || descriptor.checkpoint_state_root != checkpoint.state_root()
    {
        return Err(context_error(Component::AuthorizationKernel,
            "handoff descriptor does not match the exact checkpoint, commitment, and configurations"));
    }
    if evidence.authorization_kernel.terminal_old_header() != terminal.header()
        || evidence.authorization_kernel.terminal_old_qc() != terminal.certifying_qc()
        || descriptor.terminal_old_height != terminal.header().height()
        || descriptor.terminal_old_block_id != terminal.header().id()
        || descriptor.terminal_old_qc_digest != terminal.certifying_qc().id()
        || descriptor.terminal_old_view != terminal.header().view()
    {
        return Err(context_error(
            Component::AuthorizationKernel,
            "handoff terminal header and QC differ from the exact checkpoint proof seal two",
        ));
    }
    Ok(())
}

const fn decode_error(
    component: EpochActivationEvidenceComponentV0,
    error: DecodeError,
) -> EpochActivationEvidenceErrorV0 {
    EpochActivationEvidenceErrorV0::Decode { component, error }
}

fn validation_error(
    component: EpochActivationEvidenceComponentV0,
    error: ValidationError,
) -> EpochActivationEvidenceErrorV0 {
    EpochActivationEvidenceErrorV0::Validation { component, error }
}

const fn context_error(
    component: EpochActivationEvidenceComponentV0,
    reason: &'static str,
) -> EpochActivationEvidenceErrorV0 {
    EpochActivationEvidenceErrorV0::Context { component, reason }
}

/// Computes the frozen view-one first-proposal signing root without exposing
/// an epoch anchor or upgrading the certificate kernel into authority.
///
/// This is a pure preimage helper, like the handoff-role signing-root helpers.
/// Its structural checks do not authenticate signatures, native execution,
/// durability, or permission to sign. A strict consumer must hold the complete
/// checkpoint/two-seal/configuration authority. Skipped-view TC admission is a
/// separate, unsupported path here; the generic proposal/TC fences remain.
pub fn epoch_first_proposal_signing_root_v0(
    header: &BlockHeader,
    authorization_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
) -> crate::Result<crate::SigningRoot> {
    use crate::proposal_v0::{
        validate_header_set_binding, validate_parameters_binding, validate_scheduled_leader,
        validate_timestamp_step,
    };
    let authorization = crate::EpochAnchorAuthorizationV0::new(
        authorization_kernel.terminal_old_header().clone(),
        authorization_kernel.terminal_old_qc().clone(),
        authorization_kernel.handoff_certificate().clone(),
        old_validator_set,
        new_validator_set,
    )?;
    let descriptor = authorization.handoff_certificate().descriptor().fields();
    header.validate_shape()?;
    if header.block_kind() != crate::BlockKind::EpochHandoff
        || header.view() != crate::View::new(1)
        || header.height() != descriptor.activation_height
        || header.parent_id() != descriptor.terminal_old_block_id
        || header.epoch() != descriptor.new_epoch
        || header.next_epoch_commitment_hash().is_some()
    {
        return Err(ValidationError::InvalidProposal(
            "first epoch proposal is not the exact view-one activation geometry",
        ));
    }
    validate_header_set_binding(header, new_validator_set)?;
    validate_parameters_binding(header, new_validator_set, new_consensus_parameters)?;
    validate_scheduled_leader(header, new_validator_set, new_consensus_parameters)?;
    validate_timestamp_step(
        authorization.terminal_old_header().timestamp_ms(),
        header.timestamp_ms(),
        new_consensus_parameters,
    )?;
    let anchor = crate::QcReferenceV0::epoch_anchor(authorization.epoch_anchor_qc());
    crate::ProposalWitnessV0::signing_root_for(header, &anchor, None, Some(&authorization))
}
