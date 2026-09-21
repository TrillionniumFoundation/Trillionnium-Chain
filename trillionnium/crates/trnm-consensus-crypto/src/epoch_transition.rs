use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    decode_epoch_activation_evidence_v0_exact, epoch_first_proposal_signing_root_v0,
    validate_checkpoint_parent_header_v0, verify_same_version_epoch_transition_proof_kernel_v0,
    verify_same_version_joint_handoff_kernel_v0, BlockHeader, BlockId, CertificateId,
    Cev0AdmissionBudgetV0, ConsensusParametersV0, DecodedEpochActivationEvidenceV0, Epoch,
    EpochActivationEvidenceBytesV0, EpochActivationEvidenceErrorV0,
    EpochActivationEvidencePreimagesV0, EpochAnchorAuthorizationKernelV0,
    EpochRuntimeContextDataV1, FinalityProofV0, HandoffCertificateV0, Height,
    JointHandoffKernelError, JointHandoffKernelV0, NextEpochCommitmentV0, QuorumCertificate,
    SameVersionEpochTransitionKernelError, SameVersionEpochTransitionKernelV0, Signature64,
    SignatureVerifier, SigningRoot, StateRoot, ValidationError, ValidatorSet, View,
};

use crate::{validate_validator_set_strict_ed25519_v0, StrictEd25519Verifier};

#[path = "epoch_successor_v1.rs"]
mod successor;
pub use successor::{
    decode_verify_successor_epoch_activation_strict_v1,
    recover_successor_epoch_activation_authority_strict_v1, StrictSuccessorEpochActivationErrorV1,
};
pub(crate) use successor::{
    validate_successor_ancestry_links_v1, verify_decoded_successor_epoch_activation_v1,
};

const STRICT_EPOCH_ACTIVATION_BINDING_DOMAIN_V0: &[u8] =
    b"trnm.poco-bft.strict-epoch-activation-binding-ref.v0";

/// Inert evidence reference for one exact, strictly verified epoch activation.
///
/// The digest commits to the complete CEV0 preimages in this fixed order:
/// checkpoint finality, next-epoch commitment, authorization kernel, old
/// validator set, old consensus parameters, new validator set, new consensus
/// parameters, and authenticated checkpoint-parent header.
///
/// This value deliberately has no public raw constructor and is neither
/// `Clone` nor `Copy`. It cannot construct an authority, epoch anchor, signer
/// lease, Core, or recovery capability. A recovery path may persist the raw
/// bytes, but must repeat strict verification under the independently trusted
/// context, including the predecessor for a successor activation, and compare
/// the newly derived reference; stored bytes alone never recreate this type.
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictEpochActivationBindingRefV0;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<StrictEpochActivationBindingRefV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictEpochActivationBindingRefV0;
///
/// let _ = StrictEpochActivationBindingRefV0([0_u8; 32]);
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct StrictEpochActivationBindingRefV0([u8; 32]);

impl StrictEpochActivationBindingRefV0 {
    /// Returns the inert digest bytes for persistence or comparison.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Strict-Ed25519 authority for the exact pre-first-block epoch anchor.
///
/// The private fields bind the complete old checkpoint/two-seal finality
/// proof, the exact next-epoch commitment and old/new validator/parameter
/// preimages, the terminal seal-2 header/QC, both handoff quorums, the exact
/// authenticated checkpoint-parent header, and the exact authorization bytes.
/// Construction repeats complete strict verification through the v0 joint
/// verifier or the predecessor-bound successor path, using
/// [`StrictEd25519Verifier`]. Certificate-only validation cannot construct
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
///     binding_ref: todo!(),
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
    binding_ref: StrictEpochActivationBindingRefV0,
    runtime_data: Box<EpochRuntimeContextDataV1>,
}

impl StrictSameVersionEpochActivationAuthorityV0 {
    pub(crate) const fn runtime_data_v1(&self) -> &EpochRuntimeContextDataV1 {
        &self.runtime_data
    }

    pub(crate) fn canonical_evidence_bytes_v1(
        &self,
    ) -> trnm_consensus_types::Result<EpochActivationEvidenceBytesV0> {
        canonical_evidence_from_parts_v1(
            &self.old_checkpoint_finality,
            &self.next_epoch_commitment,
            &self.authorization_kernel,
            &self.old_validator_set,
            &self.old_consensus_parameters,
            &self.new_validator_set,
            &self.new_consensus_parameters,
            &self.authenticated_checkpoint_parent_header,
        )
    }

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

    /// Returns the inert evidence reference derived from every exact CEV0
    /// preimage owned by this strict authority.
    pub const fn binding_ref(&self) -> &StrictEpochActivationBindingRefV0 {
        &self.binding_ref
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
    let joint_handoff = verify_activation_joint_strict_v0(
        old_checkpoint_finality,
        next_epoch_commitment,
        anchor_certificate_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        authenticated_checkpoint_parent_header,
    )?;
    let encoded = canonical_evidence_from_parts_v1(
        old_checkpoint_finality,
        next_epoch_commitment,
        anchor_certificate_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        authenticated_checkpoint_parent_header,
    )
    .map_err(|_| JointHandoffKernelError::invalid_old_context())?;
    // Derive and retain the complete inert context once. Later runtime
    // construction must not reinterpret contextual evidence through v0.
    let decoded = decode_epoch_activation_evidence_v0_exact(
        encoded.as_preimages(),
        old_validator_set,
        old_consensus_parameters,
        &mut Cev0AdmissionBudgetV0::for_parameters(old_consensus_parameters),
    )
    .map_err(|_| JointHandoffKernelError::invalid_old_context())?;
    strict_authority_from_decoded_v1(&decoded, joint_handoff)
        .map_err(|_| JointHandoffKernelError::invalid_old_context())
}

// Share all strict checks while allowing recovery to reuse its complete
// admitted evidence. Nesting another large raw decoder here exhausts the
// default thread stack on the real Core recovery path.
#[allow(clippy::too_many_arguments)]
fn verify_activation_joint_strict_v0(
    old_checkpoint_finality: &FinalityProofV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    anchor_certificate_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
    authenticated_checkpoint_parent_header: &BlockHeader,
) -> Result<JointHandoffKernelV0, JointHandoffKernelError> {
    // The generic CEV0 constructor intentionally admits algorithm-neutral
    // nonzero key bytes.  This strict activation boundary must reject every
    // invalid/weak key, including a member whose signature is not present in
    // the particular handoff certificate being verified.
    validate_validator_set_strict_ed25519_v0(old_validator_set)
        .map_err(|_| JointHandoffKernelError::invalid_old_context())?;
    validate_validator_set_strict_ed25519_v0(new_validator_set)
        .map_err(|_| JointHandoffKernelError::invalid_new_context())?;
    validate_checkpoint_parent_header_v0(
        old_checkpoint_finality,
        authenticated_checkpoint_parent_header,
    )?;
    verify_same_version_joint_handoff_kernel_v0(
        old_checkpoint_finality,
        next_epoch_commitment,
        anchor_certificate_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        authenticated_checkpoint_parent_header.timestamp_ms(),
        &StrictEd25519Verifier,
    )
}

pub(crate) fn verify_decoded_epoch_activation_strict_v0(
    evidence: &DecodedEpochActivationEvidenceV0,
) -> Result<StrictSameVersionEpochActivationAuthorityV0, JointHandoffKernelError> {
    let joint = verify_activation_joint_strict_v0(
        evidence.old_checkpoint_finality(),
        evidence.next_epoch_commitment(),
        evidence.authorization_kernel(),
        evidence.old_validator_set(),
        evidence.old_consensus_parameters(),
        evidence.new_validator_set(),
        evidence.new_consensus_parameters(),
        evidence.authenticated_checkpoint_parent_header(),
    )?;
    strict_authority_from_decoded_v1(evidence, joint)
        .map_err(|_| JointHandoffKernelError::invalid_old_context())
}

fn strict_authority_from_decoded_v1(
    evidence: &DecodedEpochActivationEvidenceV0,
    joint_handoff: JointHandoffKernelV0,
) -> Result<StrictSameVersionEpochActivationAuthorityV0, ValidationError> {
    let runtime_data = Box::new(EpochRuntimeContextDataV1::from_decoded_evidence_v1(
        evidence,
    )?);
    let binding_ref = strict_epoch_activation_binding_ref_v0(
        evidence.old_checkpoint_finality(),
        evidence.next_epoch_commitment(),
        evidence.authorization_kernel(),
        evidence.old_validator_set(),
        evidence.old_consensus_parameters(),
        evidence.new_validator_set(),
        evidence.new_consensus_parameters(),
        evidence.authenticated_checkpoint_parent_header(),
    );
    Ok(StrictSameVersionEpochActivationAuthorityV0 {
        joint_handoff,
        old_checkpoint_finality: evidence.old_checkpoint_finality().clone(),
        next_epoch_commitment: *evidence.next_epoch_commitment(),
        old_validator_set: evidence.old_validator_set().clone(),
        old_consensus_parameters: *evidence.old_consensus_parameters(),
        new_validator_set: evidence.new_validator_set().clone(),
        new_consensus_parameters: *evidence.new_consensus_parameters(),
        authenticated_checkpoint_parent_header: evidence
            .authenticated_checkpoint_parent_header()
            .clone(),
        authorization_kernel: evidence.authorization_kernel().clone(),
        binding_ref,
        runtime_data,
    })
}

#[allow(clippy::too_many_arguments)]
fn canonical_evidence_from_parts_v1(
    proof: &FinalityProofV0,
    commitment: &NextEpochCommitmentV0,
    kernel: &EpochAnchorAuthorizationKernelV0,
    old_set: &ValidatorSet,
    old_parameters: &ConsensusParametersV0,
    new_set: &ValidatorSet,
    new_parameters: &ConsensusParametersV0,
    parent: &BlockHeader,
) -> trnm_consensus_types::Result<EpochActivationEvidenceBytesV0> {
    Ok(EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: proof.try_cev0_bytes()?,
        next_epoch_commitment: commitment.try_cev0_bytes()?,
        authorization_kernel: kernel.try_cev0_bytes()?,
        old_validator_set: old_set.try_cev0_bytes()?,
        old_consensus_parameters: old_parameters.canonical_bytes(),
        new_validator_set: new_set.try_cev0_bytes()?,
        new_consensus_parameters: new_parameters.canonical_bytes(),
        authenticated_checkpoint_parent_header: parent.try_cev0_bytes()?,
    })
}

#[allow(clippy::too_many_arguments)]
fn strict_epoch_activation_binding_ref_v0(
    old_checkpoint_finality: &FinalityProofV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    authorization_kernel: &EpochAnchorAuthorizationKernelV0,
    old_validator_set: &ValidatorSet,
    old_consensus_parameters: &ConsensusParametersV0,
    new_validator_set: &ValidatorSet,
    new_consensus_parameters: &ConsensusParametersV0,
    authenticated_checkpoint_parent_header: &BlockHeader,
) -> StrictEpochActivationBindingRefV0 {
    let evidence = canonical_evidence_from_parts_v1(
        old_checkpoint_finality,
        next_epoch_commitment,
        authorization_kernel,
        old_validator_set,
        old_consensus_parameters,
        new_validator_set,
        new_consensus_parameters,
        authenticated_checkpoint_parent_header,
    )
    .expect("strictly verified complete evidence has bounded canonical bytes");
    StrictEpochActivationBindingRefV0(strict_epoch_activation_binding_digest_v0([
        &evidence.old_checkpoint_finality,
        &evidence.next_epoch_commitment,
        &evidence.authorization_kernel,
        &evidence.old_validator_set,
        &evidence.old_consensus_parameters,
        &evidence.new_validator_set,
        &evidence.new_consensus_parameters,
        &evidence.authenticated_checkpoint_parent_header,
    ]))
}

/// Failures while rebuilding strict authority from independently persisted
/// canonical preimages. Reserved cryptographic work is not refunded on failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EpochActivationRecoveryErrorV0 {
    ZeroExpectedBinding,
    Evidence(EpochActivationEvidenceErrorV0),
    Verification(JointHandoffKernelError),
    BindingMismatch,
}

impl fmt::Display for EpochActivationRecoveryErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroExpectedBinding => {
                formatter.write_str("epoch recovery expected binding is zero")
            }
            Self::Evidence(error) => write!(formatter, "epoch recovery evidence: {error}"),
            Self::Verification(error) => write!(formatter, "epoch recovery verification: {error}"),
            Self::BindingMismatch => {
                formatter.write_str("epoch recovery exact evidence binding differs")
            }
        }
    }
}

impl core::error::Error for EpochActivationRecoveryErrorV0 {}

/// Rebuilds the complete non-cloneable pre-first-block strict authority from
/// bounded exact nested CEV0 evidence and an independently pinned old context.
///
/// The expected binding must come from the caller's authenticated journal or
/// checkpoint readback. This function proves the exact evidence matches that
/// reference; a caller-supplied digest alone supplies no freshness, rollback,
/// application execution, signer lease, or Core activation authority. No new
/// aggregate protocol encoding or digest is introduced.
///
/// All eight preimages are parsed, their context and checkpoint parent are
/// checked, every old/new role signature is strictly reverified, and the
/// existing complete-preimage binding is recomputed before success. Persisted
/// bytes never deserialize directly into an authority. The returned value
/// owns every verified preimage for the next explicitly authorized consumer.
/// Structural admission reserves the complete signature-work charge before
/// verification starts. A failed signature or final binding check does not
/// refund work already admitted; malformed preimages rejected before that
/// reservation leave the budget unchanged.
pub fn recover_epoch_activation_authority_strict_v0(
    preimages: EpochActivationEvidencePreimagesV0<'_>,
    trusted_old_validator_set: &ValidatorSet,
    trusted_old_consensus_parameters: &ConsensusParametersV0,
    expected_binding: [u8; 32],
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictSameVersionEpochActivationAuthorityV0, EpochActivationRecoveryErrorV0> {
    if expected_binding == [0; 32] {
        return Err(EpochActivationRecoveryErrorV0::ZeroExpectedBinding);
    }
    let evidence = decode_epoch_activation_evidence_v0_exact(
        preimages,
        trusted_old_validator_set,
        trusted_old_consensus_parameters,
        budget,
    )
    .map_err(EpochActivationRecoveryErrorV0::Evidence)?;
    let authority = verify_decoded_epoch_activation_strict_v0(&evidence)
        .map_err(EpochActivationRecoveryErrorV0::Verification)?;
    if authority.binding_ref().as_bytes() != &expected_binding {
        return Err(EpochActivationRecoveryErrorV0::BindingMismatch);
    }
    Ok(authority)
}

fn strict_epoch_activation_binding_digest_v0(preimages: [&[u8]; 8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((STRICT_EPOCH_ACTIVATION_BINDING_DOMAIN_V0.len() as u64).to_be_bytes());
    hasher.update(STRICT_EPOCH_ACTIVATION_BINDING_DOMAIN_V0);
    for preimage in preimages {
        hasher.update((preimage.len() as u64).to_be_bytes());
        hasher.update(preimage);
    }
    hasher.finalize().into()
}

/// Strictly signed view-one first-epoch header, bound to the complete epoch
/// activation evidence. It is not application-Valid, a signer permit, a Core
/// activation receipt, or a proof of first-block finality.
#[derive(Debug, PartialEq, Eq)]
pub struct StrictEpochFirstProposalHeaderV0 {
    activation_binding: [u8; 32],
    header: BlockHeader,
    proposer_signature: Signature64,
    signing_root: SigningRoot,
}
impl StrictEpochFirstProposalHeaderV0 {
    pub const fn activation_binding_v0(&self) -> [u8; 32] {
        self.activation_binding
    }
    pub const fn header_v0(&self) -> &BlockHeader {
        &self.header
    }
    pub const fn proposer_signature_v0(&self) -> &Signature64 {
        &self.proposer_signature
    }
    pub const fn signing_root_v0(&self) -> SigningRoot {
        self.signing_root
    }
}

/// The supplied complete strict authority authorizes only the cryptographic
/// context of this check. No bare anchor is accepted or returned. The caller
/// retains its authority on rejection; a malformed peer header cannot consume
/// a preparation owner. Work is reserved before Ed25519 verification and is
/// not refunded on an invalid signature. View > 1 requires a separate
/// complete TC admission path and is deliberately rejected by this v0 API.
pub fn verify_first_epoch_proposal_header_strict_v0(
    activation: &StrictSameVersionEpochActivationAuthorityV0,
    header: BlockHeader,
    proposer_signature: Signature64,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictEpochFirstProposalHeaderV0, ValidationError> {
    let bytes = header.try_cev0_bytes()?;
    budget.admit_root_bytes(bytes.len()).map_err(|_| {
        ValidationError::InvalidProposal("first epoch header exceeds admission byte limit")
    })?;
    proposer_signature.validate_shape()?;
    let signing_root = epoch_first_proposal_signing_root_v0(
        &header,
        activation.authorization_kernel(),
        activation.old_validator_set(),
        activation.new_validator_set(),
        activation.new_consensus_parameters(),
    )?;
    let proposer = activation
        .new_validator_set()
        .validator(header.proposer_id())
        .ok_or_else(|| {
            ValidationError::UnknownValidator(alloc::boxed::Box::new(header.proposer_id()))
        })?;
    budget.charge_signature_work(1).map_err(|_| {
        ValidationError::InvalidProposal(
            "first epoch header exceeds admission signature-work limit",
        )
    })?;
    if !StrictEd25519Verifier.verify(proposer, &signing_root, &proposer_signature) {
        return Err(ValidationError::InvalidSignature(alloc::boxed::Box::new(
            header.proposer_id(),
        )));
    }
    Ok(StrictEpochFirstProposalHeaderV0 {
        activation_binding: *activation.binding_ref().as_bytes(),
        header,
        proposer_signature,
        signing_root,
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
    // Keep the strict transition wrapper stronger than the generic kernel:
    // all keys in both committed sets must parse, not only signers observed
    // in the supplied finality proof.
    validate_validator_set_strict_ed25519_v0(old_validator_set)
        .map_err(|_| SameVersionEpochTransitionKernelError::invalid_joint_handoff())?;
    validate_validator_set_strict_ed25519_v0(new_validator_set)
        .map_err(|_| SameVersionEpochTransitionKernelError::invalid_new_epoch_finality())?;
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
