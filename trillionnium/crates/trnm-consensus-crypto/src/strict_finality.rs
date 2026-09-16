//! PCC1's strict, node-independent PoCO finality admission boundary.
//!
//! This module does not select a chain, trust an incoming validator set, execute
//! an application, persist a commit, authorize a signer, or migrate old proofs.
//! Its caller must obtain the set, parameters and expected parent from its own
//! authenticated genesis/checkpoint history. The expectation is a claim to check,
//! never a capability. Only the successful result records strict verification.

use core::fmt;
use trnm_consensus_types::{
    decode_finality_proof_v0_exact_with_budget,
    decode_finality_proof_v0_exact_with_trusted_genesis_and_budget, BlockId, Cev0AdmissionBudgetV0,
    ConsensusParametersV0, DecodeError, EvidenceRoot, FinalityProofV0, Height, ReceiptsRoot,
    StateRoot, ValidationError, ValidatorSet,
};

use crate::{validate_validator_set_strict_ed25519_v0, StrictEd25519Verifier};

/// Local/API dispatch name, not a newly allocated wire-format identifier.
pub const POCO_THREE_CHAIN_PROOF_CLASS_V0: &str = "poco-three-chain-v0";

/// Exact application target and authenticated parent expected by the consumer.
/// Public fields are intentional: these values are untrusted claims, not proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityExpectationV0 {
    pub block_id: BlockId,
    pub height: Height,
    pub state_root: StateRoot,
    pub receipts_root: ReceiptsRoot,
    pub evidence_root: EvidenceRoot,
    pub parent_id: BlockId,
    pub parent_height: Height,
    pub parent_timestamp_ms: u64,
}

/// An immutable strict verification result for exactly one three-chain target.
/// No public constructor, deserializer, Clone implementation, signing API or
/// mutable proof access is provided. It is not a commit or activation token.
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictFinalityProofV0;
/// use trnm_consensus_types::FinalityProofV0;
/// fn forge(proof: FinalityProofV0) -> StrictFinalityProofV0 {
///     StrictFinalityProofV0 { proof }
/// }
/// ```
#[derive(Debug)]
pub struct StrictFinalityProofV0 {
    proof: FinalityProofV0,
}

impl StrictFinalityProofV0 {
    pub const fn proof(&self) -> &FinalityProofV0 {
        &self.proof
    }

    pub fn finalized_block_id(&self) -> BlockId {
        self.proof.finalized_block().header().id()
    }

    pub fn finalized_height(&self) -> Height {
        self.proof.finalized_block().header().height()
    }

    pub fn finalized_state_root(&self) -> StateRoot {
        self.proof.finalized_block().header().state_root()
    }
}

#[derive(Debug)]
pub enum StrictFinalityErrorV0 {
    UnsupportedProofClass,
    TargetMismatch,
    ParentMismatch,
    Decode(DecodeError),
    Consensus(ValidationError),
    EpochEvidence(trnm_consensus_types::EpochActivationEvidenceErrorV0),
    EpochActivation(trnm_consensus_types::JointHandoffKernelError),
}

impl fmt::Display for StrictFinalityErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProofClass => f.write_str("unsupported PoCO finality proof class"),
            Self::TargetMismatch => f.write_str("finality proof does not bind the expected target"),
            Self::ParentMismatch => {
                f.write_str("finality proof does not extend the expected parent")
            }
            Self::EpochEvidence(error) => write!(f, "epoch evidence: {error}"),
            Self::EpochActivation(error) => write!(f, "epoch transition: {error}"),
            Self::Decode(error) => write!(f, "finality proof decode failed: {error}"),
            Self::Consensus(error) => write!(f, "strict finality verification failed: {error}"),
        }
    }
}

/// Decode once, meter once, and strictly verify the complete frozen v0 proof.
///
/// Ordinary same-epoch proofs and the context-authorized epoch-zero genesis
/// case are accepted. Nonzero-epoch anchor/handoff admission continues to use
/// the existing strict epoch-transition boundary; there is no permissive parser
/// fallback here. The caller's budget remains charged after a cryptographic
/// failure, so retrying another decoder cannot refund consumed work.
///
/// Signature checks cover all proposal, QC, optional TC and referenced-QC
/// signatures through the existing v0 verifier. Strict key admission checks
/// every active-set key, not only keys appearing in a particular certificate.
/// The oldest certified header is the finalized target, never the newest QC.
/// Legacy live receipts, ordinary QCs, TCs and arbitrary JSON cannot be relabelled
/// into this result. No signing/hashing bytes or quorum rule are changed.
pub fn decode_verify_finality_proof_strict_v0(
    proof_class: &str,
    bytes: &[u8],
    trusted_validator_set: &ValidatorSet,
    trusted_parameters: &ConsensusParametersV0,
    expected: FinalityExpectationV0,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictFinalityProofV0, StrictFinalityErrorV0> {
    if proof_class != POCO_THREE_CHAIN_PROOF_CLASS_V0 {
        return Err(StrictFinalityErrorV0::UnsupportedProofClass);
    }
    budget
        .admit_root_bytes(bytes.len())
        .map_err(StrictFinalityErrorV0::Decode)?;
    trusted_validator_set
        .validate_against_parameters(trusted_parameters)
        .map_err(StrictFinalityErrorV0::Consensus)?;
    validate_validator_set_strict_ed25519_v0(trusted_validator_set)
        .map_err(StrictFinalityErrorV0::Consensus)?;
    if expected.parent_height.get().checked_add(1) != Some(expected.height.get()) {
        return Err(StrictFinalityErrorV0::ParentMismatch);
    }
    if expected.parent_height.get() == 0
        && (trusted_validator_set.epoch().get() != 0
            || expected.parent_id.as_bytes() != trusted_validator_set.genesis_hash().as_bytes())
    {
        return Err(StrictFinalityErrorV0::ParentMismatch);
    }
    let proof = if trusted_validator_set.epoch().get() == 0 {
        decode_finality_proof_v0_exact_with_trusted_genesis_and_budget(
            bytes,
            trusted_validator_set,
            trusted_parameters,
            expected.parent_timestamp_ms,
            budget,
        )
    } else {
        decode_finality_proof_v0_exact_with_budget(
            bytes,
            trusted_validator_set,
            trusted_parameters,
            expected.parent_timestamp_ms,
            budget,
        )
    }
    .map_err(StrictFinalityErrorV0::Decode)?;
    let header = proof.finalized_block().header();
    if header.id() != expected.block_id
        || header.height() != expected.height
        || header.state_root() != expected.state_root
        || header.receipts_root() != expected.receipts_root
        || header.evidence_root() != expected.evidence_root
    {
        return Err(StrictFinalityErrorV0::TargetMismatch);
    }
    if header.parent_id() != expected.parent_id {
        return Err(StrictFinalityErrorV0::ParentMismatch);
    }
    proof
        .verify(
            trusted_validator_set,
            None,
            trusted_parameters,
            expected.parent_timestamp_ms,
            &StrictEd25519Verifier,
        )
        .map_err(StrictFinalityErrorV0::Consensus)?;
    Ok(StrictFinalityProofV0 { proof })
}

/// Strict first-new-epoch finality together with its authenticated application
/// checkpoint and next context. None of these fields can be selected by a
/// caller after verification; state-sync can join them to its current anchor.
#[derive(Debug)]
pub struct StrictEpochFinalityProofV1 {
    finality: StrictFinalityProofV0,
    checkpoint_header: trnm_consensus_types::BlockHeader,
    new_validator_set: ValidatorSet,
    new_consensus_parameters: ConsensusParametersV0,
}

impl StrictEpochFinalityProofV1 {
    pub const fn proof(&self) -> &FinalityProofV0 {
        self.finality.proof()
    }
    pub fn finalized_block_id(&self) -> BlockId {
        self.finality.finalized_block_id()
    }
    pub const fn checkpoint_header(&self) -> &trnm_consensus_types::BlockHeader {
        &self.checkpoint_header
    }
    pub const fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_validator_set
    }
    pub const fn new_consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_consensus_parameters
    }
    pub fn into_finality(self) -> StrictFinalityProofV0 {
        self.finality
    }
}

/// Strictly verifies exact first-new-epoch finality against an independent old
/// trust context and complete checkpoint/two-seal/joint evidence. This explicit
/// route never retries a rejected ordinary proof with a permissive decoder.
///
/// Skipped views require a complete TC and every referenced QC is verified in
/// the exact new context. Synthetic references must equal this handoff anchor.
/// A successful result proves the first new block, not application installation.
pub fn decode_verify_epoch_first_finality_strict_v1(
    evidence: trnm_consensus_types::EpochActivationEvidencePreimagesV0<'_>,
    bytes: &[u8],
    trusted_old_set: &ValidatorSet,
    trusted_old_parameters: &ConsensusParametersV0,
    expected: FinalityExpectationV0,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictEpochFinalityProofV1, StrictFinalityErrorV0> {
    use trnm_consensus_types::{
        decode_epoch_activation_evidence_v0_exact,
        decode_epoch_first_finality_proof_v1_exact_with_budget,
    };
    let total = [
        evidence.old_checkpoint_finality,
        evidence.next_epoch_commitment,
        evidence.authorization_kernel,
        evidence.old_validator_set,
        evidence.old_consensus_parameters,
        evidence.new_validator_set,
        evidence.new_consensus_parameters,
        evidence.authenticated_checkpoint_parent_header,
        bytes,
    ]
    .iter()
    .try_fold(0usize, |n, part| n.checked_add(part.len()))
    .ok_or(StrictFinalityErrorV0::Consensus(
        ValidationError::ArithmeticOverflow("epoch proof total bytes"),
    ))?;
    budget
        .admit_root_bytes(total)
        .map_err(StrictFinalityErrorV0::Decode)?;
    let decoded = decode_epoch_activation_evidence_v0_exact(
        evidence,
        trusted_old_set,
        trusted_old_parameters,
        budget,
    )
    .map_err(StrictFinalityErrorV0::EpochEvidence)?;
    let proof = decode_epoch_first_finality_proof_v1_exact_with_budget(bytes, &decoded, budget)
        .map_err(StrictFinalityErrorV0::Decode)?;
    let target = proof.finalized_block().header();
    if target.id() != expected.block_id
        || target.height() != expected.height
        || target.state_root() != expected.state_root
        || target.receipts_root() != expected.receipts_root
        || target.evidence_root() != expected.evidence_root
    {
        return Err(StrictFinalityErrorV0::TargetMismatch);
    }
    let parent = decoded.authorization_kernel().terminal_old_header();
    if expected.parent_id != parent.id()
        || expected.parent_height != parent.height()
        || expected.parent_timestamp_ms != parent.timestamp_ms()
        || target.parent_id() != parent.id()
    {
        return Err(StrictFinalityErrorV0::ParentMismatch);
    }
    let activation = crate::verify_same_version_epoch_activation_authority_strict_v0(
        decoded.old_checkpoint_finality(),
        decoded.next_epoch_commitment(),
        decoded.authorization_kernel(),
        decoded.old_validator_set(),
        decoded.old_consensus_parameters(),
        decoded.new_validator_set(),
        decoded.new_consensus_parameters(),
        decoded.authenticated_checkpoint_parent_header(),
    )
    .map_err(StrictFinalityErrorV0::EpochActivation)?;
    verify_epoch_finality_from_activation(&activation, &proof)
        .map_err(StrictFinalityErrorV0::Consensus)?;
    Ok(StrictEpochFinalityProofV1 {
        finality: StrictFinalityProofV0 { proof },
        checkpoint_header: decoded
            .old_checkpoint_finality()
            .finalized_block()
            .header()
            .clone(),
        new_validator_set: decoded.new_validator_set().clone(),
        new_consensus_parameters: *decoded.new_consensus_parameters(),
    })
}

// This path is reachable only after the complete strict handoff verifier above.
// Generic proposal/TC APIs keep rejecting certificate-only epoch authorization.
fn verify_epoch_finality_from_activation(
    activation: &crate::StrictSameVersionEpochActivationAuthorityV0,
    proof: &FinalityProofV0,
) -> Result<(), ValidationError> {
    use trnm_consensus_types::BlockKind;
    let set = activation.new_validator_set();
    proof.validate(
        set,
        Some(activation.old_validator_set()),
        activation.new_consensus_parameters(),
        activation.terminal_old_header().timestamp_ms(),
    )?;
    let first = proof.finalized_block();
    let descriptor = activation.handoff_certificate().descriptor().fields();
    if first.header().block_kind() != BlockKind::EpochHandoff
        || first.header().height() != descriptor.activation_height
        || first.header().parent_id() != descriptor.terminal_old_block_id
        || proof.child().header().block_kind() != BlockKind::Regular
        || proof.grandchild().header().block_kind() != BlockKind::Regular
        || first
            .epoch_anchor_authorization()
            .ok_or(ValidationError::InvalidFinalityProof(
                "first block lacks the verified epoch authorization",
            ))?
            .try_cev0_bytes()?
            != activation.authorization_cev0_bytes()?
    {
        return Err(ValidationError::InvalidFinalityProof(
            "epoch finality context substitution",
        ));
    }
    for certified in [first, proof.child(), proof.grandchild()] {
        certified
            .certifying_qc()
            .verify(set, &StrictEd25519Verifier)?;
        verify_epoch_proposal_witness_strict_v1(
            activation,
            certified.header(),
            certified.witness(),
        )?;
    }
    Ok(())
}

pub(crate) fn verify_epoch_qc_reference(
    activation: &crate::StrictSameVersionEpochActivationAuthorityV0,
    reference: &trnm_consensus_types::QcReferenceV0,
) -> Result<(), ValidationError> {
    use trnm_consensus_types::{ContextAuthorizedQcV0, View};
    let set = activation.new_validator_set();
    if let Some(qc) = reference.as_ordinary() {
        return qc.verify(set, &StrictEd25519Verifier);
    }
    let Some(ContextAuthorizedQcV0::Epoch(anchor)) = reference.as_synthetic() else {
        return Err(ValidationError::InvalidCertificate(
            "foreign synthetic epoch reference",
        ));
    };
    let terminal = activation.terminal_old_header();
    if anchor.genesis_hash() != set.genesis_hash()
        || anchor.chain_id() != set.chain_id()
        || anchor.protocol_version() != set.protocol_version()
        || anchor.epoch() != set.epoch()
        || anchor.validator_set_hash() != set.id()
        || anchor.view() != View::new(0)
        || anchor.height() != terminal.height()
        || anchor.block_id() != terminal.id()
    {
        return Err(ValidationError::InvalidCertificate(
            "epoch reference differs from strict handoff",
        ));
    }
    Ok(())
}

pub(crate) fn verify_epoch_proposal_witness_strict_v1(
    activation: &crate::StrictSameVersionEpochActivationAuthorityV0,
    header: &trnm_consensus_types::BlockHeader,
    witness: &trnm_consensus_types::ProposalWitnessV0,
) -> Result<(), ValidationError> {
    use trnm_consensus_types::{SignatureVerifier, TimeoutVote};
    let set = activation.new_validator_set();
    verify_epoch_qc_reference(activation, witness.justify_qc())?;
    if let Some(tc) = witness.timeout_certificate() {
        tc.validate_shape(set)?;
        for reference in tc.referenced_qcs() {
            verify_epoch_qc_reference(activation, reference)?;
        }
        for entry in tc.entries() {
            let validator = set.validator(entry.signer_id()).ok_or_else(|| {
                ValidationError::UnknownValidator(alloc::boxed::Box::new(entry.signer_id()))
            })?;
            let root =
                TimeoutVote::signing_root_for_set(set, tc.timed_out_view(), entry.high_qc())?;
            if !StrictEd25519Verifier.verify(validator, &root, entry.signature()) {
                return Err(ValidationError::InvalidSignature(alloc::boxed::Box::new(
                    entry.signer_id(),
                )));
            }
        }
    }
    let proposer = set.validator(header.proposer_id()).ok_or_else(|| {
        ValidationError::UnknownValidator(alloc::boxed::Box::new(header.proposer_id()))
    })?;
    let root = witness.signing_root_for_header(header)?;
    if !StrictEd25519Verifier.verify(proposer, &root, witness.proposer_signature()) {
        return Err(ValidationError::InvalidSignature(alloc::boxed::Box::new(
            proposer.id(),
        )));
    }
    Ok(())
}
