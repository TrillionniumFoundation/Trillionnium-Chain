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
    decode_finality_proof_v0_exact_with_trusted_genesis_and_budget, BlockId,
    Cev0AdmissionBudgetV0, ConsensusParametersV0, DecodeError, EvidenceRoot, FinalityProofV0,
    Height, ReceiptsRoot, StateRoot, ValidationError, ValidatorSet,
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
}

impl fmt::Display for StrictFinalityErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProofClass => f.write_str("unsupported PoCO finality proof class"),
            Self::TargetMismatch => f.write_str("finality proof does not bind the expected target"),
            Self::ParentMismatch => f.write_str("finality proof does not extend the expected parent"),
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
