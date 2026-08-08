#![no_std]
#![forbid(unsafe_code)]
//! Semantic protocol types for PoCO-BFT v0.
//!
//! This crate deliberately contains no transport, storage, clock, randomness,
//! signing-key, or application-runtime integration. It defines canonical
//! signing roots, fail-closed shape validation, and exact bounded decoding for
//! frozen CEV0 certificate, inert epoch, and ordinary block-commitment
//! kernels. Callers remain responsible for bounded transport-container
//! decoding, authenticated parent state, deterministic runtime execution, and
//! trusted authorization context.

extern crate alloc;

mod anchor;
mod block;
mod body_v0;
mod canonical;
mod certificate;
mod cev0_decode;
mod commit;
mod consumption;
mod context;
mod crypto;
mod cutoff;
mod epoch;
mod error;
mod evidence;
mod finality;
mod handoff;
mod ids;
mod joint_handoff;
mod message;
mod ordered_root;
mod parameters;
mod proposal_v0;
mod snapshot_candidate;
mod timeout_v0;
mod validator;

pub use anchor::{ContextAuthorizedQcV0, EpochAnchorQcV0, GenesisQcV0, QcReferenceV0};
pub use block::{Block, BlockHeader, BlockKind};
pub use body_v0::{
    ApplicationPayloadV0, BlockBodyV0, BlockValidationError, BlockValidationErrorCode,
    BlockValidationResult, DoubleVoteEvidenceV0, ExecutionEventAttributeV0, ExecutionEventV0,
    ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, ValidatedBlockCommitmentsV0,
    ValidatedCheckpointCommitmentsV0, VoteEvidenceRecordV0,
};
pub use canonical::CanonicalSignable;
pub use certificate::{QuorumCertificate, TimeoutCertificate};
pub use cev0_decode::{
    decode_application_payload_v0_exact, decode_application_payload_v0_exact_for_root_binding,
    decode_block_header_v0_exact, decode_checkpoint_finality_proof_v0_exact,
    decode_consensus_parameters_v0_exact, decode_double_vote_evidence_v0_exact,
    decode_epoch_anchor_authorization_kernel_v0_exact,
    decode_execution_receipt_commitment_v0_exact, decode_finality_proof_v0_exact,
    decode_handoff_certificate_v0_exact, decode_handoff_descriptor_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_ordinary_certified_header_v0_exact,
    decode_ordinary_qc_v0_exact, decode_ordinary_timeout_certificate_v0_exact,
    decode_validator_set_v0_exact, DecodeError, DecodeErrorCode, DecodeResult,
    EpochAnchorAuthorizationKernelV0, MAX_CEV0_CERTIFICATE_ITEMS,
    MAX_CEV0_HANDOFF_AGGREGATE_SIGNATURE_SHARES, MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES,
};
#[doc(hidden)]
pub use commit::CommitProof;
pub use consumption::{
    decode_consumption_certificate_v0_exact, ConsumptionCertificateBodyV0,
    ConsumptionCertificateDecodeError, ConsumptionCertificateDecodeErrorCode,
    ConsumptionCertificateV0, MAX_CONSUMPTION_CERTIFICATE_ID_BYTES,
};
pub use context::{CommonConsensusContextV0, MessageKind, SCHEMA_VERSION_V0};
pub use crypto::SignatureVerifier;
pub use cutoff::{verify_finalized_cutoff_header_v0, AuthenticatedFinalizedCutoffHeaderV0};
pub use epoch::{
    EpochFallbackReasonV0, EpochGeometryV0, NextEpochCommitmentV0, NextEpochCommitmentV0Fields,
};
pub use error::{Result, ValidationError};
pub use evidence::EquivocationEvidence;
pub use finality::{CertifiedHeaderV0, CheckpointTwoSealKernelV0, FinalityProofV0};
pub use handoff::{
    EpochAnchorAuthorizationV0, HandoffCertificateV0, HandoffDescriptorV0,
    HandoffDescriptorV0Fields, SignatureShareV0,
};
pub use ids::{
    BlockId, CertificateId, ChainId, ConsensusParametersHash, ConsensusPublicKey, ConsensusString,
    Epoch, EpochTransitionId, EvidenceId, EvidenceRoot, GenesisHash, Height,
    NextEpochCommitmentHash, PayloadDigest, ProtocolVersion, ReceiptsRoot, Signature64,
    SignatureBytes, SigningRoot, StateRoot, UpgradePlanHash, ValidatorId, ValidatorSetId, View,
    VotingPower, MAX_CONSENSUS_STRING_BYTES, MAX_VALIDATOR_ID_BYTES, SIGNATURE_BYTES,
};
pub use joint_handoff::{
    verify_same_version_joint_handoff_kernel_v0, JointHandoffKernelError,
    JointHandoffKernelErrorCode, JointHandoffKernelResult, JointHandoffKernelV0,
};
pub use message::{Proposal, ProposalJustification, QcRef, TimeoutVote, Vote};
pub use ordered_root::{ordered_leaf_digest_v0, OrderedRootV0, RootKind};
pub use parameters::{
    ConsensusParametersV0, ConsensusParametersV0Fields, LeaderSchedule, RolloutPhase,
};
pub use proposal_v0::{ProposalWitnessV0, SignedProposalV0};
pub use snapshot_candidate::{
    compute_candidate_selection_kernel_v0, decode_validator_key_proof_of_possession_v0_exact,
    CandidateComputationV0, CandidateSelectionKernelV0,
    UnauthenticatedCandidateSelectionTranscriptV0, UnauthenticatedSnapshotCandidateV0,
    UnauthenticatedSnapshotContributionV0, ValidatorKeyProofDecodeError,
    ValidatorKeyProofDecodeErrorCode, ValidatorKeyProofOfPossessionV0,
    ValidatorKeyProofOfPossessionV0Fields, MAX_SNAPSHOT_CANDIDATES, MAX_SNAPSHOT_CONTRIBUTIONS,
    MAX_SNAPSHOT_RELATION_ID_BYTES,
};
pub use timeout_v0::{TimeoutCertificateV0, TimeoutEntryV0};
pub use validator::{Validator, ValidatorSet, MAX_VALIDATORS};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod anchor_finality_tests;
