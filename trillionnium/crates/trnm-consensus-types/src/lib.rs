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
mod genesis_application;
mod handoff;
mod handoff_sign_intent;
mod ids;
mod joint_handoff;
mod message;
mod ordered_root;
mod parameters;
mod proposal_v0;
mod recovery;
mod snapshot_candidate;
mod timeout_v0;
mod validator;

pub use anchor::{ContextAuthorizedQcV0, EpochAnchorQcV0, GenesisQcV0, QcReferenceV0};
pub use block::{Block, BlockHeader, BlockKind};
pub use body_v0::{
    validate_root_bound_regular_body_v0, ApplicationPayloadV0, BlockBodyV0, BlockValidationError,
    BlockValidationErrorCode, BlockValidationResult, DoubleVoteEvidenceV0,
    ExecutionEventAttributeV0, ExecutionEventV0, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0,
    RootBoundRegularBodyV0, ValidatedBlockCommitmentsV0, ValidatedCheckpointCommitmentsV0,
    VoteEvidenceRecordV0,
};
pub use canonical::CanonicalSignable;
pub use certificate::{QuorumCertificate, TimeoutCertificate};
pub use cev0_decode::{
    decode_application_payload_v0_exact, decode_application_payload_v0_exact_for_root_binding,
    decode_block_header_v0_exact, decode_canonical_handoff_sign_intent_v1_exact,
    decode_canonical_sign_intent_v0_exact, decode_certified_header_v0_exact_with_trusted_genesis,
    decode_checkpoint_finality_proof_v0_exact, decode_consensus_parameters_v0_exact,
    decode_double_vote_evidence_v0_exact, decode_epoch_anchor_authorization_kernel_v0_exact,
    decode_execution_receipt_commitment_v0_exact, decode_finality_proof_v0_exact,
    decode_finality_proof_v0_exact_with_trusted_genesis, decode_handoff_certificate_v0_exact,
    decode_handoff_descriptor_v0_exact, decode_next_epoch_commitment_v0_exact,
    decode_ordinary_certified_header_v0_exact, decode_ordinary_qc_v0_exact,
    decode_ordinary_qc_v0_exact_with_budget, decode_ordinary_timeout_certificate_v0_exact,
    decode_ordinary_timeout_certificate_v0_exact_with_budget, decode_poco_genesis_v1_exact,
    decode_qc_reference_v0_exact_with_trusted_genesis,
    decode_qc_reference_v0_exact_with_trusted_genesis_and_budget,
    decode_timeout_certificate_v0_exact_with_trusted_genesis,
    decode_timeout_certificate_v0_exact_with_trusted_genesis_and_budget,
    decode_validator_set_v0_exact, Cev0AdmissionBudgetV0, DecodeError, DecodeErrorCode,
    DecodeResult, EpochAnchorAuthorizationKernelV0, MAX_CEV0_AUTHENTICATED_TC_SIGNATURE_SHARES_V0,
    MAX_CEV0_CANONICAL_HANDOFF_SIGN_INTENT_BYTES_V1, MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES,
    MAX_CEV0_CERTIFICATE_ITEMS, MAX_CEV0_HANDOFF_AGGREGATE_SIGNATURE_SHARES,
    MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0, MAX_CEV0_ROOT_BYTES_V0,
    MAX_CEV0_SIGNATURE_WORK_UNITS_V0, MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES,
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
pub use genesis_application::{
    GenesisApplicationCommitmentV0, GenesisQcApplicationBindingV0, PocoGenesisQcBindingV1,
    PocoGenesisV1, GENESIS_APPLICATION_COMMITMENT_BINDING_DOMAIN_V0,
    GENESIS_APPLICATION_COMMITMENT_SCHEMA_VERSION_V0, GENESIS_QC_APPLICATION_BINDING_DOMAIN_V0,
    MAX_POCO_GENESIS_CANONICAL_BYTES_V1, POCO_GENESIS_COMMITMENT_DOMAIN_V1,
    POCO_GENESIS_QC_BINDING_DOMAIN_V1, POCO_GENESIS_SCHEMA_VERSION_V1,
};
pub use handoff::{
    EpochAnchorAuthorizationV0, HandoffCertificateV0, HandoffDescriptorV0,
    HandoffDescriptorV0Fields, SignatureShareV0,
};
pub use handoff_sign_intent::{
    CanonicalHandoffSignIntentV1, CanonicalHandoffSignPreimageV1, HandoffSignIntentFingerprintV1,
    HandoffSignerRoleV1, CANONICAL_HANDOFF_SIGN_INTENT_SCHEMA_VERSION_V1,
    HANDOFF_SIGNER_PROFILE_V1,
};
pub use ids::{
    BlockId, CertificateId, ChainId, ConsensusParametersHash, ConsensusPublicKey, ConsensusString,
    Epoch, EpochTransitionId, EvidenceId, EvidenceRoot, GenesisHash, Height,
    NextEpochCommitmentHash, PayloadDigest, ProtocolVersion, ReceiptsRoot, Signature64,
    SignatureBytes, SigningRoot, StateRoot, UpgradePlanHash, ValidatorId, ValidatorSetId, View,
    VotingPower, MAX_CONSENSUS_STRING_BYTES, MAX_VALIDATOR_ID_BYTES, SIGNATURE_BYTES,
};
pub use joint_handoff::{
    validate_checkpoint_parent_header_v0, verify_same_version_epoch_transition_proof_kernel_v0,
    verify_same_version_joint_handoff_kernel_v0, JointHandoffKernelError,
    JointHandoffKernelErrorCode, JointHandoffKernelResult, JointHandoffKernelV0,
    SameVersionEpochTransitionKernelError, SameVersionEpochTransitionKernelErrorCode,
    SameVersionEpochTransitionKernelResult, SameVersionEpochTransitionKernelV0,
};
pub use message::{
    CanonicalSignIntentV0, CanonicalSignPreimageV0, Proposal, ProposalJustification, QcRef,
    SignIntentFingerprintV0, TimeoutVote, TimeoutVoteSignPreimageV0, Vote, VoteSignPreimageV0,
    CANONICAL_SIGN_INTENT_SCHEMA_VERSION_V0,
};
pub use ordered_root::{ordered_leaf_digest_v0, OrderedRootV0, RootKind};
pub use parameters::{
    ConsensusParametersV0, ConsensusParametersV0Fields, LeaderSchedule, RolloutPhase,
};
pub use proposal_v0::{ProposalWitnessV0, SignedProposalV0};
pub use recovery::{
    decode_recovery_caught_up_cut_v1_exact, decode_recovery_context_v1_exact,
    decode_recovery_ready_set_v1_exact, decode_recovery_start_certificate_v1_exact,
    decode_recovery_zero_delta_cut_v1_exact, decode_signed_recovery_ready_v1_exact,
    decode_signed_recovery_start_v1_exact, RecoveryCaughtUpCutV1, RecoveryCaughtUpCutV1Fields,
    RecoveryContextV1, RecoveryContextV1Fields, RecoveryErrorV1, RecoveryModeV1,
    RecoveryReadySetV1, RecoveryResultV1, RecoveryStartCertificateV1, RecoveryZeroDeltaCutV1,
    RecoveryZeroDeltaCutV1Fields, SignedRecoveryReadyV1, SignedRecoveryStartV1,
    DIRECT7_RECOVERY_VALIDATOR_COUNT_V1, MAX_RECOVERY_CAUGHT_UP_CUT_BYTES_V1,
    MAX_RECOVERY_CONTEXT_BYTES_V1, MAX_RECOVERY_READY_SET_BYTES_V1,
    MAX_RECOVERY_START_CERTIFICATE_BYTES_V1, MAX_RECOVERY_ZERO_DELTA_CUT_BYTES_V1,
    MAX_SIGNED_RECOVERY_READY_BYTES_V1, MAX_SIGNED_RECOVERY_START_BYTES_V1,
    RECOVERY_PROCESS_INSTANCE_V1, RECOVERY_SCHEMA_VERSION_V1,
};
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
