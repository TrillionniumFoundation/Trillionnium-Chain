//! Versioned research-evidence protocol shared by TRNM, Hepta Research League,
//! and Nakama.
//!
//! The protocol intentionally commits hashes and contribution/accounting
//! metadata only. Raw research content, match event streams, submissions,
//! evaluations, and reproductions remain off-chain.

mod canonical;
mod command;
mod hepta_handoff;
mod pq_hepta_handoff;
mod pq_rollback_witness;
mod state;
mod types;

pub use canonical::{
    canonical_hash, CanonicalCbor, CanonicalDecodeError, Encoder, CANONICAL_ENCODING,
};
pub use command::{AuthorityRole, SignedResearchCommandV1, SignedResearchCommandValidationError};
pub use hepta_handoff::{
    HeptaArtifactAdmissionV1, HeptaHandoffError, SignedHeptaAdmissionV1, HEPTA_HANDOFF_VERSION,
    MAX_HANDOFF_ENVELOPE_BYTES, MAX_HANDOFF_PAYLOAD_BYTES,
};
pub use pq_hepta_handoff::{
    PqHeptaHandoffError, SignedPqHeptaAdmissionV2, MAX_PQ_HEPTA_ENVELOPE_BYTES,
    ML_DSA_65_KEY_BYTES, ML_DSA_65_SIG_BYTES, PQ_HEPTA_HANDOFF_VERSION,
};
pub use pq_rollback_witness::{
    ExternalRecoveryExpectationV1, LocalRecoveryHeadV1, PqRecoveryWitnessError,
    PqRecoveryWitnessStatementV1, SignedPqRecoveryWitnessV1, MAX_PQ_RECOVERY_WITNESS_BYTES,
    PQ_RECOVERY_WITNESS_VERSION,
    PqRecoveryQuorumPolicyV1, PqRecoveryQuorumErrorV1, PqRecoveryTrustedSignerV1,
    ObservedPqRecoveryQuorumV1, verify_pq_recovery_quorum_v1,
    MAX_PQ_RECOVERY_QUORUM_SIGNERS_V1,
};
pub use state::{
    AppliedCommandRecordV1, ApplyOutcome, AuthorityIdentityV1, AuthoritySetV1,
    ClaimChallengeObjectV1, ClaimResolutionObjectV1, EvaluationCommitmentObjectV1,
    LicenseDeclarationObjectV1, MatchEvidenceObjectV1, ProtocolStateError, ResearchClaimObjectV1,
    ResearchProtocolSnapshotV1, ResearchProtocolState, WorkloadReceiptObjectV1,
};
pub use types::{
    ChallengeReason, ChallengeResearchClaimV1, ClaimChallengeStatus, ClaimResolutionDecision,
    ClaimResolutionV1, ClaimShareV1, ClaimStatus, ContributionRole, ContributorWorkV1,
    CreateResearchClaimV1, DeclareLicenseV1, Digest32, EvaluationCommitmentV1, ExternalKey,
    ExternalKeyError, IssueWorkloadReceiptV1, LicenseScope, MatchEvidenceCommitmentV1, ObjectRefV1,
    ResearchCommandDecodeError, ResearchCommandV1, ResearchObjectKind,
    ResearchPayloadValidationError, ResolveResearchClaimV1, PROTOCOL_VERSION,
};
