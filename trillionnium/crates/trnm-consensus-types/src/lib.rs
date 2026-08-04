#![no_std]
#![forbid(unsafe_code)]
//! Semantic protocol types for PoCO-BFT v0.
//!
//! This crate deliberately contains no transport, storage, clock, randomness,
//! signing-key, or application-runtime integration. It defines canonical
//! signing roots and fail-closed shape validation; callers remain responsible
//! for decoding bounded wire messages before constructing these values.

extern crate alloc;

mod anchor;
mod block;
mod canonical;
mod certificate;
mod commit;
mod context;
mod crypto;
mod error;
mod evidence;
mod finality;
mod handoff;
mod ids;
mod message;
mod parameters;
mod proposal_v0;
mod timeout_v0;
mod validator;

pub use anchor::{ContextAuthorizedQcV0, EpochAnchorQcV0, GenesisQcV0, QcReferenceV0};
pub use block::{Block, BlockHeader, BlockKind};
pub use canonical::CanonicalSignable;
pub use certificate::{QuorumCertificate, TimeoutCertificate};
#[doc(hidden)]
pub use commit::CommitProof;
pub use context::{CommonConsensusContextV0, MessageKind, SCHEMA_VERSION_V0};
pub use crypto::SignatureVerifier;
pub use error::{Result, ValidationError};
pub use evidence::EquivocationEvidence;
pub use finality::{CertifiedHeaderV0, FinalityProofV0};
pub use handoff::{
    EpochAnchorAuthorizationV0, HandoffCertificateV0, HandoffDescriptorV0,
    HandoffDescriptorV0Fields, SignatureShareV0,
};
pub use ids::{
    BlockId, CertificateId, ChainId, ConsensusParametersHash, ConsensusPublicKey, ConsensusString,
    Epoch, EpochTransitionId, EvidenceRoot, GenesisHash, Height, NextEpochCommitmentHash,
    PayloadDigest, ProtocolVersion, ReceiptsRoot, Signature64, SignatureBytes, SigningRoot,
    StateRoot, ValidatorId, ValidatorSetId, View, VotingPower, MAX_CONSENSUS_STRING_BYTES,
    MAX_VALIDATOR_ID_BYTES, SIGNATURE_BYTES,
};
pub use message::{Proposal, ProposalJustification, QcRef, TimeoutVote, Vote};
pub use parameters::{
    ConsensusParametersV0, ConsensusParametersV0Fields, LeaderSchedule, RolloutPhase,
};
pub use proposal_v0::{ProposalWitnessV0, SignedProposalV0};
pub use timeout_v0::{TimeoutCertificateV0, TimeoutEntryV0};
pub use validator::{Validator, ValidatorSet, MAX_VALIDATORS};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod anchor_finality_tests;
