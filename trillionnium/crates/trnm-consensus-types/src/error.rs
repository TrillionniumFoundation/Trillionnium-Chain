use alloc::boxed::Box;
use core::fmt;

use crate::ValidatorId;

pub type Result<T> = core::result::Result<T, ValidationError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    InvalidProtocolVersion,
    InvalidSchemaVersion {
        actual: u16,
        expected: u16,
    },
    MessageKindMismatch {
        actual: u8,
        expected: u8,
    },
    ZeroGenesisHash,
    GenesisHashMismatch,
    ConsensusContextMismatch,
    ConsensusParametersMismatch,
    ArithmeticOverflow(&'static str),
    LengthOverflow {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    InvalidConsensusString,
    EmptyValidatorId,
    ValidatorIdTooLong {
        actual: usize,
        maximum: usize,
    },
    EmptySignature,
    InvalidSignatureLength {
        actual: usize,
        expected: usize,
    },
    EmptyValidatorSet,
    TooManyValidators {
        actual: usize,
        maximum: usize,
    },
    ZeroValidatorId,
    ZeroConsensusPublicKey,
    ZeroVotingPower,
    DuplicateValidatorId(Box<ValidatorId>),
    DuplicateConsensusPublicKey,
    NonCanonicalValidatorOrder,
    ValidatorSetIdMismatch,
    ChainIdMismatch,
    ProtocolVersionMismatch,
    EpochMismatch,
    ViewMismatch,
    HeightMismatch,
    ValidatorSetMismatch,
    ParentBlockMismatch,
    PayloadDigestMismatch,
    TransitionMismatch,
    CertificateMismatch,
    UnknownValidator(Box<ValidatorId>),
    DuplicateSigner(Box<ValidatorId>),
    NonCanonicalSignerOrder,
    NonCanonicalQcOrder,
    ConflictingSameViewQc,
    InsufficientQuorum {
        signed: u128,
        required: u128,
    },
    InvalidSignature(Box<ValidatorId>),
    InvalidBlock(&'static str),
    InvalidProposal(&'static str),
    InvalidCertificate(&'static str),
    InvalidEpochTransition(&'static str),
    InvalidJointCertificate(&'static str),
    InvalidEvidence(&'static str),
    InvalidCommitProof(&'static str),
    InvalidFinalityProof(&'static str),
    InvalidValidatorSet(&'static str),
    InvalidConsensusParameters(&'static str),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocolVersion => formatter.write_str("unsupported protocol version"),
            Self::InvalidSchemaVersion { actual, expected } => {
                write!(
                    formatter,
                    "schema version {actual} does not equal {expected}"
                )
            }
            Self::MessageKindMismatch { actual, expected } => {
                write!(formatter, "message kind {actual} does not equal {expected}")
            }
            Self::ZeroGenesisHash => formatter.write_str("genesis hash must not be zero"),
            Self::GenesisHashMismatch => formatter.write_str("genesis hash mismatch"),
            Self::ConsensusContextMismatch => formatter.write_str("consensus context mismatch"),
            Self::ConsensusParametersMismatch => {
                formatter.write_str("consensus parameters hash mismatch")
            }
            Self::ArithmeticOverflow(field) => write!(formatter, "arithmetic overflow in {field}"),
            Self::LengthOverflow {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "{field} length {actual} exceeds canonical maximum {maximum}"
            ),
            Self::InvalidConsensusString => formatter.write_str("invalid consensus string"),
            Self::EmptyValidatorId => formatter.write_str("validator id must not be empty"),
            Self::ValidatorIdTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "validator id length {actual} exceeds maximum {maximum}"
                )
            }
            Self::EmptySignature => formatter.write_str("signature must not be empty"),
            Self::InvalidSignatureLength { actual, expected } => {
                write!(
                    formatter,
                    "signature length {actual} does not equal required length {expected}"
                )
            }
            Self::EmptyValidatorSet => formatter.write_str("validator set must not be empty"),
            Self::TooManyValidators { actual, maximum } => {
                write!(
                    formatter,
                    "validator count {actual} exceeds maximum {maximum}"
                )
            }
            Self::ZeroValidatorId => formatter.write_str("validator id must not be zero"),
            Self::ZeroConsensusPublicKey => {
                formatter.write_str("consensus public key must not be zero")
            }
            Self::ZeroVotingPower => formatter.write_str("voting power must be positive"),
            Self::DuplicateValidatorId(id) => write!(formatter, "duplicate validator id {id:?}"),
            Self::DuplicateConsensusPublicKey => {
                formatter.write_str("duplicate consensus public key")
            }
            Self::NonCanonicalValidatorOrder => {
                formatter.write_str("validator set is not in canonical order")
            }
            Self::ValidatorSetIdMismatch => formatter.write_str("validator set id mismatch"),
            Self::ChainIdMismatch => formatter.write_str("chain id mismatch"),
            Self::ProtocolVersionMismatch => formatter.write_str("protocol version mismatch"),
            Self::EpochMismatch => formatter.write_str("epoch mismatch"),
            Self::ViewMismatch => formatter.write_str("view mismatch"),
            Self::HeightMismatch => formatter.write_str("height mismatch"),
            Self::ValidatorSetMismatch => formatter.write_str("validator set mismatch"),
            Self::ParentBlockMismatch => formatter.write_str("parent block mismatch"),
            Self::PayloadDigestMismatch => formatter.write_str("payload digest mismatch"),
            Self::TransitionMismatch => formatter.write_str("epoch transition mismatch"),
            Self::CertificateMismatch => formatter.write_str("certificate mismatch"),
            Self::UnknownValidator(id) => write!(formatter, "unknown validator {id:?}"),
            Self::DuplicateSigner(id) => write!(formatter, "duplicate signer {id:?}"),
            Self::NonCanonicalSignerOrder => {
                formatter.write_str("certificate signers are not in canonical order")
            }
            Self::NonCanonicalQcOrder => {
                formatter.write_str("referenced QCs are not in canonical digest order")
            }
            Self::ConflictingSameViewQc => formatter.write_str("conflicting same-view QCs"),
            Self::InsufficientQuorum { signed, required } => {
                write!(
                    formatter,
                    "insufficient quorum power: {signed} < {required}"
                )
            }
            Self::InvalidSignature(id) => write!(formatter, "invalid signature by {id:?}"),
            Self::InvalidBlock(reason) => write!(formatter, "invalid block: {reason}"),
            Self::InvalidProposal(reason) => write!(formatter, "invalid proposal: {reason}"),
            Self::InvalidCertificate(reason) => write!(formatter, "invalid certificate: {reason}"),
            Self::InvalidEpochTransition(reason) => {
                write!(formatter, "invalid epoch transition: {reason}")
            }
            Self::InvalidJointCertificate(reason) => {
                write!(formatter, "invalid joint certificate: {reason}")
            }
            Self::InvalidEvidence(reason) => write!(formatter, "invalid evidence: {reason}"),
            Self::InvalidCommitProof(reason) => write!(formatter, "invalid commit proof: {reason}"),
            Self::InvalidFinalityProof(reason) => {
                write!(formatter, "invalid finality proof: {reason}")
            }
            Self::InvalidValidatorSet(reason) => {
                write!(formatter, "invalid validator set: {reason}")
            }
            Self::InvalidConsensusParameters(reason) => {
                write!(formatter, "invalid consensus parameters: {reason}")
            }
        }
    }
}
