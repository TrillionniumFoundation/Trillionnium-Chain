use alloc::boxed::Box;
use core::fmt;

use trnm_consensus_types::{BlockId, Epoch, ValidationError, ValidatorId, View};

pub type Result<T> = core::result::Result<T, CoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    Protocol(ValidationError),
    InvalidConfig(&'static str),
    InvalidRecovery(&'static str),
    LocalValidatorMissing(Box<ValidatorId>),
    WrongEpoch {
        expected: Epoch,
        received: Epoch,
    },
    WrongView {
        expected: View,
        received: View,
    },
    UnexpectedLeader {
        expected: Box<ValidatorId>,
        received: Box<ValidatorId>,
    },
    StaleInput,
    Busy(&'static str),
    UnexpectedStorageAck,
    UnexpectedFinalizationAck,
    UnexpectedSignature,
    SignIdMismatch,
    ConcurrentSignIntent,
    UnknownValidation(BlockId),
    TooManyPendingValidations,
    BlockTooLarge {
        actual: usize,
        maximum: usize,
    },
    ConflictingPayloadValidation(BlockId),
    UnsafeProposal,
    ConflictingCertificate,
    ConflictingBlock(BlockId),
    BlockTreeFull,
    MissingBlock(BlockId),
    ArithmeticOverflow(&'static str),
}

impl From<ValidationError> for CoreError {
    fn from(value: ValidationError) -> Self {
        Self::Protocol(value)
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "protocol validation failed: {error}"),
            Self::InvalidConfig(reason) => write!(formatter, "invalid core config: {reason}"),
            Self::InvalidRecovery(reason) => write!(formatter, "invalid recovery state: {reason}"),
            Self::LocalValidatorMissing(id) => {
                write!(
                    formatter,
                    "local validator {id:?} is absent from the active set"
                )
            }
            Self::WrongEpoch { expected, received } => write!(
                formatter,
                "wrong epoch: expected {}, received {}",
                expected.get(),
                received.get()
            ),
            Self::WrongView { expected, received } => write!(
                formatter,
                "wrong view: expected {}, received {}",
                expected.get(),
                received.get()
            ),
            Self::UnexpectedLeader { expected, received } => write!(
                formatter,
                "unexpected proposer {received:?}; expected leader {expected:?}"
            ),
            Self::StaleInput => formatter.write_str("input is stale"),
            Self::Busy(reason) => write!(formatter, "core is busy: {reason}"),
            Self::UnexpectedStorageAck => formatter.write_str("unexpected storage acknowledgement"),
            Self::UnexpectedFinalizationAck => {
                formatter.write_str("unexpected finalization acknowledgement")
            }
            Self::UnexpectedSignature => formatter.write_str("unexpected signature result"),
            Self::SignIdMismatch => {
                formatter.write_str("signature result id does not match intent")
            }
            Self::ConcurrentSignIntent => formatter.write_str("another sign intent is active"),
            Self::UnknownValidation(block_id) => {
                write!(
                    formatter,
                    "unknown payload validation for block {block_id:?}"
                )
            }
            Self::TooManyPendingValidations => {
                formatter.write_str("too many pending payload validations")
            }
            Self::BlockTooLarge { actual, maximum } => write!(
                formatter,
                "block body is too large: {actual} bytes exceeds {maximum} bytes",
            ),
            Self::ConflictingPayloadValidation(block_id) => write!(
                formatter,
                "payload validation changed for block {block_id:?}",
            ),
            Self::UnsafeProposal => formatter.write_str("proposal violates the safe-vote rule"),
            Self::ConflictingCertificate => {
                formatter.write_str("conflicting certificate at the same monotonic view")
            }
            Self::ConflictingBlock(block_id) => {
                write!(formatter, "conflicting header for block id {block_id:?}")
            }
            Self::BlockTreeFull => formatter.write_str("bounded block tree is full"),
            Self::MissingBlock(block_id) => write!(formatter, "missing block {block_id:?}"),
            Self::ArithmeticOverflow(field) => write!(formatter, "arithmetic overflow in {field}"),
        }
    }
}
