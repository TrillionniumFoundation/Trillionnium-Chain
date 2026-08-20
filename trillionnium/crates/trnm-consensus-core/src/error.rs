use alloc::boxed::Box;
use core::fmt;

use trnm_consensus_types::{BlockId, Epoch, Height, ValidationError, ValidatorId, View};

pub type Result<T> = core::result::Result<T, CoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    Protocol(ValidationError),
    InvalidConfig(&'static str),
    InvalidRecovery(&'static str),
    AuthenticatedGenesisApplicationActivationUnavailable,
    AuthenticatedGenesisApplicationH1OfflineRejected(&'static str),
    StateSyncAnchorRecoveryNotRequired,
    StateSyncAnchorRecoveryRejected(&'static str),
    StateSyncAnchorSuccessorRecoveryUnavailable,
    StateSyncAnchorSuccessorInFlightRecoveryUnavailable {
        revision: u64,
    },
    StateSyncAnchorSuccessorRecoveryRejected(&'static str),
    AnchoredOrdinaryRehydrateRejected(&'static str),
    PayloadValidationRecoveryNotRequired,
    UnsupportedPayloadValidationRecovery {
        obligations: usize,
    },
    UnsupportedPayloadValidationRecoveryState(&'static str),
    PayloadValidationRecoveryRejected,
    NativeValidCompletionRecoveryNotRequired,
    NativeValidCompletionRecoveryRejected(&'static str),
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
    PayloadTerminalFactCacheFull,
    BlockTooLarge {
        actual: usize,
        maximum: usize,
    },
    PayloadValidationResourceTooLarge {
        actual: usize,
        maximum: usize,
    },
    ValidatedProposalRetentionBudgetExceeded {
        retained: usize,
        requested: usize,
        maximum: usize,
    },
    ValidationCapabilityMismatch {
        expected: BlockId,
        received: BlockId,
    },
    ValidPayloadPermitMismatch(BlockId),
    ApplicationSealAuthorityAlreadyIssued,
    ApplicationSealedValidMismatch(BlockId),
    ApplicationValidDeliveryInvariant(&'static str),
    ApplicationFinalizationApplyAuthorityAlreadyIssued,
    ApplicationFinalizationPermitAlreadyIssued,
    ApplicationFinalizationPermitMismatch,
    ApplicationFinalizationReadbackMismatch,
    ApplicationFinalizationReceiptMismatch,
    NativeFinalizationAppliedRecoveryRejected(&'static str),
    ConflictingPayloadValidation(BlockId),
    UnsafeProposal,
    UnsupportedBlockKind,
    EpochBoundaryUnsupported {
        height: Height,
        checkpoint_height: Height,
    },
    UnsupportedEpochAnchor,
    InvalidOrdinaryCertificate,
    ConflictingTcHighQcSyncTarget,
    TooManyPendingStandaloneQcs,
    FinalizationQueueFull,
    ConflictingCertificate,
    ConflictingBlock(BlockId),
    ConflictingProposalWitness(BlockId),
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
            Self::AuthenticatedGenesisApplicationActivationUnavailable => formatter.write_str(
                "authenticated genesis application state requires its dedicated application-registered activation bundle",
            ),
            Self::AuthenticatedGenesisApplicationH1OfflineRejected(reason) => write!(
                formatter,
                "authenticated genesis application h1 offline validation was rejected: {reason}",
            ),
            Self::StateSyncAnchorRecoveryNotRequired => formatter.write_str(
                "state-sync anchor recovery requires the dedicated durable h1 anchor",
            ),
            Self::StateSyncAnchorRecoveryRejected(reason) => {
                write!(formatter, "state-sync anchor recovery was rejected: {reason}")
            }
            Self::StateSyncAnchorSuccessorRecoveryUnavailable => formatter.write_str(
                "state-sync anchored consensus progression requires authenticated successor recovery",
            ),
            Self::StateSyncAnchorSuccessorInFlightRecoveryUnavailable { revision } => write!(
                formatter,
                "state-sync anchored successor revision {revision} has an in-flight payload obligation and cannot be recovered by this protocol",
            ),
            Self::StateSyncAnchorSuccessorRecoveryRejected(reason) => write!(
                formatter,
                "state-sync anchored successor recovery was rejected: {reason}",
            ),
            Self::AnchoredOrdinaryRehydrateRejected(reason) => write!(
                formatter,
                "anchored ordinary replay rehydration was rejected: {reason}",
            ),
            Self::PayloadValidationRecoveryNotRequired => formatter.write_str(
                "payload-validation obligation recovery requires exactly one durable obligation",
            ),
            Self::UnsupportedPayloadValidationRecovery { obligations } => write!(
                formatter,
                "payload-validation obligation recovery does not support {obligations} concurrent obligations",
            ),
            Self::UnsupportedPayloadValidationRecoveryState(reason) => write!(
                formatter,
                "unsupported payload-validation recovery state: {reason}",
            ),
            Self::PayloadValidationRecoveryRejected => formatter.write_str(
                "the trusted host rejected the exact payload-validation recovery challenge",
            ),
            Self::NativeValidCompletionRecoveryNotRequired => formatter.write_str(
                "native Valid completion recovery requires one exact current completion",
            ),
            Self::NativeValidCompletionRecoveryRejected(reason) => write!(
                formatter,
                "native Valid completion recovery was rejected: {reason}",
            ),
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
            Self::PayloadTerminalFactCacheFull => {
                formatter.write_str("durable payload terminal-fact cache has no evictable entry")
            }
            Self::BlockTooLarge { actual, maximum } => write!(
                formatter,
                "block body is too large: {actual} bytes exceeds {maximum} bytes",
            ),
            Self::PayloadValidationResourceTooLarge { actual, maximum } => write!(
                formatter,
                "payload-validation durable resource weight is too large: {actual} bytes exceeds {maximum} bytes",
            ),
            Self::ValidatedProposalRetentionBudgetExceeded {
                retained,
                requested,
                maximum,
            } => write!(
                formatter,
                "validated-proposal retention budget exceeded: {retained} retained bytes plus {requested} requested bytes exceeds {maximum} bytes",
            ),
            Self::ValidationCapabilityMismatch { expected, received } => write!(
                formatter,
                "block-validation capability identifies {received:?}; expected {expected:?}",
            ),
            Self::ValidPayloadPermitMismatch(block_id) => write!(
                formatter,
                "Valid payload permit does not belong to the pending Core slot for {block_id:?}",
            ),
            Self::ApplicationSealAuthorityAlreadyIssued => formatter.write_str(
                "this Core instance already issued its application-store seal authority",
            ),
            Self::ApplicationSealedValidMismatch(block_id) => write!(
                formatter,
                "application-sealed Valid proof does not belong to this Core/store binding for {block_id:?}",
            ),
            Self::ApplicationValidDeliveryInvariant(reason) => write!(
                formatter,
                "Core accepted an application-sealed Valid callback but its delivery invariant failed: {reason}",
            ),
            Self::ApplicationFinalizationApplyAuthorityAlreadyIssued => formatter.write_str(
                "this Core instance already issued its application-finalization apply authority",
            ),
            Self::ApplicationFinalizationPermitAlreadyIssued => formatter.write_str(
                "this Core instance already issued the exact queue-front finalization permit",
            ),
            Self::ApplicationFinalizationPermitMismatch => formatter.write_str(
                "application finalization permit does not belong to this application apply authority",
            ),
            Self::ApplicationFinalizationReadbackMismatch => formatter.write_str(
                "application finalization readback does not exactly bind the queue-front carrier and applied source",
            ),
            Self::ApplicationFinalizationReceiptMismatch => formatter.write_str(
                "application finalization receipt does not belong to this Core, queue front, or apply authority",
            ),
            Self::NativeFinalizationAppliedRecoveryRejected(reason) => write!(
                formatter,
                "native finalization-applied recovery reconciliation was rejected: {reason}",
            ),
            Self::ConflictingPayloadValidation(block_id) => write!(
                formatter,
                "payload validation changed for block {block_id:?}",
            ),
            Self::UnsafeProposal => formatter.write_str("proposal violates the safe-vote rule"),
            Self::UnsupportedBlockKind => formatter
                .write_str("non-regular block kinds are unsupported before epoch transition"),
            Self::EpochBoundaryUnsupported {
                height,
                checkpoint_height,
            } => write!(
                formatter,
                "height {} reaches active epoch checkpoint {}; epoch-transition signing is unsupported",
                height.get(),
                checkpoint_height.get(),
            ),
            Self::UnsupportedEpochAnchor => formatter.write_str(
                "epoch-anchor consensus references are unsupported before epoch transition",
            ),
            Self::InvalidOrdinaryCertificate => formatter.write_str(
                "ordinary certificate must have positive view and height and exact block binding",
            ),
            Self::ConflictingTcHighQcSyncTarget => {
                formatter.write_str("a different TC high-QC sync target is already durable")
            }
            Self::TooManyPendingStandaloneQcs => {
                formatter.write_str("standalone QC sync backlog is full")
            }
            Self::FinalizationQueueFull => {
                formatter.write_str("durable application-finalization queue is full")
            }
            Self::ConflictingCertificate => {
                formatter.write_str("conflicting certificate at the same monotonic view")
            }
            Self::ConflictingBlock(block_id) => {
                write!(formatter, "conflicting header for block id {block_id:?}")
            }
            Self::ConflictingProposalWitness(block_id) => write!(
                formatter,
                "a different signed proposal witness is already fixed for block {block_id:?}",
            ),
            Self::BlockTreeFull => formatter.write_str("bounded block tree is full"),
            Self::MissingBlock(block_id) => write!(formatter, "missing block {block_id:?}"),
            Self::ArithmeticOverflow(field) => write!(formatter, "arithmetic overflow in {field}"),
        }
    }
}
