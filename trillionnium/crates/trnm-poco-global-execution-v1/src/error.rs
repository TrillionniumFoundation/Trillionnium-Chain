use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobalExecutionErrorCodeV1 {
    InvalidContext,
    InvalidBounds,
    NonCanonicalBatch,
    DaRejected,
    DaSourceChanged,
    AgentMarketRejected,
    VerifyChallengeRejected,
    MvccFeeRejected,
    ConsumptionSettlementRejected,
    SourceCutMismatch,
    CandidateCompositeRootMismatch,
    CheckpointUnavailable,
    CheckpointTamper,
    CheckpointStale,
    CheckpointRace,
    CheckpointFenced,
    FinalizationOwnerMismatch,
    FinalizationStale,
    FinalizationConflict,
    FinalizationTamper,
    RecoveryMismatch,
    ArithmeticOverflow,
}

#[derive(Debug)]
pub struct GlobalExecutionErrorV1 {
    code: GlobalExecutionErrorCodeV1,
    detail: String,
}

impl GlobalExecutionErrorV1 {
    pub(crate) fn new(code: GlobalExecutionErrorCodeV1, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub const fn code(&self) -> GlobalExecutionErrorCodeV1 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for GlobalExecutionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "global execution checkpoint rejected: {}",
            self.detail
        )
    }
}

impl Error for GlobalExecutionErrorV1 {}

impl From<rusqlite::Error> for GlobalExecutionErrorV1 {
    fn from(cause: rusqlite::Error) -> Self {
        Self::new(
            GlobalExecutionErrorCodeV1::CheckpointUnavailable,
            cause.to_string(),
        )
    }
}

pub type GlobalExecutionResultV1<T> = Result<T, GlobalExecutionErrorV1>;

pub(crate) fn error(
    code: GlobalExecutionErrorCodeV1,
    detail: impl Into<String>,
) -> GlobalExecutionErrorV1 {
    GlobalExecutionErrorV1::new(code, detail)
}
