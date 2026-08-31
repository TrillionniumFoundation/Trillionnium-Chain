use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumptionSettlementErrorCodeV1 {
    InvalidContext,
    InvalidBounds,
    NonCanonical,
    IdentifierMismatch,
    InvalidSignature,
    Unauthorized,
    StaleVersion,
    InvalidTransition,
    SequenceGap,
    RootMismatch,
    ArithmeticOverflow,
    ConservationViolation,
    InsufficientFunds,
    NotMature,
    AlreadyConsumed,
    Conflict,
    NotFound,
    StoreFailure,
    SchemaMismatch,
    TamperDetected,
    SidecarPresent,
    CommitUncertain,
    ThirdStateFenced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumptionSettlementErrorV1 {
    code: ConsumptionSettlementErrorCodeV1,
    message: String,
}

impl ConsumptionSettlementErrorV1 {
    pub(crate) fn new(code: ConsumptionSettlementErrorCodeV1, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> ConsumptionSettlementErrorCodeV1 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ConsumptionSettlementErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for ConsumptionSettlementErrorV1 {}

impl From<rusqlite::Error> for ConsumptionSettlementErrorV1 {
    fn from(value: rusqlite::Error) -> Self {
        Self::new(
            ConsumptionSettlementErrorCodeV1::StoreFailure,
            value.to_string(),
        )
    }
}

pub type ConsumptionSettlementResultV1<T> = Result<T, ConsumptionSettlementErrorV1>;

pub(crate) fn error(
    code: ConsumptionSettlementErrorCodeV1,
    message: impl Into<String>,
) -> ConsumptionSettlementErrorV1 {
    ConsumptionSettlementErrorV1::new(code, message)
}
