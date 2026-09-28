use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentMarketErrorCodeV1 {
    InvalidContext,
    InvalidBounds,
    NonCanonical,
    IdentifierMismatch,
    InvalidSignature,
    Unauthorized,
    InvalidCapability,
    InvalidSession,
    InvalidNonceLane,
    NonceReplay,
    NonceGap,
    BudgetExceeded,
    RateExceeded,
    InvalidState,
    StaleVersion,
    ConservationViolation,
    InsufficientFunds,
    Expired,
    Conflict,
    NotFound,
    ArithmeticOverflow,
    StoreFailure,
    SchemaMismatch,
    TamperDetected,
    SidecarPresent,
    CommitUncertain,
    ThirdStateFenced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentMarketErrorV1 {
    code: AgentMarketErrorCodeV1,
    message: String,
}

impl AgentMarketErrorV1 {
    pub(crate) fn new(code: AgentMarketErrorCodeV1, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> AgentMarketErrorCodeV1 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AgentMarketErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for AgentMarketErrorV1 {}

impl From<rusqlite::Error> for AgentMarketErrorV1 {
    fn from(error: rusqlite::Error) -> Self {
        Self::new(AgentMarketErrorCodeV1::StoreFailure, error.to_string())
    }
}

pub type AgentMarketResultV1<T> = Result<T, AgentMarketErrorV1>;

pub(crate) fn error(
    code: AgentMarketErrorCodeV1,
    message: impl Into<String>,
) -> AgentMarketErrorV1 {
    AgentMarketErrorV1::new(code, message)
}
