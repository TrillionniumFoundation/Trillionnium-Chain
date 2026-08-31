use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MvccFeeErrorCodeV1 {
    InvalidContext,
    InvalidBounds,
    NonCanonical,
    IdentifierMismatch,
    InvalidState,
    StaleParent,
    UndeclaredAccess,
    DuplicateAccess,
    InsufficientFunds,
    FeeLimitExceeded,
    ArithmeticOverflow,
    ConservationViolation,
    NotFound,
    StoreFailure,
    SchemaMismatch,
    TamperDetected,
    SidecarPresent,
    CommitUncertain,
    ThirdStateFenced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MvccFeeErrorV1 {
    code: MvccFeeErrorCodeV1,
    message: String,
}

impl MvccFeeErrorV1 {
    pub(crate) fn new(code: MvccFeeErrorCodeV1, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> MvccFeeErrorCodeV1 {
        self.code
    }
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MvccFeeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for MvccFeeErrorV1 {}

impl From<rusqlite::Error> for MvccFeeErrorV1 {
    fn from(value: rusqlite::Error) -> Self {
        Self::new(MvccFeeErrorCodeV1::StoreFailure, value.to_string())
    }
}

pub type MvccFeeResultV1<T> = Result<T, MvccFeeErrorV1>;

pub(crate) fn error(code: MvccFeeErrorCodeV1, message: impl Into<String>) -> MvccFeeErrorV1 {
    MvccFeeErrorV1::new(code, message)
}
