use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaErrorCodeV1 {
    InvalidContext,
    UnsupportedNamespace,
    InvalidBounds,
    NonCanonical,
    IdentifierMismatch,
    InvalidSignature,
    InvalidCommittee,
    InsufficientWeight,
    UnauthorizedAuthor,
    SequenceConflict,
    QuotaExceeded,
    QueueFull,
    StoreFailure,
    SchemaMismatch,
    TamperDetected,
    Conflict,
    NotFound,
    InvalidState,
    RetentionViolation,
    EarlyGarbageCollection,
    InvalidRepair,
    InvalidRange,
    InvalidWithholdingEvidence,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaErrorV1 {
    code: DaErrorCodeV1,
    message: String,
}

impl DaErrorV1 {
    pub(crate) fn new(code: DaErrorCodeV1, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> DaErrorCodeV1 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DaErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for DaErrorV1 {}

impl From<rusqlite::Error> for DaErrorV1 {
    fn from(error: rusqlite::Error) -> Self {
        Self::new(DaErrorCodeV1::StoreFailure, error.to_string())
    }
}

pub type DaResultV1<T> = Result<T, DaErrorV1>;

pub(crate) fn error(code: DaErrorCodeV1, message: impl Into<String>) -> DaErrorV1 {
    DaErrorV1::new(code, message)
}
