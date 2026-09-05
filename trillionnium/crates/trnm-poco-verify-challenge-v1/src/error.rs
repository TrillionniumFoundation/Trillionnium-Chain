use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyChallengeErrorCodeV1 {
    InvalidContext,
    InvalidBounds,
    NonCanonical,
    IdentifierMismatch,
    InvalidSignature,
    Unauthorized,
    InvalidReceipt,
    InvalidClaim,
    UnderQuorum,
    InvalidState,
    StaleRevision,
    Expired,
    ConservationViolation,
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
pub struct VerifyChallengeErrorV1 {
    code: VerifyChallengeErrorCodeV1,
    message: String,
}

impl VerifyChallengeErrorV1 {
    pub(crate) fn new(code: VerifyChallengeErrorCodeV1, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> VerifyChallengeErrorCodeV1 {
        self.code
    }
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for VerifyChallengeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for VerifyChallengeErrorV1 {}

impl From<rusqlite::Error> for VerifyChallengeErrorV1 {
    fn from(value: rusqlite::Error) -> Self {
        Self::new(VerifyChallengeErrorCodeV1::StoreFailure, value.to_string())
    }
}

pub type VerifyChallengeResultV1<T> = Result<T, VerifyChallengeErrorV1>;

pub(crate) fn error(
    code: VerifyChallengeErrorCodeV1,
    message: impl Into<String>,
) -> VerifyChallengeErrorV1 {
    VerifyChallengeErrorV1::new(code, message)
}
