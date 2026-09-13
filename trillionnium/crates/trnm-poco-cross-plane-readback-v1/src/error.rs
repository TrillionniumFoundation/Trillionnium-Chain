use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossPlaneReadbackErrorCodeV1 {
    InvalidContext,
    InvalidBounds,
    SourceRejected,
    SourceChanged,
    OrderMismatch,
    StoreIdentityConflict,
    LifecycleMismatch,
    DaCertificateMismatch,
    NonCanonical,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossPlaneReadbackErrorV1 {
    code: CrossPlaneReadbackErrorCodeV1,
    message: String,
}

impl CrossPlaneReadbackErrorV1 {
    pub(crate) fn new(code: CrossPlaneReadbackErrorCodeV1, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> CrossPlaneReadbackErrorCodeV1 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CrossPlaneReadbackErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for CrossPlaneReadbackErrorV1 {}

pub type CrossPlaneReadbackResultV1<T> = Result<T, CrossPlaneReadbackErrorV1>;

pub(crate) fn error(
    code: CrossPlaneReadbackErrorCodeV1,
    message: impl Into<String>,
) -> CrossPlaneReadbackErrorV1 {
    CrossPlaneReadbackErrorV1::new(code, message)
}
