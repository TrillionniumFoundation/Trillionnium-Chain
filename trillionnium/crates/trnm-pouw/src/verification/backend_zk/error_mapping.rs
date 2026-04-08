use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationErrorClass {
    Invalid,
    Unavailable,
    BackendError,
    Malformed,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendExecutionError {
    #[error("cryptographic verification backend not configured: {backend}")]
    NotConfigured { backend: String },
    #[error("verification backend '{backend}' rejected proof: {reason}")]
    InvalidProof { backend: String, reason: String },
    #[error("verification backend '{backend}' cannot currently verify proof: {reason}")]
    Unavailable { backend: String, reason: String },
    #[error("verification backend '{backend}' rejected malformed payload: {reason}")]
    MalformedProof { backend: String, reason: String },
    #[error("verification backend '{backend}' failed: {reason}")]
    Internal { backend: String, reason: String },
}

impl BackendExecutionError {
    pub fn error_class(&self) -> VerificationErrorClass {
        match self {
            Self::NotConfigured { .. } | Self::Unavailable { .. } => {
                VerificationErrorClass::Unavailable
            }
            Self::InvalidProof { .. } => VerificationErrorClass::Invalid,
            Self::MalformedProof { .. } => VerificationErrorClass::Malformed,
            Self::Internal { .. } => VerificationErrorClass::BackendError,
        }
    }

    pub fn backend(&self) -> &str {
        match self {
            Self::NotConfigured { backend }
            | Self::InvalidProof { backend, .. }
            | Self::Unavailable { backend, .. }
            | Self::MalformedProof { backend, .. }
            | Self::Internal { backend, .. } => backend,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::NotConfigured { .. } => None,
            Self::InvalidProof { reason, .. }
            | Self::Unavailable { reason, .. }
            | Self::MalformedProof { reason, .. }
            | Self::Internal { reason, .. } => Some(reason),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerificationBackendError {
    #[error(transparent)]
    Selection(#[from] BackendSelectionError),
    #[error(transparent)]
    Execution(#[from] BackendExecutionError),
}
