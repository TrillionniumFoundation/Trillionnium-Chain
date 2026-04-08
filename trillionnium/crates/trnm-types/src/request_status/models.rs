use serde::{Deserialize, Serialize};

/// Unified request status state-machine for message ingress lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestStatus {
    Open,
    Assigned,
    CommitQueued,
    RevealSubmitted,
    Rejected,
    FailedAdapter,
    FailedSubmission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStateError {
    UnknownState {
        input: String,
    },
    InvalidTransition {
        from: RequestStatus,
        to: RequestStatus,
    },
}

impl RequestStateError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            RequestStateError::UnknownState { .. } => "RequestStateUnknown",
            RequestStateError::InvalidTransition { .. } => "RequestStateInvalidTransition",
        }
    }
}
