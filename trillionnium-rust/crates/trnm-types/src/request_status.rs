use serde::{Deserialize, Serialize};
use std::fmt;

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

impl RequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestStatus::Open => "OPEN",
            RequestStatus::Assigned => "ASSIGNED",
            RequestStatus::CommitQueued => "COMMIT_QUEUED",
            RequestStatus::RevealSubmitted => "REVEAL_SUBMITTED",
            RequestStatus::Rejected => "REJECTED",
            RequestStatus::FailedAdapter => "FAILED_ADAPTER",
            RequestStatus::FailedSubmission => "FAILED_SUBMISSION",
        }
    }

    pub fn parse(s: &str) -> Result<Self, RequestStateError> {
        match s {
            "OPEN" => Ok(RequestStatus::Open),
            "ASSIGNED" => Ok(RequestStatus::Assigned),
            "COMMIT_QUEUED" => Ok(RequestStatus::CommitQueued),
            "REVEAL_SUBMITTED" => Ok(RequestStatus::RevealSubmitted),
            "REJECTED" => Ok(RequestStatus::Rejected),
            "FAILED_ADAPTER" => Ok(RequestStatus::FailedAdapter),
            "FAILED_SUBMISSION" => Ok(RequestStatus::FailedSubmission),
            other => Err(RequestStateError::UnknownState {
                input: other.to_string(),
            }),
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            RequestStatus::RevealSubmitted
                | RequestStatus::Rejected
                | RequestStatus::FailedAdapter
                | RequestStatus::FailedSubmission
        )
    }

    /// Idempotent same-state transition is allowed. Non-idempotent transitions are strictly guarded.
    pub fn can_transition_to(self, to: Self) -> bool {
        if self == to {
            return true;
        }
        matches!(
            (self, to),
            (RequestStatus::Open, RequestStatus::Assigned)
                | (RequestStatus::Assigned, RequestStatus::CommitQueued)
                | (RequestStatus::Assigned, RequestStatus::Rejected)
                | (RequestStatus::Assigned, RequestStatus::FailedAdapter)
                | (RequestStatus::CommitQueued, RequestStatus::RevealSubmitted)
                | (RequestStatus::CommitQueued, RequestStatus::Rejected)
                | (RequestStatus::CommitQueued, RequestStatus::FailedSubmission)
        )
    }

    pub fn transition(self, to: Self) -> Result<Self, RequestStateError> {
        if self.can_transition_to(to) {
            return Ok(to);
        }
        Err(RequestStateError::InvalidTransition { from: self, to })
    }
}

impl fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStateError {
    UnknownState { input: String },
    InvalidTransition { from: RequestStatus, to: RequestStatus },
}

impl RequestStateError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            RequestStateError::UnknownState { .. } => "RequestStateUnknown",
            RequestStateError::InvalidTransition { .. } => "RequestStateInvalidTransition",
        }
    }
}

impl fmt::Display for RequestStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestStateError::UnknownState { input } => {
                write!(f, "unknown request state: {}", input)
            }
            RequestStateError::InvalidTransition { from, to } => write!(
                f,
                "illegal request status transition: {} -> {} (code={})",
                from,
                to,
                self.stable_code()
            ),
        }
    }
}

impl std::error::Error for RequestStateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_transitions_pass() {
        assert_eq!(
            RequestStatus::Open.transition(RequestStatus::Assigned).unwrap(),
            RequestStatus::Assigned
        );
        assert_eq!(
            RequestStatus::Assigned
                .transition(RequestStatus::CommitQueued)
                .unwrap(),
            RequestStatus::CommitQueued
        );
        assert_eq!(
            RequestStatus::CommitQueued
                .transition(RequestStatus::RevealSubmitted)
                .unwrap(),
            RequestStatus::RevealSubmitted
        );
    }

    #[test]
    fn illegal_transition_is_stable_error() {
        let err = RequestStatus::Open
            .transition(RequestStatus::CommitQueued)
            .unwrap_err();
        assert_eq!(err.stable_code(), "RequestStateInvalidTransition");
        assert!(err
            .to_string()
            .contains("illegal request status transition: OPEN -> COMMIT_QUEUED"));
    }

    #[test]
    fn terminal_states_are_irreversible() {
        for terminal in [
            RequestStatus::RevealSubmitted,
            RequestStatus::Rejected,
            RequestStatus::FailedAdapter,
            RequestStatus::FailedSubmission,
        ] {
            assert!(terminal.is_terminal());
            assert!(terminal.transition(RequestStatus::Open).is_err());
            assert!(terminal.transition(RequestStatus::Assigned).is_err());
        }
    }

    #[test]
    fn same_state_transition_is_idempotent() {
        for s in [
            RequestStatus::Open,
            RequestStatus::Assigned,
            RequestStatus::CommitQueued,
            RequestStatus::RevealSubmitted,
            RequestStatus::Rejected,
            RequestStatus::FailedAdapter,
            RequestStatus::FailedSubmission,
        ] {
            assert_eq!(s.transition(s).unwrap(), s);
        }
    }
}
