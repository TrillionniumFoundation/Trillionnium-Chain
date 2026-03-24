use std::fmt;

use super::{RequestStateError, RequestStatus};

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
        let normalized = s.trim();
        // Accept common separator variants from external producers (hyphen/space)
        // while still requiring exact token identity.
        let canonical = normalized
            .chars()
            .map(|c| match c {
                '-' | ' ' => '_',
                _ => c,
            })
            .collect::<String>();

        if canonical.eq_ignore_ascii_case("OPEN") {
            return Ok(RequestStatus::Open);
        }
        if canonical.eq_ignore_ascii_case("ASSIGNED") {
            return Ok(RequestStatus::Assigned);
        }
        if canonical.eq_ignore_ascii_case("COMMIT_QUEUED") {
            return Ok(RequestStatus::CommitQueued);
        }
        if canonical.eq_ignore_ascii_case("REVEAL_SUBMITTED") {
            return Ok(RequestStatus::RevealSubmitted);
        }
        if canonical.eq_ignore_ascii_case("REJECTED") {
            return Ok(RequestStatus::Rejected);
        }
        if canonical.eq_ignore_ascii_case("FAILED_ADAPTER") {
            return Ok(RequestStatus::FailedAdapter);
        }
        if canonical.eq_ignore_ascii_case("FAILED_SUBMISSION") {
            return Ok(RequestStatus::FailedSubmission);
        }

        Err(RequestStateError::UnknownState {
            input: normalized.to_string(),
        })
    }
}

impl fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
