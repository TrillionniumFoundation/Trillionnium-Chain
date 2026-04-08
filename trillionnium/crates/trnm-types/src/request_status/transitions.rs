use super::{RequestStateError, RequestStatus};

impl RequestStatus {
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
