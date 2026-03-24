mod models;
mod parsing;
mod transitions;

pub use models::{RequestStateError, RequestStatus};

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STATES: [RequestStatus; 7] = [
        RequestStatus::Open,
        RequestStatus::Assigned,
        RequestStatus::CommitQueued,
        RequestStatus::RevealSubmitted,
        RequestStatus::Rejected,
        RequestStatus::FailedAdapter,
        RequestStatus::FailedSubmission,
    ];

    fn expected_legal_transition(from: RequestStatus, to: RequestStatus) -> bool {
        if from == to {
            return true;
        }

        matches!(
            (from, to),
            (RequestStatus::Open, RequestStatus::Assigned)
                | (RequestStatus::Assigned, RequestStatus::CommitQueued)
                | (RequestStatus::Assigned, RequestStatus::Rejected)
                | (RequestStatus::Assigned, RequestStatus::FailedAdapter)
                | (RequestStatus::CommitQueued, RequestStatus::RevealSubmitted)
                | (RequestStatus::CommitQueued, RequestStatus::Rejected)
                | (RequestStatus::CommitQueued, RequestStatus::FailedSubmission)
        )
    }

    #[test]
    fn legal_transitions_pass() {
        assert_eq!(
            RequestStatus::Open
                .transition(RequestStatus::Assigned)
                .unwrap(),
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
    fn transition_matrix_matches_spec_and_returns_stable_errors() {
        for from in ALL_STATES {
            for to in ALL_STATES {
                let expected_legal = expected_legal_transition(from, to);
                assert_eq!(
                    from.can_transition_to(to),
                    expected_legal,
                    "can_transition_to mismatch for {} -> {}",
                    from,
                    to
                );

                match from.transition(to) {
                    Ok(actual_to) => {
                        assert!(
                            expected_legal,
                            "transition unexpectedly succeeded for {} -> {}",
                            from, to
                        );
                        assert_eq!(actual_to, to);
                    }
                    Err(err) => {
                        assert!(
                            !expected_legal,
                            "transition unexpectedly failed for {} -> {}: {}",
                            from, to, err
                        );
                        assert_eq!(err.stable_code(), "RequestStateInvalidTransition");
                        assert!(matches!(
                            err,
                            RequestStateError::InvalidTransition {
                                from: e_from,
                                to: e_to
                            } if e_from == from && e_to == to
                        ));
                    }
                }
            }
        }
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
    fn parse_unknown_state_is_stable_error() {
        let err = RequestStatus::parse("NOT_A_STATE").unwrap_err();
        assert_eq!(err.stable_code(), "RequestStateUnknown");
        assert!(matches!(
            err,
            RequestStateError::UnknownState { input } if input == "NOT_A_STATE"
        ));
    }

    #[test]
    fn parse_accepts_case_insensitive_and_whitespace_wrapped_inputs() {
        assert_eq!(RequestStatus::parse("open").unwrap(), RequestStatus::Open);
        assert_eq!(
            RequestStatus::parse("  commit_queued\n").unwrap(),
            RequestStatus::CommitQueued
        );
        assert_eq!(
            RequestStatus::parse("ReVeAl_Submitted").unwrap(),
            RequestStatus::RevealSubmitted
        );
        assert_eq!(
            RequestStatus::parse("reveal-submitted").unwrap(),
            RequestStatus::RevealSubmitted
        );
        assert_eq!(
            RequestStatus::parse("failed adapter").unwrap(),
            RequestStatus::FailedAdapter
        );
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
        for s in ALL_STATES {
            assert_eq!(s.transition(s).unwrap(), s);
        }
    }
}
