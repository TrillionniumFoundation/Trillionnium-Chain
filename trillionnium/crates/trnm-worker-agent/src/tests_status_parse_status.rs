use super::*;

#[test]
fn transition_request_status_accepts_benign_formatting_variants() {
    let next = transition_request_status("  open ", RequestStatus::Assigned)
        .expect("OPEN -> ASSIGNED should parse with whitespace/case drift");
    assert_eq!(next, RequestStatus::Assigned.as_str());

    let next = transition_request_status("aSsIgNeD", RequestStatus::CommitQueued)
        .expect("ASSIGNED -> COMMIT_QUEUED should parse case-insensitively");
    assert_eq!(next, RequestStatus::CommitQueued.as_str());
}

#[test]
fn transition_request_status_rejects_malformed_state_with_stable_diagnostic() {
    let err = transition_request_status(" pending-ish ", RequestStatus::Assigned)
        .expect_err("unknown states must be rejected");
    assert!(
        err.to_string().contains("unknown request state"),
        "unexpected error text: {}",
        err
    );
}

#[test]
fn deterministic_rejection_codes_are_stable() {
    assert!(is_deterministic_rejection(RC_DUPLICATE));
    assert!(is_deterministic_rejection(RC_NONCE_REJECTED));
    assert!(is_deterministic_rejection(RC_SLO_VIOLATION));
    assert!(!is_deterministic_rejection(RC_OK));
    assert!(!is_deterministic_rejection(42));
}

#[test]
fn idempotent_only_accepts_duplicate() {
    assert!(is_idempotent_duplicate_ok(RC_DUPLICATE));
    assert!(!is_idempotent_duplicate_ok(RC_NONCE_REJECTED));
    assert!(!is_idempotent_duplicate_ok(RC_OK));
}

#[test]
fn terminal_commit_reject_skips_reveal_execution_gate() {
    let commit_res = AdapterExecResult {
        ok: false,
        rc: RC_NONCE_REJECTED,
        tx_hash: None,
        terminal: true,
    };

    assert!(!should_execute_reveal(&commit_res));
}

#[test]
fn duplicate_commit_still_executes_reveal_gate() {
    let commit_res = AdapterExecResult {
        ok: false,
        rc: RC_DUPLICATE,
        tx_hash: None,
        terminal: true,
    };

    assert!(should_execute_reveal(&commit_res));
}

#[test]
fn backoff_delay_is_exponential_and_saturating() {
    assert_eq!(backoff_delay_ms(200, 0), 200);
    assert_eq!(backoff_delay_ms(200, 1), 400);
    assert_eq!(backoff_delay_ms(200, 2), 800);

    // saturation guard (no overflow panic/wrap)
    assert_eq!(backoff_delay_ms(u64::MAX, 1), u64::MAX);
}
