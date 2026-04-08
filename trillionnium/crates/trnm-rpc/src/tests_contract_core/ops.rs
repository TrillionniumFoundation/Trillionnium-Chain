pub(crate) use super::*;

#[test]
fn resolve_ops_window_custom_validation() {
    assert!(resolve_ops_window(Some(OpsWindowArg::Custom), None, Some(1), 10).is_err());
    assert!(resolve_ops_window(Some(OpsWindowArg::Custom), Some(2), Some(1), 10).is_err());
    assert!(resolve_ops_window(
        Some(OpsWindowArg::Custom),
        Some(0),
        Some(OPS_WINDOW_CUSTOM_MAX_MS + 1),
        10
    )
    .is_err());

    let got = resolve_ops_window(Some(OpsWindowArg::H24), None, None, 1_000).unwrap();
    let (from, to, mode) = got.expect("window expected");
    assert_eq!(to, 1_000);
    assert_eq!(mode, "24h");
    assert!(from <= to);
}

#[test]
fn make_request_id_is_deterministic_and_separator_sensitive() {
    let a = make_request_id("telegram", "u1", "s1", "idem-1", 123);
    let b = make_request_id("telegram", "u1", "s1", "idem-1", 123);
    let c = make_request_id("telegram|u1", "s1", "idem-1", "", 123);

    assert_eq!(a, b, "same tuple must hash to a stable request id");
    assert_ne!(a, c, "field separators must keep scopes unambiguous");
    assert!(a.starts_with("req_"));
    assert_eq!(a.len(), 20, "req_ + 16 hex chars");
}

#[test]
fn submit_message_idempotency_scope_requires_channel_user_session_and_key_match() {
    let rec = MessageIngressRecord {
        request_id: "req_1".into(),
        task_id: 42,
        channel: "telegram".into(),
        user_id: "u1".into(),
        session_id: "s1".into(),
        text: "hi".into(),
        idempotency_key: "idem-1".into(),
        status: RequestStatus::Open.as_str().into(),
        created_at_unix_ms: 1,
        assigned_worker: None,
        assigned_at_unix_ms: None,
        model_output: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
    };

    assert!(is_same_submit_message_idempotency_scope(
        &rec, "telegram", "u1", "s1", "idem-1"
    ));
    assert!(!is_same_submit_message_idempotency_scope(
        &rec, "discord", "u1", "s1", "idem-1"
    ));
    assert!(!is_same_submit_message_idempotency_scope(
        &rec, "telegram", "u2", "s1", "idem-1"
    ));
    assert!(!is_same_submit_message_idempotency_scope(
        &rec, "telegram", "u1", "s2", "idem-1"
    ));
    assert!(!is_same_submit_message_idempotency_scope(
        &rec, "telegram", "u1", "s1", "idem-2"
    ));
}

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
