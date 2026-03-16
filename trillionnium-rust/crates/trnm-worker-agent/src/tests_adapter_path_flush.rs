use super::*;

#[test]
fn flush_submissions_requires_tx_hash_receipts_for_terminal_acceptance() {
    let commit_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: None,
        terminal: true,
    };
    let reveal_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: None,
        terminal: true,
    };

    let commit_idempotent_ok = should_execute_reveal(&commit_res);
    let reveal_idempotent_ok = reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);
    let commit_hash_observed = commit_res.tx_hash.is_some();
    let reveal_hash_observed = reveal_res.tx_hash.is_some();

    let (ack_status, reason_code) = if commit_idempotent_ok
        && reveal_idempotent_ok
        && commit_hash_observed
        && reveal_hash_observed
    {
        ("accepted", "idempotent_ok")
    } else if commit_idempotent_ok
        && reveal_idempotent_ok
        && (!commit_hash_observed || !reveal_hash_observed)
    {
        ("failed", "missing_tx_hash_receipt")
    } else {
        ("unexpected", "unexpected")
    };

    assert_eq!(ack_status, "failed");
    assert_eq!(reason_code, "missing_tx_hash_receipt");
}

#[test]
fn flush_submissions_reuses_persisted_tx_hash_for_duplicate_resume_acceptance() {
    let commit_res = AdapterExecResult {
        ok: false,
        rc: RC_DUPLICATE,
        tx_hash: None,
        terminal: true,
    };
    let reveal_res = AdapterExecResult {
        ok: true,
        rc: RC_OK,
        tx_hash: Some("revealbeef".to_string()),
        terminal: true,
    };

    let previous_commit_tx_hash = Some("commitbeef".to_string());
    let previous_reveal_tx_hash = None;

    let commit_hash_observed = commit_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(commit_res.rc) && previous_commit_tx_hash.is_some());
    let reveal_hash_observed = reveal_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(reveal_res.rc) && previous_reveal_tx_hash.is_some());

    let commit_tx_hash_for_ack = commit_res.tx_hash.clone().or(previous_commit_tx_hash);
    let reveal_tx_hash_for_ack = reveal_res.tx_hash.clone().or(previous_reveal_tx_hash);

    assert!(should_execute_reveal(&commit_res));
    assert!(reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc));
    assert!(commit_hash_observed);
    assert!(reveal_hash_observed);
    assert_eq!(commit_tx_hash_for_ack.as_deref(), Some("commitbeef"));
    assert_eq!(reveal_tx_hash_for_ack.as_deref(), Some("revealbeef"));
}

#[test]
fn persisted_ack_hashes_for_task_merges_hashes_across_failed_resume_attempts() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-persisted-ack-hashes-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_file(&ack_log);

    append_ack(
        &ack_log,
        77,
        "failed",
        Some("commit-old".to_string()),
        None,
        Some("missing_tx_hash_receipt".to_string()),
        Some("run-1".to_string()),
    )
    .expect("write first ack");
    append_ack(
        &ack_log,
        77,
        "accepted",
        None,
        Some("reveal-new".to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-2".to_string()),
    )
    .expect("write second ack");

    let hashes = persisted_ack_hashes_for_task(&ack_log, 77);
    assert_eq!(hashes.commit_tx_hash.as_deref(), Some("commit-old"));
    assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("reveal-new"));

    let _ = fs::remove_file(&ack_log);
}

#[test]
fn task_lock_prevents_parallel_replay_for_same_task() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-ack-lock-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let guard = try_acquire_task_lock(&ack_log, 42)
        .expect("acquire lock")
        .expect("first lock should succeed");
    assert!(
        try_acquire_task_lock(&ack_log, 42)
            .expect("second lock call")
            .is_none(),
        "second lock should be blocked"
    );
    drop(guard);
    assert!(
        try_acquire_task_lock(&ack_log, 42)
            .expect("third lock call")
            .is_some(),
        "lock should be released after drop"
    );
    let _ = fs::remove_file(&ack_log);
}

#[test]
fn is_task_acked_only_true_for_accepted_records() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-ack-records-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    fs::write(
            &ack_log,
            "{\"ts_unix_ms\":1,\"task_id\":1,\"status\":\"rejected\"}\n{\"ts_unix_ms\":2,\"task_id\":2,\"status\":\"accepted\"}\n",
        )
        .expect("write ack log");

    assert!(!is_task_acked(&ack_log, 1));
    assert!(is_task_acked(&ack_log, 2));
    let _ = fs::remove_file(&ack_log);
}

#[test]
fn message_ingress_backward_compat_defaults_provider_request_id() {
    let raw = r#"{"request_id":"r1","task_id":7,"channel":"telegram","user_id":"u1","session_id":"s1","text":"hello","idempotency_key":"ik1","status":"assigned","created_at_unix_ms":1}"#;
    let rec: MessageIngressRecord = serde_json::from_str(raw).expect("parse ingress record");
    assert_eq!(rec.provider_request_id, None);
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}
