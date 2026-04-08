use super::*;

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
fn persisted_ack_hashes_for_task_ignores_blank_wrapped_hash_entries() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-persisted-ack-blank-hashes-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_file(&ack_log);

    append_ack(
        &ack_log,
        78,
        "failed",
        Some("\u{feff}\u{200b}   \u{2060}".to_string()),
        Some("\t\n".to_string()),
        Some("missing_tx_hash_receipt".to_string()),
        Some("run-1".to_string()),
    )
    .expect("write blank ack");
    append_ack(
        &ack_log,
        78,
        "accepted",
        Some("commit-new".to_string()),
        Some("\u{feff}reveal-new\u{200b}".to_string()),
        Some("idempotent_ok".to_string()),
        Some("run-2".to_string()),
    )
    .expect("write recovery ack");

    let hashes = persisted_ack_hashes_for_task(&ack_log, 78);
    assert_eq!(hashes.commit_tx_hash.as_deref(), Some("commit-new"));
    assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("reveal-new"));

    let _ = fs::remove_file(&ack_log);
}
