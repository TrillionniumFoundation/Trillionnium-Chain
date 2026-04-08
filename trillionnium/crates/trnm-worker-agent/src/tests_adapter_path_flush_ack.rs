use super::*;
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
