use super::*;
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
