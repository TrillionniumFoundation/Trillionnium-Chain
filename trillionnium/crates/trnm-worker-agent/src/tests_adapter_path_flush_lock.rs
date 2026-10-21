use super::*;

#[cfg(unix)]
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


#[cfg(unix)]
#[test]
fn stale_task_lock_file_does_not_block_new_worker() {
    let ack_log = std::env::temp_dir().join(format!(
        "trnm-worker-agent-stale-task-lock-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let lock_path = task_lock_path(&ack_log, 43);
    let _ = fs::remove_file(&lock_path);
    fs::write(&lock_path, b"stale owner pid=0 start=0
").expect("create stale lock file");

    let guard = try_acquire_task_lock(&ack_log, 43)
        .expect("acquire stale lock")
        .expect("stale lock file must not block task execution");
    drop(guard);
    let _ = fs::remove_file(&lock_path);
    let _ = fs::remove_file(&ack_log);
}

#[cfg(unix)]
#[test]
fn stale_append_sentinel_does_not_block_advisory_append() {
    let path = std::env::temp_dir().join(format!(
        "trnm-worker-agent-stale-append-lock-{}-{}.jsonl",
        std::process::id(),
        now_ms()
    ));
    let base = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("temporary path has a UTF-8 basename");
    let stale_sentinel = path
        .parent()
        .expect("temporary path has a parent")
        .join(format!(".{base}.append.lock"));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&stale_sentinel);
    fs::write(&stale_sentinel, b"stale owner pid=0 start=0
")
        .expect("create stale append sentinel");

    append_json_line(&path, "{\"ok\":true}").expect("stale sentinel must be ignored");
    assert_eq!(fs::read_to_string(&path).expect("read append log"), "{\"ok\":true}\n");
    let _ = fs::remove_file(&stale_sentinel);
    let _ = fs::remove_file(&path);
}
