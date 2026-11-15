use super::*;

#[test]
fn corrupt_ack_refuses_flush_before_any_adapter_or_progress() {
    let dir = tempfile::tempdir().unwrap();
    let submit = dir.path().join("submit.jsonl");
    let ack = dir.path().join("ack.jsonl");
    let progress = dir.path().join("progress.jsonl");
    append_submission(&submit, 1, "worker", "commit", "result", "salt").unwrap();
    fs::write(&ack, b"{broken-ack}\n").unwrap();
    let result = flush::handle_flush_submissions(
        submit,
        dir.path().join("ingress.jsonl"),
        false,
        false,
        "/usr/bin/true".to_string(),
        Some(0),
        Some(0),
        ack,
        dir.path().join("events.jsonl"),
        progress.clone(),
    );
    assert!(
        result.is_err(),
        "a corrupt ACK must never mean an unacknowledged task"
    );
    assert!(!progress.exists(), "validation must precede task effects");
}

#[test]
fn malformed_ingress_refuses_instead_of_dropping_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ingress.jsonl");
    fs::write(&path, b"{malformed}\n").unwrap();
    assert!(load_ingress_records(&path).is_err());
}

#[test]
fn append_refuses_an_incomplete_or_corrupt_prior_record() {
    let dir = tempfile::tempdir().unwrap();
    for (index, contents) in [b"{broken}\n".as_slice(), b"{\"partial\":".as_slice()]
        .iter()
        .enumerate()
    {
        let path = dir.path().join(format!("ack-{index}.jsonl"));
        fs::write(&path, contents).unwrap();
        assert!(append_ack(&path, 1, "accepted", None, None, None, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), *contents);
    }
}

#[cfg(unix)]
#[test]
fn lock_owner_child_exits_without_running_destructors() {
    let Some(path) = env::var_os("TRNM_LOCK_EXIT_TEST_PATH") else {
        return;
    };
    let _guard = try_acquire_task_lock(Path::new(&path), 42)
        .unwrap()
        .unwrap();
    // Model process termination: Rust Drop is deliberately not run.
    std::process::exit(0);
}

#[cfg(unix)]
#[test]
fn task_lock_is_recoverable_after_process_exit() {
    let dir = tempfile::tempdir().unwrap();
    let ack = dir.path().join("ack.jsonl");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests_journal_security::lock_owner_child_exits_without_running_destructors",
            "--nocapture",
        ])
        .env("TRNM_LOCK_EXIT_TEST_PATH", &ack)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        try_acquire_task_lock(&ack, 42).unwrap().is_some(),
        "process death must release ownership without deleting a marker"
    );
}

#[test]
fn journal_replay_limits_refuse_before_record_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes_path = dir.path().join("bytes.jsonl");
    let file = fs::File::create(&bytes_path).unwrap();
    file.set_len(worker_journal::MAX_LOG_BYTES + 1).unwrap();
    assert!(load_ack_records(&bytes_path).is_err());
    let rows_path = dir.path().join("rows.jsonl");
    fs::write(
        &rows_path,
        "{}\n".repeat(worker_journal::MAX_LOG_RECORDS + 1),
    )
    .unwrap();
    assert!(load_ack_records(&rows_path).is_err());
}

#[test]
fn stale_ingress_snapshot_refuses_without_losing_committed_updates() {
    fn record(task_id: u64) -> MessageIngressRecord {
        serde_json::from_value(serde_json::json!({
            "request_id": format!("request-{task_id}"), "task_id": task_id,
            "channel":"test", "user_id":"owner", "session_id":"test",
            "text":"test", "idempotency_key":format!("key-{task_id}"),
            "status":"assigned", "created_at_unix_ms":1
        }))
        .unwrap()
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ingress.jsonl");
    let mut first = load_ingress_snapshot(&path).unwrap();
    let mut stale = load_ingress_snapshot(&path).unwrap();
    first.push(record(1));
    stale.push(record(2));
    save_ingress_snapshot(&path, &first).unwrap();
    assert!(save_ingress_snapshot(&path, &stale).is_err());
    let mut current = load_ingress_snapshot(&path).unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].task_id, 1);
    current.push(record(2));
    save_ingress_snapshot(&path, &current).unwrap();
    let reopened = load_ingress_records(&path).unwrap();
    assert_eq!(
        reopened.iter().map(|r| r.task_id).collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[cfg(unix)]
#[test]
fn stable_task_lock_inode_and_symlink_refusal() {
    use std::os::unix::fs::{symlink, MetadataExt};
    let dir = tempfile::tempdir().unwrap();
    let ack = dir.path().join("ack.jsonl");
    let guard = try_acquire_task_lock(&ack, 1).unwrap().unwrap();
    let lock = task_lock_path(&ack, 1);
    let inode = fs::metadata(&lock).unwrap().ino();
    assert!(try_acquire_task_lock(&ack, 1).unwrap().is_none());
    drop(guard);
    let _next = try_acquire_task_lock(&ack, 1).unwrap().unwrap();
    assert_eq!(fs::metadata(&lock).unwrap().ino(), inode);

    let target = dir.path().join("target");
    fs::write(&target, b"retained").unwrap();
    let linked = dir.path().join("linked.jsonl");
    symlink(&target, &linked).unwrap();
    assert!(load_ack_records(&linked).is_err());
    assert!(append_ack(&linked, 1, "accepted", None, None, None, None).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"retained");
}

#[test]
fn nonregular_ack_path_is_an_error_not_empty_history() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load_acked(dir.path()).is_err());
    assert!(is_task_acked(dir.path(), 1).is_err());
    assert!(persisted_ack_hashes_for_task(dir.path(), 1).is_err());
}

#[test]
fn exhausted_task_identity_refuses_without_panic_or_rewinding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let original = format!("{{\"last_task_id\":{}}}", u64::MAX);
    fs::write(&path, &original).unwrap();
    let result = std::panic::catch_unwind(|| next_task_id(&path));
    assert!(
        result.is_ok(),
        "task identity exhaustion is a normal refusal"
    );
    assert!(result.unwrap().is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn concurrent_task_identity_allocation_is_unique_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                next_task_id(&path).unwrap()
            })
        })
        .collect();
    let mut ids: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    ids.sort_unstable();
    assert_eq!(ids, (1001..=1008).collect::<Vec<_>>());
    assert_eq!(next_task_id(&path).unwrap(), 1009);
    let state: WorkerState = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(state.last_task_id, 1009);
}

#[test]
fn oversized_task_state_and_lock_deadline_refuse_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    fs::File::create(&state).unwrap().set_len(4097).unwrap();
    assert!(next_task_id(&state).is_err());
    assert_eq!(fs::metadata(&state).unwrap().len(), 4097);

    let journal = dir.path().join("ack.jsonl");
    append_ack(&journal, 1, "accepted", None, None, None, None).unwrap();
    let before = fs::read(&journal).unwrap();
    let _guard = worker_journal::try_lock_path(&journal).unwrap().unwrap();
    let started = std::time::Instant::now();
    let error = append_ack(&journal, 2, "accepted", None, None, None, None).unwrap_err();
    assert!(error.to_string().contains("lock deadline"));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(fs::read(&journal).unwrap(), before);
}
