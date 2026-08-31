use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

fn unique_fixture_path(name: &str, ext: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("trnm_rpc_{}_{}_{}_{}.{}", name, pid, ts, seq, ext))
}

fn run_submit_message_with_limit(
    ingress: &PathBuf,
    text: &str,
    key: &str,
    max_bytes: Option<&str>,
) -> std::process::Output {
    let mut cmd = Command::new("cargo");
    cmd.env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "submit-message",
            "--channel",
            "telegram",
            "--user-id",
            "u-1",
            "--session-id",
            "s-1",
            "--text",
            text,
            "--idempotency-key",
            key,
        ])
        .env("TRNM_RPC_INGRESS_FILE", ingress);

    if let Some(limit) = max_bytes {
        cmd.env("TRNM_RPC_SUBMIT_MESSAGE_MAX_BYTES", limit);
    }

    cmd.output().expect("failed to execute trnm-rpc")
}

#[test]
fn submit_message_concurrent_same_idempotency_key_deduplicates() {
    let ingress = unique_fixture_path("submit_message_concurrency", "jsonl");
    let _ = fs::remove_file(&ingress);

    let workers = 8usize;
    let mut joins = Vec::with_capacity(workers);
    for _ in 0..workers {
        let ingress_env = ingress.clone();
        joins.push(thread::spawn(move || {
            Command::new("cargo")
                .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
                .args(["run", "-p", "trnm-rpc", "--"])
                .args([
                    "submit-message",
                    "--channel",
                    "telegram",
                    "--user-id",
                    "u-1",
                    "--session-id",
                    "s-1",
                    "--text",
                    "hello",
                    "--idempotency-key",
                    "k-1",
                ])
                .env("TRNM_RPC_INGRESS_FILE", ingress_env)
                .output()
                .expect("failed to execute trnm-rpc")
        }));
    }

    for out in joins {
        let output = out.join().expect("join thread");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let raw = fs::read_to_string(&ingress).expect("read ingress file");
    let records: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        records.len(),
        1,
        "same session+idempotency_key should persist a single record under contention"
    );

    let v: Value = serde_json::from_str(records[0]).expect("valid ingress json line");
    assert_eq!(v["session_id"].as_str(), Some("s-1"));
    assert_eq!(v["idempotency_key"].as_str(), Some("k-1"));

    let lock = ingress.with_file_name(format!(
        "{}.lock",
        ingress
            .file_name()
            .and_then(|v| v.to_str())
            .expect("ingress file name")
    ));
    assert!(
        !lock.exists(),
        "lock file should be cleaned after concurrent writers exit"
    );
}

#[test]
fn submit_message_concurrent_same_idempotency_key_different_sessions_are_isolated() {
    let ingress = unique_fixture_path("submit_message_concurrency_sessions", "jsonl");
    let _ = fs::remove_file(&ingress);

    let workers = 8usize;
    let mut joins = Vec::with_capacity(workers);
    for i in 0..workers {
        let ingress_env = ingress.clone();
        let session = if i % 2 == 0 { "s-1" } else { "s-2" }.to_string();
        joins.push(thread::spawn(move || {
            Command::new("cargo")
                .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
                .args(["run", "-p", "trnm-rpc", "--"])
                .args([
                    "submit-message",
                    "--channel",
                    "telegram",
                    "--user-id",
                    "u-1",
                    "--session-id",
                    &session,
                    "--text",
                    "hello",
                    "--idempotency-key",
                    "k-1",
                ])
                .env("TRNM_RPC_INGRESS_FILE", ingress_env)
                .output()
                .expect("failed to execute trnm-rpc")
        }));
    }

    for out in joins {
        let output = out.join().expect("join thread");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let raw = fs::read_to_string(&ingress).expect("read ingress file");
    let records: Vec<Value> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid ingress json line"))
        .collect();
    assert_eq!(
        records.len(),
        2,
        "idempotency key should be deduplicated per session, not globally"
    );

    let mut sessions: Vec<&str> = records
        .iter()
        .filter_map(|r| r["session_id"].as_str())
        .collect();
    sessions.sort_unstable();
    assert_eq!(sessions, vec!["s-1", "s-2"]);
}

#[test]
fn submit_message_concurrent_same_idempotency_key_different_channels_are_isolated() {
    let ingress = unique_fixture_path("submit_message_concurrency_channels", "jsonl");
    let _ = fs::remove_file(&ingress);

    let workers = 8usize;
    let mut joins = Vec::with_capacity(workers);
    for i in 0..workers {
        let ingress_env = ingress.clone();
        let channel = if i % 2 == 0 { "telegram" } else { "feishu" }.to_string();
        joins.push(thread::spawn(move || {
            Command::new("cargo")
                .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
                .args(["run", "-p", "trnm-rpc", "--"])
                .args([
                    "submit-message",
                    "--channel",
                    &channel,
                    "--user-id",
                    "u-1",
                    "--session-id",
                    "s-1",
                    "--text",
                    "hello",
                    "--idempotency-key",
                    "k-1",
                ])
                .env("TRNM_RPC_INGRESS_FILE", ingress_env)
                .output()
                .expect("failed to execute trnm-rpc")
        }));
    }

    for out in joins {
        let output = out.join().expect("join thread");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let raw = fs::read_to_string(&ingress).expect("read ingress file");
    let records: Vec<Value> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid ingress json line"))
        .collect();
    assert_eq!(
        records.len(),
        2,
        "idempotency key should be deduplicated per channel scope, not globally"
    );

    let mut channels: Vec<&str> = records
        .iter()
        .filter_map(|r| r["channel"].as_str())
        .collect();
    channels.sort_unstable();
    assert_eq!(channels, vec!["feishu", "telegram"]);
}

#[test]
fn submit_message_concurrent_same_idempotency_key_different_users_are_isolated() {
    let ingress = unique_fixture_path("submit_message_concurrency_users", "jsonl");
    let _ = fs::remove_file(&ingress);

    let workers = 8usize;
    let mut joins = Vec::with_capacity(workers);
    for i in 0..workers {
        let ingress_env = ingress.clone();
        let user_id = if i % 2 == 0 { "u-1" } else { "u-2" }.to_string();
        joins.push(thread::spawn(move || {
            Command::new("cargo")
                .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
                .args(["run", "-p", "trnm-rpc", "--"])
                .args([
                    "submit-message",
                    "--channel",
                    "telegram",
                    "--user-id",
                    &user_id,
                    "--session-id",
                    "s-1",
                    "--text",
                    "hello",
                    "--idempotency-key",
                    "k-1",
                ])
                .env("TRNM_RPC_INGRESS_FILE", ingress_env)
                .output()
                .expect("failed to execute trnm-rpc")
        }));
    }

    for out in joins {
        let output = out.join().expect("join thread");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let raw = fs::read_to_string(&ingress).expect("read ingress file");
    let records: Vec<Value> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid ingress json line"))
        .collect();
    assert_eq!(
        records.len(),
        2,
        "idempotency key should be deduplicated per user scope, not globally"
    );

    let mut users: Vec<&str> = records
        .iter()
        .filter_map(|r| r["user_id"].as_str())
        .collect();
    users.sort_unstable();
    assert_eq!(users, vec!["u-1", "u-2"]);
}

#[test]
fn submit_message_idempotent_replay_survives_runtime_quota_tightening() {
    let ingress = unique_fixture_path("submit_message_quota_tightening", "jsonl");
    let _ = fs::remove_file(&ingress);

    let first = run_submit_message_with_limit(&ingress, "hello", "k-tighten", Some("5"));
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let replay = run_submit_message_with_limit(&ingress, "hello", "k-tighten", Some("4"));
    assert!(
        replay.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&replay.stderr)
    );

    let raw = fs::read_to_string(&ingress).expect("read ingress file");
    let records: Vec<Value> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid ingress json line"))
        .collect();

    assert_eq!(
        records.len(),
        1,
        "idempotent replay must not create new record"
    );
    assert_eq!(
        records[0]["idempotency_key"].as_str(),
        Some("k-tighten"),
        "replay should return existing record under tighter quota"
    );
}
