use super::*;
use std::thread;

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
        assert_command_success(out.join().expect("join thread"));
    }

    let records = read_non_empty_jsonl(&ingress);
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
        assert_command_success(out.join().expect("join thread"));
    }

    let records = read_non_empty_jsonl(&ingress);
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
        assert_command_success(out.join().expect("join thread"));
    }

    let records = read_non_empty_jsonl(&ingress);
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
