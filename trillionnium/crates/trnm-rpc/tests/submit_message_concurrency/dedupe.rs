use super::*;
use std::thread;

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
        assert_command_success(out.join().expect("join thread"));
    }

    let records = read_non_empty_jsonl(&ingress);
    assert_eq!(
        records.len(),
        1,
        "same session+idempotency_key should persist a single record under contention"
    );

    assert_eq!(records[0]["session_id"].as_str(), Some("s-1"));
    assert_eq!(records[0]["idempotency_key"].as_str(), Some("k-1"));

    fault_tolerance::assert_lock_file_cleaned(&ingress);
}
