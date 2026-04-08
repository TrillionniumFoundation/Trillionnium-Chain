use super::*;

#[test]
fn submit_message_idempotent_replay_survives_runtime_quota_tightening() {
    let ingress = unique_fixture_path("submit_message_quota_tightening", "jsonl");
    let _ = fs::remove_file(&ingress);

    let first = run_submit_message_with_limit(&ingress, "hello", "k-tighten", Some("5"));
    assert_command_success(first);

    let replay = run_submit_message_with_limit(&ingress, "hello", "k-tighten", Some("4"));
    assert_command_success(replay);

    let records = read_non_empty_jsonl(&ingress);

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
