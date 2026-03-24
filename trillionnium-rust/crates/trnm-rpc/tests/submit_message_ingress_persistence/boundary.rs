use super::*;

#[test]
fn submit_message_duplicate_lookup_prefers_latest_record() {
    let ingress = unique_fixture_path("submit_message_duplicate_latest", "jsonl");
    let _ = fs::remove_file(&ingress);

    let seed = [
        r#"{"request_id":"r-old","task_id":10001,"channel":"telegram","user_id":"u-1","session_id":"s-dup","text":"old","idempotency_key":"k-dup","status":"Open","created_at_unix_ms":1}"#,
        r#"{"request_id":"r-new","task_id":10002,"channel":"telegram","user_id":"u-1","session_id":"s-dup","text":"new","idempotency_key":"k-dup","status":"Open","created_at_unix_ms":2}"#,
    ]
    .join("\n");
    fs::write(&ingress, format!("{}\n", seed)).expect("seed ingress");

    let output = run_submit_message(&ingress, "u-1", "s-dup", "ignored", "k-dup");
    assert_command_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let out: Value = serde_json::from_str(&stdout).expect("json response");
    assert_eq!(out["request_id"].as_str(), Some("r-new"));
    assert_eq!(out["task_id"].as_u64(), Some(10_002));
    assert_eq!(out["text"].as_str(), Some("new"));

    let raw = fs::read_to_string(&ingress).expect("read ingress");
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "duplicate submit should not append a third row when key already exists"
    );
}
