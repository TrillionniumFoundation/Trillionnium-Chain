use super::*;

#[test]
fn submit_message_task_id_uses_max_existing_plus_one() {
    let ingress = unique_fixture_path("submit_message_task_id", "jsonl");
    let _ = fs::remove_file(&ingress);

    let seed = [
        r#"{"request_id":"r-1","task_id":10001,"channel":"telegram","user_id":"u-1","session_id":"s-1","text":"hello","idempotency_key":"k-1","status":"Open","created_at_unix_ms":1}"#,
        r#"{"request_id":"r-2","task_id":10999,"channel":"telegram","user_id":"u-2","session_id":"s-2","text":"world","idempotency_key":"k-2","status":"Open","created_at_unix_ms":2}"#,
        "not-json",
    ]
    .join("\n");
    fs::write(&ingress, format!("{}\n", seed)).expect("seed ingress");

    let output = run_submit_message(&ingress, "u-3", "s-3", "next", "k-3");
    assert_command_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let out: Value = serde_json::from_str(&stdout).expect("json response");
    assert_eq!(out["task_id"].as_u64(), Some(11_000));

    let raw = fs::read_to_string(&ingress).expect("read ingress");
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3, "2 seeded valid rows + new row");

    let last: Value = serde_json::from_str(lines.last().copied().unwrap()).expect("last row json");
    assert_eq!(last["task_id"].as_u64(), Some(11_000));

    let parent = ingress.parent().expect("temp parent");
    let file_name = ingress
        .file_name()
        .and_then(|v| v.to_str())
        .expect("ingress file name");
    let leftovers = fs::read_dir(parent)
        .expect("read parent dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name.starts_with(&format!(".{}.tmp-", file_name)))
        .count();
    assert_eq!(
        leftovers, 0,
        "no temp files should remain after atomic write"
    );
}
