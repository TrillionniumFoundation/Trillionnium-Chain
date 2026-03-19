use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn unique_fixture_path(name: &str, ext: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("trnm_rpc_{}_{}.{}", name, ts, ext))
}

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

    let output = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "submit-message",
            "--channel",
            "telegram",
            "--user-id",
            "u-3",
            "--session-id",
            "s-3",
            "--text",
            "next",
            "--idempotency-key",
            "k-3",
        ])
        .env("TRNM_RPC_INGRESS_FILE", &ingress)
        .output()
        .expect("run submit-message");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

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

    let output = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "submit-message",
            "--channel",
            "telegram",
            "--user-id",
            "u-1",
            "--session-id",
            "s-dup",
            "--text",
            "ignored",
            "--idempotency-key",
            "k-dup",
        ])
        .env("TRNM_RPC_INGRESS_FILE", &ingress)
        .output()
        .expect("run submit-message");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

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

#[test]
fn submit_message_quarantines_invalid_ingress_row_only_once_across_replays() {
    let ingress = unique_fixture_path("submit_message_quarantine_rewrite", "jsonl");
    let quarantine = ingress.with_file_name(format!(
        "{}.quarantine.jsonl",
        ingress
            .file_name()
            .and_then(|v| v.to_str())
            .expect("ingress file name")
    ));
    let _ = fs::remove_file(&ingress);
    let _ = fs::remove_file(&quarantine);

    let seed = [
        r#"{"request_id":"r-1","task_id":10001,"channel":"telegram","user_id":"u-1","session_id":"s-1","text":"hello","idempotency_key":"k-1","status":"Open","created_at_unix_ms":1}"#,
        "not-json",
    ]
    .join("\n");
    fs::write(&ingress, format!("{}\n", seed)).expect("seed ingress");

    let run_submit = |key: &str| {
        Command::new("cargo")
            .args(["run", "-p", "trnm-rpc", "--"])
            .args([
                "submit-message",
                "--channel",
                "telegram",
                "--user-id",
                "u-3",
                "--session-id",
                "s-3",
                "--text",
                "next",
                "--idempotency-key",
                key,
            ])
            .env("TRNM_RPC_INGRESS_FILE", &ingress)
            .output()
            .expect("run submit-message")
    };

    let first = run_submit("k-3");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let rewritten = fs::read_to_string(&ingress).expect("read rewritten ingress");
    let rewritten_lines: Vec<&str> = rewritten.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(rewritten_lines.len(), 2, "invalid row should be removed after first submit replay");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let quarantine_lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(quarantine_lines.len(), 1, "first replay should quarantine exactly once");

    let second = run_submit("k-3");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let quarantine_raw_second = fs::read_to_string(&quarantine).expect("read quarantine file again");
    let quarantine_lines_second: Vec<&str> = quarantine_raw_second
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines_second.len(),
        1,
        "quarantine noise should stay bounded across repeated idempotent replays"
    );
}
