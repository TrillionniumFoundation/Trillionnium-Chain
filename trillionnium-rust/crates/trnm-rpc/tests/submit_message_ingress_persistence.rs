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

fn expected_stable_line_hash(raw: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in raw.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
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
    assert_eq!(
        rewritten_lines.len(),
        2,
        "invalid row should be removed after first submit replay"
    );

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let quarantine_lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines.len(),
        1,
        "first replay should quarantine exactly once"
    );

    let quarantined: Value =
        serde_json::from_str(quarantine_lines[0]).expect("quarantine row json");
    assert_eq!(quarantined["raw_line"].as_str(), Some("not-json"));
    assert_eq!(
        quarantined["line_hash"].as_u64(),
        Some(expected_stable_line_hash("not-json")),
        "quarantine line hash should remain deterministic for bounded replay dedupe"
    );

    let second = run_submit("k-3");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let quarantine_raw_second =
        fs::read_to_string(&quarantine).expect("read quarantine file again");
    let quarantine_lines_second: Vec<&str> = quarantine_raw_second
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines_second.len(),
        1,
        "quarantine noise should stay bounded across repeated idempotent replays"
    );

    let quarantined_second: Value =
        serde_json::from_str(quarantine_lines_second[0]).expect("quarantine row json again");
    assert_eq!(
        quarantined_second["line_hash"].as_u64(),
        Some(expected_stable_line_hash("not-json")),
        "replayed quarantine rows should preserve the deterministic dedupe key"
    );
}

#[test]
fn submit_message_dedupes_duplicate_noise_before_quarantine_cap() {
    let ingress = unique_fixture_path("submit_message_quarantine_dedup_noise_bound", "jsonl");
    let quarantine = ingress.with_file_name(format!(
        "{}.quarantine.jsonl",
        ingress
            .file_name()
            .and_then(|v| v.to_str())
            .expect("ingress file name")
    ));
    let _ = fs::remove_file(&ingress);
    let _ = fs::remove_file(&quarantine);

    let unique_prefix = (0..255)
        .map(|idx| format!("uniq-bad-{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    let duplicate_storm = std::iter::repeat_n("storm-dup".to_string(), 100)
        .collect::<Vec<_>>()
        .join("\n");
    let fixture = format!("{unique_prefix}\n{duplicate_storm}\nuniq-tail\n");
    fs::write(&ingress, fixture).expect("write duplicate-noise ingress fixture");

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

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read deduped quarantine file");
    let quarantine_lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines.len(),
        256,
        "duplicate malformed noise should not crowd out distinct quarantine evidence"
    );

    let entries: Vec<Value> = quarantine_lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("quarantine row json"))
        .collect();
    assert_eq!(
        entries.first().and_then(|v| v["raw_line"].as_str()),
        Some("uniq-bad-1")
    );
    assert_eq!(
        entries.get(253).and_then(|v| v["raw_line"].as_str()),
        Some("uniq-bad-254")
    );
    assert_eq!(
        entries.get(254).and_then(|v| v["raw_line"].as_str()),
        Some("storm-dup")
    );
    assert_eq!(
        entries.last().and_then(|v| v["raw_line"].as_str()),
        Some("uniq-tail")
    );
    assert_eq!(
        entries
            .iter()
            .filter(|v| v["raw_line"].as_str() == Some("storm-dup"))
            .count(),
        1,
        "duplicate malformed rows should collapse to one quarantine record per salvage cycle"
    );
}

#[test]
fn submit_message_does_not_reintroduce_evicted_duplicate_noise_in_same_salvage_cycle() {
    let ingress = unique_fixture_path("submit_message_quarantine_evicted_duplicate_noise", "jsonl");
    let quarantine = ingress.with_file_name(format!(
        "{}.quarantine.jsonl",
        ingress
            .file_name()
            .and_then(|v| v.to_str())
            .expect("ingress file name")
    ));
    let _ = fs::remove_file(&ingress);
    let _ = fs::remove_file(&quarantine);

    let unique_prefix = (0..256)
        .map(|idx| format!("uniq-bad-{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    let duplicate_after_eviction = std::iter::repeat_n("uniq-bad-0".to_string(), 32)
        .collect::<Vec<_>>()
        .join("\n");
    let fixture = format!("{unique_prefix}\n{duplicate_after_eviction}\nuniq-tail\n");
    fs::write(&ingress, fixture).expect("write evicted-duplicate ingress fixture");

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

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read deduped quarantine file");
    let quarantine_lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines.len(),
        256,
        "quarantine cap should stay bounded"
    );

    let entries: Vec<Value> = quarantine_lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("quarantine row json"))
        .collect();
    assert_eq!(
        entries.first().and_then(|v| v["raw_line"].as_str()),
        Some("uniq-bad-1")
    );
    assert_eq!(
        entries.last().and_then(|v| v["raw_line"].as_str()),
        Some("uniq-tail")
    );
    assert_eq!(
        entries
            .iter()
            .filter(|v| v["raw_line"].as_str() == Some("uniq-bad-0"))
            .count(),
        0,
        "duplicates of an evicted malformed row should not re-enter the same salvage cycle"
    );
}

#[test]
fn submit_message_rewrites_preexisting_duplicate_quarantine_rows() {
    let ingress = unique_fixture_path("submit_message_quarantine_dedupe_existing", "jsonl");
    let quarantine = ingress.with_file_name(format!(
        "{}.quarantine.jsonl",
        ingress
            .file_name()
            .and_then(|v| v.to_str())
            .expect("ingress file name")
    ));
    let _ = fs::remove_file(&ingress);
    let _ = fs::remove_file(&quarantine);

    let valid = r#"{"request_id":"r-1","task_id":10001,"channel":"telegram","user_id":"u-1","session_id":"s-1","text":"hello","idempotency_key":"k-1","status":"Open","created_at_unix_ms":1}"#;
    fs::write(&ingress, format!("{}\nnot-json\n", valid)).expect("seed ingress");

    let duplicate_quarantine = serde_json::json!({
        "source_path": ingress.display().to_string(),
        "line_number": 2,
        "line_hash": expected_stable_line_hash("not-json"),
        "raw_line": "not-json",
        "error": "expected value at line 1 column 1",
        "quarantined_at_unix_ms": 1
    });
    let duplicate_line =
        serde_json::to_string(&duplicate_quarantine).expect("serialize quarantine");
    fs::write(
        &quarantine,
        format!("{}\n{}\n", duplicate_line, duplicate_line),
    )
    .expect("seed duplicate quarantine");

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

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read deduped quarantine file");
    let quarantine_lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines.len(),
        1,
        "replay should compact preexisting duplicate quarantine rows even without adding a new unique row"
    );
}
