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

fn run_submit_message(ingress: &PathBuf, text: &str, key: &str) -> std::process::Output {
    Command::new("cargo")
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "submit-message",
            "--channel",
            "telegram",
            "--user-id",
            "u-meta",
            "--session-id",
            "s-meta",
            "--text",
            text,
            "--idempotency-key",
            key,
        ])
        .env("TRNM_RPC_INGRESS_FILE", ingress)
        .output()
        .expect("run submit-message")
}

#[test]
fn submit_message_accepts_schema_core_metadata_payload() {
    let ingress = unique_fixture_path("submit_message_metadata_ok", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"prompt":"run","metadata":{"task_type":"inference","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","model":{"model_id":"trnm-vision-base","model_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","version":"v1.0.0"},"provenance":{"producer_did":"did:trnm:org:lane-dae","produced_at":"2026-03-01T01:00:00Z","provenance_index":"prov:lane-dae:task-20260301-0001","privacy_tier":"internal"}}}"#;

    let output = run_submit_message(&ingress, text, "k-meta-ok");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn submit_message_accepts_restricted_privacy_tier_with_provenance_index() {
    let ingress = unique_fixture_path("submit_message_metadata_restricted_ok", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"prompt":"run","metadata":{"task_type":"inference","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provenance":{"producer_did":"did:trnm:org:lane-dae","produced_at":"2026-03-01T01:00:00Z","provenance_index":"prov:lane-dae:task-20260301-0099","privacy_tier":"restricted"}}}"#;

    let output = run_submit_message(&ingress, text, "k-meta-restricted-ok");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn submit_message_rejects_invalid_metadata_hash_shape() {
    let ingress = unique_fixture_path("submit_message_metadata_bad", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"metadata":{"task_type":"inference","input_hash":"NOT_HEX"}}"#;
    let output = run_submit_message(&ingress, text, "k-meta-bad");

    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("metadata.input_hash must be 64-char lowercase hex"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn submit_message_rejects_task_type_with_whitespace() {
    let ingress = unique_fixture_path("submit_message_metadata_bad_task_type", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"metadata":{"task_type":"inference batch","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let output = run_submit_message(&ingress, text, "k-meta-bad-task-type");

    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("metadata.task_type must be non-empty and whitespace-free"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn submit_message_rejects_public_privacy_tier_with_provenance_index() {
    let ingress = unique_fixture_path("submit_message_metadata_public_index_reject", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"prompt":"run","metadata":{"task_type":"inference","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provenance":{"producer_did":"did:trnm:org:lane-dae","produced_at":"2026-03-01T01:00:00Z","provenance_index":"prov:lane-dae:task-20260301-0002","privacy_tier":"public"}}}"#;

    let output = run_submit_message(&ingress, text, "k-meta-public-index");
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "metadata.provenance.provenance_index must be absent when privacy_tier=public"
        ),
        "stderr: {}",
        stderr
    );
}

#[test]
fn submit_message_rejects_internal_privacy_tier_without_provenance_index() {
    let ingress = unique_fixture_path("submit_message_metadata_internal_missing_index", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"prompt":"run","metadata":{"task_type":"inference","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provenance":{"producer_did":"did:trnm:org:lane-dae","produced_at":"2026-03-01T01:00:00Z","privacy_tier":"internal"}}}"#;

    let output = run_submit_message(&ingress, text, "k-meta-internal-missing-index");
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("metadata.provenance.provenance_index is required when privacy_tier=internal|restricted"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn submit_message_rejects_provenance_index_with_whitespace() {
    let ingress = unique_fixture_path("submit_message_metadata_whitespace_index", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"prompt":"run","metadata":{"task_type":"inference","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provenance":{"producer_did":"did:trnm:org:lane-dae","produced_at":"2026-03-01T01:00:00Z","provenance_index":"prov:lane dae:task-20260301-0003","privacy_tier":"internal"}}}"#;

    let output = run_submit_message(&ingress, text, "k-meta-whitespace-index");
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("metadata.provenance.provenance_index must use prov:* canonical form"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn submit_message_rejects_non_canonical_produced_at_timestamp() {
    let ingress = unique_fixture_path("submit_message_metadata_bad_produced_at", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"prompt":"run","metadata":{"task_type":"inference","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provenance":{"producer_did":"did:trnm:org:lane-dae","produced_at":"2026-03-01 01:00:00+08:00","provenance_index":"prov:lane-dae:task-20260301-0004","privacy_tier":"internal"}}}"#;

    let output = run_submit_message(&ingress, text, "k-meta-bad-produced-at");
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .contains("metadata.provenance.produced_at must be canonical RFC3339 UTC Z timestamp"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn submit_message_rejects_calendar_invalid_produced_at_timestamp() {
    let ingress = unique_fixture_path("submit_message_metadata_calendar_bad_produced_at", "jsonl");
    let _ = fs::remove_file(&ingress);

    let text = r#"{"prompt":"run","metadata":{"task_type":"inference","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provenance":{"producer_did":"did:trnm:org:lane-dae","produced_at":"2026-13-01T01:00:00Z","provenance_index":"prov:lane-dae:task-20260301-0005","privacy_tier":"internal"}}}"#;

    let output = run_submit_message(&ingress, text, "k-meta-calendar-bad-produced-at");
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .contains("metadata.provenance.produced_at must be canonical RFC3339 UTC Z timestamp"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn submit_message_rejects_payload_over_configured_byte_limit() {
    let ingress = unique_fixture_path("submit_message_payload_too_large", "jsonl");
    let _ = fs::remove_file(&ingress);

    let oversized = "x".repeat(33);
    let output = Command::new("cargo")
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "submit-message",
            "--channel",
            "telegram",
            "--user-id",
            "u-meta",
            "--session-id",
            "s-meta",
            "--text",
            oversized.as_str(),
            "--idempotency-key",
            "k-meta-too-large",
        ])
        .env("TRNM_RPC_INGRESS_FILE", &ingress)
        .env("TRNM_RPC_SUBMIT_MESSAGE_MAX_BYTES", "32")
        .output()
        .expect("run submit-message with max bytes override");

    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("submit-message text exceeds 32 bytes limit (got 33)"),
        "stderr: {}",
        stderr
    );
}
