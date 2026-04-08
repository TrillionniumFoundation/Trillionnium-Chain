use super::*;

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
