use super::*;

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
