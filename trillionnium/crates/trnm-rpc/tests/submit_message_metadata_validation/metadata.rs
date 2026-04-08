use super::*;

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
