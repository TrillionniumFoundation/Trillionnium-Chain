use super::*;

#[test]
fn submit_message_rejects_payload_over_configured_byte_limit() {
    let ingress = unique_fixture_path("submit_message_payload_too_large", "jsonl");
    let _ = fs::remove_file(&ingress);

    let oversized = "x".repeat(33);
    let output = Command::new("cargo")
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
