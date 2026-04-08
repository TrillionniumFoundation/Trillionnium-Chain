use crate::proof_adapter::proof_adapter_core::ProofAdapter;
use crate::proof_adapter::StandardProofAdapter;

#[test]
fn standard_proof_adapter_parse_response_accepts_last_json_line_after_noise() {
    let adapter = StandardProofAdapter;
    let stdout = "debug:warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r1\"}\n";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse trailing json line");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r1"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_embedded_in_log_line() {
    let adapter = StandardProofAdapter;
    let stdout = "info:adapter payload={\"output_text\":\"ok\",\"provider_request_id\":\"r2\"}\n";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json embedded in log line");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r2"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_prefix_before_trailing_logs() {
    let adapter = StandardProofAdapter;
    let stdout =
        "{\"output_text\":\"ok\",\"provider_request_id\":\"r2-prefix\"}\ninfo: cleanup complete\n";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse leading json object before trailing logs");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r2-prefix"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_multiline_json_payload() {
    let adapter = StandardProofAdapter;
    let stdout = "info: warmup\n```json\n{\n  \"output_text\": \"ok\",\n  \"provider_request_id\": \"r3\"\n}\n```\n";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse multiline json payload");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r3"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_crlf_fenced_multiline_json_payload() {
    let adapter = StandardProofAdapter;
    let stdout = "info: warmup\r\n```json\r\n{\r\n  \"output_text\": \"ok\",\r\n  \"provider_request_id\": \"r3-crlf\"\r\n}\r\n```\r\n";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse CRLF multiline json payload");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-crlf"));
}
