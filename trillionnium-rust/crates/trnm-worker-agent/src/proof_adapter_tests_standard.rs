use crate::proof_adapter::proof_adapter_core::ProofAdapter;
use crate::proof_adapter::StandardProofAdapter;

#[test]
fn standard_proof_adapter_reports_verifier_decision_and_reason_code() {
    let adapter = StandardProofAdapter;

    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let (ok, code) = adapter.verify("\u{200B}\u{200C}", 8);
    assert!(!ok);
    assert_eq!(code, "empty_output");

    let (ok, code) = adapter.verify("你好abc", 4);
    assert!(!ok);
    assert_eq!(code, "output_too_long");
}

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

#[test]
fn standard_proof_adapter_parse_response_accepts_json_after_ansi_csi_logs() {
    let adapter = StandardProofAdapter;
    let stdout = "\u{1b}[2K\u{1b}[32minfo\u{1b}[0m warmup\n\u{1b}[33m{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-csi\"}\u{1b}[0m\n";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json wrapped in ansi csi sequences");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-csi"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_after_ansi_osc_logs() {
    let adapter = StandardProofAdapter;
    let stdout = "\u{1b}]0;worker-agent\u{7}info: warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-osc\"}\n\u{1b}]133;C\u{1b}\\";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with ansi osc noise around it");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-osc"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_after_ansi_dcs_logs() {
    let adapter = StandardProofAdapter;
    let stdout = "\u{1b}Ptmux;warmup=1\u{1b}\\info: warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-dcs\"}\n\u{1b}Ptmux;cleanup=1\u{1b}\\";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with ansi dcs noise around it");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-dcs"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_after_ansi_apc_logs() {
    let adapter = StandardProofAdapter;
    let stdout = "\u{1b}_apc warmup\u{1b}\\info: warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-apc\"}\n\u{1b}_apc cleanup\u{1b}\\";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with ansi apc noise around it");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-apc"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_after_ansi_pm_logs() {
    let adapter = StandardProofAdapter;
    let stdout = "\u{1b}^pm warmup\u{1b}\\info: warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-pm\"}\n\u{1b}^pm cleanup\u{1b}\\";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with ansi pm noise around it");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-pm"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_after_raw_control_byte_noise() {
    let adapter = StandardProofAdapter;
    let stdout = "\0\u{2}info: warmup\u{1f}\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-control-noise\"}\0\u{3}";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with raw control-byte noise around it");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(
        parsed.provider_request_id.as_deref(),
        Some("r3-control-noise")
    );
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_with_raw_control_byte_prefix() {
    let adapter = StandardProofAdapter;
    let stdout = "\0\u{2}{\"output_text\":\"ok\",\"provider_request_id\":\"r3-control-prefix\"}";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with raw control-byte prefix");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(
        parsed.provider_request_id.as_deref(),
        Some("r3-control-prefix")
    );
}
