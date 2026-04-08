use crate::proof_adapter::proof_adapter_core::ProofAdapter;
use crate::proof_adapter::StandardProofAdapter;

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
