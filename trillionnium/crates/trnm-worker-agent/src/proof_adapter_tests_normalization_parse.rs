use super::*;

#[test]
fn standard_proof_adapter_parse_response_accepts_json_with_utf8_bom_prefix() {
    let adapter = StandardProofAdapter;
    let stdout = "\u{feff}{\"output_text\":\"ok\",\"provider_request_id\":\"r5\"}";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with leading utf-8 bom");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r5"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_with_whitespace_then_bom_prefix() {
    let adapter = StandardProofAdapter;
    let stdout = "\n  \u{feff}{\"output_text\":\"ok\",\"provider_request_id\":\"r6\"}";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with whitespace before utf-8 bom");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r6"));
}

#[test]
fn standard_proof_adapter_parse_response_accepts_json_with_zero_width_filler_prefix() {
    let adapter = StandardProofAdapter;
    let stdout =
        "\u{200b}\u{200c}\u{2060}{\"output_text\":\"ok\",\"provider_request_id\":\"r6-zwsp\"}";

    let parsed = adapter
        .parse_response(stdout)
        .expect("should parse json with zero-width filler prefix");
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r6-zwsp"));
}

#[test]
fn standard_proof_adapter_parse_response_rejects_without_json_line() {
    let adapter = StandardProofAdapter;
    let err = adapter
        .parse_response("debug:warmup\nstatus=ok\n")
        .expect_err("missing json should be rejected");
    assert_eq!(err, "no-json-line");
}
