use crate::proof_adapter::proof_adapter_core::ProofAdapter;
use crate::proof_adapter::StandardProofAdapter;
use crate::proof_adapter_utils::{
    last_balanced_json_object, normalize_adapter_label, normalize_adapter_value,
};

#[test]
fn adapter_label_normalization_peels_nested_and_shell_escaped_quote_wrappers() {
    assert_eq!(
        normalize_adapter_label(" '\"TEE_RECEIPT\"' "),
        "tee-receipt"
    );
    assert_eq!(normalize_adapter_value(" '\"ZK_PROOF\"' "), "zk-proof");
    assert_eq!(
        normalize_adapter_label(r#"\"TEE-ATTESTATION\""#),
        "tee-attestation"
    );
    assert_eq!(normalize_adapter_value(r#"\"ZK-RECEIPT\""#), "zk-receipt");
}

#[test]
fn adapter_label_normalization_peels_smart_and_localized_quote_wrappers() {
    assert_eq!(normalize_adapter_label("“TEE_RECEIPT”"), "tee-receipt");
    assert_eq!(normalize_adapter_value("‘ZK_PROOF’"), "zk-proof");
    assert_eq!(
        normalize_adapter_label("«TEE-ATTESTATION»"),
        "tee-attestation"
    );
    assert_eq!(normalize_adapter_value("‹zk receipt›"), "zk-receipt");
    assert_eq!(normalize_adapter_label("「TEE_RECEIPT」"), "tee-receipt");
    assert_eq!(normalize_adapter_value("『ZK_PROOF』"), "zk-proof");
    assert_eq!(
        normalize_adapter_label("〈TEE-ATTESTATION〉"),
        "tee-attestation"
    );
    assert_eq!(normalize_adapter_value("《ZK_RECEIPT》"), "zk-receipt");
    assert_eq!(normalize_adapter_label("⟨TEE_RECEIPT⟩"), "tee-receipt");
    assert_eq!(normalize_adapter_value("⟨ZK_PROOF⟩"), "zk-proof");
    assert_eq!(normalize_adapter_label(r#"\“TEE_RECEIPT\”"#), "tee-receipt");
    assert_eq!(normalize_adapter_value(r#"\‘ZK_PROOF\’"#), "zk-proof");
}
#[test]
fn last_balanced_json_object_ignores_braces_inside_strings() {
    let payload = "log {\"message\":\"brace } kept\"}\nlog {\"output_text\":\"ok\",\"provider_request_id\":\"r4\"}";
    let candidate = last_balanced_json_object(payload).expect("expected a balanced json object");
    assert_eq!(
        candidate,
        "{\"output_text\":\"ok\",\"provider_request_id\":\"r4\"}"
    );
}

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
