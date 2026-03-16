use crate::{
    adapter_model::LlmAdapterResponse,
    proof_adapter_rules::{is_tee_receipt_adapter_label, is_zk_receipt_adapter_label},
    proof_adapter_verify::{
        validate_receipt_adapter_response, verify_standard_adapter_output,
        verify_tee_receipt_adapter_output, verify_zk_receipt_adapter_output,
    },
};

#[test]
fn verify_standard_adapter_output_accepts_non_empty() {
    let (ok, code) = verify_standard_adapter_output("hello", 200);
    assert!(ok);
    assert_eq!(code, "ok");
}

#[test]
fn verify_standard_adapter_output_rejects_control_only() {
    let (ok, code) = verify_standard_adapter_output("\u{001b}", 200);
    assert!(!ok);
    assert_eq!(code, "empty_output");
}

#[test]
fn verify_tee_receipt_adapter_output_maps_ok_to_tee_code() {
    let (ok, code) = verify_tee_receipt_adapter_output("hello", 200);
    assert!(ok);
    assert_eq!(code, "tee_receipt_ok");
}

#[test]
fn verify_zk_receipt_adapter_output_maps_ok_to_zk_code() {
    let (ok, code) = verify_zk_receipt_adapter_output("hello", 200);
    assert!(ok);
    assert_eq!(code, "zk_receipt_ok");
}

#[test]
fn validate_receipt_adapter_response_checks_request_id_and_adapter_label() {
    let payload = LlmAdapterResponse {
        output_text: "x".to_string(),
        provider_request_id: Some("abc-123".to_string()),
        provider: None,
        model: None,
        adapter: Some("TEE-RECEIPT".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    assert!(validate_receipt_adapter_response(
        "tee-receipt",
        &payload,
        is_tee_receipt_adapter_label
    )
    .is_ok());

    assert!(
        validate_receipt_adapter_response("zk-receipt", &payload, is_zk_receipt_adapter_label)
            .is_err()
    );
}
