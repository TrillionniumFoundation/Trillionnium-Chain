use super::*;
#[test]
fn llm_adapter_tee_receipt_path_uses_adapter_parse_response_validation() {
    let cmd = "{\"output_text\":\"ok\",\"provider_request_id\":\"req-tee-1\",\"adapter\":\"tee-receipt\"}";
    let tee_adapter = build_proof_adapter("tee-receipt").expect("tee adapter");
    let parsed = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        cmd,
        Duration::from_secs(1),
        tee_adapter.as_ref(),
    )
    .expect("tee receipt payload should parse");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("req-tee-1"));
    assert_eq!(parsed.adapter.as_deref(), Some("tee-receipt"));

    let bad_cmd = "{\"output_text\":\"ok\",\"provider_request_id\":\"req-tee-2\"}";
    let err = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        bad_cmd,
        Duration::from_secs(1),
        tee_adapter.as_ref(),
    )
    .expect_err("missing adapter label must fail closed");
    assert_eq!(err.kind, AdapterErrorKind::NonRetriable);
    assert!(err.context.contains("tee-receipt-missing-adapter-label"));
}
