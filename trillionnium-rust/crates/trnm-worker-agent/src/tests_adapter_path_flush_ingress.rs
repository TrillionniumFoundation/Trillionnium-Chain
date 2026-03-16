use super::*;
#[test]
fn message_ingress_backward_compat_defaults_provider_request_id() {
    let raw = r#"{"request_id":"r1","task_id":7,"channel":"telegram","user_id":"u1","session_id":"s1","text":"hello","idempotency_key":"ik1","status":"assigned","created_at_unix_ms":1}"#;
    let rec: MessageIngressRecord = serde_json::from_str(raw).expect("parse ingress record");
    assert_eq!(rec.provider_request_id, None);
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}
