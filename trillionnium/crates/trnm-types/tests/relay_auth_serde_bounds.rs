use serde_json::json;
use trnm_types::{RelayAuthEnvelope, RelayEnvelope, RelaySession};

fn valid_wire() -> serde_json::Value {
    json!({
        "version": RelayAuthEnvelope::SPEC_VERSION,
        "chain_id": "trnm-mainnet",
        "task_id": "task-1",
        "session_id": "session-1",
        "seq": 1,
        "timestamp_ms": 1_730_000_000_000u64,
        "msg_type": "INPUT_CHUNK",
        "from": "trnm1from",
        "to": "trnm1to",
        "nonce": "nonce-1",
        "payload": [1, 2, 3],
        "payload_hash": RelayAuthEnvelope::payload_hash_hex(&[1, 2, 3]),
        "sig": "test"
    })
}

#[test]
fn relay_auth_serde_rejects_oversized_identity_fields() {
    let mut value = valid_wire();
    value["task_id"] = json!("x".repeat(257));
    assert!(serde_json::from_value::<RelayAuthEnvelope>(value).is_err());
}

#[test]
fn relay_auth_serde_rejects_unknown_fields() {
    let mut value = valid_wire();
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<RelayAuthEnvelope>(value).is_err());
}

#[test]
fn relay_records_serde_reject_oversized_fields() {
    let envelope = json!({
        "envelope_id": 1,
        "session_id": "session-1",
        "sequence": 1,
        "route": "x".repeat(257),
        "from": "worker-a",
        "to": null,
        "payload": [1, 2, 3],
        "created_at_unix_ms": 1
    });
    assert!(serde_json::from_value::<RelayEnvelope>(envelope).is_err());

    let session = json!({
        "session_id": "x".repeat(257),
        "status": "Open",
        "created_at_unix_ms": 1,
        "closed_at_unix_ms": null
    });
    assert!(serde_json::from_value::<RelaySession>(session).is_err());
}

