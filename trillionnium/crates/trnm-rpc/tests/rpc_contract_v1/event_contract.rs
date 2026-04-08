use super::*;

#[test]
fn contract_event_shape_backward_compatible_when_audit_fields_absent() {
    let v = serde_json::to_value(EventQueryResponse {
        event_type: "commit".into(),
        task_id: 7,
        from_status: "Assigned".into(),
        to_status: "Committed".into(),
        actor: "worker-1".into(),
        tx_id: 11,
        block_height: 3,
        state_root: "0xabc".into(),
        ts_unix_ms: 123,
        signer: None,
        challenger: None,
        tx_hash: None,
        resolution_code: None,
        treasury_delta: None,
        challenger_delta: None,
        bond_disposition: None,
    })
    .unwrap();
    assert_eq!(
        v,
        json!({
            "event_type":"commit",
            "task_id":7,
            "from_status":"Assigned",
            "to_status":"Committed",
            "actor":"worker-1",
            "tx_id":11,
            "block_height":3,
            "state_root":"0xabc",
            "ts_unix_ms":123
        })
    );
}

#[test]
fn contract_event_shape_includes_audit_fields_when_present() {
    let v = serde_json::to_value(EventQueryResponse {
        event_type: "resolve".into(),
        task_id: 7,
        from_status: "Challenged".into(),
        to_status: "Resolved".into(),
        actor: "authority".into(),
        tx_id: 12,
        block_height: 4,
        state_root: "0xdef".into(),
        ts_unix_ms: 124,
        signer: Some("authority".into()),
        challenger: Some("challenger-a".into()),
        tx_hash: Some("0x123".into()),
        resolution_code: Some("completed".into()),
        treasury_delta: Some(0),
        challenger_delta: Some(0),
        bond_disposition: Some("forfeited".into()),
    })
    .unwrap();
    assert_eq!(
        v,
        json!({
            "event_type":"resolve",
            "task_id":7,
            "from_status":"Challenged",
            "to_status":"Resolved",
            "actor":"authority",
            "tx_id":12,
            "block_height":4,
            "state_root":"0xdef",
            "ts_unix_ms":124,
            "signer":"authority",
            "challenger":"challenger-a",
            "tx_hash":"0x123",
            "resolution_code":"completed",
            "treasury_delta":0,
            "challenger_delta":0,
            "bond_disposition":"forfeited"
        })
    );
}
