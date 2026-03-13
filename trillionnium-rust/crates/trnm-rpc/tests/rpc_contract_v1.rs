use serde_json::json;
use trnm_rpc::{
    AccountBalanceQueryResponse, AccountNonceQueryResponse, EventQueryResponse, GetTxResponse,
    RpcErrorResponse, SendTxResponse, TaskMeteringDerivedQueryResponse,
    TaskMeteringPolicyQueryResponse, TaskMeteringQueryResponse, TxStatus,
};

#[test]
fn contract_balance_shape_stable() {
    let v = serde_json::to_value(AccountBalanceQueryResponse {
        address: "trnm1abc".into(),
        balance: 1,
        version: 1,
    })
    .unwrap();
    assert_eq!(v, json!({"address":"trnm1abc","balance":1,"version":1}));
}

#[test]
fn contract_nonce_shape_stable() {
    let v = serde_json::to_value(AccountNonceQueryResponse {
        address: "trnm1abc".into(),
        nonce: 7,
        version: 1,
    })
    .unwrap();
    assert_eq!(v, json!({"address":"trnm1abc","nonce":7,"version":1}));
}

#[test]
fn contract_sendtx_shape_stable() {
    let v = serde_json::to_value(SendTxResponse {
        tx_hash: "0xabc".into(),
        status: TxStatus::Pending,
    })
    .unwrap();
    assert_eq!(v, json!({"tx_hash":"0xabc","status":"pending"}));
}

#[test]
fn contract_gettx_shape_stable() {
    let v = serde_json::to_value(GetTxResponse {
        tx_hash: "0xabc".into(),
        status: TxStatus::Committed,
        error: None,
    })
    .unwrap();
    assert_eq!(
        v,
        json!({"tx_hash":"0xabc","status":"committed","error":null})
    );
}

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
        metering: None,
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
        metering: None,
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

#[test]
fn contract_event_shape_includes_metering_when_present() {
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
        metering: Some(TaskMeteringQueryResponse {
            workload_class: "llm_inference".into(),
            metering_schema: "llm_token_meter_v1".into(),
            receipt_hash: "deadbeef".into(),
            prompt_tokens: 128,
            generated_tokens: 32,
            decode_steps: 32,
            kv_bytes_moved: 4096,
            normalized_work_units: 192,
            prompt_token_weight: 1,
            generated_token_weight: 1,
            decode_step_weight: 1,
            kv_byte_weight: 0,
            policy: TaskMeteringPolicyQueryResponse {
                snapshot_version: 1,
                min_accept_work_units: 100,
                challenge_success_bounty_base: 1,
                challenge_success_bounty_per_work_unit_num: 1,
                challenge_success_bounty_per_work_unit_den: 192,
                worker_completion_bonus_per_work_unit_num: 1,
                worker_completion_bonus_per_work_unit_den: 256,
                worker_slash_rebate_per_work_unit_num: 1,
                worker_slash_rebate_per_work_unit_den: 384,
            },
            derived: TaskMeteringDerivedQueryResponse {
                path: "Resolved".into(),
                accept_floor_pass: true,
                challenge_metered_bonus: 1,
                challenge_bonus_total: 2,
                worker_completion_bonus: 1,
                worker_slash_rebate: 1,
            },
        }),
    })
    .unwrap();
    assert_eq!(v["metering"]["normalized_work_units"], json!(192));
    assert_eq!(v["metering"]["policy"]["snapshot_version"], json!(1));
    assert_eq!(v["metering"]["derived"]["challenge_bonus_total"], json!(2));
}

#[test]
fn contract_error_codes_stable() {
    let invalid = RpcErrorResponse {
        code: "INVALID_ADDRESS",
        message: "bad".into(),
    };
    let not_found = RpcErrorResponse {
        code: "ACCOUNT_NOT_FOUND",
        message: "nf".into(),
    };
    let tx_nf = RpcErrorResponse {
        code: "TX_NOT_FOUND",
        message: "tx".into(),
    };

    assert_eq!(invalid.code, "INVALID_ADDRESS");
    assert_eq!(not_found.code, "ACCOUNT_NOT_FOUND");
    assert_eq!(tx_nf.code, "TX_NOT_FOUND");
}
