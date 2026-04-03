use serde_json::json;
use trnm_rpc::{
    AccountBalanceQueryResponse, AccountNonceQueryResponse, AccountState, EventQueryResponse,
    FaucetRequestResponse, GetTxResponse, GovParamQueryResponse, GovProposalQueryResponse,
    OracleValidateSnapshotResponse, RequestFullQueryResponse, RpcErrorResponse, SendTxResponse,
    TaskMeteringDerivedQueryResponse, TaskMeteringPolicyQueryResponse,
    TaskMeteringQueryResponse, TaskQueryResponse, TxStatus,
};

#[test]
fn contract_account_state_shape_stable() {
    let v = serde_json::to_value(AccountState {
        address: "trnm1abc".into(),
        balance: 1,
        nonce: 7,
    })
    .unwrap();
    assert_eq!(v, json!({"address":"trnm1abc","balance":1,"nonce":7}));
}

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

#[test]
fn contract_error_response_shape_stable() {
    let value = serde_json::to_value(RpcErrorResponse {
        code: "INVALID_ADDRESS",
        message: "bad".into(),
    })
    .unwrap();
    assert_eq!(value, json!({"code":"INVALID_ADDRESS","message":"bad"}));
}

#[test]
fn contract_gov_param_shape_omits_pending_update_when_absent() {
    let v = serde_json::to_value(GovParamQueryResponse {
        key_id: 7,
        key: "runtime_metadata_schema".into(),
        value: "v2".into(),
        version: 3,
        pending_update: None,
    })
    .unwrap();

    assert_eq!(
        v,
        json!({
            "key_id":7,
            "key":"runtime_metadata_schema",
            "value":"v2",
            "version":3
        })
    );
}

#[test]
fn contract_gov_param_shape_includes_pending_update_when_present() {
    let v = serde_json::to_value(GovParamQueryResponse {
        key_id: 7,
        key: "runtime_metadata_schema".into(),
        value: "v2".into(),
        version: 3,
        pending_update: Some(trnm_rpc::PendingGovParamUpdateQueryResponse {
            key_id: 7,
            key: "runtime_metadata_schema".into(),
            value: "v3".into(),
            activate_at_height: 4096,
        }),
    })
    .unwrap();

    assert_eq!(
        v,
        json!({
            "key_id":7,
            "key":"runtime_metadata_schema",
            "value":"v2",
            "version":3,
            "pending_update": {
                "key_id":7,
                "key":"runtime_metadata_schema",
                "value":"v3",
                "activate_at_height":4096
            }
        })
    );
}

#[test]
fn contract_oracle_validate_snapshot_shape_stable() {
    let v = serde_json::to_value(OracleValidateSnapshotResponse {
        ok: true,
        now_ts_ms: 1_710_000_000_123,
        observation: trnm_oracle::OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 1,
        },
        metrics: trnm_oracle::OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 1,
            accepted_total: 1,
            sample_count: 1,
        },
        error: None,
    })
    .unwrap();

    assert_eq!(
        v,
        json!({
            "ok": true,
            "now_ts_ms": 1710000000123u64,
            "observation": {
                "stale_reject_total": 0,
                "quorum_reject_total": 0,
                "drift_reject_total": 0,
                "accepted_total": 1
            },
            "metrics": {
                "oracle_stale_reject_total": 0,
                "oracle_quorum_reject_total": 0,
                "oracle_drift_reject_total": 0,
                "oracle_source_cardinality": 1,
                "accepted_total": 1,
                "sample_count": 1
            }
        })
    );
}

#[test]
fn contract_public_read_payloads_reject_unknown_top_level_fields() {
    let event_err = serde_json::from_value::<EventQueryResponse>(json!({
        "event_type":"commit",
        "task_id":7,
        "from_status":"Assigned",
        "to_status":"Committed",
        "actor":"worker-1",
        "tx_id":11,
        "block_height":3,
        "state_root":"0xabc",
        "ts_unix_ms":123,
        "unexpected":"schema-drift"
    }))
    .expect_err("event contract should fail closed on unknown fields");
    assert!(event_err.to_string().contains("unexpected"));

    let task_err = serde_json::from_value::<TaskQueryResponse>(json!({
        "task_id":7,
        "status":"Open",
        "worker":"worker-1",
        "bounty":42,
        "result_hash_hex":null,
        "version":3,
        "unexpected":"schema-drift"
    }))
    .expect_err("task contract should fail closed on unknown fields");
    assert!(task_err.to_string().contains("unexpected"));

    let gov_proposal_err = serde_json::from_value::<GovProposalQueryResponse>(json!({
        "proposal_id":9,
        "title":"freeze economics tuple",
        "proposer":"validator-1",
        "status":"Voting",
        "version":2,
        "unexpected":true
    }))
    .expect_err("gov proposal contract should fail closed on unknown fields");
    assert!(gov_proposal_err.to_string().contains("unexpected"));

    let request_err = serde_json::from_value::<RequestFullQueryResponse>(json!({
        "request": {
            "request_id":"req-1",
            "task_id":7,
            "channel":"discord",
            "user_id":"u-1",
            "session_id":"s-1",
            "text":"hello",
            "idempotency_key":"idem-1",
            "status":"accepted",
            "created_at_unix_ms":123
        },
        "verifier_status": null,
        "resolution_code": null,
        "result_hash": null,
        "commit_tx_hash": null,
        "reveal_tx_hash": null,
        "events": [],
        "unexpected": true
    }))
    .expect_err("request contract should fail closed on unknown fields");
    assert!(request_err.to_string().contains("unexpected"));

    let nested_request_err = serde_json::from_value::<RequestFullQueryResponse>(json!({
        "request": {
            "request_id":"req-1",
            "task_id":7,
            "channel":"discord",
            "user_id":"u-1",
            "session_id":"s-1",
            "text":"hello",
            "idempotency_key":"idem-1",
            "status":"accepted",
            "created_at_unix_ms":123,
            "unexpected":"schema-drift"
        },
        "verifier_status": null,
        "resolution_code": null,
        "result_hash": null,
        "commit_tx_hash": null,
        "reveal_tx_hash": null,
        "events": []
    }))
    .expect_err("nested request contract should fail closed on unknown fields");
    assert!(nested_request_err.to_string().contains("unexpected"));

    let nested_event_err = serde_json::from_value::<RequestFullQueryResponse>(json!({
        "request": {
            "request_id":"req-1",
            "task_id":7,
            "channel":"discord",
            "user_id":"u-1",
            "session_id":"s-1",
            "text":"hello",
            "idempotency_key":"idem-1",
            "status":"accepted",
            "created_at_unix_ms":123
        },
        "verifier_status": null,
        "resolution_code": null,
        "result_hash": null,
        "commit_tx_hash": null,
        "reveal_tx_hash": null,
        "events": [{
            "event_type":"commit",
            "task_id":7,
            "from_status":"Assigned",
            "to_status":"Committed",
            "actor":"worker-1",
            "tx_id":11,
            "block_height":3,
            "state_root":"0xabc",
            "ts_unix_ms":123,
            "unexpected":true
        }]
    }))
    .expect_err("nested event contract should fail closed on unknown fields");
    assert!(nested_event_err.to_string().contains("unexpected"));

    let nested_task_metering_err = serde_json::from_value::<TaskQueryResponse>(json!({
        "task_id":7,
        "status":"Open",
        "worker":"worker-1",
        "bounty":42,
        "result_hash_hex":"0xabc",
        "version":3,
        "metering": {
            "workload_class":"llm_inference",
            "metering_schema":"llm_token_meter_v1",
            "receipt_hash":"deadbeef",
            "prompt_tokens":128,
            "generated_tokens":32,
            "decode_steps":32,
            "kv_bytes_moved":4096,
            "normalized_work_units":192,
            "prompt_token_weight":1,
            "generated_token_weight":1,
            "decode_step_weight":1,
            "kv_byte_weight":0,
            "policy": {
                "snapshot_version":1,
                "min_accept_work_units":100,
                "challenge_success_bounty_base":1,
                "challenge_success_bounty_per_work_unit_num":1,
                "challenge_success_bounty_per_work_unit_den":192,
                "worker_completion_bonus_per_work_unit_num":1,
                "worker_completion_bonus_per_work_unit_den":256,
                "worker_slash_rebate_per_work_unit_num":1,
                "worker_slash_rebate_per_work_unit_den":384
            },
            "derived": {
                "path":"Resolved",
                "accept_floor_pass":true,
                "challenge_metered_bonus":1,
                "challenge_bonus_total":2,
                "worker_completion_bonus":1,
                "worker_slash_rebate":1
            },
            "unexpected":"schema-drift"
        }
    }))
    .expect_err("nested task metering contract should fail closed on unknown fields");
    assert!(nested_task_metering_err.to_string().contains("unexpected"));

    let nested_task_metering_policy_err = serde_json::from_value::<TaskQueryResponse>(json!({
        "task_id":7,
        "status":"Open",
        "worker":"worker-1",
        "bounty":42,
        "result_hash_hex":"0xabc",
        "version":3,
        "metering": {
            "workload_class":"llm_inference",
            "metering_schema":"llm_token_meter_v1",
            "receipt_hash":"deadbeef",
            "prompt_tokens":128,
            "generated_tokens":32,
            "decode_steps":32,
            "kv_bytes_moved":4096,
            "normalized_work_units":192,
            "prompt_token_weight":1,
            "generated_token_weight":1,
            "decode_step_weight":1,
            "kv_byte_weight":0,
            "policy": {
                "snapshot_version":1,
                "min_accept_work_units":100,
                "challenge_success_bounty_base":1,
                "challenge_success_bounty_per_work_unit_num":1,
                "challenge_success_bounty_per_work_unit_den":192,
                "worker_completion_bonus_per_work_unit_num":1,
                "worker_completion_bonus_per_work_unit_den":256,
                "worker_slash_rebate_per_work_unit_num":1,
                "worker_slash_rebate_per_work_unit_den":384,
                "unexpected":"schema-drift"
            },
            "derived": {
                "path":"Resolved",
                "accept_floor_pass":true,
                "challenge_metered_bonus":1,
                "challenge_bonus_total":2,
                "worker_completion_bonus":1,
                "worker_slash_rebate":1
            }
        }
    }))
    .expect_err("nested task metering policy contract should fail closed on unknown fields");
    assert!(nested_task_metering_policy_err.to_string().contains("unexpected"));

    let nested_task_metering_derived_err = serde_json::from_value::<TaskQueryResponse>(json!({
        "task_id":7,
        "status":"Open",
        "worker":"worker-1",
        "bounty":42,
        "result_hash_hex":"0xabc",
        "version":3,
        "metering": {
            "workload_class":"llm_inference",
            "metering_schema":"llm_token_meter_v1",
            "receipt_hash":"deadbeef",
            "prompt_tokens":128,
            "generated_tokens":32,
            "decode_steps":32,
            "kv_bytes_moved":4096,
            "normalized_work_units":192,
            "prompt_token_weight":1,
            "generated_token_weight":1,
            "decode_step_weight":1,
            "kv_byte_weight":0,
            "policy": {
                "snapshot_version":1,
                "min_accept_work_units":100,
                "challenge_success_bounty_base":1,
                "challenge_success_bounty_per_work_unit_num":1,
                "challenge_success_bounty_per_work_unit_den":192,
                "worker_completion_bonus_per_work_unit_num":1,
                "worker_completion_bonus_per_work_unit_den":256,
                "worker_slash_rebate_per_work_unit_num":1,
                "worker_slash_rebate_per_work_unit_den":384
            },
            "derived": {
                "path":"Resolved",
                "accept_floor_pass":true,
                "challenge_metered_bonus":1,
                "challenge_bonus_total":2,
                "worker_completion_bonus":1,
                "worker_slash_rebate":1,
                "unexpected":"schema-drift"
            }
        }
    }))
    .expect_err("nested task metering derived contract should fail closed on unknown fields");
    assert!(nested_task_metering_derived_err.to_string().contains("unexpected"));

    let gov_param_err = serde_json::from_value::<GovParamQueryResponse>(json!({
        "key_id":1,
        "key":"runtime_metadata_schema",
        "value":"v2",
        "version":3,
        "unexpected":"schema-drift"
    }))
    .expect_err("gov param contract should fail closed on unknown fields");
    assert!(gov_param_err.to_string().contains("unexpected"));

    let pending_update_err = serde_json::from_value::<GovParamQueryResponse>(json!({
        "key_id":1,
        "key":"runtime_metadata_schema",
        "value":"v2",
        "version":3,
        "pending_update": {
            "key_id":1,
            "key":"runtime_metadata_schema",
            "value":"v3",
            "activate_at_height":100,
            "unexpected":"schema-drift"
        }
    }))
    .expect_err("pending update contract should fail closed on unknown fields");
    assert!(pending_update_err.to_string().contains("unexpected"));

    let account_state_err = serde_json::from_value::<AccountState>(json!({
        "address":"trnm1abc",
        "balance":1,
        "nonce":7,
        "unexpected":true
    }))
    .expect_err("account state contract should fail closed on unknown fields");
    assert!(account_state_err.to_string().contains("unexpected"));

    let balance_err = serde_json::from_value::<AccountBalanceQueryResponse>(json!({
        "address":"trnm1abc",
        "balance":1,
        "version":1,
        "unexpected":true
    }))
    .expect_err("account balance contract should fail closed on unknown fields");
    assert!(balance_err.to_string().contains("unexpected"));

    let nonce_err = serde_json::from_value::<AccountNonceQueryResponse>(json!({
        "address":"trnm1abc",
        "nonce":7,
        "version":1,
        "unexpected":true
    }))
    .expect_err("account nonce contract should fail closed on unknown fields");
    assert!(nonce_err.to_string().contains("unexpected"));

    let sendtx_err = serde_json::from_value::<SendTxResponse>(json!({
        "tx_hash":"0xabc",
        "status":"pending",
        "unexpected":true
    }))
    .expect_err("sendtx contract should fail closed on unknown fields");
    assert!(sendtx_err.to_string().contains("unexpected"));

    let gettx_err = serde_json::from_value::<GetTxResponse>(json!({
        "tx_hash":"0xabc",
        "status":"committed",
        "error":null,
        "unexpected":true
    }))
    .expect_err("gettx contract should fail closed on unknown fields");
    assert!(gettx_err.to_string().contains("unexpected"));

    let faucet_err = serde_json::from_value::<FaucetRequestResponse>(json!({
        "ok":true,
        "code":"OK",
        "message":"granted",
        "address":"trnm1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "requested_amount":1,
        "granted_amount":1,
        "balance":1,
        "nonce":1,
        "window_seconds":60,
        "next_allowed_unix_ms":123,
        "version":1,
        "unexpected":true
    }))
    .expect_err("faucet contract should fail closed on unknown fields");
    assert!(faucet_err.to_string().contains("unexpected"));

    let oracle_err = serde_json::from_value::<OracleValidateSnapshotResponse>(json!({
        "ok": true,
        "now_ts_ms": 1710000000123u64,
        "observation": {
            "stale_reject_total": 0,
            "quorum_reject_total": 0,
            "drift_reject_total": 0,
            "accepted_total": 1
        },
        "metrics": {
            "oracle_stale_reject_total": 0,
            "oracle_quorum_reject_total": 0,
            "oracle_drift_reject_total": 0,
            "oracle_source_cardinality": 1,
            "accepted_total": 1,
            "sample_count": 1
        },
        "unexpected": false
    }))
    .expect_err("oracle validation contract should fail closed on unknown fields");
    assert!(oracle_err.to_string().contains("unexpected"));

    let oracle_observation_err = serde_json::from_value::<OracleValidateSnapshotResponse>(json!({
        "ok": true,
        "now_ts_ms": 1710000000123u64,
        "observation": {
            "stale_reject_total": 0,
            "quorum_reject_total": 0,
            "drift_reject_total": 0,
            "accepted_total": 1,
            "unexpected": 7
        },
        "metrics": {
            "oracle_stale_reject_total": 0,
            "oracle_quorum_reject_total": 0,
            "oracle_drift_reject_total": 0,
            "oracle_source_cardinality": 1,
            "accepted_total": 1,
            "sample_count": 1
        }
    }))
    .expect_err("oracle observation contract should fail closed on unknown fields");
    assert!(oracle_observation_err.to_string().contains("unexpected"));

    let oracle_metrics_err = serde_json::from_value::<OracleValidateSnapshotResponse>(json!({
        "ok": true,
        "now_ts_ms": 1710000000123u64,
        "observation": {
            "stale_reject_total": 0,
            "quorum_reject_total": 0,
            "drift_reject_total": 0,
            "accepted_total": 1
        },
        "metrics": {
            "oracle_stale_reject_total": 0,
            "oracle_quorum_reject_total": 0,
            "oracle_drift_reject_total": 0,
            "oracle_source_cardinality": 1,
            "accepted_total": 1,
            "sample_count": 1,
            "unexpected": false
        }
    }))
    .expect_err("oracle metrics contract should fail closed on unknown fields");
    assert!(oracle_metrics_err.to_string().contains("unexpected"));
}
