use super::*;
use trnm_types::TaskMetadataCompatibilityFinding;

#[test]
fn rpc_schema_smoke_task_fields_stable() {
    let task = TaskQueryResponse {
        task_id: 1,
        status: TaskStatus::Open,
        worker: None,
        bounty: 100,
        result_hash_hex: None,
        version: 1,
        metadata_compatibility: None,
        metadata_runtime_compatible: None,
        metadata_requires_governance_upgrade: None,
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: None,
        metering: None,
    };
    let v = serde_json::to_value(task).unwrap();
    let obj = v.as_object().unwrap();
    for k in [
        "task_id",
        "status",
        "worker",
        "bounty",
        "result_hash_hex",
        "version",
    ] {
        assert!(obj.contains_key(k), "missing key: {}", k);
    }
}

#[test]
fn rpc_task_query_omits_metering_when_absent() {
    let task = TaskQueryResponse {
        task_id: 1,
        status: TaskStatus::Open,
        worker: None,
        bounty: 100,
        result_hash_hex: None,
        version: 1,
        metadata_compatibility: None,
        metadata_runtime_compatible: None,
        metadata_requires_governance_upgrade: None,
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: None,
        metering: None,
    };
    let v = serde_json::to_value(task).unwrap();
    assert!(v.get("metering").is_none());
}

#[test]
fn rpc_task_query_includes_metadata_compatibility_when_present() {
    let task = TaskQueryResponse {
        task_id: 1,
        status: TaskStatus::Revealed,
        worker: Some("worker-1".into()),
        bounty: 100,
        result_hash_hex: Some("abcd".into()),
        version: 3,
        metadata_compatibility: Some(TaskMetadataCompatibility {
            legacy_note_only: false,
            canonical_core_fields: true,
            complete_metering_snapshot: true,
        }),
        metadata_runtime_compatible: Some(true),
        metadata_requires_governance_upgrade: Some(false),
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: None,
        metering: None,
    };
    let v = serde_json::to_value(task).unwrap();
    assert_eq!(v["metadata_compatibility"]["legacy_note_only"], json!(false));
    assert_eq!(
        v["metadata_compatibility"]["canonical_core_fields"],
        json!(true)
    );
    assert_eq!(
        v["metadata_compatibility"]["complete_metering_snapshot"],
        json!(true)
    );
    assert_eq!(v["metadata_runtime_compatible"], json!(true));
    assert_eq!(v["metadata_requires_governance_upgrade"], json!(false));
}

#[test]
fn rpc_task_query_includes_metadata_compatibility_findings_when_present() {
    let task = TaskQueryResponse {
        task_id: 9,
        status: TaskStatus::Revealed,
        worker: Some("worker-1".into()),
        bounty: 100,
        result_hash_hex: Some("abcd".into()),
        version: 3,
        metadata_compatibility: Some(TaskMetadataCompatibility {
            legacy_note_only: false,
            canonical_core_fields: false,
            complete_metering_snapshot: false,
        }),
        metadata_runtime_compatible: Some(false),
        metadata_requires_governance_upgrade: Some(true),
        metadata_primary_compatibility_finding: Some(
            TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
        ),
        metadata_compatibility_findings: Some(vec![
            TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
            TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
        ]),
        metering: None,
    };
    let v = serde_json::to_value(task).unwrap();
    assert_eq!(v["metadata_runtime_compatible"], json!(false));
    assert_eq!(v["metadata_requires_governance_upgrade"], json!(true));
    assert_eq!(
        v["metadata_primary_compatibility_finding"],
        json!("non_canonical_core_fields")
    );
    assert_eq!(
        v["metadata_compatibility_findings"],
        json!(["non_canonical_core_fields", "incomplete_metering_snapshot"])
    );
}

#[test]
fn rpc_task_query_omits_empty_metadata_compatibility_findings_array() {
    let task = TaskQueryResponse {
        task_id: 10,
        status: TaskStatus::Assigned,
        worker: Some("worker-2".into()),
        bounty: 200,
        result_hash_hex: None,
        version: 4,
        metadata_compatibility: Some(TaskMetadataCompatibility {
            legacy_note_only: false,
            canonical_core_fields: true,
            complete_metering_snapshot: true,
        }),
        metadata_runtime_compatible: Some(true),
        metadata_requires_governance_upgrade: Some(false),
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: Some(vec![]),
        metering: None,
    };
    let v = serde_json::to_value(task).unwrap();
    assert!(v.get("metadata_compatibility_findings").is_none());
}

#[test]
fn rpc_task_query_includes_metering_when_present() {
    let task = TaskQueryResponse {
        task_id: 1,
        status: TaskStatus::Revealed,
        worker: Some("worker-1".into()),
        bounty: 100,
        result_hash_hex: Some("abcd".into()),
        version: 3,
        metadata_compatibility: None,
        metadata_runtime_compatible: None,
        metadata_requires_governance_upgrade: None,
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: None,
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
                min_accept_work_units: 0,
                challenge_success_bounty_base: 1,
                challenge_success_bounty_per_work_unit_num: 1,
                challenge_success_bounty_per_work_unit_den: 192,
                worker_completion_bonus_per_work_unit_num: 1,
                worker_completion_bonus_per_work_unit_den: 192,
                worker_slash_rebate_per_work_unit_num: 1,
                worker_slash_rebate_per_work_unit_den: 192,
            },
            derived: TaskMeteringDerivedQueryResponse {
                path: "Revealed".into(),
                accept_floor_pass: true,
                challenge_metered_bonus: 1,
                challenge_bonus_total: 2,
                worker_completion_bonus: 1,
                worker_slash_rebate: 1,
            },
        }),
    };
    let v = serde_json::to_value(task).unwrap();
    assert_eq!(v["metering"]["normalized_work_units"], json!(192));
    assert_eq!(v["metering"]["policy"]["snapshot_version"], json!(1));
    assert_eq!(
        v["metering"]["policy"]["challenge_success_bounty_base"],
        json!(1)
    );
    assert_eq!(v["metering"]["derived"]["challenge_bonus_total"], json!(2));
    assert_eq!(v["metering"]["derived"]["accept_floor_pass"], json!(true));
}

#[test]
fn rpc_event_query_omits_metering_when_absent() {
    let event = EventQueryResponse {
        event_type: "commit".into(),
        task_id: 1,
        from_status: "Accepted".into(),
        to_status: "Committed".into(),
        actor: "worker-a".into(),
        tx_id: 10,
        block_height: 3,
        state_root: "abc".into(),
        ts_unix_ms: 123,
        signer: None,
        challenger: None,
        tx_hash: None,
        resolution_code: None,
        treasury_delta: None,
        challenger_delta: None,
        bond_disposition: None,
        metering: None,
    };
    let v = serde_json::to_value(event).unwrap();
    assert!(v.get("metering").is_none());
}

#[test]
fn rpc_schema_smoke_event_fields_stable() {
    let evt = EventQueryResponse {
        event_type: "commit".into(),
        task_id: 1,
        from_status: "Assigned".into(),
        to_status: "Committed".into(),
        actor: "worker1".into(),
        tx_id: 7,
        block_height: 2,
        state_root: "abc".into(),
        ts_unix_ms: 1,
        signer: None,
        challenger: None,
        tx_hash: None,
        resolution_code: None,
        treasury_delta: None,
        challenger_delta: None,
        bond_disposition: None,
        metering: None,
    };
    let v = serde_json::to_value(evt).unwrap();
    assert_eq!(
        v,
        json!({
            "event_type":"commit",
            "task_id":1,
            "from_status":"Assigned",
            "to_status":"Committed",
            "actor":"worker1",
            "tx_id":7,
            "block_height":2,
            "state_root":"abc",
            "ts_unix_ms":1
        })
    );
}

#[test]
fn rpc_event_query_includes_optional_audit_fields_when_present() {
    let event = EventQueryResponse {
        event_type: "resolve".into(),
        task_id: 11,
        from_status: "Challenged".into(),
        to_status: "Completed".into(),
        actor: "arbiter-1".into(),
        tx_id: 19,
        block_height: 8,
        state_root: "def".into(),
        ts_unix_ms: 456,
        signer: Some("arbiter-1".into()),
        challenger: Some("challenger-9".into()),
        tx_hash: Some("0xdeadbeef".into()),
        resolution_code: Some("completed".into()),
        treasury_delta: Some(-25),
        challenger_delta: Some(25),
        bond_disposition: Some("released".into()),
        metering: None,
    };
    let v = serde_json::to_value(event).unwrap();
    assert_eq!(v["signer"], json!("arbiter-1"));
    assert_eq!(v["challenger"], json!("challenger-9"));
    assert_eq!(v["tx_hash"], json!("0xdeadbeef"));
    assert_eq!(v["resolution_code"], json!("completed"));
    assert_eq!(v["treasury_delta"], json!(-25));
    assert_eq!(v["challenger_delta"], json!(25));
    assert_eq!(v["bond_disposition"], json!("released"));
}
