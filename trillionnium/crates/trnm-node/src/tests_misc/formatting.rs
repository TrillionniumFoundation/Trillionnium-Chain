use super::*;

#[test]
fn format_task_metering_event_fields_includes_normalized_work_units_and_policy_summary() {
    let snapshot = TaskMeteringSnapshot {
        workload_class: "llm_inference".into(),
        metering_schema: "llm_token_meter_v1".into(),
        policy_snapshot_version: 1,
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
        min_accept_work_units: 100,
        challenge_success_bounty_base: 1,
        challenge_success_bounty_per_work_unit_num: 1,
        challenge_success_bounty_per_work_unit_den: 192,
        worker_completion_bonus_per_work_unit_num: 1,
        worker_completion_bonus_per_work_unit_den: 256,
        worker_slash_rebate_per_work_unit_num: 1,
        worker_slash_rebate_per_work_unit_den: 384,
    };
    let line = format_task_metering_event_fields(&snapshot);
    assert!(line.contains("metering_schema=llm_token_meter_v1"));
    assert!(line.contains("metering_normalized_work_units=192"));
    assert!(line.contains("metering_policy_snapshot_version=1"));
    assert!(line.contains("metering_min_accept_work_units=100"));
    assert!(line.contains("metering_worker_slash_rebate_per_work_unit_den=384"));
}

#[test]
fn format_task_metering_event_fields_preserves_da_checkpoint_light_verifier_evidence_fields() {
    let snapshot = TaskMeteringSnapshot {
        workload_class: "da-light-verifier".into(),
        metering_schema: "da_checkpoint_audit_v1".into(),
        policy_snapshot_version: 3,
        receipt_hash: "ef".repeat(32),
        prompt_tokens: 0,
        generated_tokens: 0,
        decode_steps: 0,
        kv_bytes_moved: 2048,
        normalized_work_units: 64,
        prompt_token_weight: 0,
        generated_token_weight: 0,
        decode_step_weight: 0,
        kv_byte_weight: 1,
        min_accept_work_units: 32,
        challenge_success_bounty_base: 2,
        challenge_success_bounty_per_work_unit_num: 1,
        challenge_success_bounty_per_work_unit_den: 64,
        worker_completion_bonus_per_work_unit_num: 1,
        worker_completion_bonus_per_work_unit_den: 96,
        worker_slash_rebate_per_work_unit_num: 1,
        worker_slash_rebate_per_work_unit_den: 128,
    };
    let line = format_task_metering_event_fields(&snapshot);
    assert!(line.contains("metering_workload_class=da-light-verifier"));
    assert!(line.contains("metering_schema=da_checkpoint_audit_v1"));
    assert!(line.contains(&format!("metering_receipt_hash={}", snapshot.receipt_hash)));
    assert!(line.contains("metering_policy_snapshot_version=3"));
    assert!(line.contains("metering_normalized_work_units=64"));
}
