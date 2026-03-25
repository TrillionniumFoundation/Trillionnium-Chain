use super::*;

#[test]
fn query_task_from_state_snapshot_computes_metering_derived_block() {
    let tasks = vec![TaskObject {
        task_id: 77,
        creator: "alice".into(),
        bounty: 777,
        status: TaskStatus::Completed,
        proof_type: trnm_types::ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: None,
            task_type: None,
            input_hash: None,
            model: None,
            provenance: None,
            metering: Some(TaskMeteringSnapshot {
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
            }),
        }),
        worker: Some("worker-a".into()),
        committed_hash: None,
        result_hash: Some([0xabu8; 32]),
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 9,
    }];
    let out = query_task_from_state_snapshot(77, &tasks).expect("task expected");
    let metering = out.metering.expect("metering expected");
    assert_eq!(metering.derived.path, "Completed");
    assert!(metering.derived.accept_floor_pass);
    assert_eq!(metering.derived.challenge_metered_bonus, 1);
    assert_eq!(metering.derived.challenge_bonus_total, 2);
    assert_eq!(metering.derived.worker_completion_bonus, 1);
    assert_eq!(metering.derived.worker_slash_rebate, 1);
}

#[test]
fn query_task_from_state_snapshot_exposes_metering_audit_fields() {
    let tasks = vec![TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 777,
        status: TaskStatus::Revealed,
        proof_type: trnm_types::ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: None,
            task_type: None,
            input_hash: None,
            model: None,
            provenance: None,
            metering: Some(TaskMeteringSnapshot {
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
            }),
        }),
        worker: Some("worker-a".into()),
        committed_hash: None,
        result_hash: Some([0xabu8; 32]),
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 9,
    }];

    let out = query_task_from_state_snapshot(42, &tasks).expect("task expected");
    let expected_result_hash = hex::encode([0xabu8; 32]);
    assert_eq!(out.bounty, 777);
    assert_eq!(
        out.result_hash_hex.as_deref(),
        Some(expected_result_hash.as_str())
    );
    let metering = out.metering.expect("metering expected");
    assert_eq!(metering.normalized_work_units, 192);
    assert_eq!(metering.policy.snapshot_version, 1);
    assert_eq!(metering.policy.min_accept_work_units, 100);
    assert_eq!(
        metering.policy.challenge_success_bounty_per_work_unit_den,
        192
    );
    assert_eq!(metering.derived.path, "Revealed");
    assert_eq!(metering.derived.challenge_bonus_total, 2);
}

#[test]
fn query_task_from_state_snapshot_surfaces_metadata_governance_upgrade_signals() {
    let tasks = vec![TaskObject {
        task_id: 314,
        creator: "alice".into(),
        bounty: 500,
        status: TaskStatus::Assigned,
        proof_type: trnm_types::ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("legacy-only".into()),
            task_type: None,
            input_hash: None,
            model: None,
            provenance: None,
            metering: None,
        }),
        worker: Some("worker-a".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 2,
    }];

    let out = query_task_from_state_snapshot(314, &tasks).expect("task expected");
    let compatibility = out
        .metadata_compatibility
        .expect("metadata compatibility expected");
    assert!(compatibility.legacy_note_only);
    assert!(compatibility.canonical_core_fields);
    assert!(compatibility.complete_metering_snapshot);
    assert_eq!(out.metadata_requires_governance_upgrade, Some(true));
    assert_eq!(
        out.metadata_compatibility_findings,
        Some(vec![TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload])
    );
}
