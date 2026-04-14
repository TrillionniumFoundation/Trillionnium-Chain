use super::*;

#[test]
fn task_metadata_string_field_boundaries_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let task1 = TaskObject {
        task_id: 6,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("ab".into()),
            task_type: Some("c".into()),
            input_hash: None,
            model: None,
            provenance: None,
            metering: None,
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };
    let mut task2 = task1.clone();
    task2.metadata = Some(TaskMetadata {
        note: Some("a".into()),
        task_type: Some("bc".into()),
        input_hash: None,
        model: None,
        provenance: None,
        metering: None,
            settlement: None,
    });

    st1.put_task_new(task1).unwrap();
    st2.put_task_new(task2).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should frame task metadata string lengths so distinct field boundaries cannot collide"
    );
}
#[test]
fn task_metadata_presence_bit_should_affect_state_root_even_when_nested_fields_are_empty() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 6_501,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: None,
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
        version: 1,
    };

    let mut with_empty_metadata = base_task.clone();
    with_empty_metadata.metadata = Some(TaskMetadata::default());

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(with_empty_metadata).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should distinguish absent task metadata from an explicitly present empty metadata container"
    );
}
#[test]
fn task_model_metadata_string_field_boundaries_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 6_502,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: None,
            task_type: None,
            input_hash: None,
            model: Some(TaskModelMetadata {
                model_id: Some("ab".into()),
                model_digest: Some("c".into()),
                version: None,
            }),
            provenance: None,
            metering: None,
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };

    let mut changed_task = base_task.clone();
    changed_task.metadata = Some(TaskMetadata {
        note: None,
        task_type: None,
        input_hash: None,
        model: Some(TaskModelMetadata {
            model_id: Some("a".into()),
            model_digest: Some("bc".into()),
            version: None,
        }),
        provenance: None,
        metering: None,
            settlement: None,
    });

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should length-frame nested task model metadata strings so field-boundary collisions cannot hash identically"
    );
}
#[test]
fn task_metadata_and_proof_type_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 7,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: None,
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
        version: 1,
    };

    st1.put_task_new(base_task.clone()).unwrap();

    let mut changed_task = base_task;
    changed_task.proof_type = ProofType::Zk;
    changed_task.metadata = Some(TaskMetadata {
        note: Some("zk task".into()),
        task_type: Some("inference".into()),
        input_hash: Some("ab".repeat(32)),
        model: Some(TaskModelMetadata {
            model_id: Some("trnm-model".into()),
            model_digest: Some("cd".repeat(32)),
            version: Some("v1".into()),
        }),
        provenance: Some(TaskProvenanceMetadata {
            producer_did: Some("did:trnm:test".into()),
            produced_at: Some("2026-03-11T08:42:00Z".into()),
            provenance_index: Some("prov-7".into()),
            privacy_tier: Some(PrivacyTier::Internal),
        }),
        metering: None,
            settlement: None,
    });
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task proof_type and metadata"
    );
}
#[test]
fn task_version_must_affect_state_root_even_when_other_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let base_task = TaskObject {
        task_id: 6_503,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("same logical payload".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test".into()),
                produced_at: Some("2026-03-26T03:21:00Z".into()),
                provenance_index: Some("prov-6503".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: None,
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };

    let mut changed_task = base_task.clone();
    changed_task.version = 2;

    state_a.put_task_new(base_task.clone()).unwrap();
    state_b.put_task_new(changed_task.clone()).unwrap();

    let root_v1 = state_a.state_root();
    assert_ne!(
        root_v1,
        state_b.state_root(),
        "task object version must contribute to state_root so otherwise identical task payloads at different canonical object versions cannot hash identically"
    );

    state_b.restore_task(changed_task.task_id, Some(base_task));
    assert_eq!(
        state_b.state_root(),
        root_v1,
        "restoring the original task object version should rewind the deterministic root exactly"
    );
}
#[test]
fn task_challenge_window_snapshot_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Revealed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: None,
        resolve_deadline_height: Some(42),
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 2,
    };

    let mut changed_task = base_task.clone();
    changed_task.challenge_window_blocks_snapshot = Some(24);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task challenge_window_blocks_snapshot so reveal-time resolve semantics remain deterministic"
    );
}
#[test]
fn task_challenge_deadline_height_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_001,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Revealed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: None,
        resolve_deadline_height: Some(42),
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 2,
    };

    let mut changed_task = base_task.clone();
    changed_task.challenge_deadline_height = Some(31);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task challenge_deadline_height so retained proof-expiry semantics cannot hash identically"
    );
}
#[test]
fn task_challenged_at_height_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_001_1,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Challenged,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: Some([0x22; 32]),
        reveal_salt: Some([0x33; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(42),
        challenge_bond: Some(17),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 2,
    };

    let mut changed_task = base_task.clone();
    changed_task.challenged_at_height = Some(26);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task challenged_at_height so retained collateral/proof activation boundaries cannot hash identically"
    );
}
#[test]
fn challenge_bond_forfeited_flag_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_002,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Challenged,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([0x22; 32]),
        result_hash: Some([0x33; 32]),
        reveal_salt: Some([0x44; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(42),
        challenge_bond: Some(17),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 2,
    };

    let mut changed_task = base_task.clone();
    changed_task.challenge_bond_forfeited = Some(true);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate challenge_bond_forfeited so refund-vs-forfeit challenge outcomes cannot hash identically"
    );
}
#[test]
fn task_metering_receipt_and_policy_version_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_003,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("da receipt anchored task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test".into()),
                produced_at: Some("2026-03-12T06:45:00Z".into()),
                provenance_index: Some("prov-metering-1".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: Some(TaskMeteringSnapshot {
                workload_class: "da-light-verifier".into(),
                metering_schema: "metering.v1".into(),
                policy_snapshot_version: 3,
                receipt_hash: "ef".repeat(32),
                prompt_tokens: 120,
                generated_tokens: 45,
                decode_steps: 17,
                kv_bytes_moved: 4096,
                normalized_work_units: 88,
                prompt_token_weight: 2,
                generated_token_weight: 3,
                decode_step_weight: 5,
                kv_byte_weight: 7,
                min_accept_work_units: 55,
                challenge_success_bounty_base: 13,
                challenge_success_bounty_per_work_unit_num: 2,
                challenge_success_bounty_per_work_unit_den: 1,
                worker_completion_bonus_per_work_unit_num: 3,
                worker_completion_bonus_per_work_unit_den: 2,
                worker_slash_rebate_per_work_unit_num: 1,
                worker_slash_rebate_per_work_unit_den: 4,
            }),
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };

    let mut changed_task = base_task.clone();
    let metering = changed_task
        .metadata
        .as_mut()
        .unwrap()
        .metering
        .as_mut()
        .unwrap();
    metering.policy_snapshot_version = 4;
    metering.receipt_hash = "fe".repeat(32);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task metering receipt_hash and policy_snapshot_version so DA checkpoint evidence snapshots cannot hash identically when only verifier/audit metadata changes"
    );
}

#[test]
fn task_metering_workload_class_should_affect_state_root_even_when_receipt_and_policy_match() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_004,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("checkpoint-linked verifier task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test".into()),
                produced_at: Some("2026-03-12T06:45:00Z".into()),
                provenance_index: Some("prov-metering-2".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: Some(TaskMeteringSnapshot {
                workload_class: "da-light-verifier".into(),
                metering_schema: "metering.v1".into(),
                policy_snapshot_version: 3,
                receipt_hash: "ef".repeat(32),
                prompt_tokens: 120,
                generated_tokens: 45,
                decode_steps: 17,
                kv_bytes_moved: 4096,
                normalized_work_units: 88,
                prompt_token_weight: 2,
                generated_token_weight: 3,
                decode_step_weight: 5,
                kv_byte_weight: 7,
                min_accept_work_units: 55,
                challenge_success_bounty_base: 13,
                challenge_success_bounty_per_work_unit_num: 2,
                challenge_success_bounty_per_work_unit_den: 1,
                worker_completion_bonus_per_work_unit_num: 3,
                worker_completion_bonus_per_work_unit_den: 2,
                worker_slash_rebate_per_work_unit_num: 1,
                worker_slash_rebate_per_work_unit_den: 4,
            }),
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };

    let mut changed_task = base_task.clone();
    changed_task
        .metadata
        .as_mut()
        .unwrap()
        .metering
        .as_mut()
        .unwrap()
        .workload_class = "da-checkpoint-audit".into();

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root must include metering workload_class so DA light-verifier and checkpoint-audit tasks cannot hash identically when receipt and policy metadata match"
    );
}

#[test]
fn task_metering_schema_should_affect_state_root_even_when_receipt_and_policy_match() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_004_1,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("checkpoint-linked verifier task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test".into()),
                produced_at: Some("2026-03-12T06:45:00Z".into()),
                provenance_index: Some("prov-metering-2a".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: Some(TaskMeteringSnapshot {
                workload_class: "da-light-verifier".into(),
                metering_schema: "metering.v1".into(),
                policy_snapshot_version: 3,
                receipt_hash: "ef".repeat(32),
                prompt_tokens: 120,
                generated_tokens: 45,
                decode_steps: 17,
                kv_bytes_moved: 4096,
                normalized_work_units: 88,
                prompt_token_weight: 2,
                generated_token_weight: 3,
                decode_step_weight: 5,
                kv_byte_weight: 7,
                min_accept_work_units: 55,
                challenge_success_bounty_base: 13,
                challenge_success_bounty_per_work_unit_num: 2,
                challenge_success_bounty_per_work_unit_den: 1,
                worker_completion_bonus_per_work_unit_num: 3,
                worker_completion_bonus_per_work_unit_den: 2,
                worker_slash_rebate_per_work_unit_num: 1,
                worker_slash_rebate_per_work_unit_den: 4,
            }),
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };

    let mut changed_task = base_task.clone();
    changed_task
        .metadata
        .as_mut()
        .unwrap()
        .metering
        .as_mut()
        .unwrap()
        .metering_schema = "metering.v2".into();

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root must include metering_schema so equivalent DA light-verifier checkpoint evidence cannot hash identically across verifier schema revisions"
    );
}

#[test]
fn task_metering_work_units_should_affect_state_root_even_when_receipt_metadata_matches() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_004_2,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("checkpoint-linked verifier task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test".into()),
                produced_at: Some("2026-03-12T06:45:00Z".into()),
                provenance_index: Some("prov-metering-2b".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: Some(TaskMeteringSnapshot {
                workload_class: "da-light-verifier".into(),
                metering_schema: "metering.v1".into(),
                policy_snapshot_version: 3,
                receipt_hash: "ef".repeat(32),
                prompt_tokens: 120,
                generated_tokens: 45,
                decode_steps: 17,
                kv_bytes_moved: 4096,
                normalized_work_units: 88,
                prompt_token_weight: 2,
                generated_token_weight: 3,
                decode_step_weight: 5,
                kv_byte_weight: 7,
                min_accept_work_units: 55,
                challenge_success_bounty_base: 13,
                challenge_success_bounty_per_work_unit_num: 2,
                challenge_success_bounty_per_work_unit_den: 1,
                worker_completion_bonus_per_work_unit_num: 3,
                worker_completion_bonus_per_work_unit_den: 2,
                worker_slash_rebate_per_work_unit_num: 1,
                worker_slash_rebate_per_work_unit_den: 4,
            }),
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };

    let mut changed_task = base_task.clone();
    changed_task
        .metadata
        .as_mut()
        .unwrap()
        .metering
        .as_mut()
        .unwrap()
        .normalized_work_units = 89;

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root must include metering normalized_work_units so DA light-verifier checkpoint evidence with different audited work-unit totals cannot hash identically when receipt metadata matches"
    );
}

#[test]
fn task_provenance_index_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_000,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("checkpoint evidence linked task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test".into()),
                produced_at: Some("2026-03-12T06:45:00Z".into()),
                provenance_index: Some("checkpoint-proof-17".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: None,
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };

    let mut changed_task = base_task.clone();
    changed_task
        .metadata
        .as_mut()
        .unwrap()
        .provenance
        .as_mut()
        .unwrap()
        .provenance_index = Some("checkpoint-proof-18".into());

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task provenance_index so distinct checkpoint evidence links cannot hash identically"
    );
}

#[test]
fn task_provenance_privacy_tier_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_001,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("privacy-sensitive task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test".into()),
                produced_at: Some("2026-03-12T06:45:00Z".into()),
                provenance_index: Some("prov-privacy-1".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: None,
                    settlement: None,
        }),
        worker: None,
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
        version: 1,
    };

    let mut changed_task = base_task.clone();
    changed_task
        .metadata
        .as_mut()
        .unwrap()
        .provenance
        .as_mut()
        .unwrap()
        .privacy_tier = Some(PrivacyTier::Restricted);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task provenance privacy_tier so otherwise identical privacy classifications cannot hash identically"
    );
}
